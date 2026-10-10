"""Lower SDK stamps and stub imports in Prospero ELF modules for a backport."""
import struct

from . import elf
from .registry import GADGET, TRAP

PT_LOAD, PF_X = 1, 1
DT_RELA, DT_RELASZ, DT_JMPREL, DT_PLTRELSZ = 7, 8, 23, 2
R_X86_64_JUMP_SLOT = 7
SYMBOL = elf.SYMBOL_ENTRY
RELA = struct.Struct("<QQq")


def executable_segments(data):
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(phnum):
        at = phoff + i * phentsize
        p_type, p_flags = struct.unpack_from("<II", data, at)
        p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from("<QQQQ", data, at + 8)
        if p_type == PT_LOAD and p_flags & PF_X:
            yield p_offset, p_vaddr, p_filesz


class Patcher:
    def __init__(self, path):
        self.path = path
        self.module = elf.Module(path)
        self.data = bytearray(self.module.data)
        self.log = []

    def stamp(self, tier):
        """Cap both SDK words at the tier's pair — lowered, never raised.
        Returns True if either word changed."""
        at = self.module.param
        if at is None:
            raise ValueError(f"{self.path}: no param segment")
        old = struct.unpack_from("<II", self.data, at + 0x10)
        new = (min(old[0], tier.stamp_ps4), min(old[1], tier.stamp_ps5))
        if new == old:
            return False
        struct.pack_into("<II", self.data, at + 0x10, *new)
        self.log.append(f"stamp ps4 {old[0]:#010x}->{new[0]:#010x} "
                        f"ps5 {old[1]:#010x}->{new[1]:#010x}")
        return True

    def symbols(self):
        """(index, file offset, library, nid, shndx, value) for every NID symbol."""
        m = self.module
        base = m.tags[m.layout["symtab"]][0]
        symtab = (m.dynlibdata + base if m.layout is elf.ORBIS
                  else m._vaddr_to_offset(base))
        libraries = m._library_names()
        for i in range(m._symbol_count(SYMBOL.size)):
            at = symtab + i * SYMBOL.size
            nameoff, _info, _other, shndx, value, _size = SYMBOL.unpack_from(self.data, at)
            parts = m.string(nameoff).split("#") if nameoff else []
            if len(parts) != 3:
                continue
            library = libraries.get(elf._token_id(parts[1]), parts[1])
            yield i, at, library, parts[0], shndx, value

    def gadget(self):
        for offset, vaddr, size in executable_segments(self.data):
            hit = self.data.find(GADGET, offset, offset + size)
            if hit >= 0:
                return vaddr + hit - offset
        for offset, vaddr, size in executable_segments(self.data):
            hit = self.data.find(b"\xcc" * 4, offset, offset + size)
            if hit >= 0:
                self.data[hit:hit + 3] = GADGET
                self.log.append(f"gadget written into int3 padding at {vaddr + hit - offset:#x}")
                return vaddr + hit - offset
        raise ValueError(f"{self.path}: no gadget and no int3 padding")

    def relocations(self, tag, size_tag):
        m = self.module
        if tag not in m.tags:
            return
        start = m._vaddr_to_offset(m.tags[tag][0])
        for at in range(start, start + m.tags[size_tag][0], RELA.size):
            r_offset, r_info, _addend = RELA.unpack_from(self.data, at)
            yield r_offset, r_info >> 32, r_info & 0xffffffff

    def place(self, code):
        """Write code into int3 padding of an executable segment; return its vaddr."""
        # A ret before the padding keeps the stub out of the image header area
        # and off vaddr 0, which a loader may read as an undefined symbol.
        pattern = b"\xc3" + b"\xcc" * len(code)
        for offset, vaddr, size in executable_segments(self.data):
            hit = self.data.find(pattern, offset, offset + size)
            if hit >= 0:
                hit += 1
                self.data[hit:hit + len(code)] = code
                self.log.append(f"{len(code)}-byte stub written into int3 padding at {vaddr + hit - offset:#x}")
                return vaddr + hit - offset
        raise ValueError(f"{self.path}: no int3 padding for {len(code)} bytes")

    def stub(self, pairs, code=None, target=None):
        pairs = set(pairs)
        if not pairs:
            return set()
        if target is None:
            target = self.place(code) if code else self.gadget()
        stubbed = {}
        for index, at, library, nid, shndx, value in self.symbols():
            if (library, nid) in pairs and shndx == 0 and value == 0:
                struct.pack_into("<H", self.data, at + 6, 1)
                struct.pack_into("<Q", self.data, at + 8, target)
                stubbed[index] = (library, nid)
        slots = 0
        for r_offset, sym, kind in self.relocations(DT_JMPREL, DT_PLTRELSZ):
            if sym in stubbed and kind == R_X86_64_JUMP_SLOT:
                struct.pack_into("<Q", self.data, self.module._vaddr_to_offset(r_offset), target)
                slots += 1
        for _r_offset, sym, kind in self.relocations(DT_RELA, DT_RELASZ):
            if sym in stubbed:
                self.log.append(f"WARNING non-PLT relocation type {kind} uses stubbed {stubbed[sym]}")
        missing = pairs - set(stubbed.values())
        self.log.append(f"stubbed {len(stubbed)} imports at gadget {target:#x}, {slots} GOT slots"
                        + (f"; not found: {sorted(missing)}" if missing else ""))
        return set(stubbed.values())

    def retarget(self, pair, new_nid):
        """Rename an import's NID in place so it binds to an older equivalent."""
        library, nid = pair
        renamed = 0
        for _index, at, lib, sym_nid, shndx, value in self.symbols():
            if (lib, sym_nid) == pair and shndx == 0 and value == 0:
                nameoff, = struct.unpack_from("<I", self.data, at)
                start = self.module.strtab + nameoff
                assert self.data[start:start + 11].decode() == nid, pair
                self.data[start:start + 11] = new_nid.encode()
                renamed += 1
        if not renamed:
            raise ValueError(f"{self.path}: no undefined import {pair}")
        self.log.append(f"retargeted {library}:{nid} -> {new_nid}")

    def stub_registered(self, pairs, registry, allow_unreviewed=False):
        """Stub or retarget each pair using its registry entry.

        Returns {vaddr: (library, nid)} so a crash address maps to one stub.
        Retargeted imports bind to a real function and get no address.
        """
        placed = {}
        for pair in sorted(pairs):
            entry = registry.entry(pair)
            if (entry and entry["stub"].startswith("retarget:")
                    and not registry.refused([pair], allow_unreviewed)):
                self.retarget(pair, entry["stub"].split(":", 1)[1])
                continue
            code = registry.code(pair, allow_unreviewed)
            target = self.place(code)
            assert self.stub([pair], code=None, target=target) == {pair}, pair
            placed[target] = pair
        return placed

    def grow_text(self, size):
        """Extend the executable segment by size bytes into its page padding.

        Returns (vaddr, file offset) of the new space, filled with int3.
        """
        return self.grow_segment(size, executable=True)

    def grow_rodata(self, size):
        """Extend the read-only data segment by size bytes; returns (vaddr, file offset)."""
        return self.grow_segment(size, executable=False)

    def grow_segment(self, size, executable):
        phoff, = struct.unpack_from("<Q", self.data, 0x20)
        phentsize, phnum = struct.unpack_from("<HH", self.data, 0x36)
        loads = []
        for i in range(phnum):
            at = phoff + i * phentsize
            p_type, p_flags = struct.unpack_from("<II", self.data, at)
            p_offset, p_vaddr, _paddr, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", self.data, at + 8)
            if p_type == PT_LOAD:
                loads.append((at, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))
        PF_W, PF_R = 2, 4
        if executable:
            text = [l for l in loads if l[1] & PF_X]
            fill = b"\xcc"
        else:
            text = [l for l in loads if l[1] == PF_R]
            fill = b"\x00"
        assert len(text) == 1, text
        at, _flags, p_offset, p_vaddr, p_filesz, p_memsz = text[0]
        assert p_filesz == p_memsz
        start = (p_filesz + 15) & ~15
        end = start + size
        nxt = min((l[3] for l in loads if l[3] > p_vaddr), default=None)
        nxt_off = min((l[2] for l in loads if l[2] > p_offset), default=len(self.data))
        if (nxt is not None and p_vaddr + end > nxt) or p_offset + end > nxt_off:
            raise ValueError(f"{self.path}: no room after the text segment")
        if any(self.data[p_offset + p_filesz:p_offset + end]):
            raise ValueError(f"{self.path}: bytes after the text segment are not zero")
        self.data[p_offset + p_filesz:p_offset + end] = fill * (end - p_filesz)
        struct.pack_into("<QQ", self.data, at + 0x20, end, end)
        self.log.append(f"{'text' if executable else 'rodata'} segment grown {p_filesz:#x} -> {end:#x}")
        return p_vaddr + start, p_offset + start

    def export_address(self, library, nid):
        hits = {value for _i, _at, lib, n, shndx, value in self.symbols()
                if lib == library and n == nid and shndx and value}
        if len(hits) != 1:
            raise ValueError(f"{self.path}: export {library}:{nid} -> {sorted(hits)}")
        return hits.pop()

    def unpeg_on_vrr_event(self):
        """Make AddVrrActiveStatusEvent also unpeg the output for VRR-aware apps.

        Type B titles never call sceVideoOutVrrUnpegFromFixedRate; on firmware that
        only knows Type A the output then stays pegged at the max refresh rate.
        """
        add_event = self.export_address("libSceVideoOutVrrStatus", "LibwuIonIBw")
        unpeg = self.export_address("libSceVideoOutVrrPeg", "T4ucGB8CsnM")
        aware = self.export_address("libSceVideoOutVrrStatus", "kP2L8t3j-aM")
        # The opt-in is `xor eax,eax; mov byte [rip+d32],1; ret`; take the flag from it.
        at = self.module._vaddr_to_offset(aware)
        code = bytes(self.data[at:at + 10])
        if code[:4] != b"\x31\xc0\xc6\x05" or code[8] != 1 or code[9] != 0xc3:
            raise ValueError(f"{self.path}: unexpected VRR-aware export {code.hex()}")
        flag = aware + 9 + struct.unpack_from("<i", code, 4)[0]

        size = 48
        base, file_at = self.grow_text(size)

        out = bytearray()

        def rel32(target):
            return struct.pack("<i", target - (base + len(out) + 4))

        out += b"\x55\x48\x89\xe5\x53\x41\x54"      # push rbp; mov rbp,rsp; push rbx; push r12
        out += b"\x41\x89\xf4"                      # mov r12d, esi   (video handle)
        out += b"\xe8"; out += rel32(add_event)     # call AddVrrActiveStatusEvent
        out += b"\x89\xc3"                          # mov ebx, eax
        out += b"\x85\xc0\x75\x11"                  # test eax,eax; jnz done
        out += b"\x80\x3d"                          # cmp byte [rip+flag], 1
        out += struct.pack("<i", flag - (base + len(out) + 5)) + b"\x01"
        out += b"\x75\x08"                          # jne done
        out += b"\x44\x89\xe7"                      # mov edi, r12d
        out += b"\xe8"; out += rel32(unpeg)         # call UnpegFromFixedRate
        out += b"\x89\xd8"                          # done: mov eax, ebx
        out += b"\x41\x5c\x5b\x5d\xc3"              # pop r12; pop rbx; pop rbp; ret
        assert len(out) <= size, len(out)
        self.data[file_at:file_at + len(out)] = out

        moved = 0
        for _index, sym_at, lib, nid, shndx, value in self.symbols():
            if lib == "libSceVideoOutVrrStatus" and nid == "LibwuIonIBw" and shndx and value == add_event:
                struct.pack_into("<Q", self.data, sym_at + 8, base)
                moved += 1
        assert moved == 1, moved
        self.log.append(f"unpeg shim at {base:#x}: AddVrrActiveStatusEvent {add_event:#x} + "
                        f"Unpeg {unpeg:#x} when flag {flag:#x} is set")
        return base

    def plt_for_import(self, nid):
        index = {i for i, _at, _lib, n, sh, _v in self.symbols() if n == nid and not sh}
        slots = {off for off, sym, kind in self.relocations(DT_JMPREL, DT_PLTRELSZ) if sym in index}
        assert len(slots) == 1, (nid, slots)
        slot = slots.pop()
        for offset, vaddr, size in executable_segments(self.data):
            at = offset
            while True:
                at = self.data.find(b"\xff\x25", at, offset + size)
                if at < 0:
                    break
                here = vaddr + at - offset
                if here + 6 + struct.unpack_from("<i", self.data, at + 2)[0] == slot:
                    return here
                at += 1
        raise ValueError(f"{self.path}: no PLT entry for {nid}")

    def vrr_shims(self, source):
        """Route AddVrrActiveStatusEvent and GetOutputStatusWithVrr through source.

        source is vrr_shim.s; both wrappers unpeg the output for VRR-aware apps.
        """
        import subprocess
        import tempfile
        add_event = self.export_address("libSceVideoOutVrrStatus", "LibwuIonIBw")
        get_vrr = self.export_address("libSceVideoOutVrrStatus", "gWT7X8H0bYs")
        unpeg = self.export_address("libSceVideoOutVrrPeg", "T4ucGB8CsnM")
        aware = self.export_address("libSceVideoOutVrrStatus", "kP2L8t3j-aM")
        at = self.module._vaddr_to_offset(aware)
        code = bytes(self.data[at:at + 10])
        if code[:4] != b"\x31\xc0\xc6\x05" or code[8] != 1 or code[9] != 0xc3:
            raise ValueError(f"{self.path}: unexpected VRR-aware export {code.hex()}")
        aware_flag = aware + 9 + struct.unpack_from("<i", code, 4)[0]
        # Unpeg tests its own state byte with `cmp byte [rip+d32], 0` before the ioctl.
        at = self.module._vaddr_to_offset(unpeg)
        hit = self.data.find(b"\x80\x3d", at, at + 0x60)
        if hit < 0 or self.data[hit + 6] != 0:
            raise ValueError(f"{self.path}: unpeg state flag not found")
        peg_flag = unpeg + (hit - at) + 7 + struct.unpack_from("<i", self.data, hit + 2)[0]

        size = 0x200
        base, file_at = self.grow_text(size)
        peg = self.export_address("libSceVideoOutVrrPeg", "5tRaBjtdTzY")
        syms = dict(add_event=add_event, get_vrr=get_vrr, peg=peg, unpeg=unpeg,
                    aware_flag=aware_flag, peg_flag=peg_flag)
        with tempfile.TemporaryDirectory() as tmp:
            obj, out, mapf = f"{tmp}/s.o", f"{tmp}/s.bin", f"{tmp}/s.map"
            subprocess.run(["clang", "-c", "--target=x86_64-unknown-elf", "-o", obj, source], check=True)
            subprocess.run(["ld.lld", "-o", out, "--oformat=binary", "--image-base=0", f"-Ttext={base:#x}", "-e", "0",
                            "-Map", mapf, *[f"--defsym={k}={v:#x}" for k, v in syms.items()], obj], check=True)
            blob = open(out, "rb").read()
            entries = {}
            for line in open(mapf):
                parts = line.split()
                if parts and parts[-1] in ("add_event_shim", "get_vrr_shim"):
                    entries[parts[-1]] = int(parts[0], 16)
        assert len(blob) <= size and len(entries) == 2, (len(blob), entries)
        self.data[file_at:file_at + len(blob)] = blob
        for nid, old, new in (("LibwuIonIBw", add_event, entries["add_event_shim"]),
                              ("gWT7X8H0bYs", get_vrr, entries["get_vrr_shim"])):
            moved = 0
            for _index, sym_at, lib, n, shndx, value in self.symbols():
                if lib == "libSceVideoOutVrrStatus" and n == nid and shndx and value == old:
                    struct.pack_into("<Q", self.data, sym_at + 8, new)
                    moved += 1
            assert moved == 1, (nid, moved)
        self.log.append(f"vrr shims at {base:#x} ({len(blob)} bytes): add {entries['add_event_shim']:#x}, "
                        f"get {entries['get_vrr_shim']:#x}; aware {aware_flag:#x}, peg flag {peg_flag:#x}")
        return entries

    def write(self, dest):
        with open(dest, "wb") as fh:
            fh.write(self.data)

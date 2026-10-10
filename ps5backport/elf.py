"""Read module metadata out of PS4/PS5 ELF images, and unwrap SELFs.

Two toolchains produce these files and they disagree on where the dynamic
tables live. Orbis-built modules (a game's eboot.bin and the prx it bundles)
keep strings and symbols inside PT_SCE_DYNLIBDATA and address them with the
0x610000{13,15,35,37,39} tag block. Prospero-built modules, which is what the
PS5 system libraries are even for the PS4 compatibility surface, use a
standard DT_STRTAB/DT_SYMTAB and the 0x610000{43,45,47,49} block.

Symbol names are "NID#libraryToken#moduleToken", where the tokens are base64
ids that index the module's import/export library tables. A library's symbols
can live in a module of another name, so anything matching imports against
exports has to go through the library name, not the filename.

unself() rebuilds the plain ELF inside an unencrypted, uncompressed Sony SELF.
Only run it on Sony-built SELFs: on our own make_fself output it shifts the
version records by 8 bytes, and re-signing that gives a different file.
"""
import struct
from collections import defaultdict

PT_LOAD = 1
PT_DYNAMIC = 2
PT_SCE_DYNLIBDATA = 0x61000000
PT_SCE_PROCPARAM = 0x61000001
PT_SCE_MODULE_PARAM = 0x61000002
PT_SCE_VERSION = 0x6FFFFF01

DT_NULL = 0
DT_SONAME = 14
MODULE_PARAM_MAGIC = 0x3C13F4BF
# "ORBI": the PT_SCE_PROCPARAM magic in PS5 eboots.
PROCESS_PARAM_MAGIC = 0x4942524F

ORBIS = dict(strtab=0x61000035, strsz=0x61000037, symtab=0x61000039,
             symtabsz=0x6100003F, export=0x61000013, imp=0x61000015)
PROSPERO = dict(strtab=5, strsz=10, symtab=6,
                symtabsz=0x6100003F, export=0x61000047, imp=0x61000049)

ID_ALPHABET = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
               "abcdefghijklmnopqrstuvwxyz0123456789+-")
SYMBOL_ENTRY = struct.Struct('<IBBHQQ')

SELF_MAGICS = (b"\x4f\x15\x3d\x1d", b"\x54\x14\xf5\xee")

EXEC_SUFFIXES = ('.elf', '.self', '.prx', '.sprx')


class NotAnElf(ValueError):
    pass


def _token_id(token):
    value = 0
    for ch in token:
        value = value * 64 + ID_ALPHABET.index(ch)
    return value


class Module:
    """One parsed ELF image.

    exports maps a library name to the NIDs it defines; imports is a list of
    (library, nid) pairs the image needs from elsewhere. ps4_sdk and ps5_sdk are
    the two words of the param segment, or None when the image has no param
    segment, one with an unrecognised magic, or (for ps5_sdk) a revision older
    than 3.
    """

    def __init__(self, path):
        self.path = str(path)
        with open(path, 'rb') as fh:
            self.data = fh.read()
        if self.data[:4] != b'\x7fELF':
            raise NotAnElf(f'{path}: not an ELF')

        self._read_segments()
        self._read_dynamic()
        self.exports, self.imports = self._read_symbols()

    def _read_segments(self):
        phoff, = struct.unpack_from('<Q', self.data, 0x20)
        phentsize, phnum = struct.unpack_from('<HH', self.data, 0x36)
        self.loads = []
        self.dynamic = self.dynlibdata = self.param = None
        for i in range(phnum):
            at = phoff + i * phentsize
            p_type, = struct.unpack_from('<I', self.data, at)
            p_offset, = struct.unpack_from('<Q', self.data, at + 0x08)
            p_vaddr, = struct.unpack_from('<Q', self.data, at + 0x10)
            p_filesz, = struct.unpack_from('<Q', self.data, at + 0x20)
            if p_type == PT_LOAD:
                self.loads.append((p_vaddr, p_offset, p_filesz))
            elif p_type == PT_DYNAMIC:
                self.dynamic = (p_offset, p_filesz)
            elif p_type == PT_SCE_DYNLIBDATA:
                self.dynlibdata = p_offset
            elif p_type in (PT_SCE_PROCPARAM, PT_SCE_MODULE_PARAM):
                self.param = p_offset

    def _vaddr_to_offset(self, vaddr):
        for base, offset, size in self.loads:
            if 0 <= vaddr - base < size:
                return offset + (vaddr - base)
        raise ValueError(f'{self.path}: vaddr 0x{vaddr:x} is not file-backed')

    def _read_dynamic(self):
        self.tags = defaultdict(list)
        self.flavour = None
        self.layout = PROSPERO
        self.strtab = self.strsz = None
        if self.dynamic is None:
            return
        offset, size = self.dynamic
        for at in range(offset, offset + size, 16):
            tag, value = struct.unpack_from('<QQ', self.data, at)
            self.tags[tag].append(value)
            if tag == DT_NULL:
                break

        self.layout = ORBIS if ORBIS['strtab'] in self.tags else PROSPERO
        self.flavour = 'orbis' if self.layout is ORBIS else 'prospero'
        if self.layout['strtab'] not in self.tags:
            self.strtab = self.strsz = None
            return
        self.strsz = self.tags[self.layout['strsz']][0]
        base = self.tags[self.layout['strtab']][0]
        self.strtab = (self.dynlibdata + base if self.layout is ORBIS
                       else self._vaddr_to_offset(base))

    def string(self, offset):
        start = self.strtab + offset
        end = self.data.find(b'\0', start, self.strtab + self.strsz)
        return self.data[start:end].decode('utf-8', 'replace')

    @property
    def soname(self):
        if DT_SONAME in self.tags:
            return self.string(self.tags[DT_SONAME][0])
        return None

    def _library_names(self):
        names = {}
        for tag in (self.layout['export'], self.layout['imp']):
            for value in self.tags.get(tag, []):
                names[value >> 48] = self.string(value & 0xFFFFFFFF)
        return names

    def _symbol_count(self, entsize):
        size = self.tags.get(self.layout['symtabsz'], [0])[0]
        if size and size % entsize == 0:
            return size // entsize
        # Some Prospero modules omit the size tag; DT_HASH's chain count covers
        # the same table.
        for value in self.tags.get(4, []):
            _, chains = struct.unpack_from('<II', self.data,
                                           self._vaddr_to_offset(value))
            if chains:
                return chains
        return 0

    def _read_symbols(self):
        exports = defaultdict(set)
        imports = []
        if self.strtab is None or self.layout['symtab'] not in self.tags:
            return exports, imports

        base = self.tags[self.layout['symtab']][0]
        symtab = (self.dynlibdata + base if self.layout is ORBIS
                  else self._vaddr_to_offset(base))
        libraries = self._library_names()

        for i in range(self._symbol_count(SYMBOL_ENTRY.size)):
            nameoff, _, _, shndx, value, _ = SYMBOL_ENTRY.unpack_from(
                self.data, symtab + i * SYMBOL_ENTRY.size)
            if not nameoff:
                continue
            parts = self.string(nameoff).split('#')
            if len(parts) != 3:
                continue
            nid, libtoken, _ = parts
            try:
                library = libraries.get(_token_id(libtoken), libtoken)
            except ValueError:
                continue
            if value or shndx:
                exports[library].add(nid)
            else:
                imports.append((library, nid))
        return exports, imports

    @property
    def ps4_sdk(self):
        return self._param_word(0x10)

    @property
    def ps5_sdk(self):
        return self._param_word(0x14)

    def _param_word(self, at):
        if self.param is None:
            return None
        magic, revision = struct.unpack_from('<II', self.data, self.param + 0x08)
        if magic not in (MODULE_PARAM_MAGIC, PROCESS_PARAM_MAGIC):
            return None
        if at == 0x14 and revision < 3:
            return None
        return struct.unpack_from('<I', self.data, self.param + at)[0]

    def export_pairs(self):
        """The exports as a set of (library, nid)."""
        return {(lib, nid) for lib, nids in self.exports.items() for nid in nids}


def read(path):
    """Parse path, or return None when it is not an ELF this can handle."""
    try:
        return Module(path)
    except (NotAnElf, ValueError, struct.error, IndexError, OSError):
        return None


def unself(data):
    """Rebuild a plain ELF from an unencrypted, uncompressed fake SELF
    (PS4 or PS5 magic). Byte-identical to the ELF inside a Sony-built SELF."""
    if data[:4] not in SELF_MAGICS:
        raise ValueError("not a SELF")
    count, = struct.unpack_from("<H", data, 0x18)
    entries = [struct.unpack_from("<QQQQ", data, 0x20 + i * 0x20) for i in range(count)]
    ehdr = 0x20 + count * 0x20
    phoff, = struct.unpack_from("<Q", data, ehdr + 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, ehdr + 0x36)
    phdrs = [struct.unpack_from("<IIQQQQQQ", data, ehdr + phoff + i * phentsize) for i in range(phnum)]
    size = max(ehdr + phoff + phnum * phentsize, *(p[2] + p[5] for p in phdrs))
    out = bytearray(size)
    out[:phoff + phnum * phentsize] = data[ehdr:ehdr + phoff + phnum * phentsize]
    for props, offset, filesz, _memsz in entries:
        # Bit 11 marks a blocked segment; bits 20-31 name the program header it backs.
        if not props & 0x800:
            continue
        if props & 0xa:
            raise ValueError("encrypted or compressed segment")
        index = (props >> 20) & 0xfff
        p_offset, p_filesz = phdrs[index][2], phdrs[index][5]
        out[p_offset:p_offset + p_filesz] = data[offset:offset + min(filesz, p_filesz)]
    # Headers outside every mapped segment (PT_NOTE, PT_SCE_VERSION) have no
    # entry; their data is packed in header order after the last mapped entry.
    end = max(o + f for _p, o, f, _m in entries)
    spans = [(phdrs[(p >> 20) & 0xfff][2], phdrs[(p >> 20) & 0xfff][2] + phdrs[(p >> 20) & 0xfff][5])
             for p, _o, _f, _m in entries if p & 0x800]
    for _t, _f, p_offset, _va, _pa, p_filesz, _ms, _al in phdrs:
        if not p_filesz or any(lo <= p_offset < hi for lo, hi in spans):
            continue
        out[p_offset:p_offset + p_filesz] = data[end:end + p_filesz].ljust(p_filesz, b"\0")
        end += p_filesz
    return bytes(out)

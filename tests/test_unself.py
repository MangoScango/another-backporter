import struct
import unittest

from ps5backport.elf import unself

SEGMENT = bytes(range(0x20))
VERSION = b"\x0fverrec\x01\x02\x03"


def make_self():
    """A minimal SELF wrapping an ELF with one PT_LOAD and one PT_SCE_VERSION.

    ELF layout: ehdr (64) + 2 phdrs (56 each) at 0x40; PT_LOAD file offset
    0x100 size 0x20; PT_SCE_VERSION offset 0x120 size 8, backed by no entry.
    SELF layout: 0x20 header, 1 entry (0x20), then ehdr+phdrs, segment data,
    and the version record packed after the last mapped entry.
    """
    ehdr = bytearray(0x40)
    ehdr[:4] = b"\x7fELF"
    struct.pack_into("<Q", ehdr, 0x20, 0x40)      # e_phoff
    struct.pack_into("<H", ehdr, 0x36, 56)        # e_phentsize
    struct.pack_into("<H", ehdr, 0x38, 2)         # e_phnum
    ph_load = struct.pack("<IIQQQQQQ", 1, 5, 0x100, 0x400000, 0x400000,
                          len(SEGMENT), len(SEGMENT), 0x1000)
    ph_ver = struct.pack("<IIQQQQQQ", 0x6FFFFF01, 4, 0x120, 0, 0,
                         len(VERSION), len(VERSION), 1)
    elf = bytes(ehdr) + ph_load + ph_ver
    elf = elf.ljust(0x100, b"\0") + SEGMENT + VERSION

    props = 0x800 | (0 << 20)  # blocked segment backing phdr 0
    entry_data_off = 0x20 + 0x20 + len(bytes(ehdr) + ph_load + ph_ver)
    entry = struct.pack("<QQQQ", props, entry_data_off, len(SEGMENT), len(SEGMENT))
    header = (b"\x4f\x15\x3d\x1d".ljust(0x18, b"\0")
              + struct.pack("<H", 1)).ljust(0x20, b"\0")
    self_data = header + entry + bytes(ehdr) + ph_load + ph_ver + SEGMENT + VERSION
    return self_data, elf


class UnselfTest(unittest.TestCase):
    def test_byte_identity(self):
        self_data, elf = make_self()
        self.assertEqual(unself(self_data), elf)

    def test_rejects_non_self(self):
        with self.assertRaises(ValueError):
            unself(b"\x7fELF" + b"\0" * 100)

    def test_rejects_encrypted_segment(self):
        self_data, _ = make_self()
        props, off, filesz, memsz = struct.unpack_from("<QQQQ", self_data, 0x20)
        bad = self_data[:0x20] + struct.pack("<QQQQ", props | 0x2, off, filesz, memsz) + self_data[0x40:]
        with self.assertRaises(ValueError):
            unself(bad)


if __name__ == "__main__":
    unittest.main()

"""diag.trap_at: ud2 lands at the requested vaddrs. Needs firmware dumps.
"""
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from ps5backport.diag import trap_at
from ps5backport.patch import Patcher, executable_segments

LIBS = Path(__file__).resolve().parent.parent / "data" / "PS5_Libs"
PAD = LIBS / "13.60" / "system" / "common" / "lib" / "libScePad.sprx"


@unittest.skipUnless(PAD.exists(), "firmware dumps not available")
class TrapAtTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "libScePad.sprx"
        shutil.copyfile(PAD, self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_ud2_at_vaddr(self):
        patcher = Patcher(str(self.path))
        offset, vaddr, _size = next(iter(executable_segments(patcher.data)))
        sites = [vaddr, vaddr + 0x100]
        sites_out = trap_at(sites)(patcher)
        self.assertEqual(sites_out, {"traps": sites})
        for va in sites:
            off = patcher.module._vaddr_to_offset(va)
            self.assertEqual(bytes(patcher.data[off:off + 2]), b"\x0f\x0b")
        # untouched between sites
        off = patcher.module._vaddr_to_offset(vaddr + 2)
        self.assertNotEqual(bytes(patcher.data[off:off + 2]), b"\x0f\x0b")

    def test_bad_vaddr_raises(self):
        patcher = Patcher(str(self.path))
        with self.assertRaises(ValueError):
            trap_at([0xDEADBEEF000])(patcher)


class DiagTitleTest(unittest.TestCase):
    def test_traps_required(self):
        from ps5backport.diag import diag_title
        with self.assertRaisesRegex(ValueError, "no trap sites"):
            diag_title(None, None, None, None, None, None, [], {})


if __name__ == "__main__":
    unittest.main()

"""Patcher.stamp on real firmware modules: lowered to the tier, never raised.

Needs the firmware dumps (the data/PS5_Libs symlink); skipped without them.
"""
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from ps5backport.config import TIERS, Config
from ps5backport.patch import Patcher

LIBS = Path(__file__).resolve().parent.parent / "data" / "PS5_Libs"
NEW = LIBS / "13.60" / "system" / "common" / "lib" / "libScePad.sprx"
OLD = LIBS / "1.00" / "lib" / "libScePad.sprx"  # oldest dumps have a flat lib/


@unittest.skipUnless(NEW.exists() and OLD.exists(), "firmware dumps not available")
class StampTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tier = TIERS["7xx"]

    def tearDown(self):
        self.tmp.cleanup()

    def _copy(self, src):
        dst = Path(self.tmp.name) / src.name
        shutil.copyfile(src, dst)
        return dst

    def words(self, path):
        p = Patcher(str(path))
        return struct.unpack_from("<II", p.data, p.module.param + 0x10)

    def test_lowers_new_module(self):
        path = self._copy(NEW)
        before = self.words(path)
        patcher = Patcher(str(path))
        self.assertTrue(patcher.stamp(self.tier))
        ps4, ps5 = struct.unpack_from("<II", patcher.data, patcher.module.param + 0x10)
        self.assertEqual(ps5, self.tier.stamp_ps5)
        self.assertEqual(ps4, self.tier.stamp_ps4)
        self.assertGreater(before[1], self.tier.stamp_ps5)

    def test_never_raises(self):
        path = self._copy(OLD)
        before = self.words(path)
        patcher = Patcher(str(path))
        self.assertFalse(patcher.stamp(self.tier))
        ps4, ps5 = struct.unpack_from("<II", patcher.data, patcher.module.param + 0x10)
        self.assertEqual((ps4, ps5), before)
        self.assertLessEqual(ps5, self.tier.stamp_ps5)

    def test_idempotent(self):
        path = self._copy(NEW)
        patcher = Patcher(str(path))
        patcher.stamp(self.tier)
        once = bytes(patcher.data)
        out = Path(self.tmp.name) / "stamped.sprx"
        patcher.write(out)
        again = Patcher(str(out))
        self.assertFalse(again.stamp(self.tier))


if __name__ == "__main__":
    unittest.main()

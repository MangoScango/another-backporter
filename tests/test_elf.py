import unittest
from pathlib import Path

from ps5backport.config import TIERS, Config
from ps5backport.elf import read

LIBS = Path(__file__).resolve().parent.parent / "data" / "PS5_Libs"
PAD = LIBS / "13.60" / "system" / "common" / "lib" / "libScePad.sprx"


@unittest.skipUnless(PAD.exists(), "firmware dumps not available")
class ModuleTest(unittest.TestCase):
    def test_parse_system_module(self):
        module = read(PAD)
        self.assertIsNotNone(module)
        self.assertEqual(module.flavour, "prospero")
        self.assertTrue(module.exports)
        self.assertIsNotNone(module.ps5_sdk)

    def test_export_pairs(self):
        module = read(PAD)
        pairs = module.export_pairs()
        self.assertTrue(all(isinstance(p, tuple) and len(p) == 2 for p in pairs))


class TierTest(unittest.TestCase):
    def test_seven_xx_stamp(self):
        tier = TIERS["7xx"]
        self.assertEqual((tier.stamp_ps5, tier.stamp_ps4), (0x07000038, 0x10590001))

    def test_config_defaults_inside_repo(self):
        cfg = Config.default()
        self.assertTrue(str(cfg.registry).endswith("registry/backport-stubs.csv"))
        self.assertEqual(cfg.source_override["libSceVideoOut.sprx"], "10.01")


if __name__ == "__main__":
    unittest.main()

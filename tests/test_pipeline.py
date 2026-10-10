"""End-to-end: run_title from a loose folder of SELFs through to a signed
backport folder, using a throwaway cache. Needs the data/ symlinks.
"""
import json
import tempfile
import unittest
from pathlib import Path

from ps5backport.build import run_title
from ps5backport.config import TIERS, Config
from ps5backport.exportdb import ExportDB
from ps5backport.registry import StubRegistry

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "data" / "binaries" / "PPSA17121"
REF = REPO / "reference" / "prototype" / "fakelibs-7xx" / "plan-7.01.json"


@unittest.skipUnless(SRC.exists() and REF.exists(), "cached binaries not available")
class RunTitleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = Config.default()
        cfg = Config(libs=base.libs,
                     cache=Path(cls.tmp.name) / "cache",
                     elf_cache=Path(cls.tmp.name) / "elf",
                     fwdb=base.fwdb, registry=base.registry,
                     make_fself=base.make_fself)
        db = ExportDB(cfg.fwdb)
        db.load_priv(cfg.libs, Path(cls.tmp.name) / "priv-exports.pkl")
        cls.out = Path(cls.tmp.name) / "out" / "PPSA17121"
        cls.plan, cls.report = run_title(cfg, TIERS["7xx"], StubRegistry(cfg.registry),
                                         db, SRC, cls.out, title="PPSA17121")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_same_fakelibs_as_universe_plan(self):
        ref = json.load(open(REF))["titles"]["PPSA17121"]["fakelibs"]
        self.assertEqual(sorted(self.plan.titles["PPSA17121"]["fakelibs"]), ref)

    def test_plan_json_written(self):
        plan = json.loads((self.out.parent / "PPSA17121-plan.json").read_text())
        self.assertIn("PPSA17121", plan["titles"])

    def test_backport_folder(self):
        self.assertTrue((self.out / "fakelib" / "libSceAgc.sprx").exists())
        self.assertTrue((self.out / "fakelib" / "libSceAgcDriver.sprx").exists())
        self.assertTrue((self.out / "eboot.bin").exists())
        self.assertIn("eboot.bin", self.report["files"])

    def test_unwrap_populated_elf_cache(self):
        # unwrap ran inside run_title and fed the planner
        self.assertTrue(self.plan.titles["PPSA17121"])


if __name__ == "__main__":
    unittest.main()

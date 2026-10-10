"""Game-supplied libraries the title doesn't carry are left unbound, not
stubbed (the Wolverine/libSceNpCppWebApi case). Needs the cached title.
"""
import tempfile
import unittest
from pathlib import Path

from ps5backport.build import build_title
from ps5backport.config import TIERS, Config
from ps5backport.exportdb import ExportDB
from ps5backport.plan import Planner
from ps5backport.registry import StubRegistry

REPO = Path(__file__).resolve().parent.parent
DUMP = REPO / "data" / "binaries-elf" / "PPSA03671"


@unittest.skipUnless(DUMP.exists(), "Wolverine not in the ELF cache")
class UnshippedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cfg = Config.default()
        db = ExportDB(cfg.fwdb)
        db.load_priv(cfg.libs, cfg.cache / "priv-exports.pkl")
        reg = StubRegistry(cfg.registry)
        plan = Planner(cfg, db, TIERS["7xx"], reg).plan([DUMP])
        fakelibs = sorted(plan.titles[DUMP.name]["fakelibs"])
        cls.report = build_title(cfg, TIERS["7xx"], reg, db, DUMP,
                                 Path(cls.tmp.name) / "out", fakelibs)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_np_cpp_web_api_left_unbound(self):
        unshipped = self.report["unshipped"]
        self.assertTrue(unshipped)
        self.assertTrue(all(u["library"] == "libSceNpCppWebApi" for u in unshipped))
        self.assertTrue(all(u["in"] == ["eboot.bin"] for u in unshipped))

    def test_no_stub_for_unshipped(self):
        for f in self.report["files"].values():
            for stub in f["stubs"].values():
                self.assertFalse(stub["key"].startswith("libSceNpCppWebApi:"))

    def test_all_stubs_reviewed(self):
        for f in self.report["files"].values():
            for stub in f["stubs"].values():
                self.assertEqual(stub["status"], "reviewed", stub)


if __name__ == "__main__":
    unittest.main()

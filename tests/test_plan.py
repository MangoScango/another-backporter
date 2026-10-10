"""Planner equivalence against the prototype's reference plan for 7.01.

Needs the firmware dumps and cached title ELFs (the data/ symlinks); skipped
when they are not available.
"""
import json
import unittest
from pathlib import Path

from ps5backport.config import Config, TIERS
from ps5backport.exportdb import ExportDB
from ps5backport.plan import Planner, UnresolvedImports
from ps5backport.registry import StubRegistry

REPO = Path(__file__).resolve().parent.parent
REF = REPO / "reference" / "prototype" / "fakelibs-7xx" / "plan-7.01.json"


@unittest.skipUnless(REF.exists() and (REPO / "data" / "binaries-elf").exists(),
                     "reference plan or cached ELFs not available")
class PlannerEquivalenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cfg = Config.default()
        db = ExportDB(cfg.fwdb)
        db.load_priv(cfg.libs, cfg.cache / "priv-exports.pkl")
        ref = json.load(open(REF))
        # Plan over exactly the titles the reference plan covers; the cache may
        # hold newer titles acquired since.
        titles = [cfg.elf_cache / name for name in sorted(ref["titles"])]
        cls.ref = ref
        cls.report = Planner(cfg, db, TIERS["7xx"], StubRegistry(cfg.registry)) \
            .plan(titles).to_json()

    def test_same_fakelibs(self):
        self.assertEqual(set(self.report["fakelibs"]), set(self.ref["fakelibs"]))

    def test_same_sources_titles_stubs(self):
        for m, r in self.ref["fakelibs"].items():
            mine = self.report["fakelibs"][m]
            self.assertEqual(mine["source"], r["source"], m)
            self.assertEqual(mine["titles"], r["titles"], m)
            self.assertEqual({s["nid"] for s in mine["stubs"]},
                             {s["nid"] for s in r["stubs"]}, m)

    def test_same_game_side(self):
        self.assertEqual({g["nid"] for g in self.report["game_side"]},
                         {g["nid"] for g in self.ref["game_side"]})

    def test_all_plan_stubs_reviewed(self):
        for m in self.report["fakelibs"].values():
            for s in m["stubs"]:
                self.assertEqual(s["status"], "reviewed", s)


class UnresolvedImportsTest(unittest.TestCase):
    def test_message_lists_every_import(self):
        err = UnresolvedImports([
            ("TITLEA", "eboot.bin", "libX", "nid1"),
            ("TITLEB", "sce_module/foo.prx", "libY", "nid2"),
        ])
        text = str(err)
        self.assertIn("TITLEA: eboot.bin imports libX:nid1", text)
        self.assertIn("TITLEB: sce_module/foo.prx imports libY:nid2", text)
        self.assertEqual(len(err.unresolved), 2)


if __name__ == "__main__":
    unittest.main()

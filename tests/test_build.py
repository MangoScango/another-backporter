import csv
import tempfile
import unittest
from pathlib import Path

from ps5backport.build import BuildError, _check_refused
from ps5backport.registry import StubRegistry

ROWS = [
    ("libA", "nidA0000001", "", "", "reviewed", "return0"),
    ("libB", "nidB0000001", "", "", "unreviewed", "return0"),
]


class CheckRefusedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = Path(self.tmp.name) / "stubs.csv"
        with open(path, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["library", "nid", "name", "since", "status", "stub"])
            w.writerows(ROWS)
        self.reg = StubRegistry(path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_lists_every_refusal_and_file(self):
        plan = [
            (Path("eboot.bin"), None, {("libB", "nidB0000001"), ("libZ", "nidZ0000009")}),
            (Path("sce_module/foo.prx"), None, {("libB", "nidB0000001")}),
        ]
        with self.assertRaises(BuildError) as ctx:
            _check_refused(self.reg, plan, allow_unreviewed=False)
        msg = str(ctx.exception)
        self.assertIn("libB:nidB0000001 (unreviewed)", msg)
        self.assertIn("libZ:nidZ0000009 (not in registry)", msg)
        self.assertIn("eboot.bin", msg)
        self.assertIn("sce_module/foo.prx", msg)
        self.assertIn("nothing written", msg)

    def test_clean_plan_passes(self):
        plan = [(Path("eboot.bin"), None, {("libA", "nidA0000001")})]
        _check_refused(self.reg, plan)


if __name__ == "__main__":
    unittest.main()

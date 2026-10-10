import csv
import tempfile
import unittest
from pathlib import Path

from ps5backport import registry
from ps5backport.registry import RegistryError, StubRegistry

ROWS = [
    # library, nid, name, since, status, stub
    ("libA", "nidA0000001", "", "", "reviewed", "return0"),
    ("libA", "nidA0000002", "", "", "reviewed", "trap"),
    ("libA", "nidA0000003", "", "", "reviewed", "b8ff002a80c3"),
    ("libA", "nidA0000004", "", "", "reviewed", "retarget:nidA0000001"),
    ("libB", "nidB0000001", "", "", "unreviewed", "return0"),
    ("libC", "nidC0000001", "", "", "rejected", "return0"),
]


def make_registry(tmp):
    path = Path(tmp) / "stubs.csv"
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["library", "nid", "name", "since", "status", "stub"])
        w.writerows(ROWS)
    return StubRegistry(path)


class RegistryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.reg = make_registry(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_refused_collects_everything(self):
        pairs = [("libC", "nidC0000001"), ("libB", "nidB0000001"),
                 ("libD", "nidD0000001")]
        refused = self.reg.refused(pairs)  # sorted by pair
        self.assertEqual([r for _, r in refused],
                         ["unreviewed", "rejected", "not in registry"])

    def test_require_raises_with_full_list(self):
        with self.assertRaises(RegistryError) as ctx:
            self.reg.require([("libB", "nidB0000001"), ("libD", "nidD0000001")])
        self.assertEqual(len(ctx.exception.refusals), 2)
        self.assertIn("libD:nidD0000001", str(ctx.exception))

    def test_require_passes_when_all_reviewed(self):
        self.reg.require([("libA", "nidA0000001"), ("libA", "nidA0000002")])

    def test_allow_unreviewed(self):
        self.assertEqual(self.reg.refused([("libB", "nidB0000001")],
                                          allow_unreviewed=True), [])
        self.assertEqual(self.reg.code(("libB", "nidB0000001"),
                                       allow_unreviewed=True),
                         registry.GADGET)

    def test_code_bytes(self):
        self.assertEqual(self.reg.code(("libA", "nidA0000001")), registry.GADGET)
        self.assertEqual(self.reg.code(("libA", "nidA0000002")), registry.TRAP)
        self.assertEqual(self.reg.code(("libA", "nidA0000003")),
                         bytes.fromhex("b8ff002a80c3"))

    def test_retarget_has_no_code(self):
        with self.assertRaises(ValueError):
            self.reg.code(("libA", "nidA0000004"))

    def test_refused_code_raises(self):
        with self.assertRaises(RegistryError):
            self.reg.code(("libD", "nidD0000001"))


if __name__ == "__main__":
    unittest.main()

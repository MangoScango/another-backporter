import unittest

from ps5backport import casefix


class CasefixTest(unittest.TestCase):
    def test_case_mismatch_found(self):
        exe = {"eboot.bin": b"\x00%s/Modules/Il2CppUserAssemblies.prx\x00"}
        shipped = ["Modules/Il2cppUserAssemblies.prx"]
        found = casefix.mismatches(exe, shipped)
        self.assertEqual(len(found), 1)
        owner, off, got, real = found[0]
        self.assertEqual(owner, "eboot.bin")
        self.assertEqual(got, "Il2CppUserAssemblies.prx")
        self.assertEqual(real, "Il2cppUserAssemblies.prx")
        # The offset points at the basename inside the string.
        self.assertEqual(exe["eboot.bin"][off:off + len(got)], got.encode())

    def test_exact_match_ignored(self):
        exe = {"eboot.bin": b"\x00Il2cppUserAssemblies.prx\x00"}
        shipped = ["Modules/Il2cppUserAssemblies.prx"]
        self.assertEqual(casefix.mismatches(exe, shipped), [])

    def test_ambiguous_match_ignored(self):
        exe = {"eboot.bin": b"\x00FOO.prx\x00"}
        shipped = ["a/Foo.prx", "b/foo.prx"]
        self.assertEqual(casefix.mismatches(exe, shipped), [])

    def test_same_name_in_any_directory(self):
        # Directory-name mismatches aren't handled; only the basename counts.
        exe = {"eboot.bin": b"\x00other/dir/Foo.prx\x00"}
        shipped = ["sce_module/foo.prx"]
        found = casefix.mismatches(exe, shipped)
        self.assertEqual(len(found), 1)

    def test_patchable_only_modules(self):
        # PS4-classics style "EBOOT.BIN" mismatches are warnings, not patches.
        self.assertFalse(casefix.patchable("EBOOT.BIN"))
        self.assertTrue(casefix.patchable("Il2cppUserAssemblies.prx"))
        self.assertTrue(casefix.patchable("libScePad.sprx"))

    def test_non_matching_strings_ignored(self):
        exe = {"eboot.bin": b"\x00some random string\x00savegame.dat\x00"}
        shipped = ["Modules/foo.prx"]
        self.assertEqual(casefix.mismatches(exe, shipped), [])


if __name__ == "__main__":
    unittest.main()

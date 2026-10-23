"""Acquire cache refresh and prospero-pub-cmd invocation tests."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from ps5backport.acquire import _pub_argv, acquire_loose, acquire_pkg, unwrap
from ps5backport.config import Config

CFG = Config(libs=Path("/l"), cache=Path("/c"), elf_cache=Path("/e"),
             fwdb=Path("/f"), registry=Path("/r"), make_fself=Path("/m"),
             pub_cmd=Path("/tools/prospero-pub-cmd.exe"))


class PubArgvTest(unittest.TestCase):
    def test_native_on_nt(self):
        with mock.patch("os.name", "nt"):
            self.assertEqual(_pub_argv(CFG, ["img_file_list"]),
                             ["/tools/prospero-pub-cmd.exe", "img_file_list"])

    def test_wine_elsewhere(self):
        with mock.patch("os.name", "posix"):
            self.assertEqual(_pub_argv(CFG, ["img_file_list"]),
                             ["wine", "/tools/prospero-pub-cmd.exe", "img_file_list"])

    def test_pub_cmd_required(self):
        cfg = Config(libs=Path("/l"), cache=Path("/c"), elf_cache=Path("/e"),
                     fwdb=Path("/f"), registry=Path("/r"), make_fself=Path("/m"))
        with self.assertRaises(RuntimeError):
            _pub_argv(cfg, ["img_file_list"])


class CacheTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.cfg = Config(libs=base / "libs", cache=base / "cache",
                          elf_cache=base / "elf", fwdb=base / "fwdb",
                          registry=base / "registry", make_fself=base / "make_fself")
        self.src = base / "src"
        self.src.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_same_size_change_reacquired_and_stale_removed(self):
        module = self.src / "sce_module"
        module.mkdir()
        (self.src / "eboot.bin").write_bytes(b"old")
        (module / "stale.prx").write_bytes(b"stale")
        out = acquire_loose(self.cfg, self.src, title="TITLE")

        (self.src / "eboot.bin").write_bytes(b"new")
        (module / "stale.prx").unlink()
        acquire_loose(self.cfg, self.src, title="TITLE")

        self.assertEqual((out / "eboot.bin").read_bytes(), b"new")
        self.assertFalse((out / "sce_module" / "stale.prx").exists())
        self.assertFalse((out / "sce_module").exists())

    def test_pkg_same_size_change_reacquired(self):
        pkg = self.src / "game.pkg"
        pkg.write_bytes(b"pkg")
        raw = self.cfg.cache / "TITLE"
        raw.mkdir(parents=True)
        (raw / "eboot.bin").write_bytes(b"old")

        def pub(_cfg, *args):
            if args[0] == "img_file_list":
                return SimpleNamespace(returncode=0, stdout="F 3 eboot.bin\n", stderr="")
            Path(args[-1]).write_bytes(b"new")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch("ps5backport.acquire._pub", side_effect=pub):
            out = acquire_pkg(self.cfg, pkg, title="TITLE")

        self.assertEqual((out / "eboot.bin").read_bytes(), b"new")

    def test_unwrap_removes_stale_elf_cache(self):
        raw = self.cfg.cache / "TITLE"
        raw.mkdir(parents=True)
        (raw / "eboot.bin").write_bytes(b"\x7fELF")
        stale = self.cfg.elf_cache / "TITLE" / "sce_module" / "stale.prx"
        stale.parent.mkdir(parents=True)
        stale.write_bytes(b"stale")

        unwrap(self.cfg, "TITLE")

        self.assertEqual((self.cfg.elf_cache / "TITLE" / "eboot.bin").read_bytes(),
                         b"\x7fELF")
        self.assertFalse(stale.exists())
        self.assertFalse(stale.parent.exists())


if __name__ == "__main__":
    unittest.main()

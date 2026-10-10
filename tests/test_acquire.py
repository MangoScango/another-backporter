"""acquire._pub_argv: prospero-pub-cmd runs natively on NT, via wine elsewhere."""
import unittest
from pathlib import Path
from unittest import mock

from ps5backport.acquire import _pub_argv
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


if __name__ == "__main__":
    unittest.main()

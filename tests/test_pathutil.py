from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import unittest

from contextcourier.pathutil import is_link_or_reparse, portable_posix_path


class PathUtilTests(unittest.TestCase):
    def test_portable_paths_reject_windows_and_control_hazards(self) -> None:
        for value in (
            "CON",
            "docs/NUL.txt",
            "name:stream",
            "trailing.",
            "trailing ",
            "C:/absolute.txt",
            "docs/escape\x1b.txt",
            "docs/reverse\u202etxt",
            "docs\\windows.txt",
        ):
            with self.subTest(value=repr(value)):
                self.assertIsNone(portable_posix_path(value))
        self.assertEqual(portable_posix_path("docs/valid-name.md"), "docs/valid-name.md")

    def test_python_311_windows_reparse_attribute_is_detected(self) -> None:
        fake_stat = SimpleNamespace(st_file_attributes=0x400)
        self.assertTrue(is_link_or_reparse(Path("ordinary-looking-path"), fake_stat))

    def test_plain_file_attributes_are_not_reparse(self) -> None:
        fake_stat = SimpleNamespace(st_file_attributes=0)
        self.assertFalse(is_link_or_reparse(Path("ordinary-looking-path"), fake_stat))


if __name__ == "__main__":
    unittest.main()

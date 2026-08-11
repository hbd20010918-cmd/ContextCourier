from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from contextcourier.archive import build_archive, verify_archive
from contextcourier.config import Config
from contextcourier.errors import ScanError
from contextcourier.models import GitInfo
from contextcourier.scanner import scan_project


class ScannerTests(unittest.TestCase):
    def test_nonportable_candidate_paths_are_skipped_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ok.txt").write_text("safe\n", encoding="utf-8")
            candidates = ["CON", "files/name:stream", "trailing.", "ok.txt"]
            with (
                patch("contextcourier.scanner.git_file_list", return_value=candidates),
                patch("contextcourier.scanner.snapshot_token", return_value=None),
                patch("contextcourier.scanner.git_info", return_value=GitInfo()),
            ):
                scan = scan_project(root, Config())

            self.assertEqual([item.path for item in scan.files], ["ok.txt"])
            self.assertEqual(
                sum(item.reason == "unsafe_path" for item in scan.skipped), 3
            )

    def test_unicode_normalization_collision_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            composed = "caf\u00e9.txt"
            decomposed = "cafe\u0301.txt"
            (root / composed).write_text("first\n", encoding="utf-8")
            (root / decomposed).write_text("second\n", encoding="utf-8")
            names = set(os.listdir(root))
            if composed not in names or decomposed not in names:
                self.skipTest("Filesystem does not preserve distinct NFC/NFD names")
            with (
                patch(
                    "contextcourier.scanner.git_file_list",
                    return_value=[composed, decomposed],
                ),
                patch("contextcourier.scanner.snapshot_token", return_value=None),
                patch("contextcourier.scanner.git_info", return_value=GitInfo()),
                self.assertRaises(ScanError),
            ):
                scan_project(root, Config())

    def test_bidi_git_branch_is_safely_replaced_and_archive_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("# demo\n", encoding="utf-8")
            git = GitInfo(
                available=True,
                branch="feature/reverse\u202etxt",
                commit=None,
                dirty=False,
            )
            with (
                patch(
                    "contextcourier.scanner.git_file_list", return_value=["README.md"]
                ),
                patch("contextcourier.scanner.snapshot_token", return_value="stable"),
                patch("contextcourier.scanner.git_info", return_value=git),
            ):
                scan = scan_project(root, Config())
            self.assertNotIn("\u202e", scan.git.branch or "")
            self.assertEqual(scan.metadata_redactions["UNSAFE_METADATA"], 1)

            output = root / "bidi.contextcourier.zip"
            build_archive(scan, Config(), output)
            self.assertEqual(verify_archive(output)["integrity"], "VERIFIED")


if __name__ == "__main__":
    unittest.main()

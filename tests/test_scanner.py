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
from contextcourier.scanner import _walk_files, scan_project


class ScannerTests(unittest.TestCase):
    def test_nonportable_candidate_paths_are_skipped_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ok.txt").write_text("safe\n", encoding="utf-8")
            candidates = ["CON", "files/name:stream", "trailing.", "ok.txt"]
            with (
                patch("contextcourier.scanner.git_file_list", return_value=candidates),
                patch("contextcourier.scanner.snapshot_token", return_value="stable"),
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
                patch("contextcourier.scanner.snapshot_token", return_value="stable"),
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

    def test_linked_directory_cannot_alias_an_immutable_exclusion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected = root / ".aws"
            protected.mkdir()
            (protected / "opaque.txt").write_text("must stay excluded\n", encoding="utf-8")
            alias = root / "public-alias"
            try:
                alias.symlink_to(protected, target_is_directory=True)
            except OSError:
                self.skipTest("Directory symlinks are not available in this environment")
            with (
                patch(
                    "contextcourier.scanner.git_file_list",
                    return_value=["public-alias/opaque.txt"],
                ),
                patch("contextcourier.scanner.snapshot_token", return_value="stable"),
                patch("contextcourier.scanner.git_info", return_value=GitInfo()),
            ):
                scan = scan_project(root, Config())

            self.assertEqual(scan.files, [])
            self.assertEqual(scan.skipped[0].reason, "symlink_or_junction")

    def test_late_nul_marks_the_entire_file_as_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "late.txt").write_bytes((b"A" * 8192) + b"\0tail")
            with (
                patch("contextcourier.scanner.git_file_list", return_value=["late.txt"]),
                patch("contextcourier.scanner.snapshot_token", return_value="stable"),
                patch("contextcourier.scanner.git_info", return_value=GitInfo()),
            ):
                scan = scan_project(root, Config())

            self.assertEqual(scan.files, [])
            self.assertEqual(scan.skipped[0].reason, "binary_content")

    def test_nfd_ignore_rule_excludes_nfd_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            decomposed = "cafe\u0301.txt"
            (root / decomposed).write_text("private\n", encoding="utf-8")
            (root / ".contextcourierignore").write_text(
                decomposed + "\n", encoding="utf-8"
            )
            with (
                patch(
                    "contextcourier.scanner.git_file_list",
                    return_value=[decomposed],
                ),
                patch("contextcourier.scanner.snapshot_token", return_value="stable"),
                patch("contextcourier.scanner.git_info", return_value=GitInfo()),
            ):
                scan = scan_project(root, Config())

            self.assertEqual(scan.files, [])
            self.assertEqual(scan.skipped[0].reason, "project_ignore")

    def test_surrogate_git_path_is_skipped_without_decode_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch(
                    "contextcourier.scanner.git_file_list",
                    return_value=["invalid-\udcff.txt"],
                ),
                patch("contextcourier.scanner.snapshot_token", return_value="stable"),
                patch("contextcourier.scanner.git_info", return_value=GitInfo()),
            ):
                scan = scan_project(root, Config())

            self.assertEqual(scan.files, [])
            self.assertEqual(scan.skipped[0].reason, "unsafe_path")

    def test_fallback_enumeration_stops_at_the_entry_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(3):
                (root / f"file-{index}.txt").write_text("x\n", encoding="utf-8")
            with (
                patch("contextcourier.scanner.HARD_MAX_CANDIDATES", 2),
                self.assertRaises(ScanError),
            ):
                _walk_files(root)

    def test_ignore_match_work_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".contextcourierignore").write_text("private/\n", encoding="utf-8")
            deep_path = (("nested/" * 10) + "value.txt").rstrip("/")
            with (
                patch(
                    "contextcourier.scanner.git_file_list",
                    return_value=[deep_path],
                ),
                patch("contextcourier.scanner.snapshot_token", return_value="stable"),
                patch("contextcourier.scanner.MAX_IGNORE_MATCH_WORK", 5),
                self.assertRaises(ScanError),
            ):
                scan_project(root, Config())

    def test_ignore_policy_change_during_scan_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "public.txt").write_text("public\n", encoding="utf-8")
            policy = root / ".contextcourierignore"
            policy.write_text("private/\n", encoding="utf-8")

            def mutate_policy(*args: object, **kwargs: object) -> GitInfo:
                policy.write_text("private/\ninternal/\n", encoding="utf-8")
                return GitInfo()

            with (
                patch(
                    "contextcourier.scanner.git_file_list",
                    return_value=["public.txt"],
                ),
                patch("contextcourier.scanner.snapshot_token", return_value="stable"),
                patch("contextcourier.scanner.git_info", side_effect=mutate_policy),
                self.assertRaises(ScanError),
            ):
                scan_project(root, Config())

    def test_git_snapshot_degradation_at_end_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "public.txt").write_text("public\n", encoding="utf-8")
            with (
                patch(
                    "contextcourier.scanner.git_file_list",
                    return_value=["public.txt"],
                ),
                patch(
                    "contextcourier.scanner.snapshot_token",
                    side_effect=["stable", None],
                ),
                patch("contextcourier.scanner.git_info", return_value=GitInfo()),
                self.assertRaises(ScanError),
            ):
                scan_project(root, Config())

    def test_atomically_initialized_regular_file_is_not_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged = root / "staged.tmp"
            target = root / ".contextcourier.toml"
            staged.write_text("[contextcourier]\n", encoding="utf-8")
            os.replace(staged, target)
            with (
                patch(
                    "contextcourier.scanner.git_file_list",
                    return_value=[".contextcourier.toml"],
                ),
                patch("contextcourier.scanner.snapshot_token", return_value="stable"),
                patch("contextcourier.scanner.git_info", return_value=GitInfo()),
            ):
                scan = scan_project(root, Config())

            self.assertEqual([item.path for item in scan.files], [".contextcourier.toml"])

    def test_skipped_binary_reads_count_toward_inspection_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = [f"binary-{index}.txt" for index in range(4)]
            for name in names:
                (root / name).write_bytes(b"\0" * 600)
            config = Config(max_file_size=1024, max_total_size=1024, max_files=10)
            with (
                patch("contextcourier.scanner.git_file_list", return_value=names),
                patch("contextcourier.scanner.snapshot_token", return_value="stable"),
                patch("contextcourier.scanner.git_info", return_value=GitInfo()),
                self.assertRaises(ScanError),
            ):
                scan_project(root, config)


if __name__ == "__main__":
    unittest.main()

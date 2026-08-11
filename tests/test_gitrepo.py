from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from contextcourier.config import Config
from contextcourier.errors import ScanError
from contextcourier.gitrepo import (
    _decode_nul_paths,
    _find_git_executable,
    _run_git,
    _status_args,
    locate_root,
    snapshot_token,
)
from contextcourier.scanner import scan_project


class GitDiscoveryTests(unittest.TestCase):
    def _require_git(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("Git is required for this integration test")

    def test_tracked_file_later_ignored_is_excluded_for_privacy(self) -> None:
        self._require_git()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "tracked.txt").write_text("private draft\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(root), "add", "tracked.txt"],
                check=True,
            )
            (root / ".gitignore").write_text("tracked.txt\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(root), "add", ".gitignore"],
                check=True,
            )

            scan = scan_project(root, Config())
            selected = {item.path for item in scan.files}

            self.assertNotIn("tracked.txt", selected)
            self.assertIn(".gitignore", selected)

    def test_unborn_repository_snapshot_detects_new_candidates(self) -> None:
        self._require_git()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            before = snapshot_token(root)
            self.assertIsNotNone(before)
            (root / "new.txt").write_text("new candidate\n", encoding="utf-8")
            after = snapshot_token(root)
            self.assertIsNotNone(after)
            self.assertNotEqual(before, after)

    def test_git_routing_environment_cannot_redirect_repository(self) -> None:
        self._require_git()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            requested = base / "requested"
            attacker = base / "attacker"
            subprocess.run(["git", "init", "-q", str(requested)], check=True)
            subprocess.run(["git", "init", "-q", str(attacker)], check=True)
            environment = {
                "GIT_DIR": str(attacker / ".git"),
                "GIT_WORK_TREE": str(attacker),
                "GIT_INDEX_FILE": str(attacker / ".git" / "index"),
                "GIT_LITERAL_PATHSPECS": "1",
                "GIT_TRACE2_EVENT": str(base / "trace.json"),
            }
            with patch.dict(os.environ, environment, clear=False):
                self.assertEqual(locate_root(requested), requested.resolve())
            self.assertFalse((base / "trace.json").exists())

    def test_git_subdirectory_is_not_silently_broadened_to_repository(self) -> None:
        self._require_git()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            chosen = root / "chosen"
            chosen.mkdir()
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            with self.assertRaises(ScanError):
                locate_root(chosen)

    def test_repository_local_git_executable_is_never_selected(self) -> None:
        self._require_git()
        actual = Path(shutil.which("git") or "").resolve(strict=True)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            planted = root / ("git.exe" if os.name == "nt" else "git")
            planted.write_bytes(b"not an executable that should run\n")
            if os.name != "nt":
                planted.chmod(0o755)
            safe_path = os.pathsep.join((str(root), str(actual.parent)))
            with patch.dict(os.environ, {"PATH": safe_path}, clear=False):
                selected = _find_git_executable(root)

            self.assertEqual(Path(selected or "").resolve(), actual)

    def test_non_utf8_git_paths_decode_fail_closed_instead_of_crashing(self) -> None:
        decoded = _decode_nul_paths(b"valid.txt\0invalid-\xff.txt\0")

        self.assertEqual(decoded[0], "valid.txt")
        self.assertIn("\udcff", decoded[1])

    def test_git_path_count_is_checked_before_materializing_strings(self) -> None:
        with (
            patch("contextcourier.gitrepo.HARD_MAX_CANDIDATES", 2),
            self.assertRaises(ScanError),
        ):
            _decode_nul_paths(b"a\0b\0c\0")

    def test_git_commands_disable_external_protocols_and_lazy_fetch(self) -> None:
        self._require_git()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            executable = _find_git_executable(root)
            self.assertIsNotNone(executable)
            captured: dict[str, object] = {}
            real_popen = subprocess.Popen

            def recording_popen(*args: object, **kwargs: object):
                captured["command"] = args[0]
                captured["environment"] = kwargs.get("env")
                return real_popen(*args, **kwargs)

            with patch(
                "contextcourier.gitrepo.subprocess.Popen",
                side_effect=recording_popen,
            ):
                _run_git(
                    root,
                    ["rev-parse", "--is-inside-work-tree"],
                    check=True,
                    git_executable=executable or "",
                )

            command = captured["command"]
            environment = captured["environment"]
            self.assertIn("protocol.allow=never", command)
            self.assertIn("protocol.ext.allow=never", command)
            self.assertIn("submodule.recurse=false", command)
            self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
            self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
            self.assertIn("--ignore-submodules=all", _status_args(None))


if __name__ == "__main__":
    unittest.main()

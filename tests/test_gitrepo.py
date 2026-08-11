from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from contextcourier.config import Config
from contextcourier.gitrepo import locate_root, snapshot_token
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
            }
            with patch.dict(os.environ, environment, clear=False):
                self.assertEqual(locate_root(requested), requested.resolve())


if __name__ == "__main__":
    unittest.main()

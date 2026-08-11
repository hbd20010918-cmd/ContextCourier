from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from contextcourier.errors import ConfigError
from contextcourier.ignore import always_excluded, ignored_by_rules, load_rules


class IgnoreTests(unittest.TestCase):
    def test_credential_containers_are_always_excluded(self) -> None:
        self.assertTrue(always_excluded(".env"))
        self.assertTrue(always_excluded("config/.env.production"))
        self.assertTrue(always_excluded("keys/server.pem"))
        self.assertTrue(always_excluded(".codex/session.json"))
        self.assertTrue(always_excluded(".docker/config.json"))
        self.assertTrue(always_excluded(".aws/credentials"))
        self.assertTrue(always_excluded(".git-credentials"))
        self.assertFalse(always_excluded(".env.example"))
        self.assertFalse(always_excluded("src/secrets.py"))

    def test_project_ignore_is_deny_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".contextcourierignore").write_text(
                "reports/\n*.egg-info/\n*.snapshot\n",
                encoding="utf-8",
            )
            rules = load_rules(root)

            self.assertTrue(ignored_by_rules("reports/a.txt", rules))
            self.assertTrue(ignored_by_rules("src/demo.egg-info/PKG-INFO", rules))
            self.assertTrue(ignored_by_rules("tests/a.snapshot", rules))
            self.assertFalse(ignored_by_rules("src/a.py", rules))

    def test_negation_rule_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".contextcourierignore").write_text("!private.txt\n", encoding="utf-8")

            with self.assertRaises(ConfigError):
                load_rules(root)

    def test_project_ignore_invalid_utf8_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".contextcourierignore").write_bytes(b"private/\n\xff\n")
            with self.assertRaises(ConfigError):
                load_rules(root)

    def test_gitignore_fallback_remains_best_effort(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".gitignore").write_bytes(b"private/\n\xff\n")
            rules = load_rules(root, include_gitignore_fallback=True)
            self.assertTrue(ignored_by_rules("private/value.txt", rules))


if __name__ == "__main__":
    unittest.main()

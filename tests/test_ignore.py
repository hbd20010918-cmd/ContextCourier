from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from contextcourier.errors import ConfigError
from contextcourier.ignore import (
    MAX_IGNORE_RULES,
    IgnoreRule,
    always_excluded,
    ignored_by_rules,
    load_rules,
)


class IgnoreTests(unittest.TestCase):
    def test_credential_containers_are_always_excluded(self) -> None:
        self.assertTrue(always_excluded(".env"))
        self.assertTrue(always_excluded("config/.env.production"))
        self.assertTrue(always_excluded(".env.production/value.txt"))
        self.assertTrue(always_excluded("keys/server.pem/value.txt"))
        self.assertTrue(always_excluded("keys/server.pem"))
        self.assertTrue(always_excluded("keys/server.ppk"))
        self.assertTrue(always_excluded("keys/server.ppk.bak"))
        self.assertTrue(always_excluded("terraform.tfstate"))
        self.assertTrue(always_excluded("terraform.tfstate.backup"))
        self.assertTrue(always_excluded(".codex/session.json"))
        self.assertTrue(always_excluded(".docker/config.json"))
        self.assertTrue(always_excluded(".aws/credentials"))
        self.assertTrue(always_excluded(".git-credentials"))
        self.assertTrue(always_excluded(".npmrc.bak"))
        self.assertTrue(always_excluded("credentials.json.backup"))
        self.assertTrue(always_excluded("id_rsa.old"))
        self.assertTrue(always_excluded("keys/server.pem.orig"))
        self.assertTrue(always_excluded("vault.kdbx~"))
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

    def test_project_ignore_accepts_utf8_bom_without_losing_first_rule(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".contextcourierignore").write_bytes(
                b"\xef\xbb\xbfprivate/\nreports/\n"
            )
            rules = load_rules(root)
            self.assertTrue(ignored_by_rules("private/value.txt", rules))
            self.assertTrue(ignored_by_rules("reports/value.txt", rules))

    def test_gitignore_fallback_remains_best_effort(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".gitignore").write_bytes(b"private/\n\xff\n")
            rules = load_rules(root, include_gitignore_fallback=True)
            self.assertTrue(ignored_by_rules("private/value.txt", rules))

    def test_gitignore_negation_cannot_override_project_privacy_deny(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".contextcourierignore").write_text(
                "private/\n", encoding="utf-8"
            )
            (root / ".gitignore").write_text(
                "!private/value.txt\n", encoding="utf-8"
            )

            rules = load_rules(root, include_gitignore_fallback=True)

            self.assertTrue(ignored_by_rules("private/value.txt", rules))

    def test_ignore_rules_match_unicode_in_canonical_form(self) -> None:
        decomposed = "cafe\u0301.txt"
        self.assertTrue(
            ignored_by_rules(decomposed, [IgnoreRule(pattern=decomposed)])
        )

    def test_ignore_rule_count_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rules = "".join(f"private-{index}/\n" for index in range(MAX_IGNORE_RULES + 1))
            (root / ".contextcourierignore").write_text(rules, encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_rules(root)

    def test_policy_opened_handle_must_match_the_checked_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / ".contextcourierignore"
            alternate = root / "alternate.ignore"
            policy.write_text("private/\n", encoding="utf-8")
            alternate.write_text("public/\n", encoding="utf-8")
            original_open = Path.open

            def redirected_open(path: Path, *args: object, **kwargs: object):
                target = alternate if path == policy else path
                return original_open(target, *args, **kwargs)

            with (
                patch.object(Path, "open", redirected_open),
                self.assertRaises(ConfigError),
            ):
                load_rules(root)


if __name__ == "__main__":
    unittest.main()

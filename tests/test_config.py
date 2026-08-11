from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from contextcourier.config import (
    Config,
    HARD_MAX_FILE_SIZE,
    HARD_MAX_FILES,
    HARD_MAX_TOTAL_SIZE,
    MAX_POLICY_FILE_BYTES,
)
from contextcourier.errors import ConfigError


class ConfigTests(unittest.TestCase):
    def test_unknown_top_level_table_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".contextcourier.toml").write_text(
                "[contextcourier_typo]\nmax_files = 1\n", encoding="utf-8"
            )
            with self.assertRaises(ConfigError):
                Config.load(root)

    def test_hard_limits_apply_to_files_and_api_overrides(self) -> None:
        cases = (
            ("max_file_size", HARD_MAX_FILE_SIZE),
            ("max_total_size", HARD_MAX_TOTAL_SIZE),
            ("max_files", HARD_MAX_FILES),
        )
        for name, maximum in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / ".contextcourier.toml").write_text(
                    f"[contextcourier]\n{name} = {maximum + 1}\n", encoding="utf-8"
                )
                with self.assertRaises(ConfigError):
                    Config.load(root)
                with self.assertRaises(ConfigError):
                    Config().with_overrides(**{name: maximum + 1})

    def test_zero_and_negative_overrides_are_rejected(self) -> None:
        for value in (0, -1):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                Config().with_overrides(max_files=value)

    def test_config_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "policy.toml"
            target.write_text("[contextcourier]\nmax_files = 1\n", encoding="utf-8")
            link = root / ".contextcourier.toml"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("File symlinks are not available in this environment")
            with self.assertRaises(ConfigError):
                Config.load(root)

    def test_config_accepts_utf8_bom(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".contextcourier.toml").write_bytes(
                b"\xef\xbb\xbf[contextcourier]\nmax_files = 7\n"
            )
            self.assertEqual(Config.load(root).max_files, 7)

    def test_oversized_config_is_rejected_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / ".contextcourier.toml"
            with path.open("wb") as handle:
                handle.truncate(MAX_POLICY_FILE_BYTES + 1)
            with self.assertRaises(ConfigError):
                Config.load(root)

    def test_loaded_config_detects_policy_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / ".contextcourier.toml"
            path.write_text("[contextcourier]\nmax_files = 7\n", encoding="utf-8")
            config = Config.load(root)
            path.write_text("[contextcourier]\nmax_files = 8\n", encoding="utf-8")

            with self.assertRaises(ConfigError):
                config.assert_source_unchanged(root)


if __name__ == "__main__":
    unittest.main()

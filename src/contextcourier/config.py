"""Configuration loading with strict limits and no runtime dependencies."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
import stat
import tomllib

from .errors import ConfigError
from .pathutil import is_link_or_reparse


CONFIG_FILENAME = ".contextcourier.toml"
IGNORE_FILENAME = ".contextcourierignore"
HARD_MAX_FILE_SIZE = 8 * 1024 * 1024
HARD_MAX_TOTAL_SIZE = 48 * 1024 * 1024
HARD_MAX_FILES = 10_000
HARD_MAX_CANDIDATES = 100_000

DEFAULT_CONFIG_TEXT = """# ContextCourier project policy
[contextcourier]
# Text files larger than this are skipped.
max_file_size = 1048576
# Maximum total size of redacted file content in one pack.
max_total_size = 26214400
# Maximum number of files in one pack.
max_files = 5000
# Include untracked files that are not ignored by Git.
include_untracked = true
"""

DEFAULT_IGNORE_TEXT = """# Additional project-specific exclusions.
# Git's own ignore rules are respected when Git is available.
# Built-in credential and private-key exclusions cannot be overridden.

# Generated data
coverage/
reports/
tmp/

# Add private project paths below, for example:
# internal/customer-data/
"""


@dataclass(frozen=True)
class Config:
    max_file_size: int = 1024 * 1024
    max_total_size: int = 25 * 1024 * 1024
    max_files: int = 5000
    include_untracked: bool = True

    @classmethod
    def load(cls, root: Path) -> "Config":
        path = root / CONFIG_FILENAME
        try:
            details = path.lstat()
        except FileNotFoundError:
            return cls()
        except OSError as exc:
            raise ConfigError(f"Cannot inspect {CONFIG_FILENAME}") from exc
        if not stat.S_ISREG(details.st_mode) or is_link_or_reparse(path, details):
            raise ConfigError(f"{CONFIG_FILENAME} must be a regular, non-link file")
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"Cannot read {CONFIG_FILENAME}: {exc}") from exc
        unknown_tables = sorted(set(data) - {"contextcourier"})
        if unknown_tables:
            raise ConfigError(f"Unknown top-level config key(s): {', '.join(unknown_tables)}")
        table = data.get("contextcourier", {})
        if not isinstance(table, dict):
            raise ConfigError("[contextcourier] must be a TOML table")

        allowed = {
            "max_file_size",
            "max_total_size",
            "max_files",
            "include_untracked",
        }
        unknown = sorted(set(table) - allowed)
        if unknown:
            raise ConfigError(f"Unknown config key(s): {', '.join(unknown)}")

        config = cls(
            max_file_size=_bounded_int(
                table.get("max_file_size", cls.max_file_size),
                "max_file_size",
                HARD_MAX_FILE_SIZE,
            ),
            max_total_size=_bounded_int(
                table.get("max_total_size", cls.max_total_size),
                "max_total_size",
                HARD_MAX_TOTAL_SIZE,
            ),
            max_files=_bounded_int(
                table.get("max_files", cls.max_files),
                "max_files",
                HARD_MAX_FILES,
            ),
            include_untracked=_bool(
                table.get("include_untracked", cls.include_untracked),
                "include_untracked",
            ),
        )
        if config.max_file_size > config.max_total_size:
            raise ConfigError("max_file_size cannot exceed max_total_size")
        return config

    def with_overrides(
        self,
        *,
        max_file_size: int | None = None,
        max_total_size: int | None = None,
        max_files: int | None = None,
    ) -> "Config":
        result = replace(
            self,
            max_file_size=(
                _bounded_int(max_file_size, "max_file_size", HARD_MAX_FILE_SIZE)
                if max_file_size is not None
                else self.max_file_size
            ),
            max_total_size=(
                _bounded_int(max_total_size, "max_total_size", HARD_MAX_TOTAL_SIZE)
                if max_total_size is not None
                else self.max_total_size
            ),
            max_files=(
                _bounded_int(max_files, "max_files", HARD_MAX_FILES)
                if max_files is not None
                else self.max_files
            ),
        )
        if result.max_file_size > result.max_total_size:
            raise ConfigError("max_file_size cannot exceed max_total_size")
        return result


def _bounded_int(value: object, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{name} must be a positive integer")
    if value > maximum:
        raise ConfigError(f"{name} exceeds the hard safety limit of {maximum}")
    return value


def _bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{name} must be true or false")
    return value

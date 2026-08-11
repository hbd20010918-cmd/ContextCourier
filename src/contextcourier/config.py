"""Configuration loading with strict limits and no runtime dependencies."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import os
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
MAX_POLICY_FILE_BYTES = 1024 * 1024

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
    _source_token: str | None = field(default=None, repr=False, compare=False)

    @classmethod
    def load(cls, root: Path) -> "Config":
        path = root / CONFIG_FILENAME
        raw = _read_config_bytes(path)
        source_token = _policy_token(raw)
        if raw is None:
            return cls(_source_token=source_token)
        try:
            data = tomllib.loads(raw.decode("utf-8-sig"))
        except (UnicodeError, tomllib.TOMLDecodeError) as exc:
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
            _source_token=source_token,
        )
        if config.max_file_size > config.max_total_size:
            raise ConfigError("max_file_size cannot exceed max_total_size")
        return config

    def assert_source_unchanged(self, root: Path) -> None:
        """Fail closed if a policy loaded by :meth:`load` changed mid-operation."""
        if self._source_token is None:
            return
        current = _policy_token(_read_config_bytes(root / CONFIG_FILENAME))
        if current != self._source_token:
            raise ConfigError(f"{CONFIG_FILENAME} changed while the project was scanned")

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


def _read_config_bytes(path: Path) -> bytes | None:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ConfigError(f"Cannot inspect {CONFIG_FILENAME}") from exc
    if not stat.S_ISREG(before.st_mode) or is_link_or_reparse(path, before):
        raise ConfigError(f"{CONFIG_FILENAME} must be a regular, non-link file")
    if before.st_size > MAX_POLICY_FILE_BYTES:
        raise ConfigError(f"{CONFIG_FILENAME} exceeds the policy file safety limit")
    try:
        with path.open("rb") as handle:
            opened = _stat_identity(handle.fileno())
            raw = handle.read(MAX_POLICY_FILE_BYTES + 1)
        after = path.lstat()
    except OSError as exc:
        raise ConfigError(f"Cannot read {CONFIG_FILENAME}") from exc
    if len(raw) > MAX_POLICY_FILE_BYTES:
        raise ConfigError(f"{CONFIG_FILENAME} exceeds the policy file safety limit")
    if (
        opened != _stat_identity(before)
        or _stat_identity(after) != opened
        or _stat_version(before) != _stat_version(after)
    ):
        raise ConfigError(f"{CONFIG_FILENAME} changed while it was read")
    return raw


def _stat_identity(value: int | os.stat_result) -> tuple[int, int, int, int]:
    details = os.fstat(value) if isinstance(value, int) else value
    return (
        details.st_size,
        details.st_mtime_ns,
        getattr(details, "st_dev", 0),
        getattr(details, "st_ino", 0),
    )


def _stat_version(details: os.stat_result) -> tuple[int, int, int]:
    return (details.st_size, details.st_mtime_ns, details.st_ctime_ns)


def _policy_token(raw: bytes | None) -> str:
    digest = hashlib.sha256()
    digest.update(b"missing\0" if raw is None else b"present\0")
    if raw is not None:
        digest.update(raw)
    return digest.hexdigest()

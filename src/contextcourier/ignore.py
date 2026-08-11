"""Layered path filtering: immutable safety rules plus user ignore rules."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import unicodedata

from .config import IGNORE_FILENAME, MAX_POLICY_FILE_BYTES
from .errors import ConfigError
from .pathutil import is_link_or_reparse


ALWAYS_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".codex",
    ".claude",
    ".cursor",
    ".aws",
    ".azure",
    ".docker",
    ".gcloud",
    ".gnupg",
    ".kube",
    ".ssh",
    ".terraform",
    ".idea",
    ".vscode",
    ".venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "node_modules",
    "bower_components",
    "vendor",
    "target",
    "build",
    "dist",
}

ALWAYS_EXCLUDED_BASENAMES = {
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    ".dockerconfigjson",
    "credentials.json",
    "service-account.json",
    "auth.json",
    "cookies.sqlite",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
}

ALWAYS_EXCLUDED_SUFFIXES = {
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".ppk",
    ".jks",
    ".keystore",
    ".kdbx",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".contextcourier.zip",
}

SAFE_ENV_TEMPLATES = {
    ".env.example",
    ".env.sample",
    ".env.template",
}
SENSITIVE_BACKUP_SUFFIXES = (".backup", ".orig", ".save", ".bak", ".old", "~")
MAX_IGNORE_RULES = 512
MAX_IGNORE_PATTERN_BYTES = 1024


@dataclass(frozen=True)
class IgnoreRule:
    pattern: str
    negated: bool = False
    deny_only: bool = False


def normalize_relative(path: str | Path) -> str:
    value = str(path).replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return value.strip("/")


def always_excluded(path: str | Path) -> bool:
    rel = unicodedata.normalize("NFC", normalize_relative(path))
    if not rel:
        return False
    parts = PurePosixPath(rel).parts
    lowered_parts = tuple(part.lower() for part in parts)
    if any(
        part in ALWAYS_EXCLUDED_DIRS
        or part.endswith(".egg-info")
        or _sensitive_component(part, allow_safe_env_template=False)
        for part in lowered_parts[:-1]
    ):
        return True
    name = lowered_parts[-1]
    if name in ALWAYS_EXCLUDED_DIRS or name in ALWAYS_EXCLUDED_BASENAMES:
        return True
    return _sensitive_component(name, allow_safe_env_template=True)


def _sensitive_component(name: str, *, allow_safe_env_template: bool) -> bool:
    stripped = name
    is_backup = False
    for suffix in SENSITIVE_BACKUP_SUFFIXES:
        if stripped.endswith(suffix):
            stripped = stripped[: -len(suffix)]
            is_backup = True
            break
    if stripped in ALWAYS_EXCLUDED_BASENAMES:
        return True
    if stripped.startswith(".env") and (
        is_backup or not allow_safe_env_template or stripped not in SAFE_ENV_TEMPLATES
    ):
        return True
    if stripped.startswith(("id_rsa_", "id_dsa_", "id_ecdsa_", "id_ed25519_")):
        return True
    if stripped.endswith(".tfstate") or ".tfstate." in stripped:
        return True
    if stripped.endswith(".ppk") or ".ppk." in stripped:
        return True
    return any(stripped.endswith(suffix) for suffix in ALWAYS_EXCLUDED_SUFFIXES)


def load_rules(root: Path, *, include_gitignore_fallback: bool = False) -> list[IgnoreRule]:
    rules: list[IgnoreRule] = []
    rules.extend(
        _parse_rule_file(root / IGNORE_FILENAME, allow_negation=False, strict=True)
    )
    if include_gitignore_fallback:
        rules.extend(
            _parse_rule_file(root / ".gitignore", allow_negation=True, strict=False)
        )
    return rules


def rules_policy_token(root: Path, *, include_gitignore_fallback: bool = False) -> str:
    """Hash policy bytes so a scan can detect deny-rule changes."""
    digest = hashlib.sha256()
    sources = [(root / IGNORE_FILENAME, True)]
    if include_gitignore_fallback:
        sources.append((root / ".gitignore", False))
    for path, strict in sources:
        raw = _read_rule_bytes(path, strict=strict)
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0missing\0" if raw is None else b"\0present\0")
        if raw is not None:
            digest.update(raw)
        digest.update(b"\0")
    return digest.hexdigest()


def _parse_rule_file(
    path: Path, *, allow_negation: bool, strict: bool
) -> list[IgnoreRule]:
    raw_bytes = _read_rule_bytes(path, strict=strict)
    if raw_bytes is None:
        return []
    try:
        lines = raw_bytes.decode(
            "utf-8-sig", errors="strict" if strict else "replace"
        ).splitlines()
    except ConfigError:
        raise
    except (OSError, UnicodeError) as exc:
        if strict:
            raise ConfigError(f"Cannot read {IGNORE_FILENAME} as UTF-8") from exc
        return []
    rules: list[IgnoreRule] = []
    for line_number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        if negated and not allow_negation:
            raise ConfigError(
                f"{IGNORE_FILENAME}:{line_number}: negation rules are not allowed; "
                "project exclusions are deny-only"
            )
        pattern = line[1:] if negated else line
        pattern = unicodedata.normalize("NFC", pattern.replace("\\", "/"))
        if pattern:
            if len(pattern.encode("utf-8")) > MAX_IGNORE_PATTERN_BYTES:
                raise ConfigError(
                    f"{path.name}:{line_number}: ignore pattern exceeds safety limit"
                )
            if len(rules) >= MAX_IGNORE_RULES:
                raise ConfigError(f"{path.name} has too many ignore rules")
            rules.append(
                IgnoreRule(
                    pattern=pattern,
                    negated=negated,
                    deny_only=not allow_negation,
                )
            )
    return rules


def _read_rule_bytes(path: Path, *, strict: bool) -> bytes | None:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        if strict:
            raise ConfigError(f"Cannot inspect {IGNORE_FILENAME}") from exc
        return None
    if not stat.S_ISREG(before.st_mode) or is_link_or_reparse(path, before):
        if strict:
            raise ConfigError(f"{IGNORE_FILENAME} must be a regular, non-link file")
        return None
    if before.st_size > MAX_POLICY_FILE_BYTES:
        raise ConfigError(f"{path.name} exceeds the policy file safety limit")
    try:
        with path.open("rb") as handle:
            opened_before = os.fstat(handle.fileno())
            raw = handle.read(MAX_POLICY_FILE_BYTES + 1)
            opened_after = os.fstat(handle.fileno())
        after = path.lstat()
    except OSError as exc:
        if strict:
            raise ConfigError(f"Cannot read {IGNORE_FILENAME} as UTF-8") from exc
        return None
    if len(raw) > MAX_POLICY_FILE_BYTES:
        raise ConfigError(f"{path.name} exceeds the policy file safety limit")
    before_identity = (
        before.st_size,
        before.st_mtime_ns,
        getattr(before, "st_dev", 0),
        getattr(before, "st_ino", 0),
    )
    after_identity = (
        after.st_size,
        after.st_mtime_ns,
        getattr(after, "st_dev", 0),
        getattr(after, "st_ino", 0),
    )
    opened_before_identity = (
        opened_before.st_size,
        opened_before.st_mtime_ns,
        getattr(opened_before, "st_dev", 0),
        getattr(opened_before, "st_ino", 0),
    )
    opened_after_identity = (
        opened_after.st_size,
        opened_after.st_mtime_ns,
        getattr(opened_after, "st_dev", 0),
        getattr(opened_after, "st_ino", 0),
    )
    before_version = (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    after_version = (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    opened_before_version = (
        opened_before.st_size,
        opened_before.st_mtime_ns,
        opened_before.st_ctime_ns,
    )
    opened_after_version = (
        opened_after.st_size,
        opened_after.st_mtime_ns,
        opened_after.st_ctime_ns,
    )
    if (
        before_identity != opened_before_identity
        or opened_before_identity != opened_after_identity
        or opened_after_identity != after_identity
        or before_version != after_version
        or opened_before_version != opened_after_version
    ):
        raise ConfigError(f"{path.name} changed while it was read")
    return raw


def ignored_by_rules(path: str | Path, rules: list[IgnoreRule]) -> bool:
    rel = unicodedata.normalize("NFC", normalize_relative(path))
    ignored = False
    for rule in rules:
        pattern = unicodedata.normalize("NFC", rule.pattern)
        if _matches(rel, pattern):
            if rule.deny_only:
                return True
            ignored = not rule.negated
    return ignored


def _matches(rel: str, pattern: str) -> bool:
    anchored = pattern.startswith("/")
    pattern = pattern.lstrip("/")
    directory = pattern.endswith("/")
    pattern = pattern.rstrip("/")
    if not pattern:
        return False

    if directory:
        if anchored:
            return rel == pattern or rel.startswith(pattern + "/")
        pattern_length = len(PurePosixPath(pattern).parts)
        rel_parts = PurePosixPath(rel).parts
        return any(
            fnmatchcase("/".join(rel_parts[index : index + pattern_length]), pattern)
            for index in range(len(rel_parts))
        )

    if anchored or "/" in pattern:
        return fnmatchcase(rel, pattern) or PurePosixPath(rel).match(pattern)
    return any(fnmatchcase(part, pattern) for part in PurePosixPath(rel).parts)

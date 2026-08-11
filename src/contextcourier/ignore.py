"""Layered path filtering: immutable safety rules plus user ignore rules."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
import stat

from .config import IGNORE_FILENAME
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


@dataclass(frozen=True)
class IgnoreRule:
    pattern: str
    negated: bool = False


def normalize_relative(path: str | Path) -> str:
    value = str(path).replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return value.strip("/")


def always_excluded(path: str | Path) -> bool:
    rel = normalize_relative(path)
    if not rel:
        return False
    parts = PurePosixPath(rel).parts
    lowered_parts = tuple(part.lower() for part in parts)
    if any(
        part in ALWAYS_EXCLUDED_DIRS or part.endswith(".egg-info")
        for part in lowered_parts[:-1]
    ):
        return True
    name = lowered_parts[-1]
    if name in ALWAYS_EXCLUDED_DIRS or name in ALWAYS_EXCLUDED_BASENAMES:
        return True
    if name.startswith(".env") and name not in SAFE_ENV_TEMPLATES:
        return True
    if name.startswith(("id_rsa_", "id_dsa_", "id_ecdsa_", "id_ed25519_")):
        return True
    return any(name.endswith(suffix) for suffix in ALWAYS_EXCLUDED_SUFFIXES)


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


def _parse_rule_file(
    path: Path, *, allow_negation: bool, strict: bool
) -> list[IgnoreRule]:
    if strict:
        try:
            details = path.lstat()
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise ConfigError(f"Cannot inspect {IGNORE_FILENAME}") from exc
        if not stat.S_ISREG(details.st_mode) or is_link_or_reparse(path, details):
            raise ConfigError(f"{IGNORE_FILENAME} must be a regular, non-link file")
    elif not path.is_file():
        return []
    try:
        lines = path.read_text(
            encoding="utf-8", errors="strict" if strict else "replace"
        ).splitlines()
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
        pattern = pattern.replace("\\", "/")
        if pattern:
            rules.append(IgnoreRule(pattern=pattern, negated=negated))
    return rules


def ignored_by_rules(path: str | Path, rules: list[IgnoreRule]) -> bool:
    rel = normalize_relative(path)
    ignored = False
    for rule in rules:
        if _matches(rel, rule.pattern):
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

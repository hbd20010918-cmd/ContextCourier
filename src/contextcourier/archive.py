"""Deterministic archive creation, inspection, and integrity verification."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
import unicodedata
import zipfile

from . import __version__
from .config import (
    Config,
    HARD_MAX_CANDIDATES,
    HARD_MAX_FILES,
    HARD_MAX_FILE_SIZE,
    HARD_MAX_TOTAL_SIZE,
)
from .errors import ContextCourierError, VerificationError
from .models import ScanResult
from .pathutil import (
    BIDI_CONTROL_CHARACTERS,
    is_link_or_reparse,
    portable_posix_path,
)


FORMAT_NAME = "contextcourier"
SCHEMA_VERSION = 1
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 10_010
MAX_CENTRAL_DIRECTORY_BYTES = 8 * 1024 * 1024
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
REQUIRED_GENERATED_ENTRIES = {
    "CONTEXT.md",
    "REDACTIONS.md",
    "adapters/AGENTS.md",
    "adapters/CLAUDE.md",
    "adapters/IMPORT_PROMPT.md",
    "adapters/cursor-context.mdc",
}
@dataclass(frozen=True)
class ArchiveResult:
    path: Path
    sha256: str
    archive_bytes: int
    source_files: int
    source_bytes: int
    redactions: int


def build_archive(
    scan: ScanResult,
    config: Config,
    output: Path,
    *,
    force: bool = False,
) -> ArchiveResult:
    output = Path(os.path.abspath(os.fspath(output.expanduser())))
    if is_link_or_reparse(output):
        raise ContextCourierError("Refusing to overwrite a symlink or junction")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        if not force:
            raise ContextCourierError(f"Output already exists: {output} (use --force)")
        if not output.is_file():
            raise ContextCourierError(f"Output is not a regular file: {output}")

    generated = {
        "CONTEXT.md": _render_context(scan, config).encode("utf-8"),
        "REDACTIONS.md": _render_redactions(scan).encode("utf-8"),
        "adapters/AGENTS.md": _render_agent_adapter("AGENTS.md").encode("utf-8"),
        "adapters/CLAUDE.md": _render_agent_adapter("CLAUDE.md").encode("utf-8"),
        "adapters/cursor-context.mdc": _render_cursor_adapter().encode("utf-8"),
        "adapters/IMPORT_PROMPT.md": _render_import_prompt(scan.project_name).encode("utf-8"),
    }
    entries: dict[str, bytes] = dict(generated)
    for item in scan.files:
        entries[f"files/{item.path}"] = item.content

    manifest = _build_manifest(scan, config, entries, generated)
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise ContextCourierError("Generated manifest exceeds the v1 safety limit")
    entries["MANIFEST.json"] = manifest_bytes

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{output.name}.",
            suffix=".tmp",
            dir=output.parent,
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
        with zipfile.ZipFile(
            temporary_path,
            mode="w",
            compression=zipfile.ZIP_STORED,
            allowZip64=False,
        ) as archive:
            for name in sorted(entries, key=lambda value: (value.casefold(), value)):
                _write_entry(archive, name, entries[name])
        os.replace(temporary_path, output)
        temporary_path = None
    except (OSError, ValueError, zipfile.LargeZipFile) as exc:
        raise ContextCourierError(f"Could not write archive: {exc}") from exc
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    return ArchiveResult(
        path=output,
        sha256=_sha256_file(output),
        archive_bytes=output.stat().st_size,
        source_files=len(scan.files),
        source_bytes=scan.source_bytes,
        redactions=scan.redaction_total,
    )


def inspect_archive(path: Path) -> dict[str, object]:
    path = Path(os.path.abspath(os.fspath(path.expanduser())))
    expected_entry_count = _preflight_archive(path)
    try:
        with zipfile.ZipFile(path, "r") as archive:
            if archive.comment:
                raise VerificationError("Archive comments are not allowed")
            infos = archive.infolist()
            if len(infos) != expected_entry_count:
                raise VerificationError("Central-directory entry count is inconsistent")
            actual_names, infos_by_name = _validate_archive_entries(infos)
            info = archive.getinfo("MANIFEST.json")
            manifest = _read_manifest(archive, info)
    except VerificationError:
        raise
    except KeyError as exc:
        raise VerificationError("MANIFEST.json is missing") from exc
    except OSError as exc:
        raise ContextCourierError(f"Cannot read archive: {path}") from exc
    except (
        RuntimeError,
        NotImplementedError,
        ValueError,
        RecursionError,
        OverflowError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ) as exc:
        raise VerificationError(f"Cannot inspect archive: {exc}") from exc
    records, project, policy, totals = _validate_manifest_structure(manifest)
    _validate_declared_layout(
        records, project, policy, totals, actual_names, infos_by_name
    )
    return _summary_from_manifest(manifest, integrity="NOT_VERIFIED")


def verify_archive(path: Path) -> dict[str, object]:
    path = Path(os.path.abspath(os.fspath(path.expanduser())))
    expected_entry_count = _preflight_archive(path)
    try:
        with zipfile.ZipFile(path, "r") as archive:
            if archive.comment:
                raise VerificationError("Archive comments are not allowed")
            infos = archive.infolist()
            if len(infos) != expected_entry_count:
                raise VerificationError("Central-directory entry count is inconsistent")
            actual_names, infos_by_name = _validate_archive_entries(infos)

            try:
                manifest_info = archive.getinfo("MANIFEST.json")
            except KeyError as exc:
                raise VerificationError("MANIFEST.json is missing") from exc
            manifest = _read_manifest(archive, manifest_info)
            records, project, policy, totals = _validate_manifest_structure(manifest)
            validated_records = _validate_declared_layout(
                records, project, policy, totals, actual_names, infos_by_name
            )
            for name, size, expected_hash, _kind, _redactions, _source_size in validated_records:
                info = infos_by_name[name]
                digest = hashlib.sha256()
                actual_size = 0
                with archive.open(info, "r") as handle:
                    while chunk := handle.read(64 * 1024):
                        actual_size += len(chunk)
                        if actual_size > MAX_ARCHIVE_BYTES:
                            raise VerificationError(f"Entry exceeds safety limit: {name}")
                        digest.update(chunk)
                if actual_size != size or digest.hexdigest() != expected_hash:
                    raise VerificationError(f"SHA-256 mismatch: {name}")
    except VerificationError:
        raise
    except OSError as exc:
        raise ContextCourierError(f"Cannot read archive: {path}") from exc
    except (
        RuntimeError,
        NotImplementedError,
        ValueError,
        RecursionError,
        OverflowError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ) as exc:
        raise VerificationError(f"Cannot verify archive: {exc}") from exc

    summary = _summary_from_manifest(manifest, integrity="VERIFIED")
    summary["archive_sha256"] = _sha256_file(path)
    return summary


def _build_manifest(
    scan: ScanResult,
    config: Config,
    entries: dict[str, bytes],
    generated: dict[str, bytes],
) -> dict[str, object]:
    source_by_archive = {f"files/{item.path}": item for item in scan.files}
    records: list[dict[str, object]] = []
    for name in sorted(entries, key=lambda value: (value.casefold(), value)):
        content = entries[name]
        record: dict[str, object] = {
            "kind": "generated" if name in generated else "source",
            "path": name,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
        source = source_by_archive.get(name)
        if source is not None:
            record["source_path"] = source.path
            record["source_size"] = source.source_size
            if source.redactions:
                record["redactions"] = source.redactions
        records.append(record)

    skipped_counts = dict(sorted(Counter(item.reason for item in scan.skipped).items()))
    return {
        "entries": records,
        "format": FORMAT_NAME,
        "policy": {
            "archive_compression": "stored",
            "include_untracked": config.include_untracked,
            "max_file_size": config.max_file_size,
            "max_files": config.max_files,
            "max_total_size": config.max_total_size,
            "secret_policy": "redact",
            "text_encoding": "UTF-8",
            "text_newlines": "LF",
        },
        "project": {
            "git": {
                "available": scan.git.available,
                "branch": scan.git.branch,
                "commit": scan.git.commit,
                "dirty": scan.git.dirty,
            },
            "languages": scan.languages,
            "metadata_redactions": scan.metadata_redactions,
            "name": scan.project_name,
        },
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "contextcourier", "version": __version__},
        "totals": {
            "candidate_files": scan.candidate_count,
            "excluded_by_reason": skipped_counts,
            "packed_bytes": scan.packed_bytes,
            "source_bytes": scan.source_bytes,
            "redactions": scan.redaction_total,
            "redactions_by_kind": scan.redaction_counts,
            "source_files": len(scan.files),
        },
        "warnings": scan.warnings,
    }


def _render_context(scan: ScanResult, config: Config) -> str:
    git_lines = [f"- Git available: `{str(scan.git.available).lower()}`"]
    if scan.git.branch:
        git_lines.append(f"- Branch: `{scan.git.branch}`")
    if scan.git.commit:
        git_lines.append(f"- Commit: `{scan.git.commit}`")
    if scan.git.dirty is not None:
        git_lines.append(f"- Working tree dirty: `{str(scan.git.dirty).lower()}`")
    language_text = ", ".join(
        f"{name} ({count})" for name, count in scan.languages.items()
    ) or "No recognized source-language extensions"
    paths = [item.path for item in scan.files]
    visible_paths = paths[:500]
    tree = "\n".join(f"- `files/{path}`" for path in visible_paths)
    if len(paths) > len(visible_paths):
        tree += f"\n- ... {len(paths) - len(visible_paths)} more files (see MANIFEST.json)"
    warning_text = "\n".join(f"- {warning}" for warning in scan.warnings) or "- None"
    return f"""# {scan.project_name} — AI project handoff

This is a local, deterministic ContextCourier snapshot for continuing work in another AI
coding tool or account. Read this file first, then inspect the selected files under `files/`.

## Snapshot

{chr(10).join(git_lines)}
- Packed source files: `{len(scan.files)}`
- Packed source bytes: `{scan.packed_bytes}`
- Redactions applied: `{scan.redaction_total}`
- Languages: {language_text}

## Recommended import prompt

```text
Treat this ContextCourier archive as a read-only project handoff. Read CONTEXT.md and
MANIFEST.json first. Use files/ as a redacted snapshot, preserve the documented project
state and task intent, and verify assumptions against the live checkout before editing.
Never try to reconstruct values marked CONTEXTCOURIER_REDACTED.
```

Ready-to-copy variants are in `adapters/` for AGENTS.md, CLAUDE.md, and Cursor rules.

## Included files

{tree or '- No source files were selected.'}

## Transfer boundary

- Included: selected UTF-8 project text, Git branch/commit state, integrity hashes, and
  generated handoff instructions.
- Excluded: app-private conversations, account data, Git remotes, absolute local paths,
  known credential containers, binary files, caches, dependencies, and build output.
- Secret detection is heuristic. Review `REDACTIONS.md` and the archive before sharing it.
- The original ChatGPT/Codex task history remains attached to the original account; this
  pack transfers project knowledge, not ownership of server-side conversations.

## Integrity

Run `ctxcourier verify <archive>` before trusting or importing the pack. A successful
inspection alone does not verify content hashes.

## Scanner warnings

{warning_text}

Policy limits: `{config.max_files}` files, `{config.max_file_size}` bytes per file,
`{config.max_total_size}` bytes total.
"""


def _render_redactions(scan: ScanResult) -> str:
    if not scan.redaction_counts:
        details = "No high-confidence secret patterns were redacted."
        files = "- None"
    else:
        details = "\n".join(
            f"- `{kind}`: {count}" for kind, count in scan.redaction_counts.items()
        )
        redacted_files = [item for item in scan.files if item.redactions]
        file_lines = [
            f"- `files/{item.path}`: "
            + ", ".join(f"{kind}={count}" for kind, count in item.redactions.items())
            for item in redacted_files
        ]
        if scan.metadata_redactions:
            file_lines.insert(
                0,
                "- Project/Git metadata: "
                + ", ".join(
                    f"{kind}={count}" for kind, count in scan.metadata_redactions.items()
                ),
            )
        files = "\n".join(file_lines) or "- None"
    return f"""# Redaction report

ContextCourier never records matched secret values or their original hashes.

## Counts by detector

{details}

## Affected files

{files}

## Important limitation

Detection is heuristic and cannot guarantee that every unknown or custom credential was
found. Credential containers and private-key file types are excluded before content is
read. Always inspect a pack before sending it to another person or service.
"""


def _render_agent_adapter(filename: str) -> str:
    return f"""# Imported project handoff ({filename})

This directory was generated by ContextCourier. Read `../CONTEXT.md` and
`../MANIFEST.json` first, then use `../files/` as a redacted, read-only snapshot.

- Preserve the recorded project state and task intent.
- Verify assumptions against the live checkout before changing code.
- Never infer or reconstruct `CONTEXTCOURIER_REDACTED` values.
- Do not claim that server-side conversation history was migrated.
"""


def _render_cursor_adapter() -> str:
    return """---
description: Imported ContextCourier project handoff
alwaysApply: true
---

Read `../CONTEXT.md` and `../MANIFEST.json` before using the redacted snapshot under
`../files/`. Verify assumptions against the live checkout and never reconstruct values
marked `CONTEXTCOURIER_REDACTED`.
"""


def _render_import_prompt(project_name: str) -> str:
    return f"""# Import {project_name}

Treat this ContextCourier archive as a read-only project handoff. Read CONTEXT.md and
MANIFEST.json first. Use files/ as a redacted snapshot, preserve the documented project
state and task intent, and verify assumptions against the live checkout before editing.
Never try to reconstruct values marked CONTEXTCOURIER_REDACTED.
"""


def _write_entry(archive: zipfile.ZipFile, name: str, content: bytes) -> None:
    safe_name = _safe_entry_name(name)
    if safe_name != name:
        raise ContextCourierError(f"Unsafe generated archive path: {name}")
    info = zipfile.ZipInfo(filename=name, date_time=FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (0o100644 & 0xFFFF) << 16
    info.extra = b""
    info.comment = b""
    archive.writestr(info, content)


def _validate_archive_entries(
    infos: list[zipfile.ZipInfo],
) -> tuple[set[str], dict[str, zipfile.ZipInfo]]:
    names: list[str] = []
    actual_names: set[str] = set()
    collision_keys: set[str] = set()
    infos_by_name: dict[str, zipfile.ZipInfo] = {}
    for info in infos:
        name = _validate_archive_entry(info)
        if name in actual_names:
            raise VerificationError(f"Duplicate archive entry: {name}")
        collision_key = unicodedata.normalize("NFC", name).casefold()
        if collision_key in collision_keys:
            raise VerificationError("Archive paths collide after normalization")
        collision_keys.add(collision_key)
        actual_names.add(name)
        infos_by_name[name] = info
        names.append(name)
    if names != sorted(names, key=lambda value: (value.casefold(), value)):
        raise VerificationError("Archive entries are not in canonical order")
    return actual_names, infos_by_name


def _validate_archive_entry(info: zipfile.ZipInfo) -> str:
    name = info.filename
    if _safe_entry_name(name) != name:
        raise VerificationError(f"Unsafe archive entry path: {name!r}")
    if info.is_dir():
        raise VerificationError(f"Directory entries are not allowed: {name}")
    if info.flag_bits & 0x1:
        raise VerificationError(f"Encrypted entries are not supported: {name}")
    if info.flag_bits & ~0x800:
        raise VerificationError(f"Unsupported ZIP flags: {name}")
    if info.compress_type != zipfile.ZIP_STORED:
        raise VerificationError(f"Unsupported compression method: {name}")
    if info.compress_size != info.file_size:
        raise VerificationError(f"Stored entry size is inconsistent: {name}")
    if info.file_size < 0 or info.file_size > MAX_ARCHIVE_BYTES:
        raise VerificationError(f"Entry exceeds safety limit: {name}")
    if info.create_system != 3:
        raise VerificationError(f"Entry is not in canonical Unix mode: {name}")
    mode = (info.external_attr >> 16) & 0xFFFF
    if mode != (stat.S_IFREG | 0o644):
        raise VerificationError(f"Entry mode is not a regular 0644 file: {name}")
    if info.date_time != FIXED_ZIP_TIME:
        raise VerificationError(f"Entry timestamp is not canonical: {name}")
    if info.extra or info.comment:
        raise VerificationError(f"Entry has unsupported extra metadata: {name}")
    return name


def _validate_declared_layout(
    records: list[dict[str, object]],
    project: dict[str, object],
    policy: dict[str, object],
    totals: dict[str, object],
    actual_names: set[str],
    infos_by_name: dict[str, zipfile.ZipInfo],
) -> list[tuple[str, int, str, str, dict[str, int], int | None]]:
    expected_names = {"MANIFEST.json"}
    generated_names: set[str] = set()
    source_count = 0
    packed_source_bytes = 0
    original_source_bytes = 0
    source_redactions: Counter[str] = Counter()
    validated: list[tuple[str, int, str, str, dict[str, int], int | None]] = []
    for record in records:
        parsed = _validate_manifest_record(record)
        name, size, _expected_hash, kind, redactions, source_size = parsed
        if name in expected_names:
            raise VerificationError(f"Manifest contains a duplicate entry: {name}")
        expected_names.add(name)
        if kind == "generated":
            generated_names.add(name)
        else:
            source_count += 1
            packed_source_bytes += size
            source_redactions.update(redactions)
            if source_size is None or source_size > policy["max_file_size"]:
                raise VerificationError(f"Source exceeds declared file policy: {name}")
            original_source_bytes += source_size
        info = infos_by_name.get(name)
        if info is None:
            raise VerificationError(f"Archive entry is missing: {name}")
        if info.file_size != size:
            raise VerificationError(f"Size mismatch: {name}")
        validated.append(parsed)

    if generated_names != REQUIRED_GENERATED_ENTRIES:
        raise VerificationError("Required generated handoff entries are incomplete")
    if actual_names != expected_names:
        extras = sorted(actual_names - expected_names)
        missing = sorted(expected_names - actual_names)
        detail = extras[0] if extras else missing[0]
        raise VerificationError(f"Archive entry set does not match manifest: {detail}")

    metadata_redactions = Counter(project["metadata_redactions"])
    combined_redactions = source_redactions + metadata_redactions
    if source_count != totals["source_files"]:
        raise VerificationError("Manifest source_files total is inconsistent")
    if packed_source_bytes != totals["packed_bytes"]:
        raise VerificationError("Manifest packed_bytes total is inconsistent")
    if totals["source_bytes"] is not None and original_source_bytes != totals["source_bytes"]:
        raise VerificationError("Manifest source_bytes total is inconsistent")
    if dict(sorted(combined_redactions.items())) != totals["redactions_by_kind"]:
        raise VerificationError("Manifest redaction totals are inconsistent")
    if sum(combined_redactions.values()) != totals["redactions"]:
        raise VerificationError("Manifest redaction count is inconsistent")
    if (
        source_count > policy["max_files"]
        or packed_source_bytes > policy["max_total_size"]
        or original_source_bytes > policy["max_total_size"]
    ):
        raise VerificationError("Manifest content exceeds its declared policy")
    return validated


def _safe_entry_name(name: str) -> str | None:
    return portable_posix_path(name)


def _validate_manifest_structure(
    manifest: object,
) -> tuple[
    list[dict[str, object]],
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    if not isinstance(manifest, dict):
        raise VerificationError("Manifest root must be an object")
    if manifest.get("format") != FORMAT_NAME:
        raise VerificationError("Unsupported archive format")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise VerificationError("Unsupported ContextCourier schema version")

    tool = _require_dict(manifest.get("tool"), "tool")
    if tool.get("name") != "contextcourier":
        raise VerificationError("Manifest tool name is invalid")
    _require_safe_text(tool.get("version"), "tool.version", maximum=64)

    project = _require_dict(manifest.get("project"), "project")
    _require_safe_text(project.get("name"), "project.name", maximum=255)
    git = _require_dict(project.get("git"), "project.git")
    if not isinstance(git.get("available"), bool):
        raise VerificationError("project.git.available must be boolean")
    branch = git.get("branch")
    if branch is not None:
        _require_safe_text(branch, "project.git.branch", maximum=1024)
    commit = git.get("commit")
    if commit is not None and (
        not isinstance(commit, str) or re.fullmatch(r"[0-9a-fA-F]{40,64}", commit) is None
    ):
        raise VerificationError("project.git.commit is invalid")
    dirty = git.get("dirty")
    if dirty is not None and not isinstance(dirty, bool):
        raise VerificationError("project.git.dirty must be boolean or null")
    project["languages"] = _require_count_map(project.get("languages"), "project.languages")
    project["metadata_redactions"] = (
        _require_count_map(
            project.get("metadata_redactions"), "project.metadata_redactions"
        )
        if "metadata_redactions" in project
        else {}
    )

    policy = _require_dict(manifest.get("policy"), "policy")
    if policy.get("archive_compression") != "stored":
        raise VerificationError("Manifest archive compression is unsupported")
    if policy.get("secret_policy") != "redact":
        raise VerificationError("Manifest secret policy is unsupported")
    if policy.get("text_encoding") != "UTF-8" or policy.get("text_newlines") != "LF":
        raise VerificationError("Manifest text normalization is unsupported")
    if not isinstance(policy.get("include_untracked"), bool):
        raise VerificationError("policy.include_untracked must be boolean")
    policy["max_file_size"] = _require_bounded_int(
        policy.get("max_file_size"), "policy.max_file_size", 1, HARD_MAX_FILE_SIZE
    )
    policy["max_total_size"] = _require_bounded_int(
        policy.get("max_total_size"), "policy.max_total_size", 1, HARD_MAX_TOTAL_SIZE
    )
    policy["max_files"] = _require_bounded_int(
        policy.get("max_files"), "policy.max_files", 1, HARD_MAX_FILES
    )
    if policy["max_file_size"] > policy["max_total_size"]:
        raise VerificationError("Manifest file limit exceeds total limit")

    totals = _require_dict(manifest.get("totals"), "totals")
    totals["candidate_files"] = _require_bounded_int(
        totals.get("candidate_files"),
        "totals.candidate_files",
        0,
        HARD_MAX_CANDIDATES,
    )
    totals["source_files"] = _require_bounded_int(
        totals.get("source_files"), "totals.source_files", 0, HARD_MAX_FILES
    )
    totals["packed_bytes"] = _require_bounded_int(
        totals.get("packed_bytes"), "totals.packed_bytes", 0, HARD_MAX_TOTAL_SIZE
    )
    totals["source_bytes"] = (
        _require_bounded_int(
            totals.get("source_bytes"), "totals.source_bytes", 0, HARD_MAX_TOTAL_SIZE
        )
        if "source_bytes" in totals
        else None
    )
    totals["redactions"] = _require_bounded_int(
        totals.get("redactions"), "totals.redactions", 0, 2**31 - 1
    )
    totals["excluded_by_reason"] = _require_count_map(
        totals.get("excluded_by_reason"), "totals.excluded_by_reason"
    )
    totals["redactions_by_kind"] = _require_count_map(
        totals.get("redactions_by_kind"), "totals.redactions_by_kind"
    )
    if sum(totals["redactions_by_kind"].values()) != totals["redactions"]:
        raise VerificationError("Manifest redaction total is inconsistent")
    if (
        sum(totals["excluded_by_reason"].values()) + totals["source_files"]
        != totals["candidate_files"]
    ):
        raise VerificationError("Manifest candidate/exclusion totals are inconsistent")

    warnings = manifest.get("warnings")
    if not isinstance(warnings, list) or len(warnings) > 100:
        raise VerificationError("Manifest warnings must be a bounded list")
    for warning in warnings:
        _require_safe_text(warning, "warning", maximum=2048)

    records = manifest.get("entries")
    if not isinstance(records, list) or len(records) > MAX_ARCHIVE_ENTRIES - 1:
        raise VerificationError("Manifest entries must be a bounded list")
    if len(records) != totals["source_files"] + len(REQUIRED_GENERATED_ENTRIES):
        raise VerificationError("Manifest entry count is inconsistent")
    if not all(isinstance(record, dict) for record in records):
        raise VerificationError("Manifest entry must be an object")
    return records, project, policy, totals


def _validate_manifest_record(
    record: dict[str, object],
) -> tuple[str, int, str, str, dict[str, int], int | None]:
    name = record.get("path")
    size = record.get("size")
    expected_hash = record.get("sha256")
    kind = record.get("kind")
    if not isinstance(name, str) or _safe_entry_name(name) != name:
        raise VerificationError("Manifest contains an unsafe entry path")
    size = _require_bounded_int(size, f"entry size for {name}", 0, MAX_ARCHIVE_BYTES)
    if not isinstance(expected_hash, str) or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None:
        raise VerificationError(f"Manifest contains an invalid SHA-256 for {name}")
    if kind == "generated":
        if name not in REQUIRED_GENERATED_ENTRIES:
            raise VerificationError(f"Unknown generated handoff entry: {name}")
        return name, size, expected_hash, kind, {}, None
    if kind != "source" or not name.startswith("files/"):
        raise VerificationError(f"Invalid manifest entry kind/path: {name}")
    source_path = record.get("source_path")
    if not isinstance(source_path, str) or source_path != name[len("files/") :]:
        raise VerificationError(f"Source path mismatch: {name}")
    source_size = _require_bounded_int(
        record.get("source_size"), f"source size for {name}", 0, HARD_MAX_FILE_SIZE
    )
    redactions_value = record.get("redactions", {})
    redactions = _require_count_map(redactions_value, f"redactions for {name}")
    return name, size, expected_hash, kind, redactions, source_size


def _require_dict(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise VerificationError(f"Manifest {label} must be an object")
    return value


def _require_bounded_int(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise VerificationError(f"Manifest {label} is outside its allowed range")
    return value


def _require_count_map(value: object, label: str) -> dict[str, int]:
    mapping = _require_dict(value, label)
    if len(mapping) > 128:
        raise VerificationError(f"Manifest {label} has too many keys")
    result: dict[str, int] = {}
    for key, count in mapping.items():
        _require_safe_text(key, f"{label} key", maximum=128)
        result[key] = _require_bounded_int(count, f"{label}.{key}", 0, 2**31 - 1)
    return dict(sorted(result.items()))


def _require_safe_text(value: object, label: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise VerificationError(f"Manifest {label} must be a bounded string")
    for char in value:
        if char in BIDI_CONTROL_CHARACTERS or unicodedata.category(char) in {"Cc", "Cs"}:
            raise VerificationError(f"Manifest {label} contains unsafe characters")
    return value


def _summary_from_manifest(manifest: dict[str, object], *, integrity: str) -> dict[str, object]:
    project = manifest.get("project") if isinstance(manifest.get("project"), dict) else {}
    totals = manifest.get("totals") if isinstance(manifest.get("totals"), dict) else {}
    tool = manifest.get("tool") if isinstance(manifest.get("tool"), dict) else {}
    return {
        "format": manifest.get("format"),
        "schema_version": manifest.get("schema_version"),
        "tool_version": tool.get("version"),
        "project": project.get("name"),
        "source_files": totals.get("source_files"),
        "packed_bytes": totals.get("packed_bytes"),
        "redactions": totals.get("redactions"),
        "integrity": integrity,
    }


def _preflight_archive(path: Path) -> int:
    """Bound central-directory work before handing an untrusted file to ZipFile."""
    try:
        file_stat = path.lstat()
    except OSError as exc:
        raise ContextCourierError(f"Cannot read archive: {path}") from exc
    if not stat.S_ISREG(file_stat.st_mode) or is_link_or_reparse(path, file_stat):
        raise ContextCourierError(f"Archive input is not a regular file: {path}")
    size = file_stat.st_size
    if size > MAX_ARCHIVE_BYTES:
        raise VerificationError("Archive exceeds the v1 safety limit")
    if size < 22:
        raise VerificationError("Archive is too small to contain a ZIP directory")

    tail_size = min(size, 22 + 65_535)
    try:
        with path.open("rb") as handle:
            handle.seek(size - tail_size)
            tail = handle.read(tail_size)
    except OSError as exc:
        raise ContextCourierError(f"Cannot read archive: {path}") from exc
    signature = b"PK\x05\x06"
    index = tail.rfind(signature)
    if index < 0 or len(tail) - index < 22:
        raise VerificationError("ZIP end-of-central-directory record is missing")
    try:
        (
            _signature,
            disk_number,
            central_disk,
            entries_on_disk,
            entry_count,
            central_size,
            central_offset,
            comment_length,
        ) = struct.unpack_from("<4s4H2LH", tail, index)
    except struct.error as exc:
        raise VerificationError("ZIP end-of-central-directory record is malformed") from exc

    if comment_length != 0 or index + 22 != len(tail):
        raise VerificationError("ZIP comments or trailing data are not allowed")
    if disk_number != 0 or central_disk != 0 or entries_on_disk != entry_count:
        raise VerificationError("Multi-disk ZIP archives are not supported")
    if entry_count == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        raise VerificationError("Zip64 archives are not supported")
    if entry_count > MAX_ARCHIVE_ENTRIES:
        raise VerificationError("Archive has too many entries")
    if central_size > MAX_CENTRAL_DIRECTORY_BYTES:
        raise VerificationError("ZIP central directory exceeds the safety limit")
    eocd_offset = size - tail_size + index
    if central_offset + central_size != eocd_offset:
        raise VerificationError("ZIP central-directory bounds are inconsistent")
    return entry_count


def _read_manifest(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> dict[str, object]:
    if info.file_size > MAX_MANIFEST_BYTES:
        raise VerificationError("Manifest exceeds the v1 safety limit")
    try:
        data = archive.read(info)
        text = data.decode("utf-8")
        value = json.loads(
            text,
            parse_int=_bounded_json_int,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except VerificationError:
        raise
    except (
        UnicodeError,
        json.JSONDecodeError,
        RuntimeError,
        NotImplementedError,
        ValueError,
        RecursionError,
        OverflowError,
    ) as exc:
        raise VerificationError("MANIFEST.json is not bounded, unique-key UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise VerificationError("Manifest root must be an object")
    canonical = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if data != canonical:
        raise VerificationError("MANIFEST.json is not in canonical JSON form")
    return value


def _bounded_json_int(value: str) -> int:
    digits = value.lstrip("-")
    if len(digits) > 19:
        raise ValueError("JSON integer exceeds v1 range")
    return int(value)


def _reject_json_number(value: str) -> float:
    raise ValueError(f"Non-integer JSON number is not allowed: {value[:16]}")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise ContextCourierError(f"Cannot read archive for SHA-256: {path}") from exc
    return digest.hexdigest()

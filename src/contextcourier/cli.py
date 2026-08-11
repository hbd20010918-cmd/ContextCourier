"""Command-line interface for ContextCourier."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import replace
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Sequence

from . import __version__
from .archive import build_archive, inspect_archive, verify_archive
from .config import (
    CONFIG_FILENAME,
    DEFAULT_CONFIG_TEXT,
    DEFAULT_IGNORE_TEXT,
    IGNORE_FILENAME,
    Config,
)
from .errors import (
    ConfigError,
    ContextCourierError,
    ScanError,
    SecretPolicyError,
    VerificationError,
)
from .gitrepo import locate_root
from .models import ScanResult
from .pathutil import is_link_or_reparse
from .redact import redact_text
from .scanner import scan_project


EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_SECRET_POLICY = 3
EXIT_VERIFICATION = 4
EXIT_OPERATIONAL = 5


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctxcourier",
        description=(
            "Carry a deterministic, secret-aware project handoff across AI coding "
            "tools and accounts. Runs locally and uses no API."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser(
        "init", help="Create project policy and ignore templates"
    )
    init_parser.add_argument("path", nargs="?", default=".", help="Project directory")
    init_parser.add_argument("--force", action="store_true", help="Replace existing templates")
    init_parser.add_argument("--json", action="store_true", help="Print machine-readable output")

    scan_parser = subparsers.add_parser(
        "scan", help="Preview selected files, exclusions, and redaction counts"
    )
    _add_scan_options(scan_parser)

    pack_parser = subparsers.add_parser(
        "pack", help="Create a deterministic .contextcourier.zip handoff"
    )
    _add_scan_options(pack_parser)
    pack_parser.add_argument("-o", "--output", type=Path, help="Archive output path")
    pack_parser.add_argument("--force", action="store_true", help="Replace an existing output")

    inspect_parser = subparsers.add_parser(
        "inspect", help="Show archive metadata without verifying content hashes"
    )
    inspect_parser.add_argument("archive", type=Path)
    inspect_parser.add_argument("--json", action="store_true", help="Print JSON")

    verify_parser = subparsers.add_parser(
        "verify", help="Validate archive paths, entry set, sizes, and SHA-256 hashes"
    )
    verify_parser.add_argument("archive", type=Path)
    verify_parser.add_argument("--json", action="store_true", help="Print JSON")
    return parser


def _add_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", nargs="?", default=".", help="Project directory")
    parser.add_argument(
        "--tracked-only",
        action="store_true",
        help="Exclude every untracked file, even when Git would include it",
    )
    parser.add_argument(
        "--fail-on-secret",
        action="store_true",
        help="Exit with code 3 and write no archive if any redaction is needed",
    )
    parser.add_argument("--max-file-size", type=_parse_size, metavar="SIZE")
    parser.add_argument("--max-total-size", type=_parse_size, metavar="SIZE")
    parser.add_argument("--max-files", type=_positive_int, metavar="COUNT")
    parser.add_argument("--json", action="store_true", help="Print machine-readable output")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            return _command_init(args)
        if args.command == "scan":
            return _command_scan(args)
        if args.command == "pack":
            return _command_pack(args)
        if args.command == "inspect":
            return _command_inspect(args)
        if args.command == "verify":
            return _command_verify(args)
        parser.error("Unknown command")
    except SecretPolicyError as exc:
        _error(str(exc))
        return EXIT_SECRET_POLICY
    except VerificationError as exc:
        _error(str(exc))
        return EXIT_VERIFICATION
    except ConfigError as exc:
        _error(str(exc))
        return EXIT_CONFIG
    except (ScanError, ContextCourierError, OSError) as exc:
        _error(str(exc))
        return EXIT_OPERATIONAL
    return EXIT_OPERATIONAL


def entrypoint() -> None:
    raise SystemExit(main())


def _command_init(args: argparse.Namespace) -> int:
    root = locate_root(Path(args.path))
    targets = {
        root / CONFIG_FILENAME: DEFAULT_CONFIG_TEXT,
        root / IGNORE_FILENAME: DEFAULT_IGNORE_TEXT,
    }
    originals: dict[Path, bytes | None] = {}
    existing_names: list[str] = []
    for path in targets:
        try:
            details = path.lstat()
        except FileNotFoundError:
            originals[path] = None
            continue
        except OSError as exc:
            raise ConfigError(f"Cannot inspect init target: {path.name}") from exc
        if not stat.S_ISREG(details.st_mode) or is_link_or_reparse(path, details):
            raise ConfigError(f"Refusing to replace non-regular path: {path.name}")
        existing_names.append(path.name)
        try:
            originals[path] = path.read_bytes()
        except OSError as exc:
            raise ConfigError(f"Cannot read existing init target: {path.name}") from exc
    if existing_names and not args.force:
        raise ConfigError(
            f"Refusing to replace existing file(s): {', '.join(existing_names)} (use --force)"
        )

    staged: dict[Path, Path] = {}
    replaced: list[Path] = []
    try:
        for path, content in targets.items():
            staged[path] = _stage_bytes(path.parent, path.name, content.encode("utf-8"))
        for path in targets:
            os.replace(staged[path], path)
            staged.pop(path)
            replaced.append(path)
    except OSError as exc:
        rollback_failed = False
        for path in reversed(replaced):
            original = originals[path]
            try:
                if original is None:
                    path.unlink(missing_ok=True)
                else:
                    restore = _stage_bytes(path.parent, path.name, original)
                    os.replace(restore, path)
            except OSError:
                rollback_failed = True
        detail = " and rollback was incomplete" if rollback_failed else ""
        raise ConfigError(f"Could not create init templates{detail}") from exc
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)
    project_name = "redacted-project" if redact_text(root.name).total else root.name
    payload = {"project": project_name, "created": [path.name for path in targets]}
    _print_payload(payload, as_json=args.json, human=f"Created {CONFIG_FILENAME} and {IGNORE_FILENAME}")
    return EXIT_OK


def _command_scan(args: argparse.Namespace) -> int:
    root, config = _load_project(args)
    scan = scan_project(root, config)
    _enforce_secret_policy(scan, args.fail_on_secret)
    payload = _scan_payload(scan)
    _print_payload(payload, as_json=args.json, human=_human_scan(scan))
    return EXIT_OK


def _command_pack(args: argparse.Namespace) -> int:
    root, config = _load_project(args)
    output_name = (
        "redacted-project"
        if redact_text(root.name).total
        else root.name
    )
    output = args.output or (root / f"{output_name}.contextcourier.zip")
    output = Path(os.path.abspath(os.fspath(output.expanduser())))
    scan = scan_project(root, config, output_path=output)
    _enforce_secret_policy(scan, args.fail_on_secret)
    result = build_archive(scan, config, output, force=args.force)
    payload = {
        "archive_bytes": result.archive_bytes,
        "archive_sha256": result.sha256,
        "output": str(result.path),
        "project": scan.project_name,
        "redactions": result.redactions,
        "source_bytes": result.source_bytes,
        "source_files": result.source_files,
    }
    human = (
        f"[OK] Packed {result.source_files} files ({_format_size(result.source_bytes)})\n"
        f"Output: {result.path}\n"
        f"SHA-256: {result.sha256}\n"
        f"Redactions: {result.redactions}\n"
        f"Next: ctxcourier verify \"{result.path}\""
    )
    _print_payload(payload, as_json=args.json, human=human)
    return EXIT_OK


def _command_inspect(args: argparse.Namespace) -> int:
    payload = inspect_archive(args.archive)
    human = _human_archive_summary(payload)
    _print_payload(payload, as_json=args.json, human=human)
    return EXIT_OK


def _command_verify(args: argparse.Namespace) -> int:
    payload = verify_archive(args.archive)
    human = "[OK] Archive integrity verified\n" + _human_archive_summary(payload)
    _print_payload(payload, as_json=args.json, human=human)
    return EXIT_OK


def _load_project(args: argparse.Namespace) -> tuple[Path, Config]:
    root = locate_root(Path(args.path))
    config = Config.load(root).with_overrides(
        max_file_size=args.max_file_size,
        max_total_size=args.max_total_size,
        max_files=args.max_files,
    )
    if args.tracked_only:
        config = replace(config, include_untracked=False)
    return root, config


def _enforce_secret_policy(scan: ScanResult, enabled: bool) -> None:
    if enabled and scan.redaction_total:
        kinds = ", ".join(scan.redaction_counts)
        raise SecretPolicyError(
            f"Secret policy blocked the pack: {scan.redaction_total} match(es) ({kinds})"
        )


def _scan_payload(scan: ScanResult) -> dict[str, object]:
    return {
        "candidate_files": scan.candidate_count,
        "languages": scan.languages,
        "packed_bytes": scan.packed_bytes,
        "project": scan.project_name,
        "redactions": scan.redaction_total,
        "redactions_by_kind": scan.redaction_counts,
        "selected_files": len(scan.files),
        "skipped_by_reason": dict(sorted(Counter(item.reason for item in scan.skipped).items())),
        "warnings": scan.warnings,
    }


def _human_scan(scan: ScanResult) -> str:
    skipped = Counter(item.reason for item in scan.skipped)
    skipped_text = ", ".join(f"{name}={count}" for name, count in sorted(skipped.items()))
    warnings = "\n".join(f"Warning: {item}" for item in scan.warnings)
    result = (
        f"Project: {scan.project_name}\n"
        f"Selected: {len(scan.files)} files ({_format_size(scan.packed_bytes)})\n"
        f"Redactions: {scan.redaction_total}\n"
        f"Skipped: {skipped_text or 'none'}"
    )
    return f"{result}\n{warnings}" if warnings else result


def _human_archive_summary(payload: dict[str, object]) -> str:
    return (
        f"Project: {payload.get('project')}\n"
        f"Files: {payload.get('source_files')}\n"
        f"Packed bytes: {payload.get('packed_bytes')}\n"
        f"Redactions: {payload.get('redactions')}\n"
        f"Integrity: {payload.get('integrity')}"
    )


def _print_payload(payload: dict[str, object], *, as_json: bool, human: str) -> None:
    if as_json:
        _write_console(sys.stdout, json.dumps(payload, ensure_ascii=True, sort_keys=True))
    else:
        _write_console(sys.stdout, human)


def _error(message: str) -> None:
    _write_console(sys.stderr, f"error: {message}")


def _write_console(stream: object, message: str) -> None:
    encoding = getattr(stream, "encoding", None)
    if isinstance(encoding, str):
        message = message.encode(encoding, errors="backslashreplace").decode(encoding)
    stream.write(message + "\n")


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _parse_size(value: str) -> int:
    match = re.fullmatch(r"\s*(\d+)\s*([kmgt]?i?b?)?\s*", value, re.IGNORECASE)
    if not match:
        raise argparse.ArgumentTypeError("use bytes or a suffix such as 256K, 1MiB, or 25M")
    number = int(match.group(1))
    suffix = (match.group(2) or "").lower()
    powers = {
        "": 0,
        "b": 0,
        "k": 1,
        "kb": 1,
        "ki": 1,
        "kib": 1,
        "m": 2,
        "mb": 2,
        "mi": 2,
        "mib": 2,
        "g": 3,
        "gb": 3,
        "gi": 3,
        "gib": 3,
        "t": 4,
        "tb": 4,
        "ti": 4,
        "tib": 4,
    }
    if suffix not in powers or number <= 0:
        raise argparse.ArgumentTypeError("size must be a positive byte value")
    return number * (1024 ** powers[suffix])


def _format_size(value: int) -> str:
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{value} B"


def _stage_bytes(directory: Path, target_name: str, content: bytes) -> Path:
    with tempfile.NamedTemporaryFile(
        mode="wb",
        prefix=f".{target_name}.",
        suffix=".tmp",
        dir=directory,
        delete=False,
    ) as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
        return Path(handle.name)

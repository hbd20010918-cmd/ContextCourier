"""Project scanning, path safety, text normalization, and redaction."""

from __future__ import annotations

from collections import Counter
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import unicodedata

from .config import Config, HARD_MAX_CANDIDATES
from .errors import ScanError
from .gitrepo import git_file_list, git_info, snapshot_token
from .ignore import (
    always_excluded,
    ignored_by_rules,
    load_rules,
    normalize_relative,
    rules_policy_token,
)
from .models import PackedFile, ScanResult, SkippedFile
from .pathutil import (
    BIDI_CONTROL_CHARACTERS,
    has_link_or_reparse_component,
    is_link_or_reparse,
    portable_posix_path,
)
from .redact import redact_text


MAX_CANDIDATE_PATH_BYTES = 32 * 1024 * 1024
MAX_IGNORE_MATCH_WORK = 2_000_000
BINARY_SUFFIXES = {
    ".7z",
    ".a",
    ".avi",
    ".bin",
    ".bmp",
    ".class",
    ".dll",
    ".dmg",
    ".doc",
    ".docx",
    ".eot",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".jar",
    ".jpeg",
    ".jpg",
    ".lib",
    ".lockb",
    ".mov",
    ".mp3",
    ".mp4",
    ".o",
    ".otf",
    ".pdf",
    ".png",
    ".ppt",
    ".pptx",
    ".pyc",
    ".rar",
    ".so",
    ".tar",
    ".tif",
    ".tiff",
    ".ttf",
    ".wav",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
    ".xls",
    ".xlsx",
    ".xz",
    ".zip",
}

LANGUAGES = {
    ".c": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cs": "C#",
    ".css": "CSS",
    ".go": "Go",
    ".h": "C/C++ Header",
    ".hpp": "C++ Header",
    ".html": "HTML",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".json": "JSON",
    ".kt": "Kotlin",
    ".lua": "Lua",
    ".md": "Markdown",
    ".php": "PHP",
    ".ps1": "PowerShell",
    ".py": "Python",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".sh": "Shell",
    ".sql": "SQL",
    ".swift": "Swift",
    ".toml": "TOML",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".vue": "Vue",
    ".xml": "XML",
    ".yaml": "YAML",
    ".yml": "YAML",
}

HIGH_SIGNAL_NAMES = {
    "agents.md",
    "changelog.md",
    "claude.md",
    "code_of_conduct.md",
    "contributing.md",
    "dockerfile",
    "handoff.md",
    "license",
    "license.md",
    "makefile",
    "package.json",
    "project_context.md",
    "pyproject.toml",
    "readme.md",
    "security.md",
    "task_queue.md",
}


def scan_project(root: Path, config: Config, *, output_path: Path | None = None) -> ScanResult:
    root = root.resolve(strict=True)
    root_real = root.resolve(strict=True)
    config.assert_source_unchanged(root)
    output_relative = _output_relative_to_root(root, output_path)
    before = snapshot_token(root, excluded_path=output_relative)
    git_candidates = git_file_list(root, include_untracked=config.include_untracked)
    warnings: list[str] = []
    fallback_rules = git_candidates is None
    rules_before = rules_policy_token(
        root, include_gitignore_fallback=fallback_rules
    )
    if fallback_rules:
        candidates = _walk_files(root)
        rules = load_rules(root, include_gitignore_fallback=True)
        warnings.append(
            "Git metadata was unavailable; root .gitignore matching used a best-effort fallback."
        )
    else:
        candidates = git_candidates
        rules = load_rules(root)
    if rules_policy_token(
        root, include_gitignore_fallback=fallback_rules
    ) != rules_before:
        raise ScanError("Project privacy policy changed while it was loaded; retry")
    if output_relative:
        candidates = [
            item for item in candidates if normalize_relative(item) != output_relative
        ]
    if len(candidates) > HARD_MAX_CANDIDATES:
        raise ScanError(
            f"Project has {len(candidates)} candidates; hard safety limit is "
            f"{HARD_MAX_CANDIDATES}"
        )
    ignore_match_work = sum(
        max(1, len(PurePosixPath(normalize_relative(item)).parts))
        for item in candidates
    ) * len(rules)
    if rules and ignore_match_work > MAX_IGNORE_MATCH_WORK:
        raise ScanError(
            "Project ignore matching exceeds the hard safety work limit; "
            "reduce candidate files or simplify ignore rules"
        )

    normalized: list[tuple[int, str, str]] = []
    skipped: list[SkippedFile] = []
    path_redaction_counts: Counter[str] = Counter()
    collision_keys: dict[str, str] = {}
    output_resolved = output_path.resolve(strict=False) if output_path else None

    for raw_rel in candidates:
        if "\\" in str(raw_rel):
            skipped.append(SkippedFile(_opaque_path_label(str(raw_rel)), "unsafe_path"))
            continue
        rel = normalize_relative(raw_rel)
        safe_rel = _safe_archive_path(rel)
        if safe_rel is None:
            skipped.append(SkippedFile(_opaque_path_label(rel), "unsafe_path"))
            continue
        path_redaction = redact_text(safe_rel)
        if path_redaction.total:
            path_redaction_counts.update(path_redaction.counts)
            skipped.append(SkippedFile("<redacted-path>", "secret_in_path"))
            continue
        collision_key = unicodedata.normalize("NFC", safe_rel).casefold()
        previous = collision_keys.get(collision_key)
        if previous is not None and previous != rel:
            raise ScanError(
                "Two project paths collide after Unicode/case normalization; "
                "rename one before packing"
            )
        collision_keys[collision_key] = rel
        if always_excluded(safe_rel):
            skipped.append(SkippedFile(safe_rel, "always_excluded"))
            continue
        if ignored_by_rules(safe_rel, rules):
            skipped.append(SkippedFile(safe_rel, "project_ignore"))
            continue
        candidate = root / Path(*PurePosixPath(rel).parts)
        if output_resolved is not None and candidate.resolve(strict=False) == output_resolved:
            skipped.append(SkippedFile(safe_rel, "output_archive"))
            continue
        normalized.append((_priority(safe_rel), safe_rel, rel))

    normalized.sort(key=lambda item: (item[0], item[1].casefold(), item[1]))
    files: list[PackedFile] = []
    observations: list[tuple[Path, str, str, int]] = []
    total_bytes = 0
    total_source_bytes = 0
    inspected_source_bytes = 0
    inspection_limit = config.max_total_size * 2
    language_counts: Counter[str] = Counter()

    for _, archive_rel, source_rel in normalized:
        if len(files) >= config.max_files:
            skipped.append(SkippedFile(archive_rel, "file_limit"))
            continue
        path = root / Path(*PurePosixPath(source_rel).parts)
        try:
            planned_source_size = path.lstat().st_size
        except OSError:
            planned_source_size = 0
        if inspected_source_bytes + planned_source_size > inspection_limit:
            raise ScanError("Project source inspection exceeds the hard safety limit")
        if total_source_bytes + planned_source_size > config.max_total_size:
            skipped.append(SkippedFile(archive_rel, "source_total_size_limit"))
            continue
        packed, reason, raw_sha256, inspected_bytes = _read_one(
            path, root_real, archive_rel, config.max_file_size
        )
        inspected_source_bytes += inspected_bytes
        if inspected_source_bytes > inspection_limit:
            raise ScanError("Project source inspection exceeds the hard safety limit")
        if packed is None:
            skipped.append(SkippedFile(archive_rel, reason or "unreadable"))
            continue
        if total_bytes + len(packed.content) > config.max_total_size:
            skipped.append(SkippedFile(archive_rel, "total_size_limit"))
            continue
        if total_source_bytes + packed.source_size > config.max_total_size:
            skipped.append(SkippedFile(archive_rel, "source_total_size_limit"))
            continue
        files.append(packed)
        assert raw_sha256 is not None
        observations.append((path, archive_rel, raw_sha256, packed.source_size))
        total_bytes += len(packed.content)
        total_source_bytes += packed.source_size
        language = LANGUAGES.get(PurePosixPath(archive_rel).suffix.lower())
        if language:
            language_counts[language] += 1

    for path, archive_rel, expected_raw_sha256, expected_source_size in observations:
        if inspected_source_bytes + expected_source_size > inspection_limit:
            raise ScanError("Project source inspection exceeds the hard safety limit")
        current, reason, current_raw_sha256, inspected_bytes = _read_one(
            path, root_real, archive_rel, config.max_file_size
        )
        inspected_source_bytes += inspected_bytes
        if inspected_source_bytes > inspection_limit:
            raise ScanError("Project source inspection exceeds the hard safety limit")
        if current is None or reason is not None or current_raw_sha256 != expected_raw_sha256:
            raise ScanError("Project content changed while it was being packed; retry")

    raw_git = git_info(root, excluded_path=output_relative)
    after = snapshot_token(root, excluded_path=output_relative)
    if git_candidates is not None and (
        before is None or after is None or before != after
    ):
        raise ScanError(
            "Project snapshot could not be confirmed stable; retry from a stable repository"
        )
    config.assert_source_unchanged(root)
    if rules_policy_token(
        root, include_gitignore_fallback=fallback_rules
    ) != rules_before:
        raise ScanError("Project privacy policy changed while it was scanned; retry")

    project_name, metadata_counts = _redact_metadata(root.name, maximum=255)
    for kind, count in path_redaction_counts.items():
        metadata_counts[kind] = metadata_counts.get(kind, 0) + count
    branch, branch_counts = _redact_metadata(raw_git.branch, maximum=1024)
    for kind, count in branch_counts.items():
        metadata_counts[kind] = metadata_counts.get(kind, 0) + count
    safe_git = type(raw_git)(
        available=raw_git.available,
        branch=branch,
        commit=raw_git.commit,
        dirty=raw_git.dirty,
    )
    return ScanResult(
        root=root,
        project_name=project_name or "redacted-project",
        files=files,
        skipped=sorted(skipped, key=lambda item: (item.reason, item.path.casefold())),
        git=safe_git,
        candidate_count=len(candidates),
        languages=dict(sorted(language_counts.items(), key=lambda item: (-item[1], item[0]))),
        metadata_redactions=dict(sorted(metadata_counts.items())),
        warnings=warnings,
    )


def _walk_files(root: Path) -> list[str]:
    paths: list[str] = []
    path_bytes = 0
    discovered = 0
    pending: list[tuple[Path, str]] = [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    discovered += 1
                    rel = f"{prefix}/{entry.name}" if prefix else entry.name
                    path_bytes += len(rel.encode("utf-8", errors="surrogatepass")) + 1
                    if (
                        discovered > HARD_MAX_CANDIDATES
                        or path_bytes > MAX_CANDIDATE_PATH_BYTES
                    ):
                        raise ScanError(
                            "Project candidate paths exceed the hard safety limit"
                        )
                    child = Path(entry.path)
                    if entry.is_symlink() or is_link_or_reparse(child):
                        continue
                    try:
                        is_directory = entry.is_dir(follow_symlinks=False)
                    except OSError:
                        continue
                    if is_directory:
                        if not always_excluded(rel):
                            pending.append((child, rel))
                    else:
                        paths.append(rel)
        except ScanError:
            raise
        except OSError as exc:
            raise ScanError("Project directory cannot be enumerated safely") from exc
    return sorted(paths)


def _read_one(
    path: Path,
    root_real: Path,
    archive_rel: str,
    max_file_size: int,
) -> tuple[PackedFile | None, str | None, str | None, int]:
    inspected_bytes = 0
    try:
        if has_link_or_reparse_component(path, root_real):
            return None, "symlink_or_junction", None, inspected_bytes
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or is_link_or_reparse(path, before):
            return None, "symlink_or_junction", None, inspected_bytes
        if not stat.S_ISREG(before.st_mode):
            return None, "not_regular_file", None, inspected_bytes
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(root_real)
        except ValueError:
            return None, "outside_project", None, inspected_bytes
        if before.st_size > max_file_size:
            return None, "file_size_limit", None, inspected_bytes
        if path.suffix.lower() in BINARY_SUFFIXES:
            return None, "binary_extension", None, inspected_bytes
        with path.open("rb") as handle:
            opened_before = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened_before.st_mode):
                return None, "not_regular_file", None, inspected_bytes
            if opened_before.st_size > max_file_size:
                return None, "file_size_limit", None, inspected_bytes
            data = handle.read(max_file_size + 1)
            inspected_bytes = len(data)
            opened_after = os.fstat(handle.fileno())
        path_after = path.lstat()
    except OSError:
        return None, "io_error", None, inspected_bytes

    if (
        _file_state(before) != _file_state(opened_before)
        or _file_state(opened_before) != _file_state(opened_after)
        or _file_state(opened_after) != _file_state(path_after)
        or _file_version(before) != _file_version(path_after)
        or _file_version(opened_before) != _file_version(opened_after)
        or not stat.S_ISREG(path_after.st_mode)
        or stat.S_ISLNK(path_after.st_mode)
        or is_link_or_reparse(path, path_after)
    ):
        return None, "changed_during_read", None, inspected_bytes
    if len(data) > max_file_size:
        return None, "file_size_limit", None, inspected_bytes
    if _is_binary(data):
        return None, "binary_content", None, inspected_bytes
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None, "non_utf8_text", None, inspected_bytes

    # Canonical LF and UTF-8 make packs portable across checkout settings.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    redaction = redact_text(text)
    content = redaction.text.encode("utf-8")
    return (
        PackedFile(
            path=archive_rel,
            source_size=len(data),
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
            redactions=redaction.counts,
        ),
        None,
        hashlib.sha256(data).hexdigest(),
        inspected_bytes,
    )


def _is_binary(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data:
        return True
    controls = sum(byte < 9 or 13 < byte < 32 for byte in data)
    return controls / len(data) > 0.05


def _file_state(details: os.stat_result) -> tuple[int, int, int, int]:
    return (
        details.st_size,
        details.st_mtime_ns,
        getattr(details, "st_dev", 0),
        getattr(details, "st_ino", 0),
    )


def _file_version(details: os.stat_result) -> tuple[int, int, int]:
    return (details.st_size, details.st_mtime_ns, details.st_ctime_ns)


def _safe_archive_path(rel: str) -> str | None:
    return portable_posix_path(rel, normalize=True)


def _opaque_path_label(rel: str) -> str:
    digest = hashlib.sha256(rel.encode("utf-8", errors="surrogatepass")).hexdigest()[:12]
    return f"<unsafe-path:{digest}>"


def _priority(rel: str) -> int:
    pure = PurePosixPath(rel)
    name = pure.name.lower()
    if name in HIGH_SIGNAL_NAMES or name.startswith("readme"):
        return 0
    if pure.parts and pure.parts[0].lower() in {"docs", ".github"}:
        return 1
    if len(pure.parts) <= 2:
        return 2
    if pure.parts[0].lower() in {"src", "app", "lib", "packages"}:
        return 3
    if pure.parts[0].lower() in {"test", "tests", "spec", "specs"}:
        return 4
    return 5


def _output_relative_to_root(root: Path, output_path: Path | None) -> str | None:
    if output_path is None:
        return None
    try:
        return output_path.resolve(strict=False).relative_to(root.resolve(strict=True)).as_posix()
    except (OSError, ValueError):
        return None


def _redact_metadata(
    value: str | None, *, maximum: int
) -> tuple[str | None, dict[str, int]]:
    if value is None:
        return None, {}
    result = redact_text(value)
    counts = Counter(result.counts)
    safe_characters: list[str] = []
    for char in result.text:
        if char in BIDI_CONTROL_CHARACTERS or unicodedata.category(char) in {"Cc", "Cs"}:
            safe_characters.append("\ufffd")
            counts["UNSAFE_METADATA"] += 1
        else:
            safe_characters.append(char)
    safe_text = "".join(safe_characters)
    if len(safe_text) > maximum:
        marker = "[CONTEXTCOURIER_TRUNCATED]"
        safe_text = safe_text[: maximum - len(marker)] + marker
        counts["TRUNCATED_METADATA"] += 1
    return safe_text, dict(sorted(counts.items()))

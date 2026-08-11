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
from .ignore import always_excluded, ignored_by_rules, load_rules, normalize_relative
from .models import PackedFile, ScanResult, SkippedFile
from .pathutil import BIDI_CONTROL_CHARACTERS, is_link_or_reparse, portable_posix_path
from .redact import redact_text


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
    output_relative = _output_relative_to_root(root, output_path)
    before = snapshot_token(root, excluded_path=output_relative)
    git_candidates = git_file_list(root, include_untracked=config.include_untracked)
    warnings: list[str] = []
    if git_candidates is None:
        candidates = _walk_files(root)
        rules = load_rules(root, include_gitignore_fallback=True)
        warnings.append(
            "Git metadata was unavailable; root .gitignore matching used a best-effort fallback."
        )
    else:
        candidates = git_candidates
        rules = load_rules(root)
    if output_relative:
        candidates = [
            item for item in candidates if normalize_relative(item) != output_relative
        ]
    if len(candidates) > HARD_MAX_CANDIDATES:
        raise ScanError(
            f"Project has {len(candidates)} candidates; hard safety limit is "
            f"{HARD_MAX_CANDIDATES}"
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
    observations: list[tuple[Path, str, str]] = []
    total_bytes = 0
    total_source_bytes = 0
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
        if total_source_bytes + planned_source_size > config.max_total_size:
            skipped.append(SkippedFile(archive_rel, "source_total_size_limit"))
            continue
        packed, reason, raw_sha256 = _read_one(
            path, root_real, archive_rel, config.max_file_size
        )
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
        observations.append((path, archive_rel, raw_sha256))
        total_bytes += len(packed.content)
        total_source_bytes += packed.source_size
        language = LANGUAGES.get(PurePosixPath(archive_rel).suffix.lower())
        if language:
            language_counts[language] += 1

    for path, archive_rel, expected_raw_sha256 in observations:
        current, reason, current_raw_sha256 = _read_one(
            path, root_real, archive_rel, config.max_file_size
        )
        if current is None or reason is not None or current_raw_sha256 != expected_raw_sha256:
            raise ScanError("Project content changed while it was being packed; retry")

    after = snapshot_token(root, excluded_path=output_relative)
    if before is not None and after is not None and before != after:
        raise ScanError("Project changed while it was being packed; retry from a stable snapshot")

    raw_git = git_info(root, excluded_path=output_relative)
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
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        retained: list[str] = []
        for name in dirnames:
            child = directory_path / name
            rel = child.relative_to(root).as_posix()
            if is_link_or_reparse(child) or always_excluded(rel):
                continue
            retained.append(name)
        dirnames[:] = retained
        for name in filenames:
            paths.append((directory_path / name).relative_to(root).as_posix())
    return sorted(paths)


def _read_one(
    path: Path,
    root_real: Path,
    archive_rel: str,
    max_file_size: int,
) -> tuple[PackedFile | None, str | None, str | None]:
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or is_link_or_reparse(path, before):
            return None, "symlink_or_junction", None
        if not stat.S_ISREG(before.st_mode):
            return None, "not_regular_file", None
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(root_real)
        except ValueError:
            return None, "outside_project", None
        if before.st_size > max_file_size:
            return None, "file_size_limit", None
        if path.suffix.lower() in BINARY_SUFFIXES:
            return None, "binary_extension", None
        data = path.read_bytes()
        after = path.stat()
    except OSError:
        return None, "io_error", None

    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or getattr(before, "st_ino", 0) != getattr(after, "st_ino", 0)
    ):
        return None, "changed_during_read", None
    if len(data) > max_file_size:
        return None, "file_size_limit", None
    if _is_binary(data):
        return None, "binary_content", None
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None, "non_utf8_text", None

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
    )


def _is_binary(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:8192]
    if b"\x00" in sample:
        return True
    controls = sum(byte < 9 or 13 < byte < 32 for byte in sample)
    return controls / len(sample) > 0.05


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

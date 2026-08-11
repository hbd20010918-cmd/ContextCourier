"""Git-backed file discovery and non-sensitive repository metadata."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess

from .errors import ScanError
from .models import GitInfo


GIT_TIMEOUT_SECONDS = 30
GIT_ROUTING_ENV = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE",
    "GIT_WORK_TREE",
}


def locate_root(path: Path) -> Path:
    try:
        requested = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ScanError(f"Project path cannot be resolved: {path}") from exc
    if not requested.is_dir():
        raise ScanError(f"Project path is not a directory: {requested}")
    if shutil.which("git") is None:
        return requested

    result = _run_git(requested, ["rev-parse", "--show-toplevel"], check=False)
    if result.returncode != 0:
        return requested
    root_text = os.fsdecode(result.stdout).strip()
    if not root_text:
        return requested
    try:
        root = Path(root_text).resolve(strict=True)
    except OSError:
        return requested
    if not root.is_dir():
        return requested
    try:
        requested.relative_to(root)
    except ValueError:
        return requested
    return root


def git_file_list(root: Path, *, include_untracked: bool) -> list[str] | None:
    if shutil.which("git") is None:
        return None
    probe = _run_git(root, ["rev-parse", "--is-inside-work-tree"], check=False)
    if probe.returncode != 0 or os.fsdecode(probe.stdout).strip() != "true":
        return None

    args = ["ls-files", "--cached"]
    if include_untracked:
        args.extend(["--others", "--exclude-standard"])
    args.extend(["--deduplicate", "-z", "--"])
    result = _run_git(root, args, check=True)
    paths = _decode_nul_paths(result.stdout)
    if not paths:
        return []

    # Privacy-first: also exclude tracked files that now match an ignore rule.
    payload = b"\0".join(os.fsencode(item) for item in paths) + b"\0"
    ignored_result = _run_git(
        root,
        ["check-ignore", "--no-index", "--stdin", "-z"],
        check=False,
        input_bytes=payload,
    )
    if ignored_result.returncode not in (0, 1):
        raise ScanError("git check-ignore failed while applying repository privacy rules")
    ignored = set(_decode_nul_paths(ignored_result.stdout))
    return sorted({item.replace("\\", "/") for item in paths if item not in ignored})


def git_info(root: Path, *, excluded_path: str | None = None) -> GitInfo:
    if shutil.which("git") is None:
        return GitInfo()
    probe = _run_git(root, ["rev-parse", "--is-inside-work-tree"], check=False)
    if probe.returncode != 0:
        return GitInfo()
    branch_result = _run_git(root, ["branch", "--show-current"], check=False)
    commit_result = _run_git(root, ["rev-parse", "HEAD"], check=False)
    status_result = _run_git(root, _status_args(excluded_path), check=False)
    branch = os.fsdecode(branch_result.stdout).strip() or None
    commit = os.fsdecode(commit_result.stdout).strip() or None
    dirty = bool(status_result.stdout) if status_result.returncode == 0 else None
    return GitInfo(available=True, branch=branch, commit=commit, dirty=dirty)


def snapshot_token(root: Path, *, excluded_path: str | None = None) -> str | None:
    """Return a private in-memory token used only to detect concurrent repo changes."""
    if shutil.which("git") is None:
        return None
    head = _run_git(root, ["rev-parse", "HEAD"], check=False)
    status = _run_git(root, _status_args(excluded_path), check=False)
    if status.returncode != 0:
        return None
    digest = hashlib.sha256()
    digest.update(head.stdout if head.returncode == 0 else b"<UNBORN_HEAD>")
    digest.update(b"\0")
    digest.update(status.stdout)
    return digest.hexdigest()


def _run_git(
    root: Path,
    args: list[str],
    *,
    check: bool,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    for name in GIT_ROUTING_ENV:
        environment.pop(name, None)
    for name in tuple(environment):
        if name.startswith("GIT_CONFIG_"):
            environment.pop(name, None)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        result = subprocess.run(
            [
                "git",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-C",
                os.fspath(root),
                *args,
            ],
            input=input_bytes,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScanError(f"Git command failed: git {' '.join(args[:2])}") from exc
    if check and result.returncode != 0:
        raise ScanError(f"Git command failed: git {' '.join(args[:2])}")
    return result


def _decode_nul_paths(data: bytes) -> list[str]:
    return [os.fsdecode(item) for item in data.split(b"\0") if item]


def _status_args(excluded_path: str | None) -> list[str]:
    args = ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--", "."]
    if excluded_path:
        normalized = excluded_path.replace("\\", "/").strip("/")
        if normalized:
            args.append(f":(exclude,literal){normalized}")
    return args

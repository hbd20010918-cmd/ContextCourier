"""Git-backed file discovery and non-sensitive repository metadata."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import time

from .config import HARD_MAX_CANDIDATES
from .errors import ScanError
from .models import GitInfo


GIT_TIMEOUT_SECONDS = 30
MAX_GIT_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_GIT_STDERR_BYTES = 1024 * 1024


def locate_root(path: Path) -> Path:
    try:
        requested = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ScanError("Project path cannot be resolved") from exc
    if not requested.is_dir():
        raise ScanError("Project path is not a directory")
    git_executable = _find_git_executable(requested)
    if git_executable is None:
        return requested

    result = _run_git(
        requested,
        ["rev-parse", "--show-toplevel"],
        check=False,
        git_executable=git_executable,
    )
    if result.returncode != 0:
        return requested
    root_text = _decode_git_text(result.stdout).strip()
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
    if root != requested:
        raise ScanError(
            "The requested path is inside a Git repository; pass the repository "
            "top-level directory instead"
        )
    return root


def git_file_list(root: Path, *, include_untracked: bool) -> list[str] | None:
    git_executable = _find_git_executable(root)
    if git_executable is None:
        return None
    probe = _run_git(
        root,
        ["rev-parse", "--is-inside-work-tree"],
        check=False,
        git_executable=git_executable,
    )
    if probe.returncode != 0 or _decode_git_text(probe.stdout).strip() != "true":
        return None

    args = ["ls-files", "--cached"]
    if include_untracked:
        args.extend(["--others", "--exclude-standard"])
    args.extend(["--deduplicate", "-z", "--"])
    result = _run_git(root, args, check=True, git_executable=git_executable)
    paths = _decode_nul_paths(result.stdout)
    path_bytes = sum(len(_encode_git_path(item)) + 1 for item in paths)
    if len(paths) > HARD_MAX_CANDIDATES or path_bytes > MAX_GIT_OUTPUT_BYTES:
        raise ScanError("Git candidate paths exceed the hard safety limit")
    if not paths:
        return []

    # Privacy-first: also exclude tracked files that now match an ignore rule.
    payload = b"\0".join(_encode_git_path(item) for item in paths) + b"\0"
    ignored_result = _run_git(
        root,
        ["check-ignore", "--no-index", "--stdin", "-z"],
        check=False,
        input_bytes=payload,
        git_executable=git_executable,
    )
    if ignored_result.returncode not in (0, 1):
        raise ScanError("git check-ignore failed while applying repository privacy rules")
    ignored = set(_decode_nul_paths(ignored_result.stdout))
    return sorted({item.replace("\\", "/") for item in paths if item not in ignored})


def git_info(root: Path, *, excluded_path: str | None = None) -> GitInfo:
    git_executable = _find_git_executable(root)
    if git_executable is None:
        return GitInfo()
    probe = _run_git(
        root,
        ["rev-parse", "--is-inside-work-tree"],
        check=False,
        git_executable=git_executable,
    )
    if probe.returncode != 0:
        return GitInfo()
    branch_result = _run_git(
        root, ["branch", "--show-current"], check=False, git_executable=git_executable
    )
    commit_result = _run_git(
        root, ["rev-parse", "HEAD"], check=False, git_executable=git_executable
    )
    status_result = _run_git(
        root, _status_args(excluded_path), check=False, git_executable=git_executable
    )
    branch = _decode_git_text(branch_result.stdout).strip() or None
    commit = _decode_git_text(commit_result.stdout).strip() or None
    dirty = bool(status_result.stdout) if status_result.returncode == 0 else None
    return GitInfo(available=True, branch=branch, commit=commit, dirty=dirty)


def snapshot_token(root: Path, *, excluded_path: str | None = None) -> str | None:
    """Return a private in-memory token used only to detect concurrent repo changes."""
    git_executable = _find_git_executable(root)
    if git_executable is None:
        return None
    head = _run_git(
        root, ["rev-parse", "HEAD"], check=False, git_executable=git_executable
    )
    status = _run_git(
        root, _status_args(excluded_path), check=False, git_executable=git_executable
    )
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
    git_executable: str,
) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.upper().startswith("GIT_"):
            environment.pop(name, None)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_NO_LAZY_FETCH"] = "1"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["NoDefaultCurrentDirectoryInExePath"] = "1"
    command = [
        git_executable,
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "submodule.recurse=false",
        "-C",
        os.fspath(root),
        *args,
    ]
    try:
        with (
            tempfile.TemporaryFile() as stdin_file,
            tempfile.TemporaryFile() as stdout_file,
            tempfile.TemporaryFile() as stderr_file,
        ):
            if input_bytes is not None:
                stdin_file.write(input_bytes)
                stdin_file.seek(0)
            process = subprocess.Popen(
                command,
                stdin=stdin_file if input_bytes is not None else subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                env=environment,
                cwd=os.fspath(Path(git_executable).parent),
                shell=False,
            )
            deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
            while process.poll() is None:
                if (
                    os.fstat(stdout_file.fileno()).st_size > MAX_GIT_OUTPUT_BYTES
                    or os.fstat(stderr_file.fileno()).st_size > MAX_GIT_STDERR_BYTES
                ):
                    process.kill()
                    process.wait()
                    raise ScanError("Git command output exceeds the hard safety limit")
                if time.monotonic() >= deadline:
                    process.kill()
                    process.wait()
                    raise subprocess.TimeoutExpired(command, GIT_TIMEOUT_SECONDS)
                time.sleep(0.01)
            if (
                os.fstat(stdout_file.fileno()).st_size > MAX_GIT_OUTPUT_BYTES
                or os.fstat(stderr_file.fileno()).st_size > MAX_GIT_STDERR_BYTES
            ):
                process.wait()
                raise ScanError("Git command output exceeds the hard safety limit")
            stdout_file.seek(0)
            stderr_file.seek(0)
            result = subprocess.CompletedProcess(
                command,
                process.returncode,
                stdout_file.read(),
                stderr_file.read(),
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScanError(f"Git command failed: git {' '.join(args[:2])}") from exc
    if check and result.returncode != 0:
        raise ScanError(f"Git command failed: git {' '.join(args[:2])}")
    return result


def _decode_nul_paths(data: bytes) -> list[str]:
    if not data:
        return []
    if not data.endswith(b"\0"):
        raise ScanError("Git returned a malformed path list")
    if data.count(b"\0") > HARD_MAX_CANDIDATES:
        raise ScanError("Git candidate paths exceed the hard safety limit")
    return [item.decode("utf-8", errors="surrogateescape") for item in data.split(b"\0") if item]


def _decode_git_text(data: bytes) -> str:
    return data.decode("utf-8", errors="surrogateescape")


def _encode_git_path(value: str) -> bytes:
    return value.encode("utf-8", errors="surrogateescape")


def _find_git_executable(root: Path) -> str | None:
    root_absolute = Path(os.path.abspath(os.fspath(root)))
    executable_names = ("git.exe",) if os.name == "nt" else ("git",)
    for raw_directory in os.environ.get("PATH", "").split(os.pathsep):
        raw_directory = raw_directory.strip().strip('"')
        if not raw_directory:
            continue
        directory = Path(raw_directory).expanduser()
        if not directory.is_absolute():
            continue
        for executable_name in executable_names:
            candidate = directory / executable_name
            try:
                lexical = Path(os.path.abspath(os.fspath(candidate)))
                if _is_within(lexical, root_absolute):
                    continue
                resolved = candidate.resolve(strict=True)
            except OSError:
                continue
            if not resolved.is_file() or not os.access(resolved, os.X_OK):
                continue
            if _is_within(resolved, root_absolute):
                continue
            return os.fspath(resolved)
    return None


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _status_args(excluded_path: str | None) -> list[str]:
    args = [
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=all",
        "--",
        ".",
    ]
    if excluded_path:
        normalized = excluded_path.replace("\\", "/").strip("/")
        if normalized:
            args.append(f":(exclude,literal){normalized}")
    return args

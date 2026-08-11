"""Cross-version helpers for Windows reparse points and ordinary symlinks."""

from __future__ import annotations

import os
from pathlib import Path
from pathlib import PurePosixPath
import stat
from typing import Any
import unicodedata


BIDI_CONTROL_CHARACTERS = {
    "\u061c",
    "\u200e",
    "\u200f",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}
WINDOWS_RESERVED_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}


def is_link_or_reparse(path: Path, file_stat: os.stat_result | Any | None = None) -> bool:
    """Return true for symlinks, junctions, and other Windows reparse points.

    ``Path.is_junction`` was added after Python 3.11, so the file-attribute fallback is part
    of the supported Windows security boundary rather than an optional optimization.
    """
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        details = file_stat if file_stat is not None else path.lstat()
    except OSError:
        return False
    attributes = getattr(details, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def has_link_or_reparse_component(path: Path, root: Path) -> bool:
    """Check every component below ``root`` without following it first."""
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    current = root
    for part in relative.parts:
        current = current / part
        details = current.lstat()
        if stat.S_ISLNK(details.st_mode) or is_link_or_reparse(current, details):
            return True
    return False


def portable_posix_path(value: str, *, normalize: bool = False) -> str | None:
    """Return a Windows-safe, canonical POSIX path, or ``None`` when unsafe."""
    if not value or "\x00" in value or "\\" in value:
        return None
    normalized = unicodedata.normalize("NFC", value)
    if normalized != value and not normalize:
        return None
    if len(normalized.encode("utf-8", errors="surrogatepass")) > 4096:
        return None
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
        return None
    canonical = pure.as_posix()
    if canonical != normalized:
        return None
    for part in pure.parts:
        if not part or len(part.encode("utf-8", errors="surrogatepass")) > 255:
            return None
        if ":" in part or part.endswith((" ", ".")):
            return None
        reserved_stem = part.rstrip(" .").split(".", 1)[0].casefold()
        if reserved_stem in WINDOWS_RESERVED_NAMES:
            return None
    for char in normalized:
        if char in BIDI_CONTROL_CHARACTERS or unicodedata.category(char) in {"Cc", "Cs"}:
            return None
    return canonical

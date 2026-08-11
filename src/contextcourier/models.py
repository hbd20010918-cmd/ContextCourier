"""Small immutable data models shared by scanner and archive code."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class PackedFile:
    path: str
    source_size: int
    content: bytes
    sha256: str
    redactions: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class SkippedFile:
    path: str
    reason: str


@dataclass(frozen=True)
class GitInfo:
    available: bool = False
    branch: str | None = None
    commit: str | None = None
    dirty: bool | None = None


@dataclass
class ScanResult:
    root: Path
    project_name: str
    files: list[PackedFile]
    skipped: list[SkippedFile]
    git: GitInfo
    candidate_count: int
    languages: dict[str, int]
    metadata_redactions: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def packed_bytes(self) -> int:
        return sum(len(item.content) for item in self.files)

    @property
    def source_bytes(self) -> int:
        return sum(item.source_size for item in self.files)

    @property
    def redaction_counts(self) -> dict[str, int]:
        counts: dict[str, int] = dict(self.metadata_redactions)
        for item in self.files:
            for kind, count in item.redactions.items():
                counts[kind] = counts.get(kind, 0) + count
        return dict(sorted(counts.items()))

    @property
    def redaction_total(self) -> int:
        return sum(self.redaction_counts.values())

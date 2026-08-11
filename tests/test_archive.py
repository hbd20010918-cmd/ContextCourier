from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
import zipfile

from contextcourier.archive import build_archive, inspect_archive, verify_archive
from contextcourier.config import Config
from contextcourier.errors import ContextCourierError, VerificationError
from contextcourier.scanner import scan_project


FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def _canonical_info(name: str, *, mode: int = stat.S_IFREG | 0o644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (mode & 0xFFFF) << 16
    info.extra = b""
    info.comment = b""
    return info


def _write_entries(
    path: Path,
    entries: dict[str, bytes],
    *,
    ordered_names: list[str] | None = None,
    modes: dict[str, int] | None = None,
) -> None:
    names = ordered_names or sorted(entries, key=lambda value: (value.casefold(), value))
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in names:
            archive.writestr(
                _canonical_info(name, mode=(modes or {}).get(name, stat.S_IFREG | 0o644)),
                entries[name],
            )


def _read_entries(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path, "r") as archive:
        return {info.filename: archive.read(info) for info in archive.infolist()}


def _canonical_manifest(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


class ArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.project = self.base / "demo"
        (self.project / "src").mkdir(parents=True)
        (self.project / "README.md").write_text("# Demo\n", encoding="utf-8")
        self.canary = "sk-proj-" + ("C" * 32)
        key_name = "API_" + "KEY"
        (self.project / "src" / "app.py").write_text(
            f'{key_name} = "{self.canary}"\nprint("hello")\n',
            encoding="utf-8",
        )
        env_key = "PASS" + "WORD"
        env_value = "must-not-" + "escape"
        (self.project / ".env").write_text(
            f"{env_key}={env_value}\n", encoding="utf-8"
        )
        self.path_canary = "ghp_" + ("d" * 36)
        (self.project / f"notes-{self.path_canary}.txt").write_text(
            "safe body\n", encoding="utf-8"
        )
        (self.project / "image.bin").write_bytes(b"\x00\x01\x02")
        self._init_git()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _init_git(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("Git is required for this integration test")
        subprocess.run(["git", "init", "-q", str(self.project)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.project),
                "add",
                "README.md",
                "src/app.py",
                "image.bin",
                f"notes-{self.path_canary}.txt",
            ],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.project), "add", "-f", ".env"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.project), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"],
            check=True,
        )
        self.branch_canary = "gho_" + ("e" * 36)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.project),
                "checkout",
                "-qb",
                f"feature/{self.branch_canary}",
            ],
            check=True,
        )

    def test_pack_is_deterministic_redacted_and_verifiable(self) -> None:
        config = Config()
        scan = scan_project(self.project, config)
        first = self.base / "first.contextcourier.zip"
        second = self.base / "second.contextcourier.zip"

        first_result = build_archive(scan, config, first)
        second_result = build_archive(scan, config, second)

        self.assertEqual(first_result.sha256, second_result.sha256)
        self.assertEqual(first_result.source_bytes, scan.source_bytes)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertNotIn(self.canary.encode(), first.read_bytes())
        self.assertNotIn(self.path_canary.encode(), first.read_bytes())
        self.assertNotIn(self.branch_canary.encode(), first.read_bytes())
        self.assertNotIn(b"must-not-escape", first.read_bytes())
        summary = verify_archive(first)
        self.assertEqual(summary["integrity"], "VERIFIED")
        self.assertEqual(summary["redactions"], 3)
        inspected = inspect_archive(first)
        self.assertEqual(inspected["integrity"], "NOT_VERIFIED")

        with zipfile.ZipFile(first, "r") as archive:
            self.assertNotIn("files/.env", archive.namelist())
            manifest = json.loads(archive.read("MANIFEST.json"))
            self.assertNotIn(str(self.project), json.dumps(manifest))

    def test_tampered_entry_fails_sha256_verification(self) -> None:
        config = Config()
        scan = scan_project(self.project, config)
        original = self.base / "original.contextcourier.zip"
        tampered = self.base / "tampered.contextcourier.zip"
        build_archive(scan, config, original)

        with zipfile.ZipFile(original, "r") as source, zipfile.ZipFile(
            tampered, "w", compression=zipfile.ZIP_STORED
        ) as destination:
            for info in source.infolist():
                content = source.read(info)
                if info.filename == "CONTEXT.md":
                    content += b"tampered\n"
                destination.writestr(info.filename, content)

        with self.assertRaises(VerificationError):
            verify_archive(tampered)

    def test_force_repack_inside_clean_repo_is_byte_identical(self) -> None:
        config = Config()
        output = self.project / "handoff [v1]!.contextcourier.zip"

        first_scan = scan_project(self.project, config, output_path=output)
        first = build_archive(first_scan, config, output)
        second_scan = scan_project(self.project, config, output_path=output)
        second = build_archive(second_scan, config, output, force=True)

        self.assertFalse(first_scan.git.dirty)
        self.assertFalse(second_scan.git.dirty)
        self.assertEqual(first.sha256, second.sha256)

    def test_path_traversal_entry_is_rejected(self) -> None:
        malicious = self.base / "malicious.zip"
        with zipfile.ZipFile(malicious, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("../escape.txt", b"no")
        with self.assertRaises(VerificationError):
            verify_archive(malicious)

    def test_output_symlink_is_never_followed(self) -> None:
        config = Config()
        scan = scan_project(self.project, config)
        target = self.base / "target.zip"
        target.write_bytes(b"keep-me")
        link = self.base / "output.contextcourier.zip"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("File symlinks are not available in this environment")

        with self.assertRaises(ContextCourierError):
            build_archive(scan, config, link, force=True)
        self.assertEqual(target.read_bytes(), b"keep-me")

    def test_manifest_hashes_match_all_non_manifest_entries(self) -> None:
        config = Config()
        scan = scan_project(self.project, config)
        output = self.base / "hashes.contextcourier.zip"
        build_archive(scan, config, output)

        with zipfile.ZipFile(output, "r") as archive:
            manifest = json.loads(archive.read("MANIFEST.json"))
            for record in manifest["entries"]:
                content = archive.read(record["path"])
                self.assertEqual(hashlib.sha256(content).hexdigest(), record["sha256"])

    def test_early_v1_optional_statistics_remain_verifiable(self) -> None:
        config = Config()
        original = self.base / "new-v1.zip"
        compatible = self.base / "early-v1.zip"
        build_archive(scan_project(self.project, config), config, original)
        entries = _read_entries(original)
        manifest = json.loads(entries["MANIFEST.json"])
        early_metadata = manifest["project"].pop("metadata_redactions")
        for kind, count in early_metadata.items():
            manifest["totals"]["redactions_by_kind"][kind] -= count
            if manifest["totals"]["redactions_by_kind"][kind] == 0:
                manifest["totals"]["redactions_by_kind"].pop(kind)
            manifest["totals"]["redactions"] -= count
        manifest["totals"].pop("source_bytes")
        entries["MANIFEST.json"] = _canonical_manifest(manifest)
        _write_entries(compatible, entries)

        self.assertEqual(verify_archive(compatible)["integrity"], "VERIFIED")

    def test_required_layout_and_extra_root_entries_are_rejected(self) -> None:
        config = Config()
        original = self.base / "layout-original.zip"
        build_archive(scan_project(self.project, config), config, original)

        missing = self.base / "missing-adapter.zip"
        missing_entries = _read_entries(original)
        manifest = json.loads(missing_entries["MANIFEST.json"])
        manifest["entries"] = [
            item for item in manifest["entries"] if item["path"] != "adapters/CLAUDE.md"
        ]
        missing_entries.pop("adapters/CLAUDE.md")
        missing_entries["MANIFEST.json"] = _canonical_manifest(manifest)
        _write_entries(missing, missing_entries)

        extra = self.base / "extra-root.zip"
        extra_entries = _read_entries(original)
        extra_entries["run-me.cmd"] = b"echo unsafe\n"
        _write_entries(extra, extra_entries)

        for candidate in (missing, extra):
            with self.subTest(candidate=candidate.name):
                with self.assertRaises(VerificationError):
                    inspect_archive(candidate)
                with self.assertRaises(VerificationError):
                    verify_archive(candidate)

    def test_unsafe_cross_platform_paths_and_symlink_modes_are_rejected(self) -> None:
        unsafe_names = (
            "C:/drive.txt",
            "files/name:stream",
            "files/CON",
            "files/control\x1b.txt",
        )
        for index, name in enumerate(unsafe_names):
            candidate = self.base / f"unsafe-{index}.zip"
            _write_entries(candidate, {name: b"unsafe"})
            with self.subTest(name=repr(name)), self.assertRaises(VerificationError):
                verify_archive(candidate)

        symlink = self.base / "symlink-entry.zip"
        _write_entries(
            symlink,
            {"MANIFEST.json": b"{}\n"},
            modes={"MANIFEST.json": stat.S_IFLNK | 0o777},
        )
        with self.assertRaises(VerificationError):
            verify_archive(symlink)

    def test_manifest_json_and_entry_order_must_be_canonical(self) -> None:
        config = Config()
        original = self.base / "canonical-original.zip"
        build_archive(scan_project(self.project, config), config, original)
        entries = _read_entries(original)

        noncanonical_json = self.base / "noncanonical-json.zip"
        value = json.loads(entries["MANIFEST.json"])
        compact_entries = dict(entries)
        compact_entries["MANIFEST.json"] = json.dumps(value, separators=(",", ":")).encode(
            "utf-8"
        )
        _write_entries(noncanonical_json, compact_entries)

        reversed_order = self.base / "reversed-order.zip"
        canonical_names = sorted(entries, key=lambda item: (item.casefold(), item))
        _write_entries(reversed_order, entries, ordered_names=list(reversed(canonical_names)))

        for candidate in (noncanonical_json, reversed_order):
            with self.subTest(candidate=candidate.name), self.assertRaises(VerificationError):
                verify_archive(candidate)

    def test_malformed_or_deep_manifest_is_a_bounded_verification_error(self) -> None:
        huge_integer = b'{"schema_version":' + (b"9" * 5000) + b"}\n"
        deep_json = ("[" * 2000 + "0" + "]" * 2000 + "\n").encode("utf-8")
        for index, payload in enumerate((huge_integer, deep_json)):
            candidate = self.base / f"malformed-{index}.zip"
            _write_entries(candidate, {"MANIFEST.json": payload})
            with self.subTest(index=index), self.assertRaises(VerificationError):
                inspect_archive(candidate)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from contextcourier.cli import EXIT_CONFIG, EXIT_OK, EXIT_SECRET_POLICY, main
from contextcourier.cli import EXIT_OPERATIONAL, EXIT_VERIFICATION


class CliTests(unittest.TestCase):
    def test_init_pack_and_verify_json_flow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("# Small project\n", encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(main(["init", str(root), "--json"]), EXIT_OK)
            self.assertTrue((root / ".contextcourier.toml").exists())
            self.assertTrue((root / ".contextcourierignore").exists())

            archive = root / "handoff.contextcourier.zip"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = main(["pack", str(root), "-o", str(archive), "--json"])
            self.assertEqual(result, EXIT_OK)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["output"], str(archive))

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(main(["verify", str(archive), "--json"]), EXIT_OK)
            self.assertEqual(json.loads(stdout.getvalue())["integrity"], "VERIFIED")

    def test_init_refuses_overwrite_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".contextcourier.toml").write_text("existing\n", encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(["init", str(root)])
            self.assertEqual(result, EXIT_CONFIG)
            self.assertIn("Refusing to replace", stderr.getvalue())

    def test_fail_on_secret_writes_no_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = "pass" + "word"
            value = "correct-horse-" + "battery-staple"
            (root / "app.txt").write_text(
                f'{key}="{value}"\n',
                encoding="utf-8",
            )
            output = root / "blocked.contextcourier.zip"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(
                    ["pack", str(root), "-o", str(output), "--fail-on-secret"]
                )
            self.assertEqual(result, EXIT_SECRET_POLICY)
            self.assertFalse(output.exists())
            self.assertNotIn("correct-horse", stderr.getvalue())

    def test_secret_in_filename_triggers_fail_on_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            credential = "ghp_" + ("f" * 36)
            (root / f"notes-{credential}.txt").write_text(
                "safe body\n", encoding="utf-8"
            )
            output = root / "blocked.contextcourier.zip"
            with redirect_stderr(io.StringIO()):
                result = main(
                    ["pack", str(root), "-o", str(output), "--fail-on-secret"]
                )
            self.assertEqual(result, EXIT_SECRET_POLICY)
            self.assertFalse(output.exists())

    def test_init_preflights_all_targets_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".contextcourierignore").mkdir()
            with redirect_stderr(io.StringIO()):
                result = main(["init", str(root)])
            self.assertEqual(result, EXIT_CONFIG)
            self.assertFalse((root / ".contextcourier.toml").exists())

    def test_archive_operational_and_verification_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing.zip"
            corrupt = root / "corrupt.zip"
            corrupt.write_bytes(b"not a zip")
            for archive, expected in (
                (missing, EXIT_OPERATIONAL),
                (root, EXIT_OPERATIONAL),
                (corrupt, EXIT_VERIFICATION),
            ):
                with self.subTest(archive=archive), redirect_stderr(io.StringIO()):
                    self.assertEqual(main(["verify", str(archive)]), expected)

    def test_console_output_survives_legacy_windows_encoding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project-\U0001f680"
            root.mkdir()
            (root / "README.md").write_text("# demo\n", encoding="utf-8")
            for arguments in (
                ["scan", str(root)],
                ["scan", str(root), "--json"],
            ):
                raw = io.BytesIO()
                stream = io.TextIOWrapper(raw, encoding="cp936", errors="strict")
                try:
                    with self.subTest(arguments=arguments), redirect_stdout(stream):
                        self.assertEqual(main(arguments), EXIT_OK)
                    stream.flush()
                    output = raw.getvalue().decode("cp936")
                    self.assertTrue(output.strip())
                finally:
                    stream.detach()


if __name__ == "__main__":
    unittest.main()

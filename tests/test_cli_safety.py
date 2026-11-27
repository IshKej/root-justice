"""CLI safety/UX regression tests for :mod:`artex_antidote.cli`.

Covers the audit fixes:

* ``reverse-patch --export-dir`` now routes through the human-review gate and
  refuses to write a federal bundle without ``--reviewed-by``.
* ``--version`` is sourced from ``artex_antidote.__version__``.
* ``prog`` is ``root-justice`` (matches the installed binary / docs).
* The cosmetic posture flag is renamed on ``dashboard`` / ``health`` while the
  old ``--enforce`` spelling stays backward-compatible.
* Top-level error handling turns common I/O / parse failures into a concise
  ``error:`` line on stderr with a non-zero exit (no raw traceback).

Every test runs fully offline. The RDAP seam used by ``reverse-patch`` is
monkeypatched so nothing touches the network.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

from artex_antidote import __version__, cli
from artex_antidote import attribution as attribution_mod


def _run_cli(argv: list[str]) -> tuple[str, str, int]:
    """Run ``cli.main`` with ``argv``; return (stdout, stderr, exit_code)."""
    out, err = io.StringIO(), io.StringIO()
    old = sys.argv
    sys.argv = ["root-justice"] + argv
    code = 0
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            cli.main()
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    finally:
        sys.argv = old
    return out.getvalue(), err.getvalue(), code


class _NoNetwork:
    """Patch out the RDAP lookup so reverse-patch stays offline."""

    def __enter__(self):
        self._orig = attribution_mod.lookup_rdap
        attribution_mod.lookup_rdap = lambda ip: {"ip": ip, "offline": True}
        return self

    def __exit__(self, *a):
        attribution_mod.lookup_rdap = self._orig


class TestReversePatchReviewerGate(unittest.TestCase):
    def test_export_dir_without_reviewer_refuses_and_exits_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _NoNetwork():
            export_dir = Path(tmp) / "fed_out"
            stdout, stderr, code = _run_cli([
                "reverse-patch", "--ip", "203.0.113.45",
                "--path", "/.env", "--ua", "nuclei",
                "--export-dir", str(export_dir),
            ])
            self.assertNotEqual(code, 0)
            self.assertIn("--reviewed-by", stderr)
            self.assertEqual(stdout, "")
            # No federal-named bundle may be written without a reviewer.
            self.assertFalse((export_dir / "ic3_cisa_report.md").exists())
            self.assertFalse((export_dir / "stix_bundle.json").exists())

    def test_export_dir_with_reviewer_writes_reviewed_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _NoNetwork():
            export_dir = Path(tmp) / "fed_out"
            stdout, stderr, code = _run_cli([
                "reverse-patch", "--ip", "203.0.113.45",
                "--path", "/.env", "--ua", "nuclei",
                "--export-dir", str(export_dir),
                "--reviewed-by", "Operator One",
            ])
            self.assertEqual(code, 0, stderr)
            payload = json.loads(stdout)
            self.assertIn("exported_files", payload)
            # The reviewer-gated exporter writes the attestation.
            self.assertTrue((export_dir / "review_attestation.json").exists())
            attestation = json.loads((export_dir / "review_attestation.json").read_text(encoding="utf-8"))
            self.assertEqual(attestation["reviewed_by"], "Operator One")

    def test_no_export_dir_skips_bundle(self) -> None:
        with _NoNetwork():
            stdout, stderr, code = _run_cli([
                "reverse-patch", "--ip", "203.0.113.45", "--path", "/.env",
            ])
            self.assertEqual(code, 0, stderr)
            payload = json.loads(stdout)
            self.assertNotIn("exported_files", payload)


class TestVersionAndProg(unittest.TestCase):
    def test_version_flag_reports_package_version(self) -> None:
        stdout, stderr, code = _run_cli(["--version"])
        self.assertEqual(code, 0)
        self.assertIn(__version__, stdout)
        self.assertIn("root-justice", stdout)

    def test_prog_name_in_usage(self) -> None:
        # Argparse errors exit 2 and print usage with the prog name.
        stdout, stderr, code = _run_cli([])
        self.assertEqual(code, 2)
        self.assertIn("root-justice", stderr)
        self.assertNotIn("artex-antidote", stderr)


class TestPostureLabelRename(unittest.TestCase):
    def test_health_new_posture_flag(self) -> None:
        stdout, _, code = _run_cli(["health", "--posture-label-enforce"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["mode"], "enforce")

    def test_health_legacy_enforce_alias_still_works(self) -> None:
        stdout, _, code = _run_cli(["health", "--enforce"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["mode"], "enforce")

    def test_dashboard_new_posture_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_html = str(Path(tmp) / "dash.html")
            stdout, stderr, code = _run_cli([
                "dashboard", "--evidence", str(Path(tmp) / "nope.jsonl"),
                "--out", out_html, "--posture-label-enforce",
            ])
            self.assertEqual(code, 0, stderr)
            self.assertTrue(Path(out_html).exists())


class TestTopLevelErrorHandling(unittest.TestCase):
    def test_missing_file_is_concise_error_not_traceback(self) -> None:
        missing = "this_file_does_not_exist_12345.json"
        stdout, stderr, code = _run_cli(["validate-stix", missing])
        self.assertEqual(code, 1)
        self.assertTrue(stderr.startswith("error:"))
        self.assertNotIn("Traceback", stderr)

    def test_bad_json_is_concise_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("{not valid json", encoding="utf-8")
            stdout, stderr, code = _run_cli(["validate-stix", str(bad)])
            self.assertEqual(code, 1)
            self.assertTrue(stderr.startswith("error:"))
            self.assertNotIn("Traceback", stderr)


if __name__ == "__main__":
    unittest.main()

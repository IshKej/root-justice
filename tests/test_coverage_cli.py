"""Tests for the ``coverage`` CLI subcommand wired into artex_antidote.cli.

Deterministic and offline: the coverage matrix does no I/O, and these tests
drive the CLI entrypoint in-process (patching argv and capturing stdout), so no
network, admin, or filesystem-external access is required. The core assertion is
that the control matrix exposes exactly the seven AI-hacking-tool classes.
"""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout
from unittest import mock

from artex_antidote import cli, coverage


def _run_cli(argv):
    """Invoke cli.main() with the given argv list, returning captured stdout."""
    buf = io.StringIO()
    with mock.patch("sys.argv", ["artex-antidote", *argv]), redirect_stdout(buf):
        cli.main()
    return buf.getvalue()


class CoverageMatrixTests(unittest.TestCase):
    def test_coverage_matrix_has_seven_entries(self) -> None:
        self.assertEqual(len(coverage.coverage_matrix()), 7)


class CoverageCliJsonTests(unittest.TestCase):
    def test_coverage_command_emits_seven_entries(self) -> None:
        out = _run_cli(["coverage"])
        payload = json.loads(out)
        self.assertIn("matrix", payload)
        self.assertEqual(len(payload["matrix"]), 7)
        # Summary counts must also account for exactly seven rows.
        self.assertEqual(sum(payload["summary"].values()), 7)

    def test_coverage_command_rows_have_required_keys(self) -> None:
        payload = json.loads(_run_cli(["coverage"]))
        required = {"id", "attack", "root_justice_control", "status", "note"}
        for row in payload["matrix"]:
            self.assertEqual(set(row.keys()), required, row)

    def test_coverage_ids_are_distinct(self) -> None:
        payload = json.loads(_run_cli(["coverage"]))
        ids = [row["id"] for row in payload["matrix"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 7)


class CoverageCliMarkdownTests(unittest.TestCase):
    def test_markdown_renders_header_and_seven_rows(self) -> None:
        out = _run_cli(["coverage", "--markdown"])
        lines = [ln for ln in out.splitlines() if ln.strip()]
        # header + separator + 7 data rows
        self.assertEqual(len(lines), 9)
        self.assertTrue(lines[0].startswith("| ID |"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

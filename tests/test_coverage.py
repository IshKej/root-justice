"""Tests for artex_antidote.coverage — the self-documenting control matrix.

Deterministic and offline: the module does no I/O, so these assertions only
exercise the in-memory data and its deterministic readers.
"""

from __future__ import annotations

import unittest

from artex_antidote import coverage
from artex_antidote.coverage import (
    COVERAGE,
    STATUSES,
    STATUS_NEUTRALIZED,
    coverage_matrix,
    render_markdown,
    summary,
)

EXPECTED_IDS = {
    "cloud_buckets",
    "lookalike_domains",
    "hash_cracking",
    "exposed_site_files",
    "firmware_secrets",
    "keystroke_injection",
    "wifi_cracking",
}

EXPECTED_STATUS = {
    "exposed_site_files": "neutralized",
    "firmware_secrets": "partial",
    "hash_cracking": "partial",
    "cloud_buckets": "partial",
    "lookalike_domains": "partial",
    "keystroke_injection": "advisory",
    "wifi_cracking": "advisory",
}


class CoverageShapeTests(unittest.TestCase):
    def test_exactly_seven_entries(self) -> None:
        self.assertEqual(len(COVERAGE), 7)
        self.assertEqual(len(coverage_matrix()), 7)

    def test_all_expected_attack_classes_present(self) -> None:
        ids = {row["id"] for row in COVERAGE}
        self.assertEqual(ids, EXPECTED_IDS)

    def test_no_duplicate_ids(self) -> None:
        ids = [row["id"] for row in COVERAGE]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_row_has_required_keys(self) -> None:
        required = {"id", "attack", "root_justice_control", "status", "note"}
        for row in COVERAGE:
            self.assertEqual(set(row.keys()), required, row)

    def test_every_control_and_note_non_empty(self) -> None:
        for row in COVERAGE:
            self.assertTrue(row["root_justice_control"].strip(), row["id"])
            self.assertTrue(row["note"].strip(), row["id"])
            self.assertTrue(row["attack"].strip(), row["id"])

    def test_statuses_are_from_vocabulary(self) -> None:
        for row in COVERAGE:
            self.assertIn(row["status"], STATUSES, row["id"])


class StatusAssignmentTests(unittest.TestCase):
    def test_exposed_site_files_is_neutralized(self) -> None:
        row = next(r for r in COVERAGE if r["id"] == "exposed_site_files")
        self.assertEqual(row["status"], STATUS_NEUTRALIZED)
        self.assertEqual(row["status"], "neutralized")

    def test_each_row_has_expected_status(self) -> None:
        actual = {row["id"]: row["status"] for row in COVERAGE}
        self.assertEqual(actual, EXPECTED_STATUS)

    def test_exactly_one_neutralized(self) -> None:
        neutralized = [r for r in COVERAGE if r["status"] == "neutralized"]
        self.assertEqual(len(neutralized), 1)
        self.assertEqual(neutralized[0]["id"], "exposed_site_files")


class SummaryTests(unittest.TestCase):
    def test_counts_sum_to_seven(self) -> None:
        self.assertEqual(sum(summary().values()), 7)

    def test_summary_values(self) -> None:
        self.assertEqual(
            summary(),
            {"neutralized": 1, "partial": 4, "advisory": 2, "out_of_scope": 0},
        )

    def test_summary_keys_cover_vocabulary(self) -> None:
        self.assertEqual(set(summary().keys()), set(STATUSES))


class IsolationTests(unittest.TestCase):
    def test_coverage_matrix_returns_copy(self) -> None:
        rows = coverage_matrix()
        rows[0]["status"] = "mutated"
        rows.append({"id": "x"})
        # Source of truth is untouched.
        self.assertEqual(len(COVERAGE), 7)
        self.assertNotEqual(COVERAGE[0]["status"], "mutated")

    def test_summary_is_stable_across_calls(self) -> None:
        self.assertEqual(summary(), summary())


class RenderMarkdownTests(unittest.TestCase):
    def test_returns_str_with_header_and_rows(self) -> None:
        md = render_markdown()
        self.assertIsInstance(md, str)
        lines = md.splitlines()
        # header + separator + 7 data rows
        self.assertEqual(len(lines), 9)
        self.assertTrue(lines[0].startswith("| ID |"))
        self.assertTrue(set(lines[1]) <= set("| -"))

    def test_every_id_appears_in_table(self) -> None:
        md = render_markdown()
        for row in COVERAGE:
            self.assertIn(row["id"], md)

    def test_cells_do_not_break_table(self) -> None:
        # No raw newline inside a rendered data row would corrupt the table.
        for line in render_markdown().splitlines()[2:]:
            self.assertEqual(line.count("\n"), 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

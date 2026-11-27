"""Tests for artex_antidote.retention (offline, no clock, no admin).

All timing is injected: rotation takes the archive timestamp as an argument and
pruning takes ``now_ts``, so these tests are deterministic. File sizes are driven
both by real bytes on disk and, where a large file would be wasteful, by
monkeypatching the module-level ``_file_size`` seam.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from artex_antidote import retention


class RotateIfNeededTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.ledger = self.dir / "evidence.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_absent_file_is_noop(self) -> None:
        self.assertIsNone(retention.rotate_if_needed(self.ledger, max_bytes=10, timestamp=1000))
        self.assertFalse(self.ledger.exists())

    def test_under_threshold_not_rotated(self) -> None:
        self.ledger.write_text("x" * 50, encoding="utf-8")
        self.assertIsNone(retention.rotate_if_needed(self.ledger, max_bytes=100, timestamp=1000))
        # Live file untouched.
        self.assertEqual(self.ledger.read_text(encoding="utf-8"), "x" * 50)

    def test_exactly_at_threshold_not_rotated(self) -> None:
        self.ledger.write_text("x" * 100, encoding="utf-8")
        # size == max_bytes is NOT over size.
        self.assertIsNone(retention.rotate_if_needed(self.ledger, max_bytes=100, timestamp=1000))

    def test_over_threshold_rotates_and_recreates_live_file(self) -> None:
        payload = "y" * 200
        self.ledger.write_text(payload, encoding="utf-8")
        archive = retention.rotate_if_needed(self.ledger, max_bytes=100, timestamp=1700000000)

        self.assertIsNotNone(archive)
        archive_path = Path(archive)
        # Archive holds the full original bytes, unmodified.
        self.assertTrue(archive_path.exists())
        self.assertEqual(archive_path.read_text(encoding="utf-8"), payload)
        self.assertEqual(archive_path.name, "evidence.jsonl.1700000000.jsonl")
        # Active ledger is never dropped: it exists again and is empty.
        self.assertTrue(self.ledger.exists())
        self.assertEqual(self.ledger.read_text(encoding="utf-8"), "")

    def test_rotation_preserves_append_only_continuity(self) -> None:
        self.ledger.write_text("old line\n", encoding="utf-8")
        retention.rotate_if_needed(self.ledger, max_bytes=1, timestamp=42)
        # Appending to the fresh live file works and does not resurrect old data.
        with self.ledger.open("a", encoding="utf-8") as fh:
            fh.write("new line\n")
        self.assertEqual(self.ledger.read_text(encoding="utf-8"), "new line\n")

    def test_injected_size_seam(self) -> None:
        # Tiny real file, but the seam reports it as huge -> must rotate.
        self.ledger.write_text("tiny", encoding="utf-8")
        original = retention._file_size
        try:
            retention._file_size = lambda _p: 10_000_000
            archive = retention.rotate_if_needed(self.ledger, max_bytes=1024, timestamp=7)
        finally:
            retention._file_size = original
        self.assertIsNotNone(archive)
        self.assertTrue(Path(archive).exists())

    def test_invalid_arguments_raise(self) -> None:
        self.ledger.write_text("data", encoding="utf-8")
        with self.assertRaises(ValueError):
            retention.rotate_if_needed(self.ledger, max_bytes=-1, timestamp=1)
        with self.assertRaises(ValueError):
            retention.rotate_if_needed(self.ledger, max_bytes=1, timestamp=-5)
        with self.assertRaises(ValueError):
            # bool must not sneak through as an int timestamp.
            retention.rotate_if_needed(self.ledger, max_bytes=1, timestamp=True)


class ArchiveHelperTests(unittest.TestCase):
    def test_is_archive_and_timestamp(self) -> None:
        self.assertTrue(retention.is_archive("evidence.jsonl.1700000000.jsonl"))
        self.assertEqual(retention.archive_timestamp("evidence.jsonl.1700000000.jsonl"), 1700000000)
        # The live ledger is not an archive.
        self.assertFalse(retention.is_archive("evidence.jsonl"))
        self.assertIsNone(retention.archive_timestamp("evidence.jsonl"))
        # Unrelated files are ignored.
        self.assertFalse(retention.is_archive("notes.txt"))

    def test_list_archives_sorted_and_missing_dir(self) -> None:
        self.assertEqual(retention.list_archives("C:/no/such/dir/xyz-absent"), [])
        with tempfile.TemporaryDirectory() as d:
            dpath = Path(d)
            (dpath / "evidence.jsonl").write_text("live", encoding="utf-8")  # live, ignored
            (dpath / "evidence.jsonl.300.jsonl").write_text("c", encoding="utf-8")
            (dpath / "evidence.jsonl.100.jsonl").write_text("a", encoding="utf-8")
            (dpath / "evidence.jsonl.200.jsonl").write_text("b", encoding="utf-8")
            (dpath / "readme.md").write_text("x", encoding="utf-8")  # ignored
            archives = retention.list_archives(dpath)
            self.assertEqual(
                [p.name for p in archives],
                [
                    "evidence.jsonl.100.jsonl",
                    "evidence.jsonl.200.jsonl",
                    "evidence.jsonl.300.jsonl",
                ],
            )


class PruneArchivesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _make(self, ts: int) -> Path:
        p = self.dir / f"evidence.jsonl.{ts}.jsonl"
        p.write_text(f"archive@{ts}\n", encoding="utf-8")
        return p

    def test_prunes_only_old_archives(self) -> None:
        day = retention.SECONDS_PER_DAY
        now = 100 * day
        old = self._make(now - 40 * day)      # 40 days old -> pruned (retain 30)
        boundary = self._make(now - 30 * day)  # exactly 30 days -> kept
        fresh = self._make(now - 5 * day)      # recent -> kept
        live = self.dir / "evidence.jsonl"
        live.write_text("active\n", encoding="utf-8")

        removed = retention.prune_archives(self.dir, retain_days=30, now_ts=now)

        self.assertEqual(removed, [str(old.resolve())])
        self.assertFalse(old.exists())
        self.assertTrue(boundary.exists())
        self.assertTrue(fresh.exists())
        # The live ledger is never a prune candidate.
        self.assertTrue(live.exists())

    def test_zero_retain_keeps_current_second(self) -> None:
        now = 1_000_000
        same = self._make(now)        # age 0 -> kept even at retain_days=0
        one_sec = self._make(now - 1)  # age 1s > 0 -> pruned
        removed = retention.prune_archives(self.dir, retain_days=0, now_ts=now)
        self.assertEqual(removed, [str(one_sec.resolve())])
        self.assertTrue(same.exists())

    def test_missing_dir_returns_empty(self) -> None:
        removed = retention.prune_archives(self.dir / "absent", retain_days=7, now_ts=10**9)
        self.assertEqual(removed, [])

    def test_negative_retain_raises(self) -> None:
        with self.assertRaises(ValueError):
            retention.prune_archives(self.dir, retain_days=-1, now_ts=10**9)


class RetentionReportTests(unittest.TestCase):
    def test_report_summarises_archives(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            dpath = Path(d)
            (dpath / "evidence.jsonl").write_text("live-not-counted", encoding="utf-8")
            a = dpath / "evidence.jsonl.100.jsonl"
            b = dpath / "evidence.jsonl.300.jsonl"
            a.write_text("AAAA", encoding="utf-8")   # 4 bytes
            b.write_text("BBBBBB", encoding="utf-8")  # 6 bytes

            report = retention.retention_report(dpath)

            self.assertEqual(report["archive_count"], 2)
            self.assertEqual(report["total_bytes"], 10)
            self.assertEqual(report["oldest_timestamp"], 100)
            self.assertEqual(report["newest_timestamp"], 300)
            names = [e["name"] for e in report["archives"]]
            self.assertEqual(
                names, ["evidence.jsonl.100.jsonl", "evidence.jsonl.300.jsonl"]
            )
            self.assertTrue(all(e["timestamp"] is not None for e in report["archives"]))

    def test_empty_dir_report(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            report = retention.retention_report(d)
            self.assertEqual(report["archive_count"], 0)
            self.assertEqual(report["total_bytes"], 0)
            self.assertIsNone(report["oldest_timestamp"])
            self.assertIsNone(report["newest_timestamp"])
            self.assertEqual(report["archives"], [])


class RotateThenPruneIntegrationTests(unittest.TestCase):
    """Rotation and pruning compose over a realistic ledger lifecycle."""

    def test_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            dpath = Path(d)
            ledger = dpath / "evidence.jsonl"
            day = retention.SECONDS_PER_DAY

            # Two rotations at two different injected days.
            ledger.write_text("z" * 500, encoding="utf-8")
            arch1 = retention.rotate_if_needed(ledger, max_bytes=100, timestamp=1 * day)
            ledger.write_text("z" * 500, encoding="utf-8")
            arch2 = retention.rotate_if_needed(ledger, max_bytes=100, timestamp=50 * day)

            self.assertIsNotNone(arch1)
            self.assertIsNotNone(arch2)
            self.assertEqual(retention.retention_report(dpath)["archive_count"], 2)

            # At day 60 with a 30-day window, arch1 (day 1) is stale; arch2 (day 50) stays.
            removed = retention.prune_archives(dpath, retain_days=30, now_ts=60 * day)
            self.assertEqual(removed, [str(Path(arch1).resolve())])
            self.assertTrue(Path(arch2).exists())
            # Live ledger survived everything.
            self.assertTrue(ledger.exists())
            self.assertEqual(retention.retention_report(dpath)["archive_count"], 1)


if __name__ == "__main__":
    unittest.main()

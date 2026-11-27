"""Tests for forensic chain continuity across evidence-ledger rotation.

These cover the audit fix for the rotation gap: with ``chain_across_rotation``
the sealed archive's final ``entry_hash`` is carried into the new live file as a
continuation header, so (a) a record survives a rotation with a valid cross-file
link and the chain still verifies across archives, and (b) deleting any archive
breaks a cross-file link and makes ``verify_chain(across_archives=True)`` fail.

All timing is injected (``rotate_timestamp`` / signing timestamps are explicit),
so everything here is deterministic and offline.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from artex_antidote import retention, signing
from artex_antidote.evidence import GENESIS_HASH, EvidenceRecord, EvidenceStore


def _record(ip: str = "203.0.113.45", reportable: bool = True) -> EvidenceRecord:
    return EvidenceRecord(
        timestamp_utc="2026-01-01T00:00:00.000Z",
        stream_id="stream-" + ip,
        attributed_ip=ip,
        attributed_confidence="high",
        is_reportable=reportable,
        ip_chain=[{"ip": ip, "confidence": "high"}],
        method="GET",
        path="/.env",
        user_agent="nuclei",
        header_hash="h" * 64,
        body_sha256="b" * 64,
        severity="high",
        reasons=["canary_probe:/.env"],
    )


class ContinuationHeaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.ledger = str(self.dir / "evidence.jsonl")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_default_rotation_restarts_from_genesis(self) -> None:
        """Backward-compatible default: no continuation header, live file empty."""
        store = EvidenceStore(self.ledger, max_bytes=10)
        entry = store.append(_record(), rotate_timestamp=1700000000)
        self.assertIn("rotated_archive", entry)
        # New live file is empty (historical behaviour preserved).
        self.assertEqual(Path(self.ledger).read_text(encoding="utf-8"), "")
        # The next append chains from genesis, not the sealed archive.
        nxt = store.append(_record(ip="198.51.100.7"))
        self.assertEqual(nxt["prev_hash"], GENESIS_HASH)

    def test_continuation_header_links_new_live_file(self) -> None:
        store = EvidenceStore(self.ledger, max_bytes=10, chain_across_rotation=True)
        first = store.append(_record(), rotate_timestamp=1700000000)
        archive_final = first["entry_hash"]

        # The recreated live file holds exactly one continuation header line.
        lines = Path(self.ledger).read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        header = json.loads(lines[0])
        self.assertTrue(header["continuation"])
        self.assertEqual(header["prev_hash"], archive_final)
        self.assertTrue(header["prev_archive"].endswith(".1700000000.jsonl"))

        # The next appended record chains FROM the sealed archive's final hash,
        # i.e. the record survives the rotation with a valid cross-file link.
        nxt = store.append(_record(ip="198.51.100.7"))
        self.assertEqual(nxt["prev_hash"], archive_final)
        self.assertNotEqual(nxt["prev_hash"], GENESIS_HASH)

    def test_records_and_single_file_verify_ignore_header(self) -> None:
        store = EvidenceStore(self.ledger, max_bytes=10, chain_across_rotation=True)
        store.append(_record(), rotate_timestamp=1700000000)
        store.append(_record(ip="198.51.100.7"))
        # records() excludes the continuation header (one real record in live file).
        recs = store.records()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["attributed_ip"], "198.51.100.7")
        # Single-file verify honours the header and reports the live file intact.
        chain = store.verify_chain()
        self.assertTrue(chain["intact"])
        self.assertEqual(chain["verified_records"], 1)


class AcrossArchiveVerifyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.ledger = str(self.dir / "evidence.jsonl")
        self.manifest = self.ledger + ".manifest.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _build_two_rotations(self) -> EvidenceStore:
        """Append records across two rotations -> two archives + a live file."""
        store = EvidenceStore(self.ledger, max_bytes=10, chain_across_rotation=True)
        store.append(_record(ip="203.0.113.1"), rotate_timestamp=1000)  # seals archive @1000
        store.append(_record(ip="203.0.113.2"), rotate_timestamp=2000)  # seals archive @2000
        store.append(_record(ip="203.0.113.3"))  # stays in the live file
        return store

    def test_record_survives_rotation_cross_file_link(self) -> None:
        store = self._build_two_rotations()
        archives = store._own_archives()
        self.assertEqual(len(archives), 2)

        # Every appended record is preserved somewhere (two archived + one live).
        archived = []
        for a in archives:
            for line in a.read_text(encoding="utf-8").splitlines():
                obj = json.loads(line)
                if "record" in obj:
                    archived.append(obj["record"]["attributed_ip"])
        self.assertEqual(sorted(archived), ["203.0.113.1", "203.0.113.2"])
        self.assertEqual([r["attributed_ip"] for r in store.records()], ["203.0.113.3"])

        # The across-archives chain is intact and all three records verify.
        chain = store.verify_chain(across_archives=True)
        self.assertTrue(chain["intact"])
        self.assertEqual(chain["verified_records"], 3)
        self.assertEqual(chain["archive_count"], 2)

        # The live file's continuation prev_hash equals the latest archive's last hash.
        live_header = json.loads(
            Path(self.ledger).read_text(encoding="utf-8").splitlines()[0]
        )
        latest_archive = archives[-1]
        self.assertEqual(
            live_header["prev_hash"], retention.ledger_tail(latest_archive)["final_hash"]
        )

    def test_deleting_an_archive_is_detected(self) -> None:
        store = self._build_two_rotations()
        self.assertTrue(store.verify_chain(across_archives=True)["intact"])

        # Delete the most recent archive: the live file's continuation header now
        # references a hash no present file produces -> the walk must FAIL.
        latest = store._own_archives()[-1]
        latest.unlink()
        broken = store.verify_chain(across_archives=True)
        self.assertFalse(broken["intact"])
        self.assertIsNotNone(broken["broken_file"])

        # Sanity: the live file ALONE still "verifies" (that is exactly the gap
        # the across-archives mode exists to close).
        self.assertTrue(store.verify_chain()["intact"])

    def test_deleting_the_first_archive_is_detected(self) -> None:
        store = self._build_two_rotations()
        first = store._own_archives()[0]
        first.unlink()
        broken = store.verify_chain(across_archives=True)
        self.assertFalse(broken["intact"])

    def test_manifest_records_each_sealed_archive(self) -> None:
        self._build_two_rotations()
        entries = retention.read_manifest(self.manifest)
        sealed = [e for e in entries if e["type"] == "sealed"]
        self.assertEqual(len(sealed), 2)
        for e in sealed:
            self.assertEqual(len(e["final_hash"]), 64)
            self.assertEqual(e["record_count"], 1)
            self.assertIn("archive", e)


class ManifestSigningAndTombstoneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.ledger = str(self.dir / "evidence.jsonl")
        self.manifest = str(self.dir / "evidence.manifest.jsonl")
        self.key = str(self.dir / "sign.key")
        signing.generate_key(self.key)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_rotation_signs_manifest(self) -> None:
        store = EvidenceStore(
            self.ledger,
            max_bytes=10,
            chain_across_rotation=True,
            manifest_path=self.manifest,
            sign_key_path=self.key,
            sign_timestamp="2026-01-01T00:00:00.000Z",
        )
        store.append(_record(), rotate_timestamp=1000)
        sig = self.manifest + signing.SIG_SUFFIX
        self.assertTrue(Path(sig).exists())
        # The signature verifies against the manifest as written.
        self.assertTrue(signing.verify_file(self.manifest, sig, self.key))
        # Tampering with the manifest breaks the signature.
        Path(self.manifest).write_text("tampered\n", encoding="utf-8")
        self.assertFalse(signing.verify_file(self.manifest, sig, self.key))

    def test_prune_appends_tombstone_instead_of_silent_delete(self) -> None:
        # Seal one archive, then prune it with a manifest attached.
        store = EvidenceStore(
            self.ledger,
            max_bytes=10,
            chain_across_rotation=True,
            manifest_path=self.manifest,
        )
        entry = store.append(_record(), rotate_timestamp=1000)
        archive = Path(entry["rotated_archive"])
        self.assertTrue(archive.exists())

        day = retention.SECONDS_PER_DAY
        removed = retention.prune_archives(
            self.dir, retain_days=30, now_ts=1000 + 60 * day, manifest_path=self.manifest
        )
        self.assertEqual(removed, [str(archive.resolve())])
        self.assertFalse(archive.exists())

        tombstones = [e for e in retention.read_manifest(self.manifest) if e["type"] == "tombstone"]
        self.assertEqual(len(tombstones), 1)
        self.assertEqual(tombstones[0]["archive"], archive.name)
        self.assertEqual(len(tombstones[0]["final_hash"]), 64)
        self.assertEqual(tombstones[0]["record_count"], 1)

    def test_prune_without_manifest_is_silent_delete(self) -> None:
        # Backward compatibility: no manifest_path -> no tombstone, just deletion.
        (self.dir / "evidence.jsonl.1000.jsonl").write_text("x\n", encoding="utf-8")
        day = retention.SECONDS_PER_DAY
        removed = retention.prune_archives(self.dir, retain_days=0, now_ts=1000 + day)
        self.assertEqual(len(removed), 1)
        self.assertFalse(Path(self.manifest).exists())


class LedgerTailTests(unittest.TestCase):
    def test_empty_and_missing(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            missing = Path(d) / "nope.jsonl"
            tail = retention.ledger_tail(missing)
            self.assertEqual(tail["final_hash"], GENESIS_HASH)
            self.assertEqual(tail["record_count"], 0)

    def test_header_only_file_carries_prev_hash(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "evidence.jsonl"
            prev = "a" * 64
            p.write_text(
                json.dumps({"continuation": True, "prev_archive": "x", "prev_hash": prev}) + "\n",
                encoding="utf-8",
            )
            tail = retention.ledger_tail(p)
            self.assertEqual(tail["final_hash"], prev)
            self.assertEqual(tail["record_count"], 0)
            self.assertEqual(tail["first_prev_hash"], prev)


if __name__ == "__main__":
    unittest.main()

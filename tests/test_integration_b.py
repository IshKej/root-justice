"""Integration Task B: reporting + CLI wiring.

Covers the backward-compatible wiring added in this task:

* :class:`evidence.EvidenceStore` append-time ledger rotation (retention).
* :mod:`reporter` detached-signature helpers and optional bundle signing.
* The new / extended CLI commands in :mod:`cli` (serve-flag plumbing, health,
  dashboard, intel-refresh, sign-bundle / verify-bundle, taxii-push).

Every test runs fully offline: the only network seam exercised (TAXII) is
monkeypatched, and intel is driven from a local file. No admin and no sockets
are required.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from artex_antidote import cli, reporter, signing, taxii
from artex_antidote.evidence import EvidenceRecord, EvidenceStore


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


def _run_cli(argv: list[str]) -> str:
    """Invoke ``cli.main`` with ``argv`` and return captured stdout."""
    import sys

    buf = io.StringIO()
    old = sys.argv
    sys.argv = ["root-justice"] + argv
    try:
        with contextlib.redirect_stdout(buf):
            cli.main()
    finally:
        sys.argv = old
    return buf.getvalue()


class TestEvidenceRotation(unittest.TestCase):
    def test_no_max_bytes_never_rotates(self) -> None:
        """Default construction (no max_bytes) is unchanged: no archive is made."""
        with tempfile.TemporaryDirectory() as tmp:
            ledger = str(Path(tmp) / "evidence.jsonl")
            store = EvidenceStore(ledger)
            for _ in range(5):
                entry = store.append(_record(), rotate_timestamp=1700000000)
                self.assertNotIn("rotated_archive", entry)
            self.assertIsNone(store.last_rotated_archive)
            # Only the live ledger exists, no "<name>.<ts>.jsonl" archive.
            archives = [p.name for p in Path(tmp).iterdir() if ".jsonl." in p.name]
            self.assertEqual(archives, [])

    def test_rotation_requires_both_threshold_and_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = str(Path(tmp) / "evidence.jsonl")
            # Tiny threshold so the first record overflows it.
            store = EvidenceStore(ledger, max_bytes=10)
            # Without a timestamp, rotation is skipped (module reads no clock).
            entry = store.append(_record())
            self.assertNotIn("rotated_archive", entry)
            self.assertIsNone(store.last_rotated_archive)
            # With a timestamp, the oversized live file is sealed into an archive.
            entry = store.append(_record(), rotate_timestamp=1700000000)
            self.assertIn("rotated_archive", entry)
            self.assertIsNotNone(store.last_rotated_archive)
            archive = Path(entry["rotated_archive"])
            self.assertTrue(archive.exists())
            self.assertTrue(archive.name.endswith(".1700000000.jsonl"))
            # The live ledger is recreated (empty) so appends continue.
            self.assertTrue(Path(ledger).exists())
            self.assertEqual(Path(ledger).read_text(encoding="utf-8"), "")


class TestReporterSigning(unittest.TestCase):
    def test_sign_verify_roundtrip_and_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "bundle.json"
            target.write_text(json.dumps({"type": "bundle", "objects": []}), encoding="utf-8")
            key = str(Path(tmp) / "sign.key")
            signing.generate_key(key)

            sidecar = reporter.sign_bundle(str(target), key, timestamp="2026-01-01T00:00:00.000Z")
            self.assertEqual(sidecar["timestamp"], "2026-01-01T00:00:00.000Z")
            self.assertTrue(reporter.verify_bundle(str(target), key))

            # Any change to the bytes must invalidate the signature.
            target.write_text(json.dumps({"type": "bundle", "objects": [{}]}), encoding="utf-8")
            self.assertFalse(reporter.verify_bundle(str(target), key))

    def test_reviewed_bundle_optionally_signs_stix(self) -> None:
        records = [
            {"attributed_ip": "203.0.113.45", "is_reportable": True, "timestamp_utc": "t",
             "method": "GET", "path": "/.env", "user_agent": "nuclei", "body_sha256": "a",
             "reasons": ["canary"]},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            key = str(Path(tmp) / "sign.key")
            signing.generate_key(key)
            paths = reporter.export_reviewed_federal_bundle(
                tmp, records, reviewed_by="Operator One",
                sign_key_path=key, sign_timestamp="2026-01-01T00:00:00.000Z",
            )
            self.assertIn("stix_bundle_signature", paths)
            self.assertTrue(Path(paths["stix_bundle_signature"]).exists())
            # The sidecar verifies against the written bundle.
            self.assertTrue(reporter.verify_bundle(paths["stix_bundle"], key))

    def test_reviewed_bundle_unsigned_by_default(self) -> None:
        records = [{"attributed_ip": "203.0.113.45", "is_reportable": True}]
        with tempfile.TemporaryDirectory() as tmp:
            paths = reporter.export_reviewed_federal_bundle(tmp, records, reviewed_by="Op")
            self.assertNotIn("stix_bundle_signature", paths)


class TestCliCommands(unittest.TestCase):
    def test_health(self) -> None:
        out = json.loads(_run_cli(["health", "--enforce"]))
        self.assertEqual(out["mode"], "enforce")
        self.assertEqual(out["status"], "ok")

    def test_health_log_only_default(self) -> None:
        out = json.loads(_run_cli(["health"]))
        self.assertEqual(out["mode"], "log-only")

    def test_sign_then_verify_via_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "ledger.jsonl"
            target.write_text("one line\n", encoding="utf-8")
            key = str(Path(tmp) / "k.key")

            sign_out = json.loads(_run_cli(
                ["sign-bundle", str(target), "--key", key, "--generate-key",
                 "--timestamp", "2026-01-01T00:00:00.000Z"]
            ))
            self.assertEqual(sign_out["algorithm"], "HMAC-SHA256")
            self.assertTrue(Path(str(target) + ".sig.json").exists())

            verify_out = json.loads(_run_cli(["verify-bundle", str(target), "--key", key]))
            self.assertTrue(verify_out["valid"])

            # Tamper and confirm the CLI reports invalid.
            target.write_text("tampered\n", encoding="utf-8")
            verify_out = json.loads(_run_cli(["verify-bundle", str(target), "--key", key]))
            self.assertFalse(verify_out["valid"])

    def test_dashboard_renders_html_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = str(Path(tmp) / "evidence.jsonl")
            store = EvidenceStore(ledger)
            store.append(_record())
            out_html = str(Path(tmp) / "dash.html")
            out = json.loads(_run_cli(["dashboard", "--evidence", ledger, "--out", out_html]))
            self.assertEqual(out["records"], 1)
            self.assertTrue(Path(out_html).exists())
            self.assertIn("<", Path(out_html).read_text(encoding="utf-8"))

    def test_intel_refresh_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            feed = Path(tmp) / "bans.txt"
            feed.write_text("203.0.113.7 ; scanner\n198.51.100.0/24 bad net\n", encoding="utf-8")
            out = json.loads(_run_cli(["intel-refresh", "--intel", str(feed)]))
            self.assertEqual(out["entry_count"], 2)
            self.assertEqual(out["errors"], {})

    def test_taxii_push_uses_mocked_transport(self) -> None:
        # Monkeypatch the ONLY network seam so nothing touches the wire.
        captured = {}

        def fake_http(method, url, headers, body):
            captured["method"] = method
            captured["url"] = url
            captured["body"] = json.loads(body.decode("utf-8")) if body else None
            return {"status": 202, "headers": {"Content-Type": "application/taxii+json;version=2.1"},
                    "body": {"id": "status-1", "status": "complete"}}

        original = taxii._http_request
        taxii._http_request = fake_http
        try:
            with tempfile.TemporaryDirectory() as tmp:
                ledger = str(Path(tmp) / "evidence.jsonl")
                store = EvidenceStore(ledger)
                store.append(_record(reportable=True))
                store.append(_record(ip="10.0.0.9", reportable=False))  # held back
                out = json.loads(_run_cli([
                    "taxii-push", "--evidence", ledger,
                    "--api-root", "https://taxii.example.test/api1",
                    "--collection", "col-1", "--token", "SECRET",
                ]))
        finally:
            taxii._http_request = original

        self.assertEqual(out["reportable_records"], 1)  # only the reportable IP
        self.assertEqual(captured["method"], "POST")
        self.assertTrue(captured["url"].endswith("/collections/col-1/objects/"))
        # TAXII envelope shape: {"objects": [...]}, not a bundle.
        self.assertIn("objects", captured["body"])
        values = [o.get("value") for o in captured["body"]["objects"] if o.get("type") == "ipv4-addr"]
        self.assertIn("203.0.113.45", values)
        self.assertNotIn("10.0.0.9", values)


if __name__ == "__main__":
    unittest.main()

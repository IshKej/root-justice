"""Tests for artex_antidote.firmware_audit (GAP #5: secrets inside firmware).

All tests run offline and deterministically: scans touch only temp files, and
the REA bridge is exercised through an injected analyzer seam (never the real
``attribution.run_rea_static_analysis``, never a subprocess, never a network).
"""

import os
import tempfile
import unittest
from pathlib import Path

from artex_antidote import firmware_audit
from artex_antidote.firmware_audit import (
    deep_scan,
    redact,
    scan_file,
    shannon_entropy,
)


# A fake AWS key (not a real credential) + a fake PEM header + a benign line.
DIRTY_FIRMWARE = (
    "boot: initializing device v1.2.3\n"
    "aws_key = AKIAIOSFODNN7EXAMPLE\n"
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEhfakekeymaterialdoesnotmatterforaheaderonlytest==\n"
    "status: all systems nominal\n"
)

CLEAN_FIRMWARE = (
    "boot: initializing device v1.2.3\n"
    "temperature nominal; fan speed 1200 rpm\n"
    "status: all systems nominal and uneventful today\n"
)


class _TempFile:
    """Write *text* (str or bytes) to a temp file and yield its path."""

    def __init__(self, data):
        self.data = data
        self._path = None

    def __enter__(self):
        mode = "wb" if isinstance(self.data, (bytes, bytearray)) else "w"
        fd, name = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        with open(name, mode) as fh:
            fh.write(self.data)
        self._path = name
        return name

    def __exit__(self, *exc):
        try:
            os.unlink(self._path)
        except OSError:
            pass


class ShannonEntropyTests(unittest.TestCase):
    def test_empty_is_zero(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_uniform_string_low_entropy(self):
        self.assertAlmostEqual(shannon_entropy("aaaaaaaa"), 0.0)

    def test_random_token_high_entropy(self):
        # A mixed base64-ish token should clear the default threshold.
        token = "aZ9kLm2Qp7Rt4Xv1Bc8Nf3Hj6Wd0Ye5"
        self.assertGreater(
            shannon_entropy(token), firmware_audit.DEFAULT_ENTROPY_THRESHOLD
        )


class RedactTests(unittest.TestCase):
    def test_long_secret_shows_first_and_last(self):
        out = redact("AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(out.startswith("AKIA"))
        self.assertTrue(out.endswith("MPLE"))
        self.assertIn("*", out)
        self.assertEqual(len(out), len("AKIAIOSFODNN7EXAMPLE"))
        # The middle of the secret must NOT survive verbatim.
        self.assertNotIn("IOSFODNN7EX", out)

    def test_short_secret_fully_masked(self):
        self.assertEqual(redact("abcd"), "****")

    def test_empty(self):
        self.assertEqual(redact(""), "")


class ScanFileTests(unittest.TestCase):
    def test_detects_aws_key_and_pem_header(self):
        with _TempFile(DIRTY_FIRMWARE) as path:
            result = scan_file(path)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["path"], str(Path(path)))
        types = {f["type"] for f in result["findings"]}
        self.assertIn("aws_access_key", types)
        self.assertIn("private_key_block", types)
        self.assertGreaterEqual(result["secret_count"], 2)

    def test_matched_secret_is_redacted(self):
        with _TempFile(DIRTY_FIRMWARE) as path:
            result = scan_file(path)

        aws = next(f for f in result["findings"] if f["type"] == "aws_access_key")
        # Redacted form, not the raw key.
        self.assertNotEqual(aws["redacted"], "AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(aws["redacted"].startswith("AKIA"))
        self.assertIn("*", aws["redacted"])
        # The full raw key must not appear anywhere in the serialized findings.
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", repr(result["findings"]))
        # Finding carries a line number and severity.
        self.assertEqual(aws["line"], 2)
        self.assertEqual(aws["severity"], "critical")

    def test_generic_credential_assignment(self):
        blob = 'config:\n  password = "s3cr3tP@ssw0rd123"\n'
        with _TempFile(blob) as path:
            result = scan_file(path)
        types = {f["type"] for f in result["findings"]}
        self.assertIn("generic_credential_assignment", types)
        cred = next(
            f for f in result["findings"]
            if f["type"] == "generic_credential_assignment"
        )
        self.assertNotIn("s3cr3tP@ssw0rd123", cred["redacted"])

    def test_clean_file_zero_secrets(self):
        with _TempFile(CLEAN_FIRMWARE) as path:
            result = scan_file(path)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["secret_count"], 0)
        self.assertEqual(result["findings"], [])

    def test_missing_file_errors_gracefully(self):
        result = scan_file(os.path.join(tempfile.gettempdir(), "no_such_fw_xyz.bin"))
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["secret_count"], 0)
        self.assertEqual(result["findings"], [])

    def test_high_entropy_token_flagged(self):
        blob = "token_blob xQ9mKv2Lp7Rt4Wz1Bc8Nf3Hj6Yd0Ae5Gk2Mn9Pr\n"
        with _TempFile(blob) as path:
            result = scan_file(path)
        types = {f["type"] for f in result["findings"]}
        self.assertIn("high_entropy_token", types)


class DeepScanTests(unittest.TestCase):
    def test_deep_scan_merges_rea_status_via_seam(self):
        captured = {}

        def fake_rea(target):
            captured["target"] = target
            return {"status": "ok", "returncode": 0, "stdout_preview": "clean"}

        with _TempFile(DIRTY_FIRMWARE) as path:
            result = deep_scan(path, run_rea=True, rea_analyzer=fake_rea)

        self.assertIn("rea", result)
        self.assertEqual(result["rea"]["status"], "ok")
        self.assertEqual(captured["target"], str(Path(path)))
        # Base scan findings still present.
        self.assertGreaterEqual(result["secret_count"], 2)

    def test_deep_scan_skips_rea_when_disabled(self):
        with _TempFile(CLEAN_FIRMWARE) as path:
            result = deep_scan(path, run_rea=False)
        self.assertEqual(result["rea"], {"status": "skipped"})
        self.assertEqual(result["secret_count"], 0)

    def test_deep_scan_rea_failure_degrades(self):
        def broken_rea(target):
            raise RuntimeError("npx exploded")

        with _TempFile(CLEAN_FIRMWARE) as path:
            result = deep_scan(path, run_rea=True, rea_analyzer=broken_rea)
        self.assertEqual(result["rea"]["status"], "unavailable")
        self.assertIn("npx exploded", result["rea"]["error"])


if __name__ == "__main__":
    unittest.main()

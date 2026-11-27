"""Tests for artex_antidote.signing (Spec #9 signed + timestamped evidence).

All tests run fully offline with no admin and no network: the only network
seam (``signing._http_post_tsa`` / the ``tsa_stub`` hook) is exercised with a
local stub, never a real request.
"""

import json
import tempfile
import unittest
from pathlib import Path

from artex_antidote import signing


FIXED_TS = "2026-11-26T12:00:00.000Z"


class SigningTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.evidence = self.tmp / "evidence.jsonl"
        self.evidence.write_text('{"record": "flagged event"}\n', encoding="utf-8")
        self.key_path = self.tmp / "signing.key"
        self.key = signing.generate_key(str(self.key_path))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # -- key generation ---------------------------------------------------- #
    def test_generate_key_is_random_and_sized(self) -> None:
        self.assertEqual(len(self.key), signing.DEFAULT_KEY_BYTES)
        self.assertEqual(signing.load_key(str(self.key_path)), self.key)
        other = signing.generate_key(str(self.tmp / "other.key"))
        self.assertNotEqual(self.key, other, "two keys must differ")

    def test_generate_key_rejects_tiny_key(self) -> None:
        with self.assertRaises(ValueError):
            signing.generate_key(str(self.tmp / "tiny.key"), nbytes=8)

    # -- happy path -------------------------------------------------------- #
    def test_sign_then_verify_true(self) -> None:
        sidecar = signing.sign_file(
            str(self.evidence), str(self.key_path), timestamp=FIXED_TS
        )
        sig_path = str(self.evidence) + signing.SIG_SUFFIX
        self.assertTrue(Path(sig_path).is_file(), "sidecar should be written next to file")

        # The passed-in timestamp is recorded verbatim.
        self.assertEqual(sidecar["timestamp"], FIXED_TS)
        self.assertEqual(sidecar["algorithm"], signing.SIG_ALGORITHM)
        self.assertIn("signature", sidecar)
        self.assertIn("file_sha256", sidecar)

        self.assertTrue(
            signing.verify_file(str(self.evidence), sig_path, str(self.key_path))
        )

    def test_default_sig_path_matches_suffix(self) -> None:
        signing.sign_file(str(self.evidence), str(self.key_path), timestamp=FIXED_TS)
        self.assertTrue(Path(str(self.evidence) + ".sig.json").is_file())

    # -- tamper detection -------------------------------------------------- #
    def test_tampered_file_verify_false(self) -> None:
        signing.sign_file(str(self.evidence), str(self.key_path), timestamp=FIXED_TS)
        sig_path = str(self.evidence) + signing.SIG_SUFFIX

        # Attacker edits the evidence after signing.
        self.evidence.write_text('{"record": "ALTERED"}\n', encoding="utf-8")

        self.assertFalse(
            signing.verify_file(str(self.evidence), sig_path, str(self.key_path)),
            "verification must fail once the signed bytes change",
        )

    def test_tampered_timestamp_in_sidecar_verify_false(self) -> None:
        signing.sign_file(str(self.evidence), str(self.key_path), timestamp=FIXED_TS)
        sig_path = Path(str(self.evidence) + signing.SIG_SUFFIX)

        sidecar = json.loads(sig_path.read_text(encoding="utf-8"))
        sidecar["timestamp"] = "2099-01-01T00:00:00.000Z"  # backdate/forward-date attack
        sig_path.write_text(json.dumps(sidecar), encoding="utf-8")

        self.assertFalse(
            signing.verify_file(str(self.evidence), str(sig_path), str(self.key_path)),
            "the timestamp is HMAC-covered, so editing it must break verification",
        )

    # -- wrong key --------------------------------------------------------- #
    def test_wrong_key_verify_false(self) -> None:
        signing.sign_file(str(self.evidence), str(self.key_path), timestamp=FIXED_TS)
        sig_path = str(self.evidence) + signing.SIG_SUFFIX

        wrong_key_path = self.tmp / "wrong.key"
        signing.generate_key(str(wrong_key_path))

        self.assertFalse(
            signing.verify_file(str(self.evidence), sig_path, str(wrong_key_path)),
            "a different key must not verify",
        )

    # -- robustness: never raise on missing/garbage sidecar ---------------- #
    def test_missing_sidecar_returns_false(self) -> None:
        self.assertFalse(
            signing.verify_file(
                str(self.evidence), str(self.tmp / "nope.sig.json"), str(self.key_path)
            )
        )

    def test_garbage_sidecar_returns_false(self) -> None:
        bad = self.tmp / "bad.sig.json"
        bad.write_text("not json {{{", encoding="utf-8")
        self.assertFalse(
            signing.verify_file(str(self.evidence), str(bad), str(self.key_path))
        )

    def test_sign_missing_file_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            signing.sign_file(
                str(self.tmp / "ghost.bin"), str(self.key_path), timestamp=FIXED_TS
            )

    # -- optional TSA hook (network seam, exercised offline) --------------- #
    def test_tsa_stub_token_is_covered_and_verifies(self) -> None:
        calls = {}

        def fake_tsa(url: str, digest_hex: str) -> dict:
            calls["url"] = url
            calls["digest"] = digest_hex
            return {"tsa": "demo", "token": "deadbeef", "digest": digest_hex}

        sidecar = signing.sign_file(
            str(self.evidence),
            str(self.key_path),
            timestamp=FIXED_TS,
            tsa_url="https://tsa.example.test",
            tsa_stub=fake_tsa,
        )
        sig_path = str(self.evidence) + signing.SIG_SUFFIX

        # The stub was consulted with the file digest, no real network.
        self.assertEqual(calls["url"], "https://tsa.example.test")
        self.assertEqual(calls["digest"], sidecar["file_sha256"])
        self.assertEqual(sidecar["tsa"]["token"], "deadbeef")

        # Token is folded into the signed header, so it still verifies...
        self.assertTrue(
            signing.verify_file(str(self.evidence), sig_path, str(self.key_path))
        )

        # ...and tampering with the TSA token breaks verification.
        tampered = json.loads(Path(sig_path).read_text(encoding="utf-8"))
        tampered["tsa"]["token"] = "0000"
        Path(sig_path).write_text(json.dumps(tampered), encoding="utf-8")
        self.assertFalse(
            signing.verify_file(str(self.evidence), sig_path, str(self.key_path))
        )

    def test_default_tsa_seam_not_called_without_opt_in(self) -> None:
        # No tsa_url / tsa_stub -> no TSA token, _http_post_tsa never invoked.
        def boom(url, digest):  # pragma: no cover - must not run
            raise AssertionError("TSA seam must not be called by default")

        original = signing._http_post_tsa
        signing._http_post_tsa = boom
        try:
            sidecar = signing.sign_file(
                str(self.evidence), str(self.key_path), timestamp=FIXED_TS
            )
        finally:
            signing._http_post_tsa = original
        self.assertIsNone(sidecar.get("tsa"))


if __name__ == "__main__":
    unittest.main()

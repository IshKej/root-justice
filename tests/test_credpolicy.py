"""Tests for artex_antidote.credpolicy (GAP #3: make stolen hashes useless).

All tests run offline and deterministically: the single network seam
``credpolicy._http_get`` is never called -- ``hibp_range_check`` is exercised
with a fake ``fetch`` that is also asserted to receive ONLY the 5-char prefix,
never the full hash. No sockets, no admin, no clock, no randomness.
"""

import hashlib
import unittest

from artex_antidote import credpolicy
from artex_antidote.credpolicy import (
    argon2id_recommended_params,
    classify_hash,
    hibp_range_check,
    password_policy_report,
    sha1_hex_of,
)


class ClassifyHashTests(unittest.TestCase):
    def test_bare_md5_is_weak_unsalted(self):
        md5 = "5f4dcc3b5aa765d61d8327deb882cf99"  # 32 hex chars ("password")
        self.assertEqual(len(md5), 32)
        c = classify_hash(md5)
        self.assertEqual(c["verdict"], "WEAK")
        self.assertEqual(c["scheme"], "md5")
        self.assertFalse(c["salted"])
        self.assertIn("argon2id", str(c["recommendation"]).lower())

    def test_bare_sha1_is_weak(self):
        sha1 = "a" * 40
        c = classify_hash(sha1)
        self.assertEqual(c["verdict"], "WEAK")
        self.assertEqual(c["scheme"], "sha1")

    def test_bare_sha256_is_weak(self):
        sha256 = "0" * 64
        c = classify_hash(sha256)
        self.assertEqual(c["verdict"], "WEAK")
        self.assertEqual(c["scheme"], "sha256")

    def test_argon2id_is_strong(self):
        h = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$abcdefghijklmnopqrstuvwxyz012345"
        c = classify_hash(h)
        self.assertEqual(c["verdict"], "STRONG")
        self.assertEqual(c["scheme"], "argon2id")
        self.assertTrue(c["salted"])

    def test_bcrypt_is_strong(self):
        h = "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
        c = classify_hash(h)
        self.assertEqual(c["verdict"], "STRONG")
        self.assertEqual(c["scheme"], "bcrypt")

    def test_scrypt_is_strong(self):
        h = "$scrypt$ln=16,r=8,p=1$c2FsdA$aGFzaA"
        c = classify_hash(h)
        self.assertEqual(c["verdict"], "STRONG")
        self.assertEqual(c["scheme"], "scrypt")

    def test_pbkdf2_high_iterations_is_strong(self):
        h = "pbkdf2_sha256$600000$somesalt$aGFzaHZhbHVl"
        c = classify_hash(h)
        self.assertEqual(c["verdict"], "STRONG")
        self.assertEqual(c["scheme"], "pbkdf2")

    def test_pbkdf2_low_iterations_is_weak(self):
        h = "pbkdf2_sha256$1000$somesalt$aGFzaHZhbHVl"
        c = classify_hash(h)
        self.assertEqual(c["verdict"], "WEAK")
        self.assertEqual(c["scheme"], "pbkdf2")

    def test_empty_and_garbage(self):
        self.assertEqual(classify_hash("")["verdict"], "UNKNOWN")
        # 50-char non-hex, no known prefix
        self.assertEqual(classify_hash("zzz!!!" + "x" * 44)["verdict"], "UNKNOWN")

    def test_non_string_input(self):
        self.assertEqual(classify_hash(None)["verdict"], "UNKNOWN")  # type: ignore[arg-type]


class HibpRangeCheckTests(unittest.TestCase):
    def _digest_for(self, password: str) -> str:
        return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    def test_parses_count_and_sends_only_prefix(self):
        digest = self._digest_for("password")
        prefix, suffix = digest[:5], digest[5:]

        seen = {}

        def fake_fetch(url):
            seen["url"] = url
            # The range endpoint returns SUFFIX:COUNT lines; include ours plus noise.
            return (
                "003D68EB55068C33ACE09247EE4C639306B:3\r\n"
                f"{suffix}:4242\r\n"
                "1E4C9B93F3F0682250B6CF8331B7EE68FD8:1\r\n"
            )

        count = hibp_range_check(digest, fetch=fake_fetch)
        self.assertEqual(count, 4242)

        # k-anonymity guarantee: only the 5-char prefix is ever sent.
        self.assertIn(prefix, seen["url"])
        self.assertNotIn(suffix, seen["url"])
        self.assertNotIn(digest, seen["url"])
        # URL ends with the prefix -- nothing more of the hash leaked.
        self.assertTrue(seen["url"].endswith(prefix))

    def test_lowercase_input_still_matches(self):
        digest = self._digest_for("hunter2")
        suffix = digest[5:]

        def fake_fetch(url):
            return f"{suffix}:7\n"

        self.assertEqual(hibp_range_check(digest.lower(), fetch=fake_fetch), 7)

    def test_not_breached_returns_none(self):
        digest = self._digest_for("a-very-unique-passphrase-xyz")
        suffix = digest[5:]

        def fake_fetch(url):
            # Return some other suffix only.
            other = ("F" * 35)
            if other == suffix:
                other = ("0" * 35)
            return f"{other}:9\n"

        self.assertIsNone(hibp_range_check(digest, fetch=fake_fetch))

    def test_malformed_hash_returns_none_without_fetching(self):
        def exploding_fetch(url):
            raise AssertionError("fetch must not be called for malformed input")

        self.assertIsNone(hibp_range_check("not-a-hash", fetch=exploding_fetch))
        self.assertIsNone(hibp_range_check("a" * 39, fetch=exploding_fetch))

    def test_fetch_failure_returns_none(self):
        digest = self._digest_for("whatever")

        def boom(url):
            raise OSError("network down")

        self.assertIsNone(hibp_range_check(digest, fetch=boom))

    def test_zero_count_suffix_returns_zero_not_none(self):
        digest = self._digest_for("edgecase")
        suffix = digest[5:]

        def fake_fetch(url):
            return f"{suffix}:0\n"

        self.assertEqual(hibp_range_check(digest, fetch=fake_fetch), 0)

    def test_sha1_hex_helper_matches_hashlib(self):
        self.assertEqual(sha1_hex_of("password"), self._digest_for("password"))


class Argon2ParamsTests(unittest.TestCase):
    def test_recommended_params_shape(self):
        p = argon2id_recommended_params()
        self.assertEqual(p["algorithm"], "argon2id")
        self.assertGreaterEqual(int(p["memory_cost_kib"]), 19456)
        self.assertGreaterEqual(int(p["time_cost"]), 1)
        self.assertGreaterEqual(int(p["parallelism"]), 1)


class PolicyReportTests(unittest.TestCase):
    def test_report_mixes_weak_and_strong(self):
        samples = [
            "5f4dcc3b5aa765d61d8327deb882cf99",  # md5 weak
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA",  # strong
            "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345",  # strong
        ]
        report = password_policy_report(samples)
        self.assertEqual(report["total"], 3)
        self.assertEqual(report["counts"]["WEAK"], 1)
        self.assertEqual(report["counts"]["STRONG"], 2)
        self.assertAlmostEqual(report["weak_ratio"], 1 / 3, places=3)
        self.assertEqual(len(report["classifications"]), 3)
        self.assertIn("recommended_argon2id", report)
        self.assertTrue(report["recommendations"])

    def test_report_all_strong(self):
        report = password_policy_report(
            ["$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"]
        )
        self.assertEqual(report["counts"]["WEAK"], 0)
        self.assertEqual(report["weak_ratio"], 0.0)

    def test_empty_sample(self):
        report = password_policy_report([])
        self.assertEqual(report["total"], 0)
        self.assertEqual(report["weak_ratio"], 0.0)

    def test_report_does_not_touch_network(self):
        def boom(url):
            raise AssertionError("stored hashes must never be transmitted")

        # Even with a seam that explodes on use, classification is offline.
        report = password_policy_report(["a" * 40], fetch=boom)
        self.assertEqual(report["counts"]["WEAK"], 1)


class SeamTests(unittest.TestCase):
    def test_http_get_rejects_non_http_scheme(self):
        with self.assertRaises(ValueError):
            credpolicy._http_get("file:///etc/passwd")


if __name__ == "__main__":
    unittest.main()

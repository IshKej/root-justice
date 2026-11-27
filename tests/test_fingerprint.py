"""Tests for artex_antidote.fingerprint (JA3/JA4-style fingerprinting).

Runs fully offline, no admin, no network. The optional threat-intel lookup is
exercised only through a monkeypatched module-level seam (``_http_get_json``).
"""

import unittest

from artex_antidote import fingerprint as fp


# The canonical JA3 reference vector, with its published MD5.
KNOWN_JA3_STRING = (
    "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
)
KNOWN_JA3_MD5 = "ada70206e40642a3e4461f35503241d5"

VEC_VERSION = 769
VEC_CIPHERS = [47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4]
VEC_EXTENSIONS = [0, 10, 11]
VEC_CURVES = [23, 24, 25]
VEC_FORMATS = [0]


class TestJa3Vector(unittest.TestCase):
    def test_ja3_string_matches_known_vector(self):
        s = fp.ja3_string(
            VEC_VERSION, VEC_CIPHERS, VEC_EXTENSIONS, VEC_CURVES, VEC_FORMATS
        )
        self.assertEqual(s, KNOWN_JA3_STRING)

    def test_ja3_hash_matches_known_vector(self):
        self.assertEqual(
            fp.ja3_hash(
                VEC_VERSION, VEC_CIPHERS, VEC_EXTENSIONS, VEC_CURVES, VEC_FORMATS
            ),
            KNOWN_JA3_MD5,
        )

    def test_section_and_field_separators(self):
        s = fp.ja3_string(
            VEC_VERSION, VEC_CIPHERS, VEC_EXTENSIONS, VEC_CURVES, VEC_FORMATS
        )
        # Exactly five comma-separated sections.
        self.assertEqual(len(s.split(",")), 5)
        # Ciphers field uses '-' between the 12 values.
        self.assertEqual(s.split(",")[1].count("-"), len(VEC_CIPHERS) - 1)

    def test_empty_fields_render_as_empty_string(self):
        # No extensions/curves/formats -> empty sections, version+ciphers kept.
        s = fp.ja3_string(771, [4865, 4866], [], [], [])
        self.assertEqual(s, "771,4865-4866,,,")


class TestGrease(unittest.TestCase):
    def test_is_grease_true_for_reserved_values(self):
        self.assertTrue(fp.is_grease(0x0A0A))
        self.assertTrue(fp.is_grease(0xFAFA))
        self.assertTrue(fp.is_grease(0x1A1A))

    def test_is_grease_false_for_normal_values(self):
        self.assertFalse(fp.is_grease(0))
        self.assertFalse(fp.is_grease(4865))
        self.assertFalse(fp.is_grease(0x0A0B))

    def test_grease_is_stripped_from_fields(self):
        with_grease = fp.ja3_string(
            771, [0x0A0A, 4865, 4866], [0x1A1A, 0], [23], [0]
        )
        without = fp.ja3_string(771, [4865, 4866], [0], [23], [0])
        self.assertEqual(with_grease, without)

    def test_grease_retained_when_disabled(self):
        s = fp.ja3_string(771, [0x0A0A, 4865], [], [], [], drop_grease=False)
        self.assertEqual(s.split(",")[1], "2570-4865")


class TestHeaderFallback(unittest.TestCase):
    def test_deterministic_for_same_order(self):
        headers = {"Host": "x", "User-Agent": "ua", "Accept": "*/*"}
        a = fp.client_header_fingerprint(headers)
        b = fp.client_header_fingerprint(dict(headers))
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)  # sha256 hex

    def test_order_sensitive(self):
        a = fp.client_header_fingerprint({"Host": "x", "Accept": "*/*"})
        b = fp.client_header_fingerprint({"Accept": "*/*", "Host": "x"})
        self.assertNotEqual(a, b)

    def test_case_insensitive_names(self):
        a = fp.client_header_fingerprint({"Host": "x", "Accept": "y"})
        b = fp.client_header_fingerprint({"HOST": "x", "accept": "y"})
        self.assertEqual(a, b)

    def test_names_only_ignores_values_by_default(self):
        a = fp.client_header_fingerprint({"Host": "a", "Cookie": "sess=1"})
        b = fp.client_header_fingerprint({"Host": "a", "Cookie": "sess=2"})
        self.assertEqual(a, b)  # values not folded in by default

    def test_include_values_distinguishes(self):
        a = fp.client_header_fingerprint({"Cookie": "sess=1"}, include_values=True)
        b = fp.client_header_fingerprint({"Cookie": "sess=2"}, include_values=True)
        self.assertNotEqual(a, b)


class TestLookupSeam(unittest.TestCase):
    def tearDown(self):
        # Restore the default offline seam after any monkeypatch.
        import importlib

        importlib.reload(fp)

    def test_offline_default_returns_none(self):
        # No feed configured -> no lookup, no network.
        self.assertIsNone(fp.lookup_known_bad(KNOWN_JA3_MD5))

    def test_seam_not_called_without_feed(self):
        calls = []
        fp._http_get_json = lambda url, timeout=2.0: calls.append(url) or {"malicious": True}
        self.assertIsNone(fp.lookup_known_bad(KNOWN_JA3_MD5))
        self.assertEqual(calls, [])  # seam untouched when feed_url is empty

    def test_seam_consulted_with_feed(self):
        seen = {}

        def fake(url, timeout=2.0):
            seen["url"] = url
            return {"malicious": True, "family": "testbot"}

        fp._http_get_json = fake
        result = fp.lookup_known_bad(KNOWN_JA3_MD5, feed_url="https://feed.local/ja3")
        self.assertIsNotNone(result)
        is_bad, detail = result
        self.assertTrue(is_bad)
        self.assertEqual(detail["family"], "testbot")
        self.assertIn(KNOWN_JA3_MD5, seen["url"])

    def test_seam_none_response_is_safe(self):
        fp._http_get_json = lambda url, timeout=2.0: None
        self.assertIsNone(
            fp.lookup_known_bad(KNOWN_JA3_MD5, feed_url="https://feed.local")
        )


if __name__ == "__main__":
    unittest.main()

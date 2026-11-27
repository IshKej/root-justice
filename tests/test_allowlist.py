"""Tests for artex_antidote.allowlist.

Offline, no network, no admin. Covers exact IP matches, CIDR membership,
non-members, IPv6, safe handling of invalid input, mutation (add/remove), and
file loading with comments.
"""

import os
import tempfile
import unittest

from artex_antidote.allowlist import Allowlist, parse_network


class ParseNetworkTests(unittest.TestCase):
    def test_bare_ipv4_becomes_host_network(self):
        net = parse_network("203.0.113.7")
        self.assertIsNotNone(net)
        self.assertEqual(str(net), "203.0.113.7/32")

    def test_bare_ipv6_becomes_host_network(self):
        net = parse_network("2001:db8::1")
        self.assertIsNotNone(net)
        self.assertEqual(net.prefixlen, 128)

    def test_cidr_with_host_bits_is_normalized(self):
        net = parse_network("10.0.0.5/8")
        self.assertEqual(str(net), "10.0.0.0/8")

    def test_invalid_entries_return_none(self):
        for bad in ("", "   ", "not-an-ip", "999.999.999.999", "10.0.0.0/99", None):
            self.assertIsNone(parse_network(bad))


class ExactMatchTests(unittest.TestCase):
    def test_exact_ipv4_match(self):
        allow = Allowlist(["203.0.113.7"])
        self.assertTrue(allow.is_allowed("203.0.113.7"))

    def test_exact_ipv4_non_member(self):
        allow = Allowlist(["203.0.113.7"])
        self.assertFalse(allow.is_allowed("203.0.113.8"))

    def test_contains_operator(self):
        allow = Allowlist(["203.0.113.7"])
        self.assertIn("203.0.113.7", allow)
        self.assertNotIn("203.0.113.8", allow)


class CidrMembershipTests(unittest.TestCase):
    def setUp(self):
        self.allow = Allowlist(["10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32"])

    def test_ipv4_inside_cidr(self):
        self.assertTrue(self.allow.is_allowed("10.1.2.3"))
        self.assertTrue(self.allow.is_allowed("10.255.255.254"))
        self.assertTrue(self.allow.is_allowed("192.168.1.42"))

    def test_ipv4_outside_cidr(self):
        self.assertFalse(self.allow.is_allowed("11.0.0.1"))
        self.assertFalse(self.allow.is_allowed("192.168.2.1"))

    def test_ipv6_inside_cidr(self):
        self.assertTrue(self.allow.is_allowed("2001:db8::dead:beef"))

    def test_ipv6_outside_cidr(self):
        self.assertFalse(self.allow.is_allowed("2001:dead::1"))

    def test_ipv4_not_matched_against_ipv6_net(self):
        only6 = Allowlist(["2001:db8::/32"])
        self.assertFalse(only6.is_allowed("10.0.0.1"))


class InvalidInputTests(unittest.TestCase):
    def test_invalid_query_is_safe(self):
        allow = Allowlist(["10.0.0.0/8"])
        for bad in ("", "   ", "garbage", "10.0.0.0/8", "999.1.1.1", None):
            # A CIDR string is not a single address, so is_allowed must reject it.
            self.assertFalse(allow.is_allowed(bad))

    def test_invalid_constructor_entries_skipped(self):
        allow = Allowlist(["not-an-ip", "", "203.0.113.7", "bad/33"])
        self.assertEqual(len(allow), 1)
        self.assertTrue(allow.is_allowed("203.0.113.7"))

    def test_empty_allowlist_allows_nothing(self):
        allow = Allowlist()
        self.assertFalse(allow.is_allowed("203.0.113.7"))


class MutationTests(unittest.TestCase):
    def test_add_returns_true_and_takes_effect(self):
        allow = Allowlist()
        self.assertTrue(allow.add("10.0.0.0/8"))
        self.assertTrue(allow.is_allowed("10.1.1.1"))

    def test_add_invalid_returns_false(self):
        allow = Allowlist()
        self.assertFalse(allow.add("nope"))
        self.assertEqual(len(allow), 0)

    def test_add_duplicate_not_stored_twice(self):
        allow = Allowlist(["10.0.0.0/8"])
        allow.add("10.0.0.5/8")  # same normalized network
        self.assertEqual(len(allow), 1)

    def test_remove_present_entry(self):
        allow = Allowlist(["10.0.0.0/8"])
        self.assertTrue(allow.remove("10.0.0.0/8"))
        self.assertFalse(allow.is_allowed("10.1.1.1"))

    def test_remove_by_denormalized_form(self):
        allow = Allowlist(["10.0.0.5/8"])
        self.assertTrue(allow.remove("10.0.0.0/8"))
        self.assertEqual(len(allow), 0)

    def test_remove_absent_or_invalid_returns_false(self):
        allow = Allowlist(["10.0.0.0/8"])
        self.assertFalse(allow.remove("192.168.0.0/16"))
        self.assertFalse(allow.remove("garbage"))


class LoadFromFileTests(unittest.TestCase):
    def _write(self, text):
        fd, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        self.addCleanup(os.remove, path)
        return path

    def test_loads_entries_and_skips_comments(self):
        path = self._write(
            "# monitors\n"
            "203.0.113.7\n"
            "10.0.0.0/8   # internal\n"
            "\n"
            "   \n"
            "bogus-line\n"
            "2001:db8::/32\n"
        )
        allow = Allowlist()
        added = allow.load_from_file(path)
        self.assertEqual(added, 3)
        self.assertTrue(allow.is_allowed("203.0.113.7"))
        self.assertTrue(allow.is_allowed("10.9.9.9"))
        self.assertTrue(allow.is_allowed("2001:db8::5"))
        self.assertFalse(allow.is_allowed("8.8.8.8"))

    def test_load_merges_into_existing(self):
        path = self._write("192.168.1.0/24\n")
        allow = Allowlist(["10.0.0.0/8"])
        allow.load_from_file(path)
        self.assertTrue(allow.is_allowed("10.1.1.1"))
        self.assertTrue(allow.is_allowed("192.168.1.1"))

    def test_entries_roundtrip(self):
        allow = Allowlist(["203.0.113.7", "10.0.0.0/8"])
        self.assertEqual(set(allow.entries()), {"203.0.113.7/32", "10.0.0.0/8"})


if __name__ == "__main__":
    unittest.main()

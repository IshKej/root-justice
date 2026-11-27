"""Tests for artex_antidote.intel (threat-intel feeds).

All tests run offline: the single network seam ``intel._http_get`` is
monkeypatched, and file-based feeds use a tempfile. No admin, no sockets.
"""

import ipaddress
import tempfile
import unittest
from pathlib import Path

from artex_antidote import intel
from artex_antidote.intel import IntelSource, ThreatIntel


LOCAL_FEED = """\
# local bans
203.0.113.7           ; manual ban: repeated SQLi probes
198.51.100.0/24       scanner subnet

   # blank line above, indented comment here
2001:db8:dead::1
"""

REMOTE_FEED = """\
# abuse feed
192.0.2.55
10.0.0.0/8 internal-spoof-guard
not-an-ip-should-be-skipped
"""


class _TempFeed:
    """Context manager writing feed text to a temp file and yielding its path."""

    def __init__(self, text: str) -> None:
        self.text = text
        self._tmp = None

    def __enter__(self) -> str:
        self._tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        )
        self._tmp.write(self.text)
        self._tmp.close()
        return self._tmp.name

    def __exit__(self, *exc) -> None:
        if self._tmp is not None:
            Path(self._tmp.name).unlink(missing_ok=True)


class FileFeedTests(unittest.TestCase):
    def test_known_bad_exact_hit_reports_source_and_reason(self):
        with _TempFeed(LOCAL_FEED) as path:
            ti = ThreatIntel([{"name": "local", "path": path}])
            loaded = ti.refresh()
            self.assertGreater(loaded, 0)
            reason = ti.is_known_bad("203.0.113.7")
            self.assertIsNotNone(reason)
            self.assertIn("local", reason)
            self.assertIn("SQLi", reason)

    def test_clean_ip_misses(self):
        with _TempFeed(LOCAL_FEED) as path:
            ti = ThreatIntel([{"name": "local", "path": path}])
            ti.refresh()
            self.assertIsNone(ti.is_known_bad("8.8.8.8"))
            self.assertNotIn("8.8.8.8", ti)

    def test_cidr_membership_hit_and_boundary_miss(self):
        with _TempFeed(LOCAL_FEED) as path:
            ti = ThreatIntel([{"name": "local", "path": path}])
            ti.refresh()
            # Inside 198.51.100.0/24
            self.assertIsNotNone(ti.is_known_bad("198.51.100.200"))
            # Just outside the /24
            self.assertIsNone(ti.is_known_bad("198.51.101.1"))

    def test_ipv6_exact_hit(self):
        with _TempFeed(LOCAL_FEED) as path:
            ti = ThreatIntel([{"name": "local", "path": path}])
            ti.refresh()
            # Same address, non-canonical spelling, must still match.
            self.assertIsNotNone(ti.is_known_bad("2001:db8:dead:0:0:0:0:1"))

    def test_contains_and_len(self):
        with _TempFeed(LOCAL_FEED) as path:
            ti = ThreatIntel([{"name": "local", "path": path}])
            ti.refresh()
            self.assertIn("203.0.113.7", ti)
            # one exact v4 + one v6 + one /24 network == 3 entries
            self.assertEqual(len(ti), 3)


class RemoteFeedTests(unittest.TestCase):
    def setUp(self):
        self._orig = intel._http_get

    def tearDown(self):
        intel._http_get = self._orig

    def test_monkeypatched_fetch_loads_and_matches(self):
        calls = {}

        def fake_http_get(url, timeout=10.0):
            calls["url"] = url
            return REMOTE_FEED

        intel._http_get = fake_http_get

        ti = ThreatIntel([IntelSource(name="abuse", url="https://feed.test/bad.txt")])
        ti.refresh()

        self.assertEqual(calls["url"], "https://feed.test/bad.txt")
        self.assertIsNotNone(ti.is_known_bad("192.0.2.55"))
        # CIDR from the remote feed
        self.assertIsNotNone(ti.is_known_bad("10.1.2.3"))
        # The malformed line was skipped, not fatal.
        self.assertIsNone(ti.is_known_bad("203.0.113.1"))
        self.assertEqual(ti.last_errors, {})

    def test_failed_feed_is_recorded_not_raised(self):
        def boom(url, timeout=10.0):
            raise OSError("network down")

        intel._http_get = boom
        ti = ThreatIntel([{"name": "flaky", "url": "https://feed.test/x.txt"}])
        count = ti.refresh()
        self.assertEqual(count, 0)
        self.assertIn("flaky", ti.last_errors)
        self.assertIn("network down", ti.last_errors["flaky"])

    def test_dead_feed_does_not_wipe_working_feed(self):
        def boom(url, timeout=10.0):
            raise OSError("timeout")

        intel._http_get = boom
        with _TempFeed(LOCAL_FEED) as path:
            ti = ThreatIntel(
                [
                    {"name": "local", "path": path},
                    {"name": "dead", "url": "https://feed.test/x.txt"},
                ]
            )
            ti.refresh()
            # Local source still works despite the dead remote feed.
            self.assertIsNotNone(ti.is_known_bad("203.0.113.7"))
            self.assertIn("dead", ti.last_errors)


class SourceValidationTests(unittest.TestCase):
    def test_source_requires_exactly_one_of_path_or_url(self):
        with self.assertRaises(ValueError):
            IntelSource(name="bad")  # neither
        with self.assertRaises(ValueError):
            IntelSource(name="bad", path="/x", url="https://y")  # both

    def test_http_get_rejects_non_http_scheme(self):
        with self.assertRaises(ValueError):
            intel._http_get("file:///etc/passwd")

    def test_malformed_lookup_input_returns_none(self):
        ti = ThreatIntel([])
        ti.refresh()
        self.assertIsNone(ti.is_known_bad("not-an-ip"))


class MostSpecificMatchTests(unittest.TestCase):
    def test_longest_prefix_cidr_wins(self):
        feed = "10.0.0.0/8 broad\n10.1.0.0/16 narrow\n"
        with _TempFeed(feed) as path:
            ti = ThreatIntel([{"name": "s", "path": path}])
            ti.refresh()
            reason = ti.is_known_bad("10.1.2.3")
            self.assertIsNotNone(reason)
            self.assertIn("narrow", reason)


if __name__ == "__main__":
    unittest.main()

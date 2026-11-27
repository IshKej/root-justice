"""Tests for artex_antidote.persistence.DurableRegistry.

These run fully offline (no network, no admin). SQLite writes to a temp file on
disk so we can prove state survives a simulated process restart by opening a brand
new DurableRegistry on the same path.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from artex_antidote.persistence import DurableRegistry
from artex_antidote.shield import VirtualPatchRegistry


class DurabilityTest(unittest.TestCase):
    def setUp(self) -> None:
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite3", prefix="artex_test_")
        os.close(fd)
        # Start from a clean file so the schema is (re)created by DurableRegistry.
        os.unlink(self.db_path)

    def tearDown(self) -> None:
        # addCleanup() callbacks (which close connections) run after tearDown, so on
        # Windows the file may still be locked here; ignore that and let the OS temp
        # sweeper reclaim it. The assertions above are what matter.
        if os.path.exists(self.db_path):
            try:
                os.unlink(self.db_path)
            except PermissionError:
                pass

    def test_state_survives_restart(self) -> None:
        # First "process": write some state, then drop the instance entirely.
        reg = DurableRegistry(self.db_path)
        reg.block_ip("203.0.113.9", "canary_probe:/.env")
        reg.add_virtual_patch("/api/v1/debug", "exploit_probe_pattern")
        reg.close()
        del reg

        # Second "process": a brand new instance on the same file must see it all.
        reopened = DurableRegistry(self.db_path)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.is_ip_blocked("203.0.113.9"), "canary_probe:/.env")
        self.assertEqual(
            reopened.match_virtual_patch("/api/v1/debug"), "exploit_probe_pattern"
        )
        snap = reopened.snapshot()
        self.assertEqual(snap["blocked_ips"]["203.0.113.9"], "canary_probe:/.env")
        self.assertEqual(snap["patched_paths"]["/api/v1/debug"], "exploit_probe_pattern")

    def test_unblocked_ip_returns_none(self) -> None:
        reg = DurableRegistry(self.db_path)
        self.addCleanup(reg.close)
        self.assertIsNone(reg.is_ip_blocked("198.51.100.1"))

    def test_block_upsert_updates_reason(self) -> None:
        reg = DurableRegistry(self.db_path)
        self.addCleanup(reg.close)
        reg.block_ip("203.0.113.9", "first_reason")
        reg.block_ip("203.0.113.9", "second_reason")
        self.assertEqual(reg.is_ip_blocked("203.0.113.9"), "second_reason")
        self.assertEqual(len(reg.snapshot()["blocked_ips"]), 1)


class PathBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.reg = DurableRegistry(":memory:")
        self.addCleanup(self.reg.close)

    def test_exact_and_child_match_but_not_prefix_substring(self) -> None:
        self.reg.add_virtual_patch("/admin", "weaponized")
        # Exact path matches.
        self.assertEqual(self.reg.match_virtual_patch("/admin"), "weaponized")
        # Child under a real "/" boundary matches.
        self.assertEqual(self.reg.match_virtual_patch("/admin/users"), "weaponized")
        # A sibling that merely shares the textual prefix must NOT match.
        self.assertIsNone(self.reg.match_virtual_patch("/administrator"))
        self.assertIsNone(self.reg.match_virtual_patch("/adminpanel"))
        # An unrelated path does not match.
        self.assertIsNone(self.reg.match_virtual_patch("/home"))

    def test_query_string_is_ignored(self) -> None:
        self.reg.add_virtual_patch("/api/v1/debug", "exploit")
        self.assertEqual(
            self.reg.match_virtual_patch("/api/v1/debug?x=1&y=2"), "exploit"
        )

    def test_root_is_never_a_wildcard(self) -> None:
        self.reg.add_virtual_patch("/", "should_not_flag_whole_site")
        self.assertIsNone(self.reg.match_virtual_patch("/anything"))
        self.assertIsNone(self.reg.match_virtual_patch("/"))

    def test_trailing_slash_patch_matches_children(self) -> None:
        self.reg.add_virtual_patch("/wp-admin/", "weaponized")
        self.assertEqual(self.reg.match_virtual_patch("/wp-admin/post.php"), "weaponized")
        self.assertIsNone(self.reg.match_virtual_patch("/wp-adminx"))

    def test_api_parity_with_in_memory_registry(self) -> None:
        # The durable registry must agree with VirtualPatchRegistry on the same inputs.
        mem = VirtualPatchRegistry()
        for r in (self.reg, mem):
            r.block_ip("203.0.113.5", "burst")
            r.add_virtual_patch("/admin", "weaponized")
        for probe in ("/admin", "/admin/x", "/administrator", "/", "/home"):
            self.assertEqual(
                self.reg.match_virtual_patch(probe),
                mem.match_virtual_patch(probe),
                msg=f"mismatch for {probe!r}",
            )
        self.assertEqual(
            self.reg.is_ip_blocked("203.0.113.5"), mem.is_ip_blocked("203.0.113.5")
        )


class TtlTest(unittest.TestCase):
    """TTL behavior with a controllable clock seam (no real sleeping)."""

    def setUp(self) -> None:
        self.reg = DurableRegistry(":memory:")
        self.addCleanup(self.reg.close)
        self._clock = [1_000.0]
        # Monkeypatch the time seam so tests do not sleep and stay deterministic.
        self.reg._now = lambda: self._clock[0]  # type: ignore[method-assign]

    def test_block_expires_after_ttl(self) -> None:
        self.reg.block_ip("203.0.113.7", "temp_block", ttl_seconds=30)
        # Still blocked just before expiry.
        self._clock[0] = 1_029.0
        self.assertEqual(self.reg.is_ip_blocked("203.0.113.7"), "temp_block")
        # Expired once the TTL elapses.
        self._clock[0] = 1_031.0
        self.assertIsNone(self.reg.is_ip_blocked("203.0.113.7"))
        self.assertNotIn("203.0.113.7", self.reg.snapshot()["blocked_ips"])

    def test_no_ttl_blocks_indefinitely(self) -> None:
        self.reg.block_ip("203.0.113.8", "permanent")
        self._clock[0] = 10_000_000.0
        self.assertEqual(self.reg.is_ip_blocked("203.0.113.8"), "permanent")

    def test_purge_expired_counts_removed(self) -> None:
        self.reg.block_ip("a", "r", ttl_seconds=10)
        self.reg.block_ip("b", "r", ttl_seconds=100)
        self.reg.block_ip("c", "r")  # no TTL
        self._clock[0] = 1_050.0
        removed = self.reg.purge_expired()
        self.assertEqual(removed, 1)
        self.assertEqual(set(self.reg.snapshot()["blocked_ips"]), {"b", "c"})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

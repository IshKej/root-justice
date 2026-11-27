"""Concurrency tests for the thread-shared shield state.

``VirtualPatchRegistry`` is the DEFAULT registry under ``ThreadingHTTPServer`` and
``ArtexShield`` is shared across request-handler threads. These tests hammer the
registry and the burst tracker from many threads at once. Before the locking fix,
a reader iterating ``_patched_paths`` / ``_recent_hits`` while another thread wrote
could raise ``RuntimeError: dictionary changed size during iteration`` (which the
server turned into a fail-open), so each test fails the moment any worker thread
raises.
"""

from __future__ import annotations

import threading
import unittest

from artex_antidote.shield import ArtexShield, RequestEvent, VirtualPatchRegistry


def _event(path: str, ip: str = "198.51.100.25") -> RequestEvent:
    return RequestEvent(
        timestamp_utc="2026-11-26T20:00:00.000Z",
        remote_ip=ip,
        forwarded_for=[],
        method="GET",
        path=path,
        user_agent="nuclei",
        headers={},
        body_sha256="",
        body_size=0,
    )


def _run_workers(targets) -> list:
    """Run worker callables as threads; return a list of exceptions they raised."""
    errors: list = []
    lock = threading.Lock()

    def wrap(fn):
        def inner():
            try:
                fn()
            except BaseException as exc:  # noqa: BLE001 - we want to surface any race
                with lock:
                    errors.append(exc)

        return inner

    threads = [threading.Thread(target=wrap(t)) for t in targets]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return errors


class TestVirtualPatchRegistryConcurrency(unittest.TestCase):
    def test_block_and_match_under_contention(self) -> None:
        reg = VirtualPatchRegistry()
        ITER = 4000

        def writer_ips():
            for i in range(ITER):
                reg.block_ip(f"203.0.113.{i % 256}", f"scan-{i}")

        def writer_patches():
            for i in range(ITER):
                reg.add_virtual_patch(f"/api/res{i}", f"patch-{i}")

        def reader_match():
            for i in range(ITER):
                reg.match_virtual_patch(f"/api/res{i}/child")

        def reader_blocked():
            for i in range(ITER):
                reg.is_ip_blocked(f"203.0.113.{i % 256}")

        def reader_snapshot():
            for _ in range(ITER // 10):
                snap = reg.snapshot()
                # snapshot must be a stable, detached copy
                self.assertIn("blocked_ips", snap)
                self.assertIn("patched_paths", snap)

        errors = _run_workers(
            [writer_ips, writer_patches, reader_match, reader_blocked, reader_snapshot]
            * 2
        )
        self.assertEqual(errors, [], msg=f"registry raced under contention: {errors[:3]}")

    def test_concurrent_writes_are_all_retained(self) -> None:
        reg = VirtualPatchRegistry()
        N = 500

        def writer(base):
            def inner():
                for i in range(N):
                    reg.add_virtual_patch(f"/w{base}/p{i}", "x")

            return inner

        errors = _run_workers([writer(b) for b in range(6)])
        self.assertEqual(errors, [])
        self.assertEqual(len(reg.snapshot()["patched_paths"]), 6 * N)


class TestArtexShieldBurstConcurrency(unittest.TestCase):
    def test_inspect_burst_state_is_thread_safe(self) -> None:
        shield = ArtexShield(patches=VirtualPatchRegistry(), burst_threshold=5)
        ITER = 3000

        def hammer(ip):
            def inner():
                for i in range(ITER):
                    # Rotating and repeating IPs exercises insert + append + evict.
                    shield.inspect(_event(f"/probe{i}", ip=f"198.51.100.{i % 50}"))

            return inner

        errors = _run_workers([hammer(b) for b in range(6)])
        self.assertEqual(errors, [], msg=f"burst tracker raced: {errors[:3]}")


if __name__ == "__main__":
    unittest.main()

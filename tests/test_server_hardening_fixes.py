"""Tests for the server/health safety + observability hardening fixes.

Covers the audit findings fixed in ``server.py`` / ``health.py``:

* the operator ``/dashboard`` route is gated to loopback peers (404 otherwise),
  while ``/healthz`` and ``/readyz`` stay public;
* a bounded worker semaphore sheds load with ``503`` when saturated;
* the banner is a neutral factual notice by default, with the statute text
  strictly opt-in;
* evidence records persist the route only (no query string) plus a sha256 of the
  full raw path;
* request/flagged/last-event telemetry is counted in ``handle()`` and surfaced
  through the health payload, and error increments are lock-guarded;
* a saturated tarpit budget serves the banner without the slow drip.

Everything is offline: an ephemeral loopback ``ThreadingHTTPServer`` is the only
"network", and the tarpit drip is replaced by a counting stub.
"""

from __future__ import annotations

import tempfile
import threading
import unittest
from hashlib import sha256
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

from artex_antidote import server as server_mod
from artex_antidote.health import engine_stats, health_payload
from artex_antidote.server import (
    ShieldEngine,
    _is_loopback,
    build_warning_response,
    make_handler,
)
from artex_antidote.shield import ArtexShield, RequestEvent, VirtualPatchRegistry


def _engine(tmp: str, **kw) -> ShieldEngine:
    return ShieldEngine(evidence_path=str(Path(tmp) / "ledger.jsonl"), **kw)


def _flagging_event() -> RequestEvent:
    return RequestEvent(
        timestamp_utc="2026-11-26T00:00:00.000Z",
        remote_ip="203.0.113.45",
        forwarded_for=["203.0.113.45"],
        method="GET",
        path="/.env",
        user_agent="nuclei",
        headers={},
        body_sha256="",
        body_size=0,
    )


# --------------------------------------------------------------------------- #
# Finding 5 — honest / neutral banner, opt-in statute text
# --------------------------------------------------------------------------- #
class BannerTests(unittest.TestCase):
    def _detection(self):
        return ArtexShield(patches=VirtualPatchRegistry()).inspect(_flagging_event())

    def test_default_banner_is_neutral(self) -> None:
        banner = build_warning_response(self._detection()).decode("utf-8")
        self.assertIn("detected and blocked", banner)
        self.assertIn("logged", banner)
        # No criminal accusation and no referral claim by default.
        self.assertNotIn("FBI IC3", banner)
        self.assertNotIn("18 U.S.C. 1030", banner)
        self.assertNotIn("federal crime", banner)
        self.assertNotIn("referral", banner.lower())

    def test_statute_notice_is_opt_in(self) -> None:
        banner = build_warning_response(
            self._detection(), statute_notice=True
        ).decode("utf-8")
        self.assertIn("18 U.S.C. 1030", banner)
        self.assertIn("FBI IC3", banner)
        # Still factual: "may violate", not "you committed a crime".
        self.assertIn("may violate", banner)
        self.assertNotIn("is a federal crime", banner)

    def test_engine_statute_flag_drives_plan_banner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # Default: statute OFF.
            eng = _engine(tmp, enforce=True, decoy_enabled=False)
            det = eng.handle("203.0.113.45", "GET", "/.env", {"User-Agent": "nuclei"}, b"")
            _, _, body, _ = eng.plan_enforcement(det, "/.env")
            self.assertNotIn(b"18 U.S.C. 1030", body)

            # Opt-in: statute ON.
            eng2 = _engine(tmp, enforce=True, decoy_enabled=False, statute_notice=True)
            det2 = eng2.handle("203.0.113.45", "GET", "/.env", {"User-Agent": "nuclei"}, b"")
            _, _, body2, _ = eng2.plan_enforcement(det2, "/.env")
            self.assertIn(b"18 U.S.C. 1030", body2)


# --------------------------------------------------------------------------- #
# Finding 6 — PII minimization (no raw query strings in the ledger)
# --------------------------------------------------------------------------- #
class QueryStringStrippingTests(unittest.TestCase):
    def test_evidence_stores_route_only_plus_raw_path_hash(self) -> None:
        raw = "/api/users?q=1 UNION SELECT 1,2&token=sekret"
        with tempfile.TemporaryDirectory() as tmp:
            eng = _engine(tmp, enforce=True)
            det = eng.handle("203.0.113.45", "GET", raw, {"User-Agent": "ffuf"}, b"")
            self.assertTrue(det.flagged)
            recs = eng.store.records()
            self.assertEqual(len(recs), 1)
            rec = recs[0]
            # Route only — the query string (and its secrets) is not persisted.
            self.assertEqual(rec["path"], "/api/users")
            self.assertNotIn("?", rec["path"])
            self.assertNotIn("sekret", rec["path"])
            # A sha256 of the FULL raw path is retained for correlation.
            self.assertEqual(
                rec["rea_findings"]["raw_path_sha256"],
                sha256(raw.encode("utf-8")).hexdigest(),
            )

    def test_path_without_query_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            eng = _engine(tmp, enforce=True)
            eng.handle("203.0.113.45", "GET", "/.env", {"User-Agent": "nuclei"}, b"")
            self.assertEqual(eng.store.records()[0]["path"], "/.env")


# --------------------------------------------------------------------------- #
# Finding 4 — accurate telemetry
# --------------------------------------------------------------------------- #
class TelemetryTests(unittest.TestCase):
    def test_request_and_flagged_counts_track_handle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            eng = _engine(tmp, enforce=True)
            eng.handle("1.2.3.4", "GET", "/home", {"User-Agent": "Mozilla/5.0"}, b"")
            eng.handle("203.0.113.45", "GET", "/.env", {"User-Agent": "nuclei"}, b"")
            self.assertEqual(eng.request_count, 2)
            self.assertEqual(eng.flagged_count, 1)
            self.assertIsNotNone(eng.last_event_utc)

            stats = engine_stats(eng)
            self.assertEqual(stats["request_count"], 2)
            self.assertEqual(stats["flagged_count"], 1)
            payload = health_payload(stats)
            self.assertEqual(payload["requests"], 2)
            self.assertEqual(payload["flagged"], 1)
            self.assertTrue(payload["last_event_utc"])

    def test_allowlisted_request_counts_but_not_flagged(self) -> None:
        from artex_antidote.allowlist import Allowlist

        with tempfile.TemporaryDirectory() as tmp:
            eng = _engine(tmp, enforce=True, allowlist=Allowlist(["203.0.113.45"]))
            eng.handle("203.0.113.45", "GET", "/.env", {"User-Agent": "nuclei"}, b"")
            self.assertEqual(eng.request_count, 1)
            self.assertEqual(eng.flagged_count, 0)

    def test_error_increments_are_lock_guarded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            eng = _engine(tmp, enforce=True)

            def boom(*_a, **_k):
                raise RuntimeError("detector exploded")

            eng.shield.inspect = boom  # type: ignore[assignment]
            det = eng.handle("203.0.113.45", "GET", "/.env", {"User-Agent": "nuclei"}, b"")
            self.assertFalse(det.flagged)  # fail OPEN
            self.assertEqual(eng.errors, 1)
            self.assertEqual(engine_stats(eng)["errors"], 1)

    def test_concurrent_requests_count_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            eng = _engine(tmp, enforce=False)

            def worker() -> None:
                for _ in range(25):
                    eng.handle("1.2.3.4", "GET", "/home", {"User-Agent": "Mozilla/5.0"}, b"")

            threads = [threading.Thread(target=worker) for _ in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(eng.request_count, 100)

    def test_alerter_health_surfaced(self) -> None:
        class _A:
            failure_count = 2
            last_error = "hook 500"

        with tempfile.TemporaryDirectory() as tmp:
            eng = _engine(tmp)
            eng.alerter = _A()  # type: ignore[assignment]
            stats = engine_stats(eng)
            self.assertEqual(stats["alerter_failures"], 2)
            self.assertEqual(stats["alerter_last_error"], "hook 500")


# --------------------------------------------------------------------------- #
# Finding 1 — /dashboard loopback gate
# --------------------------------------------------------------------------- #
class LoopbackHelperTests(unittest.TestCase):
    def test_is_loopback(self) -> None:
        for host in ("127.0.0.1", "127.0.0.5", "::1", "localhost"):
            self.assertTrue(_is_loopback(host), host)
        for host in ("203.0.113.45", "10.0.0.1", "8.8.8.8", "not-an-ip"):
            self.assertFalse(_is_loopback(host), host)


class _FakeInfraHandler:
    """Minimal stand-in that exercises ``_try_infra_route`` without a socket."""

    def __init__(self, engine, command: str, path: str, peer: str) -> None:
        Handler = make_handler(engine)
        self._real = Handler
        self.command = command
        self.path = path
        self.client_address = (peer, 54321)
        self.captured: dict = {}
        # Bind the real route logic + helpers onto this fake instance.
        self._try_infra_route = Handler._try_infra_route.__get__(self, _FakeInfraHandler)
        self._route_only_path = Handler._route_only_path.__get__(self, _FakeInfraHandler)

    def _write_json(self, status, obj):
        self.captured = {"kind": "json", "status": status, "obj": obj}

    def _write(self, status, headers, body):
        self.captured = {"kind": "html", "status": status, "body": body}


class DashboardGateTests(unittest.TestCase):
    def test_dashboard_from_loopback_renders(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = _FakeInfraHandler(_engine(tmp), "GET", "/dashboard", "127.0.0.1")
            self.assertTrue(h._try_infra_route())
            self.assertEqual(h.captured["kind"], "html")
            self.assertEqual(h.captured["status"], 200)

    def test_dashboard_from_remote_is_404(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = _FakeInfraHandler(_engine(tmp), "GET", "/dashboard", "203.0.113.45")
            self.assertTrue(h._try_infra_route())  # handled (not scored)
            self.assertEqual(h.captured["kind"], "json")
            self.assertEqual(h.captured["status"], 404)

    def test_health_and_ready_stay_public(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for route in ("/healthz", "/readyz"):
                h = _FakeInfraHandler(_engine(tmp), "GET", route, "203.0.113.45")
                self.assertTrue(h._try_infra_route())
                self.assertEqual(h.captured["kind"], "json")
                self.assertEqual(h.captured["status"], 200)


class _LiveServer:
    def __init__(self, engine, **handler_kw) -> None:
        self.handler_cls = make_handler(engine, **handler_kw)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self.handler_cls)
        self.port = self.httpd.server_address[1]

    def __enter__(self) -> "_LiveServer":
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def get(self, path: str, headers=None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", path, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()


class LiveDashboardGateTests(unittest.TestCase):
    def test_loopback_dashboard_over_the_wire(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with _LiveServer(_engine(tmp)) as srv:  # client is 127.0.0.1
                status, body = srv.get("/dashboard")
                self.assertEqual(status, 200)
                self.assertIn(b"Operator Dashboard", body)


# --------------------------------------------------------------------------- #
# Finding 2 — bounded concurrency (503) and bounded tarpit budget
# --------------------------------------------------------------------------- #
class _FakeDispatchHandler:
    """Stand-in to exercise ``_dispatch``'s saturation gate without a socket."""

    def __init__(self, Handler) -> None:
        self._worker_sem = Handler._worker_sem
        self._tarpit_sem = Handler._tarpit_sem
        self.captured: dict = {}
        self._dispatch = Handler._dispatch.__get__(self, _FakeDispatchHandler)

    def _write_json(self, status, obj):
        self.captured = {"status": status, "obj": obj}

    def _dispatch_inner(self):  # pragma: no cover - must NOT run when saturated
        self.captured = {"status": "inner-ran"}


class SaturationTests(unittest.TestCase):
    def test_default_concurrency_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            Handler = make_handler(_engine(tmp))
            self.assertEqual(Handler.timeout, 30.0)
            self.assertEqual(Handler._worker_sem._initial_value, 128)
            self.assertEqual(Handler._tarpit_sem._initial_value, 16)

    def test_saturated_server_returns_503(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            Handler = make_handler(_engine(tmp), max_workers=1, request_timeout=7.0)
            self.assertEqual(Handler.timeout, 7.0)
            # Drain the only worker permit so the next dispatch is shed.
            self.assertTrue(Handler._worker_sem.acquire(blocking=False))
            try:
                h = _FakeDispatchHandler(Handler)
                h._dispatch()
                self.assertEqual(h.captured["status"], 503)
                self.assertEqual(h.captured["obj"]["status"], "unavailable")
            finally:
                Handler._worker_sem.release()

    def test_dispatch_runs_inner_when_capacity_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            Handler = make_handler(_engine(tmp), max_workers=2)
            h = _FakeDispatchHandler(Handler)
            h._dispatch()
            self.assertEqual(h.captured["status"], "inner-ran")
            # Permit released after dispatch: full budget is back.
            self.assertTrue(Handler._worker_sem.acquire(blocking=False))
            Handler._worker_sem.release()


class TarpitBudgetTests(unittest.TestCase):
    def test_full_tarpit_budget_skips_the_drip(self) -> None:
        orig = server_mod.tarpit_mod.drip
        calls = {"n": 0}

        def _counting_drip(write, **kw):
            calls["n"] += 1
            # Still deliver the payload (just without the real slow drip) so the
            # client receives a complete response.
            write(kw["payload"])

        server_mod.tarpit_mod.drip = _counting_drip
        try:
            with tempfile.TemporaryDirectory() as tmp:
                # decoy disabled so a flagged canary falls back to the drip banner.
                eng = _engine(tmp, enforce=True, decoy_enabled=False)
                with _LiveServer(eng, max_tarpits=1) as srv:
                    # Budget available -> the drip path is taken.
                    status, body = srv.get("/.env", headers={"User-Agent": "nuclei"})
                    self.assertEqual(status, 403)
                    self.assertIn(b"detected and blocked", body)
                    self.assertEqual(calls["n"], 1)

                    # Drain the single tarpit permit -> banner is sent WITHOUT drip.
                    self.assertTrue(srv.handler_cls._tarpit_sem.acquire(blocking=False))
                    try:
                        status2, body2 = srv.get("/.env", headers={"User-Agent": "nuclei"})
                        self.assertEqual(status2, 403)
                        self.assertIn(b"detected and blocked", body2)
                        self.assertEqual(calls["n"], 1)  # drip NOT called again
                    finally:
                        srv.handler_cls._tarpit_sem.release()
        finally:
            server_mod.tarpit_mod.drip = orig


if __name__ == "__main__":
    unittest.main()

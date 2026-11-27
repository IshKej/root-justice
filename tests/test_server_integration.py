"""Integration tests for the wired-up request path in ``server.py``.

These exercise the features stitched into :class:`server.ShieldEngine` and its
HTTP handler: allowlist short-circuit, durable persistence, threat-intel
pre-blocking, header fingerprinting, the upstream reverse proxy, tarpit/decoy
enforcement planning, high-severity alerting, and the infra (health/readiness/
dashboard) routes.

Everything runs OFFLINE with no admin: the only "network" is a loopback
ThreadingHTTPServer on an ephemeral port, and the upstream proxy's socket seam
(``proxy._open_conn``) is monkeypatched so no real upstream is contacted.
"""

from __future__ import annotations

import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

from artex_antidote import proxy as proxy_mod
from artex_antidote.allowlist import Allowlist
from artex_antidote.dashboard import Alerter
from artex_antidote.decoy import CANARY_MARKER
from artex_antidote.intel import ThreatIntel
from artex_antidote.persistence import DurableRegistry
from artex_antidote.server import ShieldEngine, make_handler
from artex_antidote.shield import DetectionResult
from http.server import ThreadingHTTPServer


def _engine(tmp: str, **kw) -> ShieldEngine:
    return ShieldEngine(evidence_path=str(Path(tmp) / "ledger.jsonl"), **kw)


class TestAllowlistShortCircuit(unittest.TestCase):
    def test_allowlisted_ip_is_never_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp, enforce=True, allowlist=Allowlist(["203.0.113.45"]))
            # A hard canary probe from an allowlisted source: still NOT flagged.
            det = engine.handle("203.0.113.45", "GET", "/.env", {"User-Agent": "nuclei"}, b"")
            self.assertFalse(det.flagged)
            self.assertEqual(det.recommended_action, "allow")
            self.assertTrue(any(r.startswith("allowlisted:") for r in det.reasons))
            # Nothing recorded for a trusted source.
            self.assertEqual(len(engine.store.records()), 0)

    def test_cidr_allowlist_covers_range(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp, enforce=True, allowlist=Allowlist(["10.0.0.0/8"]))
            det = engine.handle("10.1.2.3", "GET", "/.env", {"User-Agent": "nuclei"}, b"")
            self.assertFalse(det.flagged)

    def test_non_allowlisted_still_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp, enforce=True, allowlist=Allowlist(["10.0.0.0/8"]))
            det = engine.handle("203.0.113.45", "GET", "/.env", {"User-Agent": "nuclei"}, b"")
            self.assertTrue(det.flagged)


class TestPersistence(unittest.TestCase):
    def test_durable_registry_survives_new_engine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "state.sqlite3")
            engine = _engine(tmp, enforce=True, db_path=db)
            self.assertIsInstance(engine.patches, DurableRegistry)
            # A critical canary probe in enforce mode blocks the socket peer.
            det = engine.handle("203.0.113.45", "GET", "/.env", {"User-Agent": "nuclei"}, b"")
            self.assertTrue(det.flagged)
            self.assertIsNotNone(engine.patches.is_ip_blocked("203.0.113.45"))
            engine.patches.close()

            # A brand-new engine pointed at the same DB still sees the block.
            reopened = ShieldEngine(evidence_path=str(Path(tmp) / "l2.jsonl"), db_path=db)
            self.assertIsNotNone(reopened.patches.is_ip_blocked("203.0.113.45"))
            reopened.patches.close()

    def test_default_registry_is_in_memory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp)
            self.assertNotIsInstance(engine.patches, DurableRegistry)


class TestThreatIntel(unittest.TestCase):
    def test_known_bad_ip_is_flagged_before_scoring(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            feed = Path(tmp) / "bans.txt"
            feed.write_text("203.0.113.45 known scanner\n", encoding="utf-8")
            intel = ThreatIntel([{"name": "local-bans", "path": str(feed)}])
            intel.refresh()
            engine = _engine(tmp, enforce=True, intel=intel)
            # A benign path from a known-bad IP is flagged purely on intel.
            det = engine.handle("203.0.113.45", "GET", "/home", {"User-Agent": "Mozilla/5.0"}, b"")
            self.assertTrue(det.flagged)
            self.assertTrue(any("threat_intel" in r for r in det.reasons))

    def test_unknown_ip_not_flagged_by_intel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            feed = Path(tmp) / "bans.txt"
            feed.write_text("198.51.100.9\n", encoding="utf-8")
            intel = ThreatIntel([{"name": "local-bans", "path": str(feed)}])
            intel.refresh()
            engine = _engine(tmp, enforce=True, intel=intel)
            det = engine.handle("203.0.113.45", "GET", "/home", {"User-Agent": "Mozilla/5.0"}, b"")
            self.assertFalse(det.flagged)


class TestFingerprint(unittest.TestCase):
    def test_fingerprint_attached_to_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp)
            det = engine.handle(
                "203.0.113.45", "GET", "/home", {"User-Agent": "x", "Accept": "*/*"}, b""
            )
            self.assertTrue(det.client_fingerprint)
            self.assertEqual(det.client_fingerprint, engine.last_fingerprint)

    def test_fingerprint_present_on_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp, enforce=True)
            det = engine.handle("203.0.113.45", "GET", "/.env", {"User-Agent": "nuclei"}, b"")
            self.assertTrue(det.flagged)
            self.assertTrue(det.client_fingerprint)


class TestEnforcementPlanning(unittest.TestCase):
    def test_decoy_served_for_flagged_canary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp, enforce=True)
            det = engine.handle("203.0.113.45", "GET", "/.env", {"User-Agent": "nuclei"}, b"")
            plan = engine.plan_enforcement(det, "/.env")
            self.assertIsNotNone(plan)
            status, headers, body, drip = plan
            self.assertEqual(status, 200)  # decoy looks like success
            self.assertFalse(drip)
            self.assertIn(CANARY_MARKER.encode("utf-8"), body)

    def test_decoy_disabled_falls_back_to_banner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp, enforce=True, decoy_enabled=False)
            det = engine.handle("203.0.113.45", "GET", "/.env", {"User-Agent": "nuclei"}, b"")
            plan = engine.plan_enforcement(det, "/.env")
            self.assertIsNotNone(plan)
            status, headers, body, drip = plan
            self.assertEqual(status, 403)
            self.assertTrue(drip)  # canary action is tarpit -> slow-drip the banner
            # Default banner is the neutral notice (no statute text unless opted in).
            self.assertIn(b"detected and blocked", body)
            self.assertNotIn(b"FBI IC3", body)

    def test_backoff_action_plans_429_banner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp, enforce=True)
            det = engine.handle(
                "203.0.113.45", "GET", "/api/users?q=1 UNION SELECT 1,2", {"User-Agent": "ffuf"}, b""
            )
            self.assertEqual(det.recommended_action, "backoff_429")
            plan = engine.plan_enforcement(det, det and "/api/users")
            status, headers, body, drip = plan
            self.assertEqual(status, 429)
            self.assertFalse(drip)

    def test_log_only_mode_plans_no_enforcement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp, enforce=False)
            det = engine.handle("203.0.113.45", "GET", "/.env", {"User-Agent": "nuclei"}, b"")
            self.assertTrue(det.flagged)
            self.assertIsNone(engine.plan_enforcement(det, "/.env"))


class TestAlerter(unittest.TestCase):
    def test_alerter_fires_on_critical(self) -> None:
        sent = []
        alerter = Alerter("https://hook.example.test/x", post_fn=lambda u, p: sent.append((u, p)) or 200)
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp, enforce=True, alerter=alerter)
            engine.handle("203.0.113.45", "GET", "/.env", {"User-Agent": "nuclei"}, b"")
            self.assertEqual(len(sent), 1)
            self.assertEqual(sent[0][1]["severity"], "critical")

    def test_alerter_silent_on_clean_traffic(self) -> None:
        sent = []
        alerter = Alerter("https://hook.example.test/x", post_fn=lambda u, p: sent.append(p) or 200)
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp, enforce=True, alerter=alerter)
            engine.handle("203.0.113.45", "GET", "/home", {"User-Agent": "Mozilla/5.0"}, b"")
            self.assertEqual(sent, [])


class TestProxyForwarding(unittest.TestCase):
    def test_forward_clean_relays_to_upstream(self) -> None:
        captured = {}

        class _FakeResp:
            status = 201

            def read(self, *_a):
                return b"UPSTREAM-OK"

            def getheaders(self):
                return [("Content-Type", "text/plain"), ("X-Up", "1")]

        class _FakeConn:
            def __init__(self, *a, **k):
                pass

            def request(self, method, target, body=b"", headers=None):
                captured["method"] = method
                captured["target"] = target
                captured["xff"] = (headers or {}).get("X-Forwarded-For")

            def getresponse(self):
                return _FakeResp()

            def close(self):
                pass

        orig = proxy_mod._open_conn
        proxy_mod._open_conn = lambda host, port, use_https, timeout: _FakeConn()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                engine = _engine(tmp, upstream="http://127.0.0.1:9000")
                result = engine.forward_clean(
                    "GET", "/dashboard-app", {"Host": "x"}, b"", client_ip="203.0.113.45"
                )
                self.assertIsNotNone(result)
                status, headers, body = result
                self.assertEqual(status, 201)
                self.assertEqual(body, b"UPSTREAM-OK")
                # The unspoofable socket peer is appended to X-Forwarded-For.
                self.assertIn("203.0.113.45", captured["xff"])
        finally:
            proxy_mod._open_conn = orig

    def test_forward_clean_none_without_upstream(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp)
            self.assertIsNone(engine.forward_clean("GET", "/x", {}, b"", client_ip="1.2.3.4"))


class _LiveServer:
    """Context manager running the shield handler on a loopback ephemeral port."""

    def __init__(self, engine: ShieldEngine) -> None:
        self.engine = engine
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(engine))
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


class TestLiveInfraRoutes(unittest.TestCase):
    def test_healthz_reports_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with _LiveServer(_engine(tmp, enforce=False)) as srv:
                status, body = srv.get("/healthz")
                self.assertEqual(status, 200)
                self.assertIn(b"log-only", body)
                self.assertIn(b"status", body)

    def test_readyz_is_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with _LiveServer(_engine(tmp)) as srv:
                status, body = srv.get("/readyz")
                self.assertEqual(status, 200)
                self.assertIn(b"ready", body)

    def test_dashboard_renders_html(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with _LiveServer(_engine(tmp)) as srv:
                status, body = srv.get("/dashboard")
                self.assertEqual(status, 200)
                self.assertIn(b"Operator Dashboard", body)

    def test_health_route_not_scored_as_attack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp, enforce=True)
            with _LiveServer(engine) as srv:
                srv.get("/healthz", headers={"User-Agent": "nuclei"})
            # No evidence recorded for an infra probe, even with a tool UA.
            self.assertEqual(len(engine.store.records()), 0)

    def test_benign_request_hits_local_sink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with _LiveServer(_engine(tmp)) as srv:
                status, body = srv.get("/home")
                self.assertEqual(status, 200)
                self.assertIn(b"ok", body)

    def test_enforced_canary_serves_decoy_over_the_wire(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with _LiveServer(_engine(tmp, enforce=True)) as srv:
                status, body = srv.get("/.env", headers={"User-Agent": "nuclei"})
                self.assertEqual(status, 200)
                self.assertIn(CANARY_MARKER.encode("utf-8"), body)


if __name__ == "__main__":
    unittest.main()

"""Unit tests for the operator dashboard + alerting module (spec #8).

Offline by design: the one network seam (``dashboard._http_post_json``) is never
invoked; the alert tests inject their own ``post_fn`` (or monkeypatch the seam)
so the suite needs no network and no admin rights.
"""

import json
import tempfile
import unittest
from pathlib import Path

from artex_antidote import dashboard as dashboard_mod
from artex_antidote.dashboard import Alerter, build_stats, render_dashboard
from artex_antidote.evidence import EvidenceRecord, EvidenceStore


def _sample_stats():
    return {
        "total_events": 137,
        "flagged_events": 42,
        "reportable_events": 7,
        "blocked_ips": 3,
        "severity_counts": {"critical": 5, "high": 12, "medium": 25, "none": 95},
        "top_ips": [("203.0.113.9", 88), ("198.51.100.4", 31)],
        "enforce": True,
        "chain_integrity": {"intact": True, "broken_at_index": None, "verified_records": 137},
        "generated_utc": "2026-01-02T03:04:05.000Z",
    }


class RenderDashboardTests(unittest.TestCase):
    def test_contains_supplied_numbers(self):
        html = render_dashboard(_sample_stats())
        for needle in ("137", "42", "7", "3", "88", "31"):
            self.assertIn(needle, html)

    def test_contains_top_ips_and_timestamp(self):
        html = render_dashboard(_sample_stats())
        self.assertIn("203.0.113.9", html)
        self.assertIn("198.51.100.4", html)
        self.assertIn("2026-01-02T03:04:05.000Z", html)

    def test_is_self_contained_localhost_page(self):
        html = render_dashboard(_sample_stats())
        self.assertTrue(html.lstrip().lower().startswith("<!doctype html>"))
        self.assertIn("</html>", html)
        # No external resources fetched -> genuinely self-contained / offline.
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("<script", html.lower())

    def test_enforce_vs_log_only_mode(self):
        enforcing = render_dashboard({**_sample_stats(), "enforce": True})
        self.assertIn("ENFORCING", enforcing)
        self.assertNotIn("LOG-ONLY", enforcing)

        logonly = render_dashboard({**_sample_stats(), "enforce": False})
        self.assertIn("LOG-ONLY", logonly)
        self.assertNotIn("ENFORCING", logonly)

    def test_chain_integrity_intact_and_broken(self):
        ok = render_dashboard(_sample_stats())
        self.assertIn("INTACT", ok)

        broken = render_dashboard(
            {
                **_sample_stats(),
                "chain_integrity": {"intact": False, "broken_at_index": 4, "verified_records": 4},
            }
        )
        self.assertIn("BROKEN", broken)
        self.assertIn("index 4", broken)

    def test_escapes_hostile_values(self):
        # Attacker-controlled IP/label must not inject live markup.
        html = render_dashboard({**_sample_stats(), "top_ips": [("<script>alert(1)</script>", 9)]})
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_empty_stats_renders(self):
        html = render_dashboard({})
        self.assertTrue(html.lstrip().lower().startswith("<!doctype html>"))
        self.assertIn("LOG-ONLY", html)  # default enforce=False
        self.assertIn("No attributed sources yet.", html)

    def test_top_ips_accepts_mapping(self):
        html = render_dashboard({**_sample_stats(), "top_ips": {"192.0.2.1": 55}})
        self.assertIn("192.0.2.1", html)
        self.assertIn("55", html)


class BuildStatsTests(unittest.TestCase):
    def _store_with_records(self, path):
        store = EvidenceStore(str(path))
        for sev, ip, reportable in [
            ("critical", "203.0.113.9", True),
            ("high", "203.0.113.9", True),
            ("none", "", False),
        ]:
            store.append(
                EvidenceRecord(
                    timestamp_utc="2026-01-01T00:00:00.000Z",
                    stream_id="s",
                    attributed_ip=ip,
                    attributed_confidence="socket",
                    is_reportable=reportable,
                    ip_chain=[],
                    method="GET",
                    path="/",
                    user_agent="x",
                    header_hash="h",
                    body_sha256="b",
                    severity=sev,
                    reasons=[],
                )
            )
        return store

    def test_build_stats_aggregates_from_store(self):
        with tempfile.TemporaryDirectory() as d:
            store = self._store_with_records(Path(d) / "ev.jsonl")
            stats = build_stats(store, enforce=True)
            self.assertEqual(stats["total_events"], 3)
            self.assertEqual(stats["flagged_events"], 2)  # non-"none" severities
            self.assertEqual(stats["reportable_events"], 2)
            self.assertTrue(stats["enforce"])
            self.assertTrue(stats["chain_integrity"]["intact"])
            self.assertEqual(stats["top_ips"][0], ("203.0.113.9", 2))

    def test_build_stats_render_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            store = self._store_with_records(Path(d) / "ev.jsonl")
            html = render_dashboard(build_stats(store, enforce=False))
            self.assertIn("203.0.113.9", html)
            self.assertIn("LOG-ONLY", html)


class AlerterTests(unittest.TestCase):
    def test_builds_right_payload_and_posts(self):
        captured = {}

        def fake_post(url, payload):
            captured["url"] = url
            captured["payload"] = payload
            return 200

        alerter = Alerter("https://hooks.example.test/abc", post_fn=fake_post)
        event = {
            "stream_id": "artex-stream-deadbeef",
            "attributed_ip": "203.0.113.9",
            "severity": "critical",
            "reasons": ["canary_probe:/.env", "exploit_probe_pattern", "a", "b", "c", "d", "e"],
            "recommended_action": "tarpit",
        }
        ok = alerter.notify(event)

        self.assertTrue(ok)
        self.assertEqual(alerter.sent_count, 1)
        self.assertEqual(captured["url"], "https://hooks.example.test/abc")
        payload = captured["payload"]
        self.assertEqual(payload["source"], "root-justice")
        self.assertEqual(payload["severity"], "critical")
        self.assertEqual(payload["attributed_ip"], "203.0.113.9")
        self.assertEqual(payload["stream_id"], "artex-stream-deadbeef")
        self.assertEqual(payload["action"], "tarpit")
        self.assertEqual(len(payload["reasons"]), 5)  # capped for compactness
        self.assertIn("timestamp_utc", payload)
        # Must be JSON-serializable (it gets POSTed as JSON).
        json.dumps(payload)

    def test_action_key_alias(self):
        captured = {}
        alerter = Alerter("u", post_fn=lambda u, p: captured.update(p) or 204)
        alerter.notify({"action": "block", "severity": "high"})
        self.assertEqual(captured["action"], "block")

    def test_swallows_exceptions(self):
        def boom(url, payload):
            raise ConnectionError("webhook unreachable")

        alerter = Alerter("https://down.example.test", post_fn=boom)
        # Must NOT raise, must report failure.
        self.assertFalse(alerter.notify({"severity": "high"}))
        self.assertEqual(alerter.failure_count, 1)
        self.assertIn("unreachable", alerter.last_error)

    def test_non_2xx_is_failure(self):
        alerter = Alerter("u", post_fn=lambda u, p: 500)
        self.assertFalse(alerter.notify({"severity": "high"}))
        self.assertEqual(alerter.failure_count, 1)

    def test_default_seam_is_not_called_in_tests(self):
        # Sanity: the module exposes the monkeypatchable seam.
        self.assertTrue(hasattr(dashboard_mod, "_http_post_json"))

        calls = []
        original = dashboard_mod._http_post_json
        dashboard_mod._http_post_json = lambda url, payload, timeout=4.0: calls.append(url) or 200
        try:
            # No post_fn -> uses the module seam we just replaced.
            alerter = Alerter("https://seam.example.test")
            self.assertTrue(alerter.notify({"severity": "low"}))
            self.assertEqual(calls, ["https://seam.example.test"])
        finally:
            dashboard_mod._http_post_json = original

    def test_string_reason_is_normalized(self):
        captured = {}
        alerter = Alerter("u", post_fn=lambda u, p: captured.update(p) or 200)
        alerter.notify({"severity": "high", "reasons": "single_reason"})
        self.assertEqual(captured["reasons"], ["single_reason"])


if __name__ == "__main__":
    unittest.main()

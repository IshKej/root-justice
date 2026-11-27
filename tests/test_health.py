"""Tests for artex_antidote.health — liveness/readiness probe shapes.

Pure, offline, no network and no admin: everything here is a dict in / dict out.
"""

from __future__ import annotations

import json
import unittest

from artex_antidote.health import (
    MODE_ENFORCE,
    MODE_LOG_ONLY,
    engine_stats,
    health_payload,
    readiness,
)


class _FakePatches:
    def __init__(self, blocked=None, tarpitted=None, raises=False):
        self._blocked = blocked or {}
        self._tarpitted = tarpitted or {}
        self._raises = raises

    def snapshot(self):
        if self._raises:
            raise RuntimeError("snapshot boom")
        return {"blocked_ips": self._blocked, "tarpitted_ips": self._tarpitted}


class _FakeEngine:
    def __init__(self, enforce=False, errors=0, patches=None):
        self.enforce = enforce
        self.errors = errors
        self.patches = patches


class HealthPayloadTests(unittest.TestCase):
    def test_log_only_default_shape(self):
        payload = health_payload(
            {"enforce": False, "errors": 0, "active_mitigations": 0}
        )
        self.assertEqual(
            payload,
            {
                "status": "ok",
                "mode": MODE_LOG_ONLY,
                "active_mitigations": 0,
                "requests": 0,
                "flagged": 0,
                "errors": 0,
                "last_event_utc": "",
                "alerter_failures": 0,
                "alerter_last_error": "",
            },
        )

    def test_enforce_mode_is_reported(self):
        payload = health_payload({"enforce": True, "active_mitigations": 7})
        self.assertEqual(payload["mode"], MODE_ENFORCE)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["active_mitigations"], 7)

    def test_request_and_flagged_counts_passed_through(self):
        payload = health_payload(
            {"request_count": 40, "flagged_count": 3, "last_event_utc": "2026-01-01T00:00:00.000Z"}
        )
        self.assertEqual(payload["requests"], 40)
        self.assertEqual(payload["flagged"], 3)
        self.assertEqual(payload["last_event_utc"], "2026-01-01T00:00:00.000Z")

    def test_legacy_events_key_maps_to_active_mitigations(self):
        # Backward compatibility: an old-style stats dict still populates the
        # renamed field.
        payload = health_payload({"events": 5})
        self.assertEqual(payload["active_mitigations"], 5)

    def test_errors_mark_status_degraded_but_still_alive(self):
        payload = health_payload({"enforce": False, "errors": 3, "events": 2})
        self.assertEqual(payload["status"], "degraded")
        # Mode is independent of health status.
        self.assertEqual(payload["mode"], MODE_LOG_ONLY)
        self.assertEqual(payload["errors"], 3)

    def test_has_required_keys(self):
        payload = health_payload({})
        for key in ("status", "mode", "active_mitigations", "requests", "flagged"):
            self.assertIn(key, payload)

    def test_empty_stats_defaults_to_ok_log_only(self):
        payload = health_payload({})
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["mode"], MODE_LOG_ONLY)
        self.assertEqual(payload["active_mitigations"], 0)

    def test_non_mapping_input_is_tolerated(self):
        # A probe must never raise on junk input.
        payload = health_payload(None)  # type: ignore[arg-type]
        self.assertEqual(payload["mode"], MODE_LOG_ONLY)
        self.assertEqual(payload["active_mitigations"], 0)

    def test_non_numeric_fields_coerced_safely(self):
        payload = health_payload(
            {"active_mitigations": "not-a-number", "errors": "nope", "request_count": "x"}
        )
        self.assertEqual(payload["active_mitigations"], 0)
        self.assertEqual(payload["requests"], 0)
        self.assertEqual(payload["errors"], 0)
        self.assertEqual(payload["status"], "ok")

    def test_payload_is_json_serialisable(self):
        payload = health_payload({"enforce": True, "errors": 1, "active_mitigations": 4})
        round_tripped = json.loads(json.dumps(payload))
        self.assertEqual(round_tripped, payload)


class ReadinessTests(unittest.TestCase):
    def test_ready_returns_200(self):
        code, body = readiness(bound=True)
        self.assertEqual(code, 200)
        self.assertEqual(body["status"], "ready")
        self.assertTrue(body["bound"])

    def test_not_ready_returns_503(self):
        code, body = readiness(bound=False)
        self.assertEqual(code, 503)
        self.assertEqual(body["status"], "not-ready")
        self.assertFalse(body["bound"])

    def test_returns_tuple_of_code_and_dict(self):
        result = readiness(bound=True)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        code, body = result
        self.assertIsInstance(code, int)
        self.assertIsInstance(body, dict)

    def test_readiness_body_is_json_serialisable(self):
        for bound in (True, False):
            _, body = readiness(bound=bound)
            self.assertEqual(json.loads(json.dumps(body)), body)


class EngineStatsTests(unittest.TestCase):
    def test_extracts_from_engine_like_object(self):
        eng = _FakeEngine(
            enforce=True,
            errors=2,
            patches=_FakePatches(blocked={"1.2.3.4": "scan"}, tarpitted={"5.6.7.8": "x"}),
        )
        stats = engine_stats(eng)
        self.assertTrue(stats["enforce"])
        self.assertEqual(stats["errors"], 2)
        self.assertEqual(stats["active_mitigations"], 2)  # 1 blocked + 1 tarpitted

    def test_fresh_engine_is_log_only_zero_mitigations(self):
        eng = _FakeEngine(patches=_FakePatches())
        stats = engine_stats(eng)
        self.assertFalse(stats["enforce"])
        self.assertEqual(stats["active_mitigations"], 0)
        # Fresh engine feeds a clean liveness payload.
        self.assertEqual(health_payload(stats)["mode"], MODE_LOG_ONLY)

    def test_missing_patches_degrades_gracefully(self):
        eng = _FakeEngine(patches=None)
        stats = engine_stats(eng)
        self.assertEqual(stats["active_mitigations"], 0)
        self.assertEqual(stats["errors"], 0)

    def test_snapshot_exception_does_not_propagate(self):
        eng = _FakeEngine(patches=_FakePatches(raises=True))
        stats = engine_stats(eng)  # must not raise
        self.assertEqual(stats["active_mitigations"], 0)

    def test_arbitrary_object_accepted(self):
        stats = engine_stats(object())
        self.assertEqual(
            stats,
            {
                "enforce": False,
                "errors": 0,
                "active_mitigations": 0,
                "request_count": 0,
                "flagged_count": 0,
                "last_event_utc": "",
                "alerter_failures": 0,
                "alerter_last_error": "",
            },
        )

    def test_request_telemetry_is_surfaced(self):
        eng = _FakeEngine(patches=_FakePatches())
        eng.request_count = 12
        eng.flagged_count = 4
        eng.last_event_utc = "2026-02-02T03:04:05.000Z"
        stats = engine_stats(eng)
        self.assertEqual(stats["request_count"], 12)
        self.assertEqual(stats["flagged_count"], 4)
        self.assertEqual(stats["last_event_utc"], "2026-02-02T03:04:05.000Z")

    def test_alerter_health_is_surfaced(self):
        class _A:
            failure_count = 3
            last_error = "webhook down"

        eng = _FakeEngine(patches=_FakePatches())
        eng.alerter = _A()
        stats = engine_stats(eng)
        self.assertEqual(stats["alerter_failures"], 3)
        self.assertEqual(stats["alerter_last_error"], "webhook down")


if __name__ == "__main__":
    unittest.main()

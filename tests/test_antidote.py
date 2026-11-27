"""Unit tests for Artex Antidote / Root Justice.

Covers the 2:1 swarm, trustworthy origin attribution (no spoofable-IP blocking),
exact-path virtual patching, the evidence hash chain + review gate, the warning
banner, and federal reporting.
"""

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from artex_antidote import attribution as attribution_mod
from artex_antidote.attribution import attribute_origin, lookup_asn, lookup_rdap, reverse_engineer_request
from artex_antidote.evidence import EvidenceStore, EvidenceRecord, build_review_manifest, header_fingerprint
from artex_antidote.host_audit import check_local_ports
from artex_antidote.origin import TrustedProxies, resolve_origin, CONFIDENCE_SOCKET, CONFIDENCE_TRUSTED, CONFIDENCE_ASSERTED
from artex_antidote.reporter import (
    ReviewRequiredError,
    build_stix_bundle,
    export_federal_bundle,
    export_reviewed_federal_bundle,
    validate_stix_bundle,
)
from artex_antidote.server import build_warning_response, ShieldEngine
from artex_antidote.shield import ArtexShield, RequestEvent, VirtualPatchRegistry
from artex_antidote.swarm import DefenderSwarmCoordinator


def _event(**kw):
    base = dict(
        timestamp_utc="2026-11-26T20:00:00.000Z",
        remote_ip="198.51.100.25",
        forwarded_for=["198.51.100.25"],
        method="GET",
        path="/.env",
        user_agent="nuclei",
        headers={},
        body_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        body_size=0,
    )
    base.update(kw)
    return RequestEvent(**base)


class TestSwarmAndAttribution(unittest.TestCase):
    def test_2_to_1_swarm_blocks_socket_peer_not_spoofed_xff(self) -> None:
        patches = VirtualPatchRegistry()
        shield = ArtexShield(patches=patches)  # no trusted proxies
        swarm = DefenderSwarmCoordinator(patches=patches)

        event = _event(
            headers={"X-Forwarded-For": "203.0.113.45, 198.51.100.25"},
        )
        det = shield.inspect(event)
        self.assertTrue(det.flagged)
        self.assertEqual(det.severity, "critical")
        self.assertEqual(det.recommended_action, "tarpit")
        # Attribution is the unspoofable socket peer, not the attacker-supplied value.
        self.assertEqual(det.attributed_ip, "198.51.100.25")
        self.assertEqual(det.attributed_confidence, CONFIDENCE_SOCKET)

        asyncio.run(swarm.dispatch(event, det))
        self.assertEqual(swarm.swarm_ratio(), {"attacker_streams": 1, "defender_agents": 2, "ratio": 2})
        # The spoofed leftmost XFF must NOT be blocked.
        self.assertIsNone(patches.is_ip_blocked("203.0.113.45"))
        self.assertIsNotNone(patches.is_ip_blocked("198.51.100.25"))

    def test_trusted_proxy_attributes_real_client(self) -> None:
        trusted = TrustedProxies(["198.51.100.25"])
        shield = ArtexShield(patches=VirtualPatchRegistry(), trusted_proxies=trusted)
        event = _event(headers={"X-Forwarded-For": "203.0.113.45"})
        det = shield.inspect(event)
        # Behind a trusted proxy, the real client is attributed and reportable.
        self.assertEqual(det.attributed_ip, "203.0.113.45")
        self.assertTrue(det.is_reportable)

    def test_spoofed_xff_without_trusted_proxy_is_not_reportable_lead(self) -> None:
        res = resolve_origin("198.51.100.25", {"X-Forwarded-For": "203.0.113.45"}, TrustedProxies())
        self.assertEqual(res.attributed_ip, "198.51.100.25")
        self.assertTrue(res.is_reportable)  # socket peer is reportable
        # The spoofed value is present only as an asserted lead.
        asserted = [h for h in res.chain if h.confidence == CONFIDENCE_ASSERTED]
        self.assertTrue(any(h.ip == "203.0.113.45" for h in asserted))


class TestVirtualPatchScope(unittest.TestCase):
    def test_exact_path_patch_not_site_wide(self) -> None:
        patches = VirtualPatchRegistry()
        shield = ArtexShield(patches=patches)
        swarm = DefenderSwarmCoordinator(patches=patches)
        # A corroborated exploit probe (not a canary) -> backoff_429 -> exact-path patch.
        event = _event(path="/api/users?q=1 UNION SELECT 1,2", user_agent="ffuf", headers={})
        det = shield.inspect(event)
        self.assertTrue(det.flagged)
        self.assertEqual(det.recommended_action, "backoff_429")
        asyncio.run(swarm.dispatch(event, det))
        # Only the exact path (or its children) is patched; unrelated paths are clean.
        self.assertIsNotNone(patches.match_virtual_patch("/api/users"))
        self.assertIsNotNone(patches.match_virtual_patch("/api/users/1"))
        self.assertIsNone(patches.match_virtual_patch("/"))
        self.assertIsNone(patches.match_virtual_patch("/api"))
        self.assertIsNone(patches.match_virtual_patch("/billing"))

    def test_root_probe_contains_ip_without_wildcard_patch(self) -> None:
        patches = VirtualPatchRegistry()
        shield = ArtexShield(patches=patches)
        swarm = DefenderSwarmCoordinator(patches=patches)
        # Flagged probe to "/" must contain the IP, never install a site-wide patch.
        event = _event(path="/?x=../../etc/passwd", user_agent="ffuf")
        det = shield.inspect(event)
        self.assertTrue(det.flagged)
        asyncio.run(swarm.dispatch(event, det))
        self.assertIsNone(patches.match_virtual_patch("/anything"))
        self.assertIsNotNone(patches.is_ip_blocked(det.attributed_ip))


class TestFalsePositives(unittest.TestCase):
    """Legitimate automation must never be blocked on a weak/spoofable signal."""

    def test_benign_httpx_client_not_flagged(self) -> None:
        shield = ArtexShield(patches=VirtualPatchRegistry())
        det = shield.inspect(_event(path="/home", user_agent="python-httpx/0.27"))
        self.assertFalse(det.flagged)

    def test_benign_go_client_not_flagged(self) -> None:
        shield = ArtexShield(patches=VirtualPatchRegistry())
        det = shield.inspect(_event(path="/api/status", user_agent="Go-http-client/2.0"))
        self.assertFalse(det.flagged)

    def test_offensive_tool_ua_alone_does_not_block(self) -> None:
        # A tool UA to a benign path is a lead, not grounds to block legit traffic.
        shield = ArtexShield(patches=VirtualPatchRegistry())
        det = shield.inspect(_event(path="/home", user_agent="nuclei"))
        self.assertFalse(det.flagged)
        self.assertEqual(det.recommended_action, "allow")

    def test_tool_ua_plus_canary_still_blocks(self) -> None:
        shield = ArtexShield(patches=VirtualPatchRegistry())
        det = shield.inspect(_event(path="/.env", user_agent="nuclei"))
        self.assertTrue(det.flagged)
        self.assertEqual(det.severity, "critical")


class TestEvidenceLedger(unittest.TestCase):
    def _record(self, ip="203.0.113.45", reportable=True):
        return EvidenceRecord(
            timestamp_utc="2026-11-26T20:00:00.000Z",
            stream_id="artex-stream-abc",
            attributed_ip=ip,
            attributed_confidence=CONFIDENCE_TRUSTED if reportable else CONFIDENCE_ASSERTED,
            is_reportable=reportable,
            ip_chain=[{"ip": ip, "confidence": "trusted"}],
            method="GET",
            path="/.env",
            user_agent="nuclei",
            header_hash="deadbeef",
            body_sha256="abc",
            severity="critical",
            reasons=["canary_probe:/.env"],
        )

    def test_append_and_hash_chain_intact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore(str(Path(tmp) / "ledger.jsonl"))
            store.append(self._record())
            store.append(self._record(ip="203.0.113.99"))
            chain = store.verify_chain()
            self.assertTrue(chain["intact"])
            self.assertEqual(chain["verified_records"], 2)

    def test_tamper_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "ledger.jsonl"
            store = EvidenceStore(str(p))
            store.append(self._record())
            store.append(self._record(ip="203.0.113.99"))
            lines = p.read_text(encoding="utf-8").splitlines()
            first = json.loads(lines[0])
            first["record"]["attributed_ip"] = "8.8.8.8"  # tamper
            lines[0] = json.dumps(first)
            p.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertFalse(EvidenceStore(str(p)).verify_chain()["intact"])

    def test_review_manifest_holds_low_confidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore(str(Path(tmp) / "ledger.jsonl"))
            store.append(self._record(reportable=True))
            store.append(self._record(ip="10.0.0.9", reportable=False))
            manifest = build_review_manifest(store)
            self.assertEqual(manifest["total_records"], 2)
            self.assertEqual(manifest["reportable_records"], 1)
            self.assertEqual(manifest["held_for_low_confidence"], 1)


class TestReviewGate(unittest.TestCase):
    def test_bundle_requires_reviewer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ReviewRequiredError):
                export_reviewed_federal_bundle(tmp, [], reviewed_by="")

    def test_reviewed_bundle_excludes_non_reportable(self) -> None:
        records = [
            {"origin_ip": "203.0.113.45", "attributed_ip": "203.0.113.45", "is_reportable": True,
             "timestamp_utc": "t", "method": "GET", "path": "/.env", "user_agent": "nuclei",
             "body_sha256": "a", "reasons": ["canary"]},
            {"origin_ip": "10.0.0.9", "attributed_ip": "10.0.0.9", "is_reportable": False,
             "timestamp_utc": "t", "method": "GET", "path": "/.env", "user_agent": "nuclei",
             "body_sha256": "b", "reasons": ["canary"]},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            paths = export_reviewed_federal_bundle(tmp, records, reviewed_by="Operator One")
            self.assertEqual(paths["records_submitted"], 1)
            self.assertEqual(paths["records_held"], 1)
            stix = json.loads(Path(paths["stix_bundle"]).read_text(encoding="utf-8"))
            values = [o.get("value") for o in stix["objects"] if o.get("type") == "ipv4-addr"]
            self.assertIn("203.0.113.45", values)
            self.assertNotIn("10.0.0.9", values)
            att = json.loads(Path(paths["review_attestation"]).read_text(encoding="utf-8"))
            self.assertEqual(att["reviewed_by"], "Operator One")


class TestServerBannerAndEngine(unittest.TestCase):
    def test_warning_banner_is_neutral_by_default(self) -> None:
        shield = ArtexShield(patches=VirtualPatchRegistry())
        det = shield.inspect(_event(headers={}))
        banner = build_warning_response(det).decode("utf-8")
        # Neutral, factual notice: states what happened, attributes the origin,
        # and makes NO claim that a crime occurred or that a referral is underway.
        self.assertIn("detected and blocked", banner)
        self.assertIn("logged", banner)
        self.assertIn(det.attributed_ip, banner)
        self.assertNotIn("FBI IC3", banner)
        self.assertNotIn("18 U.S.C. 1030", banner)
        self.assertNotIn("federal crime", banner)

    def test_warning_banner_statute_notice_is_opt_in(self) -> None:
        shield = ArtexShield(patches=VirtualPatchRegistry())
        det = shield.inspect(_event(headers={}))
        banner = build_warning_response(det, statute_notice=True).decode("utf-8")
        # Opt-in reference is factual ("may violate"), not an accusation.
        self.assertIn("18 U.S.C. 1030", banner)
        self.assertIn("FBI IC3", banner)
        self.assertIn("may violate", banner)

    def test_engine_records_flagged_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = ShieldEngine(evidence_path=str(Path(tmp) / "ledger.jsonl"), enforce=True)
            det = engine.handle("203.0.113.45", "GET", "/.env", {"User-Agent": "nuclei"}, b"")
            self.assertTrue(det.flagged)
            recs = engine.store.records()
            self.assertEqual(len(recs), 1)
            self.assertEqual(recs[0]["attributed_ip"], "203.0.113.45")
            self.assertTrue(engine.store.verify_chain()["intact"])

    def test_engine_fails_open_on_shield_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = ShieldEngine(evidence_path=str(Path(tmp) / "ledger.jsonl"), enforce=True)

            def boom(*_a, **_k):
                raise RuntimeError("detector exploded")

            engine.shield.inspect = boom  # type: ignore[assignment]
            det = engine.handle("203.0.113.45", "GET", "/.env", {"User-Agent": "nuclei"}, b"")
            self.assertFalse(det.flagged)  # fail OPEN, do not deny traffic
            self.assertEqual(engine.errors, 1)


class TestAttribution(unittest.TestCase):
    def setUp(self) -> None:
        self._orig = attribution_mod._http_get_json

    def tearDown(self) -> None:
        attribution_mod._http_get_json = self._orig

    def test_rdap_parses_network_country_and_abuse(self) -> None:
        def fake(url, timeout=4.0):
            return {
                "name": "GOOGLE",
                "handle": "NET-8-8-8-0",
                "country": "US",
                "startAddress": "8.8.8.0",
                "endAddress": "8.8.8.255",
                "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": ["vcard", [["email", {}, "text", "abuse@google.com"]]],
                    }
                ],
            }

        attribution_mod._http_get_json = fake
        r = lookup_rdap("8.8.8.8")
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["name"], "GOOGLE")
        self.assertEqual(r["cidr"], "8.8.8.0/24")
        self.assertEqual(r["abuse_email"], "abuse@google.com")

    def test_asn_resolves_number_and_holder(self) -> None:
        def fake(url, timeout=4.0):
            if "network-info" in url:
                return {"data": {"asns": [15169], "prefix": "8.8.8.0/24"}}
            return {"data": {"holder": "GOOGLE, US"}}

        attribution_mod._http_get_json = fake
        a = lookup_asn("8.8.8.8")
        self.assertEqual(a["asn"], "AS15169")
        self.assertEqual(a["prefix"], "8.8.8.0/24")
        self.assertEqual(a["holder"], "GOOGLE, US")

    def test_attribute_origin_merges_rdap_and_asn(self) -> None:
        def fake(url, timeout=4.0):
            if "network-info" in url:
                return {"data": {"asns": [15169], "prefix": "8.8.8.0/24"}}
            if "as-overview" in url:
                return {"data": {"holder": "GOOGLE, US"}}
            return {"name": "GOOGLE", "country": "US", "entities": []}

        attribution_mod._http_get_json = fake
        m = attribute_origin("8.8.8.8")
        self.assertEqual(m["name"], "GOOGLE")
        self.assertEqual(m["asn"], "AS15169")
        self.assertEqual(m["asn_holder"], "GOOGLE, US")

    def test_private_ip_is_not_looked_up(self) -> None:
        self.assertEqual(lookup_rdap("10.0.0.1")["status"], "non_routable_or_local")
        self.assertEqual(lookup_asn("127.0.0.1")["status"], "non_routable_or_local")


class TestStixValidation(unittest.TestCase):
    def _records(self):
        return [{"attributed_ip": "203.0.113.45", "user_agent": "nuclei",
                 "timestamp_utc": "2026-11-26T20:00:00.000Z", "reasons": ["canary"]}]

    def test_generated_bundle_is_valid(self) -> None:
        bundle = build_stix_bundle(self._records(), "Test Incident")
        result = validate_stix_bundle(bundle)
        self.assertTrue(result["valid"], result["errors"])

    def test_bad_ip_and_id_are_caught(self) -> None:
        bundle = {
            "type": "bundle",
            "id": "bundle--not-a-uuid",
            "objects": [
                {"type": "ipv4-addr", "spec_version": "2.1", "id": "ipv4-addr--x", "value": "999.1.1.1"},
            ],
        }
        result = validate_stix_bundle(bundle)
        self.assertFalse(result["valid"])
        self.assertTrue(any("ipv4-addr.value" in e for e in result["errors"]))
        self.assertTrue(any("bundle.id" in e for e in result["errors"]))


class TestExistingBehavior(unittest.TestCase):
    def test_reverse_engineer_attack_synthesizes_coraza_and_python(self) -> None:
        re_atk = reverse_engineer_request("GET", "/login?id=1 UNION SELECT 1,2", "sqlmap/1.8")
        self.assertIn("sqli", re_atk.vectors)
        self.assertIn("automated_scanner", re_atk.vectors)
        self.assertIn("SecRule REQUEST_URI", re_atk.coraza_seclang_rule)
        self.assertIn("def guard_", re_atk.python_guard_snippet)

    def test_export_federal_bundle(self) -> None:
        records = [
            {
                "timestamp_utc": "2026-11-26T20:00:00.000Z",
                "origin_ip": "203.0.113.45",
                "method": "GET",
                "path": "/.env",
                "user_agent": "nuclei",
                "body_sha256": "abc123",
                "reasons": ["canary_probe:/.env"],
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            paths = export_federal_bundle(tmp, records, rdap_results={"203.0.113.45": {"name": "TEST-NET-3", "country": "US"}})
            stix = json.loads(Path(paths["stix_bundle"]).read_text(encoding="utf-8"))
            self.assertEqual(stix["type"], "bundle")
            self.assertEqual(len(stix["objects"]), 2)
            md = Path(paths["ic3_cisa_report"]).read_text(encoding="utf-8")
            self.assertIn("203.0.113.45", md)
            self.assertIn("FBI IC3", md)

    def test_host_audit_runs_cleanly(self) -> None:
        res = check_local_ports()
        self.assertEqual(len(res), 2)


if __name__ == "__main__":
    unittest.main()

"""Federal Authority Evidence & Incident Reporting (STIX 2.1 + FBI IC3 / CISA Summary)."""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import signing

_STIX_ID_RE = re.compile(r"^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def validate_stix_bundle(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Structurally validate a STIX 2.1 bundle (stdlib only).

    Checks bundle/object shape, id format, spec_version, and object-specific
    required fields. If the official ``stix2validator`` package is installed it
    is also run and its result merged. Returns {"valid": bool, "errors": [...]}.
    """
    errors: List[str] = []
    if bundle.get("type") != "bundle":
        errors.append("bundle.type must be 'bundle'")
    if not str(bundle.get("id", "")).startswith("bundle--") or not _STIX_ID_RE.match(bundle.get("id", "")):
        errors.append("bundle.id must be 'bundle--<uuid>'")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        errors.append("bundle.objects must be a list")
        objects = []

    for i, obj in enumerate(objects):
        where = f"objects[{i}]"
        otype = obj.get("type")
        if not otype:
            errors.append(f"{where}: missing type")
            continue
        if not _STIX_ID_RE.match(obj.get("id", "")):
            errors.append(f"{where} ({otype}): invalid id format")
        if obj.get("spec_version") != "2.1":
            errors.append(f"{where} ({otype}): spec_version must be '2.1'")
        if otype == "ipv4-addr":
            try:
                ipaddress.IPv4Address(obj.get("value", ""))
            except (ipaddress.AddressValueError, ValueError):
                errors.append(f"{where}: ipv4-addr.value is not a valid IPv4 address")
        elif otype == "indicator":
            for req in ("pattern", "pattern_type", "valid_from", "created", "modified"):
                if not obj.get(req):
                    errors.append(f"{where} (indicator): missing '{req}'")
            if obj.get("pattern_type") not in (None, "stix"):
                errors.append(f"{where} (indicator): unsupported pattern_type")
            if not isinstance(obj.get("labels", []), list):
                errors.append(f"{where} (indicator): labels must be a list")

    result: Dict[str, Any] = {"valid": not errors, "errors": errors, "validator": "structural"}

    try:  # Optional: official validator for authoritative conformance.
        from stix2validator import validate_instance  # type: ignore

        official = validate_instance(json.dumps(bundle))
        result["validator"] = "structural+stix2validator"
        result["official_valid"] = bool(official.is_valid)
        if not official.is_valid:
            result["valid"] = False
            result["errors"] = errors + [str(e) for e in getattr(official, "errors", [])]
    except Exception:
        result["official_valid"] = None  # package not installed or validation skipped
    return result


def build_stix_bundle(evidence_records: List[Dict[str, Any]], incident_title: str) -> Dict[str, Any]:
    """Compile observed attacker IPs and indicators into a valid STIX 2.1 JSON Bundle."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects: List[Dict[str, Any]] = []
    seen_ips: set[str] = set()

    for rec in evidence_records:
        ip = rec.get("attributed_ip") or rec.get("origin_ip", "")
        if not ip or ip in seen_ips:
            continue
        seen_ips.add(ip)

        ip_obj_id = f"ipv4-addr--{uuid.uuid5(uuid.NAMESPACE_DNS, ip)}"
        ind_obj_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, f'{incident_title}:{ip}')}"

        objects.append(
            {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": ip_obj_id,
                "value": ip,
            }
        )
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_obj_id,
                "created": now_iso,
                "modified": now_iso,
                "name": f"{incident_title} - Source {ip}",
                "description": (
                    f"Automated scanning/probing observed from {ip} "
                    f"(UA: {rec.get('user_agent', 'unknown')}, reasons: {rec.get('reasons', [])})."
                ),
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": rec.get("timestamp_utc") or now_iso,
                "labels": ["malicious-activity", "automated-scanning"],
            }
        )

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def build_ic3_cisa_markdown(
    evidence_records: List[Dict[str, Any]],
    incident_title: str,
    rdap_results: Optional[Dict[str, Dict[str, Any]]] = None,
) -> str:
    """Generate a structured FBI IC3 / CISA-ready incident report in Markdown."""
    rdap_results = rdap_results or {}

    def _ip(r: Dict[str, Any]) -> str:
        return r.get("attributed_ip") or r.get("origin_ip", "")

    unique_ips = sorted({_ip(r) for r in evidence_records if _ip(r)})
    now_iso = datetime.now(timezone.utc).isoformat()

    lines = [
        f"# Cyber Incident Evidence Package: {incident_title}",
        f"- **Generated (UTC):** {now_iso}",
        f"- **Total Flagged Events:** {len(evidence_records)}",
        f"- **Unique Origin IPs:** {len(unique_ips)}",
        "- **Submission Channels:** FBI IC3 (`https://www.ic3.gov`) | CISA (`https://www.cisa.gov/report`)",
        "",
        "## Attacker Origin IP Summary",
        "| Origin IP | RDAP / Network | ASN (Holder) | Country | Abuse Contact | Observed Events |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for ip in unique_ips:
        rdap = rdap_results.get(ip, {})
        net = rdap.get("name") or rdap.get("network") or rdap.get("status", "pending")
        asn = rdap.get("asn") or "N/A"
        holder = rdap.get("asn_holder")
        asn_cell = f"{asn} ({holder})" if holder else asn
        country = rdap.get("country") or "N/A"
        abuse = rdap.get("abuse_email") or "N/A"
        count = sum(1 for r in evidence_records if _ip(r) == ip)
        lines.append(f"| `{ip}` | {net} | {asn_cell} | {country} | {abuse} | {count} |")

    lines.extend(["", "## Chain-of-Custody Event Log (Latest 50)"])
    for rec in evidence_records[:50]:
        lines.append(
            f"- **{rec.get('timestamp_utc')}** | `{_ip(rec)}` | "
            f"`{rec.get('method')} {rec.get('path')}` | UA: `{rec.get('user_agent')}` | "
            f"SHA-256: `{rec.get('body_sha256')}` | Reasons: `{rec.get('reasons')}`"
        )
    return "\n".join(lines) + "\n"


def export_federal_bundle(
    output_dir: str,
    evidence_records: List[Dict[str, Any]],
    incident_title: str = "Artex Autonomous Scan Incident",
    rdap_results: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, str]:
    """Write STIX 2.1 JSON and IC3/CISA Markdown report to output_dir."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    stix_path = out / "stix_bundle.json"
    report_path = out / "ic3_cisa_report.md"
    validation_path = out / "stix_validation.json"

    bundle = build_stix_bundle(evidence_records, incident_title)
    validation = validate_stix_bundle(bundle)
    stix_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    report_path.write_text(build_ic3_cisa_markdown(evidence_records, incident_title, rdap_results), encoding="utf-8")
    validation_path.write_text(json.dumps(validation, indent=2), encoding="utf-8")

    return {
        "stix_bundle": str(stix_path),
        "ic3_cisa_report": str(report_path),
        "stix_validation": str(validation_path),
        "stix_valid": validation["valid"],
    }


class ReviewRequiredError(RuntimeError):
    """Raised when a federal bundle is requested without explicit human sign-off."""


def sign_bundle(
    bundle_path: str,
    key_path: str,
    *,
    timestamp: Optional[str] = None,
    sig_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Drop a detached ``*.sig.json`` signature sidecar next to a bundle file.

    Thin wrapper over :func:`signing.sign_file`. ``timestamp`` is the caller's
    authoritative signing time (ISO-8601 UTC); when omitted the signing module
    records the current UTC time. Returns the signature dict that was written.
    Use this to seal a ``stix_bundle.json`` (or any reporter artifact) so a later
    reviewer can detect tampering at rest with :func:`verify_bundle`.
    """
    return signing.sign_file(bundle_path, key_path, timestamp=timestamp, sig_path=sig_path)


def verify_bundle(bundle_path: str, key_path: str, *, sig_path: Optional[str] = None) -> bool:
    """Verify a bundle file against its detached signature. Never raises.

    Returns ``True`` only when the file bytes, embedded timestamp/header, and
    HMAC all match under ``key_path``. ``sig_path`` defaults to
    ``bundle_path + '.sig.json'`` (the layout :func:`sign_bundle` writes). Gate
    any federal submission or human review on this returning ``True``.
    """
    resolved_sig = sig_path or (bundle_path + signing.SIG_SUFFIX)
    return signing.verify_file(bundle_path, resolved_sig, key_path)


def export_reviewed_federal_bundle(
    output_dir: str,
    evidence_records: List[Dict[str, Any]],
    reviewed_by: str,
    incident_title: str = "Artex Autonomous Scan Incident",
    rdap_results: Optional[Dict[str, Dict[str, Any]]] = None,
    *,
    sign_key_path: Optional[str] = None,
    sign_timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Write a federal bundle ONLY after a human reviewer signs off.

    - Requires a non-empty ``reviewed_by`` (the person accountable for submission).
    - Includes only records whose attribution is reportable (not spoofable-only).
    - Never transmits anything; it prepares files for a human to submit.
    - When ``sign_key_path`` is given, the written ``stix_bundle.json`` is sealed
      with a detached HMAC-SHA256 signature (``signing.sign_file``) and the
      sidecar path is returned under ``"stix_bundle_signature"``. ``sign_timestamp``
      (ISO-8601 UTC) lets the caller record an authoritative signing moment.
      Signing is off by default, so existing callers are unaffected.
    """
    if not reviewed_by or not reviewed_by.strip():
        raise ReviewRequiredError(
            "Federal evidence bundles require an explicit human reviewer. "
            "Re-run with the reviewer's name; low-confidence (spoofable) origins "
            "are excluded automatically but a human must still confirm submission."
        )

    reportable = [r for r in evidence_records if r.get("is_reportable")]
    held = [r for r in evidence_records if not r.get("is_reportable")]

    paths = export_federal_bundle(output_dir, reportable, incident_title, rdap_results)

    if sign_key_path:
        sidecar = sign_bundle(paths["stix_bundle"], sign_key_path, timestamp=sign_timestamp)
        paths["stix_bundle_signature"] = paths["stix_bundle"] + signing.SIG_SUFFIX
        paths["stix_bundle_signed_sha256"] = sidecar["file_sha256"]

    attestation = {
        "incident_title": incident_title,
        "reviewed_by": reviewed_by.strip(),
        "reviewed_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "records_submitted": len(reportable),
        "records_held_low_confidence": len(held),
        "held_ips": sorted({r.get("attributed_ip", "") for r in held if r.get("attributed_ip")}),
        "statement": (
            "I have reviewed these records and authorize their preparation for "
            "referral to FBI IC3 / CISA. Held low-confidence records were excluded."
        ),
    }
    att_path = Path(output_dir) / "review_attestation.json"
    att_path.write_text(json.dumps(attestation, indent=2), encoding="utf-8")
    paths["review_attestation"] = str(att_path)
    paths["records_submitted"] = len(reportable)
    paths["records_held"] = len(held)
    return paths

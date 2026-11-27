"""CLI entrypoint for Artex Antidote."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from hashlib import sha256
from http.server import ThreadingHTTPServer
from pathlib import Path

from . import __version__
from . import coverage, credpolicy, domainwatch, firmware_audit, hardening, posture, signing, tlsconf
from .allowlist import Allowlist
from .attribution import attribute_origin, lookup_rdap, reverse_engineer_request, run_rea_static_analysis
from .dashboard import Alerter, build_stats, render_dashboard
from .evidence import EvidenceStore, build_review_manifest
from .health import health_payload
from .host_audit import check_local_ports
from .intel import ThreatIntel
from .origin import TrustedProxies
from .reporter import (
    ReviewRequiredError,
    build_stix_bundle,
    export_reviewed_federal_bundle,
    validate_stix_bundle,
    verify_bundle,
)
from .server import ShieldEngine, export_crowdsec_decisions, make_handler, serve
from .shield import ArtexShield, RequestEvent, VirtualPatchRegistry
from .swarm import DefenderSwarmCoordinator
from .taxii import Taxii21Client


def _build_intel(sources: list[str]) -> ThreatIntel:
    """Construct and eagerly refresh a :class:`ThreatIntel` from CLI ``--intel`` values.

    Each value is a local file path or an ``http(s)`` URL (URLs are detected by
    scheme). Refresh failures are recorded on ``intel.last_errors`` rather than
    raised, so a dead feed never stops the shield from starting.
    """
    specs = []
    for i, src in enumerate(sources):
        if src.startswith("http://") or src.startswith("https://"):
            specs.append({"name": f"intel-{i}", "url": src})
        else:
            specs.append({"name": f"intel-{i}", "path": src})
    intel = ThreatIntel(specs)
    intel.refresh()
    return intel


def _build_allowlist(values: list[str]) -> Allowlist:
    """Build an :class:`Allowlist` from ``--allowlist`` values.

    Each value is either a path to an allowlist file (loaded line by line) or a
    single IP/CIDR entry. Existing files are treated as files; everything else is
    treated as a literal entry.
    """
    allow = Allowlist()
    for value in values:
        if Path(value).is_file():
            allow.load_from_file(value)
        else:
            allow.add(value)
    return allow


def _run_serve(args: argparse.Namespace) -> None:
    """Build the shield engine from serve args (incl. decoy/tarpit) and serve.

    This mirrors :func:`server.serve` but additionally threads the
    ``--no-decoy`` / ``--no-tarpit`` switches into the engine (those are
    engine-level, keyword-only controls not exposed on ``serve``'s own
    signature). HTTPS termination reuses :mod:`tlsconf`.
    """
    allow = _build_allowlist(args.allowlist) if args.allowlist else None
    intel = _build_intel(args.intel) if args.intel else None
    alerter = Alerter(args.webhook) if args.webhook else None

    engine = ShieldEngine(
        evidence_path=args.evidence,
        enforce=args.enforce,
        trusted_proxies=TrustedProxies(args.trusted_proxy),
        allowlist=allow,
        db_path=args.db or None,
        intel=intel,
        upstream=args.upstream or None,
        alerter=alerter,
        decoy_enabled=not args.no_decoy,
        tarpit_enabled=not args.no_tarpit,
    )
    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(engine))

    scheme = "http"
    if args.tls_cert and args.tls_key:
        context = tlsconf.build_ssl_context(args.tls_cert, args.tls_key)
        tlsconf.wrap_server_socket(httpd, context)
        scheme = "https"

    mode = "ENFORCE" if args.enforce else "LOG-ONLY"
    print(
        f"[root-justice] shield listening on {scheme}://{args.host}:{args.port} ({mode}); "
        f"evidence -> {args.evidence}"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[root-justice] shutting down")
    finally:
        httpd.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(prog="root-justice", description="2:1 Defender Swarm & Attribution CLI")
    parser.add_argument("--version", action="version", version=f"root-justice {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    rev = sub.add_parser("reverse-patch", help="Reverse-engineer a probe and synthesize Coraza + Python patches")
    rev.add_argument("--ip", required=True)
    rev.add_argument("--method", default="GET")
    rev.add_argument("--path", required=True)
    rev.add_argument("--ua", default="nuclei")
    rev.add_argument("--body", default="")
    rev.add_argument("--export-dir", default="",
                     help="Directory for a reviewer-gated federal bundle; requires --reviewed-by")
    rev.add_argument("--reviewed-by", default="",
                     help="Reviewer name; REQUIRED to write a federal bundle with --export-dir")

    rea = sub.add_parser("rea-analyze", help="Run REA static analysis on a captured artifact")
    rea.add_argument("target", help="Path to captured JS/ASAR/artifact")

    sub.add_parser("audit-host", help="Check local host for default Artex listeners (:8787, :8788)")

    srv = sub.add_parser("serve", help="Run the edge shield server (log-only unless --enforce)")
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8080)
    srv.add_argument("--evidence", default="./evidence_out/evidence_ledger.jsonl")
    srv.add_argument("--enforce", action="store_true", help="Actually block/tarpit and serve the warning banner")
    srv.add_argument("--trusted-proxy", action="append", default=[], help="Trusted proxy IP/CIDR (repeatable)")
    srv.add_argument("--allowlist", action="append", default=[],
                     help="Allowlist file path, or a single IP/CIDR entry (repeatable)")
    srv.add_argument("--db", default="", help="SQLite path for durable block/patch persistence")
    srv.add_argument("--intel", action="append", default=[],
                     help="Threat-intel feed: local path or http(s) URL (repeatable)")
    srv.add_argument("--upstream", default="", help="Upstream base_url to reverse-proxy clean traffic to")
    srv.add_argument("--webhook", default="", help="Alerter webhook URL for high/critical events")
    srv.add_argument("--tls-cert", default="", help="PEM certificate for HTTPS termination")
    srv.add_argument("--tls-key", default="", help="PEM private key for HTTPS termination")
    srv.add_argument("--no-decoy", action="store_true", help="Disable decoy responses (on by default in enforce mode)")
    srv.add_argument("--no-tarpit", action="store_true", help="Disable tarpit slow-drip (on by default in enforce mode)")

    rep = sub.add_parser("export-report", help="Prepare an FBI IC3 / CISA bundle from the evidence ledger")
    rep.add_argument("--evidence", default="./evidence_out/evidence_ledger.jsonl")
    rep.add_argument("--export-dir", default="./evidence_out")
    rep.add_argument("--reviewed-by", default="", help="Reviewer name; REQUIRED to write a submission bundle")
    rep.add_argument("--title", default="Artex Autonomous Scan Incident")
    rep.add_argument("--enrich", action="store_true", help="Look up RDAP + ASN for reportable IPs (network)")
    rep.add_argument("--sign-key", default="", help="Key file (signing.generate_key) to seal the STIX bundle")
    rep.add_argument("--sign-timestamp", default="", help="ISO-8601 UTC signing time (default: now)")

    ver = sub.add_parser("verify-evidence", help="Verify the evidence ledger hash chain is intact")
    ver.add_argument("--evidence", default="./evidence_out/evidence_ledger.jsonl")

    att = sub.add_parser("attribute", help="RDAP + ASN attribution for an IP")
    att.add_argument("--ip", required=True)

    val = sub.add_parser("validate-stix", help="Validate a STIX 2.1 bundle file")
    val.add_argument("path", help="Path to stix_bundle.json")

    sgn = sub.add_parser("sign-bundle", help="Write a detached HMAC signature sidecar for a file")
    sgn.add_argument("path", help="File to sign (e.g. stix_bundle.json or the evidence ledger)")
    sgn.add_argument("--key", required=True, help="Key file created with signing.generate_key")
    sgn.add_argument("--timestamp", default="", help="ISO-8601 UTC signing time (default: now)")
    sgn.add_argument("--sig", default="", help="Sidecar output path (default: <path>.sig.json)")
    sgn.add_argument("--generate-key", action="store_true", help="Create --key first if it does not exist")

    vfy = sub.add_parser("verify-bundle", help="Verify a file against its detached signature")
    vfy.add_argument("path", help="File to verify")
    vfy.add_argument("--key", required=True, help="Key file used to sign it")
    vfy.add_argument("--sig", default="", help="Sidecar path (default: <path>.sig.json)")

    dsh = sub.add_parser("dashboard", help="Render the operator dashboard HTML from the evidence ledger")
    dsh.add_argument("--evidence", default="./evidence_out/evidence_ledger.jsonl")
    dsh.add_argument("--out", default="./evidence_out/dashboard.html", help="Where to write the HTML")
    dsh.add_argument("--posture-label-enforce", action="store_true", dest="enforce",
                     help="Render the posture label as ENFORCE (cosmetic; this subcommand never enforces)")
    # Backward-compatible alias; hidden so it is not confused with serve's real --enforce switch.
    dsh.add_argument("--enforce", action="store_true", dest="enforce", help=argparse.SUPPRESS)
    dsh.add_argument("--host", default="127.0.0.1", help="Host shown in the live /dashboard URL")
    dsh.add_argument("--port", type=int, default=8080, help="Port shown in the live /dashboard URL")

    hlt = sub.add_parser("health", help="Print the liveness/health payload")
    hlt.add_argument("--posture-label-enforce", action="store_true", dest="enforce",
                     help="Report the posture label as enforce (cosmetic; this subcommand never enforces)")
    # Backward-compatible alias; hidden so it is not confused with serve's real --enforce switch.
    hlt.add_argument("--enforce", action="store_true", dest="enforce", help=argparse.SUPPRESS)

    irf = sub.add_parser("intel-refresh", help="Load threat-intel feeds and report the result")
    irf.add_argument("--intel", action="append", default=[],
                     help="Threat-intel feed: local path or http(s) URL (repeatable)")

    txp = sub.add_parser("taxii-push", help="Publish reportable indicators to a TAXII 2.1 collection (network)")
    txp.add_argument("--evidence", default="./evidence_out/evidence_ledger.jsonl")
    txp.add_argument("--api-root", required=True, help="TAXII 2.1 API root URL")
    txp.add_argument("--collection", required=True, help="Writable collection id")
    txp.add_argument("--token", default="", help="Bearer token (omit for unauthenticated servers)")
    txp.add_argument("--title", default="Artex Autonomous Scan Incident")
    txp.add_argument("--discover", action="store_true", help="List collections instead of pushing")

    # --- Defensive audit commands (operator-owned assets only) -------------- #
    fwa = sub.add_parser("firmware-audit",
                         help="Scan an operator-owned firmware image/binary for leaked secrets (offline)")
    fwa.add_argument("path", help="Path to the firmware image or binary to scan (never executed)")
    fwa.add_argument("--deep", action="store_true",
                     help="Also merge REA static forensics (deep_scan); default is an offline regex/entropy scan")

    dwt = sub.add_parser("domain-watch",
                         help="Enumerate lookalike/homoglyph domains of a brand you own and flag registered ones")
    dwt.add_argument("domain", help="The operator's own domain to monitor (e.g. example.com)")

    cps = sub.add_parser("cloud-posture",
                         help="Audit operator-owned S3/GCS/Azure storage URLs for public exposure")
    cps.add_argument("--bucket", action="append", default=[], required=True,
                     help="Operator-owned storage URL to probe (repeatable)")

    cpp = sub.add_parser("check-password-policy",
                         help="Classify stored password hashes and report credential posture (offline)")
    cpp.add_argument("--hash", action="append", default=[], dest="hashes",
                     help="A stored hash to classify (repeatable)")
    cpp.add_argument("--hash-file", default="",
                     help="File of stored hashes, one per line (combined with any --hash values)")

    hgd = sub.add_parser("harden-guide",
                         help="Print endpoint/Wi-Fi hardening baselines (advisory; no live enforcement)")
    hgd.add_argument("--endpoint", action="store_true", help="Include the endpoint baseline (default: both)")
    hgd.add_argument("--wifi", action="store_true", help="Include the Wi-Fi baseline (default: both)")
    hgd.add_argument("--markdown", action="store_true", help="Render Markdown instead of JSON")
    hgd.add_argument("--quickcheck", action="store_true",
                     help="Emit a safe, read-only local host report (local_quickcheck) instead of the baselines")

    cov = sub.add_parser("coverage",
                         help="Print the defensive control matrix (AI-hacking-tool classes)")
    cov.add_argument("--markdown", action="store_true", help="Render Markdown instead of JSON")

    args = parser.parse_args()

    try:
        _dispatch(args)
    except (FileNotFoundError, PermissionError, json.JSONDecodeError) as exc:
        # Surface common I/O / parse failures as a concise message rather than a
        # raw traceback, and exit non-zero so callers/scripts can detect failure.
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)


def _dispatch(args: argparse.Namespace) -> None:
    """Route a parsed ``args`` namespace to the matching subcommand handler."""
    if args.cmd == "audit-host":
        print(json.dumps(check_local_ports(), indent=2))
        return

    if args.cmd == "firmware-audit":
        if args.deep:
            result = firmware_audit.deep_scan(args.path)
        else:
            result = firmware_audit.scan_file(args.path)
        print(json.dumps(result, indent=2))
        return

    if args.cmd == "domain-watch":
        # Uses the real DNS resolver by default (domainwatch._resolve seam).
        print(json.dumps(domainwatch.scan(args.domain), indent=2))
        return

    if args.cmd == "cloud-posture":
        results = posture.audit(args.bucket)
        print(json.dumps({
            "results": results,
            "summary": posture.summarize(results),
            "checklist": posture.posture_checklist() if posture.summarize(results)["public"] else [],
        }, indent=2))
        return

    if args.cmd == "check-password-policy":
        hashes = list(args.hashes)
        if args.hash_file:
            for line in Path(args.hash_file).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    hashes.append(line)
        print(json.dumps(credpolicy.password_policy_report(hashes), indent=2))
        return

    if args.cmd == "harden-guide":
        if args.quickcheck:
            print(json.dumps(hardening.local_quickcheck(), indent=2))
            return
        # Default to both baselines unless the operator narrows the selection.
        want_endpoint = args.endpoint or not (args.endpoint or args.wifi)
        want_wifi = args.wifi or not (args.endpoint or args.wifi)
        baselines = {}
        if want_endpoint:
            baselines["endpoint"] = hardening.endpoint_baseline()
        if want_wifi:
            baselines["wifi"] = hardening.wifi_baseline()
        if args.markdown:
            print(hardening.render_markdown(baselines))
        else:
            print(json.dumps(baselines, indent=2))
        return

    if args.cmd == "coverage":
        if args.markdown:
            print(coverage.render_markdown())
        else:
            print(json.dumps({
                "matrix": coverage.coverage_matrix(),
                "summary": coverage.summary(),
            }, indent=2))
        return

    if args.cmd == "serve":
        _run_serve(args)
        return

    if args.cmd == "health":
        print(json.dumps(health_payload({"enforce": args.enforce}), indent=2))
        return

    if args.cmd == "intel-refresh":
        intel = _build_intel(args.intel)
        print(json.dumps({
            "sources": [s.name for s in intel.sources],
            "entry_count": intel.entry_count,
            "errors": intel.last_errors,
        }, indent=2))
        return

    if args.cmd == "dashboard":
        store = EvidenceStore(args.evidence)
        html = render_dashboard(build_stats(store, None, enforce=args.enforce))
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(html, encoding="utf-8")
        print(json.dumps({
            "dashboard_file": str(out.resolve()),
            "live_url": f"http://{args.host}:{args.port}/dashboard",
            "records": len(store.records()),
        }, indent=2))
        return

    if args.cmd == "sign-bundle":
        if args.generate_key and not Path(args.key).exists():
            signing.generate_key(args.key)
        sidecar = signing.sign_file(
            args.path, args.key,
            timestamp=args.timestamp or None,
            sig_path=args.sig or None,
        )
        print(json.dumps(sidecar, indent=2))
        return

    if args.cmd == "verify-bundle":
        valid = verify_bundle(args.path, args.key, sig_path=args.sig or None)
        print(json.dumps({"valid": valid, "path": args.path}, indent=2))
        return

    if args.cmd == "taxii-push":
        store = EvidenceStore(args.evidence)
        client = Taxii21Client(args.api_root, args.token)
        if args.discover:
            print(json.dumps({"collections": client.discover_collections()}, indent=2))
            return
        records = store.reportable_records()
        bundle = build_stix_bundle(records, args.title)
        response = client.push_objects(args.collection, bundle)
        print(json.dumps({
            "pushed_objects": len(bundle["objects"]),
            "reportable_records": len(records),
            "response": response,
        }, indent=2))
        return

    if args.cmd == "verify-evidence":
        store = EvidenceStore(args.evidence)
        print(json.dumps(store.verify_chain(), indent=2))
        return

    if args.cmd == "attribute":
        print(json.dumps(attribute_origin(args.ip), indent=2))
        return

    if args.cmd == "validate-stix":
        bundle = json.loads(Path(args.path).read_text(encoding="utf-8"))
        print(json.dumps(validate_stix_bundle(bundle), indent=2))
        return

    if args.cmd == "export-report":
        store = EvidenceStore(args.evidence)
        records = store.records()
        manifest = build_review_manifest(store)
        if not args.reviewed_by.strip():
            manifest["action"] = "review_required_no_bundle_written"
            print(json.dumps(manifest, indent=2))
            return
        rdap_results = None
        if args.enrich:
            reportable_ips = {r.get("attributed_ip") for r in records if r.get("is_reportable") and r.get("attributed_ip")}
            rdap_results = {ip: attribute_origin(ip) for ip in reportable_ips}
        try:
            paths = export_reviewed_federal_bundle(
                args.export_dir, records, reviewed_by=args.reviewed_by,
                incident_title=args.title, rdap_results=rdap_results,
                sign_key_path=args.sign_key or None,
                sign_timestamp=args.sign_timestamp or None,
            )
        except ReviewRequiredError as exc:
            print(json.dumps({"status": "review_required", "error": str(exc)}, indent=2))
            return
        print(json.dumps({"status": "bundle_written", **manifest, "paths": paths}, indent=2))
        return

    if args.cmd == "rea-analyze":
        print(json.dumps(run_rea_static_analysis(args.target), indent=2))
        return

    if args.cmd == "reverse-patch":
        patches = VirtualPatchRegistry()
        shield = ArtexShield(patches=patches)
        swarm = DefenderSwarmCoordinator(patches=patches)
        event = RequestEvent(
            timestamp_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            remote_ip=args.ip,
            forwarded_for=[args.ip],
            method=args.method,
            path=args.path,
            user_agent=args.ua,
            headers={"User-Agent": args.ua},
            body_sha256=sha256(args.body.encode("utf-8")).hexdigest(),
            body_size=len(args.body.encode("utf-8")),
        )
        det = shield.inspect(event, body_preview=args.body)
        pair = asyncio.run(swarm.dispatch(event, det))
        re_attack = reverse_engineer_request(args.method, args.path, args.ua, args.body)
        rdap = lookup_rdap(args.ip)

        out = {
            "detection": det.__dict__,
            "swarm_ratio": swarm.swarm_ratio(),
            "reverse_engineered": re_attack.__dict__,
            "rdap": rdap,
        }
        if args.export_dir:
            # Writing a federal-named bundle must go through the human-review
            # gate: require --reviewed-by and route through the reviewer-gated,
            # reportable-only exporter (never the raw export_federal_bundle).
            if not args.reviewed_by.strip():
                print(
                    "error: --export-dir requires --reviewed-by; refusing to write a "
                    "federal bundle without a named human reviewer",
                    file=sys.stderr,
                )
                raise SystemExit(2)
            records = pair.evidence_records if pair is not None else []
            try:
                out["exported_files"] = export_reviewed_federal_bundle(
                    args.export_dir,
                    records,
                    reviewed_by=args.reviewed_by,
                    rdap_results={args.ip: rdap},
                )
            except ReviewRequiredError as exc:
                print(f"error: {exc}", file=sys.stderr)
                raise SystemExit(2)
        print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()

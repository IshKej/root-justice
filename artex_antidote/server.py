"""Edge shield HTTP server: inspect, record, and serve the legal warning banner.

This is the Python reference of the design's `internal/shield` edge proxy. It
binds a socket, so the TCP peer is ground truth for attribution. For every
request it runs detection, dispatches the 2:1 swarm, and appends a
chain-of-custody record. The warning banner is returned *in the response to the
attacker's own request* — never by reaching out to their address — so it cannot
be spoofed onto an innocent third party and stays on the right side of the law.

Safety: virtual patching / blocking is log-only unless `enforce=True`
(design §4.4). In log-only mode every request still gets a normal response and
nothing is denied; the event is recorded for review.

Integrated request-path features (all optional, backward-compatible defaults):

* **allowlist** — trusted IPs/CIDRs short-circuit to a non-flagged "allowed"
  result before any detection, scoring, or reporting runs.
* **persistence** — pass ``db_path`` to back the block/patch registry with
  SQLite so containment decisions survive a restart (default: in-memory).
* **intel** — an optional :class:`ThreatIntel` feed; a known-bad source IP is
  blocked (with a reason) before scoring.
* **proxy** — when ``upstream`` is set, CLEAN (non-flagged, non-enforced)
  traffic is reverse-proxied to the real origin instead of the local sink.
* **tarpit** — in enforce mode a ``tarpit`` action slow-drips the banner on our
  own socket to waste an attacker's connection budget (bounded).
* **decoy** — in enforce mode a flagged canary/decoy path is answered with
  synthetic honeypot loot instead of the banner.
* **fingerprint** — an order-preserving HTTP header fingerprint is attached to
  every detection for clustering/correlation.
* **health** — ``GET /healthz`` and ``GET /readyz`` are infra probes, never
  treated as attacks.
* **dashboard** — ``GET /dashboard`` renders a localhost operator view; an
  optional :class:`Alerter` fires on high/critical flagged streams.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import signal
import ssl
import threading
from datetime import datetime, timezone
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import tarpit as tarpit_mod
from . import tlsconf
from .attribution import reverse_engineer_request
from .dashboard import Alerter, build_stats, render_dashboard
from .decoy import decoy_headers, decoy_response, is_decoy_path
from .evidence import EvidenceRecord, EvidenceStore, header_fingerprint
from .fingerprint import client_header_fingerprint
from .health import engine_stats, health_payload, readiness
from .intel import ThreatIntel
from .origin import TrustedProxies
from .persistence import DurableRegistry
from .proxy import ProxyResult, UpstreamProxy
from .shield import ArtexShield, DetectionResult, RequestEvent, VirtualPatchRegistry
from .swarm import DefenderSwarmCoordinator

MAX_BODY_BYTES = 256 * 1024

# Infrastructure probe routes that MUST never be scored as attacks.
HEALTH_PATH = "/healthz"
READY_PATH = "/readyz"
DASHBOARD_PATH = "/dashboard"

# Neutral, factual notice served back on the flagged request's own connection.
# It states only what happened (activity blocked, request + origin logged) and
# makes no assertion that a crime was committed or that any referral is underway.
WARNING_BANNER = (
    "Automated or unauthorized activity was detected and blocked; this request "
    "and its network origin have been logged.\n"
)

# Optional, opt-in statute reference. OFF by default. When an operator enables
# it (``ShieldEngine(statute_notice=True)``) this factual pointer to the
# relevant law and reporting channels is appended. It is phrased as general
# information, not as a claim that this specific request was criminal or that a
# referral has been initiated.
STATUTE_NOTICE = (
    "\n"
    "Notice: Unauthorized access to protected computer systems may violate the "
    "U.S. Computer Fraud and Abuse Act (18 U.S.C. 1030) and comparable laws. "
    "Suspected incidents can be reported to the FBI IC3 (https://www.ic3.gov) "
    "and CISA (https://www.cisa.gov/report).\n"
)


def build_warning_response(
    detection: DetectionResult, *, statute_notice: bool = False
) -> bytes:
    """The neutral security notice served back on the flagged request's connection.

    ``statute_notice`` is opt-in (default ``False``). When ``True`` an additional
    factual pointer to 18 U.S.C. 1030 and the FBI IC3 / CISA reporting channels
    is appended; it is never emitted by default so the shield makes no legal
    assertion unless an operator explicitly turns it on.
    """
    header = f"Incident-Stream: {detection.stream_id}\n"
    header += f"Attributed-Origin: {detection.attributed_ip} ({detection.attributed_confidence})\n"
    header += f"Classification: {detection.severity} [{', '.join(detection.reasons)}]\n\n"
    body = header + WARNING_BANNER
    if statute_notice:
        body += STATUTE_NOTICE
    return body.encode("utf-8")


class ShieldEngine:
    """Stateful detection + swarm + evidence pipeline shared across requests.

    All feature parameters are optional and default to the historical behaviour,
    so ``ShieldEngine(evidence_path=..., enforce=...)`` is unchanged.

    Parameters
    ----------
    evidence_path, enforce, trusted_proxies:
        As before — the evidence ledger location, enforce vs. log-only, and the
        proxies whose ``X-Forwarded-For`` we are willing to believe.
    allowlist:
        Optional :class:`allowlist.Allowlist`. An attributed IP it matches
        short-circuits to a non-flagged "allowed" result (no detection, no
        scoring, no evidence, no alert).
    db_path:
        Optional SQLite path. When set, the block/patch registry is a
        :class:`persistence.DurableRegistry` (survives restarts) instead of the
        in-memory :class:`VirtualPatchRegistry`.
    intel:
        Optional :class:`intel.ThreatIntel`. A source IP it reports as known-bad
        is blocked (with a reason) before scoring, so it is flagged this request.
    upstream:
        Optional upstream base URL (e.g. ``"http://127.0.0.1:9000"``). When set,
        CLEAN (non-flagged, non-enforced) traffic is reverse-proxied there via
        :class:`proxy.UpstreamProxy` instead of the local ``{"status":"ok"}`` sink.
    alerter:
        Optional :class:`dashboard.Alerter`. ``notify()`` is called (never raises)
        when a detection is flagged high/critical.
    decoy_enabled, tarpit_enabled:
        Whether, in enforce mode, flagged canary/decoy paths are answered with
        synthetic loot and ``tarpit`` actions are slow-dripped. Both default True
        but only take effect when ``enforce`` is True.
    tarpit_chunk, tarpit_delay, tarpit_max_duration:
        Slow-drip schedule for the tarpit (kept small so it is bounded and
        test-friendly).
    """

    def __init__(
        self,
        evidence_path: str = "./evidence_out/evidence_ledger.jsonl",
        enforce: bool = False,
        trusted_proxies: Optional[TrustedProxies] = None,
        *,
        allowlist: Optional[Any] = None,
        db_path: Optional[str] = None,
        intel: Optional[ThreatIntel] = None,
        upstream: Optional[str] = None,
        alerter: Optional[Alerter] = None,
        decoy_enabled: bool = True,
        tarpit_enabled: bool = True,
        tarpit_chunk: int = 256,
        tarpit_delay: float = 0.05,
        tarpit_max_duration: float = 2.0,
        statute_notice: bool = False,
    ) -> None:
        # Durable, disk-backed registry when a db path is given; else in-memory.
        self.patches = DurableRegistry(db_path) if db_path else VirtualPatchRegistry()
        self.shield = ArtexShield(patches=self.patches, trusted_proxies=trusted_proxies)
        self.swarm = DefenderSwarmCoordinator(patches=self.patches)
        self.store = EvidenceStore(evidence_path)
        self.enforce = enforce
        # Opt-in: append the 18 U.S.C. 1030 / IC3 statute reference to the banner.
        self.statute_notice = statute_notice

        # Telemetry. These counters are read concurrently by health probes while
        # worker threads mutate them, so every write is guarded by ``_lock``.
        self._lock = threading.Lock()
        self.errors = 0
        self.request_count = 0
        self.flagged_count = 0
        self.last_event_utc: Optional[str] = None

        self.allowlist = allowlist
        self.intel = intel
        self.proxy = UpstreamProxy(upstream) if upstream else None
        self.alerter = alerter
        self.decoy_enabled = decoy_enabled
        self.tarpit_enabled = tarpit_enabled
        self.tarpit_chunk = tarpit_chunk
        self.tarpit_delay = tarpit_delay
        self.tarpit_max_duration = tarpit_max_duration
        # Most recent header fingerprint (exposed for correlation tooling).
        self.last_fingerprint: str = ""

    # -- telemetry (lock-guarded; safe under ThreadingHTTPServer) ----------------

    def _bump_errors(self) -> None:
        """Atomically increment the internal fail-open error counter."""
        with self._lock:
            self.errors += 1

    def _record_request(self, timestamp_utc: str, flagged: bool) -> None:
        """Atomically record one handled request (and whether it was flagged)."""
        with self._lock:
            self.request_count += 1
            if flagged:
                self.flagged_count += 1
            self.last_event_utc = timestamp_utc

    # -- helpers ----------------------------------------------------------------

    def _resolve_ip(self, event: RequestEvent, peer_ip: str) -> str:
        """Best-effort attributed IP for the pre-detection allowlist/intel gates."""
        try:
            return self.shield.resolve(event).attributed_ip or peer_ip
        except Exception:  # never let origin resolution take the path down
            return peer_ip

    def handle(
        self,
        peer_ip: str,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: bytes,
    ) -> DetectionResult:
        event = RequestEvent(
            timestamp_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            remote_ip=peer_ip,
            forwarded_for=[peer_ip],
            method=method,
            path=path,
            user_agent=headers.get("User-Agent", headers.get("user-agent", "")),
            headers=headers,
            body_sha256=sha256(body).hexdigest(),
            body_size=len(body),
        )
        # Order-preserving header fingerprint for clustering/correlation.
        fingerprint = client_header_fingerprint(headers)
        self.last_fingerprint = fingerprint

        # Monotonic request telemetry (the flagged tally is updated once a
        # verdict is known, below).
        self._record_request(event.timestamp_utc, flagged=False)

        attributed_ip = self._resolve_ip(event, peer_ip)

        # Allowlist: trusted sources skip ALL detection/scoring/reporting.
        if self.allowlist is not None and self.allowlist.is_allowed(attributed_ip):
            return DetectionResult(
                flagged=False,
                severity="none",
                reasons=[f"allowlisted:{attributed_ip}"],
                recommended_action="allow",
                attributed_ip=attributed_ip,
                attributed_confidence="allowlisted",
                stream_id=ArtexShield.compute_stream_id(attributed_ip, event.user_agent),
                client_fingerprint=fingerprint,
            )

        # Threat intel: a known-bad source is blocked (with a reason) before
        # scoring, so the shield's blocked-IP short-circuit flags it immediately.
        if self.intel is not None:
            verdict = self.intel.is_known_bad(attributed_ip)
            if verdict:
                self.patches.block_ip(attributed_ip, f"threat_intel:{verdict}")

        body_preview = body[:2048].decode("utf-8", errors="replace")
        try:
            detection = self.shield.inspect(event, body_preview=body_preview)
        except Exception as exc:  # fail OPEN: never deny legitimate traffic on a bug
            self._bump_errors()
            return DetectionResult(
                flagged=False,
                severity="none",
                reasons=[f"shield_error_fail_open:{type(exc).__name__}"],
                recommended_action="allow",
                attributed_ip=peer_ip,
                client_fingerprint=fingerprint,
            )
        detection.client_fingerprint = fingerprint
        if not detection.flagged:
            return detection

        # A flagged verdict: bump the flagged tally (request already counted).
        with self._lock:
            self.flagged_count += 1

        pair = asyncio.run(self.swarm.dispatch(event, detection))
        re_atk = reverse_engineer_request(method, path, event.user_agent, body_preview)
        action = "log_only"
        if self.enforce:
            action = detection.recommended_action
        if pair is not None:
            pair.actions_taken.append(f"response: {action}")

        # PII minimization: persist the route only (no query string), plus a
        # sha256 of the full raw path so a specific probe is still correlatable
        # without storing attacker-supplied query parameters in the ledger.
        route_only = path.split("?", 1)[0]
        raw_path_sha256 = sha256(path.encode("utf-8")).hexdigest()

        try:
            self.store.append(
                EvidenceRecord(
                    timestamp_utc=event.timestamp_utc,
                    stream_id=detection.stream_id,
                    attributed_ip=detection.attributed_ip,
                    attributed_confidence=detection.attributed_confidence,
                    is_reportable=detection.is_reportable,
                    ip_chain=detection.origin_chain,
                    method=method,
                    path=route_only,
                    user_agent=event.user_agent,
                    header_hash=header_fingerprint(headers),
                    body_sha256=event.body_sha256,
                    severity=detection.severity,
                    reasons=detection.reasons,
                    matched_rule=re_atk.coraza_seclang_rule,
                    action_taken=action,
                    rea_findings={"raw_path_sha256": raw_path_sha256},
                )
            )
        except OSError:
            self._bump_errors()  # evidence write failed; detection/response still proceed

        # Alert on high-signal streams. notify() never raises, so this is safe inline.
        if self.alerter is not None and detection.severity in ("high", "critical"):
            self.alerter.notify(
                {
                    "stream_id": detection.stream_id,
                    "attributed_ip": detection.attributed_ip,
                    "severity": detection.severity,
                    "reasons": detection.reasons,
                    "action": action,
                    "timestamp_utc": event.timestamp_utc,
                }
            )
        return detection

    # -- response planning (pure; the handler performs the socket writes) --------

    def plan_enforcement(
        self, detection: DetectionResult, path: str
    ) -> Optional[Tuple[int, Dict[str, str], bytes, bool]]:
        """Decide the enforcement response for a flagged request.

        Returns ``None`` when nothing should be enforced (clean traffic, or
        log-only mode, or a non-enforcing action). Otherwise returns
        ``(status, headers, body, drip)`` where ``drip`` is True when the body
        should be slow-dripped through the tarpit.

        * A flagged canary/decoy path (when ``decoy_enabled``) is answered with
          synthetic honeypot loot — ``200`` with a plausible content type —
          instead of the banner, with the stream id woven in as a canary token.
        * Otherwise the legal warning banner is served: ``429`` for a backoff
          action, ``403`` for block/tarpit. A ``tarpit`` action with
          ``tarpit_enabled`` is marked for slow-drip.
        """
        if not (detection.flagged and self.enforce):
            return None
        action = detection.recommended_action
        if action not in ("block", "tarpit", "backoff_429"):
            return None

        # Decoy: only on our OWN honeypot canary paths that the shield flagged.
        flagged_canary = any(r.startswith("canary_probe:") for r in detection.reasons)
        if self.decoy_enabled and flagged_canary and is_decoy_path(path):
            body = decoy_response(path, token=detection.stream_id)
            headers = dict(decoy_headers(path))
            headers["Incident-Stream"] = detection.stream_id
            return (200, headers, body, False)

        body = build_warning_response(detection, statute_notice=self.statute_notice)
        status = 429 if action == "backoff_429" else 403
        headers = {"Content-Type": "text/plain; charset=utf-8"}
        drip = self.tarpit_enabled and action == "tarpit"
        return (status, headers, body, drip)

    def forward_clean(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: bytes,
        client_ip: str,
        client_proto: str = "http",
    ) -> Optional[ProxyResult]:
        """Reverse-proxy clean traffic to the configured upstream, if any.

        Returns the upstream :class:`proxy.ProxyResult` (which unpacks as
        ``(status, headers, body)``), or ``None`` when no upstream is configured
        (the caller then falls back to the local sink). The unspoofable socket
        peer is passed as ``client_ip`` so ``X-Forwarded-For`` stays trustworthy.
        """
        if self.proxy is None:
            return None
        return self.proxy.forward(
            method=method,
            path=path,
            headers=headers,
            body=body,
            client_ip=client_ip,
            client_proto=client_proto,
        )

    def dashboard_html(self) -> str:
        """Render the localhost operator dashboard from live telemetry."""
        return render_dashboard(build_stats(self.store, self.shield, enforce=self.enforce))


def _is_loopback(host: str) -> bool:
    """True when ``host`` is a loopback address (127.0.0.0/8 or ::1).

    Used to gate the operator dashboard to on-box callers only. Parsing is
    best-effort; a hostname such as ``localhost`` is accepted explicitly.
    """
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost",)


def make_handler(
    engine: ShieldEngine,
    *,
    max_workers: int = 128,
    max_tarpits: int = 16,
    request_timeout: float = 30.0,
):
    """Build the request handler class bound to ``engine``.

    Concurrency / DoS safeguards (all keyword-only, backward-compatible):

    * ``max_workers`` — a :class:`threading.BoundedSemaphore` acquired at the top
      of every dispatch. When it is saturated the request is answered ``503``
      immediately instead of spawning unbounded work.
    * ``max_tarpits`` — a separate, smaller budget for concurrent slow-drip
      tarpits so a flood of tarpit-eligible probes can never pin every worker;
      when it is exhausted the banner is sent in full without the slow drip.
    * ``request_timeout`` — the per-connection socket timeout, which drops
      slowloris-style clients that open a connection and stall.
    """
    worker_sem = threading.BoundedSemaphore(max(1, int(max_workers)))
    tarpit_sem = threading.BoundedSemaphore(max(1, int(max_tarpits)))

    class ShieldHandler(BaseHTTPRequestHandler):
        server_version = "RootJustice/0.1"
        # Per-connection socket timeout (StreamRequestHandler applies this to the
        # accepted socket), so a client that stalls mid-request is dropped.
        timeout = request_timeout

        # Shared concurrency budgets (class-level: one set per server).
        _worker_sem = worker_sem
        _tarpit_sem = tarpit_sem

        # -- small response writers --------------------------------------------
        def _write(self, status: int, headers: Dict[str, str], body: bytes) -> None:
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _write_json(self, status: int, obj: Any) -> None:
            self._write(status, {"Content-Type": "application/json"}, json.dumps(obj).encode("utf-8"))

        def _client_proto(self) -> str:
            return "https" if isinstance(self.connection, ssl.SSLSocket) else "http"

        def _route_only_path(self) -> str:
            return self.path.split("?", 1)[0]

        # -- infra routes (never scored as attacks) ----------------------------
        def _try_infra_route(self) -> bool:
            if self.command != "GET":
                return False
            route = self._route_only_path()
            if route == HEALTH_PATH:
                self._write_json(200, health_payload(engine_stats(engine)))
                return True
            if route == READY_PATH:
                code, payload = readiness(bound=True)
                self._write_json(code, payload)
                return True
            if route == DASHBOARD_PATH:
                # The dashboard exposes attacker telemetry (IPs, streams), so it
                # is restricted to on-box (loopback) callers. A remote peer gets
                # a plain 404 and is never scored, so the route's existence is
                # not advertised to the internet.
                if not _is_loopback(self.client_address[0]):
                    self._write_json(404, {"status": "not-found"})
                    return True
                try:
                    html = engine.dashboard_html()
                except Exception:  # a dashboard render must never crash the shield
                    engine._bump_errors()
                    html = "<!doctype html><title>dashboard unavailable</title>"
                self._write(200, {"Content-Type": "text/html; charset=utf-8"}, html.encode("utf-8"))
                return True
            return False

        def _dispatch(self) -> None:
            # Bound total concurrency: if every worker permit is in use, shed
            # load with a 503 rather than spawning unbounded work (DoS guard).
            if not self._worker_sem.acquire(blocking=False):
                self._write_json(
                    503, {"status": "unavailable", "reason": "server at capacity"}
                )
                return
            try:
                self._dispatch_inner()
            finally:
                self._worker_sem.release()

        def _dispatch_inner(self) -> None:
            # Infra probes are answered before any detection runs.
            try:
                if self._try_infra_route():
                    return
            except Exception:  # pragma: no cover - a probe must not kill the worker
                engine._bump_errors()

            try:
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = self.rfile.read(min(length, MAX_BODY_BYTES)) if length else b""
                hdrs = {k: v for k, v in self.headers.items()}
                peer_ip = self.client_address[0]
                detection = engine.handle(peer_ip, self.command, self.path, hdrs, body)
            except Exception:  # fail OPEN on any handler error
                engine._bump_errors()
                self._write_json(200, {"status": "ok"})
                return

            # Enforcement response (banner / tarpit drip / decoy) when flagged.
            plan = engine.plan_enforcement(detection, self.path)
            if plan is not None:
                status, headers, payload, drip = plan
                # Only slow-drip while the tarpit budget has room. When it is
                # exhausted we send the banner in full (no drip) so tarpitting
                # can never consume every worker thread.
                drip_slot = drip and self._tarpit_sem.acquire(blocking=False)
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if drip_slot:
                    try:
                        tarpit_mod.drip(
                            self.wfile.write,
                            total_bytes=len(payload),
                            chunk=engine.tarpit_chunk,
                            delay=engine.tarpit_delay,
                            max_duration=engine.tarpit_max_duration,
                            payload=payload,
                        )
                    finally:
                        self._tarpit_sem.release()
                else:
                    self.wfile.write(payload)
                return

            # Clean traffic: reverse-proxy to the upstream when configured.
            result = engine.forward_clean(
                method=self.command,
                path=self.path,
                headers=hdrs,
                body=body,
                client_ip=peer_ip,
                client_proto=self._client_proto(),
            )
            if result is not None:
                status, up_headers, up_body = result
                # Drop any upstream Content-Length; we set our own from the body.
                safe_headers = {k: v for k, v in up_headers.items() if k.lower() != "content-length"}
                self._write(status, safe_headers, up_body)
                return

            # Default local sink.
            self._write_json(200, {"status": "ok"})

        do_GET = _dispatch
        do_POST = _dispatch
        do_PUT = _dispatch
        do_DELETE = _dispatch
        do_HEAD = _dispatch

        def log_message(self, *args: Any) -> None:  # silence default stderr logging
            return

    return ShieldHandler


def export_crowdsec_decisions(
    patches: Any, output_path: str, duration: str = "4h"
) -> str:
    """Export blocked IPs as CrowdSec-compatible decisions for a custom bouncer."""
    snapshot = patches.snapshot()
    decisions: List[Dict[str, Any]] = [
        {
            "value": ip,
            "scope": "Ip",
            "type": "ban",
            "duration": duration,
            "origin": "root-justice",
            "reason": reason,
        }
        for ip, reason in snapshot["blocked_ips"].items()
    ]
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(decisions, indent=2), encoding="utf-8")
    return str(out)


def serve(
    host: str = "127.0.0.1",
    port: int = 8080,
    evidence_path: str = "./evidence_out/evidence_ledger.jsonl",
    enforce: bool = False,
    trusted_proxies: Optional[TrustedProxies] = None,
    *,
    allowlist: Optional[Any] = None,
    db_path: Optional[str] = None,
    intel: Optional[ThreatIntel] = None,
    upstream: Optional[str] = None,
    alerter: Optional[Alerter] = None,
    tls_cert: Optional[str] = None,
    tls_key: Optional[str] = None,
) -> None:
    engine = ShieldEngine(
        evidence_path=evidence_path,
        enforce=enforce,
        trusted_proxies=trusted_proxies,
        allowlist=allowlist,
        db_path=db_path,
        intel=intel,
        upstream=upstream,
        alerter=alerter,
    )
    httpd = ThreadingHTTPServer((host, port), make_handler(engine))

    scheme = "http"
    if tls_cert and tls_key:
        context = tlsconf.build_ssl_context(tls_cert, tls_key)
        tlsconf.wrap_server_socket(httpd, context)
        scheme = "https"

    mode = "ENFORCE" if enforce else "LOG-ONLY"
    print(
        f"[root-justice] shield listening on {scheme}://{host}:{port} ({mode}); "
        f"evidence -> {evidence_path}"
    )

    # Graceful shutdown: serve on a background thread so a SIGTERM/SIGINT handler
    # (running on the main thread) can safely call ``shutdown()`` — which must not
    # be invoked from the serving thread — letting systemd/docker ``stop`` drain
    # in-flight requests cleanly instead of relying on KeyboardInterrupt alone.
    stop_event = threading.Event()

    def _request_stop(signum: int, _frame: Any) -> None:
        stop_event.set()

    for _sig in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGINT", None)):
        if _sig is None:
            continue
        try:
            signal.signal(_sig, _request_stop)
        except (ValueError, OSError, RuntimeError):
            # Not on the main thread (or unsupported here) — fall back to the
            # KeyboardInterrupt path below.
            pass

    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    try:
        while not stop_event.wait(timeout=0.5):
            pass
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[root-justice] shutting down")
        httpd.shutdown()
        httpd.server_close()
        server_thread.join(timeout=5)

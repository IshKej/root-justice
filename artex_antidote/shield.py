"""Edge Shield: Artex scanner detection, virtual patching, 429/503 budget traps, and canary tarpits."""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .origin import ResolvedOrigin, TrustedProxies, resolve_origin
from .signatures import (
    EXPLOIT_PATTERNS,
    GENERIC_AUTOMATION_UA_PATTERNS,
    OFFENSIVE_TOOL_UA_PATTERNS,
)

# Signature regexes (UA tiers and exploit payloads) live in
# :mod:`artex_antidote.signatures`, the single source of truth shared with the
# attribution path, so the two can no longer drift apart. The tier semantics are
# unchanged: an offensive-tool UA is a heavy (still-corroborated) signal, generic
# automation (httpx / Go-http-client / curl / requests / wget) is a very weak one
# that never flags legitimate traffic on its own.

# Detection scoring. A request is flagged only when corroborated signals cross
# the threshold — no single weak/spoofable signal blocks legitimate traffic.
SCORE_OFFENSIVE_TOOL_UA = 50
SCORE_GENERIC_AUTOMATION_UA = 10
SCORE_CANARY_PATH = 60
SCORE_EXPLOIT_PATTERN = 60
SCORE_VIRTUAL_PATCH = 40
SCORE_BURST = 30
FLAG_THRESHOLD = 60

# Bound on tracked source IPs for burst detection so an attacker cannot exhaust
# memory by rotating source addresses (finding #9 / design §4.2).
MAX_TRACKED_IPS = 50_000

CANARY_PATHS: Tuple[str, ...] = (
    "/.env",
    "/.git/config",
    "/wp-admin",
    "/wp-login.php",
    "/actuator/env",
    "/server-status",
    "/api/v1/debug",
    "/phpinfo.php",
)

@dataclass
class RequestEvent:
    """Normalized inbound HTTP request telemetry for detection and chain-of-custody."""

    timestamp_utc: str
    remote_ip: str
    forwarded_for: List[str]
    method: str
    path: str
    user_agent: str
    headers: Dict[str, str]
    body_sha256: str
    body_size: int


@dataclass
class DetectionResult:
    """Result of inspecting a single HTTP request."""

    flagged: bool
    severity: str  # "none" | "low" | "medium" | "high" | "critical"
    reasons: List[str] = field(default_factory=list)
    recommended_action: str = "allow"  # "allow" | "backoff_429" | "tarpit" | "block"
    stream_id: str = ""
    # Attribution derived from the unspoofable socket peer inward (see origin.py).
    attributed_ip: str = ""
    attributed_confidence: str = ""
    is_reportable: bool = False
    origin_chain: List[Dict[str, Any]] = field(default_factory=list)
    # Optional order-preserving HTTP header fingerprint (see fingerprint.py),
    # attached by the request path for clustering/correlation. Empty by default
    # so every existing construction site stays backward-compatible.
    client_fingerprint: str = ""


class VirtualPatchRegistry:
    """Thread-safe in-memory registry of dynamic virtual patches applied by Containment Agents.

    This is the DEFAULT registry when the server runs under ``ThreadingHTTPServer``,
    so every method must be safe to call concurrently from request-handler threads.
    A single lock guards all state; readers that iterate (:meth:`match_virtual_patch`,
    :meth:`snapshot`) take a copy of the backing dict under the lock, so a concurrent
    :meth:`block_ip` / :meth:`add_virtual_patch` can never raise
    ``RuntimeError: dictionary changed size during iteration`` (which previously
    propagated into the server's request path and triggered a fail-open).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._blocked_ips: Dict[str, str] = {}
        self._patched_paths: Dict[str, str] = {}

    def block_ip(self, ip: str, reason: str) -> None:
        with self._lock:
            self._blocked_ips[ip] = reason

    def add_virtual_patch(self, path_prefix: str, rule_reason: str) -> None:
        with self._lock:
            self._patched_paths[path_prefix] = rule_reason

    def is_ip_blocked(self, ip: str) -> Optional[str]:
        with self._lock:
            return self._blocked_ips.get(ip)

    def match_virtual_patch(self, path: str) -> Optional[str]:
        # Match the exact probed path or a child under a real path boundary.
        # Never treat "/" as a wildcard that flags the whole site.
        probe = path.split("?")[0]
        # Iterate a snapshot taken under the lock so a concurrent writer cannot
        # mutate the dict mid-iteration.
        with self._lock:
            items = list(self._patched_paths.items())
        for patched, reason in items:
            if patched == "/":
                continue
            if probe == patched or probe.startswith(patched.rstrip("/") + "/"):
                return reason
        return None

    def snapshot(self) -> Dict[str, Dict[str, str]]:
        with self._lock:
            return {
                "blocked_ips": dict(self._blocked_ips),
                "patched_paths": dict(self._patched_paths),
            }


class ArtexShield:
    """Detects Artex-style autonomous scanning and selects defensive countermeasures."""

    def __init__(
        self,
        patches: Optional[VirtualPatchRegistry] = None,
        burst_threshold: int = 15,
        burst_window_sec: float = 10.0,
        trusted_proxies: Optional[TrustedProxies] = None,
    ) -> None:
        self.patches = patches or VirtualPatchRegistry()
        self.burst_threshold = burst_threshold
        self.burst_window_sec = burst_window_sec
        # Proxies whose X-Forwarded-For we are willing to believe. Empty by
        # default: with no trusted proxy, only the socket peer is attributable.
        self.trusted_proxies = trusted_proxies or TrustedProxies()
        self._recent_hits: Dict[str, List[float]] = {}
        # Guards every read-modify-write of ``_recent_hits`` (burst state). The
        # shield is shared across request-handler threads, so this prevents a
        # concurrent update from corrupting a per-IP list or racing eviction.
        self._hits_lock = threading.Lock()

    @staticmethod
    def compute_stream_id(ip: str, user_agent: str) -> str:
        digest = hashlib.sha256(f"{ip}|{user_agent}".encode("utf-8")).hexdigest()[:12]
        return f"artex-stream-{digest}"

    def resolve(self, event: RequestEvent) -> ResolvedOrigin:
        """Attribute the origin from the socket peer inward, honoring trusted proxies."""
        return resolve_origin(event.remote_ip, event.headers, self.trusted_proxies)

    def _evict_stale(self, now: float) -> None:
        """Drop IPs with no hits inside the burst window; cap total tracked IPs.

        Prevents an attacker from exhausting memory by rotating source addresses.
        The caller MUST hold ``self._hits_lock``; this mutates ``_recent_hits`` in
        place and never re-acquires the lock.
        """
        if len(self._recent_hits) < MAX_TRACKED_IPS:
            # Cheap path: only prune fully-stale entries occasionally.
            if len(self._recent_hits) % 1024 != 0:
                return
        stale = [
            ip
            for ip, ts in self._recent_hits.items()
            if not ts or now - ts[-1] > self.burst_window_sec
        ]
        for ip in stale:
            self._recent_hits.pop(ip, None)
        # Hard cap: if still over budget, evict oldest-touched IPs. Guard the sort
        # key against an empty list (an entry could be emptied elsewhere) so this
        # never raises IndexError.
        if len(self._recent_hits) >= MAX_TRACKED_IPS:
            def _last_touch(ip: str) -> float:
                ts = self._recent_hits[ip]
                return ts[-1] if ts else 0.0

            for ip in sorted(self._recent_hits, key=_last_touch)[
                : len(self._recent_hits) - MAX_TRACKED_IPS + 1
            ]:
                self._recent_hits.pop(ip, None)

    def inspect(self, event: RequestEvent, body_preview: str = "") -> DetectionResult:
        resolved = self.resolve(event)
        primary_ip = resolved.attributed_ip
        stream_id = self.compute_stream_id(primary_ip, event.user_agent)
        origin_fields = dict(
            stream_id=stream_id,
            attributed_ip=primary_ip,
            attributed_confidence=resolved.attributed_confidence,
            is_reportable=resolved.is_reportable,
            origin_chain=resolved.to_dict()["chain"],
        )

        if reason := self.patches.is_ip_blocked(primary_ip):
            return DetectionResult(
                flagged=True,
                severity="critical",
                reasons=[f"blocked_ip:{reason}"],
                recommended_action="block",
                **origin_fields,
            )

        reasons: List[str] = []
        score = 0
        has_canary = False
        has_exploit = False

        # Signal 1: User-Agent (weak, spoofable — scored, never sufficient alone).
        for pat in OFFENSIVE_TOOL_UA_PATTERNS:
            if pat.search(event.user_agent):
                reasons.append(f"offensive_tool_ua:{pat.pattern}")
                score += SCORE_OFFENSIVE_TOOL_UA
                break
        else:
            for pat in GENERIC_AUTOMATION_UA_PATTERNS:
                if pat.search(event.user_agent):
                    reasons.append(f"automation_ua:{pat.pattern}")
                    score += SCORE_GENERIC_AUTOMATION_UA
                    break

        # Signal 2: Canary / honeypot path (strong — nobody legitimate fetches these).
        lower_path = event.path.lower()
        for canary in CANARY_PATHS:
            if lower_path.startswith(canary):
                reasons.append(f"canary_probe:{canary}")
                score += SCORE_CANARY_PATH
                has_canary = True

        # Signal 3: Exploit payload patterns (strong).
        probe_text = f"{event.path} {body_preview}"
        for pat in EXPLOIT_PATTERNS:
            if pat.search(probe_text):
                reasons.append("exploit_probe_pattern")
                score += SCORE_EXPLOIT_PATTERN
                has_exploit = True
                break

        # Signal 4: Virtual patch hit (this exact path was already weaponized).
        if patch_reason := self.patches.match_virtual_patch(event.path):
            reasons.append(f"virtual_patch:{patch_reason}")
            score += SCORE_VIRTUAL_PATCH

        # Signal 5: Burst / intent-flood (bounded per-IP state). The read-append-
        # store plus eviction is a single small critical section so concurrent
        # request threads cannot corrupt a per-IP list or race the stale sweep.
        now = time.monotonic()
        with self._hits_lock:
            self._evict_stale(now)
            hits = [
                t for t in self._recent_hits.get(primary_ip, []) if now - t <= self.burst_window_sec
            ]
            hits.append(now)
            self._recent_hits[primary_ip] = hits
            burst_count = len(hits)
        if burst_count >= self.burst_threshold:
            reasons.append(f"burst_rate:{burst_count}_in_{int(self.burst_window_sec)}s")
            score += SCORE_BURST

        # Flag only on corroborated evidence crossing the threshold. A lone weak
        # signal (e.g. a tool UA or a single automation client) never enforces.
        if score < FLAG_THRESHOLD:
            observed = reasons if reasons else []
            return DetectionResult(
                flagged=False,
                severity="low" if observed else "none",
                reasons=observed,
                recommended_action="allow",
                **origin_fields,
            )

        if has_canary:
            severity, action = "critical", "tarpit"
        elif has_exploit:
            severity, action = "high", "backoff_429"
        elif score >= FLAG_THRESHOLD + SCORE_BURST:
            severity, action = "high", "backoff_429"
        else:
            severity, action = "medium", "backoff_429"

        return DetectionResult(
            flagged=True,
            severity=severity,
            reasons=reasons,
            recommended_action=action,
            **origin_fields,
        )

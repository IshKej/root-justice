"""Operator dashboard + alerting for the Root Justice / Artex Antidote blue-team stack.

This module is purely a *view* onto telemetry that the request path and evidence
store already produced. It performs no detection, takes no enforcement action,
and reaches no third-party machine of its own accord.

Two pieces:

* :func:`render_dashboard` renders a self-contained (no external CSS/JS/fonts),
  localhost-only HTML page summarizing the current posture: event counts, the
  top attributed source IPs, whether the shield is enforcing or log-only, and
  the evidence chain-integrity state. All interpolated values are HTML-escaped,
  so hostile ``User-Agent`` / path / IP strings captured from attackers cannot
  inject markup into the operator's browser.

* :class:`Alerter` POSTs a compact JSON alert to an operator-configured webhook
  (e.g. a Slack/Teams/PagerDuty incoming webhook) when a high-severity event is
  flagged. Network I/O goes through a single swappable seam (``post_fn``,
  defaulting to the module-level :func:`_http_post_json`) so the whole thing is
  unit-testable offline. ``notify`` never raises: a dead webhook must not take
  down the request path that calls it.

Typical wiring::

    html = render_dashboard(build_stats(store, shield, enforce=True))
    Path("dashboard.html").write_text(html, encoding="utf-8")

    alerter = Alerter("https://hooks.example.com/services/XXX")
    if result.flagged and result.severity in ("high", "critical"):
        alerter.notify({
            "stream_id": result.stream_id,
            "attributed_ip": result.attributed_ip,
            "severity": result.severity,
            "reasons": result.reasons,
            "action": result.recommended_action,
        })
"""

from __future__ import annotations

import html
import json
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

__all__ = ["render_dashboard", "build_stats", "Alerter"]


# --------------------------------------------------------------------------- #
# Network seam (single point the tests monkeypatch; keeps the module offline). #
# --------------------------------------------------------------------------- #
def _http_post_json(url: str, payload: Dict[str, Any], timeout: float = 4.0) -> int:
    """POST ``payload`` as JSON to ``url`` and return the HTTP status code.

    This is the ONLY place the module performs outbound network I/O. Tests
    replace it (or pass their own ``post_fn`` to :class:`Alerter`) so the suite
    runs with no network. It is deliberately tiny: no retries, no redirects of
    its own, no following attacker-controlled destinations — the webhook URL is
    always supplied by the operator, never by observed/attacker content.
    """
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "RootJustice-Alerter/0.1"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (operator URL)
        return int(getattr(resp, "status", 0) or resp.getcode())


# --------------------------------------------------------------------------- #
# Stats assembly                                                              #
# --------------------------------------------------------------------------- #
def build_stats(
    store: Any,
    shield: Any = None,
    enforce: bool = False,
    top_n: int = 10,
) -> Dict[str, Any]:
    """Assemble a ``stats`` dict for :func:`render_dashboard` from live objects.

    Convenience helper only — ``render_dashboard`` accepts any dict of the same
    shape, so callers that already have aggregated numbers can skip this.

    * ``store`` is an :class:`evidence.EvidenceStore` (anything exposing
      ``records()`` and ``verify_chain()``).
    * ``shield`` is an optional :class:`shield.ArtexShield`; only its virtual
      patch snapshot is read, for the blocked-IP count.
    * ``enforce`` reflects whether countermeasures are live (``True``) or the
      stack is in log-only / observe mode (``False``).
    """
    records: List[Dict[str, Any]] = list(store.records())
    chain = store.verify_chain()

    severities = Counter(r.get("severity", "none") for r in records)
    ip_counts = Counter(
        r.get("attributed_ip", "") for r in records if r.get("attributed_ip")
    )

    blocked_ips = 0
    if shield is not None:
        try:
            blocked_ips = len(shield.patches.snapshot().get("blocked_ips", {}))
        except Exception:  # pragma: no cover - defensive; shield shape may vary
            blocked_ips = 0

    return {
        "total_events": len(records),
        "flagged_events": sum(1 for r in records if r.get("severity", "none") != "none"),
        "reportable_events": sum(1 for r in records if r.get("is_reportable")),
        "severity_counts": dict(severities),
        "top_ips": ip_counts.most_common(top_n),
        "blocked_ips": blocked_ips,
        "enforce": bool(enforce),
        "chain_integrity": chain,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }


# --------------------------------------------------------------------------- #
# HTML rendering                                                             #
# --------------------------------------------------------------------------- #
def _e(value: Any) -> str:
    """HTML-escape any value (attacker-controlled strings land here)."""
    return html.escape(str(value), quote=True)


def _top_ip_pairs(stats: Dict[str, Any]) -> List[Tuple[str, int]]:
    """Normalize ``top_ips`` (list of pairs OR a {ip: count} mapping)."""
    raw = stats.get("top_ips", [])
    if isinstance(raw, dict):
        return sorted(raw.items(), key=lambda kv: kv[1], reverse=True)
    pairs: List[Tuple[str, int]] = []
    for item in raw:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            pairs.append((str(item[0]), int(item[1])))
    return pairs


def render_dashboard(stats: Dict[str, Any]) -> str:
    """Render a self-contained HTML operator dashboard from a ``stats`` dict.

    Recognized keys (all optional; missing numbers render as ``0``/empty):

    * ``total_events``, ``flagged_events``, ``reportable_events``, ``blocked_ips`` (ints)
    * ``severity_counts``: ``{severity: count}``
    * ``top_ips``: list of ``(ip, count)`` pairs, or ``{ip: count}`` mapping
    * ``enforce``: ``True`` -> "ENFORCING", ``False`` -> "LOG-ONLY"
    * ``chain_integrity``: ``{"intact": bool, "broken_at_index": int|None,
      "verified_records": int}`` (as returned by ``EvidenceStore.verify_chain``)
    * ``generated_utc``: timestamp string

    The returned string is a complete standalone HTML document with inline CSS
    and no network references, safe to write to disk and open from ``file://``
    or serve from ``127.0.0.1``. Nothing is fetched and no script runs.
    """
    total = int(stats.get("total_events", 0) or 0)
    flagged = int(stats.get("flagged_events", 0) or 0)
    reportable = int(stats.get("reportable_events", 0) or 0)
    blocked = int(stats.get("blocked_ips", 0) or 0)
    enforce = bool(stats.get("enforce", False))
    generated = stats.get("generated_utc") or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z"
    )

    mode_label = "ENFORCING" if enforce else "LOG-ONLY"
    mode_class = "mode-enforce" if enforce else "mode-logonly"

    chain = stats.get("chain_integrity") or {}
    intact = bool(chain.get("intact", True))
    verified = int(chain.get("verified_records", 0) or 0)
    broken_at = chain.get("broken_at_index")
    if intact:
        chain_label = f"INTACT ({verified} records verified)"
        chain_class = "chain-ok"
    else:
        chain_label = f"BROKEN at index {broken_at} ({verified} verified before break)"
        chain_class = "chain-bad"

    # Metric cards (value, label) — numbers the tests assert are present.
    cards = [
        (total, "Total Events"),
        (flagged, "Flagged Events"),
        (reportable, "Reportable Events"),
        (blocked, "Blocked IPs"),
    ]
    card_html = "\n".join(
        f'      <div class="card"><div class="metric">{_e(value)}</div>'
        f'<div class="metric-label">{_e(label)}</div></div>'
        for value, label in cards
    )

    # Severity breakdown.
    sev_counts: Dict[str, Any] = stats.get("severity_counts", {}) or {}
    sev_order = ["critical", "high", "medium", "low", "none"]
    sev_items = sorted(
        sev_counts.items(),
        key=lambda kv: (sev_order.index(kv[0]) if kv[0] in sev_order else len(sev_order), kv[0]),
    )
    if sev_items:
        sev_rows = "\n".join(
            f"        <tr><td>{_e(sev)}</td><td class=\"num\">{_e(count)}</td></tr>"
            for sev, count in sev_items
        )
    else:
        sev_rows = '        <tr><td colspan="2" class="empty">No events recorded.</td></tr>'

    # Top attributed IPs.
    top_ips = _top_ip_pairs(stats)
    if top_ips:
        ip_rows = "\n".join(
            f"        <tr><td class=\"mono\">{_e(ip)}</td>"
            f"<td class=\"num\">{_e(count)}</td></tr>"
            for ip, count in top_ips
        )
    else:
        ip_rows = '        <tr><td colspan="2" class="empty">No attributed sources yet.</td></tr>'

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Root Justice Operator Dashboard</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 24px;
    font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
    background: #0f1419; color: #e6edf3; line-height: 1.5;
  }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  .sub {{ color: #8b949e; font-size: 13px; margin-bottom: 20px; }}
  .banner {{
    display: inline-block; padding: 6px 14px; border-radius: 6px;
    font-weight: 700; letter-spacing: .5px; font-size: 13px; margin-right: 10px;
  }}
  .mode-enforce {{ background: #1f6feb; color: #fff; }}
  .mode-logonly {{ background: #3d2d00; color: #e3b341; }}
  .chain-ok {{ background: #132d1a; color: #3fb950; }}
  .chain-bad {{ background: #3d1416; color: #f85149; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: 14px; margin: 20px 0; }}
  .card {{
    background: #161b22; border: 1px solid #30363d; border-radius: 10px;
    padding: 16px 20px; min-width: 150px; flex: 1 1 150px;
  }}
  .metric {{ font-size: 30px; font-weight: 700; }}
  .metric-label {{ color: #8b949e; font-size: 12px; text-transform: uppercase; letter-spacing: .4px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 20px; }}
  section {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 16px 18px; }}
  section h2 {{ font-size: 14px; margin: 0 0 12px; color: #c9d1d9; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid #21262d; }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  td.mono, .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
  td.empty {{ color: #8b949e; font-style: italic; }}
  footer {{ color: #6e7681; font-size: 11px; margin-top: 24px; }}
</style>
</head>
<body>
  <h1>Root Justice &mdash; Operator Dashboard</h1>
  <div class="sub">Defensive posture overview (localhost view, read-only).</div>

  <div>
    <span class="banner {mode_class}">MODE: {_e(mode_label)}</span>
    <span class="banner {chain_class}">EVIDENCE CHAIN: {_e(chain_label)}</span>
  </div>

  <div class="cards">
{card_html}
  </div>

  <div class="grid">
    <section>
      <h2>Severity Breakdown</h2>
      <table>
        <thead><tr><th>Severity</th><th class="num">Count</th></tr></thead>
        <tbody>
{sev_rows}
        </tbody>
      </table>
    </section>

    <section>
      <h2>Top Attributed Source IPs</h2>
      <table>
        <thead><tr><th>Origin IP</th><th class="num">Events</th></tr></thead>
        <tbody>
{ip_rows}
        </tbody>
      </table>
    </section>
  </div>

  <footer>Generated {_e(generated)} &middot; Strictly defensive &middot; No outbound action taken from this page.</footer>
</body>
</html>
"""


# --------------------------------------------------------------------------- #
# Alerting                                                                    #
# --------------------------------------------------------------------------- #
class Alerter:
    """POST a compact JSON alert to an operator-configured webhook.

    The webhook URL is supplied by the operator (never by observed/attacker
    content). ``post_fn`` is the swappable network seam; it defaults to the
    module-level :func:`_http_post_json` and takes ``(url, payload)`` and
    returns an HTTP status code (or any truthy/2xx-ish value). Tests pass their
    own ``post_fn`` to capture the payload and to simulate failures.

    :meth:`notify` NEVER raises. A webhook that is down, slow, or misconfigured
    returns ``False`` and is otherwise ignored, so alerting can be called
    inline on the request path without risk of taking it down.
    """

    def __init__(
        self,
        webhook_url: str,
        post_fn: Optional[Callable[[str, Dict[str, Any]], Any]] = None,
    ) -> None:
        self.webhook_url = webhook_url
        self._post_fn = post_fn or _http_post_json
        self.sent_count = 0
        self.failure_count = 0
        self.last_error: Optional[str] = None

    def build_payload(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Build the compact alert payload from a detection event dict.

        Pulls a stable, minimal field set so alerts stay small and consistent
        regardless of extra keys on the source event. Reasons are capped to the
        first few to keep the alert compact.
        """
        reasons = event.get("reasons") or []
        if isinstance(reasons, str):
            reasons = [reasons]
        return {
            "source": "root-justice",
            "kind": "attack_flagged",
            "severity": event.get("severity", "unknown"),
            "attributed_ip": event.get("attributed_ip", ""),
            "stream_id": event.get("stream_id", ""),
            "action": event.get("action") or event.get("recommended_action", ""),
            "reasons": list(reasons)[:5],
            "timestamp_utc": event.get("timestamp_utc")
            or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        }

    def notify(self, event: Dict[str, Any]) -> bool:
        """Send a compact JSON alert for ``event``. Returns success; never raises.

        Success is defined as the seam returning without raising and, when it
        returns an HTTP-style status code, that code being a 2xx. A non-numeric
        truthy return is also treated as success (lets simple test stubs return
        ``True``).
        """
        payload = self.build_payload(event)
        try:
            result = self._post_fn(self.webhook_url, payload)
        except Exception as exc:  # defensive: alerting must not break the caller
            self.failure_count += 1
            self.last_error = str(exc)
            return False

        ok = self._is_ok(result)
        if ok:
            self.sent_count += 1
        else:
            self.failure_count += 1
            self.last_error = f"non-success response: {result!r}"
        return ok

    @staticmethod
    def _is_ok(result: Any) -> bool:
        if isinstance(result, bool):
            return result
        if isinstance(result, int):
            return 200 <= result < 300
        return bool(result)

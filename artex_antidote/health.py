"""Container liveness and readiness probes for the Root Justice edge shield.

Spec #13 (Container + health). This module is a tiny, dependency-free seam so
an orchestrator (Docker ``HEALTHCHECK``, Kubernetes ``livenessProbe`` /
``readinessProbe``, or a load balancer) can ask the shield two questions:

* **Liveness** — is the process up and what mode is it running in?
  Answered by :func:`health_payload`, which turns an engine's stats dict into a
  stable JSON-serialisable shape ``{"status": ..., "mode": ...,
  "active_mitigations": ..., "requests": ..., "flagged": ...}``.
* **Readiness** — has the listener actually bound its socket and is it ready to
  take traffic? Answered by :func:`readiness`, which returns an
  ``(http_status_code, payload)`` tuple so the caller can wire it straight into
  an HTTP response.

Design notes
------------
* **Defensive / log-only aware.** The reported ``mode`` is derived purely from
  the ``enforce`` flag in the stats dict; there is no enforcement side effect
  here. A fresh engine reports ``"log-only"``.
* **Standard library only.** Nothing is imported beyond typing helpers, so this
  is safe to call from inside a health handler on any Python 3.10+.
* **Total and forgiving.** ``health_payload`` never raises on a partial or
  empty stats dict — a health probe must not itself fall over. Missing numeric
  fields default to ``0`` and unknown modes degrade gracefully.

Typical use::

    from artex_antidote.health import engine_stats, health_payload, readiness

    stats = engine_stats(engine)          # engine is a server.ShieldEngine
    body = health_payload(stats)          # -> {"status": "ok", "mode": ..., ...}
    code, ready = readiness(bound=True)   # -> (200, {"status": "ready", ...})
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Tuple

__all__ = ["MODE_LOG_ONLY", "MODE_ENFORCE", "engine_stats", "health_payload", "readiness"]

MODE_LOG_ONLY = "log-only"
MODE_ENFORCE = "enforce"


def _coerce_int(value: Any, default: int = 0) -> int:
    """Best-effort int coercion that never raises (health probes must not crash)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def engine_stats(engine: Any) -> Dict[str, Any]:
    """Extract a plain, probe-friendly stats dict from a shield engine.

    ``engine`` is expected to look like :class:`artex_antidote.server.ShieldEngine`
    (attributes ``enforce``, ``errors``, the request counters and a ``patches``
    registry exposing ``snapshot()``), but any object is accepted: unknown
    attributes fall back to safe defaults so this can be called the instant the
    engine is constructed.

    Returns a dict with:

    * ``enforce`` (bool) and ``errors`` (int) — mode and internal fail-open count.
    * ``active_mitigations`` (int) — the number of currently-contained sources
      (blocked + tarpitted IPs) from the virtual-patch snapshot. This replaces
      the former, misleadingly-named ``events`` field, which never counted
      requests at all.
    * ``request_count`` / ``flagged_count`` (int) — monotonic totals of requests
      handled and of those flagged as hostile.
    * ``last_event_utc`` (str) — timestamp of the most recently handled request,
      or ``""`` if none yet.
    * ``alerter_failures`` (int) and ``alerter_last_error`` (str) — the attached
      :class:`dashboard.Alerter`'s delivery-failure count and last error, if any.
    """
    enforce = bool(getattr(engine, "enforce", False))
    errors = _coerce_int(getattr(engine, "errors", 0))
    request_count = _coerce_int(getattr(engine, "request_count", 0))
    flagged_count = _coerce_int(getattr(engine, "flagged_count", 0))
    last_event_utc = getattr(engine, "last_event_utc", None) or ""

    active_mitigations = 0
    patches = getattr(engine, "patches", None)
    snapshot = getattr(patches, "snapshot", None)
    if callable(snapshot):
        try:
            snap = snapshot()
        except Exception:  # a probe must never be taken down by a stats read
            snap = None
        if isinstance(snap, Mapping):
            blocked = snap.get("blocked_ips")
            if isinstance(blocked, Mapping):
                active_mitigations += len(blocked)
            tarpitted = snap.get("tarpitted_ips")
            if isinstance(tarpitted, Mapping):
                active_mitigations += len(tarpitted)

    # Alerter delivery health (optional; never let a missing alerter raise).
    alerter = getattr(engine, "alerter", None)
    alerter_failures = _coerce_int(getattr(alerter, "failure_count", 0))
    alerter_last_error = getattr(alerter, "last_error", None) or ""

    return {
        "enforce": enforce,
        "errors": errors,
        "active_mitigations": active_mitigations,
        "request_count": request_count,
        "flagged_count": flagged_count,
        "last_event_utc": str(last_event_utc),
        "alerter_failures": alerter_failures,
        "alerter_last_error": str(alerter_last_error),
    }


def health_payload(engine_stats: Mapping[str, Any]) -> Dict[str, Any]:
    """Build the liveness payload from an engine stats dict.

    Parameters
    ----------
    engine_stats:
        A mapping such as the one returned by :func:`engine_stats`. Only
        ``enforce``, ``errors`` and ``events`` are read; every one is optional.

    Returns
    -------
    dict
        ``{"status": "ok"|"degraded", "mode": "log-only"|"enforce",
        "active_mitigations": <int>, "requests": <int>, "flagged": <int>,
        "errors": <int>, "last_event_utc": <str>, "alerter_failures": <int>,
        "alerter_last_error": <str>}``. ``status`` is ``"degraded"`` when the
        engine has recorded one or more internal (fail-open) errors, and
        ``"ok"`` otherwise — the process is alive in both cases, which is what a
        liveness probe cares about.

    Field names describe exactly what they count: ``active_mitigations`` is the
    number of currently-contained sources (NOT a request total), ``requests`` is
    the monotonic request total, and ``flagged`` is how many were hostile. For
    backward compatibility an input mapping that still uses the old ``events``
    key is accepted as a fallback for ``active_mitigations``.

    The result is always JSON-serialisable and is never ``None``.
    """
    stats: Mapping[str, Any] = engine_stats if isinstance(engine_stats, Mapping) else {}

    enforce = bool(stats.get("enforce", False))
    errors = _coerce_int(stats.get("errors", 0))
    active_mitigations = _coerce_int(
        stats.get("active_mitigations", stats.get("events", 0))
    )
    requests = _coerce_int(stats.get("request_count", 0))
    flagged = _coerce_int(stats.get("flagged_count", 0))
    last_event_utc = str(stats.get("last_event_utc", "") or "")
    alerter_failures = _coerce_int(stats.get("alerter_failures", 0))
    alerter_last_error = str(stats.get("alerter_last_error", "") or "")

    mode = MODE_ENFORCE if enforce else MODE_LOG_ONLY
    status = "degraded" if errors > 0 else "ok"

    return {
        "status": status,
        "mode": mode,
        "active_mitigations": active_mitigations,
        "requests": requests,
        "flagged": flagged,
        "errors": errors,
        "last_event_utc": last_event_utc,
        "alerter_failures": alerter_failures,
        "alerter_last_error": alerter_last_error,
    }


def readiness(bound: bool) -> Tuple[int, Dict[str, Any]]:
    """Report whether the shield has bound its listening socket.

    Parameters
    ----------
    bound:
        ``True`` once the server socket is bound and accepting connections;
        ``False`` during startup or if binding failed.

    Returns
    -------
    (int, dict)
        A ``(status_code, payload)`` tuple ready to feed into an HTTP response.
        Ready -> ``(200, {"status": "ready", "bound": True})``; not yet ready ->
        ``(503, {"status": "not-ready", "bound": False})``. 503 (Service
        Unavailable) is the conventional "not ready, retry later" signal that
        keeps a pod out of rotation until it can serve.
    """
    if bound:
        return 200, {"status": "ready", "bound": True}
    return 503, {"status": "not-ready", "bound": False}

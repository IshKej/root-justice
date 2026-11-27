"""Defensive reverse proxy to a real upstream origin.

Root Justice inspects traffic at the edge; in a deployment that actually
terminates connections it must also *forward* the surviving (non-malicious)
requests to the real application behind it. This module is that forwarding leg:
a small, standard-library-only reverse proxy.

It is strictly defensive and strictly inbound-shaped:

  * It only ever connects to ONE configured upstream (``base_url``). It never
    reaches out to an attacker's address, never follows a target supplied by the
    request, and never performs any outbound action beyond relaying the client's
    own request to the operator's own origin.
  * It strips hop-by-hop headers in BOTH directions (RFC 7230 §6.1) so a crafted
    ``Connection:`` / ``Transfer-Encoding:`` header cannot smuggle a second
    request past the shield or desync the upstream.
  * It injects/augments ``X-Forwarded-For`` and ``X-Forwarded-Proto`` using the
    *unspoofable socket peer* passed in by the caller, so the upstream (and the
    origin-attribution layer) can see the real request path.
  * On ANY upstream failure it returns a clean ``502`` tuple instead of raising,
    so a flaky origin can never take the shield down (fail-closed to a 502, not
    a crash).

Network I/O goes through the module-level :func:`_open_conn` seam, which tests
monkeypatch to simulate an upstream without a live server. Nothing here needs
admin rights or a real socket to be exercised.

Typical use (plugged in AFTER the shield decides to ALLOW a request)::

    proxy = UpstreamProxy("https://app.internal:8443")
    status, headers, body = proxy.forward(
        method="GET",
        path="/dashboard",
        headers=incoming_headers,
        body=b"",
        client_ip="203.0.113.7",   # the unspoofable socket peer
        client_proto="https",
    )
"""

from __future__ import annotations

import http.client
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

__all__ = ["UpstreamProxy", "HOP_BY_HOP_HEADERS", "ProxyResult"]

# Hop-by-hop headers are meaningful only for a single transport-level connection
# and MUST NOT be forwarded by a proxy (RFC 7230 §6.1, RFC 2616 §13.5.1). Keeping
# them would let a client desync the upstream (request smuggling) or pin a
# connection open. Compared case-insensitively.
HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Trailers",  # common misspelling seen in the wild; strip it too
        "Transfer-Encoding",
        "Upgrade",
    )
)

# Upper bound on how much of an upstream response body we buffer. A hostile or
# broken origin cannot make the proxy consume unbounded memory.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# Default seconds before an unresponsive upstream is abandoned (-> 502).
DEFAULT_TIMEOUT = 10.0


@dataclass
class ProxyResult:
    """Structured form of a forwarded response (also unpacks as a 3-tuple)."""

    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    def as_tuple(self) -> Tuple[int, Dict[str, str], bytes]:
        return self.status, self.headers, self.body

    def __iter__(self):  # allow: status, headers, body = result
        return iter(self.as_tuple())


def _open_conn(
    host: str,
    port: int,
    use_https: bool,
    timeout: float,
) -> http.client.HTTPConnection:
    """Open a connection to the configured upstream.

    This is the single network seam of the module. Tests monkeypatch
    ``proxy._open_conn`` with a fake that returns an object exposing the same
    surface used by :meth:`UpstreamProxy.forward` (``request``, ``getresponse``,
    ``close``), so the proxy logic can be verified entirely offline.
    """
    if use_https:
        return http.client.HTTPSConnection(host, port, timeout=timeout)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _append_forwarded_for(existing: Optional[str], client_ip: str) -> str:
    """Append the socket peer to an existing X-Forwarded-For chain.

    The caller passes the *unspoofable* TCP peer. We append rather than replace
    so an already-present (header-asserted) chain is preserved for the
    attribution layer to judge, with the trustworthy hop on the right.
    """
    client_ip = (client_ip or "").strip()
    existing = (existing or "").strip()
    if existing and client_ip:
        return f"{existing}, {client_ip}"
    return client_ip or existing


class UpstreamProxy:
    """Forward an inbound request to one fixed upstream origin.

    Parameters
    ----------
    base_url:
        Scheme + host (+ optional port) of the real application, e.g.
        ``"https://app.internal:8443"`` or ``"http://127.0.0.1:9000"``. Any path
        in ``base_url`` is used as a prefix for the forwarded path.
    timeout:
        Seconds to wait on the upstream before returning a 502.
    """

    def __init__(self, base_url: str, timeout: float = DEFAULT_TIMEOUT) -> None:
        parts = urlsplit(base_url)
        scheme = (parts.scheme or "http").lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"unsupported upstream scheme: {scheme!r}")
        if not parts.hostname:
            raise ValueError(f"base_url has no host: {base_url!r}")

        self.base_url = base_url
        self.scheme = scheme
        self.use_https = scheme == "https"
        self.host = parts.hostname
        self.port = parts.port or (443 if self.use_https else 80)
        # Host header value the upstream should see (include non-default port).
        default_port = 443 if self.use_https else 80
        if parts.port and parts.port != default_port:
            self.host_header = f"{self.host}:{parts.port}"
        else:
            self.host_header = self.host
        # Optional path prefix from base_url (e.g. upstream mounted under /api).
        self.path_prefix = parts.path.rstrip("/")
        self.timeout = timeout

    # -- header hygiene ---------------------------------------------------

    def _filter_request_headers(
        self,
        headers: Dict[str, str],
        client_ip: Optional[str],
        client_proto: Optional[str],
    ) -> Dict[str, str]:
        """Drop hop-by-hop headers and set forwarding + Host headers."""
        out: Dict[str, str] = {}
        prior_xff: Optional[str] = None
        for name, value in (headers or {}).items():
            lname = name.lower()
            if lname in HOP_BY_HOP_HEADERS:
                continue
            if lname == "host":
                # We rewrite Host to the upstream; never forward the client's.
                continue
            if lname == "content-length":
                # Recomputed from the body we actually send to avoid desync.
                continue
            if lname == "x-forwarded-for":
                prior_xff = value
                continue  # re-added below in canonical form
            if lname == "x-forwarded-proto":
                continue  # re-added below from the real connection
            out[name] = value

        out["Host"] = self.host_header
        if client_ip:
            out["X-Forwarded-For"] = _append_forwarded_for(prior_xff, client_ip)
        elif prior_xff:
            out["X-Forwarded-For"] = prior_xff.strip()
        out["X-Forwarded-Proto"] = (client_proto or self.scheme).strip()
        return out

    @staticmethod
    def _filter_response_headers(
        pairs: List[Tuple[str, str]]
    ) -> Dict[str, str]:
        """Drop hop-by-hop headers from the upstream response."""
        out: Dict[str, str] = {}
        for name, value in pairs:
            if name.lower() in HOP_BY_HOP_HEADERS:
                continue
            out[name] = value
        return out

    # -- forwarding -------------------------------------------------------

    def _build_path(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        if self.path_prefix:
            return self.path_prefix + path
        return path

    def forward(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: bytes = b"",
        client_ip: Optional[str] = None,
        client_proto: Optional[str] = None,
    ) -> ProxyResult:
        """Relay a request to the upstream and return ``(status, headers, body)``.

        The return value is a :class:`ProxyResult`, which unpacks directly as a
        ``(int, dict, bytes)`` tuple.

        On any failure reaching or reading the upstream (connection refused,
        timeout, protocol error, oversized body) a ``502`` result is returned
        with a short diagnostic body; this method does not raise for upstream
        problems.
        """
        body = body or b""
        req_headers = self._filter_request_headers(headers, client_ip, client_proto)
        # Set an accurate Content-Length for the body we will actually send.
        if body or method.upper() in ("POST", "PUT", "PATCH"):
            req_headers["Content-Length"] = str(len(body))
        target = self._build_path(path)

        conn = None
        try:
            conn = _open_conn(self.host, self.port, self.use_https, self.timeout)
            conn.request(method, target, body=body, headers=req_headers)
            resp = conn.getresponse()
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                return ProxyResult(
                    status=502,
                    headers={"Content-Type": "text/plain; charset=utf-8"},
                    body=b"502 Bad Gateway: upstream response exceeded size limit",
                )
            resp_headers = self._filter_response_headers(resp.getheaders())
            return ProxyResult(status=resp.status, headers=resp_headers, body=raw)
        except Exception as exc:  # noqa: BLE001 - fail closed to a 502, never crash
            detail = type(exc).__name__
            return ProxyResult(
                status=502,
                headers={
                    "Content-Type": "text/plain; charset=utf-8",
                    "X-Proxy-Error": detail,
                },
                body=f"502 Bad Gateway: upstream unreachable ({detail})".encode("utf-8"),
            )
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001 - close is best-effort
                    pass

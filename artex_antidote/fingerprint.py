"""JA3/JA4-style TLS and HTTP client fingerprinting (defensive).

Spec item #11. This module turns the parameters a client advertises during a
TLS handshake (its ``ClientHello``) into a stable, comparable fingerprint. Two
different clients that share the exact same TLS stack and configuration produce
the same JA3 string and MD5, which lets a defender cluster traffic, recognise a
returning attacker toolkit across rotating source IPs, and flag a request whose
declared ``User-Agent`` disagrees with its real TLS stack (a classic sign of a
spoofed/automated client).

Nothing here attacks, probes, or contacts a third-party machine. Fingerprints
are computed from data the client itself already sent. An optional threat-intel
lookup is provided purely as a *local, mockable* seam (``_http_get_json``) that
is disabled/offline by default; it is never called implicitly.

Capturing a real ``ClientHello`` (and therefore a *true* JA3) requires
TLS-layer access -- a terminating proxy, load balancer, or a packet capture of
the handshake before it is decrypted. A plain WSGI/ASGI app sees only the
decrypted HTTP request and cannot reconstruct the cipher list. For those
deployments use :func:`client_header_fingerprint`, a pure-stdlib fallback that
fingerprints the ordered HTTP request headers instead. See INTEGRATION below.

Public API
----------
- :func:`ja3_string` / :func:`ja3_hash`     -- JA3 per the original spec.
- :func:`client_header_fingerprint`         -- SHA-256 HTTP-header fallback.
- :func:`is_grease`                         -- GREASE (RFC 8701) value test.
- :func:`lookup_known_bad`                  -- optional offline-by-default
                                               threat-intel lookup (seamed).

INTEGRATION
-----------
At the TLS-terminating edge (reverse proxy / LB) extract the ClientHello fields
and call ``ja3_hash(...)``; hand the resulting hash to the request path as, e.g.,
a trusted ``X-JA3`` header that your app reads into ``RequestEvent``. Where no
TLS-layer access exists, call ``client_header_fingerprint(request.headers)`` and
store it alongside ``evidence.header_fingerprint`` for correlation/clustering.
"""

from __future__ import annotations

import hashlib
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


# --- GREASE (RFC 8701) -------------------------------------------------------
# GREASE reserved values are injected by clients to keep the ecosystem tolerant
# of unknown values. The reference JA3 implementation strips them so that a
# client which randomises its GREASE values still fingerprints consistently.
_GREASE_VALUES = frozenset(
    0x0A0A + i * 0x1010 for i in range(16)
)  # 0x0a0a, 0x1a1a, ... 0xfafa


def is_grease(value: int) -> bool:
    """Return True if *value* is a TLS GREASE placeholder (RFC 8701)."""
    return value in _GREASE_VALUES


def _strip_grease(values: Iterable[int]) -> List[int]:
    return [v for v in values if not is_grease(v)]


def _join_field(values: Sequence[int], *, drop_grease: bool = True) -> str:
    """Render one JA3 field: decimal values joined by '-'.

    GREASE values are removed (per the JA3 reference) before joining. An empty
    field renders as the empty string, exactly as the spec requires.
    """
    vals = _strip_grease(values) if drop_grease else list(values)
    return "-".join(str(int(v)) for v in vals)


def ja3_string(
    tls_version: int,
    ciphers: Sequence[int],
    extensions: Sequence[int],
    curves: Sequence[int],
    ec_formats: Sequence[int],
    *,
    drop_grease: bool = True,
) -> str:
    """Build the canonical JA3 string from ClientHello fields.

    Format (sections joined by ``,``; values within a section by ``-``)::

        SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats

    - ``tls_version``: the ClientHello legacy_version (e.g. ``769`` == 0x0301,
      TLS 1.0). Order of the remaining lists is preserved as sent by the client.
    - GREASE values (RFC 8701) are stripped from ciphers/extensions/curves/
      formats by default so randomised GREASE does not perturb the fingerprint.

    Example (the canonical JA3 reference vector)::

        >>> ja3_string(769,
        ...     [47,53,5,10,49161,49162,49171,49172,50,56,19,4],
        ...     [0,10,11], [23,24,25], [0])
        '769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0'
    """
    return ",".join(
        (
            str(int(tls_version)),
            _join_field(ciphers, drop_grease=drop_grease),
            _join_field(extensions, drop_grease=drop_grease),
            _join_field(curves, drop_grease=drop_grease),
            _join_field(ec_formats, drop_grease=drop_grease),
        )
    )


def ja3_hash(
    tls_version: int,
    ciphers: Sequence[int],
    extensions: Sequence[int],
    curves: Sequence[int],
    ec_formats: Sequence[int],
    *,
    drop_grease: bool = True,
) -> str:
    """Return the MD5 hex digest of :func:`ja3_string` (the standard JA3 id).

    MD5 is used only to match the published JA3 format for interoperability with
    existing JA3 corpora; it is an identifier, not a security control.
    """
    s = ja3_string(
        tls_version, ciphers, extensions, curves, ec_formats, drop_grease=drop_grease
    )
    return hashlib.md5(s.encode("ascii")).hexdigest()


def client_header_fingerprint(
    headers: Mapping[str, str],
    *,
    include_values: bool = False,
) -> str:
    """Stdlib fallback fingerprint over ORDERED HTTP request headers.

    When the raw ClientHello is unavailable (the common WSGI/ASGI case), the
    *order and casing* of a client's HTTP headers is still a useful, if weaker,
    discriminator between browsers and automated tooling. This returns a stable
    SHA-256 hex digest.

    - ``include_values=False`` (default): fingerprint the header-name sequence
      only (names lower-cased). This captures the client's header *ordering*
      without hashing volatile values (cookies, tokens), so it stays stable for
      a given client across requests and is privacy-preserving.
    - ``include_values=True``: also fold in each header's value, yielding a
      per-request digest.

    Determinism: the same ``headers`` mapping (same insertion order) always
    yields the same digest. Distinct from :func:`evidence.header_fingerprint`,
    which sorts headers and so discards ordering; this one deliberately
    preserves order.
    """
    h = hashlib.sha256()
    for name, value in headers.items():
        h.update(name.lower().encode("utf-8", "replace"))
        if include_values:
            h.update(b"=")
            h.update(str(value).encode("utf-8", "replace"))
        h.update(b"\n")
    return h.hexdigest()


# --- Optional threat-intel enrichment (OFFLINE BY DEFAULT, MOCKABLE) ---------
#
# This is a seam, not a dependency. By default it performs no I/O and returns
# None. A deployment may monkeypatch / replace ``_http_get_json`` to consult a
# *local* allow/deny JA3 feed it already trusts. Tests patch this seam; they
# never touch the network.


def _http_get_json(url: str, timeout: float = 2.0) -> Optional[dict]:  # pragma: no cover
    """Network seam for an optional JA3 reputation lookup.

    Returns ``None`` by default (no network access). Override this module-level
    function to integrate a local threat-intel feed. Intentionally does nothing
    on its own so the module is safe and fully offline out of the box.
    """
    return None


def lookup_known_bad(
    ja3: str,
    feed_url: str = "",
) -> Optional[Tuple[bool, dict]]:
    """Optionally check a JA3 hash against a reputation feed via the seam.

    Returns ``None`` when no feed is configured or the seam yields nothing
    (the default, offline behaviour). Otherwise returns ``(is_known_bad,
    detail)`` where ``detail`` is whatever the feed returned. This never raises
    on a seam that returns ``None`` and performs no I/O itself.
    """
    if not feed_url:
        return None
    data = _http_get_json(f"{feed_url.rstrip('/')}/{ja3}")
    if not data:
        return None
    return bool(data.get("malicious", False)), data


__all__ = [
    "ja3_string",
    "ja3_hash",
    "client_header_fingerprint",
    "is_grease",
    "lookup_known_bad",
]

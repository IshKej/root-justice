"""TLS termination for the Root Justice edge shield (design #2 TLS termination).

This module builds a hardened :class:`ssl.SSLContext` for terminating HTTPS in
front of the shield server (:mod:`artex_antidote.server`) and wraps an existing
``http.server`` instance's listening socket with it.

Everything here is strictly defensive: it only configures *inbound* server-side
TLS for sockets the operator already owns. It never generates private keys,
never reaches out to any third-party host, and never performs any outbound
connection. A self-signed deployment is supported only by pointing at a cert and
key file the operator produced out-of-band (for example with ``openssl``); this
module will *not* mint keys for you.

Typical use with the reference server::

    from http.server import ThreadingHTTPServer
    from artex_antidote.server import ShieldEngine, make_handler
    from artex_antidote.tlsconf import build_ssl_context, wrap_server_socket

    engine = ShieldEngine(enforce=False)
    httpd = ThreadingHTTPServer(("0.0.0.0", 8443), make_handler(engine))
    ctx = build_ssl_context("server.crt", "server.key")
    wrap_server_socket(httpd, ctx)   # now terminates TLS on every accept()
    httpd.serve_forever()

Standard library only. No third-party runtime dependencies.
"""

from __future__ import annotations

import ssl
from pathlib import Path
from typing import Any, Optional

__all__ = [
    "TLSConfigError",
    "DEFAULT_MIN_VERSION",
    "build_ssl_context",
    "self_signed_context",
    "wrap_server_socket",
]

# Default minimum protocol floor. TLS 1.2 is the lowest version considered
# acceptable; TLS 1.0/1.1 are intentionally excluded.
DEFAULT_MIN_VERSION = ssl.TLSVersion.TLSv1_2


class TLSConfigError(ValueError):
    """Raised when TLS configuration inputs are missing or invalid.

    Subclasses :class:`ValueError` so existing ``except ValueError`` handlers in
    callers keep working while allowing precise ``except TLSConfigError`` use.
    """


def _require_readable_file(path: str, role: str) -> Path:
    """Return ``path`` as a :class:`~pathlib.Path`, or raise a clear error.

    ``role`` is a human label (``"certificate"`` / ``"private key"``) used in the
    error message so the operator can tell which file is at fault.
    """
    if not path:
        raise TLSConfigError(f"TLS {role} path is empty; a {role} file is required")
    candidate = Path(path)
    if not candidate.exists():
        raise TLSConfigError(f"TLS {role} file not found: {path!r}")
    if not candidate.is_file():
        raise TLSConfigError(f"TLS {role} path is not a regular file: {path!r}")
    return candidate


def build_ssl_context(
    certfile: str,
    keyfile: str,
    min_version: ssl.TLSVersion = DEFAULT_MIN_VERSION,
) -> ssl.SSLContext:
    """Build a hardened server-side :class:`ssl.SSLContext` for TLS termination.

    Parameters
    ----------
    certfile:
        Path to the PEM server certificate (chain). Must exist.
    keyfile:
        Path to the PEM private key for ``certfile``. Must exist.
    min_version:
        Minimum negotiated TLS version; defaults to TLS 1.2. Anything below
        TLS 1.2 (SSLv3, TLS 1.0, TLS 1.1) is rejected because those versions are
        obsolete and insecure.

    Returns
    -------
    ssl.SSLContext
        A ``PROTOCOL_TLS_SERVER`` context with the key pair loaded, the version
        floor applied, and compression disabled (CRIME mitigation).

    Raises
    ------
    TLSConfigError
        If either file is missing/unreadable, if ``min_version`` is below
        TLS 1.2, or if the key pair fails to load (bad PEM, mismatched key).
    """
    cert_path = _require_readable_file(certfile, "certificate")
    key_path = _require_readable_file(keyfile, "private key")

    if not isinstance(min_version, ssl.TLSVersion):
        raise TLSConfigError(
            "min_version must be an ssl.TLSVersion, "
            f"got {type(min_version).__name__}"
        )
    if min_version < ssl.TLSVersion.TLSv1_2:
        raise TLSConfigError(
            f"min_version {min_version!r} is below TLS 1.2 and is not permitted; "
            "use ssl.TLSVersion.TLSv1_2 or higher"
        )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = min_version
    # Defensive hardening: no TLS compression (CRIME), prefer server order where
    # applicable. These are best-effort; options always present in stdlib ssl.
    context.options |= ssl.OP_NO_COMPRESSION

    try:
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    except ssl.SSLError as exc:
        raise TLSConfigError(
            f"failed to load TLS key pair (cert={certfile!r}, key={keyfile!r}): {exc}"
        ) from exc

    return context


def self_signed_context(
    certfile: str,
    keyfile: str,
    min_version: ssl.TLSVersion = DEFAULT_MIN_VERSION,
) -> ssl.SSLContext:
    """Build a context from an *existing* self-signed cert/key pair.

    This is a thin, clearly-named convenience wrapper over
    :func:`build_ssl_context` for the common local/self-signed deployment. It
    deliberately does **not** generate keys: the operator must already have a
    cert and key on disk (for example produced with ``openssl req -x509``). The
    separate name documents intent at the call site.

    Raises
    ------
    TLSConfigError
        Same conditions as :func:`build_ssl_context`.
    """
    return build_ssl_context(certfile, keyfile, min_version=min_version)


def wrap_server_socket(httpd: Any, context: ssl.SSLContext) -> ssl.SSLContext:
    """Wrap an ``http.server`` instance's listening socket for TLS termination.

    After this call, every connection the server ``accept()``s is wrapped as the
    server side of a TLS handshake using ``context``. Works with
    :class:`http.server.HTTPServer` and :class:`~http.server.ThreadingHTTPServer`
    (anything exposing a ``.socket`` attribute).

    The wrap uses ``server_side=True`` and ``do_handshake_on_connect=False`` so
    the handshake runs inside the request-handler thread (the standard pattern
    for threaded HTTP servers) rather than blocking the accept loop.

    Parameters
    ----------
    httpd:
        An object with a ``socket`` attribute (a bound/listening socket).
    context:
        The :class:`ssl.SSLContext` to terminate with, e.g. from
        :func:`build_ssl_context`.

    Returns
    -------
    ssl.SSLContext
        The same ``context``, for call chaining.

    Raises
    ------
    TLSConfigError
        If ``httpd`` has no ``socket`` attribute or ``context`` is not an
        :class:`ssl.SSLContext`.
    """
    if not isinstance(context, ssl.SSLContext):
        raise TLSConfigError(
            f"context must be an ssl.SSLContext, got {type(context).__name__}"
        )
    sock = getattr(httpd, "socket", None)
    if sock is None:
        raise TLSConfigError(
            "httpd has no 'socket' attribute; expected an http.server instance"
        )
    httpd.socket = context.wrap_socket(
        sock,
        server_side=True,
        do_handshake_on_connect=False,
    )
    return context

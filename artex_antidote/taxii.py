"""TAXII 2.1 client for sharing STIX cyber-threat intelligence (defensive).

This module lets Root Justice / Artex Antidote *publish* its own observed
indicators (attacker IPs, scanning indicators) to a TAXII 2.1 server that the
operator runs or is authorized to post to -- for example a sharing community
(ISAC/ISAO) collection. It is strictly outbound sharing of the defender's own
evidence; it never fetches, scans, or reaches into a third party's machine.

Design goals
------------
* **Stdlib only.** The default network seam is a module-level ``_http_request``
  built on :mod:`urllib.request`. Tests monkeypatch that function (or inject a
  fake ``transport`` callable) so everything runs offline with no network.
* **Mockable transport.** ``Taxii21Client(api_root, token, transport=...)``
  accepts any callable ``transport(method, url, headers, body) -> dict`` that
  returns ``{"status": int, "headers": dict, "body": <decoded JSON or str>}``.
  When omitted, the client uses :func:`_http_request`.
* **Correct TAXII 2.1 wire format.** Endpoints, the
  ``application/taxii+json;version=2.1`` media type, bearer auth, and the
  ``{"objects": [...]}`` envelope all follow OASIS TAXII 2.1.

Typical use::

    client = Taxii21Client("https://taxii.example.org/api1", token="SECRET")
    client.discover_collections()                      # list collections
    client.push_objects("<collection-id>", stix_bundle)  # publish indicators
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

__all__ = ["Taxii21Client", "TaxiiError", "TAXII_MEDIA_TYPE", "_http_request"]

#: The TAXII 2.1 media type used for both ``Accept`` and ``Content-Type``.
TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"

#: Transport callable signature:
#: ``(method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Dict``
#: returning ``{"status": int, "headers": Dict[str, str], "body": Any}``.
Transport = Callable[[str, str, Dict[str, str], Optional[bytes]], Dict[str, Any]]


class TaxiiError(RuntimeError):
    """Raised when the TAXII server returns a non-2xx response."""

    def __init__(self, status: int, url: str, body: Any) -> None:
        super().__init__(f"TAXII request to {url} failed with HTTP {status}: {body!r}")
        self.status = status
        self.url = url
        self.body = body


def _http_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[bytes],
) -> Dict[str, Any]:
    """Default network seam (stdlib ``urllib``). Monkeypatch this in tests.

    Returns ``{"status", "headers", "body"}`` where ``body`` is parsed JSON when
    the response declares a JSON/TAXII media type, otherwise the raw text.
    This is the ONLY function in this module that performs network I/O, so
    tests replace it (or inject a ``transport``) to stay fully offline.
    """
    req = urllib.request.Request(url=url, method=method, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310 - caller-controlled TAXII URL
            raw = resp.read()
            status = resp.getcode()
            resp_headers = {k: v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:  # non-2xx still carries a body
        raw = exc.read()
        status = exc.code
        resp_headers = {k: v for k, v in (exc.headers or {}).items()}
    text = raw.decode("utf-8") if raw else ""
    ctype = resp_headers.get("Content-Type", "")
    parsed: Any = text
    if text and ("json" in ctype or "taxii" in ctype):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = text
    return {"status": status, "headers": resp_headers, "body": parsed}


class Taxii21Client:
    """A minimal TAXII 2.1 client for publishing STIX objects.

    Parameters
    ----------
    api_root:
        The TAXII 2.1 API Root URL, e.g. ``https://taxii.example.org/api1``.
        A trailing slash is optional and normalized away.
    token:
        The bearer token used for ``Authorization: Bearer <token>``. May be
        empty/``None`` only for servers that need no auth (the header is then
        omitted).
    transport:
        Optional callable ``(method, url, headers, body) -> dict`` used instead
        of :func:`_http_request`. Supply a fake in tests to record requests and
        avoid the network.
    """

    def __init__(
        self,
        api_root: str,
        token: str,
        transport: Optional[Transport] = None,
    ) -> None:
        if not api_root:
            raise ValueError("api_root is required")
        self.api_root = api_root.rstrip("/")
        self.token = token
        self._transport: Transport = transport if transport is not None else _http_request

    # -- URL + header construction -------------------------------------------------

    def _objects_url(self, collection_id: str) -> str:
        """Build ``<api_root>/collections/<id>/objects/`` (trailing slash per spec)."""
        if not collection_id:
            raise ValueError("collection_id is required")
        return f"{self.api_root}/collections/{collection_id}/objects/"

    def _collections_url(self) -> str:
        """Build ``<api_root>/collections/`` (trailing slash per spec)."""
        return f"{self.api_root}/collections/"

    def _headers(self, *, with_content_type: bool) -> Dict[str, str]:
        """Assemble TAXII 2.1 request headers (Accept, optional Content-Type, auth)."""
        headers: Dict[str, str] = {"Accept": TAXII_MEDIA_TYPE}
        if with_content_type:
            headers["Content-Type"] = TAXII_MEDIA_TYPE
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    # -- public API ----------------------------------------------------------------

    @staticmethod
    def _as_envelope(stix_bundle: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a STIX bundle (or an already-shaped envelope) to a TAXII envelope.

        TAXII 2.1 POSTs an *envelope* -- ``{"objects": [...]}`` -- not a STIX
        bundle. We accept either a bundle (``{"type": "bundle", "objects": [...]}``)
        or something that already carries ``objects`` and normalize to the
        envelope shape, dropping bundle-only keys like ``type``/``id``.
        """
        objects = stix_bundle.get("objects")
        if objects is None:
            raise ValueError("stix_bundle must contain an 'objects' list")
        if not isinstance(objects, list):
            raise ValueError("stix_bundle['objects'] must be a list")
        return {"objects": objects}

    def push_objects(self, collection_id: str, stix_bundle: Dict[str, Any]) -> Dict[str, Any]:
        """POST the bundle's objects to a collection; return the parsed response body.

        Builds the ``.../collections/<id>/objects/`` endpoint, the
        ``application/taxii+json;version=2.1`` Accept + Content-Type headers, the
        bearer Authorization header, and the ``{"objects": [...]}`` envelope body.
        A TAXII server replies with a *status resource* describing the ingest.
        """
        url = self._objects_url(collection_id)
        headers = self._headers(with_content_type=True)
        envelope = self._as_envelope(stix_bundle)
        body = json.dumps(envelope).encode("utf-8")
        resp = self._transport("POST", url, headers, body)
        return self._unwrap(resp, url)

    def discover_collections(self) -> List[Dict[str, Any]]:
        """GET ``.../collections/`` and return the list of collection resources."""
        url = self._collections_url()
        headers = self._headers(with_content_type=False)
        resp = self._transport("GET", url, headers, None)
        parsed = self._unwrap(resp, url)
        if isinstance(parsed, dict):
            collections = parsed.get("collections", [])
            return collections if isinstance(collections, list) else []
        return []

    # -- helpers -------------------------------------------------------------------

    @staticmethod
    def _unwrap(resp: Dict[str, Any], url: str) -> Any:
        """Raise :class:`TaxiiError` on non-2xx, else return the response body."""
        status = resp.get("status", 0)
        body = resp.get("body")
        if not (200 <= int(status) < 300):
            raise TaxiiError(int(status), url, body)
        return body

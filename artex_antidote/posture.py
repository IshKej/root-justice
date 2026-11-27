"""Public-exposure posture auditing for the operator's OWN storage (GAP #1).

This module is a strictly *defensive* blue-team tool. It helps an operator audit
whether object-storage URLs **they own or control** (S3 buckets, Google Cloud
Storage buckets, Azure Blob containers) are unintentionally world-readable, and
it hands back a concrete hardening checklist. It never attacks third parties and
has no offensive capability: a "check" here is a single harmless HTTP probe of a
URL the operator already supplied, interpreting the public response the same way
a passer-by's browser would.

All outbound I/O is funneled through the module-level :func:`_http_probe` seam so
tests (and cautious operators) can monkeypatch it and run completely offline. The
library performs no timing, randomness, or clock reads of its own: callers pass
anything time-dependent in. Nothing here requires admin rights.

Verdicts
--------
``PUBLIC``
    The URL answered with a success status (2xx) and a body that looks like real
    bucket content or a directory listing. This is the finding to act on.
``PRIVATE``
    The URL answered with an access-denied status (401 / 403). The bucket is
    refusing anonymous reads, which is the desired posture.
``UNKNOWN``
    Anything else (404, 5xx, network error, ambiguous body). Not classified as
    either safe or exposed; investigate manually.

Typical use::

    from artex_antidote import posture

    results = posture.audit([
        "https://my-logs.s3.amazonaws.com/",
        "https://storage.googleapis.com/my-private-bucket/",
    ])
    for r in results:
        print(r["url"], r["status"], r["verdict"])

    if any(r["verdict"] == "PUBLIC" for r in results):
        for step in posture.posture_checklist():
            print("-", step)

Standard library only. No third-party runtime dependencies.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Callable, List, Tuple
from urllib.parse import urlsplit

__all__ = [
    "PUBLIC",
    "PRIVATE",
    "UNKNOWN",
    "PostureError",
    "classify_response",
    "detect_provider",
    "check_bucket",
    "audit",
    "posture_checklist",
]

PUBLIC = "PUBLIC"
PRIVATE = "PRIVATE"
UNKNOWN = "UNKNOWN"

# Default read budget for the harmless probe. Small, because a real exposed
# bucket reveals itself in the first few hundred bytes of a listing.
_SNIPPET_BYTES = 2048

# Statuses that unambiguously mean "anonymous access refused".
_DENIED_STATUSES = frozenset({401, 403})

# Substrings that indicate a world-readable listing or real object content.
# These are matched case-insensitively against the returned body snippet.
_PUBLIC_MARKERS = (
    "<listbucketresult",        # S3 anonymous bucket listing XML
    "<enumerationresults",      # Azure Blob container listing XML
    "<?xml",                    # generic XML listing (GCS/S3 style)
    "<Contents>".lower(),       # S3 object entries
    "<Blob>".lower(),           # Azure blob entries
    '"items"',                  # GCS JSON listing
    '"kind": "storage',         # GCS JSON API payload
    "index of /",               # generic autoindex pages
)

# Substrings that indicate the service explicitly denied anonymous access even
# though the HTTP status was not one of the classic 401/403 codes.
_DENIED_MARKERS = (
    "<code>accessdenied</code>",
    "accessdenied",
    "authorizationpermissionmismatch",
    "all access to this object has been disabled",
    "anonymous caller does not have",
    "publicaccessnotpermitted",
)


class PostureError(ValueError):
    """Raised when posture inputs are missing or malformed.

    Subclasses :class:`ValueError` so existing ``except ValueError`` handlers
    keep working while allowing precise ``except PostureError`` use.
    """


def _http_probe(url: str) -> Tuple[int, str]:
    """Perform a single harmless anonymous GET and return ``(status, snippet)``.

    This is the module's only network seam. Tests monkeypatch it; real callers
    get a plain, unauthenticated GET of a URL the operator supplied. At most
    :data:`_SNIPPET_BYTES` of the body are read and decoded leniently, so a huge
    object never pulls a large payload.

    On an HTTP error status the status code is still returned together with any
    error body (that is how a 403 AccessDenied page is classified). On a
    transport-level failure (DNS, connection refused, timeout) ``(0, "")`` is
    returned so the URL lands in ``UNKNOWN`` rather than raising.

    No credentials, cookies, or operator identity are ever attached.
    """
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # nosec - operator's own asset
            status = int(getattr(response, "status", 0) or response.getcode() or 0)
            raw = response.read(_SNIPPET_BYTES)
            return status, raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:  # noqa: PERF203 - clarity over micro-perf
        try:
            raw = exc.read(_SNIPPET_BYTES)
        except Exception:
            raw = b""
        body = raw.decode("utf-8", errors="replace") if raw else ""
        return int(exc.code), body
    except (urllib.error.URLError, OSError, ValueError):
        return 0, ""


def detect_provider(url: str) -> str:
    """Return the storage provider shape implied by ``url``.

    Recognizes the common S3, Google Cloud Storage, and Azure Blob URL shapes.
    Returns one of ``"s3"``, ``"gcs"``, ``"azure"``, or ``"unknown"``. This is a
    best-effort label for the report only; classification does not depend on it.
    """
    host = (urlsplit(url).hostname or "").lower()
    if not host:
        return "unknown"
    if "amazonaws.com" in host or host.endswith(".s3") or ".s3." in host or ".s3-" in host:
        return "s3"
    if "storage.googleapis.com" in host or host.endswith(".storage.googleapis.com"):
        return "gcs"
    if "blob.core.windows.net" in host:
        return "azure"
    return "unknown"


def classify_response(status: int, body_snippet: str) -> str:
    """Classify a probe ``(status, body_snippet)`` as PUBLIC / PRIVATE / UNKNOWN.

    Rules, in order:

    1. A 401/403 status, or a body carrying an explicit access-denied marker, is
       :data:`PRIVATE` (anonymous access refused -- the desired state).
    2. A 2xx status whose body looks like a bucket listing or real object
       content is :data:`PUBLIC`.
    3. Everything else (404, 5xx, status 0/network error, empty or ambiguous
       body) is :data:`UNKNOWN`.
    """
    body = (body_snippet or "").lower()

    if status in _DENIED_STATUSES:
        return PRIVATE
    if any(marker in body for marker in _DENIED_MARKERS):
        return PRIVATE

    if 200 <= status < 300:
        if any(marker in body for marker in _PUBLIC_MARKERS):
            return PUBLIC
        # A 2xx with a non-empty body from a storage endpoint is still a real
        # anonymous read of operator content, so treat substantive bodies as
        # public exposure even without a recognized listing marker.
        if body.strip():
            return PUBLIC
        return UNKNOWN

    return UNKNOWN


def check_bucket(
    url: str,
    fetch: Callable[[str], Tuple[int, str]] = _http_probe,
) -> dict:
    """Audit a single storage ``url`` for world-readability.

    Parameters
    ----------
    url:
        A storage URL the operator owns/controls (S3, GCS, or Azure shape). Must
        be a non-empty ``http``/``https`` URL.
    fetch:
        The probe seam, ``fetch(url) -> (status: int, body_snippet: str)``.
        Defaults to :func:`_http_probe`. Tests pass a fake here to stay offline.

    Returns
    -------
    dict
        ``{"url", "provider", "status", "verdict"}`` where ``verdict`` is one of
        :data:`PUBLIC`, :data:`PRIVATE`, :data:`UNKNOWN`.

    Raises
    ------
    PostureError
        If ``url`` is empty / not a string / not an http(s) URL, or if ``fetch``
        is not callable. A ``fetch`` that itself raises is caught and reported as
        an ``UNKNOWN`` verdict (status 0) rather than propagating, so a single
        bad asset never aborts a batch :func:`audit`.
    """
    if not isinstance(url, str) or not url.strip():
        raise PostureError("url must be a non-empty string")
    scheme = urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise PostureError(
            f"url must be an http(s) URL for an asset you control, got {url!r}"
        )
    if not callable(fetch):
        raise PostureError("fetch must be callable: fetch(url) -> (status, snippet)")

    provider = detect_provider(url)

    try:
        status, snippet = fetch(url)
    except Exception:
        # Defensive: a probe seam failure degrades to UNKNOWN, never crashes.
        return {"url": url, "provider": provider, "status": 0, "verdict": UNKNOWN}

    try:
        status_int = int(status)
    except (TypeError, ValueError):
        status_int = 0

    verdict = classify_response(status_int, snippet)
    return {"url": url, "provider": provider, "status": status_int, "verdict": verdict}


def audit(
    urls,
    fetch: Callable[[str], Tuple[int, str]] = _http_probe,
) -> List[dict]:
    """Audit many storage URLs, returning one result dict per URL.

    Parameters
    ----------
    urls:
        An iterable of storage URLs the operator owns/controls.
    fetch:
        The probe seam shared across all checks (see :func:`check_bucket`).

    Returns
    -------
    list[dict]
        One :func:`check_bucket` result per input URL, in input order.

    Raises
    ------
    PostureError
        If ``urls`` is not iterable, or any element is not a valid http(s) URL.
    """
    if isinstance(urls, (str, bytes)):
        raise PostureError("urls must be an iterable of URLs, not a single string")
    try:
        url_list = list(urls)
    except TypeError as exc:
        raise PostureError("urls must be an iterable of URLs") from exc

    return [check_bucket(url, fetch=fetch) for url in url_list]


def summarize(results) -> dict:
    """Aggregate a list of :func:`audit` results into verdict counts.

    Returns ``{"total", "public", "private", "unknown", "public_urls"}`` where
    ``public_urls`` lists the URLs that need immediate remediation. Useful for a
    one-line dashboard / CLI summary.
    """
    results = list(results)
    public_urls = [r["url"] for r in results if r.get("verdict") == PUBLIC]
    return {
        "total": len(results),
        "public": sum(1 for r in results if r.get("verdict") == PUBLIC),
        "private": sum(1 for r in results if r.get("verdict") == PRIVATE),
        "unknown": sum(1 for r in results if r.get("verdict") == UNKNOWN),
        "public_urls": public_urls,
    }


def posture_checklist() -> List[str]:
    """Return concrete hardening steps for locking down public buckets.

    Provider-agnostic, ordered roughly from highest to lowest leverage. The
    operator applies these in their cloud console/IaC; this tool only reports.
    """
    return [
        "Enable the account/bucket-level 'Block Public Access' control so no "
        "policy or ACL can make objects world-readable.",
        "Review and tighten the bucket policy: remove any statement granting "
        "Principal '*' (anonymous) or 'AllUsers'/'AllAuthenticatedUsers' read.",
        "Disable object ACLs and enforce bucket-owner-only (e.g. S3 Object "
        "Ownership = BucketOwnerEnforced) so per-object ACLs cannot re-open access.",
        "Enable server access logging / data-access audit logs so any future "
        "anonymous read attempt is recorded.",
        "Require TLS-only access via a bucket policy condition denying "
        "non-HTTPS (aws:SecureTransport=false) requests.",
        "Turn on default server-side encryption for data at rest.",
        "Re-run this posture audit after changes and add it to CI so a bucket "
        "never silently drifts back to public.",
    ]

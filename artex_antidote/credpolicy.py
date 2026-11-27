"""Credential policy & hardening (GAP #3) -- DEFENSIVE: make stolen hashes useless.

This module helps an operator audit the password hashes stored for THEIR OWN
assets. It never cracks anything. Instead it:

* ``classify_hash`` -- tells apart WEAK storage schemes (bare unsalted MD5 /
  SHA1 / SHA256 hex digests) from STRONG, slow, salted schemes (bcrypt,
  argon2id, scrypt, high-iteration PBKDF2) and recommends a fix.
* ``hibp_range_check`` -- queries Have I Been Pwned's *k-anonymity* range API,
  sending only the first 5 characters of a SHA1 hash so the full hash never
  leaves the host, and reports how many breaches a password appears in.
* ``argon2id_recommended_params`` -- current OWASP-aligned argon2id parameters.
* ``password_policy_report`` -- rolls a sample of stored hashes into a single
  posture report an operator can act on.

STRICTLY DEFENSIVE. All network I/O goes through the module-level ``_http_get``
seam, which tests monkeypatch, so the module is fully testable offline and
deterministically. Callers pass any timestamps; this module uses no clock and
no randomness.
"""

from __future__ import annotations

import hashlib
import re
import urllib.request
from typing import Callable, Dict, List, Optional

__all__ = [
    "classify_hash",
    "hibp_range_check",
    "argon2id_recommended_params",
    "password_policy_report",
    "sha1_hex_of",
]

# ---------------------------------------------------------------------------
# Network seam (monkeypatched in tests; never touched offline).
# ---------------------------------------------------------------------------


def _http_get(url: str, timeout: float = 6.0) -> str:
    """Fetch a URL over HTTPS and return the body as text.

    Single seam so credential checks are testable offline. Only http(s) URLs
    are accepted; anything else (e.g. ``file://``) is rejected so a caller
    cannot be tricked into reading a local file.
    """
    if not re.match(r"^https?://", url, re.IGNORECASE):
        raise ValueError(f"refusing non-http(s) URL: {url!r}")
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "text/plain",
            # Padding asks HIBP to pad the response so the real count can't be
            # inferred from response size; harmless if the endpoint ignores it.
            "Add-Padding": "true",
            "User-Agent": "RootJustice/0.1",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (scheme checked above)
        return resp.read().decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Hash classification.
# ---------------------------------------------------------------------------

# Bare hex digests of common fast/unsalted hashes, keyed by hex length.
_BARE_HEX_SCHEMES: Dict[int, str] = {
    32: "md5",
    40: "sha1",
    56: "sha224",
    64: "sha256",
    96: "sha384",
    128: "sha512",
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# Modular-crypt / PHC prefixes for strong, salted, deliberately-slow schemes.
# Each entry: canonical scheme name.
_STRONG_PREFIXES = [
    ("$argon2id$", "argon2id"),
    ("$argon2i$", "argon2i"),
    ("$argon2d$", "argon2d"),
    ("$2a$", "bcrypt"),
    ("$2b$", "bcrypt"),
    ("$2y$", "bcrypt"),
    ("$scrypt$", "scrypt"),
    ("$7$", "scrypt"),  # crypt(3) scrypt form
    ("$6$", "sha512crypt"),
    ("$5$", "sha256crypt"),
    ("$y$", "yescrypt"),
    ("$gy$", "yescrypt"),
]

# PBKDF2 iteration floor below which the scheme is considered weak (OWASP
# guidance is >= 600k for PBKDF2-HMAC-SHA256; we flag clearly-low configs).
_PBKDF2_WEAK_ITER = 100_000


def _parse_pbkdf2(h: str) -> Optional[int]:
    """Return the iteration count if ``h`` is a recognizable PBKDF2 hash, else None.

    Handles both the Django/passlib form ``pbkdf2_sha256$<iters>$<salt>$<hash>``
    and the PHC form ``$pbkdf2-sha256$i=<iters>$...``.
    """
    low = h.lower()
    # Django / passlib style: algo$iterations$salt$hash
    m = re.match(r"^pbkdf2(?:_[a-z0-9]+)?\$(\d+)\$", low)
    if m:
        return int(m.group(1))
    # PHC style: $pbkdf2-sha256$i=29000$...
    m = re.match(r"^\$pbkdf2(?:-[a-z0-9]+)?\$i=(\d+)", low)
    if m:
        return int(m.group(1))
    return None


def classify_hash(h: str) -> Dict[str, object]:
    """Classify a single stored password hash as WEAK or STRONG.

    Returns a dict with keys:

    * ``verdict`` -- ``"WEAK"``, ``"STRONG"`` or ``"UNKNOWN"``.
    * ``scheme``  -- best-guess scheme name (e.g. ``"md5"``, ``"bcrypt"``).
    * ``salted``  -- ``True``/``False``/``None`` (None = couldn't tell).
    * ``reason``  -- short human-readable explanation.
    * ``recommendation`` -- concrete remediation advice.

    This performs *no* cracking; it only inspects structure.
    """
    result: Dict[str, object] = {
        "verdict": "UNKNOWN",
        "scheme": "unknown",
        "salted": None,
        "reason": "",
        "recommendation": "",
    }
    if not isinstance(h, str) or not h.strip():
        result["reason"] = "empty or non-string value"
        result["recommendation"] = "store a valid salted, slow password hash"
        return result

    s = h.strip()

    # 1. Strong modular-crypt / PHC prefixes.
    for prefix, name in _STRONG_PREFIXES:
        if s.startswith(prefix):
            result.update(
                verdict="STRONG",
                scheme=name,
                salted=True,
                reason=f"recognized salted, slow scheme ({name})",
                recommendation="no action needed; keep parameters current",
            )
            return result

    # 2. PBKDF2 -- strong only if the iteration count is high enough.
    iters = _parse_pbkdf2(s)
    if iters is not None:
        if iters >= _PBKDF2_WEAK_ITER:
            result.update(
                verdict="STRONG",
                scheme="pbkdf2",
                salted=True,
                reason=f"PBKDF2 with {iters} iterations (>= {_PBKDF2_WEAK_ITER})",
                recommendation="adequate; prefer argon2id for new deployments",
            )
        else:
            result.update(
                verdict="WEAK",
                scheme="pbkdf2",
                salted=True,
                reason=f"PBKDF2 with only {iters} iterations (< {_PBKDF2_WEAK_ITER})",
                recommendation=(
                    "raise iterations to >= 600000 (PBKDF2-HMAC-SHA256) "
                    "or migrate to argon2id"
                ),
            )
        return result

    # 3. Bare hex digest of a fast unsalted hash -> weak.
    if _HEX_RE.match(s) and len(s) in _BARE_HEX_SCHEMES:
        name = _BARE_HEX_SCHEMES[len(s)]
        result.update(
            verdict="WEAK",
            scheme=name,
            salted=False,
            reason=(
                f"bare {len(s)}-char hex digest looks like unsalted {name.upper()}; "
                "fast to brute-force and rainbow-table friendly"
            ),
            recommendation=(
                "rehash with argon2id (or bcrypt) on next successful login; "
                "never store bare/unsalted fast hashes"
            ),
        )
        return result

    # 4. Unknown structure.
    result["reason"] = "unrecognized hash structure"
    result["recommendation"] = (
        "verify the storage scheme; migrate to argon2id if it is not a slow, "
        "salted hash"
    )
    return result


# ---------------------------------------------------------------------------
# Have I Been Pwned k-anonymity range check.
# ---------------------------------------------------------------------------

_HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"


def sha1_hex_of(password: str) -> str:
    """Return the uppercase SHA1 hex digest of ``password``.

    Convenience for callers that start from a plaintext *they already hold*
    (e.g. validating a newly-chosen password against breach corpora before it
    is ever stored). The plaintext never leaves the process.
    """
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def hibp_range_check(
    sha1_hex: str,
    fetch: Callable[[str], str] = _http_get,
) -> Optional[int]:
    """Check a SHA1 password hash against HIBP using k-anonymity.

    Only the first **5 characters** of the SHA1 hash are ever sent to the
    remote service (the ``range`` endpoint). The remaining 35 characters stay
    local and are matched against the returned suffix list. This means the full
    hash -- and therefore the password -- is never disclosed.

    Args:
        sha1_hex: A 40-char hex SHA1 digest of the password (any case).
        fetch: Network seam ``fetch(url) -> body_text``. Defaults to
            ``_http_get``; tests pass a fake.

    Returns:
        The breach count (int, possibly 0 if the suffix is listed with 0) if
        the suffix is found, or ``None`` if the password does not appear in any
        known breach. Returns ``None`` on malformed input or fetch failure.
    """
    if not isinstance(sha1_hex, str):
        return None
    digest = sha1_hex.strip().upper()
    if len(digest) != 40 or not _HEX_RE.match(digest):
        return None

    prefix, suffix = digest[:5], digest[5:]
    url = _HIBP_RANGE_URL.format(prefix=prefix)

    try:
        body = fetch(url)
    except Exception:
        # Defensive: a breach-corpus lookup must never crash the audit.
        return None
    if not isinstance(body, str):
        return None

    for line in body.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        got_suffix, _, count_str = line.partition(":")
        if got_suffix.strip().upper() == suffix:
            try:
                return int(count_str.strip())
            except ValueError:
                return None
    return None


# ---------------------------------------------------------------------------
# Recommended parameters & posture report.
# ---------------------------------------------------------------------------


def argon2id_recommended_params() -> Dict[str, object]:
    """Return current OWASP-aligned argon2id parameters for new deployments.

    These are conservative defaults suitable for interactive logins. Operators
    should benchmark on their own hardware and raise ``time_cost`` /
    ``memory_cost`` until a single hash takes roughly 0.5--1.0 s.
    """
    return {
        "algorithm": "argon2id",
        "memory_cost_kib": 19456,  # 19 MiB
        "time_cost": 2,            # iterations
        "parallelism": 1,         # lanes/threads
        "salt_length_bytes": 16,
        "hash_length_bytes": 32,
        "note": (
            "OWASP minimum: m=19 MiB, t=2, p=1. Increase memory_cost first, "
            "then time_cost, until one hash takes ~0.5-1.0s on your hardware."
        ),
    }


def password_policy_report(
    sample_hashes: List[str],
    fetch: Callable[[str], str] = _http_get,
) -> Dict[str, object]:
    """Audit a sample of stored password hashes and summarize posture.

    For each hash in ``sample_hashes`` this classifies the scheme. It does NOT
    send stored hashes anywhere -- the ``fetch`` seam is accepted so a caller
    can optionally wire in breach checks elsewhere, but stored password hashes
    are opaque digests and are never transmitted here.

    Args:
        sample_hashes: Stored hashes to classify.
        fetch: Network seam (reserved; not used for stored-hash classification,
            which is purely structural and offline).

    Returns:
        A report dict with per-hash classifications, counts, a weak ratio and a
        prioritized recommendation list.
    """
    classifications: List[Dict[str, object]] = []
    counts = {"WEAK": 0, "STRONG": 0, "UNKNOWN": 0}
    scheme_tally: Dict[str, int] = {}

    for h in sample_hashes or []:
        c = classify_hash(h)
        classifications.append(c)
        verdict = str(c["verdict"])
        counts[verdict] = counts.get(verdict, 0) + 1
        scheme = str(c["scheme"])
        scheme_tally[scheme] = scheme_tally.get(scheme, 0) + 1

    total = len(classifications)
    weak_ratio = (counts["WEAK"] / total) if total else 0.0

    recommendations: List[str] = []
    if counts["WEAK"]:
        recommendations.append(
            f"{counts['WEAK']} weak hash(es) detected: migrate to argon2id "
            "(rehash on next successful login)."
        )
    if counts["UNKNOWN"]:
        recommendations.append(
            f"{counts['UNKNOWN']} hash(es) had an unrecognized structure: "
            "confirm their storage scheme."
        )
    if total and counts["STRONG"] == total:
        recommendations.append(
            "All sampled hashes use strong, salted, slow schemes. Keep "
            "parameters current (see argon2id_recommended_params)."
        )
    if not total:
        recommendations.append("No hashes sampled.")

    return {
        "total": total,
        "counts": counts,
        "weak_ratio": round(weak_ratio, 4),
        "schemes": scheme_tally,
        "classifications": classifications,
        "recommended_argon2id": argon2id_recommended_params(),
        "recommendations": recommendations,
    }

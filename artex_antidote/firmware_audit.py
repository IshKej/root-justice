"""Firmware / binary secret-leak auditor (GAP #5: secrets inside firmware).

STRICTLY DEFENSIVE. This module lets an operator scan THEIR OWN firmware image
or compiled binary *before shipping it* so that no hardcoded secret (API key,
private key, credential, high-entropy token) accidentally leaves the building.

Nothing here attacks a third party and nothing here executes the sample. The
scanner only reads bytes and applies regex / entropy heuristics. ``deep_scan``
optionally hands the file to ``attribution.run_rea_static_analysis`` for REA
*static* forensics -- that bridge is documented to never execute the target.

Design rules honoured here:
  * Pure library: callers supply everything; no ``random``/clock is used.
  * The only external-I/O path (REA) is reached through the existing
    ``attribution`` seam, which tests monkeypatch; ``scan_file`` touches only
    the local filesystem path the caller names and works fully offline.
  * Matched secret values are **redacted** in all output -- only the first and
    last few characters survive so a finding is actionable without re-leaking
    the secret into logs, reports or tickets.

Public API
----------
``scan_file(path, ...) -> dict``     regex + entropy scan of one file.
``deep_scan(path, ...) -> dict``     scan_file + optional REA static merge.
``redact(secret, ...) -> str``       redaction helper (first/last chars only).
``shannon_entropy(text) -> float``   bits-per-character Shannon entropy.
"""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

__all__ = [
    "scan_file",
    "deep_scan",
    "redact",
    "shannon_entropy",
    "DEFAULT_ENTROPY_THRESHOLD",
    "DEFAULT_ENTROPY_MIN_LEN",
]

# --------------------------------------------------------------------------- #
# Tunables (callers may override).
# --------------------------------------------------------------------------- #

#: Shannon entropy (bits/char) above which a token is treated as suspicious.
DEFAULT_ENTROPY_THRESHOLD: float = 4.3

#: A token must be at least this long before entropy is even considered, so
#: short-but-random-looking words do not create noise.
DEFAULT_ENTROPY_MIN_LEN: int = 24

#: Severity ranking used purely for sorting / reporting.
_SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}


# --------------------------------------------------------------------------- #
# Detectors. Each entry: (type, severity, compiled-regex, capture-group).
# The capture group identifies the exact substring to redact; group 0 means
# "redact the whole match".
# --------------------------------------------------------------------------- #

_DETECTORS: List[tuple] = [
    # AWS access key IDs: AKIA/ASIA/AGPA/... followed by 16 upper/alnum chars.
    (
        "aws_access_key",
        "critical",
        re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16})\b"),
        1,
    ),
    # PEM private-key block headers (RSA / EC / OPENSSH / PGP / generic).
    (
        "private_key_block",
        "critical",
        re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----"),
        0,
    ),
    # JSON Web Tokens: three base64url segments separated by dots.
    (
        "jwt",
        "high",
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
        0,
    ),
    # Generic assignment: api_key / apikey / secret / password / token = "...".
    (
        "generic_credential_assignment",
        "high",
        re.compile(
            r"""(?ix)
            \b(?:api[_-]?key|apikey|secret|secret[_-]?key|
                 password|passwd|pwd|token|auth[_-]?token|access[_-]?token)\b
            \s*[:=]\s*
            ['"]?
            (?P<val>[^\s'"]{6,})
            ['"]?
            """
        ),
        "val",
    ),
]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def shannon_entropy(text: str) -> float:
    """Return the Shannon entropy of *text* in bits per character.

    An empty string has entropy 0.0. A string drawn uniformly from N distinct
    symbols approaches log2(N) bits/char, so random base64 tokens score high
    (~5-6) while English words and structured identifiers score low.
    """
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    return entropy


def redact(secret: str, keep_start: int = 4, keep_end: int = 4) -> str:
    """Redact *secret*, revealing only the first/last few characters.

    ``"AKIAIOSFODNN7EXAMPLE"`` -> ``"AKIA************MPLE"``. Short secrets are
    fully masked so nothing recoverable survives. The returned string keeps the
    original length so reports still convey roughly how long the secret was.
    """
    if secret is None:
        return ""
    s = str(secret)
    n = len(s)
    if n == 0:
        return ""
    if n <= keep_start + keep_end:
        return "*" * n
    return f"{s[:keep_start]}{'*' * (n - keep_start - keep_end)}{s[-keep_end:]}"


# Tokens considered for entropy flagging: runs of key-like characters.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{%d,}" % DEFAULT_ENTROPY_MIN_LEN)


def _iter_lines(raw: bytes):
    """Yield (1-based line number, decoded text) over *raw* bytes.

    Firmware/binaries are not valid UTF-8, so we decode latin-1 (loss-free byte
    -> codepoint) and split on newlines. This keeps every printable ASCII run
    intact, which is exactly what the detectors operate on.
    """
    text = raw.decode("latin-1")
    for idx, line in enumerate(text.split("\n"), start=1):
        yield idx, line


# --------------------------------------------------------------------------- #
# Core scan
# --------------------------------------------------------------------------- #


def scan_file(
    path: str,
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    entropy_min_len: int = DEFAULT_ENTROPY_MIN_LEN,
    max_bytes: int = 64 * 1024 * 1024,
) -> Dict[str, Any]:
    """Scan a single firmware image or binary for leaked secrets.

    Reads the file at *path* (never executes it) and applies regex detectors
    plus a high-Shannon-entropy token detector. All matched secret values are
    redacted in the returned findings.

    Returns a dict::

        {
          "path": <str>,
          "findings": [
             {"type": <str>, "line": <int>, "redacted": <str>,
              "severity": <str>, "entropy": <float|None>},
             ...
          ],
          "secret_count": <int>,
          "status": "ok" | "error",
          # "error": <str>   (only when status == "error")
        }

    A clean file yields ``secret_count == 0`` and an empty ``findings`` list.
    """
    p = Path(path)
    if not p.exists() or not p.is_file():
        return {
            "path": str(p),
            "findings": [],
            "secret_count": 0,
            "status": "error",
            "error": f"Target not found or not a file: {p}",
        }

    try:
        raw = p.read_bytes()
    except OSError as exc:
        return {
            "path": str(p),
            "findings": [],
            "secret_count": 0,
            "status": "error",
            "error": f"Could not read target: {exc}",
        }

    if len(raw) > max_bytes:
        raw = raw[:max_bytes]

    findings: List[Dict[str, Any]] = []
    # Avoid flagging the same (type, line, redacted) triple twice.
    seen: set = set()

    for line_no, line in _iter_lines(raw):
        # -- regex detectors -------------------------------------------------
        for dtype, severity, regex, group in _DETECTORS:
            for m in regex.finditer(line):
                try:
                    value = m.group(group)
                except (IndexError, re.error):  # pragma: no cover - defensive
                    value = None
                if not value:
                    value = m.group(0)
                redacted = redact(value)
                key = (dtype, line_no, redacted)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    {
                        "type": dtype,
                        "line": line_no,
                        "redacted": redacted,
                        "severity": severity,
                        "entropy": round(shannon_entropy(value), 3),
                    }
                )

        # -- high-entropy token detector ------------------------------------
        for m in _TOKEN_RE.finditer(line):
            token = m.group(0)
            if len(token) < entropy_min_len:
                continue
            ent = shannon_entropy(token)
            if ent <= entropy_threshold:
                continue
            redacted = redact(token)
            key = ("high_entropy_token", line_no, redacted)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "type": "high_entropy_token",
                    "line": line_no,
                    "redacted": redacted,
                    "severity": "medium",
                    "entropy": round(ent, 3),
                }
            )

    findings.sort(
        key=lambda f: (-_SEVERITY_ORDER.get(f["severity"], 0), f["line"])
    )

    return {
        "path": str(p),
        "findings": findings,
        "secret_count": len(findings),
        "status": "ok",
    }


def deep_scan(
    path: str,
    run_rea: bool = True,
    rea_analyzer: Optional[Callable[[str], Dict[str, Any]]] = None,
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    entropy_min_len: int = DEFAULT_ENTROPY_MIN_LEN,
) -> Dict[str, Any]:
    """Run ``scan_file`` and OPTIONALLY merge REA static-analysis status.

    When *run_rea* is true, this calls ``attribution.run_rea_static_analysis``
    (or *rea_analyzer* if supplied -- the test seam) to obtain REA static
    forensics on the sample. REA is invoked statically and **never executes**
    the sample. Its status is merged into the result under ``"rea"``; a failure
    or absence of the REA bridge degrades gracefully and never raises.

    Returns the ``scan_file`` dict augmented with a ``"rea"`` key::

        {... scan_file fields ..., "rea": {"status": ..., ...} | None}
    """
    result = scan_file(
        path,
        entropy_threshold=entropy_threshold,
        entropy_min_len=entropy_min_len,
    )

    rea: Optional[Dict[str, Any]]
    if not run_rea:
        rea = {"status": "skipped"}
    else:
        analyzer = rea_analyzer
        if analyzer is None:
            # Imported lazily so the module stands alone even if the heavy
            # attribution dependencies are unavailable at import time.
            try:
                from artex_antidote import attribution

                analyzer = attribution.run_rea_static_analysis
            except Exception as exc:  # pragma: no cover - defensive
                analyzer = None
                rea = {"status": "unavailable", "error": str(exc)}
        if analyzer is not None:
            try:
                rea = analyzer(str(Path(path)))
            except Exception as exc:  # defensive: REA must never crash a scan
                rea = {"status": "unavailable", "error": str(exc)}

    result["rea"] = rea
    return result

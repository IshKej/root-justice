"""Single source of truth for Artex Antidote attack-signature regexes.

Historically the SQLi / XSS / traversal payload patterns and the scanner
user-agent patterns were copy-pasted into both :mod:`artex_antidote.shield` and
:mod:`artex_antidote.attribution`. The two copies drifted -- notably the shield
caught the ``benchmark(`` SQL time-based primitive while the attribution path did
not -- so a payload could be *detected* by the edge shield yet be *mislabeled*
(or dropped to ``anomalous_probe``) by the on-the-fly patch synthesizer.

This module holds the compiled patterns once and exposes :func:`classify_vectors`,
the shared classifier. Both modules import from here, so the patterns can no
longer drift apart, and a parity test (``tests/test_signatures.py``) fails CI if a
future edit reintroduces a divergent copy.

User-agent strings are a weak, spoofable signal. Nothing in this module decides
enforcement on its own; callers (the shield's scoring, the attribution labeler)
layer their own policy on top of these labels.
"""

from __future__ import annotations

import re
from typing import List, Tuple


# --- Exploit payload signatures -------------------------------------------------
# Each family is (label, compiled pattern). ``EXPLOIT_PATTERNS`` is the bare tuple
# of patterns for callers (the shield) that only need a yes/no "is this an exploit
# probe" scan without per-family labels.
SQLI_PATTERN = re.compile(
    r"(\bunion\b.*\bselect\b|\bor\b\s+1=1\b|sleep\(\d+\)|benchmark\()", re.IGNORECASE
)
XSS_PATTERN = re.compile(r"(<script\b|onerror\s*=|onload\s*=|javascript:)", re.IGNORECASE)
TRAVERSAL_RCE_PATTERN = re.compile(
    r"(\.\./\.\./|/etc/passwd|cmd\.exe|powershell\s+-enc)", re.IGNORECASE
)

EXPLOIT_SIGNATURES: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("sqli", SQLI_PATTERN),
    ("xss", XSS_PATTERN),
    ("path_traversal_or_rce", TRAVERSAL_RCE_PATTERN),
)

#: Bare pattern tuple (same objects as ``EXPLOIT_SIGNATURES``) for a labelless scan.
EXPLOIT_PATTERNS: Tuple["re.Pattern[str]", ...] = tuple(p for _, p in EXPLOIT_SIGNATURES)


# --- User-agent signatures ------------------------------------------------------
# UA is a WEAK, spoofable signal. We split it into two tiers so that widely
# legitimate automation (httpx, Go's default client, curl, requests, wget) is not
# treated like a dedicated offensive tool.
#
# Offensive security tools: little legitimate use against someone else's site.
OFFENSIVE_TOOL_UA_PATTERNS: Tuple["re.Pattern[str]", ...] = (
    re.compile(r"nuclei", re.IGNORECASE),
    re.compile(r"katana", re.IGNORECASE),
    re.compile(r"ffuf", re.IGNORECASE),
    re.compile(r"dalfox", re.IGNORECASE),
    re.compile(r"sqlmap", re.IGNORECASE),
    re.compile(r"bbot", re.IGNORECASE),
    re.compile(r"\bnmap\b", re.IGNORECASE),
)

# Generic automation: extremely common in legitimate traffic.
GENERIC_AUTOMATION_UA_PATTERNS: Tuple["re.Pattern[str]", ...] = (
    re.compile(r"httpx", re.IGNORECASE),
    re.compile(r"^Go-http-client/", re.IGNORECASE),
    re.compile(r"python-requests", re.IGNORECASE),
    re.compile(r"\bcurl/", re.IGNORECASE),
    re.compile(r"^Wget/", re.IGNORECASE),
)


def is_offensive_tool_ua(user_agent: str) -> bool:
    """True if the UA matches a dedicated offensive-security tool (heavy signal)."""
    return any(p.search(user_agent) for p in OFFENSIVE_TOOL_UA_PATTERNS)


def is_generic_automation_ua(user_agent: str) -> bool:
    """True if the UA matches a common automation client (very weak signal)."""
    return any(p.search(user_agent) for p in GENERIC_AUTOMATION_UA_PATTERNS)


def classify_vectors(text: str, user_agent: str) -> List[str]:
    """Return the attack-vector labels present in ``text`` / ``user_agent``.

    ``text`` is scanned for exploit payload families (``sqli``, ``xss``,
    ``path_traversal_or_rce``); ``user_agent`` is scanned for known automation.
    An ``automated_scanner`` label is added when the UA matches any known
    automation client -- offensive tool or generic library alike -- because this
    classifier is used by the forensic/attribution path, which records the fact
    that the request came from automation without itself deciding enforcement.

    Labels are returned in a stable order with no duplicates. An empty list means
    no known vector matched; callers decide how to treat that (e.g. the
    attribution path records it as an ``anomalous_probe``).
    """
    vectors: List[str] = []
    for label, pattern in EXPLOIT_SIGNATURES:
        if pattern.search(text):
            vectors.append(label)
    if is_offensive_tool_ua(user_agent) or is_generic_automation_ua(user_agent):
        vectors.append("automated_scanner")
    return vectors

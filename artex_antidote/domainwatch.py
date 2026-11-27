"""Lookalike / typosquat domain monitoring (spec GAP #2) -- STRICTLY DEFENSIVE.

This module helps an operator *watch their own brand* for lookalike domains --
typosquats, homoglyph swaps, TLD swaps and the like -- that an attacker might
register to phish the operator's users or impersonate the operator's site.

Everything here is passive and protective:

  * ``permutations(domain)`` enumerates plausible typosquat variants of a domain
    the operator owns, so they can be monitored (or defensively pre-registered).
  * ``check_registered(domains, resolve=...)`` asks a *mockable* DNS seam whether
    each candidate currently resolves. A candidate that resolves is flagged as a
    possible lookalike worth a human look. The module never probes, scrapes or
    attacks any resolved host -- it only reports "this name resolves".
  * ``email_auth_advice()`` returns concrete DMARC / SPF / DKIM hardening strings
    the operator can publish to make impersonation of *their* mail harder.
  * ``scan(domain, resolve=...)`` is a convenience that ties the above together.

The only external-I/O touch point is DNS resolution, isolated behind the
module-level ``_resolve`` seam. Tests (and offline/air-gapped runs) monkeypatch
``artex_antidote.domainwatch._resolve`` -- or pass ``resolve=`` explicitly -- so
nothing in this module performs real network or DNS I/O unless the caller wants
it to. No wall-clock or randomness is used; callers that want timestamps pass
their own.

Typical use::

    cands = permutations("example.com")
    hits = check_registered(cands, resolve=my_resolver)
    advice = email_auth_advice()
"""

from __future__ import annotations

import socket
from typing import Callable, Dict, List, Optional, Sequence


__all__ = [
    "permutations",
    "check_registered",
    "email_auth_advice",
    "scan",
    "_resolve",
    "HOMOGLYPHS",
    "COMMON_TLDS",
    "ADJACENT_KEYS",
]


# ---------------------------------------------------------------------------
# Static substitution tables (deterministic -- no randomness, no clock).
# ---------------------------------------------------------------------------

# Homoglyph / visually-confusable swaps commonly abused by typosquatters.
# Each key maps to the sequences it is frequently confused with.
HOMOGLYPHS: Dict[str, Sequence[str]] = {
    "o": ("0",),
    "0": ("o",),
    "l": ("1", "i"),
    "1": ("l",),
    "i": ("1", "l"),
    "e": ("3",),
    "a": ("4", "@"),
    "s": ("5", "$"),
    "b": ("6",),
    "g": ("9",),
    "rn": ("m",),
    "m": ("rn",),
    "vv": ("w",),
    "w": ("vv",),
    "cl": ("d",),
}

# A small list of common TLDs we swap the registered name onto. Defensive
# monitoring: these are the TLDs a brand-abuser most often grabs.
COMMON_TLDS: Sequence[str] = (
    "com",
    "net",
    "org",
    "info",
    "biz",
    "co",
    "io",
    "online",
    "site",
    "xyz",
    "app",
    "dev",
)

# QWERTY adjacency used to synthesise fat-finger / adjacent-key typos.
ADJACENT_KEYS: Dict[str, str] = {
    "q": "wa",
    "w": "qeas",
    "e": "wrsd",
    "r": "etdf",
    "t": "ryfg",
    "y": "tugh",
    "u": "yihj",
    "i": "uojk",
    "o": "ipkl",
    "p": "ol",
    "a": "qwsz",
    "s": "awedxz",
    "d": "serfcx",
    "f": "drtgvc",
    "g": "ftyhbv",
    "h": "gyujnb",
    "j": "huikmn",
    "k": "jiolm",
    "l": "kop",
    "z": "asx",
    "x": "zsdc",
    "c": "xdfv",
    "v": "cfgb",
    "b": "vghn",
    "n": "bhjm",
    "m": "njk",
}


# ---------------------------------------------------------------------------
# DNS seam.
# ---------------------------------------------------------------------------


def _resolve(name: str) -> Optional[List[str]]:
    """Resolve ``name`` to a list of IP address strings, or ``None`` on failure.

    This is the ONLY external-I/O seam in the module. Tests monkeypatch
    ``artex_antidote.domainwatch._resolve`` (or pass ``resolve=`` to the public
    functions) so the module runs fully offline and deterministically.

    A name that does not resolve -- or that cannot be looked up for any reason --
    yields ``None``. A name that resolves yields the list of address strings.
    """
    try:
        infos = socket.getaddrinfo(name, None)
    except (socket.gaierror, OSError, UnicodeError):
        return None
    addrs = sorted({info[4][0] for info in infos})
    return addrs or None


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _split(domain: str) -> "tuple[str, str]":
    """Split ``domain`` into (label, tld-suffix).

    ``"example.com"`` -> ``("example", "com")``; ``"a.co.uk"`` -> ``("a", "co.uk")``.
    A domain with no dot is treated as a bare label with an empty suffix.
    """
    domain = domain.strip().strip(".").lower()
    if "." not in domain:
        return domain, ""
    label, _, suffix = domain.partition(".")
    return label, suffix


def _char_omission(label: str) -> List[str]:
    """Drop one character at a time (missing-letter typos)."""
    out = []
    for i in range(len(label)):
        out.append(label[:i] + label[i + 1:])
    return out


def _adjacent_typo(label: str) -> List[str]:
    """Replace each character with each of its QWERTY neighbours."""
    out = []
    for i, ch in enumerate(label):
        for nb in ADJACENT_KEYS.get(ch, ""):
            out.append(label[:i] + nb + label[i + 1:])
    return out


def _homoglyph_swaps(label: str) -> List[str]:
    """Apply single homoglyph substitutions (handles multi-char keys like rn)."""
    out = []
    for key, repls in HOMOGLYPHS.items():
        start = 0
        while True:
            idx = label.find(key, start)
            if idx == -1:
                break
            for rep in repls:
                out.append(label[:idx] + rep + label[idx + len(key):])
            start = idx + 1
    return out


def _hyphen_insertion(label: str) -> List[str]:
    """Insert a hyphen between adjacent characters (hyphenation typosquats)."""
    out = []
    for i in range(1, len(label)):
        out.append(label[:i] + "-" + label[i:])
    return out


# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------


def permutations(domain: str) -> List[str]:
    """Generate typosquat / lookalike variants of ``domain``.

    Covers character omission, adjacent-key (fat-finger) typos, homoglyph swaps
    (``o``/``0``, ``l``/``1``, ``rn``/``m`` ...), TLD swaps against
    :data:`COMMON_TLDS`, and hyphen insertion. The result is de-duplicated,
    order-stable, and never contains the original ``domain`` itself.

    Returns an empty list for an empty / dot-only input.
    """
    label, suffix = _split(domain)
    if not label:
        return []

    original = f"{label}.{suffix}" if suffix else label

    variant_labels: List[str] = []
    variant_labels.extend(_char_omission(label))
    variant_labels.extend(_adjacent_typo(label))
    variant_labels.extend(_homoglyph_swaps(label))
    variant_labels.extend(_hyphen_insertion(label))

    results: List[str] = []
    seen = set()

    def _add(candidate: str) -> None:
        if candidate and candidate != original and candidate not in seen:
            seen.add(candidate)
            results.append(candidate)

    # Variant labels keep the original suffix.
    for vl in variant_labels:
        if not vl:
            continue
        _add(f"{vl}.{suffix}" if suffix else vl)

    # TLD swaps keep the original label.
    if suffix:
        for tld in COMMON_TLDS:
            if tld == suffix:
                continue
            _add(f"{label}.{tld}")

    return results


def check_registered(
    domains: Sequence[str],
    resolve: Optional[Callable[[str], Optional[List[str]]]] = None,
) -> List[dict]:
    """Check which ``domains`` currently resolve (possible live lookalikes).

    ``resolve`` is the DNS seam: a callable ``resolve(name) -> Optional[list[str]]``
    returning the resolved addresses, or ``None`` / empty when the name does not
    resolve. It defaults to the module-level :func:`_resolve`, which tests
    monkeypatch, so this runs offline when the caller supplies a fake resolver.

    Returns one dict per input domain, in input order::

        {"domain": <name>, "registered": <bool>, "addresses": [<ip>, ...]}

    A domain that resolves is flagged ``registered=True`` -- a possible lookalike
    worth human review. The function never contacts the resolved hosts.
    """
    resolver = resolve if resolve is not None else _resolve
    out: List[dict] = []
    for name in domains:
        try:
            addrs = resolver(name)
        except Exception:  # a flaky resolver must not take the audit down
            addrs = None
        registered = bool(addrs)
        out.append(
            {
                "domain": name,
                "registered": registered,
                "addresses": list(addrs) if addrs else [],
            }
        )
    return out


def email_auth_advice() -> dict:
    """Concrete DMARC / SPF / DKIM guidance to harden against impersonation.

    Returns a dict of ready-to-publish record strings and short notes. These are
    defensive controls the operator publishes for *their own* domain so that
    lookalike / spoofed mail is rejected by receivers.
    """
    return {
        "dmarc": {
            "host": "_dmarc.<your-domain>",
            "type": "TXT",
            "record": (
                "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; "
                "rua=mailto:dmarc-reports@<your-domain>; "
                "ruf=mailto:dmarc-forensics@<your-domain>; fo=1"
            ),
            "note": (
                "Enforce with p=reject once monitoring (p=none) shows legitimate "
                "mail passes. Strict alignment (adkim=s/aspf=s) blocks lookalikes."
            ),
        },
        "spf": {
            "host": "<your-domain>",
            "type": "TXT",
            "record": "v=spf1 mx include:_spf.<your-provider> -all",
            "note": (
                "End with -all (hard fail), never ~all, so unauthorised senders "
                "are rejected rather than merely flagged."
            ),
        },
        "dkim": {
            "host": "<selector>._domainkey.<your-domain>",
            "type": "TXT",
            "record": "v=DKIM1; k=rsa; p=<base64-public-key>",
            "note": (
                "Publish a DKIM key (2048-bit RSA or Ed25519), sign all outbound "
                "mail, and rotate selectors periodically."
            ),
        },
        "summary": (
            "Publish SPF (-all), DKIM signing, and DMARC p=reject with strict "
            "alignment so receivers reject spoofed and lookalike-domain mail."
        ),
    }


def scan(
    domain: str,
    resolve: Optional[Callable[[str], Optional[List[str]]]] = None,
) -> dict:
    """Convenience: enumerate variants of ``domain`` and check which resolve.

    Returns::

        {
            "domain": <domain>,
            "candidates": [<variant>, ...],
            "registered": [<result dict>, ...],   # only the resolving ones
            "all": [<result dict>, ...],           # every candidate's result
            "email_auth": {<advice>},
        }
    """
    candidates = permutations(domain)
    results = check_registered(candidates, resolve=resolve)
    return {
        "domain": domain,
        "candidates": candidates,
        "registered": [r for r in results if r["registered"]],
        "all": results,
        "email_auth": email_auth_advice(),
    }

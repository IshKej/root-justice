"""Self-documenting control matrix for the Root Justice blue-team package.

This module is **pure data plus a few deterministic readers**. It encodes, as
an auditable table, how the Root Justice (Artex Antidote) defensive package
answers each of the seven offensive *attack-tool classes* taken from the
reference set. It takes no arguments that cause I/O, performs no network, DNS,
filesystem, or time access, and imports nothing beyond the standard library, so
it is safe to call from a health endpoint, a CLI command, or a test.

Nothing here *performs* an attack or probes a third party. The matrix is a
documentation artefact: for every attack class it names the **operator-owned**
control that neutralises, partially mitigates, or merely advises against the
threat, so an auditor can see coverage and gaps at a glance.

Each row is a mapping with a stable shape::

    {
        "id": str,                      # stable machine key
        "attack": str,                  # the offensive tool class
        "root_justice_control": str,    # which module/feature answers it
        "status": str,                  # one of STATUSES
        "note": str,                    # one-line rationale
    }

Status vocabulary (:data:`STATUSES`):

* ``"neutralized"`` — Root Justice fully defends the operator's own asset.
* ``"partial"``     — meaningful mitigation, but not a complete defence.
* ``"advisory"``    — Root Justice emits guidance/hardening only; no live block.
* ``"out_of_scope"``— acknowledged but outside this package's remit.

Public API
----------
* :data:`COVERAGE` — the list of rows (module-level constant).
* :func:`coverage_matrix` — return a deep copy of the rows (safe to mutate).
* :func:`render_markdown` — render the matrix as a Markdown table string.
* :func:`summary` — return ``{status: count}`` over all rows.

Typical use::

    from artex_antidote.coverage import coverage_matrix, render_markdown, summary

    rows = coverage_matrix()
    print(render_markdown())
    print(summary())   # -> {"neutralized": 1, "partial": 4, "advisory": 2, ...}
"""

from __future__ import annotations

import copy
from typing import Dict, List

__all__ = [
    "STATUSES",
    "STATUS_NEUTRALIZED",
    "STATUS_PARTIAL",
    "STATUS_ADVISORY",
    "STATUS_OUT_OF_SCOPE",
    "COVERAGE",
    "coverage_matrix",
    "render_markdown",
    "summary",
]

STATUS_NEUTRALIZED = "neutralized"
STATUS_PARTIAL = "partial"
STATUS_ADVISORY = "advisory"
STATUS_OUT_OF_SCOPE = "out_of_scope"

#: The permitted status values, in reporting order (best coverage first).
STATUSES = (
    STATUS_NEUTRALIZED,
    STATUS_PARTIAL,
    STATUS_ADVISORY,
    STATUS_OUT_OF_SCOPE,
)

#: The control matrix: one row per attack-tool class in the reference set.
#:
#: This is the single source of truth. ``coverage_matrix()`` hands callers a
#: copy so this constant is never mutated in place.
COVERAGE: List[Dict[str, str]] = [
    {
        "id": "exposed_site_files",
        "attack": "Exposed site files / directory & backup-file exposure scanning",
        "root_justice_control": "shield + decoy + tarpit + evidence",
        "status": STATUS_NEUTRALIZED,
        "note": (
            "Probes for .git, backups and stray config on the operator's own "
            "edge are blocked by the shield, lured into decoys, slowed by the "
            "tarpit, and recorded as evidence — the scan sees nothing real."
        ),
    },
    {
        "id": "firmware_secrets",
        "attack": "Firmware secret extraction (hard-coded keys/credentials in images)",
        "root_justice_control": "firmware_audit + REA static analysis",
        "status": STATUS_PARTIAL,
        "note": (
            "Pre-ship firmware auditing plus REA static analysis surfaces baked-in "
            "secrets in the operator's own images before release, but cannot reach "
            "firmware already shipped on devices in the field."
        ),
    },
    {
        "id": "hash_cracking",
        "attack": "Offline password-hash cracking of stolen credential stores",
        "root_justice_control": "credpolicy + credential-theft-vector detection",
        "status": STATUS_PARTIAL,
        "note": (
            "Credential-policy checks push strong hashing and high work factors, "
            "and theft-vector detection flags exfiltration paths, raising the cost "
            "of cracking — but a leaked store can still be attacked offline."
        ),
    },
    {
        "id": "cloud_buckets",
        "attack": "Cloud object-storage bucket enumeration & exposure",
        "root_justice_control": "cloud posture audit",
        "status": STATUS_PARTIAL,
        "note": (
            "A posture audit of the operator's own buckets finds public ACLs and "
            "listable objects so they can be locked down, but does not enforce "
            "provider-side policy or continuously block new misconfigurations."
        ),
    },
    {
        "id": "lookalike_domains",
        "attack": "Lookalike / homoglyph phishing-domain registration",
        "root_justice_control": "domainwatch",
        "status": STATUS_PARTIAL,
        "note": (
            "Domainwatch monitors for newly registered lookalikes of the "
            "operator's brands and raises alerts, but registration and takedown "
            "of third-party domains remain outside this package's control."
        ),
    },
    {
        "id": "keystroke_injection",
        "attack": "USB keystroke-injection (HID) attacks on endpoints",
        "root_justice_control": "hardening advisory (endpoint)",
        "status": STATUS_ADVISORY,
        "note": (
            "Root Justice ships endpoint hardening guidance (USB/HID policy, "
            "device allowlisting, screen lock) but performs no live USB "
            "enforcement itself."
        ),
    },
    {
        "id": "wifi_cracking",
        "attack": "Wi-Fi handshake capture & WPA passphrase cracking",
        "root_justice_control": "hardening advisory (wifi)",
        "status": STATUS_ADVISORY,
        "note": (
            "Root Justice advises on Wi-Fi hardening (WPA3, long passphrases, "
            "management-frame protection) for the operator's own networks but "
            "does not operate the radio or block captures."
        ),
    },
]


def coverage_matrix() -> List[Dict[str, str]]:
    """Return the control matrix as a list of row mappings.

    The result is a deep copy of :data:`COVERAGE`, so callers may freely mutate
    it without disturbing the module-level source of truth.
    """
    return copy.deepcopy(COVERAGE)


def summary() -> Dict[str, int]:
    """Return a count of rows by status.

    Every value in :data:`STATUSES` is present as a key (zero when no row uses
    it), so the shape is stable regardless of the data. The counts sum to the
    number of rows in the matrix.
    """
    counts: Dict[str, int] = {status: 0 for status in STATUSES}
    for row in COVERAGE:
        status = row["status"]
        counts[status] = counts.get(status, 0) + 1
    return counts


def _escape_cell(text: str) -> str:
    """Escape a value so it renders safely inside one Markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ").strip()


def render_markdown() -> str:
    """Render the control matrix as a GitHub-flavoured Markdown table.

    The returned string has a header row, an alignment row, and one row per
    entry in :data:`COVERAGE`, in matrix order. Pure string building — no I/O.
    """
    headers = ("ID", "Attack", "Root Justice control", "Status", "Note")
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in COVERAGE:
        cells = (
            row["id"],
            row["attack"],
            row["root_justice_control"],
            row["status"],
            row["note"],
        )
        lines.append("| " + " | ".join(_escape_cell(c) for c in cells) + " |")
    return "\n".join(lines)

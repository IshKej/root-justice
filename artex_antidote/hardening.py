"""Honest, actionable hardening baselines for endpoint and wireless domains.

Spec gaps #6 ("keystroke injection / BadUSB") and #7 ("Wi-Fi cracking").

Root Justice is a *web* shield. It sits in front of HTTP(S) assets the operator
owns and inspects request traffic. It therefore **cannot** enforce controls that
live on the physical endpoint (a USB port, an autorun policy, a screen lock) or
on the radio layer (WPA3, WPS, management-frame protection). Pretending a web
proxy "blocks BadUSB" or "stops Wi-Fi cracking" would be dishonest security
theatre.

Instead this module ships what a blue team can actually act on: vetted
**hardening baselines** — plain, cited, do-this-next controls — for the two
domains, plus a read-only :func:`local_quickcheck` that reports only facts it can
safely read about the host and clearly labels everything it cannot verify as
``"manual"``. Nothing here changes a single setting on the machine; it is advice
and observation, not enforcement.

Design notes
------------
* **Strictly defensive.** These baselines harden the *operator's own* endpoints
  and wireless networks. There is no offensive capability — no attack, no crack,
  no injection — anywhere in this module.
* **Standard library only, deterministic.** The baselines are static data and
  the markdown renderer is pure. The only I/O is :func:`local_quickcheck`, which
  reads host facts through :mod:`platform`/:mod:`os` behind the mockable
  :func:`_read_host_facts` seam so tests run fully offline and deterministically.
* **No surprises.** ``local_quickcheck`` never writes, never raises, and never
  claims to have verified a control it cannot actually observe.

Typical use::

    from artex_antidote import hardening

    baselines = {"endpoint": hardening.endpoint_baseline(),
                 "wifi": hardening.wifi_baseline()}
    report = hardening.render_markdown(baselines)
    facts = hardening.local_quickcheck()   # read-only, safe
"""

from __future__ import annotations

import os
import platform
from typing import Any, Callable, Dict, List

__all__ = [
    "endpoint_baseline",
    "wifi_baseline",
    "render_markdown",
    "local_quickcheck",
]


# --------------------------------------------------------------------------- #
# Mockable host-fact seam.
#
# All host-external reads funnel through this one function so tests can
# monkeypatch it and run offline/deterministically. It reads ONLY inert,
# non-sensitive platform metadata and never mutates anything.
# --------------------------------------------------------------------------- #
def _read_host_facts() -> Dict[str, Any]:
    """Return a small dict of safe, read-only host facts.

    Reads only inert platform identity via :mod:`platform`/:mod:`os`. It changes
    nothing on the host and is the single seam the tests monkeypatch, so callers
    get fully deterministic, offline behaviour. Any failure is swallowed and the
    affected field comes back as ``None`` — a quickcheck must never crash.
    """
    facts: Dict[str, Any] = {}
    for key, getter in (
        ("system", platform.system),
        ("release", platform.release),
        ("machine", platform.machine),
        ("node", platform.node),
    ):
        try:
            facts[key] = getter() or None
        except Exception:
            facts[key] = None
    try:
        # Interactive login hint only; purely informational, never a secret.
        facts["user"] = os.environ.get("USERNAME") or os.environ.get("USER") or None
    except Exception:
        facts["user"] = None
    return facts


def _control(control_id: str, control: str, rationale: str, how: str) -> Dict[str, str]:
    """Build one baseline row with the required ``{id,control,rationale,how}`` keys."""
    return {"id": control_id, "control": control, "rationale": rationale, "how": how}


# --------------------------------------------------------------------------- #
# Gap #6 — Endpoint: keystroke injection / BadUSB and friends.
# --------------------------------------------------------------------------- #
def endpoint_baseline() -> List[Dict[str, str]]:
    """Endpoint hardening baseline (spec gap #6).

    Returns a list of control dicts, each with keys ``id``, ``control``,
    ``rationale`` and ``how``. Covers USB HID device control / BadUSB
    mitigation, disabling autorun/autoplay, a short screen-lock timeout,
    endpoint detection & response (EDR), least-privilege accounts, and
    application allowlisting.

    The list is static and deterministic (no timestamps, no randomness) so it is
    safe to diff, snapshot, and render repeatedly.
    """
    return [
        _control(
            "EP-01",
            "USB HID device control / BadUSB mitigation",
            "A malicious USB device can masquerade as a keyboard (HID) and inject "
            "keystrokes at machine speed the instant it is plugged in — a 'BadUSB' "
            "or Rubber-Ducky attack a network shield can never see.",
            "Enforce a USB device-control policy that blocks or prompts on new HID "
            "devices: Windows Group Policy 'Prevent installation of devices' by "
            "class, Intune/MDM device-control, or EDR USB control. Physically cap "
            "or disable unused ports on kiosks and servers.",
        ),
        _control(
            "EP-02",
            "Disable autorun / autoplay for removable media",
            "Autorun silently executes payloads from inserted USB sticks, SD cards "
            "and optical media without any user action.",
            "Set 'Turn off AutoPlay' for all drives via Group Policy "
            "(NoDriveTypeAutoRun = 0xFF), or the equivalent MDM policy; on Linux "
            "disable automount of removable media for untrusted desktops.",
        ),
        _control(
            "EP-03",
            "Screen-lock timeout and lock-on-away",
            "An unlocked, unattended workstation lets anyone — or any plugged-in "
            "BadUSB device — act as the logged-in user.",
            "Require an automatic screen lock after <= 5 minutes idle and lock on "
            "smart-card/badge removal. Enforce via Group Policy "
            "(InactivityTimeoutSecs) or MDM; train staff to Win+L when leaving.",
        ),
        _control(
            "EP-04",
            "Endpoint Detection & Response (EDR) deployed and reporting",
            "EDR catches the post-injection behaviour (spawned shells, credential "
            "theft, persistence) that physical-layer attacks rely on, and ships "
            "telemetry a central team can hunt in.",
            "Deploy a managed EDR/antimalware agent on every endpoint, confirm it "
            "reports to a central console, and alert on agent-missing or "
            "agent-stopped conditions.",
        ),
        _control(
            "EP-05",
            "Least-privilege user accounts (no daily admin)",
            "Keystroke-injection and dropped payloads inherit the rights of the "
            "logged-in user; a standard (non-admin) account sharply limits what a "
            "successful injection can do.",
            "Remove users from local Administrators for daily work, require a "
            "separate elevation account or LAPS-managed admin, and gate elevation "
            "behind UAC / sudo prompts.",
        ),
        _control(
            "EP-06",
            "Application allowlisting (execution control)",
            "Even a perfectly typed malicious command fails if the binary it tries "
            "to launch is not on an approved allowlist — defeating most BadUSB "
            "'open a shell and run X' payloads.",
            "Enforce application allowlisting (Windows Defender Application "
            "Control / AppLocker, or an equivalent on macOS/Linux) in enforce mode "
            "for user-writable paths such as %TEMP%, Downloads and removable media.",
        ),
    ]


# --------------------------------------------------------------------------- #
# Gap #7 — Wireless: Wi-Fi cracking.
# --------------------------------------------------------------------------- #
def wifi_baseline() -> List[Dict[str, str]]:
    """Wi-Fi / wireless hardening baseline (spec gap #7).

    Returns a list of control dicts, each with keys ``id``, ``control``,
    ``rationale`` and ``how``. Covers WPA3 / WPA2-AES, a long high-entropy
    passphrase, disabling WPS, 802.11w management-frame protection, guest-network
    client isolation, and rogue-AP / wireless-IDS monitoring.

    Static and deterministic — safe to snapshot and render.
    """
    return [
        _control(
            "WIFI-01",
            "Use WPA3, or WPA2 with AES-CCMP only",
            "WEP and WPA/TKIP are trivially cracked; WPA3-SAE resists offline "
            "dictionary attacks on captured handshakes, and WPA2-AES is the "
            "minimum defensible floor.",
            "Set the AP/controller to WPA3-SAE (or WPA3/WPA2 transition) and "
            "disable WEP, WPA-TKIP and 'mixed' TKIP modes. Retire access points "
            "that cannot do WPA2-AES.",
        ),
        _control(
            "WIFI-02",
            "Long, high-entropy pre-shared passphrase",
            "A captured WPA2 handshake is cracked offline; a short or dictionary "
            "passphrase falls in seconds, while a long random one is infeasible.",
            "Use a >= 20-character random passphrase (or 802.1X/enterprise auth "
            "instead of a PSK), rotate it when staff leave, and never reuse it "
            "across networks.",
        ),
        _control(
            "WIFI-03",
            "Disable WPS (Wi-Fi Protected Setup)",
            "The WPS 8-digit PIN has a well-known design flaw that lets an "
            "attacker brute-force it and recover the PSK regardless of its "
            "strength.",
            "Turn WPS off entirely in the AP/router admin — both PIN and "
            "push-button modes. Verify it stays off after firmware updates.",
        ),
        _control(
            "WIFI-04",
            "Enable 802.11w management-frame protection (PMF)",
            "Without protected management frames, attackers forge deauth/disassoc "
            "frames to knock clients off and force handshake re-capture or "
            "evil-twin association.",
            "Set PMF to required (or at least capable) on the SSID; WPA3 mandates "
            "it. Confirm clients in scope support 802.11w before enforcing "
            "'required'.",
        ),
        _control(
            "WIFI-05",
            "Guest network isolation (client/AP isolation)",
            "A flat guest SSID lets a visitor — or a compromised guest device — "
            "reach other clients and internal assets on the same segment.",
            "Put guests on a separate VLAN/SSID with client isolation enabled and "
            "a firewall rule allowing internet-only egress, no access to internal "
            "subnets or management interfaces.",
        ),
        _control(
            "WIFI-06",
            "Rogue-AP detection / wireless IDS monitoring",
            "Evil-twin and rogue access points impersonate your SSID to harvest "
            "credentials and handshakes; you cannot respond to what you do not "
            "detect.",
            "Enable rogue-AP detection on the wireless controller or run a "
            "wireless IDS (WIDS) sensor, alert on unknown BSSIDs advertising your "
            "SSID, and periodically walk the site for unexpected radios.",
        ),
    ]


# --------------------------------------------------------------------------- #
# Rendering.
# --------------------------------------------------------------------------- #
def render_markdown(baselines: Dict[str, List[Dict[str, str]]]) -> str:
    """Render one or more baselines as a human-readable Markdown document.

    Parameters
    ----------
    baselines:
        A mapping of section name -> baseline list, e.g.
        ``{"endpoint": endpoint_baseline(), "wifi": wifi_baseline()}``. Each
        value is a list of ``{id,control,rationale,how}`` dicts. Unknown or
        empty sections are rendered with a short placeholder rather than
        raising.

    Returns
    -------
    str
        A Markdown string. It always includes the honest scope disclaimer that
        these are endpoint/wireless controls a web shield cannot enforce.
    """
    nice = {"endpoint": "Endpoint hardening", "wifi": "Wireless (Wi-Fi) hardening"}

    lines: List[str] = []
    lines.append("# Root Justice — Hardening Baselines")
    lines.append("")
    lines.append(
        "> These are endpoint and wireless controls the operator must apply on "
        "their own devices and networks. Root Justice is a web shield and "
        "**cannot** enforce them — it ships this baseline so the gaps "
        "(keystroke injection / BadUSB, Wi-Fi cracking) are addressed honestly "
        "rather than with a fake blocker."
    )
    lines.append("")

    for key in sorted(baselines):
        controls = baselines[key] or []
        heading = nice.get(key, str(key).replace("_", " ").title())
        lines.append(f"## {heading}")
        lines.append("")
        if not controls:
            lines.append("_No controls defined for this section._")
            lines.append("")
            continue
        for item in controls:
            cid = str(item.get("id", "?"))
            control = str(item.get("control", "")).strip()
            rationale = str(item.get("rationale", "")).strip()
            how = str(item.get("how", "")).strip()
            lines.append(f"### {cid} — {control}")
            lines.append("")
            lines.append(f"- **Why:** {rationale}")
            lines.append(f"- **How:** {how}")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# Read-only local quick-check.
# --------------------------------------------------------------------------- #
def local_quickcheck(
    read_facts: Callable[[], Dict[str, Any]] = _read_host_facts,
) -> Dict[str, Any]:
    """Report only facts that can be read SAFELY about the host — changing nothing.

    This never enforces, writes or probes anything. It reads inert platform
    identity (OS, release, architecture, host/user name) through the mockable
    :func:`_read_host_facts` seam and, for every control in the baselines, emits
    an item whose ``status`` is:

    * ``"info"``   — an observed, read-only host fact; or
    * ``"manual"`` — a control this tool cannot verify from here and that a human
      must check on the device/network itself.

    Parameters
    ----------
    read_facts:
        The host-fact reader. Defaults to :func:`_read_host_facts`; tests pass a
        stub so the call is deterministic and offline. If it raises, the error
        is swallowed and ``host`` comes back empty — the quickcheck must never
        raise.

    Returns
    -------
    dict
        ``{"host": {...}, "endpoint": [...], "wifi": [...]}``. ``host`` holds the
        safe facts; ``endpoint`` and ``wifi`` each hold one status item per
        baseline control. Always JSON-serialisable; never ``None``.
    """
    try:
        facts = read_facts()
    except Exception:
        facts = {}
    if not isinstance(facts, dict):
        facts = {}

    # Normalise the host block to plain, JSON-safe values.
    host = {
        "system": facts.get("system"),
        "release": facts.get("release"),
        "machine": facts.get("machine"),
        "node": facts.get("node"),
        "user": facts.get("user"),
    }

    def _items(baseline: List[Dict[str, str]]) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        for ctrl in baseline:
            out.append(
                {
                    "id": str(ctrl.get("id", "?")),
                    "control": str(ctrl.get("control", "")),
                    # This tool is a web shield: it cannot read a USB policy, a
                    # screen-lock GPO or a router's WPS flag from here. Be honest
                    # and label every control as needing a manual check.
                    "status": "manual",
                    "detail": "Cannot be verified remotely by the shield; "
                    "verify on the device/network itself.",
                }
            )
        return out

    endpoint_items: List[Dict[str, str]] = []
    # One genuinely observable info row, then the manual controls.
    endpoint_items.append(
        {
            "id": "HOST",
            "control": "Detected operating system",
            "status": "info",
            "detail": "OS: {system} {release} ({machine})".format(
                system=host.get("system") or "unknown",
                release=host.get("release") or "?",
                machine=host.get("machine") or "?",
            ),
        }
    )
    endpoint_items.extend(_items(endpoint_baseline()))

    wifi_items = _items(wifi_baseline())

    return {"host": host, "endpoint": endpoint_items, "wifi": wifi_items}

"""Decoy / canary responses that feed an automated scanner plausible-but-FAKE loot.

This module is purely defensive. When a scanner probes one of *our own* honeypot
canary paths (the same set the Edge Shield already flags as critical), we can
answer with realistic-looking but entirely synthetic content -- a fake ``.env``,
a fake ``/.git/config``, a bogus ``phpinfo()`` page -- instead of a bare 404.

Why this helps the defender, and why it is NOT hack-back:

- Every byte served is manufactured on our own host. We never touch, probe, or
  send anything to the attacker's machine. We only decide what *our* server
  returns to a request that was already classified as a canary probe.
- The synthetic loot wastes the scanner's time and budget: it will try to
  validate/exfiltrate credentials that lead nowhere.
- Every secret-looking value is a traceable *canary token*. The literal marker
  :data:`CANARY_MARKER` is embedded in each value, and a per-stream token can be
  woven in via :func:`decoy_response` so that if the fake credential is ever
  replayed against us (or shows up in a breach dump / paste), we can tie it back
  to the exact probe that received it. No value is a real secret; the host,
  user, and key material are all obviously synthetic sinkhole placeholders.

Safety invariants:

- :func:`is_decoy_path` matches ONLY our own canary honeypot paths. A benign
  application path returns ``False`` and MUST be served normally -- never feed a
  decoy to real traffic.
- Bodies are deterministic given ``(path, token)`` so evidence is reproducible.
- No randomness that could accidentally emit a real-looking routable secret:
  hosts point at ``sinkhole.invalid`` / documentation IP ranges, and keys are
  fixed trap strings.

Minimal API
-----------
>>> from artex_antidote.decoy import is_decoy_path, decoy_response
>>> is_decoy_path("/.env")
True
>>> is_decoy_path("/home")
False
>>> body = decoy_response("/.env", token="artex-stream-abc")
>>> b"ARTEX-CANARY" in body
True
"""

from __future__ import annotations

import hashlib
from typing import Dict, Optional, Tuple


# The paths we are willing to answer with synthetic loot. These intentionally
# mirror the Edge Shield's canary set so a probe that the shield flags as a
# canary can be handed a decoy body. Matching is prefix-based (case-insensitive)
# so "/.git/config" also covers "/.git/config?ref=...".
DECOY_PATHS: Tuple[str, ...] = (
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/.git/HEAD",
    "/wp-admin",
    "/wp-login.php",
    "/wp-config.php",
    "/actuator/env",
    "/server-status",
    "/api/v1/debug",
    "/phpinfo.php",
    "/config.json",
    "/.aws/credentials",
    "/backup.sql",
)

# Woven into every secret-looking value so the loot is a traceable canary and is
# trivially greppable in logs / breach dumps. If any value bearing this marker is
# ever presented back to us, it is proof the presenter scraped one of our decoys.
CANARY_MARKER = "ARTEX-CANARY"

# Non-routable / reserved sinks used in all synthetic values so nothing we emit
# can resolve to or authenticate against a real service.
_SINK_HOST = "db.sinkhole.invalid"
_SINK_IP = "203.0.113.7"  # TEST-NET-3 (RFC 5737), never routable
_SINK_EMAIL = "noreply@sinkhole.invalid"


def is_decoy_path(path: str) -> bool:
    """Return ``True`` iff ``path`` is one of our honeypot canary paths.

    Matching is case-insensitive and prefix-based on the URL path component.
    A query string is ignored. Benign application paths return ``False`` and
    must be served by the real application -- decoys are never for real traffic.
    """
    if not path:
        return False
    # Drop query/fragment; normalize.
    clean = path.split("?", 1)[0].split("#", 1)[0].strip().lower()
    if not clean:
        return False
    return any(_is_prefix(clean, p.lower()) for p in DECOY_PATHS)


def _is_prefix(clean: str, p: str) -> bool:
    """True when ``p`` is a path-boundary prefix of ``clean`` (or equal).

    A match requires ``clean`` to actually start with ``p`` and the following
    character to be a path/extension boundary, so "/.env" matches "/.env" and
    "/.env.local" but NOT "/.environment".
    """
    if clean == p:
        return True
    if not clean.startswith(p):
        return False
    return clean[len(p):len(p) + 1] in ("/", ".", "?")


def _canary_token(path: str, token: Optional[str]) -> str:
    """Build a short, stable canary id from the path (+ optional stream token).

    Deterministic so the same probe always receives the same loot, which keeps
    the evidence ledger reproducible. The id is *not* secret -- it is a tracer.
    """
    seed = f"{CANARY_MARKER}:{path}:{token or ''}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
    return f"{CANARY_MARKER}-{digest}"


def _fake_env(cid: str) -> bytes:
    return (
        "# Application environment (production)\n"
        "APP_ENV=production\n"
        "APP_DEBUG=false\n"
        f"APP_KEY=base64:{cid}trapkeyNOTREALxxxxxxxxxxxxxxxxxxxxxxx=\n"
        f"DB_CONNECTION=mysql\n"
        f"DB_HOST={_SINK_HOST}\n"
        "DB_PORT=3306\n"
        "DB_DATABASE=app_prod\n"
        f"DB_USERNAME=svc_{CANARY_MARKER.lower().replace('-', '_')}\n"
        f"DB_PASSWORD={cid}-Tr4pP4ss-doNotUse\n"
        f"MAIL_HOST=smtp.sinkhole.invalid\n"
        f"AWS_ACCESS_KEY_ID=AKIA{cid[-8:].upper()}TRAP\n"
        f"AWS_SECRET_ACCESS_KEY={cid}trapSecretNOTREALxxxxxxxxxxxxxxxxxxxx\n"
        f"STRIPE_SECRET=sk_live_{cid}TRAPnotarealkey\n"
        f"# canary:{cid} host={_SINK_HOST} -- synthetic honeypot value, not a real secret\n"
    ).encode("utf-8")


def _fake_git_config(cid: str) -> bytes:
    return (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "\tbare = false\n"
        "[remote \"origin\"]\n"
        f"\turl = https://{CANARY_MARKER.lower()}:{cid}@git.sinkhole.invalid/app/backend.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        "[user]\n"
        f"\temail = {_SINK_EMAIL}\n"
        f"\tname = {cid}\n"
        f"# canary:{cid} -- synthetic honeypot value, not a real repository\n"
    ).encode("utf-8")


def _fake_git_head(cid: str) -> bytes:
    return f"ref: refs/heads/main\n# {cid}\n".encode("utf-8")


def _fake_aws_credentials(cid: str) -> bytes:
    return (
        "[default]\n"
        f"aws_access_key_id = AKIA{cid[-10:].upper()}TRAP\n"
        f"aws_secret_access_key = {cid}trapSecretNOTREALxxxxxxxxxxxxxxxxxxxx\n"
        f"# region sink: {_SINK_IP} -- canary:{cid}, not a real AWS credential\n"
    ).encode("utf-8")


def _fake_wp_config(cid: str) -> bytes:
    return (
        "<?php\n"
        "/** Synthetic honeypot wp-config -- not a real site. */\n"
        "define( 'DB_NAME', 'wp_prod' );\n"
        f"define( 'DB_USER', 'wp_{cid.lower().replace('-', '_')}' );\n"
        f"define( 'DB_PASSWORD', '{cid}-Tr4pP4ss' );\n"
        f"define( 'DB_HOST', '{_SINK_HOST}' );\n"
        f"define( 'AUTH_KEY', '{cid}-auth-trap-NOTREAL' );\n"
        f"define( 'SECURE_AUTH_KEY', '{cid}-secauth-trap-NOTREAL' );\n"
        f"$table_prefix = 'wp_';\n"
        f"// canary:{cid} -- synthetic honeypot value\n"
        "?>\n"
    ).encode("utf-8")


def _fake_phpinfo(cid: str) -> bytes:
    return (
        "<!DOCTYPE html><html><head><title>phpinfo()</title></head><body>"
        "<h1>PHP Version 7.4.3</h1>"
        "<table><tr><td>System</td><td>Linux honeypot 5.4.0</td></tr>"
        f"<tr><td>DOCUMENT_ROOT</td><td>/var/www/html</td></tr>"
        f"<tr><td>SERVER_ADDR</td><td>{_SINK_IP}</td></tr>"
        f"<tr><td>DB_PASSWORD (env)</td><td>{cid}-Tr4pP4ss</td></tr>"
        f"</table><!-- canary:{cid} synthetic, not a real server --></body></html>\n"
    ).encode("utf-8")


def _fake_actuator_env(cid: str) -> bytes:
    return (
        "{"
        "\"activeProfiles\":[\"production\"],"
        "\"propertySources\":[{"
        "\"name\":\"systemEnvironment\",\"properties\":{"
        f"\"spring.datasource.url\":{{\"value\":\"jdbc:mysql://{_SINK_HOST}:3306/app\"}},"
        f"\"spring.datasource.password\":{{\"value\":\"{cid}-Tr4pP4ss\"}},"
        f"\"canary.marker\":{{\"value\":\"{cid}\"}}"
        "}}]}"
        "\n"
    ).encode("utf-8")


def _fake_server_status(cid: str) -> bytes:
    return (
        "Apache Server Status for honeypot.sinkhole.invalid\n"
        "Server Version: Apache/2.4.41 (Ubuntu)\n"
        "Current Time: synthetic\n"
        f"Server Built: canary:{cid}\n"
        f"1 requests currently being processed\n"
        f"GET /admin?token={cid} HTTP/1.1\n"
    ).encode("utf-8")


def _fake_debug(cid: str) -> bytes:
    return (
        "{"
        "\"debug\":true,"
        f"\"db_host\":\"{_SINK_HOST}\","
        f"\"admin_token\":\"{cid}-admin-trap\","
        f"\"internal_ip\":\"{_SINK_IP}\","
        f"\"canary\":\"{cid}\""
        "}\n"
    ).encode("utf-8")


def _fake_config_json(cid: str) -> bytes:
    return (
        "{"
        f"\"apiKey\":\"{cid}-api-trap-NOTREAL\","
        f"\"dbPassword\":\"{cid}-Tr4pP4ss\","
        f"\"host\":\"{_SINK_HOST}\","
        f"\"canary\":\"{cid}\""
        "}\n"
    ).encode("utf-8")


def _fake_backup_sql(cid: str) -> bytes:
    return (
        "-- MySQL dump (synthetic honeypot)\n"
        "CREATE TABLE users (id INT, email VARCHAR(255), password_hash VARCHAR(255));\n"
        f"INSERT INTO users VALUES (1, '{_SINK_EMAIL}', '$2y$10${cid}trapHashNOTREAL');\n"
        f"-- canary:{cid} -- synthetic data, no real accounts\n"
    ).encode("utf-8")


# Dispatch table keyed by the canonical decoy path prefix. First matching key
# (longest-prefix) wins so "/.env.production" is distinct from "/.env" only if
# listed; here they share the env renderer, which is fine.
_RENDERERS = (
    ("/.git/config", _fake_git_config),
    ("/.git/HEAD", _fake_git_head),
    ("/.git", _fake_git_config),
    ("/.aws/credentials", _fake_aws_credentials),
    ("/wp-config.php", _fake_wp_config),
    ("/wp-admin", _fake_wp_config),
    ("/wp-login.php", _fake_wp_config),
    ("/phpinfo.php", _fake_phpinfo),
    ("/actuator/env", _fake_actuator_env),
    ("/server-status", _fake_server_status),
    ("/api/v1/debug", _fake_debug),
    ("/config.json", _fake_config_json),
    ("/backup.sql", _fake_backup_sql),
    ("/.env", _fake_env),
)


def _select_renderer(clean_path: str):
    best = None
    best_len = -1
    for prefix, fn in _RENDERERS:
        pl = prefix.lower()
        if _is_prefix(clean_path, pl) and len(pl) > best_len:
            best, best_len = fn, len(pl)
    return best


def decoy_response(path: str, token: Optional[str] = None) -> bytes:
    """Return synthetic honeypot loot for a canary ``path``.

    ``path`` must be a decoy path (see :func:`is_decoy_path`); otherwise a
    :class:`ValueError` is raised so a caller cannot accidentally serve a decoy
    for benign traffic. ``token`` is an optional per-stream id (e.g. the evidence
    ``stream_id``) woven into the canary marker so served loot is traceable to
    the exact probe. The body is deterministic in ``(path, token)``.

    The returned bytes always contain :data:`CANARY_MARKER` so the content is a
    greppable tracer, and every secret-looking value points at a sinkhole /
    reserved address and is clearly synthetic.
    """
    if not is_decoy_path(path):
        raise ValueError(f"not a decoy path: {path!r} (guard with is_decoy_path first)")
    clean = path.split("?", 1)[0].split("#", 1)[0].strip().lower()
    cid = _canary_token(clean, token)
    renderer = _select_renderer(clean)
    if renderer is None:  # pragma: no cover - DECOY_PATHS without a renderer
        renderer = _fake_env
    body = renderer(cid)
    if CANARY_MARKER.encode("utf-8") not in body:  # safety: always traceable
        body += f"\n# {cid}\n".encode("utf-8")
    return body


def decoy_headers(path: str) -> Dict[str, str]:
    """Plausible response headers to accompany a decoy body (best-effort).

    Content-Type is chosen to match what a scanner would expect for the probed
    artifact, reinforcing the illusion. Purely cosmetic; safe to ignore.
    """
    clean = (path or "").split("?", 1)[0].lower()
    if clean.endswith(".json") or clean.startswith("/actuator") or clean.startswith("/api/"):
        ctype = "application/json"
    elif clean.endswith(".php") or clean.startswith("/wp-"):
        ctype = "text/html; charset=UTF-8"
    elif clean.endswith(".sql"):
        ctype = "application/sql"
    else:
        ctype = "text/plain; charset=UTF-8"
    return {
        "Content-Type": ctype,
        "X-Canary": CANARY_MARKER,  # defender-side tracer; harmless to the client
        "Cache-Control": "no-store",
    }

"""Durable block/patch state for the Root Justice / Artex Antidote blue-team shield.

This module provides :class:`DurableRegistry`, a drop-in, disk-backed replacement
for :class:`artex_antidote.shield.VirtualPatchRegistry`. The in-memory registry in
``shield`` loses every blocked IP and virtual patch the moment the process exits or
restarts; a long-lived defender wants its containment decisions to *survive* a
restart, a crash, or a redeploy. :class:`DurableRegistry` keeps the identical public
API but persists state to a local SQLite database (standard library ``sqlite3``), so a
freshly constructed instance pointed at the same database file sees everything the
previous instance wrote.

Design notes
------------
* **Same API as VirtualPatchRegistry.** ``block_ip``, ``add_virtual_patch``,
  ``is_ip_blocked``, ``match_virtual_patch`` and ``snapshot`` behave exactly like the
  in-memory version, so ``ArtexShield(patches=DurableRegistry(path))`` just works.
* **Strictly defensive.** This only records *our own* decisions to block or patch
  inbound requests to the protected service. It never reaches out to any third-party
  host and performs no network I/O at all.
* **Path-boundary matching.** ``match_virtual_patch`` matches the exact probed path or
  a child under a real ``/`` boundary. ``"/"`` is never treated as a wildcard that
  would flag the entire site (mirrors the hardened behavior in ``shield``).
* **Optional TTL on blocks.** ``block_ip(..., ttl_seconds=...)`` records an expiry.
  Expired blocks are transparently ignored by ``is_ip_blocked`` / ``snapshot`` and are
  lazily purged, so a temporary containment action self-heals without a sweeper thread.

The module is safe to use from multiple threads in one process (``check_same_thread``
is disabled and every mutation is a short committed transaction).
"""

from __future__ import annotations

import sqlite3
import threading
import time
from typing import Dict, Optional

__all__ = ["DurableRegistry"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip         TEXT PRIMARY KEY,
    reason     TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL            -- NULL means "never expires"
);
CREATE TABLE IF NOT EXISTS patched_paths (
    path_prefix TEXT PRIMARY KEY,
    reason      TEXT NOT NULL,
    created_at  REAL NOT NULL
);
"""


class DurableRegistry:
    """SQLite-backed, restart-surviving block/patch registry.

    API-compatible with :class:`artex_antidote.shield.VirtualPatchRegistry`:

    * :meth:`block_ip` -- record an IP that should be blocked (optional TTL).
    * :meth:`add_virtual_patch` -- record a path (prefix) that should be patched.
    * :meth:`is_ip_blocked` -> ``Optional[str]`` -- reason if currently blocked.
    * :meth:`match_virtual_patch` -> ``Optional[str]`` -- reason if the path is patched.
    * :meth:`snapshot` -> ``dict`` -- ``{"blocked_ips": {...}, "patched_paths": {...}}``.

    Parameters
    ----------
    db_path:
        Filesystem path to the SQLite database. The file (and its schema) is created
        if it does not yet exist. Use ``":memory:"`` for an ephemeral, non-durable
        store (useful only when you explicitly do not want persistence).
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        # check_same_thread=False: we guard all access with our own lock, which lets
        # the registry be shared across request-handler threads.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.executescript(_SCHEMA)

    # -- time seam (overridable/mocked in tests; no network, just wall clock) ------
    @staticmethod
    def _now() -> float:
        """Current epoch seconds. Separated out so tests can control TTL timing."""
        return time.time()

    # -- mutations ----------------------------------------------------------------
    def block_ip(self, ip: str, reason: str, ttl_seconds: Optional[float] = None) -> None:
        """Durably block ``ip``, recording ``reason``.

        If ``ttl_seconds`` is given, the block automatically expires that many seconds
        from now; afterwards :meth:`is_ip_blocked` returns ``None`` for it and it is
        omitted from :meth:`snapshot`. ``ttl_seconds=None`` (the default) blocks
        indefinitely, matching ``VirtualPatchRegistry.block_ip``.
        """
        now = self._now()
        expires_at = now + ttl_seconds if ttl_seconds is not None else None
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO blocked_ips (ip, reason, created_at, expires_at) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(ip) DO UPDATE SET "
                "reason=excluded.reason, created_at=excluded.created_at, "
                "expires_at=excluded.expires_at",
                (ip, reason, now, expires_at),
            )

    def add_virtual_patch(self, path_prefix: str, rule_reason: str) -> None:
        """Durably register a virtual patch for ``path_prefix`` with ``rule_reason``."""
        now = self._now()
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO patched_paths (path_prefix, reason, created_at) "
                "VALUES (?, ?, ?) "
                "ON CONFLICT(path_prefix) DO UPDATE SET "
                "reason=excluded.reason, created_at=excluded.created_at",
                (path_prefix, rule_reason, now),
            )

    # -- queries ------------------------------------------------------------------
    def is_ip_blocked(self, ip: str) -> Optional[str]:
        """Return the block reason for ``ip`` if it is currently blocked, else ``None``.

        Expired (TTL) blocks are treated as not blocked and are purged lazily.
        """
        now = self._now()
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT reason, expires_at FROM blocked_ips WHERE ip = ?", (ip,)
            ).fetchone()
            if row is None:
                return None
            if row["expires_at"] is not None and row["expires_at"] <= now:
                # Lazily purge the stale block so the row does not linger forever.
                self._conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
                return None
            return row["reason"]

    def match_virtual_patch(self, path: str) -> Optional[str]:
        """Return the patch reason if ``path`` matches a registered patch, else ``None``.

        Matches the exact probed path or a child under a real ``/`` boundary. ``"/"``
        is never treated as a wildcard, so a root patch does not flag the whole site.
        Mirrors ``VirtualPatchRegistry.match_virtual_patch``.
        """
        probe = path.split("?")[0]
        with self._lock, self._conn:
            rows = self._conn.execute(
                "SELECT path_prefix, reason FROM patched_paths"
            ).fetchall()
        for row in rows:
            patched = row["path_prefix"]
            if patched == "/":
                continue
            if probe == patched or probe.startswith(patched.rstrip("/") + "/"):
                return row["reason"]
        return None

    def snapshot(self) -> Dict[str, Dict[str, str]]:
        """Return a plain-dict view of current state (expired blocks excluded)."""
        now = self._now()
        with self._lock, self._conn:
            ip_rows = self._conn.execute(
                "SELECT ip, reason, expires_at FROM blocked_ips"
            ).fetchall()
            path_rows = self._conn.execute(
                "SELECT path_prefix, reason FROM patched_paths"
            ).fetchall()
        blocked_ips = {
            r["ip"]: r["reason"]
            for r in ip_rows
            if r["expires_at"] is None or r["expires_at"] > now
        }
        patched_paths = {r["path_prefix"]: r["reason"] for r in path_rows}
        return {"blocked_ips": blocked_ips, "patched_paths": patched_paths}

    # -- housekeeping -------------------------------------------------------------
    def purge_expired(self) -> int:
        """Delete all expired TTL blocks now; return the number removed."""
        now = self._now()
        with self._lock, self._conn:
            cur = self._conn.execute(
                "DELETE FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at <= ?",
                (now,),
            )
            return cur.rowcount

    def close(self) -> None:
        """Close the underlying SQLite connection. Safe to call more than once."""
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    def __enter__(self) -> "DurableRegistry":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

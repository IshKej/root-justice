"""Evidence ledger rotation and retention (defensive, offline-only).

The live evidence ledger (see :mod:`artex_antidote.evidence`) is a strictly
append-only JSONL file with a forward hash chain. Left unbounded it would grow
without limit, so this module adds *rotation* (seal the current live file into a
timestamped archive once it crosses a size threshold) and *retention* (delete
archives older than a retention window). It never rewrites, reorders, or drops
lines inside a ledger, and it never deletes the active live file: rotation moves
the full live file aside into an archive and immediately recreates a live file
in its place, so appends continue uninterrupted.

Preserving the chain across the archive boundary
------------------------------------------------
By default (``continuation=False``) the recreated live file is *empty*, which
means the next record appended to it chains from genesis -- the live file then
verifies as "intact" on its own even if an entire sealed archive has been
deleted. That is a real gap for chain-of-custody. Pass ``continuation=True`` to
:func:`rotate_if_needed` (or construct the store with ``chain_across_rotation``)
and rotation instead seeds the new live file with a one-line *continuation
header*::

    {"continuation": true, "prev_archive": "<archive name>", "prev_hash": "<last entry_hash>"}

The next append then chains from ``prev_hash`` rather than genesis, and
:func:`artex_antidote.evidence.EvidenceStore.verify_chain` can walk every
archive in order and confirm each file's first ``prev_hash`` equals the prior
archive's last ``entry_hash`` -- so deleting any archive breaks the link and
makes an across-archives verification fail.

Honesty about what this proves
------------------------------
The bare hash chain is **unkeyed SHA-256**. It reliably detects accidental or
naive edits, truncation, reordering, and bit-rot corruption, because any such
change breaks the recomputed chain. It does **not** by itself stop a motivated
tamperer, who can recompute every downstream hash after an edit. Forensic-grade
integrity requires signing the sealed archives and the manifest with
:func:`artex_antidote.signing.sign_file` under a key held outside the evidence
tree (ideally an asymmetric key, so a third party can verify). The ``manifest``
and signing hooks here exist to make that step easy, not to replace it.

Design notes
------------
* **No wall-clock reads.** Nothing here calls ``datetime.now`` / ``time.time``.
  The caller injects the timestamp used for an archive name (``rotate_if_needed``)
  and the "current time" used to judge archive age (``prune_archives``). This
  keeps the module deterministic and trivially testable, and lets an integrator
  drive it from a single authoritative clock.
* **Archive naming.** An archive for live file ``<path>`` is named
  ``<path>.<timestamp>.jsonl`` where ``<timestamp>`` is an integer epoch-seconds
  value supplied by the caller. ``prune_archives`` / ``retention_report`` locate
  archives by the trailing ``.<digits>.jsonl`` marker, so an ordinary live file
  such as ``ledger.jsonl`` is never mistaken for an archive.
* **Manifest.** When a ``manifest_path`` is supplied, each sealed archive's final
  ``entry_hash`` and record count are appended to a JSONL manifest, and each
  pruned archive leaves a tombstone line instead of vanishing silently. The
  manifest is signed-capable: pass a ``sign_key_path`` (and ``sign_timestamp``)
  to re-sign it with :mod:`artex_antidote.signing` after every update.
* **Mockable I/O seam.** File size is read through the module-level
  :func:`_file_size` hook so tests can inject sizes without writing large files.

Public API: :func:`rotate_if_needed`, :func:`prune_archives`,
:func:`retention_report`, plus the helpers :func:`is_archive`,
:func:`archive_timestamp`, :func:`list_archives`, :func:`read_manifest` and
:func:`ledger_tail`.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

__all__ = [
    "rotate_if_needed",
    "prune_archives",
    "retention_report",
    "is_archive",
    "archive_timestamp",
    "list_archives",
    "read_manifest",
    "ledger_tail",
    "SECONDS_PER_DAY",
]

SECONDS_PER_DAY = 86_400

# An archive ends with ".<integer epoch seconds>.jsonl". The live ledger
# (e.g. "evidence.jsonl") does not match, so it is never treated as an archive.
_ARCHIVE_RE = re.compile(r"\.(\d+)\.jsonl$")

GENESIS_HASH = "0" * 64


# --------------------------------------------------------------------------- #
# Mockable I/O seam (tests monkeypatch these; no network is involved).
# --------------------------------------------------------------------------- #
def _file_size(path: Union[str, Path]) -> int:
    """Return the size of ``path`` in bytes. Overridable in tests."""
    return os.path.getsize(path)


# --------------------------------------------------------------------------- #
# Archive identification helpers.
# --------------------------------------------------------------------------- #
def is_archive(name: Union[str, Path]) -> bool:
    """True if ``name`` looks like a rotated archive (``*.<digits>.jsonl``)."""
    return _ARCHIVE_RE.search(Path(name).name) is not None


def archive_timestamp(name: Union[str, Path]) -> Optional[int]:
    """Extract the injected epoch-seconds timestamp from an archive name.

    Returns ``None`` when ``name`` is not a recognised archive.
    """
    m = _ARCHIVE_RE.search(Path(name).name)
    return int(m.group(1)) if m else None


def list_archives(directory: Union[str, Path]) -> List[Path]:
    """All archive files directly inside ``directory``, sorted by timestamp.

    A missing directory yields an empty list (nothing to retain).
    """
    d = Path(directory)
    if not d.is_dir():
        return []
    archives = [p for p in d.iterdir() if p.is_file() and is_archive(p.name)]
    archives.sort(key=lambda p: (archive_timestamp(p) or 0, p.name))
    return archives


# --------------------------------------------------------------------------- #
# Chain / manifest helpers.
# --------------------------------------------------------------------------- #
def ledger_tail(path: Union[str, Path]) -> Dict[str, Any]:
    """Summarise a ledger file's hash chain without recomputing it.

    Reads the JSONL file at ``path`` and returns a dict describing its tail:

    * ``final_hash`` -- the ``entry_hash`` of the last record line, or, for a
      file that holds only a continuation header and no records yet, that
      header's ``prev_hash`` (the chain is simply carried forward unchanged), or
      :data:`GENESIS_HASH` for an empty/absent file.
    * ``record_count`` -- number of record lines (continuation headers excluded).
    * ``first_prev_hash`` -- the ``prev_hash`` the file chains *from*: a
      continuation header's ``prev_hash`` when present, else the first record's
      ``prev_hash``, else ``None``.
    * ``first_ts`` / ``last_ts`` -- first and last record ``timestamp_utc``
      values when available (``None`` otherwise).

    This is a lightweight reader for manifest bookkeeping; it does not verify the
    chain (see :meth:`EvidenceStore.verify_chain` for that).
    """
    p = Path(path)
    result: Dict[str, Any] = {
        "final_hash": GENESIS_HASH,
        "record_count": 0,
        "first_prev_hash": None,
        "first_ts": None,
        "last_ts": None,
    }
    if not p.exists():
        return result
    seeded_from_header = False
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("continuation") is True:
                prev = obj.get("prev_hash")
                if prev is not None:
                    result["first_prev_hash"] = prev
                    result["final_hash"] = prev
                    seeded_from_header = True
                continue
            if not isinstance(obj, dict) or "entry_hash" not in obj:
                continue
            if result["record_count"] == 0 and not seeded_from_header:
                result["first_prev_hash"] = obj.get("prev_hash")
            result["final_hash"] = obj["entry_hash"]
            result["record_count"] += 1
            rec = obj.get("record") or {}
            ts = rec.get("timestamp_utc") if isinstance(rec, dict) else None
            if ts is not None:
                if result["first_ts"] is None:
                    result["first_ts"] = ts
                result["last_ts"] = ts
    return result


def read_manifest(manifest_path: Union[str, Path]) -> List[Dict[str, Any]]:
    """Return the manifest entries (one dict per JSONL line); ``[]`` if absent."""
    p = Path(manifest_path)
    if not p.exists():
        return []
    out: List[Dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _append_manifest_entry(
    manifest_path: Union[str, Path],
    entry: Dict[str, Any],
    *,
    sign_key_path: Optional[str],
    sign_timestamp: Optional[str],
) -> None:
    """Append one JSON line to the manifest and, if keyed, re-sign the file."""
    mp = Path(manifest_path)
    mp.parent.mkdir(parents=True, exist_ok=True)
    with mp.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
    if sign_key_path is not None:
        # Local import keeps signing optional and avoids any import cycle.
        from . import signing

        signing.sign_file(str(mp), sign_key_path, timestamp=sign_timestamp)


# --------------------------------------------------------------------------- #
# Rotation.
# --------------------------------------------------------------------------- #
def rotate_if_needed(
    path: Union[str, Path],
    max_bytes: int,
    timestamp: int,
    *,
    continuation: bool = False,
    manifest_path: Optional[Union[str, Path]] = None,
    sign_key_path: Optional[str] = None,
    sign_timestamp: Optional[str] = None,
) -> Optional[str]:
    """Seal the live ledger into a timestamped archive if it is over size.

    If the live file at ``path`` exists and its size is strictly greater than
    ``max_bytes``, it is renamed to ``<path>.<timestamp>.jsonl`` and a live file
    is recreated at ``path`` so that appends continue and the active ledger is
    never missing. The absolute archive path is returned.

    Returns ``None`` (and touches nothing) when the file is absent or at/under
    ``max_bytes``. ``timestamp`` is caller-supplied epoch seconds; this function
    never reads the clock itself.

    Keyword-only, all backward-compatible (defaults reproduce the historical
    behaviour exactly -- an empty recreated live file and no manifest):

    * ``continuation`` -- when ``True``, seed the recreated live file with a
      continuation header carrying the sealed archive's final ``entry_hash`` and
      name, so the chain of custody links across the boundary and a later append
      chains from that hash instead of genesis. When ``False`` (default) the live
      file is recreated empty.
    * ``manifest_path`` -- when given, append a ``{"type": "sealed", ...}`` entry
      recording the sealed archive's name, final hash, record count and record
      timestamp range.
    * ``sign_key_path`` / ``sign_timestamp`` -- when given with a manifest, the
      manifest is re-signed with :mod:`artex_antidote.signing` after the append
      (unkeyed SHA-256 chaining alone is not forensic proof -- see module docs).

    Raises:
        ValueError: if ``max_bytes`` is negative or ``timestamp`` is not a
            non-negative integer.
    """
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp < 0:
        raise ValueError("timestamp must be a non-negative integer (epoch seconds)")

    p = Path(path)
    if not p.exists():
        return None
    if _file_size(p) <= max_bytes:
        return None

    archive = p.with_name(f"{p.name}.{timestamp}.jsonl")
    # os.replace is atomic on the same filesystem and preserves the file's bytes
    # exactly -- we move the whole ledger aside, never edit it line by line.
    os.replace(p, archive)

    # Inspect the sealed archive's tail for the continuation header and manifest.
    tail = ledger_tail(archive)

    if continuation:
        # Recreate the live ledger seeded with a continuation header so the chain
        # links across the boundary (next append chains from the sealed hash).
        header = {
            "continuation": True,
            "prev_archive": archive.name,
            "prev_hash": tail["final_hash"],
        }
        p.write_text(json.dumps(header, ensure_ascii=False) + "\n", encoding="utf-8")
    else:
        # Historical behaviour: recreate an empty live ledger.
        p.touch()

    if manifest_path is not None:
        _append_manifest_entry(
            manifest_path,
            {
                "type": "sealed",
                "archive": archive.name,
                "final_hash": tail["final_hash"],
                "record_count": tail["record_count"],
                "first_ts": tail["first_ts"],
                "last_ts": tail["last_ts"],
                "rotated_at": timestamp,
            },
            sign_key_path=sign_key_path,
            sign_timestamp=sign_timestamp,
        )

    return str(archive.resolve())


# --------------------------------------------------------------------------- #
# Retention / pruning.
# --------------------------------------------------------------------------- #
def prune_archives(
    directory: Union[str, Path],
    retain_days: int,
    now_ts: int,
    *,
    manifest_path: Optional[Union[str, Path]] = None,
    sign_key_path: Optional[str] = None,
    sign_timestamp: Optional[str] = None,
) -> List[str]:
    """Delete archives older than ``retain_days`` relative to ``now_ts``.

    An archive is removed when ``now_ts - archive_timestamp > retain_days * 86400``
    (strictly older than the window; an archive exactly at the boundary is kept).
    Only recognised archive files are ever considered, so the live ledger and any
    unrelated files are left untouched. ``now_ts`` is caller-supplied epoch
    seconds -- no clock is read here.

    Keyword-only (default behaviour unchanged):

    * ``manifest_path`` -- when given, each archive removed leaves a
      ``{"type": "tombstone", ...}`` line in the manifest recording its name, its
      final hash, its record count and its timestamp range, *before* the file is
      unlinked. This keeps a durable record of what was retained and when it was
      pruned, instead of the archive disappearing silently.
    * ``sign_key_path`` / ``sign_timestamp`` -- when given with a manifest, the
      manifest is re-signed after each tombstone is appended.

    Returns the sorted list of absolute paths that were removed.

    Raises:
        ValueError: if ``retain_days`` is negative.
    """
    if retain_days < 0:
        raise ValueError("retain_days must be non-negative")

    cutoff = retain_days * SECONDS_PER_DAY
    removed: List[str] = []
    for archive in list_archives(directory):
        ts = archive_timestamp(archive)
        if ts is None:
            continue
        if now_ts - ts > cutoff:
            resolved = str(archive.resolve())
            if manifest_path is not None:
                tail = ledger_tail(archive)
                _append_manifest_entry(
                    manifest_path,
                    {
                        "type": "tombstone",
                        "archive": archive.name,
                        "final_hash": tail["final_hash"],
                        "record_count": tail["record_count"],
                        "ts_range": [tail["first_ts"], tail["last_ts"]],
                        "archive_ts": ts,
                        "pruned_at": now_ts,
                    },
                    sign_key_path=sign_key_path,
                    sign_timestamp=sign_timestamp,
                )
            archive.unlink()
            removed.append(resolved)
    removed.sort()
    return removed


# --------------------------------------------------------------------------- #
# Reporting.
# --------------------------------------------------------------------------- #
def retention_report(directory: Union[str, Path]) -> Dict[str, object]:
    """Summarise the archives currently held in ``directory``.

    The report is a plain dict (JSON-serialisable) describing how many archives
    exist, their combined on-disk size, the oldest/newest injected timestamps,
    and a per-archive breakdown. It reads the clock nowhere and mutates nothing,
    so it is safe to call as part of a status/health endpoint.
    """
    archives = list_archives(directory)
    entries: List[Dict[str, object]] = []
    total_bytes = 0
    timestamps: List[int] = []
    for p in archives:
        ts = archive_timestamp(p)
        size = _file_size(p)
        total_bytes += size
        if ts is not None:
            timestamps.append(ts)
        entries.append(
            {
                "name": p.name,
                "path": str(p.resolve()),
                "timestamp": ts,
                "size_bytes": size,
            }
        )
    return {
        "directory": str(Path(directory).resolve()),
        "archive_count": len(archives),
        "total_bytes": total_bytes,
        "oldest_timestamp": min(timestamps) if timestamps else None,
        "newest_timestamp": max(timestamps) if timestamps else None,
        "archives": entries,
    }

"""Append-only chain-of-custody evidence store and human-review gate.

Agent B (Attribution, REA & Evidence) writes one record per flagged event here.
Records carry the resolved origin (with per-hop confidence), the matched
detection, optional REA static-analysis findings, and a running SHA-256 hash
chain. Nothing in this module contacts an external authority: submission to FBI
IC3 / CISA is always a deliberate human step, and records whose origin is not
reportable (attribution rests only on a spoofable header) are held back from
auto-generated bundles.

Integrity: what the hash chain does and does not prove
------------------------------------------------------
The chain is **unkeyed SHA-256**: each entry hashes ``prev_hash + record``, so
recomputing the chain reliably surfaces *accidental or naive* tampering --
an edited, inserted, reordered, truncated, or bit-rot-corrupted line breaks the
chain and :meth:`EvidenceStore.verify_chain` reports where. It does **not** by
itself defeat a motivated tamperer: anyone who edits a record can recompute
every later hash so the chain still closes. Forensic-grade integrity requires
signing the ledger/archives with :func:`artex_antidote.signing.sign_file` under
a key held outside the evidence tree (asymmetric, ideally, so a third party can
verify without the signing key). Treat the chain as corruption/edit detection,
and signing as the tamper-evidence that stands up to an adversary.

Rotation and the chain across archives
--------------------------------------
When the live ledger is rotated (see :mod:`artex_antidote.retention`) with
``chain_across_rotation=True``, the sealed archive's final ``entry_hash`` is
carried into the new live file as a continuation header, so the chain links
across the boundary. :meth:`EvidenceStore.verify_chain` with
``across_archives=True`` then walks every archive in order and fails if any
archive is missing or any cross-file link does not match.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from . import retention


GENESIS_HASH = "0" * 64


def _canonical(record: Dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _chain_hash(prev_hash: str, record: Dict[str, Any]) -> str:
    return hashlib.sha256(f"{prev_hash}\n{_canonical(record)}".encode("utf-8")).hexdigest()


@dataclass
class EvidenceRecord:
    """A single chain-of-custody entry (one flagged event)."""

    timestamp_utc: str
    stream_id: str
    attributed_ip: str
    attributed_confidence: str
    is_reportable: bool
    ip_chain: List[Dict[str, Any]]
    method: str
    path: str
    user_agent: str
    header_hash: str
    body_sha256: str
    severity: str
    reasons: List[str]
    matched_rule: str = ""
    action_taken: str = ""
    rea_findings: Optional[Dict[str, Any]] = None
    rdap: Optional[Dict[str, Any]] = None

    def payload(self) -> Dict[str, Any]:
        return {
            "timestamp_utc": self.timestamp_utc,
            "stream_id": self.stream_id,
            "attributed_ip": self.attributed_ip,
            "attributed_confidence": self.attributed_confidence,
            "is_reportable": self.is_reportable,
            "ip_chain": self.ip_chain,
            "method": self.method,
            "path": self.path,
            "user_agent": self.user_agent,
            "header_hash": self.header_hash,
            "body_sha256": self.body_sha256,
            "severity": self.severity,
            "reasons": self.reasons,
            "matched_rule": self.matched_rule,
            "action_taken": self.action_taken,
            "rea_findings": self.rea_findings,
            "rdap": self.rdap,
        }


def header_fingerprint(headers: Dict[str, str]) -> str:
    """Stable SHA-256 over sorted header name/value pairs (JA3-style stand-in)."""
    items = sorted((k.lower(), v) for k, v in headers.items())
    return hashlib.sha256(json.dumps(items, sort_keys=True).encode("utf-8")).hexdigest()


def _is_continuation(obj: Any) -> bool:
    """True if ``obj`` is a rotation continuation header (not a record entry)."""
    return isinstance(obj, dict) and obj.get("continuation") is True


class EvidenceStore:
    """Append-only JSONL ledger with a per-record forward SHA-256 hash chain.

    The chain detects accidental edits, insertions, reordering, truncation and
    corruption; it is not, on its own, proof against a motivated tamperer (who
    can recompute later hashes). For adversary-resistant integrity sign the
    ledger and its archives with :mod:`artex_antidote.signing`. See the module
    docstring for the full threat model.
    """

    def __init__(
        self,
        path: str,
        *,
        max_bytes: Optional[int] = None,
        chain_across_rotation: bool = False,
        manifest_path: Optional[str] = None,
        sign_key_path: Optional[str] = None,
        sign_timestamp: Optional[str] = None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Size threshold (bytes) above which ``append`` rotates the live ledger
        # into a timestamped archive. ``None`` (the default) disables rotation
        # entirely, so historical callers and tests are completely unaffected.
        self.max_bytes = max_bytes
        # When True, rotation seeds the new live file with a continuation header
        # carrying the sealed archive's final hash, so the chain links across the
        # boundary and a deleted archive is detectable. Default False reproduces
        # the historical behaviour (the new live file restarts from genesis).
        self.chain_across_rotation = chain_across_rotation
        # Optional signed-capable archive manifest (see retention). Defaults to
        # "<path>.manifest.jsonl" when cross-rotation chaining is enabled so each
        # sealed archive's final hash + count is recorded durably.
        if manifest_path is None and chain_across_rotation:
            manifest_path = str(self.path) + ".manifest.jsonl"
        self.manifest_path = manifest_path
        self.sign_key_path = sign_key_path
        self.sign_timestamp = sign_timestamp
        # Absolute path of the archive produced by the most recent append-driven
        # rotation, or ``None`` if the last append did not rotate. Purely
        # informational (handy for a status/maintenance log).
        self.last_rotated_archive: Optional[str] = None

    def _last_hash(self) -> str:
        """Hash the next appended record should chain from.

        This is the last record's ``entry_hash``; for a freshly rotated live
        file that holds only a continuation header, it is that header's
        ``prev_hash`` (the sealed archive's final hash), so the chain continues
        across the boundary rather than restarting from genesis.
        """
        last = GENESIS_HASH
        if not self.path.exists():
            return last
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if _is_continuation(obj):
                    prev = obj.get("prev_hash")
                    if prev is not None:
                        last = prev
                    continue
                if isinstance(obj, dict) and "entry_hash" in obj:
                    last = obj["entry_hash"]
        return last

    def append(
        self, record: EvidenceRecord, *, rotate_timestamp: Optional[int] = None
    ) -> Dict[str, Any]:
        """Append one chain-linked record; optionally rotate an oversized ledger.

        The record is always written first, so the appended entry is never lost.
        Rotation happens *after* the write and only when BOTH a ``max_bytes``
        threshold was configured on this store AND the caller supplies
        ``rotate_timestamp`` (epoch seconds) — this module reads no clock itself,
        in keeping with the retention module's deterministic, caller-driven time.
        When those conditions hold and the live file has grown past ``max_bytes``,
        :func:`retention.rotate_if_needed` seals the full live file into
        ``<path>.<rotate_timestamp>.jsonl`` and recreates the live ledger so
        subsequent appends continue uninterrupted.

        If this store was built with ``chain_across_rotation=True``, the sealed
        archive's final ``entry_hash`` is carried into the new live file as a
        continuation header, so the chain of custody links across the boundary
        (the next appended record chains from that hash, not from genesis) and a
        later deletion of the archive is detectable by
        ``verify_chain(across_archives=True)``. The sealed archive's final hash
        and record count are also recorded in the signed-capable manifest.
        Otherwise (the default) the new live file is empty and records written
        after the boundary chain from genesis.

        Returns the written entry dict, with a ``"rotated_archive"`` key added
        when this append triggered a rotation.
        """
        prev = self._last_hash()
        payload = record.payload()
        entry_hash = _chain_hash(prev, payload)
        entry = {"prev_hash": prev, "entry_hash": entry_hash, "record": payload}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

        self.last_rotated_archive = None
        if self.max_bytes is not None and rotate_timestamp is not None:
            archive = retention.rotate_if_needed(
                self.path,
                max_bytes=self.max_bytes,
                timestamp=rotate_timestamp,
                continuation=self.chain_across_rotation,
                manifest_path=self.manifest_path,
                sign_key_path=self.sign_key_path,
                sign_timestamp=self.sign_timestamp,
            )
            if archive is not None:
                self.last_rotated_archive = archive
                entry["rotated_archive"] = archive
        return entry

    def read_all(self) -> List[Dict[str, Any]]:
        """All JSONL lines of the live file, including any continuation header."""
        return self._read_file(self.path)

    @staticmethod
    def _read_file(path: Path) -> List[Dict[str, Any]]:
        if not path.exists():
            return []
        out: List[Dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def records(self) -> List[Dict[str, Any]]:
        """Record payloads of the live file (continuation headers excluded)."""
        return [e["record"] for e in self.read_all() if not _is_continuation(e)]

    @staticmethod
    def _verify_entries(
        entries: List[Dict[str, Any]], prev: str, *, enforce_link: bool = True
    ) -> Dict[str, Any]:
        """Walk one file's entries from ``prev``; report the first break.

        A leading continuation header establishes the link across a rotation
        boundary. When ``enforce_link`` is True (across-archives walk) its
        ``prev_hash`` must equal the incoming ``prev`` (the prior file's final
        hash, or genesis for the first file) -- this is how a missing or
        misordered archive is caught. When ``enforce_link`` is False (checking
        the live file on its own) the header simply *seeds* ``prev``, so a
        freshly rotated live file verifies internally without the earlier
        archives present. Returns ``{"ok", "prev", "count", "broken_at_index"}``.
        """
        count = 0
        for idx, entry in enumerate(entries):
            if _is_continuation(entry):
                header_prev = entry.get("prev_hash")
                if enforce_link and header_prev != prev:
                    return {"ok": False, "prev": prev, "count": count, "broken_at_index": idx}
                if header_prev is not None:
                    prev = header_prev
                continue
            expected = _chain_hash(entry.get("prev_hash", ""), entry.get("record", {}))
            if entry.get("prev_hash") != prev or entry.get("entry_hash") != expected:
                return {"ok": False, "prev": prev, "count": count, "broken_at_index": idx}
            prev = entry["entry_hash"]
            count += 1
        return {"ok": True, "prev": prev, "count": count, "broken_at_index": None}

    def _own_archives(self) -> List[Path]:
        """Rotated archives of THIS ledger, in timestamp order."""
        prefix = self.path.name + "."
        return [
            p
            for p in retention.list_archives(self.path.parent)
            if p.name.startswith(prefix)
        ]

    def verify_chain(self, *, across_archives: bool = False) -> Dict[str, Any]:
        """Recompute the hash chain; report the first break if any.

        With ``across_archives=False`` (default) only the live file is checked,
        starting from genesis (a leading continuation header is honoured so a
        freshly rotated live file still verifies). This detects accidental edits
        and corruption within the active ledger, but — by design — a live file
        that was rotated with an empty restart verifies as intact even if a
        sealed archive has since been deleted.

        With ``across_archives=True`` every rotated archive of this ledger is
        walked in timestamp order followed by the live file. Each file's first
        ``prev_hash`` (its continuation header, or its first record for the very
        first archive) must equal the prior file's final ``entry_hash``; genesis
        is expected only for the first file. A deleted archive therefore breaks a
        cross-file link and makes verification FAIL. This is corruption/edit and
        gap detection over unkeyed SHA-256 — forensic tamper-evidence still
        requires signed archives (:mod:`artex_antidote.signing`).
        """
        if not across_archives:
            res = self._verify_entries(self.read_all(), GENESIS_HASH, enforce_link=False)
            return {
                "intact": res["ok"],
                "broken_at_index": res["broken_at_index"],
                "verified_records": res["count"],
            }

        files = list(self._own_archives()) + [self.path]
        prev = GENESIS_HASH
        total = 0
        for file_idx, fpath in enumerate(files):
            entries = self._read_file(fpath)
            res = self._verify_entries(entries, prev)
            if not res["ok"]:
                return {
                    "intact": False,
                    "broken_at_file": file_idx,
                    "broken_file": fpath.name,
                    "broken_at_index": res["broken_at_index"],
                    "verified_records": total + res["count"],
                    "files_walked": file_idx + 1,
                    "archive_count": len(files) - 1,
                }
            prev = res["prev"]
            total += res["count"]
        return {
            "intact": True,
            "broken_at_file": None,
            "broken_file": None,
            "broken_at_index": None,
            "verified_records": total,
            "files_walked": len(files),
            "archive_count": len(files) - 1,
        }

    def reportable_records(self) -> List[Dict[str, Any]]:
        """Only records whose attribution does not rest on a spoofable assertion."""
        return [r for r in self.records() if r.get("is_reportable")]


def build_review_manifest(store: EvidenceStore) -> Dict[str, Any]:
    """Summarize what a human must sign off before any federal submission."""
    records = store.records()
    reportable = [r for r in records if r.get("is_reportable")]
    held = [r for r in records if not r.get("is_reportable")]
    chain = store.verify_chain()
    return {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "total_records": len(records),
        "reportable_records": len(reportable),
        "held_for_low_confidence": len(held),
        "chain_integrity": chain,
        "held_ips": sorted({r.get("attributed_ip", "") for r in held if r.get("attributed_ip")}),
        "review_required": True,
        "note": (
            "Records held for low confidence rest only on a spoofable header and "
            "must NOT be submitted to authorities without independent corroboration."
        ),
    }

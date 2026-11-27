"""Signed + timestamped evidence (Spec #9).

Detached integrity signing for Artex Antidote evidence artifacts using only
the Python standard library. Given any file on disk -- an evidence ledger
(``EvidenceStore`` JSONL), a generated report, a REA bundle -- this module
produces a small, self-describing ``*.sig.json`` sidecar that binds together:

  * a SHA-256 digest of the exact file bytes,
  * a caller-supplied timestamp (so the signing moment is recorded, not
    silently taken from a drifting local clock), and
  * an HMAC-SHA256 tag computed over a canonical header + the file digest,
    keyed by a secret stored outside the evidence tree.

Verification recomputes the digest and the HMAC and compares both in constant
time. Any change to the file bytes, the embedded timestamp, or the key makes
``verify_file`` return ``False``.

SCOPE / THREAT MODEL
--------------------
HMAC-SHA256 is a *symmetric* MAC: it proves that whoever created the signature
held the same secret key the verifier holds. That is the right, dependency-free
MVP for the common case where the defender signs their own evidence and later
checks it has not been altered at rest. It is NOT non-repudiation: anyone with
the key can both sign and verify, so an HMAC signature cannot prove to a *third
party* (a court, the FBI) that a specific party -- and no one else -- produced
it.

TODO (upgrade path, out of scope for the stdlib MVP):
  * Asymmetric detached signatures (Ed25519 / RSA-PSS) so verifiers need only a
    public key and signatures are non-repudiable. ``cryptography`` or PyNaCl.
  * RFC-3161 trusted timestamping: send the file digest to a TSA and store the
    returned signed timestamp token alongside the signature, so the "when" is
    attested by an independent authority rather than asserted by the signer.
    The ``tsa_stub`` hook below marks exactly where that token would attach.

Public API
----------
    generate_key(key_path)            -> bytes   # os.urandom key, 0600 where supported
    sign_file(path, key_path, ...)    -> dict    # writes path + '.sig.json'
    verify_file(path, sig_path, key)  -> bool
    load_key(key_path)                -> bytes

Network / TSA I/O goes through the module-level ``_http_post_tsa`` seam so tests
can monkeypatch it; by default no signing or verifying call touches the network.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional


SIG_SUFFIX = ".sig.json"
SIG_VERSION = 1
SIG_ALGORITHM = "HMAC-SHA256"
DEFAULT_KEY_BYTES = 32
_CHUNK = 65536


# --------------------------------------------------------------------------- #
# Key management
# --------------------------------------------------------------------------- #
def generate_key(key_path: str, *, nbytes: int = DEFAULT_KEY_BYTES) -> bytes:
    """Create a fresh random secret key with ``os.urandom`` and write it to disk.

    The raw key bytes are written (not hex/base64) so the file is exactly
    ``nbytes`` long. On POSIX the file mode is tightened to 0600; on Windows,
    where ``chmod`` is a no-op for this purpose, the write still succeeds and
    the caller is responsible for ACLs. Returns the key bytes.
    """
    if nbytes < 16:
        raise ValueError("refusing to generate a key shorter than 16 bytes")
    key = os.urandom(nbytes)
    path = Path(key_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Create restrictively where the platform honors it.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    try:
        os.chmod(str(path), 0o600)
    except (OSError, NotImplementedError):
        pass
    return key


def load_key(key_path: str) -> bytes:
    """Read the raw secret key bytes from ``key_path``."""
    key = Path(key_path).read_bytes()
    if not key:
        raise ValueError(f"key file is empty: {key_path}")
    return key


# --------------------------------------------------------------------------- #
# Hashing / canonicalization
# --------------------------------------------------------------------------- #
def _file_sha256(path: Path) -> str:
    """Streaming SHA-256 of the file's bytes (handles large evidence files)."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonical(obj: Dict[str, Any]) -> bytes:
    """Deterministic JSON encoding for the signed header."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _signed_header(
    *,
    filename: str,
    file_sha256: str,
    timestamp: str,
    algorithm: str,
    version: int,
    tsa: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """The exact fields covered by the HMAC. Order-independent via canonical JSON."""
    header: Dict[str, Any] = {
        "version": version,
        "algorithm": algorithm,
        "filename": filename,
        "file_sha256": file_sha256,
        "timestamp": timestamp,
    }
    if tsa is not None:
        header["tsa"] = tsa
    return header


def _compute_hmac(key: bytes, header: Dict[str, Any]) -> str:
    return hmac.new(key, _canonical(header), hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------- #
# Optional RFC-3161 TSA hook (network seam; no-op by default)
# --------------------------------------------------------------------------- #
def _http_post_tsa(url: str, digest_hex: str) -> Dict[str, Any]:  # pragma: no cover
    """Network seam for a future RFC-3161 Time-Stamp Authority request.

    The stdlib MVP never calls a TSA, so the real implementation is deliberately
    absent. Tests (and a later asymmetric upgrade) monkeypatch THIS function to
    return a timestamp token without any real network I/O. Leaving it as a
    module-level function keeps all network access behind one mockable seam.
    """
    raise NotImplementedError(
        "RFC-3161 timestamping is not part of the stdlib MVP; monkeypatch "
        "signing._http_post_tsa to supply a TSA token."
    )


def request_tsa_token(
    digest_hex: str,
    *,
    tsa_url: Optional[str] = None,
    tsa_stub: Optional[Callable[[str, str], Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    """Fetch an (optional) trusted-timestamp token for ``digest_hex``.

    By default returns ``None`` (no TSA used). If ``tsa_stub`` is given it is
    called as ``tsa_stub(tsa_url, digest_hex)`` -- this is the clean injection
    point for tests and for a future real TSA client. If only ``tsa_url`` is
    given, the module-level ``_http_post_tsa`` seam is used (which raises until
    implemented). The returned token, when present, is folded into the signed
    header so it is covered by the HMAC.
    """
    if tsa_stub is not None:
        return tsa_stub(tsa_url or "", digest_hex)
    if tsa_url is not None:
        return _http_post_tsa(tsa_url, digest_hex)
    return None


# --------------------------------------------------------------------------- #
# Sign / verify
# --------------------------------------------------------------------------- #
def sign_file(
    path: str,
    key_path: str,
    *,
    timestamp: Optional[str] = None,
    sig_path: Optional[str] = None,
    tsa_url: Optional[str] = None,
    tsa_stub: Optional[Callable[[str, str], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Create a detached HMAC-SHA256 signature for ``path``.

    Parameters
    ----------
    path:
        File whose bytes are signed.
    key_path:
        File holding the raw secret key (see ``generate_key``).
    timestamp:
        Caller-supplied signing time. Passed in as an argument so the caller
        controls the recorded moment (and tests are deterministic). If omitted,
        the current UTC time is used. Stored verbatim and HMAC-covered.
    sig_path:
        Where to write the sidecar. Defaults to ``path + '.sig.json'``.
    tsa_url / tsa_stub:
        Optional trusted-timestamp hook (see ``request_tsa_token``). Off by
        default; no network I/O unless supplied.

    Returns the signature dict that was written to ``sig_path``.
    """
    src = Path(path)
    if not src.is_file():
        raise FileNotFoundError(f"cannot sign, not a file: {path}")

    key = load_key(key_path)
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    file_sha256 = _file_sha256(src)
    tsa_token = request_tsa_token(file_sha256, tsa_url=tsa_url, tsa_stub=tsa_stub)

    header = _signed_header(
        filename=src.name,
        file_sha256=file_sha256,
        timestamp=timestamp,
        algorithm=SIG_ALGORITHM,
        version=SIG_VERSION,
        tsa=tsa_token,
    )
    signature = _compute_hmac(key, header)

    sidecar: Dict[str, Any] = dict(header)
    sidecar["signature"] = signature

    out_path = Path(sig_path) if sig_path else Path(str(src) + SIG_SUFFIX)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(sidecar, indent=2, ensure_ascii=False), encoding="utf-8")
    return sidecar


def verify_file(path: str, sig_path: str, key_path: str) -> bool:
    """Verify ``path`` against its ``sig_path`` sidecar using ``key_path``.

    Returns ``True`` only if (a) the sidecar parses, (b) the file's current
    SHA-256 matches the signed digest, and (c) the HMAC recomputed over the
    signed header equals the stored signature, under the given key. Any
    tampering of the file, the timestamp/header, or a wrong key yields
    ``False``. Never raises on a bad/missing signature -- it returns ``False``.
    """
    src = Path(path)
    sig = Path(sig_path)
    if not src.is_file() or not sig.is_file():
        return False

    try:
        sidecar = json.loads(sig.read_text(encoding="utf-8"))
        stored_sig = sidecar["signature"]
        signed_digest = sidecar["file_sha256"]
        header = _signed_header(
            filename=sidecar["filename"],
            file_sha256=signed_digest,
            timestamp=sidecar["timestamp"],
            algorithm=sidecar.get("algorithm", SIG_ALGORITHM),
            version=sidecar.get("version", SIG_VERSION),
            tsa=sidecar.get("tsa"),
        )
    except (json.JSONDecodeError, KeyError, TypeError, OSError):
        return False

    try:
        key = load_key(key_path)
    except (OSError, ValueError):
        return False

    # Bind the signature to the actual bytes on disk right now.
    actual_digest = _file_sha256(src)
    if not hmac.compare_digest(actual_digest, str(signed_digest)):
        return False

    expected_sig = _compute_hmac(key, header)
    return hmac.compare_digest(expected_sig, str(stored_sig))


__all__ = [
    "generate_key",
    "load_key",
    "sign_file",
    "verify_file",
    "request_tsa_token",
    "SIG_SUFFIX",
    "SIG_ALGORITHM",
    "SIG_VERSION",
]

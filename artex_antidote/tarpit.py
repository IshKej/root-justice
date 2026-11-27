"""Real tarpit (slow-drip) response generator — STRICTLY DEFENSIVE.

Spec #6: waste an automated attacker's time and connection budget by writing a
response to *your own* socket very slowly, a few bytes at a time with a sleep
between chunks. This never touches the attacker's machine; it only makes the
defender's own socket respond slowly, which ties up scrapers, brute-forcers and
vulnerability scanners that keep connections open waiting for a full reply.

There is no outbound action here. ``drip`` simply calls a ``write_fn`` you supply
(e.g. ``socket.sendall`` or ``wfile.write``) and a ``sleep_fn`` (default
``time.sleep``). A hard duration cap bounds how long the tarpit can run so it can
never hang a worker indefinitely.

Typical use in a request handler::

    from artex_antidote.tarpit import drip
    # ... having decided (via shield/attribution) that this is hostile automation
    stats = drip(conn.sendall, total_bytes=4096, chunk=1, delay=0.5,
                 max_duration=30.0)

The generator :func:`tarpit_bytes_sequence` is exposed separately so the drip
schedule can be inspected and unit-tested without any real socket or clock.

Public API:
    * :data:`DEFAULT_BANNER`
    * :class:`TarpitResult`
    * :func:`tarpit_bytes_sequence`
    * :func:`drip`
    * :func:`estimate_duration`
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Iterator, Optional, Union

__all__ = [
    "DEFAULT_BANNER",
    "TarpitResult",
    "tarpit_bytes_sequence",
    "drip",
    "estimate_duration",
]


# A deliberately slow, boring HTTP-ish preamble. Attackers' scanners often wait
# for headers; dribbling this out one byte at a time keeps them parked.
DEFAULT_BANNER = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: nginx\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"\r\n"
)


@dataclass
class TarpitResult:
    """Summary of a completed (or capped) drip run.

    Attributes:
        bytes_written: Total number of bytes handed to ``write_fn``.
        chunks: Number of chunk-writes performed.
        sleeps: Number of sleeps performed (one per chunk except, optionally,
            the final chunk — see ``drip``).
        elapsed: Elapsed seconds as measured by the clock function.
        capped: True if the run stopped because the duration cap was reached
            rather than because all ``total_bytes`` were written.
    """

    bytes_written: int = 0
    chunks: int = 0
    sleeps: int = 0
    elapsed: float = 0.0
    capped: bool = False


def _coerce_payload(payload: Optional[Union[bytes, bytearray]]) -> bytes:
    if payload is None:
        return DEFAULT_BANNER
    if isinstance(payload, bytearray):
        return bytes(payload)
    if isinstance(payload, bytes):
        return payload
    raise TypeError("payload must be bytes, bytearray or None")


def tarpit_bytes_sequence(
    total_bytes: int,
    chunk: int,
    payload: Optional[Union[bytes, bytearray]] = None,
) -> Iterator[bytes]:
    """Yield successive chunks of at most ``chunk`` bytes, up to ``total_bytes``.

    This is the pure, deterministic core of the tarpit: no sleeping, no I/O.
    The bytes are drawn by cycling over ``payload`` (default
    :data:`DEFAULT_BANNER`) so the stream looks like a plausible, endless
    response body. The sum of the yielded chunk lengths is exactly
    ``total_bytes`` (or 0 when inputs are non-positive).

    Args:
        total_bytes: Total number of bytes to emit across all chunks. Values
            <= 0 yield nothing.
        chunk: Maximum size of each yielded chunk. Must be >= 1.
        payload: Byte source cycled to fill chunks. Defaults to the banner.

    Yields:
        ``bytes`` objects, each 1..``chunk`` long; the last may be shorter.

    Raises:
        ValueError: If ``chunk`` < 1.
    """
    if chunk < 1:
        raise ValueError("chunk must be >= 1")
    if total_bytes <= 0:
        return
    src = _coerce_payload(payload)
    if not src:
        src = DEFAULT_BANNER

    remaining = total_bytes
    pos = 0
    src_len = len(src)
    while remaining > 0:
        take = chunk if chunk < remaining else remaining
        # Build this chunk by cycling over the payload bytes.
        out = bytearray()
        while len(out) < take:
            need = take - len(out)
            avail = src_len - pos
            step = need if need < avail else avail
            out += src[pos:pos + step]
            pos = (pos + step) % src_len
        yield bytes(out)
        remaining -= take


def estimate_duration(total_bytes: int, chunk: int, delay: float) -> float:
    """Return the ideal (uncapped) wall-clock seconds a drip would take.

    This is ``number_of_chunks * delay``, assuming a sleep after every chunk and
    ignoring the time spent writing. Useful for choosing a sensible
    ``max_duration`` cap. Non-positive inputs return 0.0.
    """
    if total_bytes <= 0 or chunk < 1 or delay <= 0:
        return 0.0
    # ceil division without importing math
    n_chunks = (total_bytes + chunk - 1) // chunk
    return n_chunks * delay


def drip(
    write_fn: Callable[[bytes], object],
    total_bytes: int,
    chunk: int,
    delay: float,
    *,
    max_duration: float = 30.0,
    payload: Optional[Union[bytes, bytearray]] = None,
    sleep_fn: Callable[[float], object] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    sleep_after_last: bool = False,
) -> TarpitResult:
    """Slowly write up to ``total_bytes`` to ``write_fn``, sleeping between chunks.

    The loop writes ``chunk`` bytes, sleeps ``delay`` seconds, and repeats until
    either all ``total_bytes`` have been written or the ``max_duration`` cap is
    reached (whichever comes first). The cap is a hard safety bound so a tarpit
    can never tie up the defender's own worker indefinitely.

    The duration cap is checked *before* each chunk using ``clock`` so iteration
    count is bounded by the cap even when ``sleep_fn`` is a fake that does not
    advance a real clock — pass a ``clock`` that advances (e.g. one driven by the
    fake ``sleep_fn``) to exercise capping deterministically in tests.

    This performs no network calls itself; it only invokes the ``write_fn`` and
    ``sleep_fn`` you provide. All I/O is therefore injectable and testable.

    Args:
        write_fn: Called with each chunk of bytes (e.g. ``socket.sendall``).
        total_bytes: Total bytes to drip out. Values <= 0 write nothing.
        chunk: Bytes per write; must be >= 1.
        delay: Seconds to sleep between chunks; negative is treated as 0.
        max_duration: Hard cap on elapsed seconds (measured via ``clock``).
            Values <= 0 mean "write a single chunk at most".
        payload: Byte source for the body (default :data:`DEFAULT_BANNER`).
        sleep_fn: Injected sleeper; defaults to :func:`time.sleep`.
        clock: Injected monotonic clock returning seconds; defaults to
            :func:`time.monotonic`.
        sleep_after_last: If False (default) the final chunk is not followed by a
            sleep, so a completed drip does not pay one extra ``delay``.

    Returns:
        A :class:`TarpitResult` describing what happened.

    Raises:
        ValueError: If ``chunk`` < 1.
    """
    if chunk < 1:
        raise ValueError("chunk must be >= 1")

    result = TarpitResult()
    if total_bytes <= 0:
        return result

    effective_delay = delay if delay > 0 else 0.0
    start = clock()

    chunks = list(tarpit_bytes_sequence(total_bytes, chunk, payload))
    last_index = len(chunks) - 1

    for i, piece in enumerate(chunks):
        elapsed = clock() - start
        # Hard duration cap: stop before writing another chunk once exceeded.
        if elapsed > max_duration:
            result.capped = True
            break

        write_fn(piece)
        result.bytes_written += len(piece)
        result.chunks += 1

        is_last = i == last_index
        if effective_delay > 0 and (sleep_after_last or not is_last):
            sleep_fn(effective_delay)
            result.sleeps += 1

    result.elapsed = clock() - start
    return result

"""Unit tests for the slow-drip tarpit (defensive spec #6).

All tests run fully offline: no sockets, no real clock, no sleeping. Network and
timing seams (``write_fn``, ``sleep_fn``, ``clock``) are injected so the drip
schedule and the hard duration cap are exercised deterministically.
"""

import io
import unittest

from artex_antidote.tarpit import (
    DEFAULT_BANNER,
    TarpitResult,
    drip,
    estimate_duration,
    tarpit_bytes_sequence,
)


class FakeSleeper:
    """Records sleep calls and advances a fake monotonic clock by each delay."""

    def __init__(self):
        self.calls = []
        self.now = 0.0

    def sleep(self, seconds):
        self.calls.append(seconds)
        self.now += seconds

    def clock(self):
        return self.now


class TarpitBytesSequenceTests(unittest.TestCase):
    def test_total_bytes_exact(self):
        chunks = list(tarpit_bytes_sequence(100, 7))
        self.assertEqual(sum(len(c) for c in chunks), 100)

    def test_chunk_sizes_bounded(self):
        chunks = list(tarpit_bytes_sequence(100, 7))
        # every chunk is at most `chunk`, and only the last may be short
        self.assertTrue(all(len(c) <= 7 for c in chunks))
        self.assertTrue(all(len(c) == 7 for c in chunks[:-1]))
        self.assertEqual(len(chunks[-1]), 100 % 7 or 7)

    def test_number_of_chunks_is_ceil(self):
        # 100 / 7 -> 15 chunks (14 full + remainder)
        self.assertEqual(len(list(tarpit_bytes_sequence(100, 7))), 15)

    def test_bytes_cycle_payload(self):
        payload = b"ABC"
        joined = b"".join(tarpit_bytes_sequence(7, 2, payload=payload))
        self.assertEqual(joined, b"ABCABCA")

    def test_default_payload_is_banner_prefix(self):
        joined = b"".join(tarpit_bytes_sequence(len(DEFAULT_BANNER), 4))
        self.assertEqual(joined, DEFAULT_BANNER)

    def test_zero_and_negative_total_yields_nothing(self):
        self.assertEqual(list(tarpit_bytes_sequence(0, 4)), [])
        self.assertEqual(list(tarpit_bytes_sequence(-10, 4)), [])

    def test_invalid_chunk_raises(self):
        with self.assertRaises(ValueError):
            list(tarpit_bytes_sequence(10, 0))


class DripTests(unittest.TestCase):
    def test_writes_all_bytes_to_bytesio(self):
        sink = io.BytesIO()
        faker = FakeSleeper()
        result = drip(
            sink.write,
            total_bytes=20,
            chunk=4,
            delay=0.5,
            max_duration=1000.0,
            sleep_fn=faker.sleep,
            clock=faker.clock,
        )
        self.assertIsInstance(result, TarpitResult)
        self.assertEqual(result.bytes_written, 20)
        self.assertEqual(len(sink.getvalue()), 20)
        self.assertEqual(result.chunks, 5)
        self.assertFalse(result.capped)

    def test_no_sleep_after_final_chunk_by_default(self):
        sink = io.BytesIO()
        faker = FakeSleeper()
        result = drip(
            sink.write,
            total_bytes=20,
            chunk=4,
            delay=0.5,
            max_duration=1000.0,
            sleep_fn=faker.sleep,
            clock=faker.clock,
        )
        # 5 chunks -> 4 sleeps (last chunk not followed by a sleep)
        self.assertEqual(result.sleeps, 4)
        self.assertEqual(faker.calls, [0.5, 0.5, 0.5, 0.5])

    def test_sleep_after_last_adds_one_more(self):
        sink = io.BytesIO()
        faker = FakeSleeper()
        result = drip(
            sink.write,
            total_bytes=20,
            chunk=4,
            delay=0.5,
            max_duration=1000.0,
            sleep_fn=faker.sleep,
            clock=faker.clock,
            sleep_after_last=True,
        )
        self.assertEqual(result.sleeps, 5)

    def test_duration_cap_bounds_iterations(self):
        # delay 1.0 per chunk, cap 3.0 -> clock exceeds cap after ~4 chunks.
        sink = io.BytesIO()
        faker = FakeSleeper()
        result = drip(
            sink.write,
            total_bytes=10_000,  # far more than the cap would ever allow
            chunk=1,
            delay=1.0,
            max_duration=3.0,
            sleep_fn=faker.sleep,
            clock=faker.clock,
        )
        self.assertTrue(result.capped)
        # Cap must stop it well short of total_bytes.
        self.assertLess(result.bytes_written, 10_000)
        # With delay 1.0 and cap 3.0, the check (elapsed > cap) fires once the
        # clock passes 3.0: chunks written at elapsed 0,1,2,3 then stop at 4.
        self.assertEqual(result.chunks, 4)
        self.assertEqual(result.bytes_written, 4)

    def test_cap_leaves_clock_consistent(self):
        faker = FakeSleeper()
        sink = io.BytesIO()
        result = drip(
            sink.write,
            total_bytes=10_000,
            chunk=1,
            delay=1.0,
            max_duration=3.0,
            sleep_fn=faker.sleep,
            clock=faker.clock,
        )
        # elapsed recorded equals the fake clock's advance from the sleeps.
        self.assertAlmostEqual(result.elapsed, sum(faker.calls))

    def test_zero_total_bytes_noop(self):
        sink = io.BytesIO()
        faker = FakeSleeper()
        result = drip(
            sink.write,
            total_bytes=0,
            chunk=4,
            delay=0.5,
            sleep_fn=faker.sleep,
            clock=faker.clock,
        )
        self.assertEqual(result.bytes_written, 0)
        self.assertEqual(result.chunks, 0)
        self.assertEqual(faker.calls, [])
        self.assertEqual(sink.getvalue(), b"")

    def test_negative_delay_treated_as_no_sleep(self):
        sink = io.BytesIO()
        faker = FakeSleeper()
        result = drip(
            sink.write,
            total_bytes=12,
            chunk=4,
            delay=-5.0,
            max_duration=1000.0,
            sleep_fn=faker.sleep,
            clock=faker.clock,
        )
        self.assertEqual(result.bytes_written, 12)
        self.assertEqual(result.sleeps, 0)
        self.assertEqual(faker.calls, [])

    def test_invalid_chunk_raises(self):
        with self.assertRaises(ValueError):
            drip(io.BytesIO().write, total_bytes=10, chunk=0, delay=0.1)

    def test_default_sleep_fn_is_time_sleep_but_not_called_when_offline(self):
        # delay 0 means sleep_fn is never invoked, so no real sleeping occurs
        # even though the default sleep_fn is time.sleep.
        sink = io.BytesIO()
        faker = FakeSleeper()
        result = drip(
            sink.write,
            total_bytes=8,
            chunk=2,
            delay=0.0,
            max_duration=1000.0,
            clock=faker.clock,  # keep default sleep_fn; delay 0 -> never called
        )
        self.assertEqual(result.bytes_written, 8)
        self.assertEqual(result.sleeps, 0)


class EstimateDurationTests(unittest.TestCase):
    def test_basic_estimate(self):
        # 20 bytes / 4 per chunk = 5 chunks * 0.5s = 2.5s
        self.assertEqual(estimate_duration(20, 4, 0.5), 2.5)

    def test_ceil_chunks(self):
        # 21 / 4 = 6 chunks * 1.0 = 6.0
        self.assertEqual(estimate_duration(21, 4, 1.0), 6.0)

    def test_nonpositive_inputs_zero(self):
        self.assertEqual(estimate_duration(0, 4, 0.5), 0.0)
        self.assertEqual(estimate_duration(20, 4, 0.0), 0.0)


if __name__ == "__main__":
    unittest.main()

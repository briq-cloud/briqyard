import random
import unittest

import stress_trend as t

BOUND = 32
# Readings recorded on hosted runners, one list per run. None of these daemons leaked; the
# adjacent-pair check failed two of them. They are single readings, noisier than the floors the
# driver judges now. The second run kept only its last pair.
RECORDED = [
    [76.6, 57.7, 36.5, 71.9],
    [34.0, 68.0],
    [41, 66, 32, 63],
    [51, 59, 76, 34],
    [32, 60, 34, 34],
]


def settled(cycles, leak, rng, readings=3):
    """Floors of a daemon idling at 31 MB plus a leak per cycle, each reading carrying 0..40 MB of
    allocator retention that only ever adds."""
    return [min(31.0 + leak * c + rng.uniform(0, 40) for _ in range(readings)) for c in range(cycles)]


class Helpers(unittest.TestCase):
    def test_floor_skips_missing(self):
        self.assertEqual(t.floor([40, None, 33, 50]), 33)
        self.assertIsNone(t.floor([None, None]))

    def test_slope(self):
        self.assertAlmostEqual(t.slope([1, 3, 5, 7]), 2)
        self.assertAlmostEqual(t.slope([5, 5, 5]), 0)

    def test_parse(self):
        line = "info daemon rss 35840 kB, 120 fds, 41 threads; machines 8 (8 live), endpoints 8, namespaces 4"
        self.assertEqual(t.parse_daemon_line("ok  x\n" + line + "\n"), (35.0, 120, 41))
        self.assertEqual(t.parse_daemon_line("nothing"), (None, None, None))
        self.assertEqual(t.parse_daemon_line("info daemon rss x kB, 1 fds, 2 threads; a b c"), (None, None, None))


class RecordedRuns(unittest.TestCase):
    def test_recorded_series_pass(self):
        # A series under four cycles cannot be judged and is skipped, as the driver does.
        for series in RECORDED:
            failed, msg = t.rss_verdict(series, BOUND)
            self.assertFalse(failed, f"{series}: {msg}")

    def test_recorded_swings_over_eight_cycles_pass(self):
        # The same readings as the 8 cycles of CI, in both orders.
        for series in RECORDED:
            if len(series) < 4:
                continue
            for s in (series + series[::-1], series[::-1] + series):
                failed, msg = t.rss_verdict(s, BOUND)
                self.assertFalse(failed, f"{s}: {msg}")


class Leaks(unittest.TestCase):
    def fails(self, leak, seeds=300):
        return sum(t.rss_verdict(settled(8, leak, random.Random(s)), BOUND)[0] for s in range(seeds))

    def test_no_leak_never_fails(self):
        self.assertEqual(self.fails(0.0), 0)

    def test_leaks_from_10_mb_a_cycle_fail_through_the_worst_swing(self):
        # Harsh on purpose: every reading carries 0..40 MB of retention, more than any recorded
        # floor. Over 8 cycles (6 intervals judged) the bound of 32 MB is 5.33 MB a cycle without
        # noise; through this noise 6 MB a cycle fails about two runs in three, 8 MB 95 %, 10 MB 99.9 %.
        self.assertGreater(self.fails(6.0), 150)
        self.assertGreater(self.fails(8.0), 270)
        self.assertGreater(self.fails(10.0), 290)

    def test_exact_limit_without_noise(self):
        self.assertTrue(t.rss_verdict([31 + 5.5 * c for c in range(8)], BOUND)[0])
        self.assertFalse(t.rss_verdict([31 + 5.0 * c for c in range(8)], BOUND)[0])

    def test_old_check_missed_what_this_catches(self):
        floors = [31 + 5.5 * c for c in range(8)]
        self.assertLess(floors[-1] - floors[-2], BOUND)
        self.assertTrue(t.rss_verdict(floors, BOUND)[0])

    def test_message_carries_series_and_slope(self):
        failed, msg = t.rss_verdict([31 + 8 * c for c in range(8)], BOUND)
        self.assertTrue(failed)
        self.assertIn("31.0, 39.0", msg)
        self.assertIn("+8.00 MB a cycle", msg)


class Handles(unittest.TestCase):
    def test_flat_passes_and_transient_does_not_count(self):
        self.assertFalse(t.handles_verdict("fds", [120, 118, 118, 119, 118, 118, 118, 118], 2)[0])
        self.assertFalse(t.handles_verdict("fds", [120, 118, 125, 118, 118, 122, 118, 118], 2)[0])

    def test_four_fds_a_cycle_fail(self):
        failed, msg = t.handles_verdict("fds", [100 + 4 * c for c in range(8)], 2)
        self.assertTrue(failed)
        self.assertIn("fds per cycle: 100, 104", msg)

    def test_a_thread_a_cycle_fails(self):
        self.assertTrue(t.handles_verdict("threads", [40 + c for c in range(8)], 2)[0])

    def test_too_few_cycles_skipped(self):
        self.assertFalse(t.handles_verdict("fds", [1, 2, 3], 2)[0])


if __name__ == "__main__":
    unittest.main()

import random
import unittest

import stress_trend as t

BOUND = 40
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


# Floors per cycle of 14 clean runs on hosted runners (8 cycles each, the driver's own log). They
# range 31 to 101 MB with no trend; readings inside a cycle agree, so the floor is the level.
RECORDED_FLOORS = [
    [49.5, 59.3, 55.3, 59.1, 34.7, 49.6, 52.3, 43.3],
    [101.6, 75.5, 84.7, 49.9, 67.6, 47.0, 56.7, 56.4],
    [66.1, 94.3, 48.6, 66.5, 63.1, 46.3, 52.2, 65.9],
    [50.3, 54.2, 54.6, 57.0, 46.3, 63.5, 43.4, 56.6],
    [47.7, 59.9, 31.9, 46.2, 44.4, 45.6, 61.8, 43.3],
    [53.7, 45.6, 36.6, 47.4, 55.4, 57.1, 62.1, 77.8],  # growth +33.7: the run the old bound of 32 failed
    [62.7, 47.3, 43.0, 52.7, 47.4, 55.5, 65.8, 43.0],
    [55.7, 62.3, 39.1, 61.5, 67.4, 54.8, 63.8, 81.4],
    [50.9, 37.4, 58.2, 55.2, 73.5, 32.0, 56.1, 36.7],
    [38.8, 38.6, 44.2, 64.7, 34.5, 64.3, 40.5, 60.0],
    [46.9, 53.3, 31.7, 45.2, 53.7, 64.6, 48.9, 42.9],
    [68.8, 36.9, 49.7, 65.1, 75.8, 37.1, 60.8, 33.9],
    [37.7, 68.0, 50.5, 34.9, 38.3, 51.9, 60.3, 31.5],
    [50.9, 63.8, 62.3, 38.0, 40.7, 64.8, 76.0, 70.3],
]


def settled(cycles, leak, rng):
    """Floors of a daemon idling at 31 MB plus a leak per cycle plus 0..50 MB of level that does
    not trend (sd 14 MB, as in the recorded floors)."""
    return [31.0 + leak * c + rng.uniform(0, 50) for c in range(cycles)]


class Settle(unittest.TestCase):
    def run_settle(self, values):
        it, waited = iter(values), []
        out = t.settle(lambda: next(it), waited.append, 5)
        return out, waited

    def test_flat_stops_after_three_quiet_readings(self):
        out, waited = self.run_settle([40, 40, 40, 40, 40])
        self.assertEqual(out, [40, 40, 40, 40])
        self.assertEqual(waited, [5, 5, 5])

    def test_a_late_drop_is_waited_for(self):
        # The recorded shape: identical readings, then the allocator returns pages.
        out, _ = self.run_settle([70.6, 70.6, 70.6, 47.0, 47.0, 47.0, 47.0])
        self.assertEqual(t.floor(out), 47.0)

    def test_stops_after_the_most(self):
        out, _ = self.run_settle([100 - 5 * i for i in range(12)])
        self.assertEqual(len(out), 8)

    def test_missing_reading_stops(self):
        self.assertEqual(self.run_settle([40, None, 30])[0], [40, None])


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

    def test_recorded_floors_pass(self):
        for series in RECORDED_FLOORS:
            failed, msg = t.rss_verdict(series, BOUND)
            self.assertFalse(failed, msg)

    def test_recorded_swings_over_eight_cycles_pass(self):
        # The same readings as the 8 cycles of CI, in both orders.
        for series in RECORDED:
            if len(series) < 4:
                continue
            for s in (series + series[::-1], series[::-1] + series):
                failed, msg = t.rss_verdict(s, BOUND)
                self.assertFalse(failed, f"{s}: {msg}")


class Leaks(unittest.TestCase):
    def fails(self, leak, seeds=2000):
        return sum(t.rss_verdict(settled(8, leak, random.Random(s)), BOUND)[0] for s in range(seeds))

    def test_no_leak_rarely_fails(self):
        self.assertLess(self.fails(0.0), 2000 * 0.015)

    def test_detection_through_the_recorded_noise(self):
        # 8 cycles, 6 intervals judged: the bound is 6.7 MB a cycle without noise. Through the
        # noise of the recorded floors 10 MB a cycle fails about 9 runs in 10, 12 MB 98 %, 16 MB always.
        self.assertGreater(self.fails(10.0), 2000 * 0.85)
        self.assertGreater(self.fails(12.0), 2000 * 0.95)
        self.assertEqual(self.fails(16.0), 2000)

    def test_exact_limit_without_noise(self):
        self.assertTrue(t.rss_verdict([31 + 7 * c for c in range(8)], BOUND)[0])
        self.assertFalse(t.rss_verdict([31 + 6.5 * c for c in range(8)], BOUND)[0])

    def test_old_check_missed_what_this_catches(self):
        # The old pair of readings needed 32 MB in two cycles, 16 MB a cycle.
        floors = [31 + 7 * c for c in range(8)]
        self.assertLess(floors[-1] - floors[-2], 32)
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

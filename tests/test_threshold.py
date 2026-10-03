# tests/test_threshold.py
import unittest
from datetime import datetime, timedelta

from core.rule_engine.threshold import ThresholdTracker

T0 = datetime(2026, 10, 3, 12, 0, 0)


def tracker(minutes=5, count=5):
    return ThresholdTracker(timedelta(minutes=minutes), count)


class TestWindowBoundaries(unittest.TestCase):
    def test_four_in_five_minutes_do_not_alert(self):
        t = tracker()
        for i in range(4):
            self.assertIsNone(t.add("k", T0 + timedelta(seconds=i), i))

    def test_the_fifth_alerts_and_returns_the_whole_window(self):
        t = tracker()
        fired = None
        for i in range(5):
            fired = t.add("k", T0 + timedelta(seconds=i), i)
        self.assertEqual((0, 1, 2, 3, 4), fired)

    def test_the_fifth_just_outside_the_window_does_not_alert(self):
        t = tracker()
        for i in range(4):
            t.add("k", T0 + timedelta(seconds=i), i)
        self.assertIsNone(t.add("k", T0 + timedelta(minutes=5, seconds=1), 4))

    def test_the_window_is_inclusive_at_exactly_the_timeframe(self):
        # 5 events spanning exactly 5m is "within five minutes".
        t = tracker()
        fired = None
        for i, delta in enumerate([0, 60, 120, 180, 300]):
            fired = t.add("k", T0 + timedelta(seconds=delta), i)
        self.assertIsNotNone(fired)

    def test_eviction_keeps_the_newer_events(self):
        t = tracker()
        t.add("k", T0, "old")
        for i in range(4):
            t.add("k", T0 + timedelta(minutes=6, seconds=i), i)
        self.assertEqual(4, t.pending("k"))
        fired = t.add("k", T0 + timedelta(minutes=6, seconds=5), "last")
        self.assertEqual((0, 1, 2, 3, "last"), fired)


class TestRearm(unittest.TestCase):
    def test_firing_clears_the_window(self):
        t = tracker()
        for i in range(5):
            t.add("k", T0 + timedelta(seconds=i), i)
        self.assertEqual(0, t.pending("k"))

    def test_the_sixth_event_does_not_alert_again(self):
        t = tracker()
        for i in range(5):
            t.add("k", T0 + timedelta(seconds=i), i)
        self.assertIsNone(t.add("k", T0 + timedelta(seconds=5), 5))

    def test_a_second_full_burst_alerts_again(self):
        t = tracker()
        for i in range(5):
            t.add("k", T0 + timedelta(seconds=i), i)
        fired = None
        for i in range(5, 10):
            fired = t.add("k", T0 + timedelta(seconds=i), i)
        self.assertEqual((5, 6, 7, 8, 9), fired)


class TestKeyIsolation(unittest.TestCase):
    def test_two_keys_count_separately(self):
        t = tracker()
        for i in range(4):
            t.add("a", T0 + timedelta(seconds=i), i)
            t.add("b", T0 + timedelta(seconds=i), i)
        self.assertEqual(
            (0, 1, 2, 3, "a4"), t.add("a", T0 + timedelta(seconds=4), "a4")
        )
        # 'a' just fired on its 5th; 'b' is still at 4.
        self.assertEqual(0, t.pending("a"))
        self.assertEqual(4, t.pending("b"))

    def test_a_tuple_key_works(self):
        t = tracker(count=2)
        self.assertIsNone(t.add(("1.2.3.4", "alice"), T0, 1))
        self.assertIsNotNone(t.add(("1.2.3.4", "alice"), T0, 2))
        self.assertIsNone(t.add(("1.2.3.4", "bob"), T0, 3))


class TestOutOfOrder(unittest.TestCase):
    def test_an_out_of_order_event_does_not_evict_the_window(self):
        # Batch detection feeds timestamp order, but a channel read can
        # interleave sources. An older event must not reset the clock.
        t = tracker()
        for i in range(4):
            t.add("k", T0 + timedelta(seconds=i), i)
        t.add("k", T0 - timedelta(minutes=10), "stale")
        self.assertGreaterEqual(t.pending("k"), 4)

    def test_a_stale_event_is_dropped_and_never_completes_a_burst(self):
        # Four events inside five minutes plus one ten minutes EARLIER is not
        # five-in-five-minutes. The clock is the newest timestamp seen (T0+3s),
        # so the stale event is already outside the window the moment it lands.
        t = tracker()
        for i in range(4):
            t.add("k", T0 + timedelta(seconds=i), i)
        self.assertIsNone(t.add("k", T0 - timedelta(minutes=10), "stale"))
        self.assertEqual(4, t.pending("k"))
        # A genuine fifth event fires, and the stale payload is not in it.
        fired = t.add("k", T0 + timedelta(seconds=4), 4)
        self.assertEqual((0, 1, 2, 3, 4), fired)

    def test_a_late_event_inside_the_window_counts_and_sorts_by_timestamp(self):
        # Timestamps 0,1,2,4 arrive, then 3. All five are within the timeframe,
        # so the late one counts, and the payloads come back in time order.
        t = tracker()
        for i in (0, 1, 2, 4):
            self.assertIsNone(t.add("k", T0 + timedelta(seconds=i), i))
        self.assertEqual(
            (0, 1, 2, 3, 4), t.add("k", T0 + timedelta(seconds=3), 3)
        )


class TestTies(unittest.TestCase):
    # Same-second bursts are routine (a run of 4625s), and the fired payload
    # order becomes the alert evidence order, so equal timestamps keep arrival
    # order.
    def test_events_sharing_a_timestamp_come_back_in_arrival_order(self):
        t = tracker()
        fired = None
        for p in "abcde":
            fired = t.add("k", T0, p)
        self.assertEqual(("a", "b", "c", "d", "e"), fired)

    def test_a_late_tie_lands_after_its_equals_not_before(self):
        # Arrival 0@0s, 1@1s, 2@3s, then x@2s and y@2s: x and y tie, and sit
        # between 1 and 2 in arrival order.
        t = tracker()
        for p, sec in ((0, 0), (1, 1), (2, 3), ("x", 2)):
            self.assertIsNone(t.add("k", T0 + timedelta(seconds=sec), p))
        self.assertEqual(
            (0, 1, "x", "y", 2), t.add("k", T0 + timedelta(seconds=2), "y")
        )


class TestDegenerateConfig(unittest.TestCase):
    def test_count_of_one_fires_on_the_first_event(self):
        t = tracker(count=1)
        self.assertEqual((1,), t.add("k", T0, 1))

    def test_a_zero_timeframe_is_rejected_at_construction(self):
        with self.assertRaises(ValueError):
            ThresholdTracker(timedelta(0), 5)

    def test_a_count_below_one_is_rejected_at_construction(self):
        with self.assertRaises(ValueError):
            ThresholdTracker(timedelta(minutes=5), 0)

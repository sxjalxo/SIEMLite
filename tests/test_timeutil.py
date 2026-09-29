import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from core.timeutil import parse_since, to_local_naive


class TestParseSince(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 9, 29, 12, 0, 0)

    def test_minutes(self):
        self.assertEqual(
            parse_since("30m", now=self.now), self.now - timedelta(minutes=30)
        )

    def test_hours(self):
        self.assertEqual(
            parse_since("24h", now=self.now), self.now - timedelta(hours=24)
        )

    def test_days(self):
        self.assertEqual(
            parse_since("7d", now=self.now), self.now - timedelta(days=7)
        )

    def test_seconds(self):
        self.assertEqual(
            parse_since("90s", now=self.now), self.now - timedelta(seconds=90)
        )

    def test_iso_timestamp(self):
        self.assertEqual(
            parse_since("2026-09-01T08:30:00", now=self.now),
            datetime(2026, 9, 1, 8, 30, 0),
        )

    def test_bare_date(self):
        self.assertEqual(
            parse_since("2026-09-01", now=self.now), datetime(2026, 9, 1, 0, 0, 0)
        )

    def test_rejects_garbage(self):
        with self.assertRaises(ValueError):
            parse_since("yesterday", now=self.now)

    def test_rejects_negative(self):
        with self.assertRaises(ValueError):
            parse_since("-5h", now=self.now)

    def test_rejects_empty(self):
        with self.assertRaises(ValueError):
            parse_since("", now=self.now)

    def test_rejects_overflow_out_of_date_range(self):
        with self.assertRaises(ValueError) as ctx:
            parse_since("999999999d", now=self.now)
        self.assertIn("999999999d", str(ctx.exception))

    def test_rejects_overflow_too_large_for_c_int(self):
        with self.assertRaises(ValueError) as ctx:
            parse_since("99999999999999999d", now=self.now)
        self.assertIn("99999999999999999d", str(ctx.exception))

    def test_never_leaks_non_valueerror(self):
        hostile = [
            "1960-01-01T00:00:00+00:00",
            "0001-01-01T00:00:00+00:00",
            "0001-01-01T00:00:00+23:59",
            "9999-12-31T23:59:59-23:59",
            "999999999d",
            "99999999999999999d",
            "\u0663h",
            "yesterday",
            "",
        ]
        for value in hostile:
            with self.subTest(value=value):
                try:
                    result = parse_since(value)
                except ValueError:
                    continue
                self.assertIsInstance(result, datetime)

    def test_oserror_from_conversion_becomes_valueerror(self):
        value = "1960-01-01T00:00:00+00:00"
        with mock.patch(
            "core.timeutil.to_local_naive",
            side_effect=OSError("[Errno 22] Invalid argument"),
        ):
            with self.assertRaises(ValueError) as ctx:
                parse_since(value)
        self.assertIn(value, str(ctx.exception))

    def test_rejects_iso_overflow_after_shift(self):
        value = "0001-01-01T00:00:00+23:59"
        with self.assertRaises(ValueError) as ctx:
            parse_since(value, now=self.now)
        self.assertIn(value, str(ctx.exception))

    def test_rejects_unicode_digits(self):
        for value in ("\u0663h", "\uff10\uff15h"):
            with self.assertRaises(ValueError):
                parse_since(value, now=self.now)


class TestToLocalNaive(unittest.TestCase):
    def test_strips_tzinfo_from_utc(self):
        aware = datetime(2026, 9, 29, 17, 43, 30, tzinfo=timezone.utc)
        result = to_local_naive(aware)
        self.assertIsNone(result.tzinfo)

    def test_converts_utc_to_local_wall_clock(self):
        aware = datetime(2026, 9, 29, 17, 43, 30, tzinfo=timezone.utc)
        self.assertEqual(
            datetime.fromtimestamp(aware.timestamp()), to_local_naive(aware)
        )

    def test_same_instant_different_offsets_converge(self):
        a = datetime(2026, 9, 29, 12, 0, tzinfo=timezone(timedelta(hours=5)))
        b = datetime(2026, 9, 29, 7, 0, tzinfo=timezone.utc)
        self.assertEqual(to_local_naive(a), to_local_naive(b))

    def test_naive_passes_through(self):
        naive = datetime(2026, 9, 29, 12, 0, 0)
        self.assertEqual(to_local_naive(naive), naive)


if __name__ == "__main__":
    unittest.main()

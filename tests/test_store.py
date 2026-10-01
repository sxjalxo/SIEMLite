import os
import sqlite3
import tempfile
import unittest
from datetime import datetime

from core import store
from ingestion.normalizer import NormalizedEvent


def make_event(record_id=1, **kwargs):
    base = dict(
        timestamp=datetime(2026, 9, 29, 10, 0, 0),
        source_type="windows",
        host="WORKSTATION1",
        channel="Security",
        event_id=4625,
        record_id=record_id,
    )
    base.update(kwargs)
    return NormalizedEvent(**base)


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.conn = store.connect(self.db_path)
        store.init_schema(self.conn)

    def tearDown(self):
        self.conn.close()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(self.db_path + suffix)
            except OSError:
                pass


class TestSchema(StoreTestCase):
    def test_init_schema_is_idempotent(self):
        store.init_schema(self.conn)
        store.init_schema(self.conn)
        self.assertEqual(0, store.count_events(self.conn))

    def test_creates_expected_tables(self):
        names = {
            r["name"]
            for r in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        for expected in ("events", "incidents", "bookmarks", "response_actions"):
            self.assertIn(expected, names)

    def test_wal_enabled(self):
        mode = self.conn.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual("wal", mode.lower())


class TestAlertsMigration(unittest.TestCase):
    """The ALTER TABLE branch only runs against a pre-existing alerts table."""

    LEGACY_COLUMNS = (
        "id", "timestamp", "category", "severity", "detail", "evidence",
        "source", "related_ip", "related_url", "resolved",
        "mitre_technique_id", "mitre_technique_name", "mitre_tactic",
        "mitre_tactic_id", "mitre_url",
    )
    NEW_COLUMNS = (
        "rule_id", "rule_title", "entity_type", "entity_value", "event_ids",
        "incident_id", "status",
    )

    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.conn = store.connect(self.db_path)
        self.conn.execute(
            "CREATE TABLE alerts ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME, "
            "category TEXT, severity TEXT, detail TEXT, evidence TEXT, "
            "source TEXT, related_ip TEXT, related_url TEXT, "
            "resolved INTEGER DEFAULT 0, mitre_technique_id TEXT, "
            "mitre_technique_name TEXT, mitre_tactic TEXT, "
            "mitre_tactic_id TEXT, mitre_url TEXT)"
        )
        self.conn.execute(
            "INSERT INTO alerts (timestamp, category, severity, detail, "
            "evidence, source, related_ip, resolved, mitre_technique_id) "
            "VALUES ('2026-09-29 10:00:00', 'brute_force', 'HIGH', 'legacy row', "
            "'ev', 'auth.log', '10.0.0.5', 0, 'T1110')"
        )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(self.db_path + suffix)
            except OSError:
                pass

    def columns(self):
        return [r["name"] for r in self.conn.execute("PRAGMA table_info(alerts)")]

    def test_legacy_fixture_has_no_new_columns(self):
        self.assertEqual(list(self.LEGACY_COLUMNS), self.columns())

    def test_adds_new_columns_and_keeps_existing_row(self):
        store.init_schema(self.conn)
        cols = self.columns()
        for name in self.NEW_COLUMNS:
            self.assertIn(name, cols)
        row = self.conn.execute("SELECT * FROM alerts").fetchone()
        self.assertEqual("brute_force", row["category"])
        self.assertEqual("HIGH", row["severity"])
        self.assertEqual("legacy row", row["detail"])
        self.assertEqual("10.0.0.5", row["related_ip"])
        self.assertEqual("T1110", row["mitre_technique_id"])
        self.assertEqual(1, self.conn.execute(
            "SELECT COUNT(*) FROM alerts").fetchone()[0])

    def test_second_init_schema_does_not_error(self):
        store.init_schema(self.conn)
        store.init_schema(self.conn)
        self.assertEqual(
            len(self.LEGACY_COLUMNS) + len(self.NEW_COLUMNS), len(self.columns())
        )

    def test_creates_alerts_incident_index(self):
        store.init_schema(self.conn)
        names = {
            r["name"]
            for r in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            )
        }
        self.assertIn("idx_alerts_incident", names)


class TestInsert(StoreTestCase):
    def test_insert_returns_count(self):
        inserted = store.insert_events(self.conn, [make_event(1), make_event(2)])
        self.assertEqual(2, inserted)
        self.assertEqual(2, store.count_events(self.conn))

    def test_reingest_is_idempotent(self):
        events = [make_event(1), make_event(2)]
        store.insert_events(self.conn, events)
        second = store.insert_events(self.conn, events)
        self.assertEqual(0, second)
        self.assertEqual(2, store.count_events(self.conn))

    def test_partial_overlap_inserts_only_new(self):
        store.insert_events(self.conn, [make_event(1), make_event(2)])
        inserted = store.insert_events(
            self.conn, [make_event(2), make_event(3), make_event(4)]
        )
        self.assertEqual(2, inserted)
        self.assertEqual(4, store.count_events(self.conn))

    def test_empty_insert_is_noop(self):
        self.assertEqual(0, store.insert_events(self.conn, []))

    def test_batching_across_batch_size(self):
        # Each batch is one transaction = one implicit BEGIN. 11 events at
        # batch_size=3 -> batches of 3,3,3,2 -> exactly 4 transactions.
        begins = []
        self.conn.set_trace_callback(
            lambda sql: begins.append(sql) if sql.startswith("BEGIN") else None
        )
        events = [make_event(i) for i in range(1, 12)]
        inserted = store.insert_events(self.conn, events, batch_size=3)
        self.conn.set_trace_callback(None)
        self.assertEqual(11, inserted)
        self.assertEqual(11, store.count_events(self.conn))
        self.assertEqual(4, len(begins))

    def test_insert_is_committed_and_visible_to_other_connection(self):
        store.insert_events(self.conn, [make_event(1)])
        other = sqlite3.connect(self.db_path)
        try:
            n = other.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        finally:
            other.close()
        self.assertEqual(1, n)

    def test_constraint_violation_raises_not_silently_dropped(self):
        events = [make_event(1), make_event(2, event_id=None), make_event(3)]
        with self.assertRaises(sqlite3.IntegrityError):
            store.insert_events(self.conn, events)

    def open_caller_transaction(self):
        self.conn.execute("INSERT INTO bookmarks (channel, last_record_id) "
                          "VALUES ('Security', 99)")

    def bookmark_count(self, conn):
        return conn.execute("SELECT COUNT(*) FROM bookmarks").fetchone()[0]

    def test_success_commits_callers_pending_work(self):
        self.open_caller_transaction()
        store.insert_events(self.conn, [make_event(1)])
        other = sqlite3.connect(self.db_path)
        try:
            self.assertEqual(1, self.bookmark_count(other))
        finally:
            other.close()

    def test_integrity_error_rolls_back_callers_pending_work(self):
        self.open_caller_transaction()
        with self.assertRaises(sqlite3.IntegrityError):
            store.insert_events(self.conn, [make_event(1, event_id=None)])
        # Gone from the caller's own view, not merely hidden from others.
        self.assertEqual(0, self.bookmark_count(self.conn))
        other = sqlite3.connect(self.db_path)
        try:
            self.assertEqual(0, self.bookmark_count(other))
        finally:
            other.close()

    def test_true_duplicate_is_still_ignored_silently(self):
        store.insert_events(self.conn, [make_event(1)])
        # Does not raise; reports 0 written; row count unchanged.
        self.assertEqual(0, store.insert_events(self.conn, [make_event(1)]))
        self.assertEqual(1, store.count_events(self.conn))

    def test_metadata_survives_storage(self):
        store.insert_events(
            self.conn, [make_event(1, metadata={"privileges": ["SeDebugPrivilege"]})]
        )
        row = self.conn.execute("SELECT * FROM events").fetchone()
        restored = NormalizedEvent.from_row(row)
        self.assertEqual(["SeDebugPrivilege"], restored.metadata["privileges"])


class TestDedup(StoreTestCase):
    """Regression guard: same host/channel/record_id but different raw must
    not be silently dropped (no stable_record_id opt-out)."""

    def rows(self):
        return self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def test_same_key_different_raw_stored_twice(self):
        a = make_event(7, raw="<Event>first</Event>")
        b = make_event(7, raw="<Event>second</Event>")
        store.insert_events(self.conn, [a, b])
        self.assertEqual(2, self.rows())

    def test_identical_events_stored_once(self):
        a = make_event(7, raw="<Event>same</Event>")
        b = make_event(7, raw="<Event>same</Event>")
        store.insert_events(self.conn, [a, b])
        self.assertEqual(1, self.rows())


class TestStats(StoreTestCase):
    def test_stats_on_empty_store(self):
        result = store.stats(self.conn)
        self.assertEqual(0, result["total"])
        self.assertIsNone(result["earliest"])

    def test_stats_groups_by_channel_and_event_id(self):
        store.insert_events(
            self.conn,
            [
                make_event(1, channel="Security", event_id=4625),
                make_event(2, channel="Security", event_id=4625),
                make_event(3, channel="System", event_id=7045),
            ],
        )
        result = store.stats(self.conn)
        self.assertEqual(3, result["total"])
        self.assertEqual(2, result["by_channel"]["Security"])
        self.assertEqual(1, result["by_channel"]["System"])
        self.assertEqual(2, result["by_event_id"][4625])

    def test_stats_earliest_and_latest(self):
        store.insert_events(
            self.conn,
            [
                make_event(1, timestamp=datetime(2026, 9, 29, 12, 0, 0)),
                make_event(2, timestamp=datetime(2026, 9, 29, 9, 0, 0)),
                make_event(3, timestamp=datetime(2026, 9, 29, 15, 30, 0)),
            ],
        )
        result = store.stats(self.conn)
        self.assertEqual("2026-09-29 09:00:00", result["earliest"])
        self.assertEqual("2026-09-29 15:30:00", result["latest"])

    def test_by_event_id_is_top_25_by_count(self):
        # event_id i appears i times (i = 1..30): top 25 are ids 6..30.
        events = []
        for i in range(1, 31):
            for _ in range(i):
                events.append(make_event(len(events) + 1, event_id=i))
        store.insert_events(self.conn, events)
        result = store.stats(self.conn)
        self.assertEqual(465, result["total"])
        self.assertEqual(set(range(6, 31)), set(result["by_event_id"]))
        self.assertEqual(30, result["by_event_id"][30])


class TestQuery(StoreTestCase):
    def setUp(self):
        super().setUp()
        store.insert_events(
            self.conn,
            [
                make_event(1, timestamp=datetime(2026, 9, 29, 10, 0, 0),
                           source_ip="203.0.113.50", target_user="administrator"),
                make_event(2, timestamp=datetime(2026, 9, 29, 11, 0, 0),
                           source_ip="203.0.113.50", target_user="admin"),
                make_event(3, timestamp=datetime(2026, 9, 29, 12, 0, 0),
                           source_ip="10.0.0.15", user="jsmith",
                           event_id=4624, action="LOGIN_OK"),
                make_event(4, timestamp=datetime(2026, 9, 29, 13, 0, 0),
                           host="SERVER1", channel="System", event_id=7045),
            ],
        )

    def test_query_all(self):
        self.assertEqual(4, len(store.query_events(self.conn)))

    def test_returns_normalized_events(self):
        events = store.query_events(self.conn, limit=1)
        self.assertEqual("windows", events[0].source_type)

    def test_filter_by_source_ip(self):
        events = store.query_events(self.conn, source_ip="203.0.113.50")
        self.assertEqual(2, len(events))

    def test_filter_by_user_matches_target_user_too(self):
        events = store.query_events(self.conn, user="administrator")
        self.assertEqual(1, len(events))
        self.assertEqual("administrator", events[0].target_user)

    def test_filter_by_user_matches_acting_user(self):
        events = store.query_events(self.conn, user="jsmith")
        self.assertEqual(1, len(events))

    def test_filter_by_host(self):
        self.assertEqual(1, len(store.query_events(self.conn, host="SERVER1")))

    def test_filter_by_event_id(self):
        self.assertEqual(1, len(store.query_events(self.conn, event_id=7045)))

    def test_filter_by_channel(self):
        self.assertEqual(3, len(store.query_events(self.conn, channel="Security")))

    def test_filter_by_action(self):
        self.assertEqual(1, len(store.query_events(self.conn, action="LOGIN_OK")))

    def test_since_is_inclusive_lower_bound(self):
        events = store.query_events(self.conn, since=datetime(2026, 9, 29, 12, 0, 0))
        self.assertEqual(2, len(events))

    def test_until_is_inclusive_upper_bound(self):
        events = store.query_events(self.conn, until=datetime(2026, 9, 29, 11, 0, 0))
        self.assertEqual(2, len(events))

    def test_limit_applies(self):
        self.assertEqual(2, len(store.query_events(self.conn, limit=2)))

    def test_default_order_is_ascending(self):
        events = store.query_events(self.conn)
        self.assertEqual(datetime(2026, 9, 29, 10, 0, 0), events[0].timestamp)

    def test_descending_order(self):
        events = store.query_events(self.conn, order="desc")
        self.assertEqual(datetime(2026, 9, 29, 13, 0, 0), events[0].timestamp)

    def test_combined_filters(self):
        events = store.query_events(
            self.conn, source_ip="203.0.113.50",
            since=datetime(2026, 9, 29, 10, 30, 0),
        )
        self.assertEqual(1, len(events))

    def test_descending_ties_come_back_in_reverse_insertion_order(self):
        # Needs DESC plus a non-timestamp filter: ASC (or a since/until scan)
        # returns rowid order even without the id tiebreak.
        same = datetime(2026, 9, 29, 14, 0, 0)
        store.insert_events(
            self.conn,
            [make_event(r, timestamp=same, source_ip="198.51.100.7")
             for r in (30, 10, 20)],
        )
        events = store.query_events(
            self.conn, source_ip="198.51.100.7", order="desc"
        )
        self.assertEqual([20, 10, 30], [e.record_id for e in events])

    def test_hostile_order_raises_and_leaves_table_intact(self):
        with self.assertRaises(ValueError):
            store.query_events(self.conn, order="asc; DROP TABLE events")
        self.assertEqual(4, store.count_events(self.conn))

    def test_unrecognised_order_raises(self):
        for bad in ("descending", "dsc", None):
            with self.assertRaises(ValueError):
                store.query_events(self.conn, order=bad)

    def test_event_id_zero_returns_only_malformed_row(self):
        store.insert_events(self.conn, [make_event(5, event_id=0)])
        events = store.query_events(self.conn, event_id=0)
        self.assertEqual([5], [e.record_id for e in events])

    def test_empty_user_matches_nothing(self):
        self.assertEqual([], store.query_events(self.conn, user=""))

    def test_placeholder_user_matches_literally(self):
        # "-" is the schema's "not present" value, but still a real stored value.
        store.insert_events(
            self.conn, [make_event(5, user="alice", target_user="bob")]
        )
        events = store.query_events(self.conn, user="-")
        self.assertEqual([1, 2, 3, 4], [e.record_id for e in events])

    def test_empty_string_filter_matches_nothing(self):
        self.assertEqual([], store.query_events(self.conn, channel=""))

    def test_hostile_filter_value_is_bound_not_interpolated(self):
        events = store.query_events(self.conn, host="x' OR '1'='1")
        self.assertEqual([], events)


class TestBookmarks(StoreTestCase):
    def test_missing_bookmark_is_zero(self):
        self.assertEqual(0, store.get_bookmark(self.conn, "Security"))

    def test_set_then_get(self):
        store.set_bookmark(self.conn, "Security", 143105)
        self.assertEqual(143105, store.get_bookmark(self.conn, "Security"))

    def test_set_bookmark_is_committed_and_visible_to_other_connection(self):
        store.set_bookmark(self.conn, "Security", 42)
        other = sqlite3.connect(self.db_path)
        try:
            row = other.execute(
                "SELECT last_record_id FROM bookmarks WHERE channel='Security'"
            ).fetchone()
        finally:
            other.close()
        self.assertEqual((42,), row)

    def test_update_overwrites(self):
        store.set_bookmark(self.conn, "Security", 100)
        store.set_bookmark(self.conn, "Security", 200)
        self.assertEqual(200, store.get_bookmark(self.conn, "Security"))

    def test_channels_are_independent(self):
        store.set_bookmark(self.conn, "Security", 100)
        store.set_bookmark(self.conn, "System", 900)
        self.assertEqual(100, store.get_bookmark(self.conn, "Security"))
        self.assertEqual(900, store.get_bookmark(self.conn, "System"))

    def test_last_run_is_recorded(self):
        store.set_bookmark(self.conn, "Security", 1)
        row = self.conn.execute(
            "SELECT last_run FROM bookmarks WHERE channel='Security'"
        ).fetchone()
        self.assertIsNotNone(row["last_run"])


if __name__ == "__main__":
    unittest.main()

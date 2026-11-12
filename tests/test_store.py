import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from core import store
from core.timeutil import to_local_naive
from ingestion.normalizer import NormalizedEvent, normalize_windows_xml
from tests import helpers_rules
from tests.fixtures import events_xml
from tests.helpers_rules import T0, sample_alert


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
        for expected in ("events", "incidents", "bookmarks", "response_actions",
                        "alerts"):
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
        "incident_id", "status", "alert_hash",
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


class TestPromotedColumns(StoreTestCase):
    PROMOTED = {"status", "dest_port", "workstation"}

    def columns(self):
        return {r["name"] for r in self.conn.execute("PRAGMA table_info(events)")}

    def test_events_table_has_the_promoted_columns(self):
        self.assertLessEqual(self.PROMOTED, self.columns())

    def test_event_columns_matches_the_table(self):
        self.assertEqual(self.columns() - {"id"}, set(store.EVENT_COLUMNS))

    def test_promoted_values_round_trip(self):
        for xml_text in (events_xml.FAILED_LOGON_4625, events_xml.SYSMON_NETWORK_3):
            event = normalize_windows_xml(xml_text)
            store.insert_events(self.conn, [event])
        back = {e.event_id: e for e in store.query_events(self.conn)}
        self.assertEqual("0xc000006d", back[4625].status)
        self.assertEqual("KALI", back[4625].workstation)
        self.assertEqual(4444, back[3].dest_port)


class TestEventsMigration(unittest.TestCase):
    """A store written before the promotion has `events` without the columns."""

    # The Plan 1 events table: every column except the three promoted ones.
    LEGACY_DDL = (
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "timestamp DATETIME NOT NULL, source_type TEXT NOT NULL, "
        "host TEXT NOT NULL, channel TEXT NOT NULL, "
        "event_id INTEGER NOT NULL, record_id INTEGER NOT NULL, "
        "action TEXT NOT NULL, severity_hint TEXT, user TEXT, "
        "target_user TEXT, source_ip TEXT, dest_ip TEXT, logon_type INTEGER, "
        "process TEXT, process_id INTEGER, parent_process TEXT, "
        "command_line TEXT, object_name TEXT, service_name TEXT, "
        "detail TEXT, raw TEXT, metadata TEXT, event_hash TEXT NOT NULL UNIQUE)"
    )

    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.conn = store.connect(self.db_path)
        self.conn.execute(self.LEGACY_DDL)
        self.conn.execute(
            "INSERT INTO events (timestamp, source_type, host, channel, "
            "event_id, record_id, action, event_hash) VALUES "
            "('2026-09-29 10:00:00', 'windows', 'H', 'Security', 4625, 1, "
            "'LOGIN_FAIL', 'legacy-hash')"
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
        return {r["name"] for r in self.conn.execute("PRAGMA table_info(events)")}

    def test_legacy_fixture_lacks_the_promoted_columns(self):
        self.assertFalse({"status", "dest_port", "workstation"} & self.columns())

    def test_migration_adds_the_columns_and_keeps_the_row(self):
        store.init_schema(self.conn)
        self.assertLessEqual({"status", "dest_port", "workstation"}, self.columns())
        self.assertEqual(1, store.count_events(self.conn))
        # The migrated store accepts new promoted values.
        store.insert_events(self.conn, [normalize_windows_xml(
            events_xml.FAILED_LOGON_4625)])
        self.assertEqual(2, store.count_events(self.conn))

    def test_pre_migration_rows_read_back_with_the_defaults_not_none(self):
        # Rules must never see None: a Plan 1 row reads "-" / "-" / 0.
        store.init_schema(self.conn)
        old = store.query_events(self.conn, event_id=4625)[0]
        self.assertEqual("-", old.status)
        self.assertEqual("-", old.workstation)
        self.assertEqual(0, old.dest_port)

    def test_fresh_and_migrated_events_tables_declare_the_same_columns(self):
        store.init_schema(self.conn)
        fresh = store.connect(self.db_path + ".fresh")
        try:
            store.init_schema(fresh)
            def decl(conn):
                return {r["name"]: (r["type"], r["dflt_value"])
                        for r in conn.execute("PRAGMA table_info(events)")}
            migrated = decl(self.conn)
            for name in ("status", "workstation", "dest_port"):
                self.assertEqual(decl(fresh)[name], migrated[name], name)
        finally:
            fresh.close()
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.unlink(self.db_path + ".fresh" + suffix)
                except OSError:
                    pass

    def test_second_init_schema_does_not_error(self):
        store.init_schema(self.conn)
        store.init_schema(self.conn)
        self.assertEqual(set(store.EVENT_COLUMNS) | {"id"}, self.columns())


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


class TestFreshStoreAlerts(StoreTestCase):
    """`alerts` must exist after init_schema alone. The legacy --scan path is
    not a prerequisite, and `--db demo.db` never reaches it."""

    def columns(self):
        return [r["name"] for r in self.conn.execute("PRAGMA table_info(alerts)")]

    def test_alerts_table_exists(self):
        self.assertEqual(
            0, self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        )

    def test_alerts_carries_both_the_legacy_and_the_pipeline_columns(self):
        cols = self.columns()
        for name in ("category", "severity", "detail", "source", "resolved",
                     "mitre_technique_id", "mitre_url"):
            self.assertIn(name, cols)
        for name, _decl in store.ALERT_COLUMNS:
            self.assertIn(name, cols)

    def test_status_defaults_to_new_on_a_fresh_store(self):
        self.conn.execute(
            "INSERT INTO alerts (category, severity, detail, source) "
            "VALUES ('brute_force', 'HIGH', 'd', 'test')"
        )
        self.assertEqual(
            "NEW",
            self.conn.execute("SELECT status FROM alerts").fetchone()["status"],
        )


class TestAwareTimeBounds(StoreTestCase):
    """Stored timestamps are local naive and SQLite compares them as text, so
    an aware bound must be converted, not stringified with its offset."""

    def setUp(self):
        super(TestAwareTimeBounds, self).setUp()
        self.local = datetime(2026, 1, 1, 12, 0, 0)
        store.insert_events(self.conn, [make_event(1, timestamp=self.local)])

    def rows(self, **kwargs):
        return [e.record_id for e in store.query_events(self.conn, **kwargs)]

    def test_aware_since_at_the_row_instant_still_matches(self):
        # Local offset attached, wall clock unchanged: the row is that instant.
        self.assertEqual([1], self.rows(since=self.local.astimezone()))

    def test_aware_bounds_select_what_their_naive_equivalent_selects(self):
        # -13/+13 cannot equal the local offset, so a text compare must differ.
        for hours in (-13, 0, 13):
            aware = self.local.astimezone(timezone(timedelta(hours=hours)))
            for bound in ("since", "until"):
                self.assertEqual(
                    self.rows(**{bound: to_local_naive(aware)}),
                    self.rows(**{bound: aware}),
                    "{}={}".format(bound, aware),
                )


class TestQueryLimit(StoreTestCase):
    TOTAL = 1200

    def setUp(self):
        super(TestQueryLimit, self).setUp()
        store.insert_events(self.conn, [
            make_event(i, timestamp=datetime(2026, 9, 29, 10, 0, 0))
            for i in range(1, self.TOTAL + 1)
        ])

    def test_default_limit_caps_interactive_output(self):
        self.assertEqual(1000, len(store.query_events(self.conn)))

    def test_limit_none_reads_the_whole_window(self):
        self.assertEqual(self.TOTAL, len(store.query_events(self.conn, limit=None)))


class TestAlertPersistence(StoreTestCase):
    def test_an_alert_round_trips(self):
        alert = sample_alert()
        self.assertEqual(1, store.insert_alerts(self.conn, [alert]))
        row = store.query_alerts(self.conn)[0]
        self.assertEqual(alert.rule_id, row["rule_id"])
        self.assertEqual(alert.severity, row["severity"])
        self.assertEqual(alert.entity_value, row["entity_value"])
        self.assertEqual("NEW", row["status"])
        self.assertEqual(alert.alert_hash, row["alert_hash"])

    def test_the_mitre_columns_are_persisted(self):
        # Ruling R53. Task 12 recomputes an incident's tactic union from the
        # member alert rows, so the tactic must survive the table.
        store.insert_alerts(self.conn, [sample_alert(technique="T1110",
                                                     tactic="TA0006")])
        row = store.query_alerts(self.conn)[0]
        self.assertEqual("T1110", row["mitre_technique_id"])
        self.assertEqual("TA0006", row["mitre_tactic_id"])

    def test_event_hashes_persist_as_json(self):
        alert = sample_alert(event_hashes=("aa", "bb"))
        store.insert_alerts(self.conn, [alert])
        row = store.query_alerts(self.conn)[0]
        self.assertEqual(["aa", "bb"], json.loads(row["event_ids"]))

    def test_the_four_not_null_columns_are_satisfied(self):
        # Decision D4. A NOT NULL violation here would be an IntegrityError.
        store.insert_alerts(self.conn, [sample_alert()])
        row = store.query_alerts(self.conn)[0]
        for name in ("category", "severity", "detail", "source"):
            self.assertIsNotNone(row[name])

    def test_reinserting_the_same_alert_inserts_nothing(self):
        alert = sample_alert()
        self.assertEqual(1, store.insert_alerts(self.conn, [alert]))
        self.assertEqual(0, store.insert_alerts(self.conn, [alert]))
        self.assertEqual(1, len(store.query_alerts(self.conn)))

    def test_two_different_alerts_both_land(self):
        a = sample_alert(entity_value="1.2.3.4")
        b = sample_alert(entity_value="5.6.7.8")
        self.assertEqual(2, store.insert_alerts(self.conn, [a, b]))

    def test_the_hash_index_is_unique(self):
        # Pinned on the schema, not only through insert_alerts: the unique
        # index is what makes `detect` re-runnable for any writer.
        index = [r for r in self.conn.execute("PRAGMA index_list(alerts)")
                 if r["name"] == "idx_alerts_hash"]
        self.assertEqual(1, len(index))
        self.assertEqual(1, index[0]["unique"])

    def test_a_legacy_alert_with_a_null_hash_does_not_block_another(self):
        # The user's real database holds 149 pre-existing alert rows with no
        # alert_hash. SQLite treats NULLs in a UNIQUE index as distinct, so
        # they must coexist. If this breaks, the legacy path stops working.
        for _ in range(2):
            self.conn.execute(
                "INSERT INTO alerts (category, severity, detail, source) "
                "VALUES ('legacy', 'LOW', 'd', 'scanner')")
        self.conn.commit()
        self.assertEqual(2, self.conn.execute(
            "SELECT COUNT(*) FROM alerts").fetchone()[0])

    def test_a_rule_alert_lands_beside_legacy_rows(self):
        self.conn.execute(
            "INSERT INTO alerts (category, severity, detail, source) "
            "VALUES ('legacy', 'LOW', 'd', 'scanner')")
        self.conn.commit()
        self.assertEqual(1, store.insert_alerts(self.conn, [sample_alert()]))

    def test_the_timestamp_is_stored_local_naive(self):
        aware = datetime(2026, 10, 3, 14, 0, 0, tzinfo=timezone.utc)
        store.insert_alerts(self.conn, [sample_alert(timestamp=aware)])
        stored = store.query_alerts(self.conn)[0]["timestamp"]
        self.assertEqual(to_local_naive(aware).isoformat(sep=" "), stored)

    def test_a_failing_alert_rolls_the_whole_call_back(self):
        # Same contract as insert_events: one transaction, all or nothing.
        good = sample_alert(entity_value="1.2.3.4")
        bad = sample_alert(entity_value="5.6.7.8", detail=None)
        with self.assertRaises(sqlite3.IntegrityError):
            store.insert_alerts(self.conn, [good, bad])
        self.assertEqual([], store.query_alerts(self.conn))


class TestAlertQueries(StoreTestCase):
    def setUp(self):
        super().setUp()
        store.insert_alerts(self.conn, [
            sample_alert(rule_id="r1", severity="HIGH", entity_value="1.2.3.4",
                         timestamp=T0),
            sample_alert(rule_id="r2", severity="LOW", entity_value="alice",
                         entity_type="user", timestamp=T0 - timedelta(days=2)),
        ])

    def ids(self, **kwargs):
        return [r["rule_id"] for r in store.query_alerts(self.conn, **kwargs)]

    def test_filter_by_severity(self):
        self.assertEqual(["r1"], self.ids(severity="HIGH"))

    def test_filter_by_rule_id(self):
        self.assertEqual(["r2"], self.ids(rule_id="r2"))

    def test_filter_by_entity_matches_the_value(self):
        self.assertEqual(["r1"], self.ids(entity="1.2.3.4"))

    def test_filter_by_status(self):
        self.conn.execute("UPDATE alerts SET status = 'CLOSED' WHERE rule_id = 'r2'")
        self.assertEqual(["r2"], self.ids(status="CLOSED"))
        self.assertEqual(["r1"], self.ids(status="NEW"))

    def test_filter_by_incident_id(self):
        self.conn.execute("UPDATE alerts SET incident_id = 7 WHERE rule_id = 'r2'")
        self.assertEqual(["r2"], self.ids(incident_id=7))

    def test_a_falsy_filter_filters_rather_than_matches_everything(self):
        # R21: `is not None`, not truthiness. incident_id=0 and "" match no row.
        self.assertEqual([], self.ids(incident_id=0))
        self.assertEqual([], self.ids(severity=""))

    def test_filter_by_since_excludes_older(self):
        self.assertEqual(["r1"], self.ids(since=T0 - timedelta(hours=1)))

    def test_filter_by_until_excludes_newer(self):
        self.assertEqual(["r2"], self.ids(until=T0 - timedelta(hours=1)))

    def test_aware_bounds_select_what_their_naive_equivalent_selects(self):
        # The mirror of ruling R46 on the alerts table. -13/+13 cannot equal
        # the local offset, so a text compare of the stringified bound differs.
        for hours in (-13, 0, 13):
            aware = T0.astimezone(timezone(timedelta(hours=hours)))
            for bound in ("since", "until"):
                self.assertEqual(
                    self.ids(**{bound: to_local_naive(aware)}),
                    self.ids(**{bound: aware}),
                    "{}={}".format(bound, aware))
        # The alert sits exactly at the bound, so both bounds include it.
        at = T0.astimezone(timezone(timedelta(hours=13)))
        self.assertEqual(["r1"], self.ids(since=at))
        self.assertIn("r1", self.ids(until=at))

    def test_newest_first_by_default(self):
        self.assertEqual(["r1", "r2"], self.ids())

    def test_asc_order_is_oldest_first(self):
        self.assertEqual(["r2", "r1"], self.ids(order="asc"))

    def test_a_limit_caps_the_rows(self):
        self.assertEqual(["r1"], self.ids(limit=1))

    def test_the_default_limit_caps_and_limit_none_reads_the_whole_window(self):
        store.insert_alerts(self.conn, [
            sample_alert(entity_value="e{}".format(i)) for i in range(1001)])
        self.assertEqual(1000, len(store.query_alerts(self.conn)))
        self.assertEqual(1003, len(store.query_alerts(self.conn, limit=None)))

    def test_an_unknown_order_raises(self):
        with self.assertRaises(ValueError):
            store.query_alerts(self.conn, order="sideways")


class TestEventsByHash(StoreTestCase):
    def test_hashes_resolve_back_to_events(self):
        # Decision D1: an alert references events by hash, so this is how a
        # timeline gets them back.
        events = [helpers_rules.event(record_id=i, event_id=1102)
                  for i in (1, 2, 3)]
        store.insert_events(self.conn, events)
        wanted = [events[0].event_hash, events[2].event_hash]
        back = store.events_by_hash(self.conn, wanted)
        self.assertEqual({events[0].record_id, events[2].record_id},
                         {e.record_id for _, e in back})
        self.assertEqual(sorted(wanted), sorted(h for h, _ in back))

    def test_the_hash_comes_back_as_stored_not_recomputed(self):
        # Ruling R105. An event edited after it was written no longer hashes to
        # the key it is stored under, and a caller that recomputed it would
        # silently unhook the event from the alerts citing it.
        event = helpers_rules.event(record_id=7, event_id=1102)
        store.insert_events(self.conn, [event])
        self.conn.execute("UPDATE events SET channel = 'Tampered'")
        self.conn.commit()
        [(stored, back)] = store.events_by_hash(self.conn, [event.event_hash])
        self.assertEqual(event.event_hash, stored)
        self.assertNotEqual(stored, back.event_hash, "the recompute must differ")

    def test_an_unknown_hash_is_skipped_not_an_error(self):
        self.assertEqual([], store.events_by_hash(self.conn, ["nope"]))

    def test_an_empty_list_does_not_query(self):
        statements = []
        self.conn.set_trace_callback(statements.append)
        self.assertEqual([], store.events_by_hash(self.conn, []))
        self.assertEqual([], statements)

    def test_results_come_back_in_timestamp_order(self):
        events = [helpers_rules.event(record_id=i, event_id=1102,
                                      timestamp=T0 + timedelta(seconds=-i))
                  for i in (1, 2, 3)]
        store.insert_events(self.conn, events)
        back = store.events_by_hash(self.conn, [e.event_hash for e in events])
        self.assertEqual(sorted(e.timestamp for e in events),
                         [e.timestamp for _, e in back])

    def _store_descending(self, n):
        # Row id rises while the timestamp falls, so id order is the reverse
        # of timestamp order and a chunk-local sort cannot be globally right.
        events = [helpers_rules.event(record_id=i, event_id=1102,
                                      timestamp=T0 - timedelta(seconds=i))
                  for i in range(n)]
        store.insert_events(self.conn, events)
        return events

    def test_a_large_hash_list_resolves_in_global_timestamp_order(self):
        events = self._store_descending(1200)
        back = store.events_by_hash(self.conn, [e.event_hash for e in events])
        self.assertEqual(1200, len(back))
        self.assertEqual(sorted(e.timestamp for e in events),
                         [e.timestamp for _, e in back])

    def test_a_hash_repeated_across_chunks_resolves_once(self):
        # Task 12 hands in the union of several alerts' hashes, which overlap.
        events = self._store_descending(1)
        h = events[0].event_hash
        self.assertEqual(1, len(store.events_by_hash(self.conn, [h] * 1200)))

    @unittest.skipUnless(hasattr(sqlite3.Connection, "setlimit"),
                         "needs Python 3.11+")
    def test_a_large_hash_list_fits_an_old_sqlites_variable_limit(self):
        # This host's SQLite allows 32766 variables, so 1200 would pass
        # unchunked. Lower the limit to the pre-3.32 default to emulate the
        # older bundled SQLite the project's floor allows.
        events = self._store_descending(1200)
        self.conn.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 999)
        back = store.events_by_hash(self.conn, [e.event_hash for e in events])
        self.assertEqual(1200, len(back))

    def test_a_large_hash_list_is_split_into_several_queries(self):
        # The same property without setlimit: count the SELECTs issued.
        events = self._store_descending(1200)
        statements = []
        self.conn.set_trace_callback(statements.append)
        store.events_by_hash(self.conn, [e.event_hash for e in events])
        selects = [s for s in statements if s.lstrip().startswith("SELECT")]
        self.assertEqual(3, len(selects))


def open_incident(conn, entity_value="1.2.3.4", entity_type="ip", **overrides):
    fields = dict(opened_at=T0, last_seen=T0, entity_type=entity_type,
                  entity_value=entity_value, severity="HIGH", score=8,
                  tactics=[], title="t")
    fields.update(overrides)
    return store.open_incident(conn, **fields)


class TestIncidentPersistence(StoreTestCase):
    def test_open_then_find(self):
        incident_id = open_incident(self.conn, tactics=["TA0006"],
                                    title="Failed Logon Burst on 1.2.3.4")
        found = store.find_open_incident(self.conn, "ip", "1.2.3.4",
                                         T0 - timedelta(minutes=30))
        self.assertEqual(incident_id, found["id"])

    def test_find_ignores_an_incident_outside_the_window(self):
        open_incident(self.conn)
        self.assertIsNone(store.find_open_incident(
            self.conn, "ip", "1.2.3.4", T0 + timedelta(minutes=1)))

    def test_find_includes_an_incident_exactly_at_the_window_start(self):
        incident_id = open_incident(self.conn)
        self.assertEqual(incident_id, store.find_open_incident(
            self.conn, "ip", "1.2.3.4", T0)["id"])

    def test_find_ignores_a_closed_incident(self):
        incident_id = open_incident(self.conn)
        store.close_incident(self.conn, incident_id)
        self.assertIsNone(store.find_open_incident(
            self.conn, "ip", "1.2.3.4", T0 - timedelta(minutes=30)))

    def test_find_distinguishes_entity_type(self):
        open_incident(self.conn, entity_type="user")
        self.assertIsNone(store.find_open_incident(
            self.conn, "ip", "1.2.3.4", T0 - timedelta(minutes=30)))

    def test_find_distinguishes_entity_value(self):
        open_incident(self.conn, entity_value="5.6.7.8")
        self.assertIsNone(store.find_open_incident(
            self.conn, "ip", "1.2.3.4", T0 - timedelta(minutes=30)))

    def test_find_returns_the_most_recently_seen(self):
        open_incident(self.conn, last_seen=T0 - timedelta(minutes=10))
        newer = open_incident(self.conn, last_seen=T0)
        found = store.find_open_incident(self.conn, "ip", "1.2.3.4",
                                         T0 - timedelta(hours=1))
        self.assertEqual(newer, found["id"])

    def test_an_aware_window_start_is_converted_not_stringified(self):
        open_incident(self.conn)
        for hours in (-13, 0, 13):
            aware = T0.astimezone(timezone(timedelta(hours=hours)))
            found = store.find_open_incident(self.conn, "ip", "1.2.3.4", aware)
            self.assertIsNotNone(found, "window_start={}".format(aware))

    def test_timestamps_are_stored_local_naive(self):
        aware = datetime(2026, 10, 3, 14, 0, 0, tzinfo=timezone.utc)
        incident_id = open_incident(self.conn, opened_at=aware, last_seen=aware)
        row = store.query_incidents(self.conn, incident_id=incident_id)[0]
        expected = to_local_naive(aware).isoformat(sep=" ")
        self.assertEqual(expected, row["opened_at"])
        self.assertEqual(expected, row["last_seen"])

    def test_tactics_persist_as_a_json_list(self):
        incident_id = open_incident(self.conn, tactics=["TA0006", "TA0005"])
        row = store.query_incidents(self.conn, incident_id=incident_id)[0]
        self.assertEqual(["TA0006", "TA0005"], json.loads(row["tactics"]))

    def test_update_changes_only_what_it_is_given(self):
        incident_id = open_incident(self.conn, severity="LOW", score=2)
        store.update_incident(self.conn, incident_id, severity="HIGH", score=8)
        row = store.query_incidents(self.conn, incident_id=incident_id)[0]
        self.assertEqual("HIGH", row["severity"])
        self.assertEqual(8, row["score"])
        self.assertEqual("t", row["title"])

    def test_update_encodes_a_tactics_list_and_keeps_a_string(self):
        incident_id = open_incident(self.conn)
        store.update_incident(self.conn, incident_id, tactics=["TA0001"])
        row = store.query_incidents(self.conn, incident_id=incident_id)[0]
        self.assertEqual('["TA0001"]', row["tactics"])
        store.update_incident(self.conn, incident_id, tactics='["TA0002"]')
        row = store.query_incidents(self.conn, incident_id=incident_id)[0]
        self.assertEqual('["TA0002"]', row["tactics"])

    def test_update_stores_a_datetime_local_naive(self):
        incident_id = open_incident(self.conn)
        aware = datetime(2026, 10, 3, 15, 0, 0, tzinfo=timezone.utc)
        store.update_incident(self.conn, incident_id, last_seen=aware)
        row = store.query_incidents(self.conn, incident_id=incident_id)[0]
        self.assertEqual(to_local_naive(aware).isoformat(sep=" "),
                         row["last_seen"])

    def test_update_rejects_an_unknown_column(self):
        # The column name reaches the SQL text, so it is allow-listed.
        incident_id = open_incident(self.conn, severity="LOW", score=2)
        with self.assertRaises(ValueError):
            store.update_incident(self.conn, incident_id, nosuch="x")

    def test_update_rejects_an_injected_column_name(self):
        incident_id = open_incident(self.conn)
        with self.assertRaises(ValueError):
            store.update_incident(self.conn, incident_id,
                                  **{"score = 0, status": "x"})
        row = store.query_incidents(self.conn, incident_id=incident_id)[0]
        self.assertEqual("OPEN", row["status"])

    def test_update_rejects_the_id_column(self):
        incident_id = open_incident(self.conn)
        with self.assertRaises(ValueError):
            store.update_incident(self.conn, incident_id, id=999)

    def test_update_returns_the_rows_changed(self):
        incident_id = open_incident(self.conn)
        self.assertEqual(1, store.update_incident(self.conn, incident_id, score=9))
        self.assertEqual(0, store.update_incident(self.conn, 999, score=9))

    def test_update_with_no_fields_raises_rather_than_returning_zero(self):
        # 0 would read as "no such incident".
        incident_id = open_incident(self.conn)
        with self.assertRaises(ValueError):
            store.update_incident(self.conn, incident_id)

    def test_close_returns_the_rows_changed(self):
        incident_id = open_incident(self.conn)
        self.assertEqual(1, store.close_incident(self.conn, incident_id))
        self.assertEqual(0, store.close_incident(self.conn, 999))

    def test_tactics_none_is_an_empty_list(self):
        incident_id = open_incident(self.conn, tactics=None)
        row = store.query_incidents(self.conn, incident_id=incident_id)[0]
        self.assertEqual("[]", row["tactics"])
        store.update_incident(self.conn, incident_id, tactics=["TA0001"])
        store.update_incident(self.conn, incident_id, tactics=None)
        row = store.query_incidents(self.conn, incident_id=incident_id)[0]
        self.assertEqual("[]", row["tactics"])

    def test_close_sets_status_closed(self):
        incident_id = open_incident(self.conn)
        store.close_incident(self.conn, incident_id)
        row = store.query_incidents(self.conn, incident_id=incident_id)[0]
        self.assertEqual("CLOSED", row["status"])

    def test_attach_alerts_sets_incident_id_on_each(self):
        store.insert_alerts(self.conn, [sample_alert()])
        alert_id = store.query_alerts(self.conn)[0]["id"]
        incident_id = open_incident(self.conn)
        store.attach_alerts(self.conn, incident_id, [alert_id])
        self.assertEqual(incident_id,
                         store.query_alerts(self.conn)[0]["incident_id"])

    def test_attach_alerts_leaves_other_alerts_alone(self):
        store.insert_alerts(self.conn, [sample_alert(entity_value="a"),
                                        sample_alert(entity_value="b")])
        first, second = [r["id"] for r in
                         store.query_alerts(self.conn, order="asc")]
        incident_id = open_incident(self.conn)
        store.attach_alerts(self.conn, incident_id, [first])
        rows = {r["id"]: r["incident_id"] for r in store.query_alerts(self.conn)}
        self.assertEqual({first: incident_id, second: None}, rows)

    def test_attach_alerts_with_no_ids_is_a_no_op(self):
        store.insert_alerts(self.conn, [sample_alert()])
        self.assertEqual(0, store.attach_alerts(self.conn, open_incident(self.conn), []))
        self.assertIsNone(store.query_alerts(self.conn)[0]["incident_id"])

    def test_attach_alerts_returns_how_many_it_attached(self):
        store.insert_alerts(self.conn, [sample_alert(entity_value="a"),
                                        sample_alert(entity_value="b")])
        ids = [r["id"] for r in store.query_alerts(self.conn)]
        incident_id = open_incident(self.conn)
        # An alert id that does not exist is not counted.
        self.assertEqual(2, store.attach_alerts(self.conn, incident_id, ids + [999]))

    def test_attach_alerts_refuses_an_unknown_incident(self):
        # No foreign key guards the column, so the function must: a dangling
        # incident_id would be written otherwise.
        store.insert_alerts(self.conn, [sample_alert()])
        alert_id = store.query_alerts(self.conn)[0]["id"]
        with self.assertRaises(ValueError):
            store.attach_alerts(self.conn, 999, [alert_id])
        self.assertIsNone(store.query_alerts(self.conn)[0]["incident_id"])

    def test_query_incidents_filters_by_status_and_orders_by_score(self):
        low = open_incident(self.conn, entity_value="a", severity="LOW", score=2)
        high = open_incident(self.conn, entity_value="b", score=20)
        closed = open_incident(self.conn, entity_value="c", score=99)
        store.close_incident(self.conn, closed)
        rows = store.query_incidents(self.conn, status="OPEN")
        self.assertEqual([high, low], [r["id"] for r in rows])

    def test_query_incidents_filters_by_entity_and_since(self):
        old = open_incident(self.conn, entity_value="a",
                            last_seen=T0 - timedelta(days=2))
        new = open_incident(self.conn, entity_value="a")
        open_incident(self.conn, entity_value="b")
        rows = store.query_incidents(self.conn, entity="a",
                                     since=T0 - timedelta(hours=1))
        self.assertEqual([new], [r["id"] for r in rows])
        self.assertEqual({old, new}, {r["id"] for r in
                                      store.query_incidents(self.conn, entity="a")})

    def test_query_incidents_orders_by_last_seen_and_rejects_unknown_order(self):
        old = open_incident(self.conn, last_seen=T0 - timedelta(hours=1), score=99)
        new = open_incident(self.conn, last_seen=T0, score=1)
        rows = store.query_incidents(self.conn, order="last_seen")
        self.assertEqual([new, old], [r["id"] for r in rows])
        with self.assertRaises(ValueError):
            store.query_incidents(self.conn, order="sideways")
        with self.assertRaises(ValueError):
            store.query_incidents(self.conn, order=[])

    def test_query_incidents_order_is_case_insensitive_like_query_alerts(self):
        low = open_incident(self.conn, entity_value="a", score=1)
        high = open_incident(self.conn, entity_value="b", score=9)
        rows = store.query_incidents(self.conn, order="SCORE")
        self.assertEqual([high, low], [r["id"] for r in rows])

    def test_query_incidents_a_falsy_filter_filters(self):
        open_incident(self.conn)
        self.assertEqual([], store.query_incidents(self.conn, incident_id=0))
        self.assertEqual([], store.query_incidents(self.conn, status=""))

    def test_query_incidents_limit(self):
        for v in "abc":
            open_incident(self.conn, entity_value=v)
        self.assertEqual(3, len(store.query_incidents(self.conn, limit=None)))
        self.assertEqual(2, len(store.query_incidents(self.conn, limit=2)))

    def test_query_incidents_aware_since_is_converted(self):
        open_incident(self.conn)
        for hours in (-13, 0, 13):
            aware = T0.astimezone(timezone(timedelta(hours=hours)))
            self.assertEqual(1, len(store.query_incidents(self.conn, since=aware)),
                             "since={}".format(aware))


class TestCloseIdleIncidents(StoreTestCase):
    # Moved here from test_correlator with the function (R88). Seeded with
    # open_incident, not correlate: the store's tests do not need the correlator.
    #
    # The brief's offsets (+30 min, +3 h) sat far from IDLE_TIMEOUT, so mutating
    # it passed every one. The boundary tests sit on it. Chosen boundary: idle
    # for exactly the timeout is still open; only MORE than the timeout closes.
    # That matches the correlation window, where exactly one window later still
    # attaches. Literal offsets, not the constant: an offset scaled by the
    # constant under test moves with it.
    def test_an_idle_incident_closes(self):
        open_incident(self.conn)
        closed = store.close_idle_incidents(self.conn, now=T0 + timedelta(hours=3))
        self.assertEqual(1, closed)
        self.assertEqual("CLOSED", store.query_incidents(self.conn)[0]["status"])

    def test_a_recent_incident_stays_open(self):
        open_incident(self.conn)
        self.assertEqual(0, store.close_idle_incidents(
            self.conn, now=T0 + timedelta(minutes=30)))

    def test_closing_is_idempotent(self):
        open_incident(self.conn)
        store.close_idle_incidents(self.conn, now=T0 + timedelta(hours=3))
        self.assertEqual(0, store.close_idle_incidents(
            self.conn, now=T0 + timedelta(hours=4)))

    def test_idle_for_exactly_two_hours_stays_open(self):
        open_incident(self.conn)
        self.assertEqual(0, store.close_idle_incidents(
            self.conn, now=T0 + timedelta(hours=2)))

    def test_idle_one_second_past_two_hours_closes(self):
        open_incident(self.conn)
        self.assertEqual(1, store.close_idle_incidents(
            self.conn, now=T0 + timedelta(hours=2, seconds=1)))

    def test_the_idle_timeout_argument_is_honoured(self):
        open_incident(self.conn)
        self.assertEqual(1, store.close_idle_incidents(
            self.conn, now=T0 + timedelta(minutes=11),
            idle_timeout=timedelta(minutes=10)))

    def test_idleness_is_measured_from_last_seen(self):
        open_incident(self.conn, last_seen=T0 + timedelta(minutes=20))
        # 2h10m after opening (idle by that clock), 1h50m after the last alert.
        self.assertEqual(0, store.close_idle_incidents(
            self.conn, now=T0 + timedelta(hours=2, minutes=10)))

    def test_now_defaults_to_the_clock(self):
        # A year-2000 incident is idle against any real clock.
        open_incident(self.conn, opened_at=datetime(2000, 1, 1),
                      last_seen=datetime(2000, 1, 1))
        self.assertEqual(1, store.close_idle_incidents(self.conn))

    def test_a_recently_seen_incident_stays_open_beside_an_idle_one(self):
        open_incident(self.conn, entity_value="old")
        open_incident(self.conn, entity_value="new", last_seen=T0 + timedelta(hours=3))
        self.assertEqual(1, store.close_idle_incidents(
            self.conn, now=T0 + timedelta(hours=3)))
        self.assertEqual({"old": "CLOSED", "new": "OPEN"}, {
            r["entity_value"]: r["status"] for r in store.query_incidents(self.conn)})


if __name__ == "__main__":
    unittest.main()

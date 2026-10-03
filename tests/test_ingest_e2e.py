"""Phase 0-1 gate: raw source in, queryable normalized events out."""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from cli.commands import ingest as ingest_command
from core import store
from ingestion import windows_eventlog as wel
from tests.fixtures import events_xml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACCESS_LOG = os.path.join(ROOT, "data", "sample_access.log")
WINDOWS_CSV = os.path.join(ROOT, "samples", "windows_security.log")

APACHE_LINE = (
    '10.0.0.{ip} - - [09/May/2026:10:00:0{n} +0000] '
    '"GET /page{n} HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'
)


class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.tmpdir = tempfile.mkdtemp()
        self.conn = store.connect(self.db_path)
        store.init_schema(self.conn)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        try:
            os.unlink(self.db_path)
        except OSError:
            pass

    def ingest(self, records):
        with mock.patch.object(wel, "read_channel", return_value=records):
            return ingest_command.ingest_channel(self.conn, "Security", 100, None)

    def apache_file(self, name, line5_ip):
        """Five apache lines; only line 5 differs between files."""
        path = os.path.join(self.tmpdir, name)
        with open(path, "w", encoding="utf-8") as fh:
            for n in range(1, 6):
                fh.write(APACHE_LINE.format(ip=line5_ip if n == 5 else 1, n=n))
        return path

    def test_ingested_events_are_queryable_by_ip(self):
        self.ingest([events_xml.FAILED_LOGON_4625])
        events = store.query_events(self.conn, source_ip="203.0.113.50")
        self.assertEqual(1, len(events))
        self.assertEqual("LOGIN_FAIL", events[0].action)

    def test_ingested_events_are_queryable_by_target_user(self):
        self.ingest([events_xml.FAILED_LOGON_4625])
        self.assertEqual(1, len(store.query_events(self.conn, user="administrator")))

    def test_process_fields_survive_the_round_trip(self):
        self.ingest([events_xml.PROCESS_4688])
        event = store.query_events(self.conn, event_id=4688)[0]
        self.assertEqual("powershell -enc SQBFAFgA", event.command_line)
        self.assertIn("cmd.exe", event.parent_process)

    def test_metadata_survives_the_round_trip(self):
        self.ingest([events_xml.FAILED_LOGON_4625])
        event = store.query_events(self.conn, event_id=4625)[0]
        self.assertEqual("0xc000006a", event.metadata["sub_status"])

    def test_events_are_returned_in_chronological_order(self):
        self.ingest([events_xml.PROCESS_4688, events_xml.FAILED_LOGON_4625])
        events = store.query_events(self.conn)
        self.assertEqual(4625, events[0].event_id)
        self.assertEqual(4688, events[1].event_id)

    def test_legacy_csv_file_lands_in_the_same_store(self):
        result = ingest_command.ingest_logfile(self.conn, WINDOWS_CSV)
        self.assertGreater(result["inserted"], 0)
        self.assertGreater(len(store.query_events(self.conn, action="LOGIN_FAIL")), 0)

    def test_apache_sample_is_ingested_and_queryable(self):
        result = ingest_command.ingest_logfile(self.conn, ACCESS_LOG)
        self.assertGreater(result["inserted"], 0)
        with open(ACCESS_LOG, encoding="utf-8") as fh:
            lines = sum(1 for line in fh if line.strip())
        # The legacy parser skips some sample lines; every line is accounted for.
        self.assertEqual(lines, result["read"] + result["skipped"])
        self.assertEqual(result["read"], result["inserted"])
        self.assertEqual(
            result["inserted"], len(store.query_events(self.conn, channel="apache"))
        )
        self.assertGreater(
            len(store.query_events(self.conn, source_ip="192.168.1.5")), 0
        )

    def test_channel_and_file_sources_coexist(self):
        self.ingest([events_xml.FAILED_LOGON_4625])
        ingest_command.ingest_logfile(self.conn, WINDOWS_CSV)
        channels = store.stats(self.conn)["by_channel"]
        self.assertIn("Security", channels)
        self.assertIn("windows-csv", channels)

    def test_all_sources_in_one_store_lose_no_events_to_hash_collisions(self):
        results = [
            ingest_command.ingest_logfile(self.conn, ACCESS_LOG),
            ingest_command.ingest_logfile(self.conn, WINDOWS_CSV),
        ]
        live = self.ingest([events_xml.FAILED_LOGON_4625, events_xml.PROCESS_4688])
        expected = sum(r["inserted"] for r in results) + live["inserted"]
        self.assertEqual(2, live["inserted"])
        self.assertEqual(expected, store.count_events(self.conn))
        self.assertEqual(
            sum(r["read"] for r in results) + 2, store.count_events(self.conn)
        )

    def test_different_files_with_the_same_line_number_both_land(self):
        a = self.apache_file("a.log", line5_ip=5)
        b = self.apache_file("b.log", line5_ip=6)
        self.assertEqual(5, ingest_command.ingest_logfile(self.conn, a)["inserted"])
        # a and b share lines 1-4 byte for byte; only line 5 is new.
        self.assertEqual(1, ingest_command.ingest_logfile(self.conn, b)["inserted"])
        rows = self.conn.execute(
            "SELECT source_ip FROM events WHERE channel='apache' AND record_id=5"
        ).fetchall()
        self.assertEqual(2, len(rows))
        self.assertEqual({"10.0.0.5", "10.0.0.6"}, {r["source_ip"] for r in rows})

    def test_reingesting_the_same_file_inserts_nothing(self):
        first = ingest_command.ingest_logfile(self.conn, ACCESS_LOG)
        second = ingest_command.ingest_logfile(self.conn, ACCESS_LOG)
        self.assertGreater(first["inserted"], 0)
        self.assertEqual(0, second["inserted"])
        self.assertEqual(first["inserted"], store.count_events(self.conn))

    def test_live_system_channel_is_stored_and_queryable(self):
        try:
            result = ingest_command.ingest_channel(self.conn, "System", 50, None)
        except (wel.EventLogAccessError, wel.ChannelNotFoundError,
                OSError, ImportError) as exc:
            self.skipTest("Windows Event Log unavailable: {}".format(exc))
        if not result["read"]:
            self.skipTest("System channel returned no records")

        self.assertGreater(result["inserted"], 0)
        self.assertEqual(
            result["last_record_id"], store.get_bookmark(self.conn, "System")
        )
        found = store.query_events(self.conn, channel="System", limit=100)
        self.assertEqual(result["inserted"], len(found))
        self.assertIn(result["last_record_id"], [e.record_id for e in found])
        # The same row is reachable by its own host and event id.
        sample = found[0]
        again = store.query_events(
            self.conn, host=sample.host, event_id=sample.event_id, channel="System"
        )
        self.assertIn(sample.record_id, [e.record_id for e in again])


if __name__ == "__main__":
    unittest.main()

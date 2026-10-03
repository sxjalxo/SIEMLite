import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from unittest import mock

import cli
from cli.commands import ingest as ingest_command
from core import store
from ingestion import windows_eventlog as wel
from ingestion.log_ingestor import (
    LogEvent, parse_apache, parse_ssh, parse_windows_csv,
)
from ingestion.normalizer import NormalizedEvent
from tests.fixtures import events_xml

_real_insert_events = store.insert_events

WIN_CSV_HEADER = ("TimeGenerated,EventID,SourceName,Category,UserName,"
                  "ComputerName,Message\n")


def parse_text(parser, suffix, text):
    """Run a file parser over `text` in a temp file. Returns (events, skipped)."""
    handle, path = tempfile.mkstemp(suffix=suffix)
    os.close(handle)
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        return parser(path)
    finally:
        os.unlink(path)


def make_event(record_id, action="LOGON"):
    return NormalizedEvent(
        timestamp=datetime(2026, 5, 9, 10, 0, 0), source_type="windows",
        host="H", channel="Security", event_id=4625, record_id=record_id,
        action=action,
    )


def make_log_event(timestamp, user="u"):
    return LogEvent(
        timestamp=timestamp, source_type="ssh", source_ip="1.2.3.4", user=user,
        action="LOGIN_FAIL", detail="d", status_code=0, raw_line="raw " + user,
    )


class IngestTestCase(unittest.TestCase):
    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.conn = store.connect(self.db_path)
        store.init_schema(self.conn)

    def tearDown(self):
        self.conn.close()
        try:
            os.unlink(self.db_path)
        except OSError:
            pass

    def run_cli(self, argv):
        code, out, _err = self.run_cli_split(argv)
        return code, out

    def run_cli_split(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.dispatch(["--db", self.db_path] + argv)
        return code, out.getvalue(), err.getvalue()


class TestIngestChannel(IngestTestCase):
    def test_stores_read_events(self):
        with mock.patch.object(
            wel, "read_channel",
            return_value=[events_xml.FAILED_LOGON_4625, events_xml.PROCESS_4688],
        ):
            result = ingest_command.ingest_channel(self.conn, "Security", 100, None)
        self.assertEqual(2, result["read"])
        self.assertEqual(2, result["inserted"])
        self.assertEqual(2, store.count_events(self.conn))

    def test_second_run_inserts_nothing_new(self):
        with mock.patch.object(
            wel, "read_channel", return_value=[events_xml.FAILED_LOGON_4625]
        ):
            ingest_command.ingest_channel(self.conn, "Security", 100, None)
            result = ingest_command.ingest_channel(self.conn, "Security", 100, None)
        self.assertEqual(0, result["inserted"])
        self.assertEqual(1, store.count_events(self.conn))

    def test_bookmark_advances_to_highest_record_id(self):
        with mock.patch.object(
            wel, "read_channel",
            return_value=[events_xml.FAILED_LOGON_4625, events_xml.PROCESS_4688],
        ):
            ingest_command.ingest_channel(self.conn, "Security", 100, None)
        self.assertEqual(612, store.get_bookmark(self.conn, "Security"))

    def test_resume_passes_bookmark_to_reader(self):
        store.set_bookmark(self.conn, "Security", 500)
        with mock.patch.object(wel, "read_channel", return_value=[]) as reader:
            ingest_command.ingest_channel(self.conn, "Security", 100, None, resume=True)
        self.assertEqual(500, reader.call_args.kwargs["after_record_id"])

    def test_no_resume_ignores_bookmark(self):
        store.set_bookmark(self.conn, "Security", 500)
        with mock.patch.object(wel, "read_channel", return_value=[]) as reader:
            ingest_command.ingest_channel(
                self.conn, "Security", 100, None, resume=False
            )
        self.assertEqual(0, reader.call_args.kwargs["after_record_id"])

    def test_empty_channel_leaves_bookmark_untouched(self):
        store.set_bookmark(self.conn, "Security", 500)
        with mock.patch.object(wel, "read_channel", return_value=[]):
            ingest_command.ingest_channel(self.conn, "Security", 100, None)
        self.assertEqual(500, store.get_bookmark(self.conn, "Security"))

    def test_unparseable_record_does_not_abort_the_batch(self):
        with mock.patch.object(
            wel, "read_channel",
            return_value=["<not-an-event/>", events_xml.FAILED_LOGON_4625],
        ):
            result = ingest_command.ingest_channel(self.conn, "Security", 100, None)
        self.assertEqual(1, result["inserted"])
        self.assertEqual(1, result["skipped"])

    def test_bookmark_ignores_unparseable_records_at_the_tail(self):
        # read_channel puts unparseable records last on purpose.
        with mock.patch.object(
            wel, "read_channel",
            return_value=[events_xml.PROCESS_4688, "<not-an-event/>"],
        ):
            result = ingest_command.ingest_channel(self.conn, "Security", 100, None)
        self.assertEqual(612, store.get_bookmark(self.conn, "Security"))
        self.assertEqual(612, result["last_record_id"])

    def query_handed_to_reader(self, resume, bookmark=None, since=None):
        """The XPath the reader would build from what ingest_channel passed it."""
        if bookmark is not None:
            store.set_bookmark(self.conn, "Security", bookmark)
        with mock.patch.object(wel, "read_channel", return_value=[]) as reader:
            ingest_command.ingest_channel(
                self.conn, "Security", 100, since, resume=resume
            )
        kwargs = reader.call_args.kwargs
        return wel.build_query(kwargs["since"], kwargs["after_record_id"])

    def test_resume_drops_since_so_the_gap_is_not_filtered_out(self):
        # ANDing since with the bookmark hides every record in a gap longer
        # than --since, and the bookmark then advances past them: silent,
        # permanent loss. The bookmark alone defines a resumed window.
        query = self.query_handed_to_reader(
            resume=True, bookmark=500, since=datetime(2026, 10, 2, 12, 0, 0)
        )
        self.assertIn("EventRecordID>500", query)
        self.assertNotIn("TimeCreated", query)

    def test_fresh_run_without_a_bookmark_still_uses_since(self):
        query = self.query_handed_to_reader(
            resume=True, since=datetime(2026, 10, 2, 12, 0, 0)
        )
        self.assertIn("TimeCreated", query)

    def test_no_resume_still_uses_since(self):
        query = self.query_handed_to_reader(
            resume=False, bookmark=500, since=datetime(2026, 10, 2, 12, 0, 0)
        )
        self.assertIn("TimeCreated", query)
        self.assertNotIn("EventRecordID", query)

    def test_bookmark_is_max_record_id_not_last_event(self):
        events = [make_event(3), make_event(9), make_event(5)]
        with mock.patch.object(wel, "read_channel", return_value=["x"] * 3), \
                mock.patch.object(
                    ingest_command, "normalize_windows_xml", side_effect=events
                ):
            result = ingest_command.ingest_channel(self.conn, "Security", 100, None)
        self.assertEqual(9, store.get_bookmark(self.conn, "Security"))
        self.assertEqual(9, result["last_record_id"])


class TestPoisonEvent(IngestTestCase):
    """R18: one permanently malformed event must not block the channel."""

    def ingest_with_poison(self):
        # action=None violates NOT NULL, so the store raises IntegrityError.
        events = [make_event(1), make_event(2), make_event(3),
                  make_event(4, action=None)]
        with mock.patch.object(
            wel, "read_channel", return_value=["x"] * 4
        ), mock.patch.object(
            ingest_command, "normalize_windows_xml", side_effect=events
        ):
            return ingest_command.ingest_channel(self.conn, "Security", 100, None)

    def test_good_events_land_and_bad_one_is_counted(self):
        result = self.ingest_with_poison()
        self.assertEqual(3, result["inserted"])
        self.assertEqual(1, result["skipped"])
        self.assertEqual(3, store.count_events(self.conn))

    def test_bookmark_moves_past_the_poison_event(self):
        self.ingest_with_poison()
        self.assertEqual(4, store.get_bookmark(self.conn, "Security"))

    def test_rerun_does_not_stall_or_raise(self):
        self.ingest_with_poison()
        result = self.ingest_with_poison()
        self.assertEqual(0, result["inserted"])
        self.assertEqual(1, result["skipped"])
        self.assertEqual(3, store.count_events(self.conn))

    def test_rejected_record_ids_are_named(self):
        result = self.ingest_with_poison()
        self.assertEqual([4], result["rejected_record_ids"])

    def test_inserted_counts_rows_committed_by_earlier_batches(self):
        events = [make_event(1), make_event(2, action=None)]
        with mock.patch.object(wel, "read_channel", return_value=["x"] * 2), \
                mock.patch.object(
                    ingest_command, "normalize_windows_xml", side_effect=events
                ), \
                mock.patch.object(
                    store, "insert_events",
                    side_effect=lambda c, e: _real_insert_events(c, e, batch_size=1),
                ):
            result = ingest_command.ingest_channel(self.conn, "Security", 100, None)
        self.assertEqual(1, result["inserted"])
        self.assertEqual(1, result["skipped"])


class TestIngestLogfile(IngestTestCase):
    def test_bad_timestamps_are_skipped_not_fatal(self):
        events = [
            make_log_event(datetime(2026, 5, 9, 10, 0, 0), "a"),
            make_log_event(None, "b"),
            make_log_event(datetime(2026, 5, 9, 10, 0, 1), "c"),
        ]
        with mock.patch.object(
            ingest_command, "ingest_file", return_value=(events, {"skipped": 2})
        ):
            result = ingest_command.ingest_logfile(self.conn, "x.log")
        self.assertEqual(2, result["inserted"])
        self.assertEqual(3, result["read"])
        self.assertEqual(3, result["skipped"])  # 2 from the parser + 1 here

    def test_out_of_range_timestamp_is_skipped(self):
        events = [make_log_event(datetime(1, 1, 1, tzinfo=timezone.utc))]
        with mock.patch.object(
            ingest_command, "ingest_file", return_value=(events, {"skipped": 0})
        ):
            result = ingest_command.ingest_logfile(self.conn, "x.log")
        self.assertEqual(0, result["inserted"])
        self.assertEqual(1, result["skipped"])

    def test_store_rejects_are_counted_and_named(self):
        events = [make_log_event(datetime(2026, 5, 9, 10, 0, 0), "a"),
                  make_log_event(datetime(2026, 5, 9, 10, 0, 1), "b")]
        normalized = [make_event(1), make_event(2, action=None)]
        with mock.patch.object(
            ingest_command, "ingest_file", return_value=(events, {"skipped": 0})
        ), mock.patch.object(
            ingest_command, "from_log_event", side_effect=normalized
        ):
            result = ingest_command.ingest_logfile(self.conn, "x.log")
        self.assertEqual(1, result["inserted"])
        self.assertEqual(1, result["skipped"])
        self.assertEqual([2], result["rejected_record_ids"])


class TestShortCsvRow(unittest.TestCase):
    def test_row_with_fewer_fields_than_header_does_not_crash(self):
        handle, path = tempfile.mkstemp(suffix=".csv")
        os.close(handle)
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("TimeGenerated,EventID,SourceName,Category,UserName,"
                         "ComputerName,Message\n")
                fh.write("2026-05-09 10:00:01,4625\n")
                fh.write("2026-05-09 10:00:02,4625,src,cat,bob,PC,failed\n")
            events, skipped = parse_windows_csv(path)
        finally:
            os.unlink(path)
        self.assertEqual(2, len(events) + skipped)
        self.assertGreaterEqual(len(events), 1)


class TestTimestampIsNeverInvented(unittest.TestCase):
    """A substituted now() is a lie every --since, --until and purge reads."""

    def test_microsoft_csv_export_format_parses_to_the_real_time(self):
        events, skipped = parse_text(
            parse_windows_csv, ".csv",
            WIN_CSV_HEADER + "10/3/2026 10:00:00 AM,4625,s,c,bob,PC,failed\n",
        )
        self.assertEqual(0, skipped)
        self.assertEqual(datetime(2026, 10, 3, 10, 0, 0), events[0].timestamp)

    def test_unpadded_pm_hour_parses(self):
        events, _ = parse_text(
            parse_windows_csv, ".csv",
            WIN_CSV_HEADER + "9/3/2026 9:05:00 PM,4625,s,c,bob,PC,failed\n",
        )
        self.assertEqual(datetime(2026, 9, 3, 21, 5, 0), events[0].timestamp)

    def test_iso_csv_format_still_parses(self):
        events, _ = parse_text(
            parse_windows_csv, ".csv",
            WIN_CSV_HEADER + "2026-05-09 10:00:01,4625,s,c,bob,PC,failed\n",
        )
        self.assertEqual(datetime(2026, 5, 9, 10, 0, 1), events[0].timestamp)

    def test_unparseable_csv_date_is_skipped_and_stores_no_row(self):
        events, skipped = parse_text(
            parse_windows_csv, ".csv",
            WIN_CSV_HEADER + "not a date,4625,s,c,bob,PC,failed\n",
        )
        self.assertEqual([], events)
        self.assertEqual(1, skipped)

    def test_apache_line_without_an_offset_is_skipped(self):
        events, skipped = parse_text(
            parse_apache, ".log",
            '192.168.1.5 - - [09/May/2026:10:00:01] "GET /a HTTP/1.1" '
            '200 512 "-" "x"\n',
        )
        self.assertEqual([], events)
        self.assertEqual(1, skipped)


class TestMalformedSshLine(unittest.TestCase):
    """One bad line costs one line, not the file — and never a traceback."""

    GOOD = ("Feb 10 10:00:0{n} host sshd[1]: Failed password for root "
            "from 1.2.3.{n} port 22 ssh2\n")

    def parse_with_bad_line(self, bad_time):
        return parse_text(parse_ssh, ".log", "".join([
            self.GOOD.format(n=1),
            "Feb {} host sshd[1]: Failed password for root from "
            "1.2.3.4 port 22 ssh2\n".format(bad_time),
            self.GOOD.format(n=3),
        ]))

    def test_missing_seconds_does_not_raise_or_lose_the_file(self):
        events, skipped = self.parse_with_bad_line("10 10:00")
        self.assertEqual(2, len(events))
        self.assertEqual(1, skipped)

    def test_impossible_day_is_skipped(self):
        events, skipped = self.parse_with_bad_line("30 10:00:00")
        self.assertEqual(2, len(events))
        self.assertEqual(1, skipped)

    def test_out_of_range_hour_is_skipped(self):
        events, skipped = self.parse_with_bad_line("10 99:00:00")
        self.assertEqual(2, len(events))
        self.assertEqual(1, skipped)

    def test_non_numeric_time_is_skipped(self):
        events, skipped = self.parse_with_bad_line("10 notatime")
        self.assertEqual(2, len(events))
        self.assertEqual(1, skipped)


class TestIngestCommand(IngestTestCase):
    def test_missing_optional_channel_is_a_warning_not_a_failure(self):
        def reader(channel, **kwargs):
            if "Sysmon" in channel:
                raise wel.ChannelNotFoundError("no sysmon here")
            return [events_xml.FAILED_LOGON_4625]

        with mock.patch.object(wel, "read_channel", side_effect=reader):
            code, _ = self.run_cli(
                ["ingest", "--channel",
                 "Security,Microsoft-Windows-Sysmon/Operational"]
            )
        self.assertEqual(0, code)
        self.assertEqual(1, store.count_events(self.conn))

    def test_access_denied_on_every_channel_exits_nonzero(self):
        with mock.patch.object(
            wel, "read_channel",
            side_effect=wel.EventLogAccessError(
                "Access denied. Run as Administrator."
            ),
        ):
            code, output = self.run_cli(["ingest", "--channel", "Security"])
        self.assertEqual(1, code)
        self.assertIn("Administrator", output)

    def test_non_positive_count_is_a_usage_error(self):
        for value in ("0", "-5", "abc"):
            err = io.StringIO()
            with self.assertRaises(SystemExit) as raised, redirect_stderr(err):
                cli.dispatch(["--db", self.db_path, "ingest", "--count", value])
            self.assertEqual(2, raised.exception.code)
            self.assertIn("--count", err.getvalue())

    def test_json_output_is_parseable(self):
        with mock.patch.object(
            wel, "read_channel", return_value=[events_xml.FAILED_LOGON_4625]
        ):
            code, output = self.run_cli(["--json", "ingest", "--channel", "Security"])
        self.assertEqual(0, code)
        self.assertEqual(1, json.loads(output)["total_inserted"])

    def test_comma_separated_channels_are_split(self):
        seen = []

        def reader(channel, **kwargs):
            seen.append(channel)
            return []

        with mock.patch.object(wel, "read_channel", side_effect=reader):
            self.run_cli(["ingest", "--channel", "Security,System"])
        self.assertEqual(["Security", "System"], seen)

    def test_file_ingestion_stores_events(self):
        code, _ = self.run_cli(["ingest", "--file", "samples/windows_security.log"])
        self.assertEqual(0, code)
        self.assertGreater(store.count_events(self.conn), 0)

    def reader_denying_security(self):
        def reader(channel, **kwargs):
            if channel == "Security":
                raise wel.EventLogAccessError(
                    "Access denied reading the 'Security' channel."
                )
            return [events_xml.FAILED_LOGON_4625]
        return reader

    def test_partial_denial_is_reported_and_exits_3(self):
        with mock.patch.object(
            wel, "read_channel", side_effect=self.reader_denying_security()
        ):
            code, output = self.run_cli(["ingest", "--channel", "Security,System"])
        self.assertEqual(3, code)
        self.assertIn("Access denied reading the 'Security' channel", output)
        self.assertEqual(1, store.count_events(self.conn))  # System still stored

    def test_partial_denial_appears_in_json(self):
        with mock.patch.object(
            wel, "read_channel", side_effect=self.reader_denying_security()
        ):
            code, output = self.run_cli(
                ["--json", "ingest", "--channel", "Security,System"]
            )
        data = json.loads(output)
        self.assertEqual(3, code)
        self.assertEqual(1, data["total_inserted"])
        self.assertEqual(["Security"], [d["channel"] for d in data["denied"]])

    def test_skipped_records_exit_3_and_are_visible_in_output(self):
        with mock.patch.object(
            wel, "read_channel",
            return_value=["<not-an-event/>", events_xml.FAILED_LOGON_4625],
        ):
            code, output = self.run_cli(["ingest", "--channel", "Security"])
        # 3, not 0: a dropped record is a coverage gap, same as a denied
        # channel. Dropping records silently is the one thing a SIEM must
        # never report as a clean run.
        self.assertEqual(3, code)
        self.assertIn("skipped 1", output)

    def test_exit_0_when_everything_read(self):
        with mock.patch.object(
            wel, "read_channel", return_value=[events_xml.FAILED_LOGON_4625]
        ):
            code, _ = self.run_cli(["ingest", "--channel", "System"])
        self.assertEqual(0, code)

    def test_exit_1_when_denied_and_nothing_read(self):
        with mock.patch.object(
            wel, "read_channel", side_effect=self.reader_denying_security()
        ):
            code, _ = self.run_cli(["ingest", "--channel", "Security"])
        self.assertEqual(1, code)

    def test_exit_1_when_denied_and_the_rest_not_found(self):
        def reader(channel, **kwargs):
            if channel == "Security":
                raise wel.EventLogAccessError("denied")
            raise wel.ChannelNotFoundError("absent")

        with mock.patch.object(wel, "read_channel", side_effect=reader):
            code, _ = self.run_cli(["ingest", "--channel", "Security,Nope"])
        self.assertEqual(1, code)

    def test_exit_3_when_some_read_and_some_denied(self):
        with mock.patch.object(
            wel, "read_channel", side_effect=self.reader_denying_security()
        ):
            code, _ = self.run_cli(["ingest", "--channel", "Security,System"])
        self.assertEqual(3, code)

    def test_skip_warning_line_names_rejected_record_ids(self):
        events = [make_event(1), make_event(2, action=None)]
        with mock.patch.object(wel, "read_channel", return_value=["x"] * 2), \
                mock.patch.object(
                    ingest_command, "normalize_windows_xml", side_effect=events
                ):
            _, output = self.run_cli(["ingest", "--channel", "Security"])
        self.assertIn("1 record(s) skipped", output)
        self.assertIn("rejected record_id: 2", output)

    def ingest_poison(self, argv, record_ids):
        events = [make_event(i, action=None) for i in record_ids]
        with mock.patch.object(
            wel, "read_channel", return_value=["x"] * len(events)
        ), mock.patch.object(
            ingest_command, "normalize_windows_xml", side_effect=events
        ):
            return self.run_cli(argv + ["ingest", "--channel", "Security"])

    def test_rejected_ids_are_capped_in_text(self):
        _, output = self.ingest_poison([], range(1, 9))
        self.assertIn("record_id: 1, 2, 3, 4, 5, +3 more", output)

    def test_rejected_ids_at_the_cap_are_listed_without_more_suffix(self):
        _, output = self.ingest_poison([], range(1, 6))
        self.assertIn("record_id: 1, 2, 3, 4, 5", output)
        self.assertNotIn("more", output)

    def test_rejected_ids_are_complete_in_json(self):
        _, output = self.ingest_poison(["--json"], range(1, 9))
        ids = json.loads(output)["results"][0]["rejected_record_ids"]
        self.assertEqual(list(range(1, 9)), ids)

    def test_rejected_ids_are_sorted_even_when_read_out_of_order(self):
        _, output = self.ingest_poison(["--json"], [5, 2, 8])
        ids = json.loads(output)["results"][0]["rejected_record_ids"]
        self.assertEqual([2, 5, 8], ids)

    def ingest_file_with_one_reject(self, argv):
        events = [make_log_event(datetime(2026, 5, 9, 10, 0, 0), "a"),
                  make_log_event(datetime(2026, 5, 9, 10, 0, 1), "b")]
        normalized = [make_event(1), make_event(2, action=None)]
        with mock.patch.object(
            ingest_command, "ingest_file", return_value=(events, {"skipped": 0})
        ), mock.patch.object(
            ingest_command, "from_log_event", side_effect=normalized
        ):
            return self.run_cli(argv + ["ingest", "--file", "x.log"])

    def test_file_text_mode_warns_with_rejected_record_ids(self):
        code, output = self.ingest_file_with_one_reject([])
        self.assertEqual(3, code)  # one row did not make it
        self.assertIn("read 2, stored 1, skipped 1", output)
        self.assertIn("store rejected some events; rejected record_id: 2", output)

    def test_file_json_reports_total_inserted_and_rejected_ids(self):
        _, output = self.ingest_file_with_one_reject(["--json"])
        data = json.loads(output)
        self.assertEqual(1, data["total_inserted"])
        self.assertEqual([2], data["results"][0]["rejected_record_ids"])

    def test_wholly_unparseable_file_exits_3_not_0(self):
        events = [make_log_event(None, "a"), make_log_event(None, "b")]
        with mock.patch.object(
            ingest_command, "ingest_file", return_value=(events, {"skipped": 0})
        ):
            code, output = self.run_cli(["ingest", "--file", "x.log"])
        self.assertEqual(3, code)
        self.assertIn("read 2, stored 0, skipped 2", output)

    def test_a_clean_file_still_exits_0(self):
        code, _ = self.run_cli(["ingest", "--file", "samples/windows_security.log"])
        self.assertEqual(0, code)

    def test_exit_1_when_the_only_channel_is_not_found(self):
        with mock.patch.object(
            wel, "read_channel", side_effect=wel.ChannelNotFoundError("typo?")
        ):
            code, output = self.run_cli(["ingest", "--channel", "Securty"])
        self.assertEqual(1, code)
        self.assertIn("typo?", output)

    def test_exit_0_when_a_channel_is_not_found_but_another_is_read(self):
        def reader(channel, **kwargs):
            if channel == "Securty":
                raise wel.ChannelNotFoundError("typo?")
            return [events_xml.FAILED_LOGON_4625]

        with mock.patch.object(wel, "read_channel", side_effect=reader):
            code, output = self.run_cli(["ingest", "--channel", "Securty,System"])
        self.assertEqual(0, code)
        self.assertIn("typo?", output)  # still warned

    def test_file_json_on_missing_path_keeps_stdout_parseable(self):
        code, out, err = self.run_cli_split(
            ["--json", "ingest", "--file", "no/such/file.log"]
        )
        self.assertEqual(1, code)
        self.assertIn("error", json.loads(out)["results"][0])
        self.assertIn("File not found", err)

    def test_unknown_format_file_exits_1_and_json_stays_parseable(self):
        handle, path = tempfile.mkstemp(suffix=".log")
        os.close(handle)
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("hello world\nnothing to see here\n")
            code, _ = self.run_cli(["ingest", "--file", path])
            json_code, out, _err = self.run_cli_split(
                ["--json", "ingest", "--file", path]
            )
        finally:
            os.unlink(path)
        self.assertEqual(1, code)
        self.assertEqual(1, json_code)
        self.assertIn("error", json.loads(out)["results"][0])

    def test_invalid_channel_name_exits_2_with_message(self):
        code, output = self.run_cli(["ingest", "--channel", "/?"])
        self.assertEqual(2, code)
        self.assertIn("Invalid channel name", output)

    def test_missing_file_exits_nonzero(self):
        code, _ = self.run_cli(["ingest", "--file", "no/such/file.log"])
        self.assertEqual(1, code)

    def test_default_channel_is_security(self):
        seen = []

        def reader(channel, **kwargs):
            seen.append(channel)
            return []

        with mock.patch.object(wel, "read_channel", side_effect=reader):
            self.run_cli(["ingest"])
        self.assertEqual(["Security"], seen)


if __name__ == "__main__":
    unittest.main()

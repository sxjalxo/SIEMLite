import json
import unittest
from dataclasses import fields
from datetime import datetime, timedelta, timezone
from unittest import mock

from ingestion.normalizer import (
    EVENT_FIELDS,
    NormalizedEvent,
    _parse_system_time,
    parse_event_xml,
    split_events,
)
from tests.fixtures import events_xml


class TestNormalizedEvent(unittest.TestCase):
    def make(self, **kwargs):
        base = dict(
            timestamp=datetime(2026, 9, 29, 10, 0, 0),
            source_type="windows",
            host="WORKSTATION1",
            channel="Security",
            event_id=4625,
            record_id=143105,
        )
        base.update(kwargs)
        return NormalizedEvent(**base)

    def test_every_defaulted_field_has_its_pinned_default(self):
        expected = {
            "action": "OTHER", "severity_hint": "INFO",
            "user": "-", "target_user": "-", "source_ip": "-", "dest_ip": "-",
            "logon_type": 0,
            "process": "-", "process_id": 0, "parent_process": "-",
            "command_line": "-",
            "object_name": "-", "service_name": "-",
            "detail": "-", "raw": "", "metadata": {},
        }
        required = {"timestamp", "source_type", "host", "channel",
                    "event_id", "record_id"}
        # Every field is either required or pinned here, so a new field must
        # be added to this map deliberately.
        self.assertEqual(
            set(expected) | required, {f.name for f in fields(NormalizedEvent)}
        )
        event = self.make()
        for name, default in expected.items():
            with self.subTest(field=name):
                value = getattr(event, name)
                self.assertEqual(default, value)
                self.assertIs(type(default), type(value))

    def test_metadata_defaults_to_empty_dict_not_shared(self):
        first = self.make()
        second = self.make()
        first.metadata["x"] = 1
        self.assertEqual({}, second.metadata)

    def test_event_hash_differs_by_record_id(self):
        self.assertNotEqual(
            self.make(record_id=1).event_hash, self.make(record_id=2).event_hash
        )

    def test_event_hash_differs_by_host(self):
        self.assertNotEqual(
            self.make(host="A").event_hash, self.make(host="B").event_hash
        )

    def test_event_hash_differs_by_channel(self):
        self.assertNotEqual(
            self.make(channel="Security").event_hash,
            self.make(channel="System").event_hash,
        )

    def test_to_row_encodes_metadata_as_json(self):
        row = self.make(metadata={"privileges": ["SeDebugPrivilege"]}).to_row()
        self.assertEqual(
            {"privileges": ["SeDebugPrivilege"]}, json.loads(row["metadata"])
        )

    def test_to_row_includes_event_hash(self):
        row = self.make().to_row()
        self.assertEqual(self.make().event_hash, row["event_hash"])

    def test_round_trip_preserves_every_field(self):
        original = self.make(
            user="jsmith", target_user="admin", source_ip="10.0.0.15",
            dest_ip="10.0.0.99", logon_type=3, process="cmd.exe",
            process_id=420, parent_process="explorer.exe",
            command_line="cmd /c whoami", object_name=r"C:\x",
            service_name="svc", detail="d", raw="r", metadata={"a": 1},
            action="LOGIN_OK", severity_hint="LOW",
        )
        self.assertEqual(original, NormalizedEvent.from_row(original.to_row()))

    def test_to_row_timestamp_is_iso_string(self):
        self.assertEqual("2026-09-29 10:00:00", self.make().to_row()["timestamp"])

    def test_from_row_converts_aware_timestamp_to_local_naive(self):
        # UTC plus a fixed +05:30 offset: at least one always differs from the
        # machine's local offset, so a wall-clock strip cannot pass both.
        for stamp, tz in (
            ("2026-09-29 10:00:00+00:00", timezone.utc),
            ("2026-09-29 10:00:00+05:30", timezone(timedelta(hours=5, minutes=30))),
        ):
            row = self.make().to_row()
            row["timestamp"] = stamp
            expected = (
                datetime(2026, 9, 29, 10, 0, 0, tzinfo=tz)
                .astimezone()
                .replace(tzinfo=None)
            )
            self.assertEqual(expected, NormalizedEvent.from_row(row).timestamp, stamp)

    def test_event_hash_folds_in_raw_by_default(self):
        a = self.make(host="-", channel="apache", record_id=5, raw="line A")
        b = self.make(host="-", channel="apache", record_id=5, raw="line B")
        self.assertNotEqual(a.event_hash, b.event_hash)

    def test_event_hash_reingest_of_same_line_is_stable(self):
        a = self.make(host="-", channel="apache", record_id=5, raw="line A")
        b = self.make(host="-", channel="apache", record_id=5, raw="line A")
        self.assertEqual(a.event_hash, b.event_hash)

    def test_stable_record_id_event_hash_ignores_raw(self):
        a = self.make(raw="<Event> a </Event>", metadata={"stable_record_id": True})
        b = self.make(raw="<Event>a</Event>", metadata={"stable_record_id": True})
        self.assertEqual(a.event_hash, b.event_hash)

    def test_event_hash_delimiter_is_unambiguous(self):
        a = self.make(host="a|b", channel="c", record_id=5)
        b = self.make(host="a", channel="b|c", record_id=5)
        self.assertNotEqual(a.event_hash, b.event_hash)

    def test_event_fields_covers_flat_fields(self):
        for name in ("event_id", "source_ip", "target_user", "command_line",
                     "logon_type", "parent_process", "object_name", "service_name"):
            self.assertIn(name, EVENT_FIELDS)

    def test_event_fields_excludes_raw_and_metadata(self):
        self.assertNotIn("raw", EVENT_FIELDS)
        self.assertNotIn("metadata", EVENT_FIELDS)


class TestParseEventXml(unittest.TestCase):
    def test_extracts_event_id(self):
        self.assertEqual(7040, parse_event_xml(events_xml.SERVICE_7040)["event_id"])

    def test_extracts_event_id_without_qualifiers(self):
        self.assertEqual(
            4625, parse_event_xml(events_xml.FAILED_LOGON_4625)["event_id"]
        )

    def test_extracts_record_id(self):
        self.assertEqual(143105, parse_event_xml(events_xml.SERVICE_7040)["record_id"])

    def test_extracts_channel_and_host(self):
        parsed = parse_event_xml(events_xml.SERVICE_7040)
        self.assertEqual("System", parsed["channel"])
        self.assertEqual("LAPTOP-A4BLML0Q", parsed["host"])

    def test_extracts_provider(self):
        self.assertEqual(
            "Service Control Manager",
            parse_event_xml(events_xml.SERVICE_7040)["provider"],
        )

    def test_handles_seven_digit_fractional_seconds(self):
        # Smoke check only: Python 3.11+ accepts 7 digits natively, so this
        # cannot prove truncation. The strict-parser test below does.
        parsed = parse_event_xml(events_xml.SERVICE_7040)
        self.assertIsInstance(parsed["timestamp"], datetime)
        self.assertIsNone(parsed["timestamp"].tzinfo)

    def test_seven_digit_fraction_is_truncated_for_strict_parser(self):
        real = datetime.fromisoformat

        def strict(text):
            # Mimic Python 3.8-3.10: more than 6 fractional digits is rejected.
            frac = text.split(".", 1)[1] if "." in text else ""
            digits = ""
            for ch in frac:
                if not ch.isdigit():
                    break
                digits += ch
            if len(digits) > 6:
                raise ValueError("Invalid isoformat string: {!r}".format(text))
            return real(text)

        class StrictDatetime(datetime):
            fromisoformat = staticmethod(strict)

        with mock.patch("ingestion.normalizer.datetime", StrictDatetime):
            got = _parse_system_time("2026-10-01T19:17:07.6372592Z")
        expected = datetime(
            2026, 10, 1, 19, 17, 7, 637259, tzinfo=timezone.utc
        ).astimezone().replace(tzinfo=None)
        self.assertEqual(expected, got)

    def test_timestamp_is_converted_to_local(self):
        parsed = parse_event_xml(events_xml.FAILED_LOGON_4625)
        expected = datetime(
            2026, 5, 9, 10, 0, 1, 123456, tzinfo=timezone.utc
        ).astimezone().replace(tzinfo=None)
        self.assertEqual(expected, parsed["timestamp"])

    def test_extracts_event_data_by_name(self):
        data = parse_event_xml(events_xml.FAILED_LOGON_4625)["data"]
        self.assertEqual("administrator", data["TargetUserName"])
        self.assertEqual("203.0.113.50", data["IpAddress"])
        self.assertEqual("3", data["LogonType"])

    def test_extracts_userdata_element_names(self):
        data = parse_event_xml(events_xml.LOG_CLEARED_1102)["data"]
        self.assertEqual("administrator", data["SubjectUserName"])

    def test_rejects_non_event_xml(self):
        with self.assertRaises(ValueError) as ctx:
            parse_event_xml("<html><body>nope</body></html>")
        self.assertIn("Not a Windows Event record", str(ctx.exception))

    def test_rejects_event_without_system_section(self):
        with self.assertRaises(ValueError) as ctx:
            parse_event_xml("<Event/>")
        self.assertIn("Event XML has no <System> section", str(ctx.exception))

    def test_extracts_level(self):
        self.assertEqual(4, parse_event_xml(events_xml.SERVICE_7040)["level"])

    def test_parses_event_without_namespace(self):
        xml = events_xml.NO_NAMESPACE_4625
        self.assertNotIn("xmlns", xml)
        parsed = parse_event_xml(xml)
        self.assertEqual(4625, parsed["event_id"])
        self.assertEqual(500, parsed["record_id"])
        self.assertEqual("WORKSTATION1", parsed["host"])
        self.assertEqual("administrator", parsed["data"]["TargetUserName"])

    def test_fully_populated_record_parses(self):
        parsed = parse_event_xml(events_xml.SERVICE_7040)
        self.assertEqual(7040, parsed["event_id"])
        self.assertEqual(143105, parsed["record_id"])
        self.assertEqual("LAPTOP-A4BLML0Q", parsed["host"])
        self.assertIsInstance(parsed["timestamp"], datetime)

    def test_missing_or_empty_required_fields_raise(self):
        # Each required System field, as (name, element text to strip/empty).
        # A silent default would feed the dedup key and the forensic timeline.
        xml = events_xml.SERVICE_7040
        cases = {
            "SystemTime": (
                "<TimeCreated SystemTime='2026-09-29T17:43:30.7880600Z'/>",
                "<TimeCreated/>",
                "<TimeCreated SystemTime=''/>",
            ),
            "EventRecordID": (
                "<EventRecordID>143105</EventRecordID>",
                "",
                "<EventRecordID></EventRecordID>",
            ),
            "Computer": (
                "<Computer>LAPTOP-A4BLML0Q</Computer>",
                "",
                "<Computer></Computer>",
            ),
            "EventID": (
                "<EventID Qualifiers='16384'>7040</EventID>",
                "",
                "<EventID Qualifiers='16384'></EventID>",
            ),
        }
        for name, (original, *variants) in cases.items():
            self.assertIn(original, xml)
            for variant in variants:
                with self.subTest(field=name, variant=variant):
                    with self.assertRaises(ValueError) as ctx:
                        parse_event_xml(xml.replace(original, variant))
                    self.assertIn(
                        "Event XML has no {}".format(name), str(ctx.exception)
                    )

    def test_missing_time_created_element_raises(self):
        xml = events_xml.SERVICE_7040.replace(
            "<TimeCreated SystemTime='2026-09-29T17:43:30.7880600Z'/>", ""
        )
        with self.assertRaises(ValueError) as ctx:
            parse_event_xml(xml)
        self.assertIn("Event XML has no SystemTime", str(ctx.exception))

    def test_rejects_malformed_xml(self):
        with self.assertRaises(ValueError):
            parse_event_xml("<Event><System>")


class TestSplitEvents(unittest.TestCase):
    def test_splits_concatenated_dump(self):
        parts = split_events(events_xml.TWO_EVENTS_CONCATENATED)
        self.assertEqual(2, len(parts))
        self.assertEqual(7040, parse_event_xml(parts[0])["event_id"])
        self.assertEqual(4625, parse_event_xml(parts[1])["event_id"])

    def test_single_event(self):
        self.assertEqual(1, len(split_events(events_xml.SERVICE_7040)))

    def test_empty_blob(self):
        self.assertEqual([], split_events(""))

    def test_ignores_surrounding_whitespace_and_newlines(self):
        blob = "\n" + events_xml.SERVICE_7040 + "\r\n" + events_xml.FAILED_LOGON_4625
        self.assertEqual(2, len(split_events(blob)))

    def test_nested_event_element_does_not_truncate_record(self):
        parts = split_events(events_xml.NESTED_EVENT_ELEMENT_1015)
        self.assertEqual([events_xml.NESTED_EVENT_ELEMENT_1015], parts)
        parsed = parse_event_xml(parts[0])
        self.assertEqual(1015, parsed["event_id"])
        self.assertEqual("4", parsed["data"]["Event"])

    def test_nested_event_element_between_normal_events(self):
        blob = (
            events_xml.SERVICE_7040
            + events_xml.NESTED_EVENT_ELEMENT_1015
            + events_xml.FAILED_LOGON_4625
        )
        ids = [parse_event_xml(p)["event_id"] for p in split_events(blob)]
        self.assertEqual([7040, 1015, 4625], ids)

    def test_event_with_newline_in_data_value_is_one_record(self):
        parts = split_events(events_xml.MULTILINE_DATA)
        self.assertEqual(1, len(parts))
        data = parse_event_xml(parts[0])["data"]
        self.assertEqual("line one" + chr(10) + "line two" + chr(10) + "line three", data["Message"])

    def test_self_closing_event_is_returned_alongside_normal_event(self):
        blob = "<Event/>" + events_xml.SERVICE_7040
        parts = split_events(blob)
        self.assertEqual(["<Event/>", events_xml.SERVICE_7040], parts)

    def test_event_data_and_event_id_tags_are_not_event_boundaries(self):
        # <EventData> / <EventID> must not be mistaken for <Event>.
        self.assertEqual([], split_events("<EventData></EventData><EventID/>"))

    def test_stray_closing_tag_does_not_swallow_following_records(self):
        blob = "</Event>" + events_xml.SERVICE_7040 + events_xml.FAILED_LOGON_4625
        parts = split_events(blob)
        self.assertEqual(2, len(parts))
        self.assertEqual(
            [7040, 4625], [parse_event_xml(p)["event_id"] for p in parts]
        )

    def test_nested_self_closing_event_is_not_a_separate_record(self):
        record = events_xml.LOG_CLEARED_1102.replace(
            "<UserData>", "<UserData><Event/>"
        )
        self.assertIn("<Event/>", record)
        self.assertEqual([record], split_events(record))

    def test_records_keep_exact_whitespace(self):
        # CRLF, tabs and runs of spaces inside and between elements must come
        # back untouched: `raw` is stored for forensics and feeds the dedup hash.
        record = (
            events_xml.MULTILINE_DATA.replace(
                "line one\nline two", "line one\r\n\ttwo  \r\n  "
            )
            .replace("<EventData>", "<EventData>\n\t ")
            .replace("</EventData>", " \r\n</EventData>")
        )
        self.assertIn("\r\n\ttwo  \r\n  ", record)
        blob = "  \r\n" + record + "\t\r\n" + events_xml.SERVICE_7040
        parts = split_events(blob)
        self.assertEqual(2, len(parts))
        self.assertEqual(record, parts[0])

    def test_records_keep_exact_original_bytes(self):
        blob = "junk " + events_xml.MULTILINE_DATA + " junk"
        self.assertEqual([events_xml.MULTILINE_DATA], split_events(blob))


if __name__ == "__main__":
    unittest.main()

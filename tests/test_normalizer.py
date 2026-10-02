import json
import os
import tempfile
import unittest
from dataclasses import MISSING, fields
from datetime import datetime, timedelta, timezone
from unittest import mock

from core import store
from core.timeutil import to_local_naive
from ingestion.log_ingestor import LogEvent
from ingestion.normalizer import (
    EVENT_FIELDS,
    WINDOWS_ACTIONS,
    NormalizedEvent,
    _parse_system_time,
    from_log_event,
    normalize_windows_xml,
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


class TestNormalizeWindows(unittest.TestCase):
    def test_4625_maps_fields(self):
        event = normalize_windows_xml(events_xml.FAILED_LOGON_4625)
        self.assertEqual("LOGIN_FAIL", event.action)
        self.assertEqual("administrator", event.target_user)
        self.assertEqual("203.0.113.50", event.source_ip)
        self.assertEqual(3, event.logon_type)
        self.assertEqual("WORKSTATION1", event.host)
        self.assertEqual("Security", event.channel)
        self.assertEqual(500, event.record_id)

    def test_4625_keeps_status_in_metadata(self):
        event = normalize_windows_xml(events_xml.FAILED_LOGON_4625)
        self.assertEqual("0xc000006d", event.metadata["status"])
        self.assertEqual("KALI", event.metadata["workstation"])

    def test_4688_maps_process_fields(self):
        event = normalize_windows_xml(events_xml.PROCESS_4688)
        self.assertEqual("PROCESS_CREATE", event.action)
        self.assertEqual("backdoor_user", event.user)
        self.assertIn("powershell.exe", event.process)
        self.assertIn("cmd.exe", event.parent_process)
        self.assertEqual("powershell -enc SQBFAFgA", event.command_line)

    def test_4688_converts_hex_process_id(self):
        event = normalize_windows_xml(events_xml.PROCESS_4688)
        self.assertEqual(0x1A4, event.process_id)

    def test_1102_maps_from_userdata(self):
        event = normalize_windows_xml(events_xml.LOG_CLEARED_1102)
        self.assertEqual("LOG_CLEARED", event.action)
        self.assertEqual("administrator", event.user)

    def test_unmapped_event_id_still_normalizes(self):
        event = normalize_windows_xml(events_xml.SERVICE_7040)
        self.assertEqual("OTHER", event.action)
        self.assertEqual(7040, event.event_id)
        self.assertEqual("System", event.channel)

    def test_unmapped_data_preserved_in_metadata(self):
        event = normalize_windows_xml(events_xml.SERVICE_7040)
        self.assertEqual("IsolationSession", event.metadata["param1"])

    def test_raw_xml_retained(self):
        event = normalize_windows_xml(events_xml.FAILED_LOGON_4625)
        self.assertIn("<EventID>4625</EventID>", event.raw)

    def test_source_type_is_windows(self):
        self.assertEqual(
            "windows", normalize_windows_xml(events_xml.SERVICE_7040).source_type
        )

    def test_detail_is_populated(self):
        event = normalize_windows_xml(events_xml.FAILED_LOGON_4625)
        self.assertNotEqual("-", event.detail)
        self.assertIn("administrator", event.detail)

    def test_loopback_ip_normalizes_to_local(self):
        xml_text = events_xml.FAILED_LOGON_4625.replace("203.0.113.50", "::1")
        self.assertEqual("local", normalize_windows_xml(xml_text).source_ip)

    def test_dash_ip_normalizes_to_local(self):
        xml_text = events_xml.FAILED_LOGON_4625.replace(
            "<Data Name='IpAddress'>203.0.113.50</Data>",
            "<Data Name='IpAddress'>-</Data>",
        )
        self.assertEqual("local", normalize_windows_xml(xml_text).source_ip)

    def test_every_local_ip_spelling_normalizes_to_local(self):
        for spelling in ("127.0.0.1", "0.0.0.0", "", "localhost", "LOCALHOST"):
            xml_text = events_xml.FAILED_LOGON_4625.replace(
                "<Data Name='IpAddress'>203.0.113.50</Data>",
                "<Data Name='IpAddress'>{}</Data>".format(spelling),
            )
            self.assertEqual(
                "local", normalize_windows_xml(xml_text).source_ip, spelling
            )

    def test_sysmon_id_only_applies_on_sysmon_channel(self):
        xml_text = events_xml.SERVICE_7040.replace(
            "<EventID Qualifiers='16384'>7040</EventID>", "<EventID>1</EventID>"
        )
        self.assertEqual("OTHER", normalize_windows_xml(xml_text).action)

    def test_sysmon_id_applies_on_sysmon_channel_any_case(self):
        xml_text = events_xml.SERVICE_7040.replace(
            "<EventID Qualifiers='16384'>7040</EventID>", "<EventID>1</EventID>"
        ).replace(
            "<Channel>System</Channel>",
            "<Channel>Microsoft-Windows-SYSMON/Operational</Channel>",
        )
        event = normalize_windows_xml(xml_text)
        self.assertEqual("PROCESS_CREATE", event.action)

    def test_4624_sets_user_and_target_user_to_same_account(self):
        xml_text = events_xml.FAILED_LOGON_4625.replace(
            "<EventID>4625</EventID>", "<EventID>4624</EventID>"
        )
        event = normalize_windows_xml(xml_text)
        self.assertEqual("LOGIN_OK", event.action)
        self.assertEqual("administrator", event.user)
        self.assertEqual("administrator", event.target_user)

    def test_action_table_covers_core_ids(self):
        for event_id in (4624, 4625, 4672, 4688, 4720, 4728, 4732, 4740,
                         4776, 4698, 1102, 7045, 4104, 5140):
            self.assertIn(event_id, WINDOWS_ACTIONS)

    def test_normalized_event_is_storable(self):
        event = normalize_windows_xml(events_xml.FAILED_LOGON_4625)
        row = event.to_row()
        self.assertEqual(event.event_hash, row["event_hash"])

    def test_windows_event_sets_stable_record_id_flag(self):
        event = normalize_windows_xml(events_xml.FAILED_LOGON_4625)
        self.assertIs(True, event.metadata["stable_record_id"])

    def test_events_differing_only_in_raw_hash_identically(self):
        a = normalize_windows_xml(events_xml.FAILED_LOGON_4625)
        b = normalize_windows_xml(events_xml.FAILED_LOGON_4625 + "  ")
        self.assertNotEqual(a.raw, b.raw)
        self.assertEqual(a.event_hash, b.event_hash)

    def test_eventdata_cannot_set_reserved_control_flag(self):
        xml_text = events_xml.FAILED_LOGON_4625.replace(
            "</EventData>", "<Data Name='stable_record_id'>1</Data></EventData>"
        )
        event = normalize_windows_xml(xml_text)
        self.assertIs(True, event.metadata["stable_record_id"])
        self.assertEqual("1", event.metadata["eventdata_stable_record_id"])

    def test_eventdata_cannot_set_flag_on_unmapped_event(self):
        xml_text = events_xml.SERVICE_7040.replace(
            "</EventData>", "<Data Name='stable_record_id'>0</Data></EventData>"
        )
        event = normalize_windows_xml(xml_text)
        self.assertIs(True, event.metadata["stable_record_id"])
        self.assertEqual("0", event.metadata["eventdata_stable_record_id"])


_PS_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
_SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# One row per EventID: (event_id, channel, action, {source key: destination}).
# A destination is a flat field name, "a,b" for several fields, or
# "metadata.<name>". Each source key gets a unique sentinel value in the test,
# so a missing, swapped or mistargeted mapping cannot pass by coincidence.
MAPPING_TABLE = [
    (4624, "Security", "LOGIN_OK",
     {"TargetUserName": "user,target_user", "IpAddress": "source_ip",
      "LogonType": "logon_type", "ProcessName": "process"}),
    (4625, "Security", "LOGIN_FAIL",
     {"TargetUserName": "target_user", "SubjectUserName": "user",
      "IpAddress": "source_ip", "LogonType": "logon_type",
      "Status": "metadata.status", "SubStatus": "metadata.sub_status",
      "WorkstationName": "metadata.workstation"}),
    (4634, "Security", "LOGOFF",
     {"TargetUserName": "user", "LogonType": "logon_type"}),
    (4672, "Security", "PRIVILEGE_ASSIGN",
     {"SubjectUserName": "user", "PrivilegeList": "metadata.privileges"}),
    (4688, "Security", "PROCESS_CREATE",
     {"SubjectUserName": "user", "NewProcessName": "process",
      "ParentProcessName": "parent_process", "CommandLine": "command_line",
      "NewProcessId": "process_id"}),
    (4689, "Security", "PROCESS_EXIT",
     {"SubjectUserName": "user", "ProcessName": "process"}),
    (4720, "Security", "ACCOUNT_CREATE",
     {"SubjectUserName": "user", "TargetUserName": "target_user"}),
    (4722, "Security", "ACCOUNT_ENABLE",
     {"SubjectUserName": "user", "TargetUserName": "target_user"}),
    (4724, "Security", "PASSWORD_RESET",
     {"SubjectUserName": "user", "TargetUserName": "target_user"}),
    (4728, "Security", "GROUP_ADD_GLOBAL",
     {"SubjectUserName": "user", "MemberName": "target_user",
      "TargetUserName": "object_name"}),
    (4732, "Security", "GROUP_ADD_LOCAL",
     {"SubjectUserName": "user", "MemberName": "target_user",
      "TargetUserName": "object_name"}),
    (4740, "Security", "ACCOUNT_LOCKOUT",
     {"TargetUserName": "target_user", "TargetDomainName": "object_name"}),
    (4776, "Security", "NTLM_VALIDATE",
     {"TargetUserName": "target_user", "Workstation": "object_name",
      "Status": "metadata.status"}),
    (4698, "Security", "TASK_CREATE",
     {"SubjectUserName": "user", "TaskName": "object_name"}),
    (1102, "Security", "LOG_CLEARED", {"SubjectUserName": "user"}),
    (7045, "System", "SERVICE_INSTALL",
     {"AccountName": "user", "ServiceName": "service_name",
      "ImagePath": "process", "StartType": "metadata.start_type"}),
    (4104, _PS_CHANNEL, "SCRIPTBLOCK",
     {"ScriptBlockText": "command_line", "Path": "object_name"}),
    (5140, "Security", "SHARE_ACCESS",
     {"SubjectUserName": "user", "IpAddress": "source_ip",
      "ShareName": "object_name"}),
    (1, _SYSMON_CHANNEL, "PROCESS_CREATE",
     {"User": "user", "Image": "process", "ParentImage": "parent_process",
      "CommandLine": "command_line", "ProcessId": "process_id"}),
    (3, _SYSMON_CHANNEL, "NETWORK_CONNECT",
     {"User": "user", "Image": "process", "SourceIp": "source_ip",
      "DestinationIp": "dest_ip", "DestinationPort": "metadata.dest_port"}),
    (11, _SYSMON_CHANNEL, "FILE_CREATE",
     {"User": "user", "Image": "process", "TargetFilename": "object_name"}),
]

# Only these actions carry a severity hint; every other action is INFO.
_EXPECTED_SEVERITY = {
    "LOGIN_FAIL": "LOW",
    "ACCOUNT_CREATE": "MEDIUM",
    "GROUP_ADD_GLOBAL": "MEDIUM",
    "GROUP_ADD_LOCAL": "MEDIUM",
    "PRIVILEGE_ASSIGN": "MEDIUM",
    "LOG_CLEARED": "HIGH",
    "SERVICE_INSTALL": "MEDIUM",
    "TASK_CREATE": "MEDIUM",
}

# Source keys that are not stored verbatim: key -> (input text, expected value).
_TYPED_INPUTS = {
    "LogonType": ("3", 3),
    "NewProcessId": ("0x1a4", 0x1A4),
    "ProcessId": ("1234", 1234),
    "PrivilegeList": ("SENTINEL_P1 SENTINEL_P2", ["SENTINEL_P1", "SENTINEL_P2"]),
}


def _event_xml(event_id, channel, data=None):
    items = "".join(
        "<Data Name='{}'>{}</Data>".format(k, v) for k, v in (data or {}).items()
    )
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><Provider Name='Test'/><EventID>{}</EventID>"
        "<TimeCreated SystemTime='2026-05-09T10:00:00.000000Z'/>"
        "<EventRecordID>7</EventRecordID><Channel>{}</Channel>"
        "<Computer>HOST1</Computer></System><EventData>{}</EventData></Event>"
    ).format(event_id, channel, items)


class TestFieldMaps(unittest.TestCase):
    def test_every_source_key_lands_in_its_field(self):
        defaults = {
            f.name: f.default for f in fields(NormalizedEvent)
            if f.default is not MISSING
        }
        # Every Security ID is also valid on ForwardedEvents (WEF).
        cases = [
            (event_id, ch, action, mapping)
            for event_id, channel, action, mapping in MAPPING_TABLE
            for ch in ([channel, "ForwardedEvents"] if channel == "Security"
                       else [channel])
        ]
        for event_id, channel, action, mapping in cases:
            with self.subTest(event_id=event_id, channel=channel):
                data, flat, meta = {}, {}, {}
                for src, dest in mapping.items():
                    text, value = _TYPED_INPUTS.get(
                        src, ("SENTINEL_" + src, "SENTINEL_" + src)
                    )
                    data[src] = text
                    for name in dest.split(","):
                        if name.startswith("metadata."):
                            meta[name[len("metadata."):]] = value
                        else:
                            flat[name] = value
                event = normalize_windows_xml(_event_xml(event_id, channel, data))
                self.assertEqual(action, event.action)
                self.assertEqual(
                    _EXPECTED_SEVERITY.get(action, "INFO"), event.severity_hint
                )
                for name, value in flat.items():
                    self.assertEqual(value, getattr(event, name), name)
                for name, value in meta.items():
                    self.assertEqual(value, event.metadata[name], name)
                # Nothing else is touched, and claimed keys are not duplicated
                # into metadata.
                for name in EVENT_FIELDS:
                    if name in defaults and name not in flat and name not in (
                        "action", "severity_hint", "detail"
                    ):
                        self.assertEqual(defaults[name], getattr(event, name), name)
                for src in data:
                    self.assertNotIn(src, event.metadata)

    def test_action_table_and_channel_rules_cannot_drift(self):
        # Every action-table ID must be interpreted on the channel it belongs
        # to; adding an ID to WINDOWS_ACTIONS alone must not go silently dead.
        for event_id, action in WINDOWS_ACTIONS.items():
            channel = {7045: "System", 4104: _PS_CHANNEL}.get(event_id, "Security")
            with self.subTest(event_id=event_id, channel=channel):
                event = normalize_windows_xml(_event_xml(event_id, channel))
                self.assertEqual(action, event.action)


class TestDerivedValues(unittest.TestCase):
    def test_hostile_eventdata_cannot_overwrite_derived_metadata(self):
        xml_text = events_xml.FAILED_LOGON_4625.replace(
            "</EventData>",
            "<Data Name='status'>HOSTILE</Data>"
            "<Data Name='provider'>HOSTILE</Data></EventData>",
        )
        event = normalize_windows_xml(xml_text)
        self.assertEqual("0xc000006d", event.metadata["status"])
        self.assertEqual(
            "Microsoft-Windows-Security-Auditing", event.metadata["provider"]
        )

    def test_hostile_eventdata_cannot_overwrite_privileges(self):
        xml_text = _event_xml(
            4672, "Security",
            {"SubjectUserName": "bob", "PrivilegeList": "SeDebugPrivilege",
             "privileges": "HOSTILE"},
        )
        self.assertEqual(
            ["SeDebugPrivilege"], normalize_windows_xml(xml_text).metadata["privileges"]
        )

    def test_severity_hints(self):
        self.assertEqual(
            "HIGH", normalize_windows_xml(events_xml.LOG_CLEARED_1102).severity_hint
        )
        self.assertEqual(
            "LOW", normalize_windows_xml(events_xml.FAILED_LOGON_4625).severity_hint
        )

    def test_sysmon_network_loopback_ips_normalize_to_local(self):
        event = normalize_windows_xml(_event_xml(
            3, _SYSMON_CHANNEL,
            {"SourceIp": "::1", "DestinationIp": "127.0.0.1"},
        ))
        self.assertEqual("local", event.source_ip)
        self.assertEqual("local", event.dest_ip)
        # An empty peer address is the same statement as a loopback one.
        event = normalize_windows_xml(_event_xml(
            3, _SYSMON_CHANNEL, {"SourceIp": "", "DestinationIp": ""}
        ))
        self.assertEqual("local", event.source_ip)
        self.assertEqual("local", event.dest_ip)

    def test_timestamp_is_the_local_naive_system_time(self):
        expected = datetime(
            2026, 5, 9, 10, 0, 1, 123456, tzinfo=timezone.utc
        ).astimezone().replace(tzinfo=None)
        event = normalize_windows_xml(events_xml.FAILED_LOGON_4625)
        self.assertEqual(expected, event.timestamp)


class TestChannelGating(unittest.TestCase):
    def test_every_mapped_id_is_other_on_application_but_keeps_data(self):
        for event_id, _channel, _action, mapping in MAPPING_TABLE:
            with self.subTest(event_id=event_id):
                data = {src: "SENTINEL_" + src for src in mapping}
                event = normalize_windows_xml(
                    _event_xml(event_id, "Application", data)
                )
                self.assertEqual("OTHER", event.action)
                self.assertEqual("INFO", event.severity_hint)
                self.assertEqual("-", event.user)
                for src, value in data.items():
                    self.assertEqual(value, event.metadata[src])

    def test_allowed_and_denied_channels(self):
        allowed = [
            (4688, "Security"), (4688, "ForwardedEvents"), (1102, "Security"),
            (7045, "System"), (4104, _PS_CHANNEL), (4104, "PowerShell"),
            (4104, "windows powershell"), (1, _SYSMON_CHANNEL),
            (11, "sysmon"),
        ]
        denied = [
            (4688, "System"), (4688, "Application"), (4688, "Security-Evil"),
            (4688, "Microsoft-Windows-Security-Auditing"),
            (7045, "Security"), (7045, "Application"), (7045, "ForwardedEvents"),
            (4104, "Security"), (4104, "Application"),
            (4624, _SYSMON_CHANNEL), (1, "Security"), (3, "Application"),
        ]
        for event_id, channel in allowed:
            with self.subTest(event_id=event_id, channel=channel):
                event = normalize_windows_xml(_event_xml(event_id, channel))
                self.assertNotEqual("OTHER", event.action)
        for event_id, channel in denied:
            with self.subTest(event_id=event_id, channel=channel):
                event = normalize_windows_xml(_event_xml(event_id, channel))
                self.assertEqual("OTHER", event.action)

    def test_forged_security_ids_on_application_do_not_become_detections(self):
        cases = (
            (events_xml.FAILED_LOGON_4625, "LOGIN_FAIL", "TargetUserName"),
            (events_xml.LOG_CLEARED_1102, "LOG_CLEARED", "SubjectUserName"),
            (_event_xml(4720, "Security", {"TargetUserName": "bob"}),
             "ACCOUNT_CREATE", "TargetUserName"),
        )
        for xml_text, real_action, key in cases:
            forged = xml_text.replace(
                "<Channel>Security</Channel>", "<Channel>Application</Channel>"
            )
            with self.subTest(real_action=real_action):
                self.assertEqual(real_action, normalize_windows_xml(xml_text).action)
                event = normalize_windows_xml(forged)
                self.assertEqual("OTHER", event.action)
                self.assertEqual("INFO", event.severity_hint)
                self.assertIn(key, event.metadata)


class TestDetailSanitized(unittest.TestCase):
    PAYLOADS = {
        "LF": "&#10;",
        "CR": "&#13;",
        "LINE SEPARATOR": "&#x2028;",
        "NEL": "&#x85;",
        "bidi RLO": "&#x202e;",
        "tab": "&#9;",
    }

    def test_detail_has_no_nonprintable_character(self):
        for name, ref in self.PAYLOADS.items():
            xml_text = events_xml.PROCESS_4688.replace(
                "powershell -enc SQBFAFgA", "calc" + ref + "2026-10-02 FAKE ROW"
            )
            with self.subTest(payload=name):
                event = normalize_windows_xml(xml_text)
                bad = [c for c in event.detail if not c.isprintable()]
                self.assertEqual([], bad)
                self.assertIn("FAKE ROW", event.detail)
                # The flat field and raw keep the original characters.
                self.assertFalse(event.command_line.isprintable())

    def test_detail_cap_applies_after_sanitizing(self):
        xml_text = events_xml.PROCESS_4688.replace(
            "powershell -enc SQBFAFgA", "x&#10;" * 500
        )
        detail = normalize_windows_xml(xml_text).detail
        self.assertEqual(400, len(detail))
        self.assertTrue(detail.isprintable())


class TestLegacyAdapter(unittest.TestCase):
    def make_log_event(self, **kwargs):
        base = dict(
            timestamp=datetime(2026, 5, 9, 10, 0, 1),
            source_type="apache",
            source_ip="203.0.113.50",
            user="-",
            action="REQUEST",
            detail="/admin/login",
            status_code=401,
            raw_line='203.0.113.50 - - [09/May/2026:10:00:01] "GET /admin/login"',
            metadata={},
        )
        base.update(kwargs)
        return LogEvent(**base)

    def test_maps_core_fields(self):
        event = from_log_event(self.make_log_event(), line_number=7)
        self.assertEqual("apache", event.source_type)
        self.assertEqual("203.0.113.50", event.source_ip)
        self.assertEqual("REQUEST", event.action)
        self.assertEqual(401, event.event_id)
        self.assertEqual(7, event.record_id)

    def test_windows_csv_computer_becomes_host(self):
        event = from_log_event(
            self.make_log_event(source_type="windows",
                                metadata={"computer": "WORKSTATION1"}),
            line_number=1,
        )
        self.assertEqual("WORKSTATION1", event.host)

    def test_windows_csv_gets_its_own_channel(self):
        event = from_log_event(
            self.make_log_event(source_type="windows", metadata={}), line_number=1
        )
        self.assertEqual("windows-csv", event.channel)

    def test_command_line_lifted_from_metadata(self):
        event = from_log_event(
            self.make_log_event(source_type="windows",
                                metadata={"command_line": "cmd.exe /c net user",
                                          "process": "cmd.exe"}),
            line_number=2,
        )
        self.assertEqual("cmd.exe /c net user", event.command_line)
        self.assertEqual("cmd.exe", event.process)

    def test_raw_line_preserved(self):
        event = from_log_event(self.make_log_event(), line_number=1)
        self.assertIn("GET /admin/login", event.raw)

    def test_produces_storable_event(self):
        event = from_log_event(self.make_log_event(), line_number=1)
        self.assertEqual(64, len(event.event_hash))

    def test_distinct_lines_get_distinct_hashes(self):
        first = from_log_event(self.make_log_event(), line_number=1)
        second = from_log_event(self.make_log_event(), line_number=2)
        self.assertNotEqual(first.event_hash, second.event_hash)

    def test_same_line_number_different_content_gets_distinct_hashes(self):
        # Two files, same ordinal, same host/channel: only the raw digest in
        # the key keeps them apart. Fails if stable_record_id were ever set.
        first = from_log_event(self.make_log_event(raw_line="file A line"),
                               line_number=5)
        second = from_log_event(self.make_log_event(raw_line="file B line"),
                                line_number=5)
        self.assertEqual((first.host, first.channel, first.record_id),
                         (second.host, second.channel, second.record_id))
        self.assertNotEqual(first.event_hash, second.event_hash)

    def test_same_input_same_hash_so_reingest_is_idempotent(self):
        first = from_log_event(self.make_log_event(), line_number=5)
        second = from_log_event(self.make_log_event(), line_number=5)
        self.assertEqual(first.event_hash, second.event_hash)

    def test_never_sets_stable_record_id(self):
        event = from_log_event(self.make_log_event(), line_number=5)
        self.assertNotIn("stable_record_id", event.metadata)

    def test_legacy_metadata_cannot_smuggle_stable_record_id(self):
        event = from_log_event(
            self.make_log_event(metadata={"stable_record_id": True}), line_number=5
        )
        self.assertNotIn("stable_record_id", event.metadata)
        self.assertIs(True, event.metadata["legacy_stable_record_id"])

    def test_does_not_mutate_input_metadata(self):
        meta = {"stable_record_id": True, "computer": "H1"}
        from_log_event(self.make_log_event(metadata=meta), line_number=1)
        self.assertEqual({"stable_record_id": True, "computer": "H1"}, meta)

    def test_none_fields_fall_back_to_schema_defaults(self):
        event = from_log_event(
            self.make_log_event(source_ip=None, user=None, detail=None,
                                raw_line=None, metadata=None, status_code=None,
                                action=None),
            line_number=3,
        )
        self.assertEqual("local", event.source_ip)
        self.assertEqual("-", event.user)
        self.assertEqual("-", event.detail)
        self.assertEqual("", event.raw)
        self.assertEqual({}, event.metadata)
        self.assertEqual("-", event.host)
        self.assertEqual(0, event.event_id)
        self.assertEqual("OTHER", event.action)
        self.assertEqual(64, len(event.event_hash))
        self.assertIn("timestamp", event.to_row())

    def test_each_none_field_alone_does_not_raise(self):
        for name in ("source_ip", "user", "detail", "raw_line", "metadata",
                     "status_code", "action"):
            with self.subTest(field=name):
                from_log_event(self.make_log_event(**{name: None}), line_number=1)

    def test_none_timestamp_raises_clear_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            from_log_event(self.make_log_event(timestamp=None), line_number=42)
        self.assertIn("timestamp", str(ctx.exception))
        self.assertIn("42", str(ctx.exception))

    def test_detail_control_characters_stripped_and_capped(self):
        event = from_log_event(
            self.make_log_event(detail="a" + chr(10) + "FAKE ROW" + "x" * 500), line_number=1
        )
        self.assertTrue(event.detail.isprintable())
        self.assertEqual(400, len(event.detail))

    def test_aware_timestamp_becomes_local_naive(self):
        aware = datetime(2026, 5, 9, 10, 0, 1, tzinfo=timezone.utc)
        event = from_log_event(self.make_log_event(timestamp=aware), line_number=1)
        self.assertIsNone(event.timestamp.tzinfo)
        self.assertEqual(to_local_naive(aware), event.timestamp)
        self.assertNotIn("+", event.to_row()["timestamp"])

    def test_out_of_range_aware_timestamp_raises_value_error_with_line(self):
        # to_local_naive raises OSError / OverflowError on these; a single
        # exception type keeps the caller's per-record handler simple.
        cases = {
            "pre-1970": datetime(1960, 1, 1, tzinfo=timezone.utc),
            "year 1": datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=1))),
            "year 9999": datetime(9999, 12, 31, tzinfo=timezone(timedelta(hours=-1))),
        }
        for name, bad in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(ValueError) as ctx:
                    from_log_event(self.make_log_event(timestamp=bad),
                                   line_number=42)
                self.assertIn("timestamp", str(ctx.exception))
                self.assertIn("42", str(ctx.exception))

    def test_naive_timestamp_passes_through_unchanged(self):
        naive = datetime(2026, 5, 9, 10, 0, 1)
        event = from_log_event(self.make_log_event(timestamp=naive), line_number=1)
        self.assertEqual(naive, event.timestamp)

    def test_stored_apache_event_found_by_since_query(self):
        # parse_apache emits tz-aware timestamps. Stored un-normalised they
        # sort as '...+00:00' strings and a since= cutoff silently matches nothing.
        aware = datetime(2026, 5, 9, 10, 0, 1, tzinfo=timezone.utc)
        local = to_local_naive(aware)
        handle, path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        conn = store.connect(path)
        try:
            store.init_schema(conn)
            store.insert_events(conn, [
                from_log_event(self.make_log_event(timestamp=aware), line_number=1)
            ])
            stored = conn.execute("SELECT timestamp FROM events").fetchone()[0]
            self.assertEqual(local.isoformat(sep=" "), stored)
            self.assertNotIn("+", stored)
            self.assertNotIn("Z", stored)
            self.assertNotRegex(stored, r"-\d\d:\d\d$")
            found = store.query_events(conn, since=local - timedelta(hours=1))
            self.assertEqual(1, len(found))
            self.assertEqual(local, found[0].timestamp)
            self.assertEqual(
                [], store.query_events(conn, since=local + timedelta(hours=1))
            )
        finally:
            conn.close()
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.unlink(path + suffix)
                except OSError:
                    pass

    def test_metadata_event_id_wins_over_status_code(self):
        event = from_log_event(
            self.make_log_event(status_code=401, metadata={"event_id": 4625}),
            line_number=1,
        )
        self.assertEqual(4625, event.event_id)

    def test_new_account_becomes_target_user_not_user(self):
        event = from_log_event(
            self.make_log_event(user="admin", metadata={"new_account": "backdoor"}),
            line_number=1,
        )
        self.assertEqual("backdoor", event.target_user)
        self.assertEqual("admin", event.user)

    def test_ssh_metadata_host_becomes_host(self):
        event = from_log_event(
            self.make_log_event(source_type="ssh", metadata={"host": "web01"}),
            line_number=1,
        )
        self.assertEqual("web01", event.host)

    def test_computer_wins_over_host(self):
        event = from_log_event(
            self.make_log_event(metadata={"computer": "WS1", "host": "web01"}),
            line_number=1,
        )
        self.assertEqual("WS1", event.host)

    def test_junk_ids_become_zero_instead_of_raising(self):
        event = from_log_event(
            self.make_log_event(metadata={"event_id": "junk"}), line_number="junk"
        )
        self.assertEqual(0, event.event_id)
        self.assertEqual(0, event.record_id)

    def test_hex_event_id_parsed(self):
        event = from_log_event(
            self.make_log_event(metadata={"event_id": "0x1a4"}), line_number="0x10"
        )
        self.assertEqual(0x1a4, event.event_id)
        self.assertEqual(16, event.record_id)

    def test_severity_hint_follows_action(self):
        event = from_log_event(self.make_log_event(action="LOG_CLEARED"), line_number=1)
        self.assertEqual("HIGH", event.severity_hint)
        event = from_log_event(self.make_log_event(action="LOGIN_FAIL"), line_number=1)
        self.assertEqual("LOW", event.severity_hint)


if __name__ == "__main__":
    unittest.main()

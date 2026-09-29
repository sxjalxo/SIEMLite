import json
import unittest
from dataclasses import fields
from datetime import datetime, timedelta, timezone

from ingestion.normalizer import EVENT_FIELDS, NormalizedEvent


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


if __name__ == "__main__":
    unittest.main()

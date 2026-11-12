import io
import json
import re
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

import cli
from cli.commands import incidents as incidents_command
from core import store
from core.correlator import correlate
from tests import helpers_rules
from tests.helpers_rules import T0, sample_alert
from tests.test_cli_alerts import ANSI, rule_ids, table
from tests.test_cli_ingest import IngestTestCase

LIST_ROW = re.compile(r"\s*\d+\s{2,}(?:CRITICAL|HIGH|MEDIUM|LOW|INFO) ")
EVENT_ROW = re.compile(r"\s*\d{4}-\d\d-\d\d \d\d:\d\d:\d\d  ")


def incident_rows(out):
    """The list rows as columns: id, severity, score, status, type, entity,
    last seen, tactics, title. Anchoring to a column is what lets a test say
    "PC-01 is not listed" without a stray "PC-01" in a title satisfying it."""
    lines = (ANSI.sub("", line) for line in out.splitlines())
    return [re.split(r"\s{2,}", line.strip(), maxsplit=8)
            for line in lines if LIST_ROW.match(line)]


def sections(out):
    """`show` output as {section title: body lines}, ANSI removed."""
    pieces = re.split(r"\n─{60}\n  >>>  ", ANSI.sub("", out))
    return {p.split("\n", 1)[0]: p.split("\n")[2:] for p in pieces[1:]}


def header(out):
    """The `Key : value` lines of the incident header as a dict."""
    found = {}
    for line in ANSI.sub("", out).splitlines():
        match = re.match(r"\s*\[~\] (\w[\w ]*?)\s*: (.*)$", line)
        if match:
            found[match.group(1)] = match.group(2)
    return found


def event_rows(out):
    body = next(v for k, v in sections(out).items() if k.startswith("Events"))
    return [re.split(r"\s{2,}", line.strip(), maxsplit=4)
            for line in body if EVENT_ROW.match(line)]


class IncidentsCase(IngestTestCase):
    def seed(self):
        """Two incidents. The CRITICAL one has the LOWER id and the OLDER
        last_seen, so only the score can put it first: ordering by last_seen
        or by id would list 1.2.3.4 first."""
        correlate(self.conn, [
            sample_alert(rule_id="r2", rule_title="Audit Log Cleared",
                         severity="CRITICAL", entity_value="PC-01",
                         entity_type="host", tactic="TA0005", timestamp=T0),
            sample_alert(rule_id="r1", rule_title="Failed Logon Burst",
                         severity="HIGH", entity_value="1.2.3.4",
                         tactic="TA0006", timestamp=T0 + timedelta(minutes=5)),
        ])

    def seed_by_age(self):
        """One stale incident and one current one, both HIGH. Relative to the
        clock: idleness is measured against datetime.now()."""
        now = datetime.now()
        correlate(self.conn, [
            sample_alert(rule_id="r1", entity_value="STALE",
                         timestamp=now - timedelta(days=3)),
            sample_alert(rule_id="r1", entity_value="FRESH",
                         event_hashes=("cc",), timestamp=now - timedelta(minutes=5)),
        ])

    def ids(self):
        return {r["entity_value"]: r["id"] for r in store.query_incidents(self.conn)}

    def statuses(self):
        return {r["entity_value"]: r["status"] for r in store.query_incidents(self.conn)}


class TestIncidentsList(IncidentsCase):
    def test_listing_shows_both_incidents_by_entity(self):
        self.seed()
        code, out = self.run_cli(["incidents"])
        self.assertEqual(0, code)
        self.assertEqual({"PC-01", "1.2.3.4"}, {row[5] for row in incident_rows(out)})

    def test_the_columns(self):
        self.seed()
        _, out = self.run_cli(["incidents"])
        first, second = incident_rows(out)
        self.assertEqual(["CRITICAL", "OPEN", "host", "PC-01"],
                         [first[1], first[3], first[4], first[5]])
        self.assertEqual(["HIGH", "OPEN", "ip", "1.2.3.4"],
                         [second[1], second[3], second[4], second[5]])
        self.assertEqual("2026-10-03 12:05:00", second[6])
        self.assertEqual("Failed Logon Burst on 1.2.3.4", second[8])

    def test_highest_score_first(self):
        self.seed()
        _, out = self.run_cli(["incidents"])
        self.assertEqual(["PC-01", "1.2.3.4"], [r[5] for r in incident_rows(out)],
                         "CRITICAL scores above HIGH, so it ranks first even "
                         "though it is older and has the lower id")

    def test_top_limits_the_list_and_says_how_many_it_hid(self):
        self.seed()
        _, out = self.run_cli(["incidents", "--top", "1"])
        self.assertEqual(["PC-01"], [r[5] for r in incident_rows(out)])
        self.assertIn("Incidents (showing 1 of 2)", ANSI.sub("", out))

    def test_the_default_top_is_20(self):
        for i in range(22):
            store.open_incident(self.conn, T0, T0, "host", "H{}".format(i), "LOW")
        _, out = self.run_cli(["incidents"])
        self.assertEqual(20, len(incident_rows(out)))
        self.assertIn("Incidents (showing 20 of 22)", ANSI.sub("", out))

    def test_the_list_column_is_labelled_as_the_first_alert(self):
        self.seed()
        _, out = self.run_cli(["incidents"])
        self.assertIn("FIRST ALERT", out)
        self.assertNotIn("TITLE", out)

    def test_json_is_not_capped_by_default(self):
        # As in `alerts`: a script that reads JSON must not get the first 20
        # without noticing. --top still applies when given (next test).
        for i in range(22):
            store.open_incident(self.conn, T0, T0, "host", "H{}".format(i), "LOW")
        _, out, _ = self.run_cli_split(["--json", "incidents"])
        payload = json.loads(out)
        self.assertEqual((22, 22, 22), (payload["count"], payload["total"],
                                        len(payload["incidents"])))

    def test_json_open_filters_too(self):
        self.seed()
        store.close_incident(self.conn, self.ids()["PC-01"])
        _, out, _ = self.run_cli_split(["--json", "incidents", "--open"])
        payload = json.loads(out)
        self.assertEqual(["1.2.3.4"], [i["entity_value"] for i in payload["incidents"]])
        self.assertEqual((1, 1), (payload["count"], payload["total"]))

    def test_a_top_below_one_is_a_usage_error(self):
        for bad in ("0", "-1"):
            code, _ = self.run_cli(["incidents", "--top", bad])
            self.assertEqual(2, code, bad)

    def test_open_filters_to_open_incidents(self):
        self.seed()
        store.close_incident(self.conn, self.ids()["PC-01"])
        _, out = self.run_cli(["incidents", "--open"])
        self.assertEqual(["1.2.3.4"], [r[5] for r in incident_rows(out)])

    def test_without_open_closed_incidents_are_listed_with_their_status(self):
        self.seed()
        store.close_incident(self.conn, self.ids()["PC-01"])
        _, out = self.run_cli(["incidents"])
        self.assertEqual([("PC-01", "CLOSED"), ("1.2.3.4", "OPEN")],
                         [(r[5], r[3]) for r in incident_rows(out)])

    def test_an_empty_list_is_exit_0_and_says_so(self):
        code, out = self.run_cli(["incidents"])
        self.assertEqual(0, code)
        # Anchored: the ANSI reset "\033[0m" contains a "0".
        self.assertRegex(ANSI.sub("", out), r"\[~\] 0 incidents\b")
        self.assertEqual([], incident_rows(out))

    def test_a_store_that_does_not_exist_yet_is_not_a_traceback(self):
        fresh = tempfile.TemporaryDirectory()
        self.addCleanup(fresh.cleanup)
        code, out = self.run_cli(["--db", str(Path(fresh.name) / "new.db"), "incidents"])
        self.assertEqual(0, code)
        self.assertRegex(ANSI.sub("", out), r"\[~\] 0 incidents\b")

    def test_tactic_names_are_shown_not_just_ids(self):
        self.seed()
        _, out = self.run_cli(["incidents"])
        self.assertEqual(["Defense Evasion", "Credential Access"],
                         [r[7] for r in incident_rows(out)])
        self.assertNotIn("TA0006", out)

    def test_an_unknown_tactic_id_is_shown_as_it_is(self):
        store.open_incident(self.conn, T0, T0, "host", "H", "LOW",
                            tactics=["TA0006", "TA9999"])
        _, out = self.run_cli(["incidents"])
        self.assertEqual("Credential Access, TA9999", incident_rows(out)[0][7])

    def test_no_tactics_is_a_dash(self):
        store.open_incident(self.conn, T0, T0, "host", "H", "LOW")
        _, out = self.run_cli(["incidents"])
        self.assertEqual("-", incident_rows(out)[0][7])

    def test_unreadable_tactics_are_not_a_traceback(self):
        for i, bad in enumerate(("not json", "null", '"TA0006"', '{"a": 1}', "[1]")):
            store.open_incident(self.conn, T0, T0, "host", "H{}".format(i), "LOW",
                                tactics=bad)
        code, out = self.run_cli(["incidents"])
        self.assertEqual(0, code)
        self.assertEqual(5, len(incident_rows(out)))

    def test_store_filters_default_to_none(self):
        # cli/__init__.py: a falsy default means "match nothing".
        self.seed()
        self.assertIs(False, cli.build_parser().parse_args(["incidents"]).open)
        with mock.patch.object(store, "query_incidents",
                               wraps=store.query_incidents) as query:
            self.run_cli(["incidents"])
        self.assertIsNone(query.call_args.kwargs["status"])

    def test_json_is_parseable(self):
        self.seed()
        code, out, _ = self.run_cli_split(["--json", "incidents"])
        payload = json.loads(out)
        self.assertEqual(0, code)
        self.assertEqual((2, 2), (payload["count"], payload["total"]))
        self.assertEqual(["TA0005"], payload["incidents"][0]["tactics"])
        self.assertEqual("PC-01", payload["incidents"][0]["entity_value"])

    def test_json_top_caps_and_total_still_counts_all(self):
        self.seed()
        _, out, _ = self.run_cli_split(["--json", "incidents", "--top", "1"])
        payload = json.loads(out)
        self.assertEqual((1, 2), (payload["count"], payload["total"]))

    def test_an_empty_json_result_is_still_json(self):
        _, out, _ = self.run_cli_split(["--json", "incidents"])
        self.assertEqual({"count": 0, "total": 0, "incidents": []}, json.loads(out))


class TestIncidentsListMarkup(IncidentsCase):
    """Ruling R30: stored text never goes through rich markup, and a control
    character cannot reach the terminal or forge a row."""

    def test_markup_in_the_entity_and_title_is_not_interpreted(self):
        # rich would swallow "[red]" and leave a bare FORGED, which the weaker
        # assertIn("FORGED") could not tell apart from the literal text.
        store.open_incident(self.conn, T0, T0, "user", "[red]FORGED[/red]", "LOW",
                            title="[bold]T[/bold]")
        _, out = self.run_cli(["incidents"])
        row = incident_rows(out)[0]
        self.assertEqual("[red]FORGED[/red]", row[5])
        self.assertEqual("[bold]T[/bold]", row[8])

    def test_control_characters_do_not_reach_the_terminal(self):
        store.open_incident(self.conn, T0, T0, "host", "evil\x1b[2Jhost", "LOW")
        _, out = self.run_cli(["incidents"])
        self.assertNotIn("\x1b[2J", out)
        self.assertEqual("evil?[2Jhost", incident_rows(out)[0][5])

    def test_a_newline_cannot_forge_a_second_row(self):
        forged = "x\n99  CRITICAL  999  OPEN  host  attacker"
        store.open_incident(self.conn, T0, T0, "host", forged, "LOW")
        _, out = self.run_cli(["incidents"])
        self.assertEqual(1, len(incident_rows(out)))


def hostile(tag):
    """A value that tries to forge a row and drive the terminal: an ESC
    sequence, then a newline, then a line of its own. `tag` says which column
    it was put in."""
    return "{}\x1b[2J\nforged".format(tag)


def defanged(tag):
    """What `hostile(tag)` must look like on screen: both control characters
    shown as "?", on the one line."""
    return "{}?[2J?forged".format(tag)


LIST_TAGS = ("SEV", "SCORE", "STATUS", "ETYPE", "ENT", "LAST", "TACT", "TITLE")
SHOW_TAGS = LIST_TAGS + ("OPENED", "ASEV", "ATS", "RULE", "AENT", "EVID",
                         "EID", "ACT", "HOST", "USER")


class TestEveryColumnIsDefanged(IncidentsCase):
    """One hostile value in every column `list` and `show` print. Ruling R94
    put the neutralising in one module on the premise that no column bypasses
    it, so each column is asserted on its own: a tag per column means removing
    plain() from one column fails that column's assertion and no other's.
    Columns are written with raw SQL because that is the stronger position
    (the store's own writers would reject or coerce some of these)."""

    def setUp(self):
        super().setUp()
        event = helpers_rules.event(event_id=1102, action="LOG_CLEARED")
        store.insert_events(self.conn, [event])
        correlate(self.conn, [sample_alert(entity_value="E", entity_type="host",
                                           event_hashes=(event.event_hash,))])
        self.conn.execute(
            "UPDATE incidents SET severity=?, score=?, status=?, entity_type=?, "
            "entity_value=?, opened_at=?, last_seen=?, tactics=?, title=?",
            (hostile("SEV"), hostile("SCORE"), hostile("STATUS"), hostile("ETYPE"),
             hostile("ENT"), hostile("OPENED"), hostile("LAST"),
             json.dumps([hostile("TACT")]), hostile("TITLE")))
        self.conn.execute(
            "UPDATE alerts SET timestamp=?, severity=?, rule_id=?, entity_value=?, "
            "evidence=?", (hostile("ATS"), hostile("ASEV"), hostile("RULE"),
                           hostile("AENT"), json.dumps([{"service_name": hostile("EVID")}])))
        self.conn.execute("UPDATE events SET event_id=?, action=?, host=?, user=?",
                          (hostile("EID"), hostile("ACT"), hostile("HOST"), hostile("USER")))
        self.conn.commit()
        self.incident_id = store.query_incidents(self.conn)[0]["id"]

    def check(self, out, tags):
        self.assertNotIn("\x1b[2J", out)
        plain_out = ANSI.sub("", out)
        for tag in tags:
            self.assertIn(defanged(tag), plain_out, tag)
        self.assertEqual([], [l for l in plain_out.splitlines()
                              if l.strip().startswith("forged")],
                         "a newline in a column started a line of its own")

    def test_every_column_of_the_list(self):
        code, out = self.run_cli(["incidents"])
        self.assertEqual(0, code)
        self.check(out, LIST_TAGS)

    def test_every_column_of_show(self):
        code, out = self.run_cli(["incidents", "show", str(self.incident_id)])
        self.assertEqual(0, code)
        self.check(out, SHOW_TAGS)

    def test_a_long_event_field_is_cut_and_marked(self):
        # clip(plain(...)), not plain(...) alone: one 100-character command line
        # would otherwise widen the whole events table.
        self.conn.execute("UPDATE events SET user = ?", ("u" * 100,))
        self.conn.commit()
        _, out = self.run_cli(["incidents", "show", str(self.incident_id)])
        cell = event_rows(out)[0][4]
        self.assertEqual(70, len(cell))
        self.assertTrue(cell.endswith("..."))


class TestIncidentsShow(IncidentsCase):
    def seed_events(self, count=1, **alert):
        events = [helpers_rules.event(event_id=1102, action="LOG_CLEARED", record_id=i + 1,
                                      timestamp=T0 + timedelta(seconds=i))
                  for i in range(count)]
        store.insert_events(self.conn, events)
        correlate(self.conn, [sample_alert(
            entity_value="PC-01", entity_type="host",
            event_hashes=tuple(e.event_hash for e in events), **alert)])
        return events

    def show(self, *extra):
        incident_id = store.query_incidents(self.conn)[0]["id"]
        return self.run_cli(list(extra) + ["incidents", "show", str(incident_id)])

    def test_the_header(self):
        self.seed()
        _, out = self.run_cli(["incidents", "show", str(self.ids()["1.2.3.4"])])
        found = header(out)
        # The stored title is the FIRST alert's rule title and entity, not a
        # summary: an incident that escalates keeps it. The label says so.
        self.assertEqual("Failed Logon Burst on 1.2.3.4", found["First alert"])
        self.assertNotIn("Title", found)
        self.assertEqual(("HIGH", "OPEN", "ip 1.2.3.4"),
                         (found["Severity"], found["Status"], found["Entity"]))
        self.assertEqual("2026-10-03 12:05:00", found["Opened"])
        self.assertEqual("2026-10-03 12:05:00", found["Last seen"])
        self.assertEqual("Credential Access", found["Tactics"])
        self.assertEqual("10", found["Score"])  # HIGH is 8, plus 2 for one tactic

    def test_show_lists_only_the_member_alerts_newest_first(self):
        correlate(self.conn, [
            sample_alert(rule_id="r1", entity_value="PC-01", timestamp=T0),
            sample_alert(rule_id="r2", entity_value="PC-01", event_hashes=("cc",),
                         timestamp=T0 + timedelta(minutes=1)),
            sample_alert(rule_id="r3", entity_value="OTHER", event_hashes=("dd",),
                         timestamp=T0 + timedelta(minutes=2)),
        ])
        # The code is 3 here by fixture accident (sample_alert's default hashes
        # are never inserted); R102's exit 3 is pinned by its own tests (R111).
        _, out = self.run_cli(["incidents", "show", str(self.ids()["PC-01"])])
        body = next(v for k, v in sections(out).items() if k.startswith("Alerts"))
        self.assertEqual(["r2", "r1"], rule_ids("\n".join(body)))

    def test_alerts_of_one_rule_are_told_apart_by_their_evidence(self):
        # The detail is identical for every alert of a rule on a host, so the
        # evidence column is what distinguishes them (as in `alerts`).
        correlate(self.conn, [
            sample_alert(rule_id="svc", entity_value="PC-01", event_hashes=(name,),
                         timestamp=T0 + timedelta(minutes=i),
                         evidence=json.dumps([{"service_name": name}]))
            for i, name in enumerate(("EvilSvc", "OtherSvc"))])
        _, out = self.run_cli(["incidents", "show", str(self.ids()["PC-01"])])
        body = next(v for k, v in sections(out).items() if k.startswith("Alerts"))
        self.assertEqual(["service_name=OtherSvc", "service_name=EvilSvc"],
                         [row[4] for row in table("\n".join(body))])

    def test_show_resolves_the_referenced_events(self):
        # Alerts reference events by hash, so `show` must turn the hashes back
        # into events.
        self.seed_events()
        code, out = self.show()
        self.assertEqual(0, code)
        (row,) = event_rows(out)
        self.assertEqual(["1102", "LOG_CLEARED", "PC-01"], row[1:4])
        self.assertEqual("2026-10-03 12:00:00", row[0])

    def test_an_event_two_alerts_share_is_listed_once(self):
        event = helpers_rules.event(event_id=1102, action="LOG_CLEARED")
        store.insert_events(self.conn, [event])
        correlate(self.conn, [
            sample_alert(rule_id=rule, entity_value="PC-01",
                         event_hashes=(event.event_hash,))
            for rule in ("r1", "r2")])
        _, out = self.show()
        self.assertEqual(1, len(event_rows(out)))
        self.assertNotIn("no longer stored", out, "one event cited twice is not a missing one")

    def test_events_are_listed_oldest_first(self):
        self.seed_events(3)
        _, out = self.show()
        self.assertEqual(["12:00:00", "12:00:01", "12:00:02"],
                         [r[0][11:] for r in event_rows(out)])

    def test_the_event_list_is_capped_and_says_how_many_it_left_out(self):
        self.seed_events(5)
        with mock.patch.object(incidents_command, "SHOW_LIMIT", 3):
            _, out = self.show()
        self.assertEqual(["12:00:00", "12:00:01", "12:00:02"],
                         [r[0][11:] for r in event_rows(out)])
        self.assertIn("Events (showing first 3 of 5)", sections(out))

    def test_an_event_list_under_the_cap_is_not_marked(self):
        self.seed_events(3)
        with mock.patch.object(incidents_command, "SHOW_LIMIT", 3):
            _, out = self.show()
        self.assertIn("Events (3)", sections(out))

    def test_the_alert_list_is_capped_too(self):
        correlate(self.conn, [
            sample_alert(rule_id="r{}".format(i), entity_value="PC-01",
                         event_hashes=("h{}".format(i),),
                         timestamp=T0 + timedelta(seconds=i)) for i in range(5)])
        with mock.patch.object(incidents_command, "SHOW_LIMIT", 3):
            _, out = self.show()
        body = sections(out)["Alerts (showing 3 of 5)"]
        self.assertEqual(["r4", "r3", "r2"], rule_ids("\n".join(body)))

    def test_events_no_longer_stored_are_counted(self):
        # `db purge` deletes events, but the alerts that cite them stay.
        # Ruling R102: that is "something asked for was not stored" (R51), so
        # 3 -- the same code `timeline` returns on the same condition.
        events = self.seed_events(2)
        self.conn.execute("DELETE FROM events WHERE record_id = 2")
        self.conn.commit()
        code, out = self.show()
        self.assertEqual(3, code)
        self.assertEqual(1, len(event_rows(out)))
        self.assertRegex(ANSI.sub("", out), r"\[~\] 1 referenced event\(s\) are no longer stored")

    def test_missing_events_exit_3_on_the_json_path_too(self):
        # A script reading --json must get the same signal as the text note.
        self.seed_events(2)
        self.conn.execute("DELETE FROM events WHERE record_id = 2")
        self.conn.commit()
        code, out, _ = self.run_cli_split(
            ["--json", "incidents", "show",
             str(store.query_incidents(self.conn)[0]["id"])])
        self.assertEqual(3, code)
        self.assertEqual(1, json.loads(out)["events_missing"])

    def test_no_missing_note_when_every_event_is_stored(self):
        self.seed_events(2)
        code, out = self.show()
        self.assertEqual(0, code)
        self.assertNotIn("no longer stored", out)

    def test_unreadable_event_references_are_not_a_traceback(self):
        for i, bad in enumerate((None, "not json", '"abc"', '{"a": 1}', "[1, null]", "[]")):
            correlate(self.conn, [sample_alert(rule_id="r{}".format(i),
                                               entity_value="e{}".format(i))])
            self.conn.execute("UPDATE alerts SET event_ids = ? WHERE rule_id = ?",
                              (bad, "r{}".format(i)))
            self.conn.commit()
            incident_id = self.ids()["e{}".format(i)]
            code, out = self.run_cli(["incidents", "show", str(incident_id)])
            self.assertEqual(0, code, bad)
            self.assertEqual([], event_rows(out), bad)
            self.assertNotIn("no longer stored", out, bad)

    def test_an_incident_with_no_alerts_still_shows(self):
        incident_id = store.open_incident(self.conn, T0, T0, "host", "H", "LOW")
        code, out = self.run_cli(["incidents", "show", str(incident_id)])
        self.assertEqual(0, code)
        self.assertEqual("host H", header(out)["Entity"])

    def test_markup_and_control_characters_are_not_interpreted(self):
        hostile = "[red]FORGED[/red]\x1b[2J\nSeverity : CRITICAL"
        event = helpers_rules.event(user="[red]FORGED[/red]", host="evil\x1b[2Jhost")
        store.insert_events(self.conn, [event])
        correlate(self.conn, [sample_alert(
            rule_id="[red]FORGED[/red]", rule_title=hostile, entity_value=hostile,
            event_hashes=(event.event_hash,))])
        code, out = self.show()
        self.assertEqual(0, code)
        self.assertNotIn("\x1b[2J", out)
        self.assertEqual("HIGH", header(out)["Severity"], "a newline forged a header line")
        self.assertEqual("[red]FORGED[/red]", rule_ids(
            "\n".join(next(v for k, v in sections(out).items() if k.startswith("Alerts"))))[0])
        row = event_rows(out)[0]
        self.assertEqual("evil?[2Jhost", row[3])
        self.assertEqual("user=[red]FORGED[/red]", row[4])

    def test_show_does_not_close_an_idle_incident(self):
        self.seed_by_age()
        self.run_cli(["incidents", "show", str(self.ids()["STALE"])])
        self.assertEqual({"OPEN"}, set(self.statuses().values()))

    def test_json(self):
        self.seed_events(2)
        code, out, _ = self.run_cli_split(["--json", "incidents", "show",
                                           str(store.query_incidents(self.conn)[0]["id"])])
        payload = json.loads(out)
        self.assertEqual(0, code)
        self.assertEqual("PC-01", payload["incident"]["entity_value"])
        self.assertEqual(["TA0006"], payload["incident"]["tactics"])
        self.assertEqual(1, len(payload["alerts"]))
        self.assertEqual(["LOG_CLEARED"] * 2, [e["action"] for e in payload["events"]])
        self.assertEqual(0, payload["events_missing"])

    def test_json_events_missing_counts_the_purged_events(self):
        # The JSON consumer must get the "silently fewer" signal the text note
        # gives: a purged event is not in `events`, and must still be counted.
        self.seed_events(3)
        self.conn.execute("DELETE FROM events WHERE record_id IN (2, 3)")
        self.conn.commit()
        _, out, _ = self.run_cli_split(["--json", "incidents", "show",
                                        str(store.query_incidents(self.conn)[0]["id"])])
        payload = json.loads(out)
        self.assertEqual((1, 2), (len(payload["events"]), payload["events_missing"]))

    def test_json_alerts_are_not_capped(self):
        correlate(self.conn, [
            sample_alert(rule_id="r{}".format(i), entity_value="PC-01",
                         event_hashes=("h{}".format(i),),
                         timestamp=T0 + timedelta(seconds=i)) for i in range(5)])
        with mock.patch.object(incidents_command, "SHOW_LIMIT", 3):
            _, out, _ = self.run_cli_split(["--json", "incidents", "show",
                                            str(store.query_incidents(self.conn)[0]["id"])])
        self.assertEqual(5, len(json.loads(out)["alerts"]))

    def test_json_events_are_not_capped(self):
        self.seed_events(5)
        with mock.patch.object(incidents_command, "SHOW_LIMIT", 3):
            _, out, _ = self.run_cli_split(["--json", "incidents", "show",
                                            str(store.query_incidents(self.conn)[0]["id"])])
        self.assertEqual(5, len(json.loads(out)["events"]))

    def test_an_unknown_id_exits_1_and_names_it(self):
        code, out = self.run_cli(["incidents", "show", "999"])
        self.assertEqual(1, code)
        self.assertRegex(ANSI.sub("", out), r"\[x\] No incident with id 999$")

    def test_an_unknown_id_under_json_is_json(self):
        code, out, _ = self.run_cli_split(["--json", "incidents", "show", "999"])
        self.assertEqual(1, code)
        self.assertEqual({"error": "No incident with id 999"}, json.loads(out))

    def test_a_non_numeric_id_is_a_usage_error(self):
        # argparse's own exit: a SystemExit, not a code dispatch returns.
        err = io.StringIO()
        with self.assertRaises(SystemExit) as raised, redirect_stderr(err):
            cli.dispatch(["--db", self.db_path, "incidents", "show", "abc"])
        self.assertEqual(2, raised.exception.code)
        self.assertIn("invalid int value: 'abc'", err.getvalue())

    def test_show_and_close_without_an_id_are_usage_errors(self):
        for action in ("show", "close"):
            code, out = self.run_cli(["incidents", action])
            self.assertEqual(2, code, action)
            self.assertIn("needs an incident id", out, action)

    def test_list_with_an_id_is_a_usage_error(self):
        code, out = self.run_cli(["incidents", "list", "3"])
        self.assertEqual(2, code)
        self.assertIn("takes no incident id", out)


class TestIncidentsClose(IncidentsCase):
    def test_close_sets_the_status_of_that_incident_only(self):
        self.seed()
        code, out = self.run_cli(["incidents", "close", str(self.ids()["PC-01"])])
        self.assertEqual(0, code)
        self.assertRegex(ANSI.sub("", out), r"\[\+\] Closed incident \d+$")
        self.assertEqual({"PC-01": "CLOSED", "1.2.3.4": "OPEN"}, self.statuses())

    def test_closing_an_unknown_id_exits_1_and_names_it(self):
        self.seed()
        code, out = self.run_cli(["incidents", "close", "999"])
        self.assertEqual(1, code)
        self.assertRegex(ANSI.sub("", out), r"\[x\] No incident with id 999$")
        self.assertEqual({"OPEN"}, set(self.statuses().values()))

    def test_closing_an_already_closed_incident_is_exit_0(self):
        self.seed()
        incident_id = str(self.ids()["PC-01"])
        self.run_cli(["incidents", "close", incident_id])
        code, _ = self.run_cli(["incidents", "close", incident_id])
        self.assertEqual(0, code, "closing twice is not an error")
        self.assertEqual("CLOSED", self.statuses()["PC-01"])

    def test_json(self):
        self.seed()
        incident_id = self.ids()["PC-01"]
        code, out, _ = self.run_cli_split(["--json", "incidents", "close", str(incident_id)])
        self.assertEqual(0, code)
        self.assertEqual({"closed": incident_id}, json.loads(out))

    def test_json_for_an_unknown_id(self):
        code, out, _ = self.run_cli_split(["--json", "incidents", "close", "999"])
        self.assertEqual(1, code)
        self.assertEqual({"error": "No incident with id 999"}, json.loads(out))


class TestIncidentsIdleClose(IncidentsCase):
    def test_close_idle_closes_only_the_stale_incident(self):
        self.seed_by_age()
        code, out = self.run_cli(["incidents", "--close-idle"])
        self.assertEqual(0, code)
        self.assertEqual({"STALE": "CLOSED", "FRESH": "OPEN"}, self.statuses())
        self.assertRegex(ANSI.sub("", out), r"\[\+\] Closed 1 idle incident\(s\)$")

    def test_close_idle_with_nothing_idle_says_0(self):
        correlate(self.conn, [sample_alert(timestamp=datetime.now())])
        code, out = self.run_cli(["incidents", "--close-idle"])
        self.assertEqual(0, code)
        self.assertRegex(ANSI.sub("", out), r"\[\+\] Closed 0 idle incident\(s\)$")
        self.assertEqual({"OPEN"}, set(self.statuses().values()))

    def test_json(self):
        self.seed_by_age()
        code, out, _ = self.run_cli_split(["--json", "incidents", "--close-idle"])
        self.assertEqual(0, code)
        self.assertEqual({"closed_idle": 1}, json.loads(out))

    def test_list_flags_do_nothing_on_show_and_close_so_they_are_usage_errors(self):
        self.seed_by_age()
        incident_id = str(self.ids()["STALE"])
        for action in ("show", "close"):
            for flag in (["--close-idle"], ["--open"], ["--top", "5"]):
                code, out = self.run_cli(["incidents", action, incident_id] + flag)
                self.assertEqual(2, code, (action, flag))
                self.assertIn("{} goes with the list action only".format(flag[0]), out)
        self.assertEqual({"STALE": "OPEN", "FRESH": "OPEN"}, self.statuses(),
                         "a refused command must not have acted")

    def test_listing_alone_never_closes_anything(self):
        # Reading must not mutate. A list that silently closes incidents is the
        # kind of surprise that makes an operator distrust the tool. The
        # incidents are idle by the clock, so a list that did close idle ones
        # would show it.
        self.seed_by_age()
        for argv in (["incidents"], ["incidents", "list"], ["incidents", "--open"],
                     ["--json", "incidents"], ["incidents", "--top", "1"]):
            self.run_cli(argv)
            self.assertEqual({"STALE": "OPEN", "FRESH": "OPEN"}, self.statuses(), argv)


if __name__ == "__main__":
    unittest.main()

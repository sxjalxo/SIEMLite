import json
import re
import unittest
from datetime import timedelta

from cli.commands import timeline as timeline_command
from core import store
from core.correlator import correlate
from tests import helpers_rules
from tests.helpers_rules import T0, sample_alert
from tests.test_cli_alerts import ANSI, ROW
from tests.test_cli_incidents import defanged, hostile, sections
from tests.test_cli_ingest import IngestTestCase

# Spec section 10: two spaces between the mark's columns.
MARK = ">> ALERT  "


def entries(out):
    """The timeline body in print order: ("event", time, id, action, host,
    fields) for an event row, ("mark", text) for an alert mark under it, and
    ("orphan", time, text) for an alert whose events are gone. Anchoring to the
    column is what lets a test say "PC-09 is not listed" without a stray
    "PC-09" elsewhere satisfying it."""
    body = next((v for k, v in sections(out).items() if k.startswith("Timeline")), [])
    found = []
    for line in body:
        line = line.strip()
        if line.startswith(MARK):
            found.append(("mark", line[len(MARK):]))
        elif ROW.match(line + " "):
            # maxsplit=1 first: the mark's own two-space columns would
            # otherwise be split into cells of the row carrying it.
            head = re.split(r"\s{2,}", line, maxsplit=1)
            if len(head) == 2 and head[1].startswith(MARK):
                found.append(("orphan", head[0], head[1][len(MARK):]))
            else:
                found.append(("event", *re.split(r"\s{2,}", line, maxsplit=4)))
    return found


def events_of(out):
    return [e for e in entries(out) if e[0] == "event"]


def minute(n):
    return (T0 + timedelta(minutes=n)).isoformat(sep=" ")


class TimelineCase(IngestTestCase):
    def setUp(self):
        super().setUp()
        self.next_record = 0

    def add(self, minutes, **fields):
        self.next_record += 1
        fields.setdefault("record_id", self.next_record)
        fields.setdefault("source_ip", "1.2.3.4")
        event = helpers_rules.event(timestamp=T0 + timedelta(minutes=minutes), **fields)
        store.insert_events(self.conn, [event])
        return event

    def seed(self):
        """One incident for ip 1.2.3.4, opened 12:01, last seen 12:02. Alert A
        cites e1 and e2, alert B cites e2 and e3: e2 is cited twice. Events
        that are context only sit at 11:40, 11:55, 12:10 and 12:30, so a
        window of 1m, 10m and 30m takes in 3, 5 and 7 events; an event for
        another address at 12:00 is in none of them."""
        self.far_before = self.add(-20, event_id=1001, action="FAR_BEFORE")
        self.before = self.add(-5, event_id=1002, action="BEFORE")
        self.e1 = self.add(0, event_id=4625, action="LOGIN_FAIL")
        self.e2 = self.add(1, event_id=4625, action="LOGIN_FAIL2")
        self.e3 = self.add(2, event_id=4624, action="LOGIN_OK")
        self.after = self.add(10, event_id=1003, action="AFTER")
        self.far_after = self.add(30, event_id=1004, action="FAR_AFTER")
        self.add(0, event_id=1005, action="OTHER_IP", source_ip="9.9.9.9")
        correlate(self.conn, [
            sample_alert(rule_id="r-burst", severity="HIGH", tactic="TA0006",
                         timestamp=T0 + timedelta(minutes=1),
                         event_hashes=(self.e1.event_hash, self.e2.event_hash)),
            sample_alert(rule_id="r-success", severity="CRITICAL", tactic="TA0001",
                         timestamp=T0 + timedelta(minutes=2),
                         event_hashes=(self.e2.event_hash, self.e3.event_hash)),
        ])
        self.incident_id = store.query_incidents(self.conn)[0]["id"]

    def purge(self, *events):
        """What `db purge` does to the events an alert still cites."""
        self.conn.executemany("DELETE FROM events WHERE event_hash = ?",
                              [(e.event_hash,) for e in events])
        self.conn.commit()


class TestTimeline(TimelineCase):
    def test_referenced_events_and_context_events_are_both_present(self):
        self.seed()
        code, out = self.run_cli(["timeline", "--incident", str(self.incident_id)])
        self.assertEqual(0, code)
        self.assertEqual(["BEFORE", "LOGIN_FAIL", "LOGIN_FAIL2", "LOGIN_OK", "AFTER"],
                         [e[3] for e in events_of(out)])

    def test_an_event_for_another_entity_is_never_context(self):
        self.seed()
        _, out = self.run_cli(["timeline", "--incident", str(self.incident_id),
                               "--context", "1d"])
        self.assertNotIn("OTHER_IP", [e[3] for e in events_of(out)])

    def test_context_widens_the_window_both_ways(self):
        self.seed()
        counts = {}
        for context in ("1m", "10m", "30m"):
            code, out = self.run_cli(["timeline", "--incident", str(self.incident_id),
                                      "--context", context])
            self.assertEqual(0, code)
            counts[context] = len(events_of(out))
        self.assertEqual({"1m": 3, "10m": 5, "30m": 7}, counts)
        _, out = self.run_cli(["timeline", "--incident", str(self.incident_id),
                               "--context", "30m"])
        actions = [e[3] for e in events_of(out)]
        self.assertEqual(("FAR_BEFORE", "FAR_AFTER"), (actions[0], actions[-1]))

    def test_a_cited_event_outside_the_window_is_still_there(self):
        # --context 0s: the window is exactly 12:01-12:02, and e1 (12:00) is
        # outside it but cited. A cited event must never depend on the window.
        self.seed()
        _, out = self.run_cli(["timeline", "--incident", str(self.incident_id),
                               "--context", "0s"])
        self.assertEqual(["LOGIN_FAIL", "LOGIN_FAIL2", "LOGIN_OK"],
                         [e[3] for e in events_of(out)])

    def test_an_alert_row_carries_its_rule_severity_and_tactic_name(self):
        # "Credential Access", not "TA0006": tactic_name() is why it exists.
        self.seed()
        _, out = self.run_cli(["timeline", "--incident", str(self.incident_id)])
        marks = [e[1] for e in entries(out) if e[0] == "mark"]
        self.assertIn("r-burst  HIGH  [TA0006 Credential Access]", marks)
        self.assertIn("r-success  CRITICAL  [TA0001 Initial Access]", marks)

    def test_the_mark_has_two_spaces_between_its_columns(self):
        # Spec section 10 shows ">> ALERT  rule  SEV  [tactic]". Read off the
        # raw line, not through entries(), whose own parser is keyed to it.
        self.seed()
        _, out = self.run_cli(["timeline", "--incident", str(self.incident_id)])
        plain_out = ANSI.sub("", out)
        self.assertIn(">> ALERT  r-burst  HIGH  [TA0006 Credential Access]", plain_out)
        self.assertNotIn(">> ALERT r-burst", plain_out)

    def test_an_unknown_tactic_is_shown_once_as_itself_and_none_as_a_dash(self):
        store.insert_alerts(self.conn, [
            sample_alert(rule_id="odd", tactic="TA9999", event_hashes=("x",)),
            sample_alert(rule_id="plain", tactic=None, event_hashes=("y",),
                         timestamp=T0 + timedelta(minutes=1))])
        correlate(self.conn, [])
        incident = store.open_incident(self.conn, T0, T0, "ip", "1.2.3.4", "HIGH")
        store.attach_alerts(self.conn, incident,
                            [r["id"] for r in store.query_alerts(self.conn)])
        _, out = self.run_cli(["timeline", "--incident", str(incident)])
        marks = [e[2] for e in entries(out) if e[0] == "orphan"]
        self.assertEqual(["odd  HIGH  [TA9999]", "plain  HIGH  [-]"], marks)

    def test_rows_are_chronological_even_though_the_two_sources_are_not(self):
        # Referenced events and context events arrive from different queries:
        # concatenated they would put 11:55 and 12:10 after the cited ones.
        self.seed()
        _, out = self.run_cli(["timeline", "--incident", str(self.incident_id),
                               "--context", "30m"])
        times = [e[1] for e in events_of(out)]
        self.assertEqual(sorted(times), times)
        self.assertEqual(7, len(times))

    def test_an_event_cited_by_two_alerts_appears_once_with_both_marks(self):
        self.seed()
        _, out = self.run_cli(["timeline", "--incident", str(self.incident_id)])
        found = entries(out)
        second = [i for i, e in enumerate(found) if e[0] == "event" and e[3] == "LOGIN_FAIL2"]
        self.assertEqual(1, len(second), "e2 is cited by two alerts and listed once")
        after = found[second[0] + 1:second[0] + 3]
        self.assertEqual([("mark", "r-burst  HIGH  [TA0006 Credential Access]"),
                          ("mark", "r-success  CRITICAL  [TA0001 Initial Access]")], after)
        self.assertEqual(4, sum(1 for e in found if e[0] == "mark"),
                         "A cites e1 and e2, B cites e2 and e3: four marks")

    def test_an_incident_whose_events_were_purged_still_renders(self):
        # db purge can remove events an alert still cites. Say how many, and
        # exit 3: something asked for was not stored.
        self.seed()
        self.purge(self.e1, self.e2, self.e3)
        code, out = self.run_cli(["timeline", "--incident", str(self.incident_id)])
        self.assertEqual(3, code)
        self.assertIn("3 referenced event(s) are no longer stored", ANSI.sub("", out))
        found = entries(out)
        # The alerts are not lost with their events: each is a row of its own,
        # at its own time, between the context events that remain.
        self.assertEqual(["BEFORE", "r-burst  HIGH  [TA0006 Credential Access]",
                          "r-success  CRITICAL  [TA0001 Initial Access]", "AFTER"],
                         [e[3] if e[0] == "event" else e[2] for e in found])
        self.assertEqual(["2026-10-03 12:01:00", "2026-10-03 12:02:00"],
                         [e[1] for e in found if e[0] == "orphan"])

    def test_some_purged_events_are_counted_and_the_rest_still_marked(self):
        self.seed()
        self.purge(self.e1)
        code, out = self.run_cli(["timeline", "--incident", str(self.incident_id)])
        self.assertEqual(3, code)
        self.assertIn("1 referenced event(s) are no longer stored", ANSI.sub("", out))
        self.assertEqual([], [e for e in entries(out) if e[0] == "orphan"])
        # e2 is still cited twice and e3 once; only e1's mark went with it.
        self.assertEqual(3, sum(1 for e in entries(out) if e[0] == "mark"))

    def test_at_one_instant_an_event_comes_before_the_alert_it_raised(self):
        # A is orphaned (e1 and e2 gone) at 12:01, where a context event sits.
        self.seed()
        self.add(1, event_id=7777, action="TIE", record_id=900)
        self.purge(self.e1, self.e2)
        _, out = self.run_cli(["timeline", "--incident", str(self.incident_id)])
        at_1201 = [e[3] if e[0] == "event" else e[2] for e in entries(out)
                   if e[0] != "mark" and e[1] == "2026-10-03 12:01:00"]
        self.assertEqual(["TIE", "r-burst  HIGH  [TA0006 Credential Access]"], at_1201)

    def test_events_at_one_instant_are_in_record_order(self):
        self.seed()
        self.add(5, event_id=8001, action="LATER_RECORD", record_id=950)
        self.add(5, event_id=8002, action="EARLIER_RECORD", record_id=940)
        _, out = self.run_cli(["timeline", "--incident", str(self.incident_id)])
        self.assertEqual(["EARLIER_RECORD", "LATER_RECORD"],
                         [e[3] for e in events_of(out) if e[1] == "2026-10-03 12:05:00"])

    def test_an_alert_that_cites_one_event_twice_marks_it_once(self):
        event = self.add(0, event_id=4625, action="LOGIN_FAIL")
        correlate(self.conn, [sample_alert(event_hashes=(event.event_hash, event.event_hash))])
        incident = store.query_incidents(self.conn)[0]["id"]
        _, out = self.run_cli(["timeline", "--incident", str(incident)])
        self.assertEqual(1, sum(1 for e in entries(out) if e[0] == "mark"))

    def test_a_tampered_cited_event_keeps_its_marks(self):
        # Ruling R105. Editing `channel` changes what NormalizedEvent.event_hash
        # recomputes to but not the hash the row is STORED under. Keying on the
        # recompute drops e2's two marks and shows 2 cited, not 3, while still
        # reporting nothing missing: linkage lost without a word.
        self.seed()
        self.conn.execute("UPDATE events SET channel = 'Tampered' WHERE event_hash = ?",
                          (self.e2.event_hash,))
        self.conn.commit()
        code, out = self.run_cli(["timeline", "--incident", str(self.incident_id)])
        self.assertEqual(0, code)
        plain_out = ANSI.sub("", out)
        self.assertIn("5 (3 cited by alerts)", plain_out)
        self.assertNotIn("no longer stored", plain_out)
        self.assertEqual(4, sum(1 for e in entries(out) if e[0] == "mark"))
        self.assertEqual([], [e for e in entries(out) if e[0] == "orphan"])

    def test_a_tampered_cited_event_is_listed_once_not_twice(self):
        # e2 is cited AND inside the context window, so it arrives from both
        # queries. The cited copy is keyed by its stored hash and the context
        # copy by the recomputed one, which diverge here: without the
        # recomputed-hash de-duplication the same row becomes two rows.
        self.seed()
        self.conn.execute("UPDATE events SET channel = 'Tampered' WHERE event_hash = ?",
                          (self.e2.event_hash,))
        self.conn.commit()
        _, out = self.run_cli(["timeline", "--incident", str(self.incident_id)])
        actions = [e[3] for e in events_of(out)]
        self.assertEqual(["BEFORE", "LOGIN_FAIL", "LOGIN_FAIL2", "LOGIN_OK", "AFTER"],
                         actions)

    def test_a_tampered_cited_event_still_counts_the_really_missing_ones(self):
        # e1 is genuinely gone and e2's and e3's identities have diverged. The
        # count must be 1 -- what is not stored -- and the two surviving events
        # must keep the three marks between them.
        self.seed()
        self.purge(self.e1)
        self.conn.execute("UPDATE events SET channel = 'Tampered' "
                          "WHERE event_hash IN (?, ?)",
                          (self.e2.event_hash, self.e3.event_hash))
        self.conn.commit()
        code, out = self.run_cli(["timeline", "--incident", str(self.incident_id)])
        self.assertEqual(3, code)
        self.assertIn("1 referenced event(s) are no longer stored", ANSI.sub("", out))
        self.assertEqual(3, sum(1 for e in entries(out) if e[0] == "mark"))
        self.assertEqual([], [e for e in entries(out) if e[0] == "orphan"])

    def test_json_gives_the_stored_event_hash_not_a_recomputed_one(self):
        # The hash a consumer reads back must be the one that resolves through
        # events_by_hash and matches the alert's event_ids.
        self.seed()
        self.conn.execute("UPDATE events SET channel = 'Tampered' WHERE event_hash = ?",
                          (self.e2.event_hash,))
        self.conn.commit()
        _, out, _ = self.run_cli_split(
            ["--json", "timeline", "--incident", str(self.incident_id)])
        row = next(r for r in json.loads(out)["rows"]
                   if r["event"] and r["event"]["action"] == "LOGIN_FAIL2")
        self.assertEqual(self.e2.event_hash, row["event"]["event_hash"])
        self.assertEqual(self.e2.event_hash, row["event_hash"])

    def test_no_missing_events_means_exit_0(self):
        self.seed()
        code, out = self.run_cli(["timeline", "--incident", str(self.incident_id)])
        self.assertEqual(0, code)
        self.assertNotIn("no longer stored", out)

    def test_unknown_incident_exits_1_naming_the_id(self):
        code, out = self.run_cli(["timeline", "--incident", "99"])
        self.assertEqual(1, code)
        self.assertIn("No incident with id 99", out)
        code, out, err = self.run_cli_split(["--json", "timeline", "--incident", "99"])
        self.assertEqual(1, code)
        self.assertEqual({"error": "No incident with id 99"}, json.loads(out))

    def test_incident_is_required_and_the_context_must_be_a_duration(self):
        for argv in ([], ["--incident", "1", "--context", "soon"],
                     ["--incident", "1", "--context", ""]):
            with self.subTest(argv=argv):
                code, _ = self.run_cli(["timeline"] + argv)
                self.assertEqual(2, code)

    def test_an_unreadable_incident_time_exits_1_not_with_a_traceback(self):
        self.seed()
        self.conn.execute("UPDATE incidents SET opened_at = 'not a time'")
        self.conn.commit()
        code, out = self.run_cli(["timeline", "--incident", str(self.incident_id)])
        self.assertEqual(1, code)
        self.assertIn("not a time", out)

    def test_json_emits_the_same_structure(self):
        self.seed()
        code, out, err = self.run_cli_split(
            ["--json", "timeline", "--incident", str(self.incident_id)])
        self.assertEqual(0, code)
        self.assertEqual("", err)
        payload = json.loads(out)
        self.assertEqual(self.incident_id, payload["incident"]["id"])
        self.assertEqual(["TA0001", "TA0006"], sorted(payload["incident"]["tactics"]))
        self.assertEqual(0, payload["events_missing"])
        rows = payload["rows"]
        self.assertEqual(["BEFORE", "LOGIN_FAIL", "LOGIN_FAIL2", "LOGIN_OK", "AFTER"],
                         [r["event"]["action"] for r in rows])
        self.assertEqual([False, True, True, True, False], [r["referenced"] for r in rows])
        self.assertEqual([[], ["r-burst"], ["r-burst", "r-success"], ["r-success"], []],
                         [[a["rule_id"] for a in r["alerts"]] for r in rows])
        self.assertEqual(
            {"rule_id": "r-burst", "severity": "HIGH", "tactic": "TA0006",
             "tactic_name": "Credential Access", "timestamp": minute(1)},
            {k: rows[1]["alerts"][0][k]
             for k in ("rule_id", "severity", "tactic", "tactic_name", "timestamp")})

    def test_json_carries_orphan_alerts_and_the_missing_count(self):
        self.seed()
        self.purge(self.e1, self.e2, self.e3)
        code, out, _ = self.run_cli_split(
            ["--json", "timeline", "--incident", str(self.incident_id)])
        self.assertEqual(3, code)
        payload = json.loads(out)
        self.assertEqual(3, payload["events_missing"])
        self.assertEqual(["event", "alert", "alert", "event"], [r["kind"] for r in payload["rows"]])


class TestBuildTimeline(TimelineCase):
    """Task 7 (report) reuses this rather than re-querying."""

    def test_returns_the_incident_rows_and_the_missing_count(self):
        self.seed()
        built = timeline_command.build_timeline(
            self.conn, self.incident_id, timedelta(minutes=10))
        self.assertEqual(self.incident_id, built["incident"]["id"])
        self.assertEqual(5, len(built["rows"]))
        self.assertEqual(0, built["events_missing"])

    def test_an_unknown_incident_is_none(self):
        self.assertIsNone(timeline_command.build_timeline(self.conn, 99, timedelta(0)))


class TestTimelineMarkup(TimelineCase):
    """Ruling R30/R96: stored text never goes through rich markup and a control
    character cannot reach the terminal or forge a row."""

    def test_markup_in_a_field_is_not_interpreted(self):
        # rich swallows "[red]" and leaves a bare FORGED, so assert the literal.
        self.seed()
        # Ruling R105: the host is part of an event's recomputed identity, so
        # rewriting a CITED event's host is also the test that the timeline
        # keys on the stored hash. All four marks must still be there.
        self.conn.execute("UPDATE events SET action = '[red]FORGED[/red]', "
                          "host = '[red]FORGED[/red]'")
        self.conn.execute("UPDATE alerts SET rule_id = '[red]FORGED[/red]'")
        self.conn.commit()
        _, out = self.run_cli(["timeline", "--incident", str(self.incident_id)])
        row = events_of(out)[0]
        self.assertEqual(["[red]FORGED[/red]", "[red]FORGED[/red]"], [row[3], row[4]])
        marks = [e[1] for e in entries(out) if e[0] == "mark"]
        self.assertEqual(4, len(marks))
        self.assertTrue(all(m.startswith("[red]FORGED[/red]  ") for m in marks))

    def test_a_newline_cannot_forge_a_second_row(self):
        self.seed()
        forged = "x\n2026-10-03 12:09:09  4624  LOGIN_OK  PC-01  evil"
        self.conn.execute("UPDATE events SET action = ?", (forged,))
        self.conn.commit()
        _, out = self.run_cli(["timeline", "--incident", str(self.incident_id)])
        self.assertEqual(5, len(events_of(out)))


class TestEveryColumnIsDefanged(TimelineCase):
    """One hostile value in every column `timeline` prints, each with its own
    tag: removing plain() from one column fails that column's assertion and no
    other's. Raw SQL, the stronger position."""

    def setUp(self):
        super().setUp()
        self.seed()
        self.conn.execute(
            "UPDATE events SET event_id=?, action=?, user=?, target_user=? "
            "WHERE event_hash = ?",
            (hostile("EID"), hostile("ACT"), hostile("WHO"), hostile("TGT"),
             self.e1.event_hash))
        # The host is on the CITED event too: it is part of an event's
        # recomputed identity, and ruling R105 says that must not unhook the
        # alerts citing it.
        self.conn.execute("UPDATE events SET host=? WHERE event_hash = ?",
                          (hostile("HOST"), self.e1.event_hash))
        self.conn.execute(
            "UPDATE alerts SET severity=?, rule_id=?, mitre_tactic_id=? WHERE rule_id = 'r-burst'",
            (hostile("ASEV"), hostile("RULE"), hostile("TAC")))
        self.conn.commit()

    def check(self, out, tags):
        self.assertNotIn("\x1b[2J", out)
        plain_out = ANSI.sub("", out)
        for tag in tags:
            self.assertIn(defanged(tag), plain_out, tag)
        self.assertEqual([], [l for l in plain_out.splitlines()
                              if l.strip().startswith("forged")],
                         "a newline in a column started a line of its own")

    def test_every_column(self):
        code, out = self.run_cli(["timeline", "--incident", str(self.incident_id)])
        self.assertEqual(0, code)
        self.check(out, ("EID", "ACT", "HOST", "WHO", "TGT", "ASEV", "RULE", "TAC"))

    def test_the_header(self):
        # An entity type the verb does not know is shown as stored (and gets no
        # context events, since it names no column to match).
        self.conn.execute("UPDATE incidents SET entity_type=?, entity_value=?",
                          (hostile("ETYPE"), hostile("ENT")))
        self.conn.commit()
        code, out = self.run_cli(["timeline", "--incident", str(self.incident_id)])
        self.assertEqual(0, code)
        self.check(out, ("ETYPE", "ENT"))

    def test_an_orphan_alerts_own_columns(self):
        self.purge(self.e1, self.e2, self.e3)
        self.conn.execute("UPDATE alerts SET timestamp=? WHERE rule_id = ?",
                          (hostile("ATS"), hostile("RULE")))
        self.conn.commit()
        code, out = self.run_cli(["timeline", "--incident", str(self.incident_id)])
        self.assertEqual(3, code)
        self.check(out, ("ATS", "RULE", "ASEV", "TAC"))


if __name__ == "__main__":
    unittest.main()

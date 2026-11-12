"""The attack scenario carried through the six verbs this plan added.

`tests/test_pipeline.py` already pins ingest -> detect -> correlate on the same
fixture. This file starts where that one stops: it runs `detect` once through
the CLI and then asks the investigation, timeline, MITRE, response, report and
daemon verbs about what detection left behind. Nothing here may be loosened to
match what the code happens to do; a verb that stops telling the story is the
finding.

Three facts about the fixture govern every test below, and all three were
measured rather than assumed:

* It is anchored to `now` (`attack_scenario.BASE = now - 1h`) and must stay
  that way. `TestFixtureStaysInsideEveryWindowThatReadsIt` in
  `test_pipeline.py` pins both margins it is anchored against.
* The pivot is a three-level ring ip -> user -> host -> ip (ruling R101) and
  **cannot reach `svc_update`**, whose events carry `source_ip` "-" and which
  appears only as another account's `target_user`. The test asserts what the
  ring really reaches, and finds the planted account through its creator.
* `monitor --once` on this fixture reads **zero** events (ruling R132): the
  events are 49 to 60 minutes old and the derived window is 20 minutes. That
  is the daemon's window doing its job, so it is pinned by name rather than
  worked around. The one monitor test that needs an alert seeds its own fresh
  events.

No test here reads the live Event Log: `windows_eventlog.read_channel` is
patched in every monitor test. Nothing here executes a playbook action --
`respond` runs without `--execute`, and the test asserts both that
`response_actions` is empty and that `subprocess.run` was never called, which
together are the whole safety model.

Paths are relative to the repository root, like the CLI's own defaults, which
is where `python -m unittest discover -s tests` runs.
"""

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest import mock

from cli.commands import mitre as mitre_command
from cli.commands import monitor as monitor_command
from cli.commands import respond as respond_command
from core import store
from core.rule_engine.loader import load_rules
from ingestion import windows_eventlog as wel
from ingestion.normalizer import NormalizedEvent
from tests.fixtures import attack_scenario
from tests.test_cli_ingest import IngestTestCase

# The tables a second pass must not change a single row of.
TABLES = ("events", "alerts", "incidents", "response_actions")


def fresh_burst(count=6, step=8, newest_seconds_ago=30):
    """A failed-logon burst inside the daemon's derived window.

    `monitor` reads a 20-minute window, so a test that wants it to find an
    alert cannot use the hour-old fixture (ruling R132). These events are under
    two minutes old, for one source and one account, so they complete
    win-failed-logon-burst's "5 in 5 minutes".
    """
    base = datetime.now().replace(microsecond=0) - timedelta(seconds=newest_seconds_ago)
    return [NormalizedEvent(
        timestamp=base - timedelta(seconds=step * i), source_type="windows",
        host="PC-09", channel="Security", event_id=4625, record_id=9000 + i,
        action="LOGIN_FAIL", target_user="bob", source_ip="198.51.100.9",
        logon_type=3, status="0xc000006d",
        raw="<synthetic 4625 {}/>".format(9000 + i),
        metadata={"stable_record_id": True}) for i in range(count)]


class FullPipelineCase(IngestTestCase):
    """The fixture stored and detected, with the incident ids looked up by
    entity. By entity and never by "1": which of the two incidents opens first
    is the correlator's business, and the wrong one would still print a table.
    """

    def setUp(self):
        super().setUp()
        self.seed(attack_scenario.EVENTS)
        code, out, err = self.run_cli_split(["detect"])
        self.assertEqual(0, code, out + err)
        self.incidents = {(i["entity_type"], i["entity_value"]): i["id"]
                          for i in store.query_incidents(self.conn, limit=None)}
        self.attacker = self.incidents[("ip", attack_scenario.ATTACKER_IP)]
        self.planted = self.incidents[("user", "svc_update")]

    def json_cli(self, argv, expected=0):
        code, out, err = self.run_cli_split(["--json"] + argv)
        self.assertEqual(expected, code, out + err)
        return json.loads(out)

    def rows(self, table):
        return [tuple(r) for r in self.conn.execute(
            "SELECT * FROM {} ORDER BY id".format(table)).fetchall()]

    def snapshot(self):
        return {table: self.rows(table) for table in TABLES}

    def reading_nothing(self):
        """Patch the Event Log reader to return no records.

        Not a convenience: an unpatched monitor test would read this host's
        live Security channel, which is the one thing a test must not do.
        Returning [] rather than raising isolates the window behaviour under
        test from the access-denied path, which test_cli_monitor.py owns.
        """
        return mock.patch.object(wel, "read_channel", return_value=[])


class TestFullPipeline(FullPipelineCase):
    def test_investigate_finds_the_attacker_and_reaches_the_planted_account_through_its_creator(self):
        # The attacker's own history: six failures and the logon that worked,
        # plus the two alerts keyed to the address.
        payload = self.json_cli(
            ["investigate", "--ip", attack_scenario.ATTACKER_IP, "--related"])
        self.assertEqual({"events": 7, "alerts": 2}, payload["counts"])
        self.assertEqual([4625] * 6 + [4624], [e["event_id"] for e in payload["events"]])
        self.assertEqual(["win-failed-logon-burst", "win-success-after-burst"],
                         [a["rule_id"] for a in payload["alerts"]])
        # R101: the ring is ip -> user -> host -> ip, so it reaches alice and
        # PC-01 and stops. It CANNOT reach svc_update, whose events carry
        # source_ip "-", and the third level is empty because PC-01's only
        # other addresses are that "-" and the address we started from.
        levels = payload["related"]["levels"]
        self.assertEqual(["user", "host", "ip"], [lv["type"] for lv in levels])
        self.assertEqual([["alice"], ["PC-01"], []],
                         [[n["value"] for n in lv["nodes"]] for lv in levels])
        self.assertEqual("203.0.113.77", levels[0]["nodes"][0]["parent"])
        self.assertEqual("alice", levels[1]["nodes"][0]["parent"])
        # The planted account is reachable, but through its creator, which is
        # the second investigate an analyst has to run (R101's stated cost).
        creator = self.json_cli(["investigate", "--user", "alice"])
        self.assertIn("svc_update", [e["target_user"] for e in creator["events"]])

    def test_the_timeline_tells_the_story_in_order_with_its_alerts_marked(self):
        payload = self.json_cli(["timeline", "--incident", str(self.planted)])
        self.assertEqual(0, payload["events_missing"])
        events = [r for r in payload["rows"] if r["kind"] == "event"]
        # The planted account's four stages, oldest first.
        self.assertEqual([4720, 4672, 4688, 1102],
                         [r["event"]["event_id"] for r in events])
        times = [r["time"] for r in payload["rows"]]
        self.assertEqual(sorted(times), times, "the timeline must be chronological")
        # Every event here is cited by an alert, and each alert is marked on
        # the event row it belongs to -- not listed separately at the end.
        self.assertTrue(all(r["referenced"] for r in events))
        self.assertEqual(
            [["win-account-created", "win-new-account-privileged"],
             ["win-new-account-privileged"],
             ["win-encoded-powershell"],
             ["win-audit-log-cleared"]],
            [[a["rule_id"] for a in r["alerts"]] for r in events])
        # The text view marks them with spec section 10's own prefix. The
        # whole mark, two spaces and all: ">> ALERT" alone is a prefix of
        # anything that starts that way, so counting it proves nothing about
        # the format (a mutation to ">> ALERT_" survives it).
        code, out = self.run_cli(["timeline", "--incident", str(self.planted)])
        self.assertEqual(0, code, out)
        self.assertEqual(5, out.count(">> ALERT  "))
        self.assertIn(">> ALERT  win-audit-log-cleared  CRITICAL  "
                      "[TA0005 Defense Evasion]", out)

    def test_mitre_shows_the_tactics_the_incident_actually_covered(self):
        payload = self.json_cli(["mitre", "--incident", str(self.planted)])
        hits = [s["tactic"] for s in payload["stages"] if s["hit"]]
        # Exactly the three the alerts carry: persistence, privilege
        # escalation, defense evasion. Equality, not "contains": a stage that
        # lights up without an alert behind it is the bug this would catch.
        self.assertEqual(["TA0003", "TA0004", "TA0005"], hits)
        self.assertEqual(14, len(payload["stages"]), "the full 14-stage chain (R103)")
        self.assertEqual([], [s for s in payload["stages"] if s["extra"]])
        # R110: the strip wraps at stage boundaries, so every stage name
        # survives whole and no line runs past the width.
        code, out = self.run_cli(["mitre", "--incident", str(self.planted)])
        self.assertEqual(0, code, out)
        # mitre's own SEPARATOR, not a copy: it is U+00B7 and this file stays
        # ASCII (R145's reason -- a printed non-ASCII byte is a cp1252 crash
        # waiting for an entry point that forgot fix_encoding()).
        separator = mitre_command.SEPARATOR
        strip = [line.strip() for line in out.splitlines() if separator in line]
        self.assertEqual(4, len(strip), out)
        self.assertTrue(all(len(line) <= 76 for line in strip), strip)
        # Rejoining the lines gives the whole strip back, stage for stage, so a
        # wrap that split a name mid-word would fail here.
        self.assertEqual([s["name"] for s in payload["stages"]],
                         [name.strip("[]") for line in strip
                          for name in line.split(separator)])
        # The matrix counts both incidents' techniques, one row each.
        matrix = self.json_cli(["mitre", "--matrix"])
        self.assertEqual(2, matrix["incidents"])
        self.assertEqual(
            {("T1136.001", 1), ("T1098", 1), ("T1027.010", 1), ("T1070.001", 1),
             ("T1110.001", 2)},
            {(r["technique"], r["alerts"]) for r in matrix["techniques"]})

    def test_respond_matches_a_playbook_and_executes_nothing_by_default(self):
        # subprocess.run is patched for the whole call, so "nothing executed"
        # is proved by the spy and not only by an empty table: a command that
        # ran and whose logging failed would still be caught.
        #
        # input() is patched to say "y" to everything, and asserted NEVER
        # CALLED. Without it this test cannot tell the default path from the
        # --execute one: the harness gives the CLI no stdin, so confirm()
        # raises EOFError and skips every action, and a mutation inverting
        # `if args.execute:` executes nothing either way and survives.
        with mock.patch.object(respond_command.subprocess, "run") as runner, \
                mock.patch("builtins.input", return_value="y") as prompt:
            payload = self.json_cli(["respond", "--incident", str(self.attacker)])
        runner.assert_not_called()
        prompt.assert_not_called()
        self.assertEqual([], payload["executed"])
        self.assertEqual(0, payload["actions_skipped"])
        self.assertEqual([], payload["playbook_errors"])
        # TA0006 at CRITICAL matches pb-brute-force and nothing else.
        self.assertEqual(["pb-brute-force"], [b["id"] for b in payload["playbooks"]])
        actions = payload["playbooks"][0]["actions"]
        self.assertEqual([False, False, False, True], [a["manual"] for a in actions])
        # The rendered command carries the attacker's address, from the data.
        self.assertIn("remoteip=203.0.113.77", " ".join(actions[0]["command"]))
        # The manual action has guidance and no command, so there is nothing
        # for --execute to offer however it is called.
        self.assertIsNone(actions[3]["command"])
        self.assertTrue(actions[3]["guidance"])
        self.assertEqual([], self.rows("response_actions"))
        # Again in TEXT mode, which is the path `--execute` lives on: the JSON
        # branch returns before it is reached, so a JSON-only test cannot see
        # a mutation that inverts the flag.
        with mock.patch.object(respond_command.subprocess, "run") as runner, \
                mock.patch("builtins.input", return_value="y") as prompt:
            code, out = self.run_cli(["respond", "--incident", str(self.attacker)])
        self.assertEqual(0, code, out)
        runner.assert_not_called()
        prompt.assert_not_called()
        self.assertIn("Nothing has run.", out)
        self.assertEqual([], self.rows("response_actions"))

    def test_report_writes_a_file_containing_all_of_the_above(self):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "incident.md")
        try:
            payload = self.json_cli(
                ["report", "--incident", str(self.planted), "--out", path])
            self.assertEqual(0, payload["events_missing"])
            self.assertEqual({"alerts": 4, "events": 4},
                             {k: payload[k] for k in ("alerts", "events")})
            with open(path, "r", encoding="utf-8", newline="") as handle:
                text = handle.read()
        finally:
            if os.path.exists(path):
                os.unlink(path)
            os.rmdir(directory)
        self.assertEqual(payload["bytes"], len(text))
        # R130: Markdown, LF only. newline="" above means a CRLF would survive
        # the read, so this counts bytes rather than trusting the writer.
        self.assertEqual(0, text.count("\r"))
        self.assertEqual("# Incident {} - ".format(self.planted), text[:len(
            "# Incident {} - ".format(self.planted))])
        # Each section this plan's verbs feed into the file.
        for heading in ("## Kill chain", "## Alerts (4)",
                        "## Timeline (4 events, 4 cited by alerts)"):
            self.assertIn(heading, text)
        for expected in ("svc_update", "CRITICAL", "[Persistence]",
                         "[Privilege Escalation]", "[Defense Evasion]",
                         "win-audit-log-cleared", ">> ALERT"):
            self.assertIn(expected, text)
        # The strip's own furniture is ASCII (R145), stored text aside.
        self.assertEqual([], [c for c in text if ord(c) > 127])

    def test_the_whole_run_is_still_idempotent(self):
        # Whole rows of every table, not counts: a second pass that re-scored
        # an incident or re-attached an alert keeps every count identical.
        before = self.snapshot()
        self.assertTrue(all(before[t] for t in TABLES if t != "response_actions"))
        store.insert_events(self.conn, attack_scenario.EVENTS)
        code, out, err = self.run_cli_split(["detect"])
        self.assertEqual(0, code, out + err)
        with mock.patch.object(respond_command.subprocess, "run") as runner, \
                mock.patch("builtins.input", return_value="y") as prompt:
            self.run_cli_split(["--json", "respond", "--incident", str(self.attacker)])
        runner.assert_not_called()
        prompt.assert_not_called()
        self.assertEqual(before, self.snapshot())

    def test_monitor_once_on_the_scenario_reads_nothing_because_the_window_is_narrower_than_the_fixture(self):
        """R132, pinned rather than worked around.

        The fixture's events are 49 to 60 minutes old; the daemon's window is
        20 minutes. Zero events read is the window doing its job, and an
        implementer who "fixes" this by re-anchoring the fixture or widening
        the window breaks three other tests and verifies nothing.
        """
        rules, errors = load_rules("rules/windows")
        self.assertEqual([], errors)
        window = monitor_command.derive_window(rules)
        self.assertEqual(timedelta(minutes=20), window)
        newest = max(datetime.now() - e.timestamp for e in attack_scenario.EVENTS)
        oldest = min(datetime.now() - e.timestamp for e in attack_scenario.EVENTS)
        self.assertGreater(oldest, window, "the whole fixture sits outside the window")
        self.assertGreater(newest, window)
        with self.reading_nothing():
            payload = self.json_cli(["monitor", "--once"])
        self.assertEqual(0, payload["events_read"])
        self.assertEqual(0, payload["alerts_new"])
        self.assertEqual(0, payload["incidents_opened"])
        # And the alerts detect already stored are untouched: a pass that read
        # nothing must not also lose anything.
        self.assertEqual(6, len(store.query_alerts(self.conn, limit=None)))

    def test_monitor_once_detects_events_inside_its_window(self):
        """The other half of R132: the daemon is not broken, the fixture is
        simply older than the window. These events are seconds old, so the
        default window reaches them -- no --window flag, which is the point.
        """
        store.insert_events(self.conn, fresh_burst())
        with self.reading_nothing():
            payload = self.json_cli(["monitor", "--once"])
        self.assertEqual(6, payload["events_read"])
        self.assertEqual(1, payload["alerts_new"])
        self.assertEqual(1, payload["incidents_opened"])
        self.assertEqual(["win-failed-logon-burst"], [
            a["rule_id"] for a in store.query_alerts(self.conn, entity="198.51.100.9",
                                                     limit=None)])


if __name__ == "__main__":
    unittest.main()

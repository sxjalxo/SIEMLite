"""Ingest -> detect -> correlate, end to end, over the real shipped rule pack.

Every other test file exercises one piece against synthetic rules. This one
exists to catch the pieces disagreeing: a rule that never fires on the event
shape the normalizer really produces, an entity the correlator cannot group,
a re-run that inflates a count. Nothing here may be loosened to match what the
code happens to do; a rule that stops firing on the scenario is the finding.

Paths are relative to the repository root, like the CLI's own defaults, which
is where `python -m unittest discover -s tests` runs.
"""

import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from core import store
from core.correlator import correlate
from core.rule_engine.engine import load_plugins, run_rules
from core.rule_engine.loader import load_rules
from tests.fixtures import attack_scenario
from tests.test_cli_ingest import IngestTestCase

RULES_DIR = Path("rules/windows")
PLUGINS_DIR = Path("rules/plugins")

# What the scenario must fire: one rule per stage of the story, nothing else.
EXPECTED_RULES = {
    "win-failed-logon-burst", "win-success-after-burst", "win-account-created",
    "win-new-account-privileged", "win-encoded-powershell", "win-audit-log-cleared",
}

# MITRE tactic ids those rules carry: credential access, persistence, privilege
# escalation, defense evasion.
EXPECTED_TACTICS = {"TA0006", "TA0003", "TA0004", "TA0005"}


def detect_all(conn):
    """What `siem detect` does: read every stored event, run the pack and the
    plugins, correlate. Loads the pack afresh, as each real run does."""
    rules, errors = load_rules(RULES_DIR)
    plugins, plugin_errors = load_plugins(PLUGINS_DIR)
    events = store.query_events(conn, limit=None, order="asc")
    alerts, failures = run_rules(events, rules, plugins=plugins)
    return rules, plugins, errors + plugin_errors, alerts, failures, correlate(conn, alerts)


def snapshot(conn):
    """Every stored alert and incident row, so a re-run that changed
    membership, severity or score without changing a count is still seen."""
    return ([tuple(r) for r in store.query_alerts(conn, limit=None, order="asc")],
            [tuple(r) for r in store.query_incidents(conn, limit=None, order="opened_at")])


class TestFullPipeline(IngestTestCase):
    def setUp(self):
        super().setUp()
        self.seed(attack_scenario.EVENTS)
        (self.rules, self.plugins, self.errors, self.alerts, self.failures,
         self.result) = detect_all(self.conn)

    def incidents_by_entity(self):
        return {(i["entity_type"], i["entity_value"]): i
                for i in store.query_incidents(self.conn, limit=None)}

    def test_the_whole_pack_loaded_clean(self):
        # An empty or half-loaded pack would make every test below fail for
        # the wrong reason, or pass on less than it claims.
        self.assertEqual([], self.errors, "the shipped pack must load clean")
        self.assertEqual(18, len(self.rules))
        self.assertEqual(2, len(self.plugins))

    def test_every_event_was_stored(self):
        self.assertEqual(len(attack_scenario.EVENTS), store.count_events(self.conn))

    def test_no_rule_failed(self):
        self.assertEqual([], self.failures)

    def test_exactly_the_expected_rules_fired(self):
        # Equality, not "contains": a rule that begins firing on this story is
        # either a false positive or a stage the story forgot to name.
        self.assertEqual(EXPECTED_RULES, {a.rule_id for a in self.alerts})

    def test_each_alert_is_stored_once(self):
        self.assertEqual(len(self.alerts), len(store.query_alerts(self.conn, limit=None)))

    def test_the_tactic_set_spans_the_kill_chain(self):
        rows = store.query_alerts(self.conn, limit=None)
        self.assertEqual(EXPECTED_TACTICS,
                         {r["mitre_tactic_id"] for r in rows if r["mitre_tactic_id"]})

    def test_the_story_becomes_two_incidents_by_entity(self):
        # The correlator groups by entity, not host (no cross-entity linking):
        # the attacker's address, and the account it planted.
        self.assertEqual({("ip", attack_scenario.ATTACKER_IP), ("user", "svc_update")},
                         set(self.incidents_by_entity()))
        self.assertEqual(2, self.result["opened"])
        # 6 alerts, 2 of which opened an incident, so 4 joined one already open.
        self.assertEqual(4, self.result["attached"])

    def test_the_planted_account_incident_spans_three_tactics(self):
        planted = self.incidents_by_entity()[("user", "svc_update")]
        self.assertEqual(["TA0003", "TA0004", "TA0005"], json.loads(planted["tactics"]))
        # Already CRITICAL from a member alert, so escalation cannot be seen
        # here; TestSeverityEscalation is where it is.
        self.assertEqual("CRITICAL", planted["severity"])
        # Spec 7: weight of each distinct rule (MEDIUM 4 + CRITICAL 16 + HIGH 8 +
        # CRITICAL 16) plus 2 per distinct tactic (3).
        self.assertEqual(44 + 2 * 3, planted["score"])

    def test_the_attacker_incident_is_one_tactic(self):
        attacker = self.incidents_by_entity()[("ip", attack_scenario.ATTACKER_IP)]
        self.assertEqual(["TA0006"], json.loads(attacker["tactics"]))
        self.assertEqual("CRITICAL", attacker["severity"])
        self.assertEqual(8 + 16 + 2 * 1, attacker["score"])  # HIGH + CRITICAL + 1 tactic

    def test_the_most_important_incident_comes_first(self):
        incidents = store.query_incidents(self.conn, limit=None)
        self.assertEqual(sorted((i["score"] for i in incidents), reverse=True),
                         [i["score"] for i in incidents])
        self.assertEqual("svc_update", incidents[0]["entity_value"])

    def test_the_story_is_not_idle_closable(self):
        # The fixture is anchored an hour back so this holds; a base of three
        # hours would close the incident under test and read as a correlator bug.
        self.assertEqual(0, store.close_idle_incidents(self.conn))
        self.assertEqual([], store.query_incidents(self.conn, status="CLOSED", limit=None))

    def test_the_whole_pipeline_is_idempotent(self):
        # The single most important property: `detect` runs on a schedule over
        # overlapping windows and must not inflate anything. Whole rows, not
        # counts, so a re-run that re-attached or rescored would also fail.
        before = (store.count_events(self.conn), snapshot(self.conn))
        store.insert_events(self.conn, attack_scenario.EVENTS)
        *_, alerts, failures, result = detect_all(self.conn)
        self.assertEqual(len(self.alerts), len(alerts), "the second run found the same alerts")
        self.assertEqual([], failures)
        self.assertEqual((0, 0), (result["opened"], result["attached"]))
        self.assertEqual(before, (store.count_events(self.conn), snapshot(self.conn)))

    def test_an_incident_resolves_back_to_its_events(self):
        for incident in store.query_incidents(self.conn, limit=None):
            rows = store.query_alerts(self.conn, incident_id=incident["id"], limit=None)
            hashes = {h for r in rows for h in json.loads(r["event_ids"])}
            self.assertTrue(hashes)
            self.assertEqual(len(hashes), len(store.events_by_hash(self.conn, hashes)),
                             "every event an alert names must be in the store")


class TestSeverityEscalation(IngestTestCase):
    """Breadth escalates severity (spec 7): three tactics lift an incident one
    level. The main scenario cannot show it, because its incident already holds
    a CRITICAL alert, so this story is MEDIUM + MEDIUM + HIGH across three tactics."""

    def test_three_tactics_lift_a_high_incident_to_critical(self):
        self.seed(attack_scenario.ESCALATION_EVENTS)
        _, _, errors, alerts, failures, _ = detect_all(self.conn)
        self.assertEqual(([], []), (errors, failures))
        self.assertEqual(["HIGH", "MEDIUM", "MEDIUM"], sorted(a.severity for a in alerts))
        (incident,) = store.query_incidents(self.conn, limit=None)
        self.assertEqual(3, len(json.loads(incident["tactics"])))
        self.assertEqual("CRITICAL", incident["severity"])


class TestFixtureStaysInsideEveryWindowThatReadsIt(unittest.TestCase):
    """The fixture is anchored to now. These pin the two limits it is anchored
    against, so moving BASE cannot quietly turn the suite into a test of nothing."""

    def test_the_story_is_inside_detects_default_window(self):
        oldest = min(e.timestamp for e in attack_scenario.EVENTS)
        self.assertGreater(oldest, datetime.now() - timedelta(hours=23))

    def test_the_newest_event_leaves_margin_before_idle_close(self):
        newest = max(e.timestamp for e in attack_scenario.EVENTS)
        self.assertLess(datetime.now() - newest, store.IDLE_TIMEOUT - timedelta(minutes=30))


class TestPipelineThroughTheCli(IngestTestCase):
    """The same scenario through the CLI, which is the contract the user has.
    No --since: the default 24-hour window is what a scheduled run uses."""

    def setUp(self):
        super().setUp()
        self.seed(attack_scenario.EVENTS)

    def detect_json(self):
        code, out, err = self.run_cli_split(["--json", "detect"])
        self.assertEqual(0, code, err)
        return json.loads(out)

    def test_detect_reads_the_scenario_and_reports_the_whole_pack(self):
        payload = self.detect_json()
        # events_read first: a window that read nothing must fail here, loudly,
        # not pass as a clean run with no alerts.
        self.assertEqual(len(attack_scenario.EVENTS), payload["events_read"])
        self.assertEqual(20, payload["rules"])
        self.assertEqual(6, payload["alerts_new"])
        self.assertEqual(2, payload["incidents_opened"])
        self.assertEqual(4, payload["incidents_attached"])
        self.assertEqual([], payload["rule_errors"] + payload["rule_failures"])

    def test_incidents_shows_the_story(self):
        self.assertEqual(0, self.run_cli(["detect"])[0])
        code, out = self.run_cli(["incidents"])
        self.assertEqual(0, code, out)
        for text in ("203.0.113.77", "svc_update", "Credential Access", "Persistence",
                     "Privilege Escalation", "Defense Evasion"):
            self.assertIn(text, out)

    def test_incidents_show_lists_member_alerts_and_their_events(self):
        self.run_cli(["detect"])
        # By entity, not "1": which incident opens first is the correlator's
        # business, and the wrong one would still print a table.
        (attacker,) = store.query_incidents(
            self.conn, entity=attack_scenario.ATTACKER_IP, limit=None)
        code, out = self.run_cli(["incidents", "show", str(attacker["id"])])
        self.assertEqual(0, code, out)
        self.assertIn("win-failed-logon-burst", out)
        self.assertIn("win-success-after-burst", out)
        self.assertIn("4625", out)
        self.assertIn("4624", out)

    def test_alerts_lists_what_detect_found(self):
        self.run_cli(["detect"])
        code, out = self.run_cli(["alerts"])
        self.assertEqual(0, code, out)
        for rule_id in sorted(EXPECTED_RULES):
            self.assertIn(rule_id, out)

    def test_a_second_detect_run_adds_nothing(self):
        first = self.detect_json()
        second = self.detect_json()
        self.assertEqual(first["events_read"], second["events_read"])
        self.assertEqual(0, second["alerts_new"])
        self.assertEqual(first["alerts_new"], second["alerts_duplicate"])
        self.assertEqual(0, second["incidents_opened"])
        self.assertEqual(0, second["incidents_attached"])
        _, out, _ = self.run_cli_split(["--json", "incidents"])
        self.assertEqual(2, len(json.loads(out)["incidents"]))


if __name__ == "__main__":
    unittest.main()

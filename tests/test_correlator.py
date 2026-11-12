import json
import unittest
from datetime import datetime, timedelta
from unittest import mock

from core import correlator, store
from core.correlator import (correlate, escalate, incident_severity,
                             score_incident)
from core.rule_engine.loader import SEVERITIES
from modules.mitre_mapping import TACTIC_NAMES, tactic_name
from tests.helpers_rules import T0, sample_alert
from tests.test_store import StoreTestCase as StoreCase

def _as_datetime(text):
    """A stored local-naive timestamp back to a datetime."""
    return datetime.fromisoformat(text)


def _row(severity="HIGH", rule_id="r1", tactic="TA0006"):
    return {"severity": severity, "rule_id": rule_id, "tactic": tactic}


class TestGrouping(StoreCase):
    def test_two_alerts_on_one_entity_inside_the_window_make_one_incident(self):
        result = correlate(self.conn, [
            sample_alert(rule_id="r1", entity_value="1.2.3.4", timestamp=T0),
            sample_alert(rule_id="r2", entity_value="1.2.3.4",
                         timestamp=T0 + timedelta(minutes=10)),
        ])
        self.assertEqual(1, result["opened"])
        self.assertEqual(1, result["attached"])
        self.assertEqual(1, len(store.query_incidents(self.conn)))
        # Two alerts touched one incident: it is named once.
        self.assertEqual([store.query_incidents(self.conn)[0]["id"]],
                         result["incident_ids"])

    def test_alerts_are_processed_oldest_first_whatever_the_input_order(self):
        # The incident opens at the earliest alert and takes its title, even
        # when the later one is listed first.
        correlate(self.conn, [
            sample_alert(rule_id="r2", rule_title="Later Rule", entity_value="x",
                         timestamp=T0 + timedelta(minutes=10)),
            sample_alert(rule_id="r1", rule_title="Earlier Rule", entity_value="x",
                         timestamp=T0),
        ])
        row = store.query_incidents(self.conn)[0]
        self.assertEqual(T0, _as_datetime(row["opened_at"]))
        self.assertIn("Earlier Rule", row["title"])

    def test_two_alerts_outside_the_window_make_two_incidents(self):
        correlate(self.conn, [sample_alert(entity_value="1.2.3.4", timestamp=T0)])
        correlate(self.conn, [sample_alert(rule_id="r2", entity_value="1.2.3.4",
                                           timestamp=T0 + timedelta(hours=2))])
        self.assertEqual(2, len(store.query_incidents(self.conn)))

    def test_two_entities_make_two_incidents(self):
        correlate(self.conn, [
            sample_alert(entity_value="1.2.3.4"),
            sample_alert(entity_value="5.6.7.8"),
        ])
        self.assertEqual(2, len(store.query_incidents(self.conn)))

    def test_the_same_value_under_two_entity_types_does_not_merge(self):
        # Distinct rule_ids: alert_hash is rule + entity_value + events, with no
        # entity_type, so the brief's two otherwise-identical alerts collapse to
        # one row at insert. The engine fixes entity_type per rule, so that
        # collision cannot happen to a real alert.
        correlate(self.conn, [
            sample_alert(rule_id="r1", entity_type="ip", entity_value="1.2.3.4"),
            sample_alert(rule_id="r2", entity_type="user", entity_value="1.2.3.4"),
        ])
        self.assertEqual(2, len(store.query_incidents(self.conn)))

    def test_attaching_extends_last_seen(self):
        correlate(self.conn, [sample_alert(entity_value="1.2.3.4", timestamp=T0)])
        later = T0 + timedelta(minutes=20)
        correlate(self.conn, [sample_alert(rule_id="r2", entity_value="1.2.3.4",
                                           timestamp=later)])
        row = store.query_incidents(self.conn)[0]
        self.assertEqual(later, _as_datetime(row["last_seen"]))

    def test_attaching_does_not_move_opened_at(self):
        correlate(self.conn, [sample_alert(entity_value="1.2.3.4", timestamp=T0)])
        correlate(self.conn, [sample_alert(rule_id="r2", entity_value="1.2.3.4",
                                           timestamp=T0 + timedelta(minutes=20))])
        row = store.query_incidents(self.conn)[0]
        self.assertEqual(T0, _as_datetime(row["opened_at"]))

    def test_the_alerts_are_linked_back_to_the_incident(self):
        correlate(self.conn, [sample_alert(entity_value="1.2.3.4")])
        incident_id = store.query_incidents(self.conn)[0]["id"]
        self.assertEqual([incident_id],
                         [r["incident_id"] for r in store.query_alerts(self.conn)])

    def test_the_title_comes_from_the_first_alerts_rule_and_entity(self):
        correlate(self.conn, [sample_alert(rule_title="Failed Logon Burst",
                                           entity_value="1.2.3.4")])
        self.assertIn("1.2.3.4", store.query_incidents(self.conn)[0]["title"])
        self.assertIn("Failed Logon Burst",
                      store.query_incidents(self.conn)[0]["title"])

    def test_a_closed_incident_is_not_reopened_by_a_new_alert(self):
        correlate(self.conn, [sample_alert(entity_value="1.2.3.4", timestamp=T0)])
        store.close_incident(self.conn, store.query_incidents(self.conn)[0]["id"])
        correlate(self.conn, [sample_alert(rule_id="r2", entity_value="1.2.3.4",
                                           timestamp=T0 + timedelta(minutes=5))])
        self.assertEqual(2, len(store.query_incidents(self.conn)))

    def test_correlating_the_same_alert_twice_does_not_double_attach(self):
        # `detect` is re-runnable (D3), so correlate must be too.
        alert = sample_alert(entity_value="1.2.3.4")
        correlate(self.conn, [alert])
        correlate(self.conn, [alert])
        self.assertEqual(1, len(store.query_incidents(self.conn)))
        row = store.query_incidents(self.conn)[0]
        self.assertEqual(1, store.query_alerts(
            self.conn, incident_id=row["id"]).__len__())


class TestWindowBoundary(StoreCase):
    """The brief's offsets (+10 min, +2 h) sit nowhere near CORRELATION_WINDOW,
    so mutating the constant passed every one of them. These sit on it."""

    def _gap(self, gap, **kwargs):
        correlate(self.conn, [sample_alert(entity_value="x", timestamp=T0)])
        correlate(self.conn, [sample_alert(rule_id="r2", entity_value="x",
                                           timestamp=T0 + gap)], **kwargs)
        return len(store.query_incidents(self.conn))

    # Literal offsets, not CORRELATION_WINDOW: an offset scaled by the constant
    # under test would move with a mutation of it and never notice.
    def test_an_alert_exactly_thirty_minutes_later_attaches(self):
        self.assertEqual(1, self._gap(timedelta(minutes=30)))

    def test_an_alert_one_second_past_thirty_minutes_opens_a_second_incident(self):
        self.assertEqual(2, self._gap(timedelta(minutes=30, seconds=1)))

    def test_the_window_argument_is_honoured(self):
        self.assertEqual(2, self._gap(timedelta(minutes=10),
                                      window=timedelta(minutes=5)))

    def test_the_window_runs_from_last_seen_not_from_opened_at(self):
        # 0, 25, 50 minutes: 50 is past the window from the first alert but
        # inside it from the last one, so one chain of activity is one incident.
        for i, minutes in enumerate((0, 25, 50)):
            correlate(self.conn, [sample_alert(
                rule_id="r%d" % i, entity_value="x",
                timestamp=T0 + timedelta(minutes=minutes))])
        self.assertEqual(1, len(store.query_incidents(self.conn)))

    def test_a_late_older_alert_does_not_move_last_seen_backwards(self):
        newer = T0 + timedelta(minutes=20)
        correlate(self.conn, [sample_alert(entity_value="x", timestamp=newer)])
        correlate(self.conn, [sample_alert(rule_id="r2", entity_value="x",
                                           timestamp=T0)])
        row = store.query_incidents(self.conn)[0]
        self.assertEqual(newer, _as_datetime(row["last_seen"]))


class TestResult(StoreCase):
    def test_result_names_the_incidents_touched(self):
        result = correlate(self.conn, [sample_alert(entity_value="x")])
        self.assertEqual([store.query_incidents(self.conn)[0]["id"]],
                         result["incident_ids"])

    def test_a_rerun_opens_and_attaches_nothing(self):
        alert = sample_alert(entity_value="x")
        correlate(self.conn, [alert])
        result = correlate(self.conn, [alert])
        self.assertEqual((0, 0, []), (result["opened"], result["attached"],
                                      result["incident_ids"]))

    def test_the_same_alert_twice_in_one_call_is_one_alert(self):
        alert = sample_alert(entity_value="x")
        result = correlate(self.conn, [alert, alert])
        self.assertEqual((1, 0), (result["opened"], result["attached"]))
        self.assertEqual(1, len(store.query_alerts(self.conn)))

    def test_an_alert_stored_but_never_attached_is_attached_by_the_next_run(self):
        # insert_alerts commits before the incident exists, so a run that died
        # in between leaves an unattached row. The next run must pick it up.
        alert = sample_alert(entity_value="x")
        store.insert_alerts(self.conn, [alert])
        correlate(self.conn, [alert])
        self.assertEqual(1, len(store.query_incidents(self.conn)))
        self.assertIsNotNone(store.query_alerts(self.conn)[0]["incident_id"])

    def test_a_run_that_died_before_recomputing_is_repaired_by_the_next(self):
        # Ctrl-C between attach_alerts and _refresh leaves the rows attached
        # but the incident stale; the re-run skips both rows, so it must
        # refresh their incident anyway.
        a = sample_alert(rule_id="r1", severity="HIGH", tactic="TA0006",
                         entity_value="x", timestamp=T0)
        b = sample_alert(rule_id="r2", severity="CRITICAL", tactic="TA0005",
                         entity_value="x", timestamp=T0 + timedelta(minutes=5))
        real = correlator._refresh
        calls = []

        def die_on_the_second(conn, incident_id):
            calls.append(incident_id)
            if len(calls) == 2:
                raise RuntimeError("interrupted")
            return real(conn, incident_id)

        with mock.patch.object(correlator, "_refresh", die_on_the_second):
            with self.assertRaises(RuntimeError):
                correlate(self.conn, [a, b])
        stale = store.query_incidents(self.conn)[0]
        self.assertEqual("HIGH", stale["severity"])

        result = correlate(self.conn, [a, b])
        row = store.query_incidents(self.conn)[0]
        self.assertEqual(("CRITICAL", 8 + 16 + 2 * 2, ["TA0005", "TA0006"],
                          T0 + timedelta(minutes=5)),
                         (row["severity"], row["score"], json.loads(row["tactics"]),
                          _as_datetime(row["last_seen"])))
        self.assertEqual((0, 0, []), (result["opened"], result["attached"],
                                      result["incident_ids"]))

    def test_legacy_alert_rows_are_not_correlated(self):
        # R74: the table also holds scanner rows with no rule_id or entity.
        self.conn.execute(
            "INSERT INTO alerts (timestamp, category, severity, detail, source) "
            "VALUES (?, 'Brute Force', 'HIGH', 'legacy', 'scanner')",
            (str(T0),))
        self.conn.commit()
        correlate(self.conn, [sample_alert(entity_value="x", timestamp=T0)])
        legacy = [r for r in store.query_alerts(self.conn) if r["rule_id"] is None]
        self.assertEqual([None], [r["incident_id"] for r in legacy])
        self.assertEqual(1, len(store.query_incidents(self.conn)))

    def test_the_weakest_possible_alert_still_opens_an_incident(self):
        # spec 7: score ranks, it never gates.
        correlate(self.conn, [sample_alert(severity="INFO", tactic=None,
                                           entity_value="x")])
        self.assertEqual(1, len(store.query_incidents(self.conn)))


class TestTactics(StoreCase):
    def test_tactics_union_across_alerts(self):
        correlate(self.conn, [
            sample_alert(rule_id="r1", entity_value="x", tactic="TA0006"),
            sample_alert(rule_id="r2", entity_value="x", tactic="TA0005"),
        ])
        row = store.query_incidents(self.conn)[0]
        self.assertEqual({"TA0006", "TA0005"}, set(json.loads(row["tactics"])))

    def test_a_repeated_tactic_is_stored_once(self):
        correlate(self.conn, [
            sample_alert(rule_id="r1", entity_value="x", tactic="TA0006"),
            sample_alert(rule_id="r2", entity_value="x", tactic="TA0006"),
        ])
        self.assertEqual(["TA0006"],
                         json.loads(store.query_incidents(self.conn)[0]["tactics"]))

    def test_tactics_are_stored_in_a_stable_order(self):
        # Two runs over the same alerts must produce the same JSON, or a diff
        # of two reports shows a change that did not happen.
        for _ in range(2):
            self.tearDown()  # close the previous store; setUp opens a fresh one
            self.setUp()
            correlate(self.conn, [
                sample_alert(rule_id="r1", entity_value="x", tactic="TA0005"),
                sample_alert(rule_id="r2", entity_value="x", tactic="TA0006"),
            ])
            self.assertEqual('["TA0005", "TA0006"]',
                             store.query_incidents(self.conn)[0]["tactics"])

    def test_many_tactics_are_stored_sorted(self):
        # Two tactics are in sorted order by chance half the time under a
        # random string hash seed, so the test above cannot reliably catch a
        # missing sorted(). Every tactic, reversed, cannot be.
        ids = sorted(TACTIC_NAMES, reverse=True)
        correlate(self.conn, [sample_alert(rule_id="r%d" % i, entity_value="x",
                                           tactic=t) for i, t in enumerate(ids)])
        self.assertEqual(sorted(ids), json.loads(
            store.query_incidents(self.conn)[0]["tactics"]))

    def test_an_alert_with_no_tactic_adds_none(self):
        correlate(self.conn, [
            sample_alert(rule_id="r1", entity_value="x", tactic="TA0006"),
            sample_alert(rule_id="r2", entity_value="x", tactic=None),
        ])
        self.assertEqual(["TA0006"],
                         json.loads(store.query_incidents(self.conn)[0]["tactics"]))

    def test_the_tactic_survives_the_table_into_a_later_run(self):
        # R53: the second run recomputes from stored rows, so the first run's
        # tactic must come back out of the alerts table.
        correlate(self.conn, [sample_alert(rule_id="r1", entity_value="x",
                                           tactic="TA0006")])
        correlate(self.conn, [sample_alert(rule_id="r2", entity_value="x",
                                           tactic="TA0005")])
        self.assertEqual(["TA0005", "TA0006"],
                         json.loads(store.query_incidents(self.conn)[0]["tactics"]))


class TestStoredSeverityAndScore(StoreCase):
    def test_a_later_low_alert_does_not_downgrade_the_incident(self):
        correlate(self.conn, [sample_alert(rule_id="r1", severity="HIGH",
                                           entity_value="x")])
        correlate(self.conn, [sample_alert(rule_id="r2", severity="LOW",
                                           entity_value="x")])
        self.assertEqual("HIGH", store.query_incidents(self.conn)[0]["severity"])

    def test_three_tactics_across_three_runs_escalate_the_stored_incident(self):
        for i, tactic in enumerate(("TA0006", "TA0005", "TA0008")):
            correlate(self.conn, [sample_alert(
                rule_id="r%d" % i, severity="MEDIUM", tactic=tactic,
                entity_value="x", timestamp=T0 + timedelta(minutes=i))])
        self.assertEqual("HIGH", store.query_incidents(self.conn)[0]["severity"])

    def test_the_stored_score_is_the_computed_score(self):
        correlate(self.conn, [
            sample_alert(rule_id="r1", severity="HIGH", tactic="TA0006",
                         entity_value="x"),
            sample_alert(rule_id="r2", severity="LOW", tactic="TA0005",
                         entity_value="x"),
        ])
        self.assertEqual(8 + 2 + 2 * 2, store.query_incidents(self.conn)[0]["score"])


class TestSeverity(unittest.TestCase):
    def test_severity_is_the_maximum_not_the_latest(self):
        rows = [{"severity": "HIGH", "rule_id": "r1", "tactic": "TA0006"},
                {"severity": "LOW", "rule_id": "r2", "tactic": "TA0006"}]
        self.assertEqual("HIGH", incident_severity(rows))

    def test_three_distinct_tactics_escalate_one_level(self):
        rows = [{"severity": "MEDIUM", "rule_id": "r%d" % i,
                 "tactic": t} for i, t in
                enumerate(["TA0006", "TA0005", "TA0008"])]
        self.assertEqual("HIGH", incident_severity(rows))

    def test_two_tactics_do_not_escalate(self):
        rows = [{"severity": "MEDIUM", "rule_id": "r%d" % i, "tactic": t}
                for i, t in enumerate(["TA0006", "TA0005"])]
        self.assertEqual("MEDIUM", incident_severity(rows))

    def test_three_alerts_on_one_tactic_do_not_escalate(self):
        # Breadth is distinct tactics, not alert count.
        rows = [_row("MEDIUM", "r%d" % i, "TA0006") for i in range(3)]
        self.assertEqual("MEDIUM", incident_severity(rows))

    def test_a_missing_tactic_is_not_a_tactic(self):
        rows = [_row("MEDIUM", "r1", "TA0006"), _row("MEDIUM", "r2", "TA0005"),
                _row("MEDIUM", "r3", None)]
        self.assertEqual("MEDIUM", incident_severity(rows))

    def test_critical_cannot_escalate_past_itself(self):
        rows = [{"severity": "CRITICAL", "rule_id": "r%d" % i, "tactic": t}
                for i, t in enumerate(["TA0006", "TA0005", "TA0008", "TA0004"])]
        self.assertEqual("CRITICAL", incident_severity(rows))

    def test_escalate_walks_the_ladder(self):
        self.assertEqual("LOW", escalate("INFO"))
        self.assertEqual("CRITICAL", escalate("HIGH"))
        self.assertEqual("CRITICAL", escalate("CRITICAL"))

    def test_an_unknown_severity_does_not_crash_the_correlator(self):
        # A hand-edited alert row must not take down a correlation run.
        rows = [{"severity": "WEIRD", "rule_id": "r1", "tactic": "TA0006"}]
        self.assertIn(incident_severity(rows), SEVERITIES + ("WEIRD",))

    # The brief's test above passes for any of six return values. These pin it.
    def test_severity_case_is_ignored(self):
        self.assertEqual("HIGH", incident_severity([_row("high")]))
        self.assertEqual("CRITICAL", escalate("high"))
        self.assertEqual(8 + 2, score_incident([_row("high")]))

    def test_an_unknown_severity_ranks_below_every_real_one(self):
        self.assertEqual("INFO", incident_severity([_row("INFO"), _row("WEIRD", "r2")]))
        self.assertEqual("LOW", incident_severity([_row("WEIRD"), _row("LOW", "r2")]))

    def test_only_unknown_severities_give_the_lowest_known_one(self):
        self.assertEqual("INFO", incident_severity([_row("WEIRD")]))

    def test_escalate_leaves_an_unknown_severity_alone(self):
        self.assertEqual("WEIRD", escalate("WEIRD"))


class TestScore(unittest.TestCase):
    def test_score_is_weights_per_distinct_rule_plus_two_per_tactic(self):
        # spec 7: sum(severity_weight for each DISTINCT rule) + 2 * tactics
        rows = [{"severity": "HIGH", "rule_id": "r1", "tactic": "TA0006"},
                {"severity": "LOW", "rule_id": "r2", "tactic": "TA0005"}]
        self.assertEqual(8 + 2 + 2 * 2, score_incident(rows))

    def test_the_same_rule_firing_twice_counts_once(self):
        rows = [{"severity": "HIGH", "rule_id": "r1", "tactic": "TA0006"},
                {"severity": "HIGH", "rule_id": "r1", "tactic": "TA0006"}]
        self.assertEqual(8 + 2 * 1, score_incident(rows))

    def test_score_never_gates_whether_an_incident_opens(self):
        # spec 7: "Score is used for ranking output only".
        rows = [{"severity": "INFO", "rule_id": "r1", "tactic": "TA0001"}]
        self.assertGreater(score_incident(rows), 0)

    def test_an_unknown_severity_scores_without_raising(self):
        self.assertEqual(0 + 2, score_incident([_row("WEIRD")]))


class TestTacticNames(unittest.TestCase):
    def test_the_tactic_ids_the_rule_pack_uses_all_resolve(self):
        for tactic_id in ("TA0002", "TA0003", "TA0004", "TA0005", "TA0006",
                          "TA0008", "TA0011"):
            self.assertNotEqual(tactic_id, tactic_name(tactic_id),
                                tactic_id + " has no name")

    def test_an_unknown_id_returns_itself_rather_than_raising(self):
        self.assertEqual("TA9999", tactic_name("TA9999"))

    def test_the_names_are_the_attack_names_for_the_ids(self):
        # Ruling R103 added TA0043, TA0042 and TA0040 so the kill-chain strip
        # can start at Reconnaissance and end at Impact.
        self.assertEqual({
            "TA0043": "Reconnaissance", "TA0042": "Resource Development",
            "TA0001": "Initial Access", "TA0002": "Execution",
            "TA0003": "Persistence", "TA0004": "Privilege Escalation",
            "TA0005": "Defense Evasion", "TA0006": "Credential Access",
            "TA0007": "Discovery", "TA0008": "Lateral Movement",
            "TA0009": "Collection", "TA0010": "Exfiltration",
            "TA0011": "Command and Control", "TA0040": "Impact"}, TACTIC_NAMES)


if __name__ == "__main__":
    unittest.main()

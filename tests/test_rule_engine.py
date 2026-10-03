# tests/test_rule_engine.py
import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta

from core.rule_engine.engine import (
    ENTITY_TYPES, SEVERITY_WEIGHTS, RuleAlert, entity_for, run_rules,
)
from core.rule_engine.loader import SEVERITIES
# Build Rule objects through the loader, not by hand: a test that constructs
# a Rule directly stops catching loader/engine drift.
from tests.helpers_rules import T0, event, rule_from_yaml

PER_EVENT = """
id: log-cleared
title: Audit Log Cleared
severity: CRITICAL
detection:
  sel:
    event_id: 1102
  condition: sel
mitre: {technique: T1070.001, tactic: TA0005}
fields: [host, user]
description: The security audit log was cleared.
"""

THRESHOLD = """
id: brute-force
title: Failed Logon Burst
severity: HIGH
detection:
  sel:
    event_id: 4625
  timeframe: 5m
  count:
    gte: 3
    group_by: [source_ip, target_user]
  condition: sel
mitre: {technique: T1110.001, tactic: TA0006}
fields: [source_ip, target_user]
description: Repeated failed logons.
"""

# A threshold rule with no group_by: every matching event shares one window,
# and the entity comes from fields[0].
UNGROUPED = (THRESHOLD
             .replace("    group_by: [source_ip, target_user]\n", "")
             .replace("fields: [source_ip, target_user]", "fields: [host]"))


def burst(count, **kwargs):
    """`count` failed logons one second apart, same ip and user."""
    base = dict(event_id=4625, source_ip="1.2.3.4", target_user="alice")
    base.update(kwargs)
    return [event(record_id=i, timestamp=T0 + timedelta(seconds=i), **base)
            for i in range(count)]


class Raises:
    """A condition stand-in whose evaluate raises something other than ValueError."""

    def __init__(self, message="boom"):
        self.message = message

    def evaluate(self, results):
        raise RuntimeError(self.message)


class TestPerEventRules(unittest.TestCase):
    def test_one_matching_event_yields_one_alert(self):
        alerts, failures = run_rules([event(event_id=1102)],
                                     [rule_from_yaml(PER_EVENT)])
        self.assertEqual([], failures)
        self.assertEqual(1, len(alerts))
        self.assertEqual("log-cleared", alerts[0].rule_id)
        self.assertEqual("CRITICAL", alerts[0].severity)

    def test_a_non_matching_event_yields_nothing(self):
        alerts, _ = run_rules([event(event_id=4624)],
                              [rule_from_yaml(PER_EVENT)])
        self.assertEqual([], alerts)

    def test_the_alert_carries_the_event_hash_not_a_row_id(self):
        ev = event(event_id=1102)
        alert = run_rules([ev], [rule_from_yaml(PER_EVENT)])[0][0]
        self.assertEqual((ev.event_hash,), alert.event_hashes)

    def test_the_alert_timestamp_is_the_triggering_event_time(self):
        ev = event(event_id=1102, timestamp=datetime(2026, 1, 2, 3, 4, 5))
        alert = run_rules([ev], [rule_from_yaml(PER_EVENT)])[0][0]
        self.assertEqual(ev.timestamp, alert.timestamp)

    def test_the_not_null_alert_columns_are_all_filled(self):
        # Decision D4: the alerts table has four NOT NULL columns.
        alert = run_rules([event(event_id=1102)],
                          [rule_from_yaml(PER_EVENT)])[0][0]
        for name in ("category", "severity", "detail", "source"):
            self.assertTrue(getattr(alert, name), name + " must not be empty")
        self.assertEqual("rule_engine", alert.source)
        self.assertEqual("Audit Log Cleared", alert.category)

    def test_the_alert_carries_the_rule_metadata(self):
        alert = run_rules([event(event_id=1102)],
                          [rule_from_yaml(PER_EVENT)])[0][0]
        self.assertEqual(("Audit Log Cleared", "T1070.001", "TA0005"),
                         (alert.rule_title, alert.technique, alert.tactic))
        self.assertEqual(("host", "PC-01"), (alert.entity_type, alert.entity_value))

    def test_detail_is_the_description_plus_the_entity_on_one_line(self):
        alert = run_rules([event(event_id=1102)],
                          [rule_from_yaml(PER_EVENT)])[0][0]
        self.assertEqual("The security audit log was cleared. (host: PC-01)",
                         alert.detail)

    def test_a_hostile_entity_cannot_break_detail_across_lines(self):
        alert = run_rules([event(event_id=1102, host="PC\r\n01\tx")],
                          [rule_from_yaml(PER_EVENT)])[0][0]
        self.assertEqual("The security audit log was cleared. (host: PC 01 x)",
                         alert.detail)

    def test_evidence_is_the_rules_fields_for_each_event_as_json(self):
        alert = run_rules([event(event_id=1102, user="bob")],
                          [rule_from_yaml(PER_EVENT)])[0][0]
        self.assertEqual([{"host": "PC-01", "user": "bob"}],
                         json.loads(alert.evidence))

    def test_evidence_falls_back_to_group_by_when_the_rule_lists_no_fields(self):
        rule = rule_from_yaml(THRESHOLD.replace(
            "fields: [source_ip, target_user]\n", ""))
        alert = run_rules(burst(3), [rule])[0][0]
        self.assertEqual({"source_ip": "1.2.3.4", "target_user": "alice"},
                         json.loads(alert.evidence)[0])


class TestThresholdRules(unittest.TestCase):
    def test_below_the_threshold_nothing_fires(self):
        alerts, _ = run_rules(burst(2), [rule_from_yaml(THRESHOLD)])
        self.assertEqual([], alerts)

    def test_at_the_threshold_one_alert_covers_the_whole_window(self):
        events = burst(3)
        alerts, _ = run_rules(events, [rule_from_yaml(THRESHOLD)])
        self.assertEqual(1, len(alerts))
        self.assertEqual(tuple(e.event_hash for e in events), alerts[0].event_hashes)

    def test_the_alert_is_stamped_with_the_newest_event_in_the_window(self):
        alerts, _ = run_rules(burst(3), [rule_from_yaml(THRESHOLD)])
        self.assertEqual(T0 + timedelta(seconds=2), alerts[0].timestamp)

    def test_evidence_has_one_entry_per_event_in_the_window(self):
        alerts, _ = run_rules(burst(3), [rule_from_yaml(THRESHOLD)])
        self.assertEqual(3, len(json.loads(alerts[0].evidence)))

    def test_two_source_ips_are_two_alerts_not_one(self):
        # Interleaved, so a window shared across ips would fire on a mix.
        first = burst(3, source_ip="1.2.3.4")
        second = [replace(e, record_id=e.record_id + 10)
                  for e in burst(3, source_ip="5.6.7.8")]
        events = [e for pair in zip(first, second) for e in pair]
        alerts, _ = run_rules(events, [rule_from_yaml(THRESHOLD)])
        self.assertEqual(2, len(alerts))
        self.assertEqual({"1.2.3.4", "5.6.7.8"},
                         {a.entity_value for a in alerts})
        for alert in alerts:
            own = {e.event_hash for e in events if e.source_ip == alert.entity_value}
            self.assertEqual(own, set(alert.event_hashes))

    def test_events_split_across_two_ips_fire_for_neither(self):
        events = (burst(2, source_ip="1.2.3.4")
                  + [replace(e, record_id=e.record_id + 10)
                     for e in burst(2, source_ip="5.6.7.8")])
        alerts, _ = run_rules(events, [rule_from_yaml(THRESHOLD)])
        self.assertEqual([], alerts)

    def test_each_rule_gets_its_own_threshold_state(self):
        # Two rules counting the same events must not share a window.
        other = THRESHOLD.replace("brute-force", "brute-force-2")
        events = burst(3)
        alerts, _ = run_rules(events, [rule_from_yaml(THRESHOLD),
                                       rule_from_yaml(other)])
        self.assertEqual({"brute-force", "brute-force-2"},
                         {a.rule_id for a in alerts})
        # A shared window would still fire both rules, on a mix of their copies
        # of each event, so the rule ids alone prove nothing: check the evidence.
        for alert in alerts:
            self.assertEqual(tuple(e.event_hash for e in events), alert.event_hashes)

    def test_threshold_state_does_not_leak_between_run_rules_calls(self):
        rule = rule_from_yaml(THRESHOLD)
        events = burst(2)
        self.assertEqual([], run_rules(events, [rule])[0])
        self.assertEqual([], run_rules(events, [rule])[0],
                         "a second batch must start from an empty window")

    def test_the_window_key_ignores_case_like_the_matcher_does(self):
        # Windows usernames are case-insensitive; a burst that alternates case
        # must not split into windows that each stay under the threshold.
        events = [event(event_id=4625, source_ip="1.2.3.4", record_id=i,
                        timestamp=T0 + timedelta(seconds=i), target_user=name)
                  for i, name in enumerate(("Alice", "ALICE", "alice"))]
        alerts, _ = run_rules(events, [rule_from_yaml(THRESHOLD)])
        self.assertEqual(1, len(alerts))


class TestNone(unittest.TestCase):
    """The matcher reads None as "", so the engine must not read it as "None"."""

    def test_a_null_field_does_not_share_a_window_with_the_text_none(self):
        rule = rule_from_yaml(THRESHOLD.replace(
            "group_by: [source_ip, target_user]", "group_by: [target_user]"))
        events = [event(event_id=4625, record_id=i, target_user=name,
                        timestamp=T0 + timedelta(seconds=i))
                  for i, name in enumerate((None, None, "None"))]
        self.assertEqual([], run_rules(events, [rule])[0])

    def test_a_null_entity_is_empty_text_not_none(self):
        rule = rule_from_yaml(PER_EVENT.replace("fields: [host, user]",
                                                "fields: [user]"))
        self.assertEqual(("user", ""), entity_for(rule, event(user=None)))


class TestEntityAssignment(unittest.TestCase):
    def test_a_threshold_rule_takes_its_entity_from_group_by_zero(self):
        rule = rule_from_yaml(THRESHOLD)
        self.assertEqual(("ip", "1.2.3.4"),
                         entity_for(rule, event(source_ip="1.2.3.4")))

    def test_a_per_event_rule_takes_its_entity_from_fields_zero(self):
        rule = rule_from_yaml(PER_EVENT)
        self.assertEqual(("host", "PC-01"), entity_for(rule, event(host="PC-01")))

    def test_the_field_to_entity_type_map_covers_the_spec(self):
        self.assertEqual("ip", ENTITY_TYPES["source_ip"])
        self.assertEqual("ip", ENTITY_TYPES["dest_ip"])
        self.assertEqual("user", ENTITY_TYPES["user"])
        self.assertEqual("user", ENTITY_TYPES["target_user"])
        self.assertEqual("host", ENTITY_TYPES["host"])

    def test_an_unmapped_group_by_field_uses_the_field_name_as_the_type(self):
        rule = rule_from_yaml(THRESHOLD.replace(
            "group_by: [source_ip, target_user]", "group_by: [process]"))
        self.assertEqual(("process", "cmd.exe"),
                         entity_for(rule, event(process="cmd.exe")))

    def test_an_int_field_is_coerced_to_text(self):
        rule = rule_from_yaml(PER_EVENT.replace("fields: [host, user]",
                                                "fields: [dest_port]"))
        self.assertEqual(("dest_port", "443"),
                         entity_for(rule, event(dest_port=443)))

    def test_an_ungrouped_threshold_alert_ignores_arrival_order(self):
        # With no group_by the window spans every host, so an alert's events
        # can carry several entity values. The entity must come from the event
        # SET, not from whichever same-timestamp event arrived last, or the
        # same window re-detected in another order is a second alert.
        rule = rule_from_yaml(UNGROUPED)
        events = [event(event_id=4625, host=h, record_id=i, timestamp=T0)
                  for i, h in enumerate(("PC-A", "PC-B", "PC-C"))]
        forward = run_rules(events, [rule])[0]
        backward = run_rules(list(reversed(events)), [rule])[0]
        self.assertEqual(1, len(forward))
        self.assertEqual(forward[0].entity_value, backward[0].entity_value)
        self.assertEqual(forward[0].alert_hash, backward[0].alert_hash)


class TestAlertHash(unittest.TestCase):
    def test_the_same_alert_hashes_the_same(self):
        ev = event(event_id=1102)
        rule = rule_from_yaml(PER_EVENT)
        first = run_rules([ev], [rule])[0][0]
        second = run_rules([ev], [rule])[0][0]
        self.assertEqual(first.alert_hash, second.alert_hash)

    def test_a_different_entity_hashes_differently(self):
        rule = rule_from_yaml(PER_EVENT)
        a = run_rules([event(event_id=1102, host="PC-01")], [rule])[0][0]
        b = run_rules([event(event_id=1102, host="PC-02",
                             record_id=2)], [rule])[0][0]
        self.assertNotEqual(a.alert_hash, b.alert_hash)

    def test_a_different_event_set_hashes_differently(self):
        rule = rule_from_yaml(PER_EVENT)
        a = run_rules([event(event_id=1102, record_id=1)], [rule])[0][0]
        b = run_rules([event(event_id=1102, record_id=2)], [rule])[0][0]
        self.assertNotEqual(a.alert_hash, b.alert_hash)

    def test_a_different_rule_hashes_differently(self):
        ev = event(event_id=1102)
        a = run_rules([ev], [rule_from_yaml(PER_EVENT)])[0][0]
        b = run_rules([ev], [rule_from_yaml(
            PER_EVENT.replace("log-cleared", "log-cleared-2"))])[0][0]
        self.assertNotEqual(a.alert_hash, b.alert_hash)

    def test_event_order_does_not_change_the_hash(self):
        # The tracker already returns a window in timestamp order, so a
        # reordered feed is the same alert before the hash is involved.
        rule = rule_from_yaml(THRESHOLD)
        events = burst(3)
        forward = run_rules(events, [rule])[0][0]
        backward = run_rules(list(reversed(events)), [rule])[0][0]
        self.assertEqual(forward.alert_hash, backward.alert_hash)

    def test_the_hash_sorts_its_components(self):
        # The engine now stores event_hashes in a canonical order, so the
        # hash's own sort is reachable only for an alert built another way
        # (a plugin's make_alert): reorder one by hand.
        alert = run_rules(burst(3), [rule_from_yaml(THRESHOLD)])[0][0]
        reordered = replace(alert, event_hashes=alert.event_hashes[::-1])
        self.assertNotEqual(alert.event_hashes, reordered.event_hashes)
        self.assertEqual(alert.alert_hash, reordered.alert_hash)

    def test_tied_events_are_stored_in_the_same_order_whatever_arrived_first(self):
        # Task 6 dedups on alert_hash, which sorts, so a differing order never
        # duplicates a row, but the stored evidence text must not change
        # between two detections of the same alert.
        rule = rule_from_yaml(THRESHOLD)
        events = [replace(e, timestamp=T0) for e in burst(3)]
        forward = run_rules(events, [rule])[0][0]
        backward = run_rules(list(reversed(events)), [rule])[0][0]
        self.assertEqual(forward.event_hashes, backward.event_hashes)
        self.assertEqual(forward.evidence, backward.evidence)

    def test_the_alert_is_frozen(self):
        alert = run_rules([event(event_id=1102)],
                          [rule_from_yaml(PER_EVENT)])[0][0]
        self.assertIsInstance(alert, RuleAlert)
        with self.assertRaises(Exception):
            alert.severity = "LOW"


class TestSeverityWeights(unittest.TestCase):
    def test_the_weights_cover_exactly_the_loader_severities(self):
        self.assertEqual(set(SEVERITIES), set(SEVERITY_WEIGHTS))

    def test_the_weights_are_the_spec_values(self):
        self.assertEqual({"INFO": 1, "LOW": 2, "MEDIUM": 4, "HIGH": 8,
                          "CRITICAL": 16}, SEVERITY_WEIGHTS)


class TestRobustness(unittest.TestCase):
    def broken(self, **changes):
        """A loaded rule altered the way only code can: the loader rejects these."""
        return replace(rule_from_yaml(PER_EVENT), id="broken", **changes)

    def test_a_rule_that_raises_does_not_stop_the_other_rules(self):
        # The loader refuses a bad selection, so build one the way code can.
        bad = self.broken(selections={"sel": {"no_such_field": 1}})
        alerts, failures = run_rules([event(event_id=1102)],
                                     [bad, rule_from_yaml(PER_EVENT)])
        self.assertEqual(["log-cleared"], [a.rule_id for a in alerts])
        self.assertEqual(1, len(failures), "the bad rule must be reported")
        self.assertEqual("broken", failures[0][0])
        self.assertIn("no_such_field", failures[0][1])

    def test_a_failing_rule_is_reported_once_not_once_per_event(self):
        bad = self.broken(selections={"sel": {"no_such_field": 1}})
        events = [event(event_id=1102, record_id=i) for i in range(50)]
        alerts, failures = run_rules(events, [bad, rule_from_yaml(PER_EVENT)])
        self.assertEqual(1, len(failures))
        self.assertEqual(50, len(alerts), "the good rule still sees every event")

    def test_one_bad_event_does_not_silence_the_rule_for_the_rest(self):
        # hour_in needs a datetime, so only the middle event makes this rule
        # raise: a failure caused by the event, not by the rule.
        rule = rule_from_yaml(PER_EVENT.replace(
            "event_id: 1102", "event_id: 1102\n    timestamp|hour_in: ['0..23']"))
        events = [event(event_id=1102, record_id=i) for i in range(3)]
        events[1] = replace(events[1], timestamp="not a time")
        alerts, failures = run_rules(events, [rule])
        self.assertEqual([events[0].event_hash, events[2].event_hash],
                         [a.event_hashes[0] for a in alerts])
        self.assertEqual(1, len(failures))
        self.assertEqual("log-cleared", failures[0][0])

    def test_two_failing_rules_are_two_failures(self):
        a = self.broken(selections={"sel": {"no_such_field": 1}})
        b = replace(a, id="broken-2")
        _, failures = run_rules([event(), event(record_id=2)], [a, b])
        self.assertEqual(["broken", "broken-2"], [f[0] for f in failures])

    def test_any_exception_type_is_caught_and_names_its_type(self):
        bad = self.broken(condition=Raises())
        alerts, failures = run_rules([event(event_id=1102)],
                                     [bad, rule_from_yaml(PER_EVENT)])
        self.assertEqual(1, len(alerts))
        self.assertEqual([("broken", "RuntimeError: boom")], failures)

    def test_a_threshold_rule_that_cannot_build_its_tracker_is_a_failure(self):
        bad = replace(rule_from_yaml(THRESHOLD), timeframe=None)
        alerts, failures = run_rules(burst(3), [bad])
        self.assertEqual([], alerts)
        self.assertEqual(["brute-force"], [f[0] for f in failures])

    def test_a_failure_message_is_one_line(self):
        bad = self.broken(condition=Raises("one\ntwo\r\nthree"))
        _, failures = run_rules([event()], [bad])
        self.assertEqual("RuntimeError: one two three", failures[0][1])

    def test_an_empty_rule_list_is_not_an_error(self):
        self.assertEqual(([], []), run_rules([event()], []))

    def test_an_empty_event_list_is_not_an_error(self):
        self.assertEqual(([], []), run_rules([], [rule_from_yaml(PER_EVENT)]))

    def test_events_may_be_a_one_shot_iterator(self):
        second = rule_from_yaml(PER_EVENT.replace("log-cleared", "second"))
        alerts, _ = run_rules(iter([event(event_id=1102)]),
                              [rule_from_yaml(PER_EVENT), second])
        self.assertEqual(2, len(alerts))

    def test_plugins_are_refused_until_they_exist(self):
        # Silently ignoring them would drop detections without a word.
        with self.assertRaises(NotImplementedError):
            run_rules([], [], plugins=[object()])


if __name__ == "__main__":
    unittest.main()

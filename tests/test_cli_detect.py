import json
import re
import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta
from unittest import mock

import cli
from cli.commands import detect as detect_command
from cli.commands import rules as rules_command
from core import store
from tests.helpers_rules import event
from tests.test_cli_rules import SINGLE_EVENT, RulesCase
from tests.test_rule_loader_yaml import VALID

LOGON_RULE = SINGLE_EVENT.replace("win-log-cleared", "win-logon").replace(
    "event_id: 1102", "event_id: 4624")

# VALID's brute-force rule with the threshold lowered, so four events do it.
BURST_OF_3 = VALID.replace("gte: 5", "gte: 3")


def broken(rule):
    """`rule` with a selection naming a field that is not an event field."""
    return replace(rule, selections={"sel": {"no_such_field": 1}})


ANSI = re.compile(r"\033\[[0-9;]*m")


def minutes_ago(n):
    return datetime.now() - timedelta(minutes=n)


class DetectCase(RulesCase):
    """RulesCase's `pack` is the brute-force rule; detect's tests want a rule
    that one event can fire, so the packs are rebuilt here."""

    def setUp(self):
        super().setUp()
        self.pack = self.make_pack(rule=SINGLE_EVENT)
        self.mixed = self.make_pack(good=SINGLE_EVENT, bad="not: a rule\n")
        self.two = self.make_pack(a=SINGLE_EVENT, b=LOGON_RULE)
        self.burst = self.make_pack(rule=BURST_OF_3)

    def detect(self, *extra, pack=None, json_mode=False):
        argv = (["--json"] if json_mode else []) + [
            "detect", "--rules-dir", pack or self.pack] + list(extra)
        return self.run_cli_split(argv)

    def stored_alerts(self):
        return store.query_alerts(self.conn, limit=None)


class TestDetectParser(DetectCase):
    def test_defaults(self):
        args = cli.build_parser().parse_args(["detect"])
        self.assertEqual("24h", args.since)
        # A store filter: None, never "" (cli/__init__.py).
        self.assertIsNone(args.until)
        self.assertIsNone(args.rule)
        self.assertEqual(rules_command.DEFAULT_RULES_DIR, args.rules_dir)

    def test_an_until_before_since_is_a_usage_error_naming_both(self):
        # Swapped flags read nothing, which would look like a quiet window.
        code, out, _ = self.detect("--since", "1h", "--until", "2h")
        self.assertEqual(2, code)
        self.assertIn("--until", out)
        self.assertIn("--since", out)

    def test_a_bad_since_is_a_usage_error(self):
        code, _, _ = self.detect("--since", "yesterday")
        self.assertEqual(2, code)


class TestDetect(DetectCase):
    def test_a_matching_event_produces_a_stored_alert(self):
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        code, _, _ = self.detect()
        self.assertEqual(0, code)
        self.assertEqual(["win-log-cleared"], [a["rule_id"] for a in self.stored_alerts()])

    def test_nothing_matching_is_still_exit_0(self):
        # A quiet window is a successful detection run, not a failure.
        self.seed([event(event_id=4625, timestamp=minutes_ago(5))])
        code, _, _ = self.detect()
        self.assertEqual(0, code)
        self.assertEqual([], self.stored_alerts())

    def test_running_twice_does_not_duplicate_alerts(self):
        # `detect --since 24h` is expected to be re-run.
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        for _ in range(2):
            self.detect()
        self.assertEqual(1, len(self.stored_alerts()))

    def test_the_default_window_is_24_hours(self):
        old = event(event_id=1102, record_id=1, timestamp=datetime.now() - timedelta(days=2))
        new = event(event_id=1102, record_id=2, timestamp=minutes_ago(5))
        self.seed([old, new])
        self.detect()
        self.assertEqual(1, len(self.stored_alerts()))

    def test_since_bounds_the_event_window(self):
        old = event(event_id=1102, record_id=1, timestamp=datetime.now() - timedelta(days=40))
        new = event(event_id=1102, record_id=2, timestamp=minutes_ago(5))
        self.seed([old, new])
        self.detect("--since", "1h")
        self.assertEqual(1, len(self.stored_alerts()))

    def test_until_bounds_the_event_window(self):
        early = event(event_id=1102, record_id=1, timestamp=minutes_ago(120))
        late = event(event_id=1102, record_id=2, timestamp=minutes_ago(5))
        self.seed([early, late])
        self.detect("--since", "1d", "--until", "1h")
        alerts = self.stored_alerts()
        self.assertEqual(1, len(alerts))
        self.assertEqual(early.timestamp.isoformat(sep=" "), alerts[0]["timestamp"])

    def test_the_whole_window_is_read_not_the_newest_1000(self):
        # query_events caps at 1000 by default; detect must pass limit=None or
        # it silently misses everything older.
        start = minutes_ago(60)
        self.seed([event(event_id=1102, record_id=i, timestamp=start + timedelta(seconds=i))
                   for i in range(1100)])
        self.detect()
        self.assertEqual(1100, len(self.stored_alerts()))

    def test_events_reach_the_threshold_tracker_oldest_first(self):
        # Four failures a minute apart, three needed. Oldest first, the burst
        # is minutes 0-2 and the fourth event starts a new window. Newest first,
        # it is minutes 1-3: the alert is stamped a minute later.
        start = minutes_ago(60)
        self.seed([event(event_id=4625, record_id=i, source_ip="1.2.3.4",
                         target_user="alice", timestamp=start + timedelta(minutes=i))
                   for i in range(4)])
        code, _, _ = self.detect(pack=self.burst)
        self.assertEqual(0, code)
        alerts = self.stored_alerts()
        self.assertEqual(1, len(alerts))
        self.assertEqual((start + timedelta(minutes=2)).isoformat(sep=" "),
                         alerts[0]["timestamp"])


class TestDetectRuleSelection(DetectCase):
    def test_rule_selects_a_single_rule(self):
        self.seed([event(event_id=1102, record_id=1, timestamp=minutes_ago(5)),
                   event(event_id=4624, record_id=2, timestamp=minutes_ago(5))])
        code, _, _ = self.detect("--rule", "win-logon", pack=self.two)
        self.assertEqual(0, code)
        self.assertEqual(["win-logon"], [a["rule_id"] for a in self.stored_alerts()])

    def test_without_rule_every_rule_runs(self):
        self.seed([event(event_id=1102, record_id=1, timestamp=minutes_ago(5)),
                   event(event_id=4624, record_id=2, timestamp=minutes_ago(5))])
        self.detect(pack=self.two)
        self.assertEqual({"win-log-cleared", "win-logon"},
                         {a["rule_id"] for a in self.stored_alerts()})

    def test_an_unknown_rule_exits_1_and_names_the_id(self):
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        code, out, _ = self.detect("--rule", "nope")
        self.assertEqual(1, code, "an unknown --rule must not look like success")
        self.assertIn("'nope'", out)
        self.assertEqual([], self.stored_alerts())

    def test_an_unknown_rule_in_json_mode_is_still_json(self):
        code, out, _ = self.detect("--rule", "nope", json_mode=True)
        self.assertEqual(1, code)
        self.assertIn("'nope'", json.loads(out)["error"])


class TestDetectFailures(DetectCase):
    def test_a_rejected_rule_file_exits_3_but_still_detects(self):
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        code, out, _ = self.detect(pack=self.mixed)
        self.assertEqual(3, code)
        self.assertIn("bad.yml", out)
        self.assertEqual(1, len(self.stored_alerts()))

    def test_a_rule_that_fails_at_match_time_exits_3_and_is_named(self):
        # The loader refuses every selection it can see is bad, so a match-time
        # failure needs a rule built the way only code can (as test_rule_engine
        # does): the real engine runs, only the loader's output is altered.
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        good, _ = detect_command.load_rules(self.pack)
        with mock.patch.object(detect_command, "load_rules",
                               return_value=([broken(good[0])], [])):
            code, out, _ = self.detect()
        self.assertEqual(3, code)
        self.assertIn("win-log-cleared", out)
        self.assertIn("no_such_field", out)
        self.assertEqual([], self.stored_alerts())

    def test_a_failing_rule_does_not_stop_the_others(self):
        self.seed([event(event_id=4624, timestamp=minutes_ago(5))])
        good, _ = detect_command.load_rules(self.two)
        pack = [broken(good[0]), good[1]]
        with mock.patch.object(detect_command, "load_rules", return_value=(pack, [])):
            code, _, _ = self.detect()
        self.assertEqual(3, code)
        self.assertEqual(["win-logon"], [a["rule_id"] for a in self.stored_alerts()])

    def test_no_rules_at_all_exits_1(self):
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        code, out, _ = self.detect(pack=self.empty)
        self.assertEqual(1, code)
        self.assertIn("No rules loaded", out)

    def test_a_pack_where_every_file_is_rejected_exits_1_naming_them(self):
        code, out, _ = self.detect(pack=self.allbad)
        self.assertEqual(1, code)
        self.assertIn("bad.yml", out)

    def test_a_missing_rules_dir_exits_1(self):
        code, _, _ = self.detect(pack="no/such/dir")
        self.assertEqual(1, code)


class TestDetectOutput(DetectCase):
    def test_json_output_is_parseable_and_counts_what_happened(self):
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        code, out, _ = self.detect(json_mode=True)
        self.assertEqual(0, code)
        payload = json.loads(out)
        self.assertEqual(1, payload["events_read"])
        self.assertEqual(1, payload["alerts_new"])
        self.assertEqual(0, payload["alerts_duplicate"])
        self.assertEqual([], payload["rule_errors"])
        self.assertEqual([], payload["rule_failures"])

    def test_a_second_run_reports_the_duplicate_rather_than_hiding_it(self):
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        self.detect()
        _, out, _ = self.detect(json_mode=True)
        payload = json.loads(out)
        self.assertEqual(0, payload["alerts_new"])
        self.assertEqual(1, payload["alerts_duplicate"])

    def test_json_keeps_stdout_clean_and_sends_warnings_to_stderr(self):
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        code, out, err = self.detect(pack=self.mixed, json_mode=True)
        self.assertEqual(3, code)
        payload = json.loads(out)
        self.assertEqual(1, len(payload["rule_errors"]))
        self.assertIn("bad.yml", payload["rule_errors"][0]["message"])
        self.assertIn("bad.yml", err)

    def test_match_time_failures_are_in_the_json(self):
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        good, _ = detect_command.load_rules(self.pack)
        with mock.patch.object(detect_command, "load_rules",
                               return_value=([broken(good[0])], [])):
            _, out, _ = self.detect(json_mode=True)
        failures = json.loads(out)["rule_failures"]
        self.assertEqual(["win-log-cleared"], [f["rule_id"] for f in failures])
        self.assertIn("no_such_field", failures[0]["message"])

    def test_an_empty_store_exits_0_and_says_there_was_nothing_to_do(self):
        self.seed([])
        code, out, _ = self.detect()
        self.assertEqual(0, code)
        self.assertRegex(out, r"Events read\s*: 0\b")
        self.assertRegex(out, r"Alerts new\s*: 0\b")

    def test_text_output_reports_events_new_and_duplicate_alerts(self):
        self.seed([event(event_id=1102, record_id=1, timestamp=minutes_ago(5)),
                   event(event_id=4624, record_id=2, timestamp=minutes_ago(5))])
        _, out, _ = self.detect()
        self.assertRegex(out, r"Events read\s*: 2\b")
        self.assertRegex(out, r"Alerts new\s*: 1\b")
        self.assertRegex(out, r"Alerts duplicate\s*: 0\b")
        _, out, _ = self.detect()
        self.assertRegex(out, r"Alerts new\s*: 0\b")
        self.assertRegex(out, r"Alerts duplicate\s*: 1\b")


class TestDetectCorrelates(DetectCase):
    def two_alerts_one_host(self):
        # Two 1102 events, 10 minutes apart, same host: one incident, and the
        # second alert joins it.
        self.seed([event(event_id=1102, record_id=1, timestamp=minutes_ago(20)),
                   event(event_id=1102, record_id=2, timestamp=minutes_ago(10))])

    def test_detect_opens_an_incident(self):
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        code, _, _ = self.detect()
        self.assertEqual(0, code)
        incidents = store.query_incidents(self.conn)
        self.assertEqual(1, len(incidents))
        self.assertEqual([incidents[0]["id"]],
                         [a["incident_id"] for a in self.stored_alerts()])

    def test_no_correlate_skips_it(self):
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        code, _, _ = self.detect("--no-correlate")
        self.assertEqual(0, code)
        self.assertEqual(0, len(store.query_incidents(self.conn)))
        self.assertEqual(1, len(self.stored_alerts()),
                         "the alert still persists; only grouping is skipped")

    def test_no_correlate_then_a_normal_run_groups_what_was_skipped(self):
        # correlate repairs "stored but never attached", so skipping is not lossy.
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        self.detect("--no-correlate")
        self.detect()
        self.assertEqual(1, len(store.query_incidents(self.conn)))

    def test_running_twice_does_not_open_a_second_incident(self):
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        for _ in range(2):
            self.detect()
        self.assertEqual(1, len(store.query_incidents(self.conn)))

    def test_json_reports_the_incident_counts(self):
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        _, out, _ = self.detect(json_mode=True)
        payload = json.loads(out)
        self.assertEqual(1, payload["incidents_opened"])
        self.assertEqual(0, payload["incidents_attached"])
        self.assertEqual(1, payload["alerts_new"],
                         "correlating first would store the alert inside correlate "
                         "and leave the insert below it reporting 0 new")

    def test_attached_counts_alerts_joining_an_open_incident_not_the_one_opening_it(self):
        # R89: two alerts, one incident: opened 1, attached 1 (not 2).
        self.two_alerts_one_host()
        _, out, _ = self.detect(json_mode=True)
        payload = json.loads(out)
        self.assertEqual((1, 1), (payload["incidents_opened"], payload["incidents_attached"]))
        self.assertEqual(1, len(store.query_incidents(self.conn)))

    def test_a_second_run_reports_nothing_opened_or_attached(self):
        self.two_alerts_one_host()
        self.detect()
        _, out, _ = self.detect(json_mode=True)
        payload = json.loads(out)
        self.assertEqual((0, 0), (payload["incidents_opened"], payload["incidents_attached"]))
        self.assertEqual(2, payload["alerts_duplicate"])

    def test_json_says_null_not_zero_when_correlation_was_skipped(self):
        # 0 would claim "correlated, found nothing to group".
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        _, out, _ = self.detect("--no-correlate", json_mode=True)
        payload = json.loads(out)
        self.assertIsNone(payload["incidents_opened"])
        self.assertIsNone(payload["incidents_attached"])

    def test_text_summary_explains_what_attached_counts(self):
        self.two_alerts_one_host()
        _, out, _ = self.detect()
        self.assertRegex(out, r"Incidents opened\s*: 1\b")
        self.assertRegex(out, r"Alerts attached\s*: 1\b")
        self.assertRegex(out, r"already open")
        self.assertIn("not counted", out)

    def test_no_line_of_the_summary_is_wider_than_a_default_terminal(self):
        # The attached-count prose is what R89 exists to provide; wrapped at
        # 80 columns it stops being readable.
        self.two_alerts_one_host()
        _, out, _ = self.detect()
        widest = max(len(ANSI.sub("", line)) for line in out.splitlines())
        self.assertLessEqual(widest, 80)

    def test_text_summary_says_when_correlation_was_skipped(self):
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        _, out, _ = self.detect("--no-correlate")
        self.assertRegex(out, r"Incidents\s*: skipped")
        self.assertNotRegex(out, r"Incidents opened")

    def test_unrelated_hosts_with_no_recorded_user_are_not_one_incident(self):
        # R90: the entity is the rule's first declared field, `user`, which a
        # log clear often does not record ("-"). Without the fallback to the
        # next declared field every such alert shares ("user", "-") and the
        # correlator merges two machines into one CRITICAL incident.
        pack = self.make_pack(rule=SINGLE_EVENT.replace(
            "fields: [host]", "fields: [user, host]"))
        self.seed([event(event_id=1102, host="PC-A", record_id=1, timestamp=minutes_ago(9)),
                   event(event_id=1102, host="PC-B", record_id=2, timestamp=minutes_ago(8))])
        code, _, _ = self.detect(pack=pack)
        self.assertEqual(0, code)
        incidents = store.query_incidents(self.conn)
        self.assertEqual(["PC-A", "PC-B"], sorted(i["entity_value"] for i in incidents))
        self.assertEqual({"host"}, {i["entity_type"] for i in incidents})

    def test_the_same_host_with_no_recorded_user_is_still_one_incident(self):
        pack = self.make_pack(rule=SINGLE_EVENT.replace(
            "fields: [host]", "fields: [user, host]"))
        self.seed([event(event_id=1102, host="PC-A", record_id=1, timestamp=minutes_ago(9)),
                   event(event_id=1102, host="PC-A", record_id=2, timestamp=minutes_ago(8))])
        self.detect(pack=pack)
        self.assertEqual(1, len(store.query_incidents(self.conn)))

    def test_detect_does_not_close_idle_incidents(self):
        # Closing is time-based. Run over `--since 90d`, detect would close
        # incidents that are current, so it belongs to `siem incidents`.
        old = store.open_incident(
            self.conn, minutes_ago(600), minutes_ago(300), "host", "OLD-HOST", "HIGH")
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        self.detect()
        self.assertEqual("OPEN", store.query_incidents(self.conn, incident_id=old)[0]["status"])

    def test_a_quiet_window_opens_nothing_and_exits_0(self):
        self.seed([event(event_id=4625, timestamp=minutes_ago(5))])
        code, out, _ = self.detect(json_mode=True)
        payload = json.loads(out)
        self.assertEqual(0, code)
        self.assertEqual((0, 0), (payload["incidents_opened"], payload["incidents_attached"]))


class TestDetectCorrelationFailure(DetectCase):
    """Correlation failing must not lose the alerts, and must not look clean."""

    def failing(self, exc):
        return mock.patch.object(detect_command, "correlate", side_effect=exc)

    def run_failing(self, exc, json_mode=False):
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        with self.failing(exc):
            return self.detect(json_mode=json_mode)

    def test_the_alerts_are_stored_and_the_run_exits_3(self):
        code, out, _ = self.run_failing(sqlite3.OperationalError("database is locked"))
        self.assertEqual(3, code)
        self.assertEqual(1, len(self.stored_alerts()))
        self.assertIn("database is locked", out)
        self.assertRegex(out, r"Alerts new\s*: 1\b")

    def test_a_non_sqlite_failure_is_not_mistaken_for_a_usage_error(self):
        # dispatch turns a ValueError into exit 2 "bad argument". A correlator
        # bug that raised one would be reported as the user's mistake.
        code, out, _ = self.run_failing(ValueError("max() arg is an empty sequence"))
        self.assertEqual(3, code)
        self.assertEqual(1, len(self.stored_alerts()))

    def test_json_stays_json_and_names_the_failure(self):
        code, out, _ = self.run_failing(sqlite3.OperationalError("locked"), json_mode=True)
        payload = json.loads(out)
        self.assertEqual(3, code)
        self.assertIn("locked", payload["correlation_error"])
        self.assertEqual(1, payload["alerts_new"])
        self.assertIsNone(payload["incidents_opened"])

    def test_a_clean_run_has_no_correlation_error(self):
        self.seed([event(event_id=1102, timestamp=minutes_ago(5))])
        _, out, _ = self.detect(json_mode=True)
        self.assertIsNone(json.loads(out)["correlation_error"])

    def test_the_next_run_repairs_it(self):
        self.run_failing(sqlite3.OperationalError("locked"))
        self.assertEqual(0, len(store.query_incidents(self.conn)))
        code, _, _ = self.detect()
        self.assertEqual(0, code)
        self.assertEqual(1, len(store.query_incidents(self.conn)))

#!/usr/bin/env python3
"""Plugin rules: the two ordered-sequence rules, PluginRule and load_plugins.

Offsets in these tests are literal timedeltas, never derived from the rule's own
window constants: a test that scaled its inputs by the constant under test would
pass whatever the constant said.

Events are shaped as the normalizer shapes them: a 4672 carries its account in
`user` (SubjectUserName) and has no target_user; a 4720 carries the new account
in target_user and its creator in user.
"""

import json
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

from core import store
from core.correlator import correlate
from core.rule_engine.engine import (SEVERITY_WEIGHTS, PluginRule, RuleAlert,
                                     load_plugins, run_rules)
from core.rule_engine.loader import RuleError
from tests import helpers_rules, test_cli_detect
from tests.helpers_rules import T0

MIN = timedelta(minutes=1)


class TestSuccessfulLogonAfterBurst(unittest.TestCase):
    def rule(self):
        from rules.plugins.successful_logon_after_burst import Rule
        return Rule()

    def fails(self, count, ip="1.2.3.4", user="alice", start=T0, step=10, **kw):
        return [helpers_rules.event(**dict(
            dict(event_id=4625, action="LOGIN_FAIL", source_ip=ip, target_user=user,
                 record_id=100 + i, timestamp=start + timedelta(seconds=i * step)), **kw))
            for i in range(count)]

    def ok(self, ip="1.2.3.4", user="alice", at=None, record_id=200, **kw):
        return helpers_rules.event(**dict(
            dict(event_id=4624, action="LOGIN_OK", source_ip=ip, target_user=user,
                 record_id=record_id, timestamp=at or (T0 + MIN)), **kw))

    def test_a_success_after_a_burst_fires(self):
        alerts = self.rule().evaluate(self.fails(5) + [self.ok()])
        self.assertEqual(1, len(alerts))
        self.assertEqual("1.2.3.4", alerts[0].entity_value)
        self.assertEqual("ip", alerts[0].entity_type)

    def test_the_alert_covers_the_burst_and_the_success(self):
        events = self.fails(5) + [self.ok()]
        alerts = self.rule().evaluate(events)
        self.assertEqual(6, len(alerts[0].event_hashes))
        self.assertEqual({e.event_hash for e in events}, set(alerts[0].event_hashes))

    def test_a_success_with_no_preceding_burst_does_not_fire(self):
        self.assertEqual([], self.rule().evaluate([self.ok()]))

    def test_a_burst_with_no_success_does_not_fire(self):
        self.assertEqual([], self.rule().evaluate(self.fails(5)))

    def test_four_failures_are_not_a_burst(self):
        self.assertEqual([], self.rule().evaluate(self.fails(4) + [self.ok()]))

    def test_five_failures_spread_over_eight_minutes_are_not_a_burst(self):
        self.assertEqual([], self.rule().evaluate(
            self.fails(5, step=120) + [self.ok(at=T0 + 9 * MIN)]))

    def test_five_failures_spanning_just_over_five_minutes_are_not_a_burst(self):
        self.assertEqual([], self.rule().evaluate(
            self.fails(5, step=76) + [self.ok(at=T0 + 6 * MIN)]))

    def test_five_failures_spanning_exactly_five_minutes_are_a_burst(self):
        self.assertEqual(1, len(self.rule().evaluate(
            self.fails(5, step=75) + [self.ok(at=T0 + 6 * MIN)])))

    def test_the_order_matters(self):
        # Success first, then failures, is a different story entirely.
        events = [self.ok(at=T0)] + self.fails(5, start=T0 + MIN)
        self.assertEqual([], self.rule().evaluate(events))

    def test_the_order_is_the_timestamp_order_not_the_list_order(self):
        # A run over several channels can interleave them. The success is
        # listed first but happened after the burst: that is the detection.
        events = [self.ok()] + self.fails(5)
        self.assertEqual(1, len(self.rule().evaluate(events)))

    def test_a_success_listed_last_but_older_than_the_burst_does_not_fire(self):
        events = self.fails(5, start=T0 + MIN) + [self.ok(at=T0)]
        self.assertEqual([], self.rule().evaluate(events))

    def test_a_success_for_a_different_user_does_not_fire(self):
        self.assertEqual([], self.rule().evaluate(
            self.fails(5) + [self.ok(user="bob")]))

    def test_the_user_is_compared_without_regard_to_case(self):
        self.assertEqual(1, len(self.rule().evaluate(
            self.fails(5, user="Alice") + [self.ok(user="aLICE")])))

    def test_a_success_from_a_different_ip_does_not_fire(self):
        self.assertEqual([], self.rule().evaluate(
            self.fails(5) + [self.ok(ip="9.9.9.9")]))

    def test_a_success_long_after_the_burst_does_not_fire(self):
        self.assertEqual([], self.rule().evaluate(
            self.fails(5) + [self.ok(at=T0 + timedelta(hours=3))]))

    def test_the_follow_up_window_is_thirty_minutes_from_the_last_failure(self):
        last_failure = T0 + timedelta(seconds=40)
        inside = self.ok(at=last_failure + timedelta(minutes=30))
        outside = self.ok(at=last_failure + timedelta(minutes=30, seconds=1))
        self.assertEqual(1, len(self.rule().evaluate(self.fails(5) + [inside])))
        self.assertEqual([], self.rule().evaluate(self.fails(5) + [outside]))

    def test_it_fires_once_not_once_per_subsequent_success(self):
        events = self.fails(5) + [
            self.ok(at=T0 + MIN),
            self.ok(at=T0 + 2 * MIN, record_id=201),
        ]
        self.assertEqual(1, len(self.rule().evaluate(events)))

    def test_a_second_burst_arms_it_again(self):
        events = (self.fails(5) + [self.ok()]
                  + self.fails(5, start=T0 + timedelta(hours=2))
                  + [self.ok(at=T0 + timedelta(hours=2, minutes=1), record_id=202)])
        self.assertEqual(2, len(self.rule().evaluate(events)))

    def test_unrecorded_addresses_do_not_pool_into_one_burst(self):
        # Windows writes "-" for NTLM and Kerberos pass-through. Five failures
        # for one name from five unrelated machines are not one source.
        events = self.fails(5, ip="-") + [self.ok(ip="-")]
        self.assertEqual([], self.rule().evaluate(events))

    def test_events_forged_into_another_channel_do_not_fire(self):
        # 4625/4624 written to Application normalise to action OTHER.
        forged_fails = self.fails(5, action="OTHER", channel="Application")
        forged_ok = self.ok(action="OTHER", channel="Application")
        self.assertEqual([], self.rule().evaluate(forged_fails + [self.ok()]))
        self.assertEqual([], self.rule().evaluate(self.fails(5) + [forged_ok]))

    def test_other_event_ids_with_the_same_action_do_not_count(self):
        # An SSH failure carries LOGIN_FAIL too, with no EventID 4625.
        ssh = self.fails(5, event_id=0, source_type="ssh")
        self.assertEqual([], self.rule().evaluate(ssh + [self.ok()]))

    def test_an_ssh_success_does_not_complete_a_windows_burst(self):
        # The legacy parser emits LOGIN_OK with event_id 0 for an SSH logon.
        ssh_ok = self.ok(event_id=0, source_type="ssh")
        self.assertEqual([], self.rule().evaluate(self.fails(5) + [ssh_ok]))

    def test_service_account_failures_are_not_a_burst(self):
        # win-failed-logon-burst ignores these; the CRITICAL rule must agree.
        for name in ("dwm-1", "UMFD-0", "HealthMailbox0a1b2c"):
            events = self.fails(5, user=name) + [self.ok(user=name)]
            self.assertEqual([], self.rule().evaluate(events), name)

    def test_the_service_account_filter_matches_whole_names_only(self):
        # Prefixes, suffixes and a trailing newline are ordinary accounts, and
        # a guesser chooses the name it tries.
        for name in ("umfd-1bob", "xdwm-1", "dwm-1\n", "healthmailbox"):
            events = self.fails(5, user=name) + [self.ok(user=name)]
            self.assertEqual(1, len(self.rule().evaluate(events)), repr(name))

    def test_unnamed_accounts_do_not_pool_into_one_burst(self):
        events = self.fails(5, user="-") + [self.ok(user="-")]
        self.assertEqual([], self.rule().evaluate(events))
        events = self.fails(5, user="") + [self.ok(user="")]
        self.assertEqual([], self.rule().evaluate(events))

    def test_the_severity_is_higher_than_the_burst_alone(self):
        # A burst is HIGH; a burst that succeeded is the thing you get paged for.
        self.assertEqual("CRITICAL", self.rule().severity)

    def test_the_shipped_metadata(self):
        rule = self.rule()
        self.assertEqual(("win-success-after-burst", "T1110.001", "TA0006", "source_ip"),
                         (rule.id, rule.technique, rule.tactic, rule.entity_field))


class TestNewAccountPrivileged(unittest.TestCase):
    def rule(self):
        from rules.plugins.new_account_privileged import Rule
        return Rule()

    def created(self, user="mallory", at=T0, creator="admin", record_id=1, **kw):
        return helpers_rules.event(**dict(
            dict(event_id=4720, action="ACCOUNT_CREATE", target_user=user, user=creator,
                 record_id=record_id, timestamp=at), **kw))

    def privileged(self, user="mallory", at=T0 + 2 * MIN, record_id=2, **kw):
        # As the normalizer shapes 4672: SubjectUserName -> user, no target_user.
        return helpers_rules.event(**dict(
            dict(event_id=4672, action="PRIVILEGE_ASSIGN", user=user,
                 record_id=record_id, timestamp=at), **kw))

    def test_a_privilege_assignment_to_a_newly_created_account_fires(self):
        alerts = self.rule().evaluate([self.created(), self.privileged()])
        self.assertEqual(1, len(alerts))
        self.assertEqual("mallory", alerts[0].entity_value)
        self.assertEqual("user", alerts[0].entity_type)

    def test_the_alert_covers_the_creation_and_the_assignment(self):
        events = [self.created(), self.privileged()]
        alerts = self.rule().evaluate(events)
        self.assertEqual({e.event_hash for e in events}, set(alerts[0].event_hashes))

    def test_a_privilege_assignment_to_an_existing_account_does_not_fire(self):
        self.assertEqual([], self.rule().evaluate([
            self.privileged(user="administrator", at=T0)]))

    def test_the_order_matters(self):
        events = [self.privileged(at=T0), self.created(at=T0 + 2 * MIN)]
        self.assertEqual([], self.rule().evaluate(events))

    def test_the_order_is_the_timestamp_order_not_the_list_order(self):
        events = [self.privileged(), self.created()]
        self.assertEqual(1, len(self.rule().evaluate(events)))

    def test_outside_the_window_does_not_fire(self):
        events = [self.created(), self.privileged(at=T0 + timedelta(days=2))]
        self.assertEqual([], self.rule().evaluate(events))

    def test_the_window_is_twenty_four_hours(self):
        day = timedelta(hours=24)
        self.assertEqual(1, len(self.rule().evaluate(
            [self.created(), self.privileged(at=T0 + day)])))
        self.assertEqual([], self.rule().evaluate(
            [self.created(), self.privileged(at=T0 + day + timedelta(seconds=1))]))

    def test_a_different_user_does_not_fire(self):
        events = [self.created(), self.privileged(user="alice")]
        self.assertEqual([], self.rule().evaluate(events))

    def test_the_creator_is_not_the_new_account(self):
        # 4720's `user` is who created the account; only target_user is new.
        events = [self.created(user="mallory", creator="admin"),
                  self.privileged(user="admin")]
        self.assertEqual([], self.rule().evaluate(events))

    def test_the_user_is_compared_without_regard_to_case(self):
        events = [self.created(user="Mallory"), self.privileged(user="MALLORY")]
        self.assertEqual(1, len(self.rule().evaluate(events)))

    def test_it_fires_once_per_creation(self):
        events = [self.created(), self.privileged(),
                  self.privileged(at=T0 + 3 * MIN, record_id=3)]
        self.assertEqual(1, len(self.rule().evaluate(events)))

    def test_a_recreated_account_arms_it_again(self):
        events = [self.created(), self.privileged(),
                  self.created(at=T0 + 3 * MIN, record_id=3),
                  self.privileged(at=T0 + 4 * MIN, record_id=4)]
        self.assertEqual(2, len(self.rule().evaluate(events)))

    def test_unnamed_accounts_do_not_pair_up(self):
        events = [self.created(user="-"), self.privileged(user="-")]
        self.assertEqual([], self.rule().evaluate(events))

    def test_events_forged_into_another_channel_do_not_fire(self):
        forged_create = self.created(action="OTHER", channel="Application")
        forged_priv = self.privileged(action="OTHER", channel="Application")
        self.assertEqual([], self.rule().evaluate([forged_create, self.privileged()]))
        self.assertEqual([], self.rule().evaluate([self.created(), forged_priv]))

    def test_the_shipped_metadata(self):
        rule = self.rule()
        self.assertEqual(
            ("win-new-account-privileged", "CRITICAL", "T1098", "TA0004", "target_user"),
            (rule.id, rule.severity, rule.technique, rule.tactic, rule.entity_field))


class _Probe(PluginRule):
    id, title, severity = "probe", "Probe", "MEDIUM"
    technique, tactic, description = "T1000", "TA0001", "A probe.\n  Two lines."
    entity_field = "source_ip"

    def evaluate(self, events):
        return [self.make_alert(events, "9.9.9.9")]


class TestPluginRuleMakeAlert(unittest.TestCase):
    def events(self):
        return [helpers_rules.event(record_id=n, source_ip="9.9.9.9", host="PC-%d" % n,
                                    timestamp=T0 + timedelta(seconds=s))
                for n, s in ((1, 30), (2, 0), (3, 30))]

    def test_the_base_class_has_no_evaluate(self):
        with self.assertRaises(NotImplementedError):
            PluginRule().evaluate([])

    def test_the_alert_has_the_d4_columns(self):
        events = self.events()
        alert = _Probe().make_alert(events, "9.9.9.9")
        self.assertIsInstance(alert, RuleAlert)
        self.assertEqual(("probe", "Probe", "MEDIUM", "ip", "9.9.9.9"),
                         (alert.rule_id, alert.rule_title, alert.severity,
                          alert.entity_type, alert.entity_value))
        self.assertEqual(("T1000", "TA0001"), (alert.technique, alert.tactic))
        self.assertEqual(("Probe", "rule_engine"), (alert.category, alert.source))
        self.assertEqual("A probe. Two lines. (ip: 9.9.9.9)", alert.detail)

    def test_the_alert_is_stamped_with_the_newest_event(self):
        self.assertEqual(T0 + timedelta(seconds=30),
                         _Probe().make_alert(self.events(), "9.9.9.9").timestamp)

    def test_hashes_and_evidence_are_in_timestamp_then_hash_order(self):
        events = self.events()
        alert = _Probe().make_alert(events, "9.9.9.9")
        expected = sorted(events, key=lambda e: (e.timestamp, e.event_hash))
        self.assertEqual(tuple(e.event_hash for e in expected), alert.event_hashes)
        self.assertEqual([e.host for e in expected],
                         [row["host"] for row in json.loads(alert.evidence)])

    def test_the_input_order_does_not_change_the_hash(self):
        events = self.events()
        forward = _Probe().make_alert(events, "9.9.9.9")
        backward = _Probe().make_alert(events[::-1], "9.9.9.9")
        self.assertEqual(forward.alert_hash, backward.alert_hash)
        self.assertEqual(forward.evidence, backward.evidence)

    def test_the_hash_sorts_its_components_for_an_alert_built_another_way(self):
        alert = _Probe().make_alert(self.events(), "9.9.9.9")
        reordered = replace(alert, event_hashes=alert.event_hashes[::-1])
        self.assertNotEqual(alert.event_hashes, reordered.event_hashes)
        self.assertEqual(alert.alert_hash, reordered.alert_hash)

    def test_overrides_replace_columns(self):
        alert = _Probe().make_alert(self.events(), "9.9.9.9", severity="LOW")
        self.assertEqual("LOW", alert.severity)

    def test_a_new_entity_field_name_is_its_own_type(self):
        class Odd(_Probe):
            entity_field = "workstation"
        self.assertEqual("workstation", Odd().make_alert(self.events(), "x").entity_type)


class _Careless(_Probe):
    """A plugin that hands make_alert an entity it does not know."""
    entity = "-"

    def evaluate(self, events):
        return [self.make_alert(events, self.entity)]


class TestMakeAlertUnknownEntity(test_cli_detect.DetectCase):
    """R92: the correlator groups by (entity_type, entity_value), so an entity of
    "-" would merge every such alert, from any host, into one incident. The guard
    is in make_alert so it does not depend on each plugin remembering."""

    def alert(self, host, entity="-", at=T0, record_id=1):
        plugin = _Careless()
        plugin.entity = entity
        return plugin.evaluate([helpers_rules.event(
            host=host, record_id=record_id, timestamp=at, source_ip="-")])[0]

    def test_an_unknown_entity_falls_back_to_the_newest_events_host(self):
        for unknown in ("-", "", None):
            alert = self.alert("PC-A", unknown)
            self.assertEqual(("host", "PC-A"), (alert.entity_type, alert.entity_value), unknown)

    def test_the_newest_event_decides_not_the_first_passed(self):
        plugin = _Careless()
        events = [helpers_rules.event(host="PC-NEW", record_id=1, timestamp=T0 + MIN),
                  helpers_rules.event(host="PC-OLD", record_id=2, timestamp=T0)]
        self.assertEqual("PC-NEW", plugin.evaluate(events)[0].entity_value)

    def test_a_known_entity_is_left_alone(self):
        alert = self.alert("PC-A", "9.9.9.9")
        self.assertEqual(("ip", "9.9.9.9"), (alert.entity_type, alert.entity_value))

    def test_the_detail_names_the_entity_it_fell_back_to(self):
        self.assertTrue(self.alert("PC-A").detail.endswith("(host: PC-A)"))

    def test_two_careless_alerts_from_different_hosts_are_two_incidents(self):
        result = correlate(self.conn, [self.alert("PC-A", record_id=1),
                                       self.alert("PC-B", record_id=2)])
        self.assertEqual((2, 0), (result["opened"], result["attached"]))
        self.assertEqual(["PC-A", "PC-B"], sorted(
            i["entity_value"] for i in store.query_incidents(self.conn)))

    def test_two_careless_alerts_from_one_host_are_still_one_incident(self):
        result = correlate(self.conn, [
            self.alert("PC-A", record_id=1), self.alert("PC-A", at=T0 + MIN, record_id=2)])
        self.assertEqual((1, 1), (result["opened"], result["attached"]))


class TestPluginLoading(unittest.TestCase):
    def directory(self, **files):
        directory = Path(tempfile.mkdtemp())
        for name, text in files.items():
            (directory / name).write_text(text, encoding="utf-8")
        return directory

    GOOD = (
        "from core.rule_engine.engine import PluginRule\n"
        "class Rule(PluginRule):\n"
        "    id, title, severity = {id!r}, 'T', 'LOW'\n"
        "    technique, tactic, description = 'T1', 'TA1', 'd'\n"
        "    entity_field = 'host'\n"
        "    def evaluate(self, events):\n"
        "        return []\n"
    )

    def test_both_shipped_plugins_load(self):
        plugins, errors = load_plugins(Path("rules/plugins"))
        self.assertEqual([], errors)
        self.assertEqual({"win-success-after-burst", "win-new-account-privileged"},
                         {p.id for p in plugins})

    def test_a_plugin_that_fails_to_import_is_an_error_not_a_crash(self):
        directory = self.directory(**{"broken.py": "import nonexistent_module\n"})
        plugins, errors = load_plugins(directory)
        self.assertEqual([], plugins)
        self.assertEqual(1, len(errors))
        self.assertIn("broken", str(errors[0]))
        self.assertIsInstance(errors[0], RuleError)

    def test_a_syntax_error_is_an_error_too(self):
        plugins, errors = load_plugins(self.directory(**{"bad.py": "def (:\n"}))
        self.assertEqual(([], 1), (plugins, len(errors)))

    def test_one_broken_plugin_does_not_hide_the_good_one(self):
        directory = self.directory(**{
            "a_broken.py": "import nonexistent_module\n",
            "b_good.py": self.GOOD.format(id="good")})
        plugins, errors = load_plugins(directory)
        self.assertEqual(["good"], [p.id for p in plugins])
        self.assertEqual(1, len(errors))

    def test_a_module_without_a_Rule_class_is_skipped_quietly(self):
        directory = self.directory(**{"helper.py": "VALUE = 1\n"})
        self.assertEqual(([], []), load_plugins(directory))

    def test_a_Rule_that_is_not_a_PluginRule_is_skipped_quietly(self):
        directory = self.directory(**{"other.py": "class Rule:\n    id = 'x'\n"})
        self.assertEqual(([], []), load_plugins(directory))

    def test_a_Rule_that_cannot_be_constructed_is_an_error(self):
        text = self.GOOD.format(id="x") + "    def __init__(self):\n        raise RuntimeError('no')\n"
        plugins, errors = load_plugins(self.directory(**{"ctor.py": text}))
        self.assertEqual(([], 1), (plugins, len(errors)))

    def test_a_plugin_with_no_id_or_a_bad_severity_is_an_error(self):
        no_id = self.GOOD.format(id="")
        bad_severity = self.GOOD.format(id="x").replace("'LOW'", "'URGENT'")
        for text in (no_id, bad_severity):
            plugins, errors = load_plugins(self.directory(**{"p.py": text}))
            self.assertEqual(([], 1), (plugins, len(errors)), text)
        self.assertIn("URGENT", str(errors[0]))

    def test_two_plugins_with_one_id_keep_the_first(self):
        directory = self.directory(**{"a.py": self.GOOD.format(id="same"),
                                      "b.py": self.GOOD.format(id="same")})
        plugins, errors = load_plugins(directory)
        self.assertEqual(1, len(plugins))
        self.assertEqual(1, len(errors))
        self.assertIn("b.py", str(errors[0]))

    def test_a_missing_directory_is_an_error_not_a_crash(self):
        plugins, errors = load_plugins(Path(tempfile.mkdtemp()) / "nope")
        self.assertEqual(([], 1), (plugins, len(errors)))

    def test_underscore_files_are_not_loaded_as_plugins(self):
        directory = self.directory(**{"_private.py": self.GOOD.format(id="hidden"),
                                      "__init__.py": self.GOOD.format(id="init")})
        self.assertEqual(([], []), load_plugins(directory))

    def test_the_shipped_package_marker_is_not_a_plugin(self):
        plugins, _ = load_plugins(Path("rules/plugins"))
        self.assertNotIn(None, [p.id for p in plugins])
        self.assertEqual(2, len(plugins))

    def test_loading_leaves_no_global_state(self):
        before_path, before_modules = list(sys.path), set(sys.modules)
        directory = self.directory(**{"stateful.py": self.GOOD.format(id="s")})
        plugins, _ = load_plugins(directory)
        self.assertEqual(1, len(plugins))
        self.assertEqual(before_path, sys.path)
        self.assertEqual(before_modules, set(sys.modules))


class TestRunRulesWithPlugins(unittest.TestCase):
    def test_a_plugin_alert_is_returned(self):
        alerts, failures = run_rules([helpers_rules.event()], [], plugins=[_Probe()])
        self.assertEqual(["probe"], [a.rule_id for a in alerts])
        self.assertEqual([], failures)

    def test_a_plugin_is_evaluated_once_over_the_whole_batch(self):
        seen = []

        class Recorder(_Probe):
            def evaluate(self, events):
                seen.append(list(events))
                return []

        events = [helpers_rules.event(record_id=n) for n in range(3)]
        run_rules(events, [], plugins=[Recorder()])
        self.assertEqual([events], seen)

    def test_events_may_be_a_one_shot_iterator_with_plugins(self):
        seen = []

        class Recorder(_Probe):
            def evaluate(self, events):
                seen.append(len(events))
                return []

        run_rules(iter([helpers_rules.event(record_id=n) for n in range(3)]), [],
                  plugins=[Recorder()])
        self.assertEqual([3], seen)

    def test_a_plugin_that_raises_during_evaluate_does_not_stop_the_run(self):
        class Exploding(PluginRule):
            id, title, severity = "boom", "Boom", "LOW"
            technique, tactic, description = "T1000", "TA0001", "d"
            entity_field = "host"

            def evaluate(self, events):
                raise RuntimeError("boom")

        alerts, failures = run_rules([helpers_rules.event()], [],
                                     plugins=[Exploding(), _Probe()])
        self.assertEqual(["probe"], [a.rule_id for a in alerts])
        self.assertEqual([("boom", "RuntimeError: boom")], failures)

    def test_a_plugin_that_fails_halfway_through_a_generator_adds_nothing(self):
        class Halfway(_Probe):
            id = "halfway"

            def evaluate(self, events):
                yield self.make_alert(events, "9.9.9.9")
                raise RuntimeError("late")

        alerts, failures = run_rules([helpers_rules.event()], [], plugins=[Halfway()])
        self.assertEqual(([], ["halfway"]), (alerts, [f[0] for f in failures]))

    def test_yaml_rules_and_plugins_run_together(self):
        rule = helpers_rules.rule_from_yaml(
            "id: any\ntitle: Any\nseverity: LOW\ndetection:\n  sel:\n    event_id: 4625\n"
            "  condition: sel\nmitre:\n  technique: T1110\n  tactic: TA0006\n"
            "fields: [host]\ndescription: any failure\n")
        alerts, _ = run_rules([helpers_rules.event()], [rule], plugins=[_Probe()])
        self.assertEqual({"any", "probe"}, {a.rule_id for a in alerts})

    def test_the_pack_is_eighteen_yaml_rules_and_two_plugins(self):
        from core.rule_engine.loader import load_rules
        rules, rule_errors = load_rules(Path("rules/windows"))
        plugins, plugin_errors = load_plugins(Path("rules/plugins"))
        self.assertEqual(([], []), (rule_errors, plugin_errors))
        self.assertEqual(20, len(rules) + len(plugins))
        self.assertEqual(20, len({r.id for r in rules} | {p.id for p in plugins}))
        self.assertTrue(all(p.severity in SEVERITY_WEIGHTS for p in plugins))

    def test_the_shipped_plugins_fire_end_to_end_through_run_rules(self):
        plugins, _ = load_plugins(Path("rules/plugins"))
        fails = [helpers_rules.event(
            event_id=4625, action="LOGIN_FAIL", source_ip="1.2.3.4",
            target_user="alice", record_id=i, timestamp=T0 + timedelta(seconds=i))
            for i in range(5)]
        ok = helpers_rules.event(
            event_id=4624, action="LOGIN_OK", source_ip="1.2.3.4",
            target_user="alice", record_id=9, timestamp=T0 + MIN)
        alerts, failures = run_rules(fails + [ok], [], plugins=plugins)
        self.assertEqual(["win-success-after-burst"], [a.rule_id for a in alerts])
        self.assertEqual([], failures)


class TestDetectWiresPlugins(test_cli_detect.DetectCase):
    """Task 11 left these to Task 13: detect has its full set of flags only now.

    Timestamps are relative to now. The brief's fixed T0 with --since 100d
    stops being inside the window on 2027-01-11 and the tests would go red
    for no reason in the code.
    """

    def burst_then_success(self):
        start = datetime.now() - timedelta(hours=1)
        events = [helpers_rules.event(
            event_id=4625, action="LOGIN_FAIL", source_ip="1.2.3.4",
            target_user="alice", record_id=100 + i,
            timestamp=start + timedelta(seconds=i * 10)) for i in range(5)]
        events.append(helpers_rules.event(
            event_id=4624, action="LOGIN_OK", source_ip="1.2.3.4",
            target_user="alice", record_id=200,
            timestamp=start + timedelta(minutes=1)))
        return events

    def stored_rule_ids(self):
        return {r["rule_id"] for r in store.query_alerts(self.conn, limit=None)}

    def test_detect_runs_plugins_by_default(self):
        self.seed(self.burst_then_success())
        code, _ = self.run_cli(["detect", "--since", "2h"])
        self.assertEqual(0, code)
        self.assertIn("win-failed-logon-burst", self.stored_rule_ids())
        self.assertIn("win-success-after-burst", self.stored_rule_ids())

    def test_no_plugins_skips_them(self):
        self.seed(self.burst_then_success())
        self.run_cli(["detect", "--since", "2h", "--no-plugins"])
        self.assertIn("win-failed-logon-burst", self.stored_rule_ids())
        self.assertNotIn("win-success-after-burst", self.stored_rule_ids())

    def test_a_plugin_alert_is_correlated_with_the_yaml_alerts_on_its_entity(self):
        # Both rules key on the source address, so the burst and the success
        # that followed it are one incident, not two.
        self.seed(self.burst_then_success())
        self.run_cli(["detect", "--since", "2h"])
        by_rule = {a["rule_id"]: a["incident_id"]
                   for a in store.query_alerts(self.conn, limit=None)}
        self.assertIsNotNone(by_rule["win-success-after-burst"])
        self.assertEqual(by_rule["win-failed-logon-burst"],
                         by_rule["win-success-after-burst"])


class TestDetectDefaultPluginsDirectory(test_cli_detect.DetectCase):
    """R86: a missing default plugins directory is "no plugins", not exit 3."""

    def test_a_missing_default_directory_is_not_a_failure(self):
        elsewhere = tempfile.TemporaryDirectory()
        self.addCleanup(elsewhere.cleanup)
        before = os.getcwd()
        self.addCleanup(os.chdir, before)
        os.chdir(elsewhere.name)
        code, out, _ = self.detect(json_mode=True)
        payload = json.loads(out)
        self.assertEqual((0, 1, []), (code, payload["rules"], payload["rule_errors"]))

    def test_the_shipped_plugins_run_from_the_repo_root(self):
        code, out, _ = self.detect(json_mode=True)
        self.assertEqual((0, 3), (code, json.loads(out)["rules"]))

    def test_a_plugin_that_fails_to_import_still_exits_3(self):
        # The half of R86 that must NOT be silenced: only a missing directory
        # is "no plugins"; a broken plugin takes two CRITICAL rules dark.
        plugins = tempfile.TemporaryDirectory()
        self.addCleanup(plugins.cleanup)
        (Path(plugins.name) / "broken.py").write_text(
            "import nonexistent_module\n", encoding="utf-8")
        with mock.patch.object(test_cli_detect.detect_command, "DEFAULT_PLUGINS_DIR",
                               Path(plugins.name)):
            code, out, _ = self.detect(json_mode=True)
        payload = json.loads(out)
        self.assertEqual((3, 1), (code, len(payload["rule_errors"])))
        self.assertIn("nonexistent_module", payload["rule_errors"][0]["message"])
        self.assertIn("broken", payload["rule_errors"][0]["path"])

    def test_no_plugins_skips_them(self):
        code, out, _ = self.detect("--no-plugins", json_mode=True)
        self.assertEqual((0, 1), (code, json.loads(out)["rules"]))


if __name__ == "__main__":
    unittest.main()

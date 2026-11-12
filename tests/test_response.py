# tests/test_response.py
"""The trust boundary. Log data is attacker-controlled input, and these tests
are the table a reviewer reads to see what reaches a command line.

Nothing here executes anything: this module loads, matches, validates and
renders. Execution is `cli/commands/respond.py`.
"""

import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from core import store
from core.response import (
    DEFAULT_PLAYBOOKS_DIR, PLACEHOLDER_KINDS, RISKS, Action, Playbook,
    PlaybookError, load_playbook_file, load_playbooks, match_playbooks,
    placeholder_values, render, validate_value,
)
from tests.helpers_rules import sample_alert

T0 = datetime(2026, 10, 10, 9, 0, 0)

# Spec 11.1, verbatim. Loaded here as well as shipped, so a change to either
# the file or the loader that breaks the other fails a test. The spec's two em
# dashes are written \\u2014 to keep this file ASCII; Python turns them into the
# same character the shipped file holds.
SPEC_PLAYBOOK = """
id: pb-brute-force
title: Credential Access \u2014 Brute Force Response
match:
  tactic: TA0006
  min_severity: HIGH
actions:
  - name: Block source IP at host firewall
    command: ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
              'name=SIEM-Block-{source_ip}', 'dir=in', 'action=block',
              'remoteip={source_ip}']
    undo:    ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
              'name=SIEM-Block-{source_ip}']
    risk: medium
  - name: Disable targeted account
    command: ['net', 'user', '{target_user}', '/active:no']
    undo:    ['net', 'user', '{target_user}', '/active:yes']
    risk: high
  - name: Review active sessions for the account
    command: ['query', 'user', '{target_user}']
    risk: low
  - name: Force logoff the session
    manual: true
    guidance: >
      Identify the session id from `query user`, then run
      `logoff <id>`. Not automated \u2014 logging off the wrong session
      disrupts a legitimate user.
"""

MINIMAL = """
id: pb-test
title: Test Playbook
match:
  tactic: TA0006
  min_severity: HIGH
actions:
  - name: Echo the user
    command: ['cmd', '/c', 'echo {user}']
    risk: low
"""


def action(**overrides):
    """An Action with every field filled, bypassing the loader on purpose:
    these tests pin render() against a hand-built action."""
    base = dict(name="Act", command=("cmd", "/c", "echo"), undo=(),
                risk="low", manual=False, guidance="")
    base.update(overrides)
    return Action(**base)


def incident(**overrides):
    base = dict(id=1, opened_at=T0, last_seen=T0, entity_type="ip",
                entity_value="203.0.113.9", severity="HIGH", score=10,
                tactics='["TA0006"]', status="OPEN", title="t")
    base.update(overrides)
    return base


def alert(evidence=(), tactic="TA0006", **overrides):
    base = dict(id=1, timestamp=T0, severity="HIGH", rule_id="r1",
                entity_type="ip", entity_value="203.0.113.9",
                mitre_tactic_id=tactic, evidence=json.dumps(list(evidence)))
    base.update(overrides)
    return base


class PlaybookFileCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, text, name="pb.yml"):
        path = Path(self.tmp.name) / name
        path.write_text(text, encoding="utf-8")
        return path

    def assert_rejected(self, text, *expected):
        with self.assertRaises(PlaybookError) as caught:
            load_playbook_file(self.write(text))
        message = str(caught.exception)
        for fragment in expected:
            self.assertIn(fragment, message)
        return message


class TestPlaceholderValidation(unittest.TestCase):
    """Each HOSTILE row must be REJECTED with a named error."""

    HOSTILE = [
        ("ip",   "1.2.3.4; rm -rf /"),      ("ip",   "1.2.3.4 && calc"),
        ("ip",   "$(whoami)"),              ("ip",   "not-an-ip"),
        ("ip",   "1.2.3.4\nrule"),          ("ip",   ""),
        ("user", "bob; net user hax /add"), ("user", "bob&calc"),
        ("user", "../../etc/passwd"),       ("user", "a" * 65),
        ("user", "bob\x00"),                ("user", "bob\nadmin"),
        ("host", "PC-01; shutdown"),        ("host", "-/-"),
        ("host", "a" * 64),                 ("host", "PC 01"),
    ]
    LEGITIMATE = [
        ("ip", "203.0.113.9"), ("ip", "::1"), ("ip", "127.0.0.1"),
        ("user", "svc_update"), ("user", "bob$"),
        ("user", "a.b-c_d"), ("host", "PC-01"), ("host", "web01.corp.example"),
    ]
    # Ruling R106: real values the spec's username pattern has no backslash,
    # `=`, `,` or space for. Sysmon event 1 maps `User` ("DOMAIN\\user") to
    # `user`; 4728/4732 map `MemberName` (a full DN) to `target_user`. Both
    # reach this boundary and both are correctly refused -- the action is
    # skipped by name and the run carries on.
    REJECTED_BUT_LEGITIMATE = [
        ("user", "DOMAIN\\bob"),
        ("user", "CN=bob,OU=Users,DC=corp,DC=example"),
    ]

    def test_every_hostile_value_is_rejected_by_name(self):
        for kind, value in self.HOSTILE:
            with self.subTest(kind=kind, value=value):
                with self.assertRaises(ValueError) as caught:
                    validate_value(kind, value)
                self.assertIn(kind, str(caught.exception))

    def test_every_legitimate_value_is_accepted(self):
        for kind, value in self.LEGITIMATE:
            with self.subTest(kind=kind, value=value):
                self.assertEqual(validate_value(kind, value), value)

    def test_every_rejected_but_legitimate_value_is_still_rejected(self):
        # The backslash is the point: assert the test data, not just the verdict.
        self.assertIn("\\", self.REJECTED_BUT_LEGITIMATE[0][1])
        for kind, value in self.REJECTED_BUT_LEGITIMATE:
            with self.subTest(kind=kind, value=value):
                with self.assertRaises(ValueError):
                    validate_value(kind, value)

    def test_rejection_names_the_placeholder_and_the_value(self):
        act = action(command=("net", "user", "{target_user}", "/active:no"))
        with self.assertRaises(PlaybookError) as caught:
            render(act, {"target_user": ["bob&calc"]})
        message = str(caught.exception)
        self.assertIn("target_user", message)
        self.assertIn("bob&calc", message)
        self.assertIn("Act", message)

    def test_a_non_string_value_is_rejected_before_any_pattern_runs(self):
        # Ruling R113: ip_address(5) is 0.0.0.5 and ip_address(True) is
        # 0.0.0.1, so an int would validate cleanly and render a DIFFERENT
        # address. `evidence` is JSON and SQLite returns whatever was written.
        for kind, value in [("ip", 5), ("ip", True), ("ip", 16909060),
                            ("ip", None), ("ip", ["1.2.3.4"]),
                            ("user", 1234), ("host", 1), ("ip", 1.0)]:
            with self.subTest(kind=kind, value=value):
                with self.assertRaises(ValueError) as caught:
                    validate_value(kind, value)
                self.assertIn("text", str(caught.exception))

    def test_an_ip_is_the_canonical_form_of_the_parsed_object(self):
        # Not the input string: nothing reaches a command line that was not
        # reconstructed from a parsed address object (R113).
        self.assertEqual(validate_value("ip", "::0001"), "::1")
        self.assertEqual(validate_value("ip", "0:0:0:0:0:0:0:1"), "::1")

    def test_a_host_may_have_several_labels(self):
        # Ruling R112: a single-label pattern would reject these.
        for value in ("web01.corp.example", "a.b.c.d.e", "pc-01.ad.local"):
            with self.subTest(value=value):
                self.assertEqual(validate_value("host", value), value)

    def test_a_host_label_may_not_start_or_end_with_a_hyphen(self):
        for value in ("-web01.corp.example", "web01-.corp.example",
                      "web01.-corp.example", "a..b", ".a", "a."):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_value("host", value)

    def test_a_host_longer_than_253_characters_is_rejected(self):
        label = "a" * 63
        ok = ".".join([label] * 3) + "." + "a" * 61          # 253
        too_long = ok + "a"                                   # 254
        self.assertEqual(len(ok), 253)
        self.assertEqual(validate_value("host", ok), ok)
        with self.assertRaises(ValueError):
            validate_value("host", too_long)

    def test_a_kind_with_no_validator_is_an_error_not_a_pass(self):
        for kind in ("process", "command_line", "", "IP"):
            with self.subTest(kind=kind):
                with self.assertRaises(ValueError):
                    validate_value(kind, "anything")

    def test_every_placeholder_kind_has_a_validator(self):
        # The map is pinned: a new name here widens the trust boundary and
        # must be a visible change, not a quiet one.
        self.assertEqual(PLACEHOLDER_KINDS, {
            "ip": "ip", "source_ip": "ip", "dest_ip": "ip",
            "user": "user", "target_user": "user", "host": "host",
        })
        for name, kind in PLACEHOLDER_KINDS.items():
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    validate_value(kind, "\x00")


class TestRender(unittest.TestCase):
    def test_a_command_is_a_list_never_a_string(self):
        rendered = render(action(command=("cmd", "/c", "echo", "{user}")),
                          {"user": ["bob"]})
        self.assertIsInstance(rendered, list)
        self.assertEqual(rendered, ["cmd", "/c", "echo", "bob"])
        for element in rendered:
            self.assertIsInstance(element, str)

    def test_an_unknown_placeholder_aborts_rather_than_rendering_literally(self):
        # '{nosuch}' must not reach a command line as the text "{nosuch}".
        with self.assertRaises(PlaybookError) as caught:
            render(action(command=("echo", "{nosuch}")), {"nosuch": ["x"]})
        # Reported as an unknown placeholder, which is what an author can act
        # on -- not as a validator that happens to be missing.
        self.assertIn("nosuch", str(caught.exception))
        self.assertIn("not a placeholder", str(caught.exception))

    def test_a_placeholder_whose_value_is_missing_aborts_the_action(self):
        with self.assertRaises(PlaybookError) as caught:
            render(action(command=("net", "user", "{target_user}")), {})
        message = str(caught.exception)
        self.assertIn("target_user", message)
        self.assertIn("Act", message)

    def test_rendering_never_concatenates_into_one_argument(self):
        # The element with a space is what makes this a real check: a render
        # that joined the list and re-split it would return five arguments.
        rendered = render(
            action(command=("cmd", "/c", "echo hello {user}", "/q")),
            {"user": ["bob"]})
        self.assertEqual(rendered, ["cmd", "/c", "echo hello bob", "/q"])

    def test_a_hostile_value_cannot_split_an_argument_because_it_is_refused(self):
        for value in ("bob; calc", "bob\nadmin", "bob and more"):
            with self.subTest(value=value):
                with self.assertRaises(PlaybookError):
                    render(action(command=("net", "user", "{user}")),
                           {"user": [value]})

    def test_an_ambiguous_placeholder_aborts_the_action_listing_the_values(self):
        # Ruling R114: an incident can hold alerts from two source IPs and
        # nothing says which to firewall, so neither is chosen.
        with self.assertRaises(PlaybookError) as caught:
            render(action(command=("block", "{source_ip}")),
                   {"source_ip": ["203.0.113.9", "198.51.100.4"]})
        message = str(caught.exception)
        self.assertIn("203.0.113.9", message)
        self.assertIn("198.51.100.4", message)
        self.assertIn("Act", message)

    def test_a_value_given_as_bare_text_is_refused_rather_than_indexed(self):
        # placeholder_values returns lists, and Task 5 passes them straight
        # through. A bare string is a sequence too: "b" would render as "b"
        # and "bob" would read as three candidate characters.
        for given in ("b", "bob"):
            with self.subTest(given=given):
                with self.assertRaises(PlaybookError) as caught:
                    render(action(command=("net", "user", "{user}")),
                           {"user": given})
                self.assertIn("list", str(caught.exception))

    def test_one_value_in_a_list_renders(self):
        self.assertEqual(render(action(command=("block", "{source_ip}")),
                                {"source_ip": ["203.0.113.9"]}),
                         ["block", "203.0.113.9"])

    def test_a_placeholder_renders_the_validated_value_not_the_input(self):
        self.assertEqual(render(action(command=("block", "{source_ip}")),
                                {"source_ip": ["::0001"]}),
                         ["block", "::1"])

    def test_every_occurrence_in_one_element_is_replaced(self):
        self.assertEqual(
            render(action(command=("name=B-{source_ip}", "remoteip={source_ip}")),
                   {"source_ip": ["203.0.113.9"]}),
            ["name=B-203.0.113.9", "remoteip=203.0.113.9"])

    def test_a_manual_action_has_no_command_to_render(self):
        with self.assertRaises(PlaybookError) as caught:
            render(action(command=(), manual=True, guidance="do it by hand"),
                   {})
        self.assertIn("manual", str(caught.exception))

    def test_an_unbalanced_brace_aborts_rather_than_reaching_a_command_line(self):
        for element in ("{user", "user}", "{{user}"):
            with self.subTest(element=element):
                with self.assertRaises(PlaybookError):
                    render(action(command=("echo", element)), {"user": ["bob"]})

    def test_undo_renders_through_the_same_boundary(self):
        act = action(command=("net", "user", "{user}", "/active:no"),
                     undo=("net", "user", "{user}", "/active:yes"))
        values = {"user": ["bob"]}
        self.assertEqual(render(act, values, undo=True),
                         ["net", "user", "bob", "/active:yes"])
        with self.assertRaises(PlaybookError):
            render(act, {"user": ["bob; calc"]}, undo=True)

    def test_an_action_with_no_undo_renders_nothing(self):
        self.assertEqual(render(action(undo=()), {}, undo=True), [])


class TestMatching(unittest.TestCase):
    def playbook(self, **overrides):
        base = dict(id="pb", title="t", tactic="TA0006", min_severity="HIGH",
                    actions=(action(),), source_file="pb.yml")
        base.update(overrides)
        return Playbook(**base)

    def test_a_playbook_matches_on_tactic_and_min_severity(self):
        pb = self.playbook()
        self.assertEqual(
            match_playbooks([pb], incident(severity="HIGH"), [alert()]), [pb])

    def test_min_severity_is_a_floor_not_an_equality(self):
        pb = self.playbook(min_severity="HIGH")
        self.assertEqual(
            match_playbooks([pb], incident(severity="CRITICAL"), [alert()]), [pb])

    def test_an_incident_below_min_severity_does_not_match(self):
        pb = self.playbook(min_severity="HIGH")
        for severity in ("INFO", "LOW", "MEDIUM"):
            with self.subTest(severity=severity):
                self.assertEqual(
                    match_playbooks([pb], incident(severity=severity),
                                    [alert()]), [])

    def test_a_tactic_the_incident_does_not_have_does_not_match(self):
        pb = self.playbook(tactic="TA0003")
        self.assertEqual(match_playbooks([pb], incident(), [alert()]), [])

    def test_the_tactic_comes_from_the_member_alerts(self):
        # The correlator derives incidents.tactics from these same rows, and a
        # column is not a JSON blob that a hand edit can quietly empty.
        pb = self.playbook(tactic="TA0003")
        self.assertEqual(
            match_playbooks([pb], incident(tactics="[]"),
                            [alert(tactic="TA0003")]), [pb])

    def test_no_match_is_an_empty_list_not_an_error(self):
        self.assertEqual(match_playbooks([], incident(), []), [])
        self.assertEqual(
            match_playbooks([self.playbook()], incident(), []), [])

    def test_an_unknown_incident_severity_matches_nothing(self):
        # A hand-edited row must not become a floor of its own.
        pb = self.playbook(min_severity="INFO")
        for severity in ("", "URGENT", None):
            with self.subTest(severity=severity):
                self.assertEqual(
                    match_playbooks([pb], incident(severity=severity),
                                    [alert()]), [])

    def test_several_playbooks_can_match_one_incident(self):
        first, second = self.playbook(id="a"), self.playbook(id="b")
        self.assertEqual(
            match_playbooks([first, second], incident(), [alert()]),
            [first, second])


class TestPlaceholderValues(unittest.TestCase):
    """The map is the incident's entity_type -> entity_value, plus every field
    name in the member alerts' evidence JSON. Nothing else."""

    def test_the_incidents_entity_is_available_under_its_entity_type(self):
        self.assertEqual(
            placeholder_values(incident(entity_type="ip",
                                        entity_value="203.0.113.9"), []),
            {"ip": ["203.0.113.9"]})

    def test_alert_evidence_fields_are_available_by_name(self):
        values = placeholder_values(
            incident(), [alert(evidence=[{"source_ip": "203.0.113.9",
                                          "target_user": "bob"}])])
        self.assertEqual(values["target_user"], ["bob"])
        self.assertEqual(values["source_ip"], ["203.0.113.9"])

    def test_several_distinct_values_are_all_collected(self):
        values = placeholder_values(incident(), [
            alert(evidence=[{"source_ip": "203.0.113.9"}]),
            alert(evidence=[{"source_ip": "198.51.100.4"}]),
        ])
        self.assertEqual(values["source_ip"], ["203.0.113.9", "198.51.100.4"])

    def test_a_repeated_value_is_collected_once(self):
        values = placeholder_values(incident(), [
            alert(evidence=[{"source_ip": "203.0.113.9"},
                            {"source_ip": "203.0.113.9"}]),
            alert(evidence=[{"source_ip": "203.0.113.9"}]),
        ])
        self.assertEqual(values["source_ip"], ["203.0.113.9"])

    def test_a_field_no_alert_carries_is_absent_rather_than_blank(self):
        values = placeholder_values(incident(), [alert(evidence=[{"user": "b"}])])
        self.assertNotIn("target_user", values)

    def test_the_not_recorded_sentinel_is_absent_rather_than_a_value(self):
        # Ruling R150: "-" is this project's not-recorded sentinel, and spec
        # 11.2's own username pattern admits a bare hyphen -- so without this
        # filter `net user - /active:no` renders and is OFFERED to an operator.
        values = placeholder_values(
            incident(), [alert(evidence=[{"source_ip": "203.0.113.9",
                                          "target_user": "-"}])])
        self.assertNotIn("target_user", values)
        self.assertEqual(values["source_ip"], ["203.0.113.9"])

    def test_an_empty_or_blank_value_is_absent_too(self):
        for value in ("", " ", "\t", "\n"):
            with self.subTest(value=value):
                values = placeholder_values(
                    incident(), [alert(evidence=[{"target_user": value}])])
                self.assertNotIn("target_user", values)

    def test_the_sentinel_is_filtered_for_every_placeholder_kind(self):
        # One filter at collection rather than a special case per kind: the
        # incident's own entity goes through it as well as evidence fields.
        values = placeholder_values(
            incident(entity_type="host", entity_value="-"),
            [alert(evidence=[{"ip": "-", "source_ip": "-", "dest_ip": "-",
                              "user": "-", "target_user": "-", "host": "-"}])])
        self.assertEqual(values, {})

    def test_a_value_that_merely_contains_a_hyphen_is_still_collected(self):
        # The fix must not become "reject anything with a hyphen": only the
        # bare sentinel is absent. "--" and "-x-" are real text, and a user
        # like a.b-c_d is in the accepted table above.
        values = placeholder_values(incident(), [
            alert(evidence=[{"target_user": "--"}]),
            alert(evidence=[{"user": "-x-"}]),
            alert(evidence=[{"host": "pc-01"}]),
        ])
        self.assertEqual(values["target_user"], ["--"])
        self.assertEqual(values["user"], ["-x-"])
        self.assertEqual(values["host"], ["pc-01"])

    def test_the_sentinel_does_not_become_a_second_ambiguous_value(self):
        # One real user plus a "-" on another alert is one value, not two:
        # filtering at collection means the sentinel cannot trigger R114's
        # ambiguity abort on an otherwise unambiguous placeholder.
        values = placeholder_values(incident(), [
            alert(evidence=[{"target_user": "bob"}]),
            alert(evidence=[{"target_user": "-"}]),
        ])
        self.assertEqual(values["target_user"], ["bob"])
        self.assertEqual(render(action(command=("net", "user", "{target_user}")),
                                values), ["net", "user", "bob"])

    def test_a_sentinel_value_aborts_the_action_with_no_value_not_a_pattern(self):
        # The honest message: the operator is told there is no target_user,
        # not that "-" failed a character class. A pattern error here would
        # read as a malformed username rather than an unrecorded one.
        values = placeholder_values(
            incident(), [alert(evidence=[{"target_user": "-"}])])
        with self.assertRaises(PlaybookError) as caught:
            render(action(command=("net", "user", "{target_user}", "/active:no")),
                   values)
        message = str(caught.exception)
        self.assertIn("target_user", message)
        self.assertIn("has no value in this incident", message)
        self.assertNotIn("is not 1 to 64", message)

    def test_the_sentinel_is_still_a_valid_username_at_the_pattern(self):
        # Pinned so the fix cannot drift into validate_value: spec 11.2's
        # pattern is unwidened AND unnarrowed. "-" never reaches it because
        # placeholder_values does not collect it (R150), not because the
        # boundary rejects it.
        self.assertEqual(validate_value("user", "-"), "-")

    def test_hand_edited_evidence_contributes_nothing(self):
        for evidence in ("not json", "{}", "[1, 2]", '["a"]', "null", ""):
            with self.subTest(evidence=evidence):
                values = placeholder_values(
                    incident(entity_type="ip", entity_value="1.2.3.4"),
                    [dict(alert(), evidence=evidence)])
                self.assertEqual(values, {"ip": ["1.2.3.4"]})

    def test_a_non_string_evidence_value_survives_to_be_rejected(self):
        # R113 end to end: a stored source_ip of 5 must not become 0.0.0.5.
        values = placeholder_values(incident(), [alert(evidence=[{"source_ip": 5}])])
        with self.assertRaises(PlaybookError):
            render(action(command=("block", "{source_ip}")), values)

    def test_it_reads_real_sqlite_rows(self):
        # placeholder_values and match_playbooks are given sqlite3.Row objects
        # by the verb, which has no .get() and no .keys() lookup by default.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "t.db"
        conn = store.connect(path)
        self.addCleanup(conn.close)
        store.init_schema(conn)
        incident_id = store.open_incident(conn, T0, T0, "ip", "203.0.113.9",
                                          "HIGH", tactics=["TA0006"])
        store.insert_alerts(conn, [sample_alert(
            evidence=json.dumps([{"source_ip": "203.0.113.9",
                                  "target_user": "bob"}]))])
        rows = store.query_alerts(conn)
        row = store.query_incidents(conn, incident_id=incident_id)[0]
        self.assertIsInstance(row, sqlite3.Row)
        self.assertEqual(placeholder_values(row, rows),
                         {"ip": ["203.0.113.9"],
                          "source_ip": ["203.0.113.9"],
                          "target_user": ["bob"]})
        playbooks, errors = load_playbooks(DEFAULT_PLAYBOOKS_DIR)
        self.assertEqual(errors, [])
        matched = match_playbooks(playbooks, row, rows)
        self.assertEqual([p.id for p in matched], ["pb-brute-force"])
        self.assertEqual(
            render(matched[0].actions[1], placeholder_values(row, rows)),
            ["net", "user", "bob", "/active:no"])


class TestLoading(PlaybookFileCase):
    def test_a_valid_playbook_loads_every_field(self):
        pb = load_playbook_file(self.write(SPEC_PLAYBOOK))
        self.assertEqual(pb.id, "pb-brute-force")
        self.assertEqual(pb.title, "Credential Access \u2014 Brute Force Response")
        self.assertEqual(pb.tactic, "TA0006")
        self.assertEqual(pb.min_severity, "HIGH")
        self.assertEqual(len(pb.actions), 4)
        first = pb.actions[0]
        self.assertEqual(first.name, "Block source IP at host firewall")
        self.assertEqual(first.command[0], "netsh")
        self.assertEqual(first.command[5], "name=SIEM-Block-{source_ip}")
        self.assertEqual(len(first.command), 9)
        self.assertEqual(first.undo[-1], "name=SIEM-Block-{source_ip}")
        self.assertEqual(first.risk, "medium")
        self.assertFalse(first.manual)

    def test_a_manual_action_has_guidance_and_no_command(self):
        last = load_playbook_file(self.write(SPEC_PLAYBOOK)).actions[-1]
        self.assertTrue(last.manual)
        self.assertEqual(last.command, ())
        self.assertEqual(last.undo, ())
        self.assertIn("logoff <id>", last.guidance)
        # Spec 11.1's manual action declares no risk, and that file ships
        # verbatim: a risk is required only of an action that can run.
        self.assertEqual(last.risk, "")

    def test_a_manual_action_may_still_declare_a_risk(self):
        act = load_playbook_file(self.write("""
id: pb-test
title: t
match: {tactic: TA0006, min_severity: HIGH}
actions:
  - name: By hand
    manual: true
    guidance: do it
    risk: high
""")).actions[0]
        self.assertEqual(act.risk, "high")

    def test_a_command_is_stored_as_a_sequence_of_text(self):
        command = load_playbook_file(self.write(MINIMAL)).actions[0].command
        self.assertEqual(command, ("cmd", "/c", "echo {user}"))
        for element in command:
            self.assertIsInstance(element, str)

    def test_an_action_with_both_command_and_manual_is_rejected(self):
        self.assert_rejected(
            MINIMAL.replace("    risk: low\n", "    manual: true\n    risk: low\n"),
            "manual", "command")

    def test_an_unknown_risk_level_is_rejected(self):
        for risk in ("critical", "LOW", "", "none", "1"):
            with self.subTest(risk=risk):
                self.assert_rejected(
                    MINIMAL.replace("risk: low", "risk: {}".format(risk or "''")),
                    "risk")

    def test_a_missing_risk_is_rejected(self):
        self.assert_rejected(MINIMAL.replace("    risk: low\n", ""), "risk")

    def test_a_command_given_as_a_string_is_rejected(self):
        # The single most dangerous rule-file mistake: a string would be
        # executed as a shell line, or iterated one character per argument.
        message = self.assert_rejected(
            MINIMAL.replace("command: ['cmd', '/c', 'echo {user}']",
                            "command: cmd /c echo {user}"), "command", "list")
        self.assertIn("shell", message)

    def test_a_command_element_that_is_not_text_is_rejected(self):
        for command in ("[1, 2]", "['net', 4625]", "['net', ['user']]",
                        "['net', null]", "['net', '']", "[]"):
            with self.subTest(command=command):
                self.assert_rejected(
                    MINIMAL.replace("['cmd', '/c', 'echo {user}']", command),
                    "command")

    def test_an_undo_given_as_a_string_is_rejected(self):
        self.assert_rejected(
            MINIMAL.replace("    risk: low\n", "    undo: net user bob\n    risk: low\n"),
            "undo", "list")

    def test_a_manual_action_without_guidance_is_rejected(self):
        self.assert_rejected("""
id: pb-test
title: t
match: {tactic: TA0006, min_severity: HIGH}
actions:
  - name: By hand
    manual: true
    risk: low
""", "guidance")

    def test_an_undo_on_a_manual_action_is_rejected(self):
        self.assert_rejected("""
id: pb-test
title: t
match: {tactic: TA0006, min_severity: HIGH}
actions:
  - name: By hand
    manual: true
    guidance: do it
    undo: ['net', 'user']
    risk: low
""", "undo", "manual")

    def test_manual_false_still_needs_a_command(self):
        self.assert_rejected("""
id: pb-test
title: t
match: {tactic: TA0006, min_severity: HIGH}
actions:
  - name: Nothing
    manual: false
    risk: low
""", "command")

    def test_an_action_name_is_required(self):
        self.assert_rejected("""
id: pb-test
title: t
match: {tactic: TA0006, min_severity: HIGH}
actions:
  - command: ['cmd', '/c', 'echo']
    risk: low
""", "name")

    def test_guidance_without_manual_is_rejected(self):
        self.assert_rejected(
            MINIMAL.replace("    risk: low\n", "    guidance: by hand\n    risk: low\n"),
            "guidance", "manual")

    def test_at_least_one_action_is_required(self):
        self.assert_rejected(MINIMAL.split("actions:")[0] + "actions: []\n",
                             "actions")

    def test_match_requires_a_tactic_and_a_min_severity(self):
        self.assert_rejected(MINIMAL.replace("  tactic: TA0006\n", ""), "tactic")
        self.assert_rejected(MINIMAL.replace("  min_severity: HIGH\n", ""),
                             "min_severity")
        self.assert_rejected(MINIMAL.replace(
            "match:\n  tactic: TA0006\n  min_severity: HIGH\n", "match: {}\n"),
            "match")

    def test_an_unknown_min_severity_is_rejected(self):
        self.assert_rejected(MINIMAL.replace("min_severity: HIGH",
                                             "min_severity: SEVERE"),
                             "min_severity")

    def test_an_unknown_key_is_rejected_at_every_level(self):
        self.assert_rejected(MINIMAL + "enabled: true\n", "enabled")
        self.assert_rejected(MINIMAL.replace("  tactic:", "  technique: T1110\n  tactic:"),
                             "technique")
        self.assert_rejected(MINIMAL.replace("    risk: low\n",
                                             "    shell: true\n    risk: low\n"),
                             "shell")

    def test_an_id_and_a_title_are_required(self):
        self.assert_rejected(MINIMAL.replace("id: pb-test\n", ""), "id")
        self.assert_rejected(MINIMAL.replace("title: Test Playbook\n", ""), "title")

    def test_an_empty_file_is_rejected(self):
        self.assert_rejected("", "empty")

    def test_a_file_that_is_not_a_mapping_is_rejected(self):
        self.assert_rejected("- pb-test\n", "mapping")

    def test_actions_must_be_a_list_of_mappings(self):
        self.assert_rejected(MINIMAL.split("actions:")[0] + "actions: hello\n",
                             "actions")
        self.assert_rejected(MINIMAL.split("actions:")[0] + "actions: ['go']\n",
                             "actions")

    def test_one_bad_playbook_does_not_stop_the_others(self):
        self.write(MINIMAL, "good.yml")
        self.write("id: broken\n", "bad.yml")
        self.write(MINIMAL.replace("pb-test", "pb-other"), "other.yml")
        playbooks, errors = load_playbooks(self.tmp.name)
        self.assertEqual(sorted(p.id for p in playbooks), ["pb-other", "pb-test"])
        self.assertEqual(len(errors), 1)
        self.assertIn("bad.yml", str(errors[0]))

    def test_a_duplicated_actions_key_is_an_error_not_a_dropped_list(self):
        # Ruling R119. yaml.safe_load keeps the LAST of two equal keys, so
        # without this check the firewall action would vanish and the operator
        # would read a playbook covering less than its author wrote, with
        # nothing on screen to say so. Written as two `actions:` because that
        # is the duplicate that costs a playbook the most.
        doubled = SPEC_PLAYBOOK + """
actions:
  - name: Only this one survives safe_load
    command: ['cmd', '/c', 'echo', 'second']
    risk: low
"""
        message = self.assert_rejected(doubled, "actions", "duplicate key at line")
        self.assertNotIn("netsh", message)

    def test_a_duplicate_key_does_not_hide_the_other_playbooks(self):
        self.write(MINIMAL, "good.yml")
        self.write(MINIMAL.replace("pb-test", "pb-dupe") + "match:\n  tactic: TA0003\n"
                   "  min_severity: LOW\n", "dupe.yml")
        playbooks, errors = load_playbooks(self.tmp.name)
        self.assertEqual([p.id for p in playbooks], ["pb-test"])
        self.assertEqual(len(errors), 1)
        self.assertIn("dupe.yml", str(errors[0]))
        self.assertIn("duplicate key", str(errors[0]))

    def test_duplicate_playbook_id_is_an_error(self):
        self.write(MINIMAL, "a.yml")
        self.write(MINIMAL, "b.yml")
        playbooks, errors = load_playbooks(self.tmp.name)
        self.assertEqual([p.id for p in playbooks], ["pb-test"])
        self.assertEqual(len(errors), 1)
        self.assertIn("already defined", str(errors[0]))
        self.assertIn("a.yml", str(errors[0]))

    def test_a_non_yaml_file_is_ignored(self):
        self.write(MINIMAL, "pb.yml")
        self.write("nonsense", "notes.txt")
        playbooks, errors = load_playbooks(self.tmp.name)
        self.assertEqual(len(playbooks), 1)
        self.assertEqual(errors, [])

    def test_a_missing_directory_is_one_error_not_an_exception(self):
        playbooks, errors = load_playbooks(Path(self.tmp.name) / "nope")
        self.assertEqual(playbooks, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("does not exist", str(errors[0]))

    def test_an_error_names_the_file_and_carries_path_and_key(self):
        with self.assertRaises(PlaybookError) as caught:
            load_playbook_file(self.write(MINIMAL.replace("risk: low", "risk: nope")))
        self.assertTrue(caught.exception.path.endswith("pb.yml"))
        self.assertIn("risk", caught.exception.key)
        self.assertIn("pb.yml", str(caught.exception))

    def test_yaml_safe_load_only(self):
        # An unsafe load would call print() while constructing the document.
        text = MINIMAL.replace("title: Test Playbook",
                               "title: !!python/object/apply:builtins.print ['PWNED']")
        captured = io.StringIO()
        with redirect_stdout(captured):
            with self.assertRaises(PlaybookError) as caught:
                load_playbook_file(self.write(text))
        self.assertNotIn("PWNED", captured.getvalue())
        self.assertIn("cannot read", str(caught.exception))


class TestShippedPlaybooks(unittest.TestCase):
    def test_the_shipped_pack_loads_without_errors(self):
        playbooks, errors = load_playbooks(DEFAULT_PLAYBOOKS_DIR)
        self.assertEqual([str(e) for e in errors], [])
        self.assertIn("pb-brute-force", [p.id for p in playbooks])

    def test_the_pack_covers_credential_access_persistence_and_evasion(self):
        playbooks, _ = load_playbooks(DEFAULT_PLAYBOOKS_DIR)
        self.assertEqual(sorted(p.tactic for p in playbooks),
                         ["TA0003", "TA0005", "TA0006"])

    def test_pb_brute_force_matches_the_spec_text(self):
        # Ruling R120: the shipped file writes the spec's two em dashes as
        # hyphens so that no file under rules/ is non-ASCII. That is the ONLY
        # difference allowed: ids, structure, commands, undos, risks and the
        # words of the guidance are still compared character for character.
        shipped = load_playbooks(DEFAULT_PLAYBOOKS_DIR)[0]
        pb = [p for p in shipped if p.id == "pb-brute-force"][0]
        spec = load_playbook_file(_spec_file())
        self.assertEqual(
            (pb.id, pb.title, pb.tactic, pb.min_severity),
            (spec.id, _hyphens(spec.title), spec.tactic, spec.min_severity))
        self.assertEqual(pb.actions, tuple(
            replace(a, name=_hyphens(a.name), guidance=_hyphens(a.guidance))
            for a in spec.actions))
        # The dash really is the only difference, so the untouched spec text
        # must NOT compare equal: without this, _hyphens() could be a no-op
        # and the test above would still pass.
        self.assertNotEqual(pb.title, spec.title)

    def test_no_file_under_rules_is_non_ascii(self):
        # Ruling R120. A non-ASCII byte in a rule or playbook file needs
        # core.report.fix_encoding() to have run before it can print on a
        # cp1252 console, and renders as a replacement character when it has
        # not -- in the files an operator reads under pressure.
        offenders = {}
        for path in sorted(Path("rules").rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                data = path.read_bytes()
                if any(byte > 127 for byte in data):
                    offenders[str(path)] = [hex(b) for b in data if b > 127][:4]
        self.assertEqual({}, offenders)

    def test_every_runnable_action_carries_a_risk_and_every_manual_one_guidance(self):
        playbooks, _ = load_playbooks(DEFAULT_PLAYBOOKS_DIR)
        self.assertTrue(playbooks)
        for pb in playbooks:
            for act in pb.actions:
                with self.subTest(playbook=pb.id, action=act.name):
                    if not act.manual:
                        self.assertIn(act.risk, RISKS)
                    self.assertEqual(bool(act.guidance), act.manual)
                    self.assertEqual(bool(act.command), not act.manual)

    def test_every_placeholder_in_the_pack_has_a_known_kind(self):
        # A playbook shipping '{process}' would abort at render time instead of
        # failing here, where an author can see it.
        import re
        playbooks, _ = load_playbooks(DEFAULT_PLAYBOOKS_DIR)
        for pb in playbooks:
            for act in pb.actions:
                for element in tuple(act.command) + tuple(act.undo):
                    for name in re.findall(r"\{([^{}]*)\}", element):
                        with self.subTest(playbook=pb.id, placeholder=name):
                            self.assertIn(name, PLACEHOLDER_KINDS)


def _hyphens(text):
    """`text` with the spec's em dashes written as the hyphens the shipped
    playbook uses (ruling R120). Nothing else is normalised."""
    return text.replace("\u2014", "-")


def _spec_file():
    directory = tempfile.mkdtemp()
    path = Path(directory) / "spec.yml"
    path.write_text(SPEC_PLAYBOOK, encoding="utf-8")
    return path


if __name__ == "__main__":
    unittest.main()

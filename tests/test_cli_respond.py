#!/usr/bin/env python3
"""Tests for `siem respond` -- the guarded execution verb.

The two that are the whole safety model are
`test_without_execute_nothing_runs_and_nothing_is_logged` (subprocess.run never
called, response_actions empty) and `test_there_is_no_yes_to_all` (three
actions, three prompts). They patch `subprocess.run` at its own module, so no
import path in the verb can route around them, and they assert the *absence* of
a call rather than a message about one.

Nothing here runs a real command: every test patches `subprocess.run`, and the
one playbook these tests ship is `cmd /c echo` so that a patch that failed to
apply would still be harmless.
"""

import getpass
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core import store
from core.correlator import correlate
from core.response import DEFAULT_PLAYBOOKS_DIR
from tests.helpers_rules import sample_alert
from tests.test_cli_alerts import ANSI
from tests.test_cli_incidents import defanged, hostile
from tests.test_cli_ingest import IngestTestCase

IP = "203.0.113.9"
USER = "bob"

# Three runnable actions and one manual one: three is what makes the prompt
# count a real check, and the manual one must never be prompted for.
ECHO_PLAYBOOK = """
id: pb-echo
title: Echo Playbook
match:
  tactic: TA0006
  min_severity: HIGH
actions:
  - name: Echo the source IP
    command: ['cmd', '/c', 'echo', 'blocked {source_ip}']
    undo:    ['cmd', '/c', 'echo', 'unblocked {source_ip}']
    risk: medium
  - name: Echo the target user
    command: ['cmd', '/c', 'echo', 'disabled {target_user}']
    risk: high
  - name: Echo a constant
    command: ['cmd', '/c', 'echo', 'third']
    risk: low
  - name: Do this one by hand
    manual: true
    guidance: Read the evidence, then decide which session to log off.
"""

# A playbook whose own literal argument carries an ESC and a newline. The
# playbook file is not attacker-controlled the way a log field is, but it is
# text this verb prints, so it goes through plain() like everything else.
HOSTILE_PLAYBOOK = r"""
id: pb-hostile
title: Hostile Playbook
match:
  tactic: TA0006
  min_severity: HIGH
actions:
  - name: Echo a hostile argument
    command: ["cmd", "/c", "ARG\e[2J\nforged"]
    risk: low
"""

# An action whose command renders cleanly but whose undo does not: one
# target_user in the incident, two source_ips (ruling R114's ambiguity). A
# command that cannot be reversed from the record is not offered at all.
UNDO_FAILS_PLAYBOOK = """
id: pb-undo-fails
title: Undo Placeholder Playbook
match:
  tactic: TA0006
  min_severity: HIGH
actions:
  - name: Command renders but its undo cannot
    command: ['cmd', '/c', 'echo', 'disabled {target_user}']
    undo:    ['cmd', '/c', 'echo', 'unblocked {source_ip}']
    risk: high
"""

BROKEN_PLAYBOOK = """
id: pb-broken
title: Broken Playbook
match:
  tactic: TA0006
  min_severity: HIGH
actions:
  - name: A command written as a string
    command: 'net user bob /active:no'
    risk: low
"""


def text(out):
    """`out` with ANSI removed, as stripped lines."""
    return [line.strip() for line in ANSI.sub("", out).splitlines()]


_ACTION = re.compile(r"\[[~!x+]\] (\d+)\. (.*)$")


def action_lines(out):
    """The numbered action headers as (number, rest-of-line).

    Anchored to the "N. " prefix so a test can say "action 2 is SKIPPED"
    without a stray "SKIPPED" elsewhere in the output satisfying it.
    """
    found = []
    for line in text(out):
        match = _ACTION.match(line)
        if match:
            found.append((int(match.group(1)), match.group(2)))
    return found


def answers(given):
    """A side_effect that yields `given` and then raises EOFError for ever.

    EOF after the answers run out rather than StopIteration: a test that
    under-counts the prompts must fail on the assertion it wrote, not on a
    mock running dry.
    """
    def generate():
        for answer in given:
            yield answer
        while True:
            yield EOFError
    return generate()


class RespondCase(IngestTestCase):
    def setUp(self):
        super().setUp()
        self.books = tempfile.TemporaryDirectory()
        self.addCleanup(self.books.cleanup)
        self.write(ECHO_PLAYBOOK)

    def write(self, playbook, name="echo.yml"):
        path = Path(self.books.name) / name
        path.write_text(playbook, encoding="utf-8")
        return path

    def seed(self, evidence=None, severity="HIGH", tactic="TA0006"):
        """One incident for ip 203.0.113.9 whose alert's evidence names a
        source_ip and a target_user, so both placeholders resolve."""
        if evidence is None:
            evidence = [{"source_ip": IP, "target_user": USER}]
        correlate(self.conn, [sample_alert(
            severity=severity, tactic=tactic, entity_type="ip", entity_value=IP,
            evidence=json.dumps(evidence))])
        self.incident_id = store.query_incidents(self.conn)[0]["id"]
        return self.incident_id

    def respond(self, argv, replies=(), returncode=0, side_effect=None):
        """Run the verb with `subprocess.run` and `input` patched.

        Returns (exit code, stdout, stderr, the subprocess.run mock, the input
        mock). `subprocess.run` is patched on the subprocess module itself, so
        however the verb imports it the call is caught -- and a test that
        asserts it was never called cannot be satisfied by a different import.
        """
        completed = mock.Mock(returncode=returncode)
        # --json is a global flag and goes before the verb (see cli/__init__),
        # so it is hoisted out of argv rather than written there by hand.
        rest = [a for a in argv if a != "--json"]
        head = ["--json"] if "--json" in argv else []
        with mock.patch.object(subprocess, "run", return_value=completed,
                               side_effect=side_effect) as runner, \
                mock.patch("builtins.input", side_effect=answers(replies)) as asked:
            code, out, err = self.run_cli_split(
                head + ["respond", "--playbooks-dir", self.books.name] + rest)
        return code, out, err, runner, asked

    def logged(self):
        return self.conn.execute(
            "SELECT * FROM response_actions ORDER BY id").fetchall()


class TestRespondIsSafeByDefault(RespondCase):
    def test_without_execute_nothing_runs_and_nothing_is_logged(self):
        # The whole safety model. Not "no message about running" -- no call.
        self.seed()
        code, out, _err, runner, asked = self.respond(
            ["--incident", str(self.incident_id)])
        self.assertEqual(0, code)
        runner.assert_not_called()
        asked.assert_not_called()
        self.assertEqual([], self.logged())
        self.assertIn("Nothing has run", "\n".join(text(out)))

    def test_the_plan_lists_every_action_in_order_with_its_risk(self):
        self.seed()
        _code, out, _err, _runner, _asked = self.respond(
            ["--incident", str(self.incident_id)])
        self.assertEqual(
            [(1, "Echo the source IP (risk: medium)"),
             (2, "Echo the target user (risk: high)"),
             (3, "Echo a constant (risk: low)"),
             (4, "Do this one by hand (manual)")], action_lines(out))
        self.assertIn("cmd /c echo blocked {}".format(IP), text(out))

    def test_the_plan_shows_the_undo_command_that_would_be_stored(self):
        self.seed()
        _code, out, _err, _runner, _asked = self.respond(
            ["--incident", str(self.incident_id)])
        self.assertIn("undo: cmd /c echo unblocked {}".format(IP), text(out))

    def test_manual_actions_print_guidance_and_are_never_executable(self):
        self.seed()
        code, out, _err, runner, asked = self.respond(
            ["--incident", str(self.incident_id), "--execute"],
            replies=["n", "n", "n"])
        self.assertEqual(0, code)
        self.assertIn("Read the evidence, then decide which session to log off.",
                      text(out))
        # Three runnable actions, so three prompts: the manual one is not among
        # them however the operator answers.
        self.assertEqual(3, asked.call_count)
        self.assertNotIn("Do this one by hand",
                         "".join(str(c) for c in asked.call_args_list))
        runner.assert_not_called()

    def test_json_lists_matched_playbooks_without_executing(self):
        self.seed()
        code, out, _err, runner, asked = self.respond(
            ["--incident", str(self.incident_id), "--json"])
        self.assertEqual(0, code)
        payload = json.loads(out)
        self.assertEqual(["pb-echo"], [p["id"] for p in payload["playbooks"]])
        self.assertEqual(["cmd", "/c", "echo", "blocked " + IP],
                         payload["playbooks"][0]["actions"][0]["command"])
        self.assertEqual([], payload["executed"])
        runner.assert_not_called()
        asked.assert_not_called()
        self.assertEqual([], self.logged())

    def test_no_matching_playbook_exits_0_and_says_so(self):
        # LOW is below pb-echo's HIGH floor. No match is an answer.
        self.seed(severity="LOW")
        code, out, _err, runner, _asked = self.respond(
            ["--incident", str(self.incident_id)])
        self.assertEqual(0, code)
        self.assertIn("0 playbooks match", "\n".join(text(out)))
        runner.assert_not_called()

    def test_unknown_incident_exits_1(self):
        code, out, _err, runner, _asked = self.respond(["--incident", "4242"])
        self.assertEqual(1, code)
        self.assertIn("No incident with id 4242", "\n".join(text(out)))
        runner.assert_not_called()

    def test_a_rejected_playbook_file_is_reported_and_the_rest_still_load(self):
        self.seed()
        self.write(BROKEN_PLAYBOOK, "broken.yml")
        code, out, _err, _runner, _asked = self.respond(
            ["--incident", str(self.incident_id)])
        self.assertEqual(3, code)
        joined = "\n".join(text(out))
        self.assertIn("broken.yml", joined)
        self.assertIn("pb-echo", joined)

    def test_an_empty_playbook_directory_exits_1(self):
        self.seed()
        empty = tempfile.TemporaryDirectory()
        self.addCleanup(empty.cleanup)
        with mock.patch.object(subprocess, "run") as runner:
            code, out = self.run_cli(["respond", "--playbooks-dir", empty.name,
                                      "--incident", str(self.incident_id)])
        self.assertEqual(1, code)
        self.assertIn("No playbooks loaded", "\n".join(text(out)))
        runner.assert_not_called()

    def test_hostile_text_in_a_playbook_argument_cannot_forge_a_line(self):
        self.seed()
        self.write(HOSTILE_PLAYBOOK, "hostile.yml")
        _code, out, _err, _runner, _asked = self.respond(
            ["--incident", str(self.incident_id)])
        self.assertIn("cmd /c " + defanged("ARG"), text(out))
        self.assertNotIn(hostile("ARG"), out)
        self.assertNotIn("\x1b[2J", out)

    def test_exactly_one_of_incident_and_undo_is_required(self):
        for argv in ([], ["--incident", "1", "--undo", "1"]):
            with self.subTest(argv=argv):
                code, _out, _err, runner, _asked = self.respond(argv)
                self.assertEqual(2, code)
                runner.assert_not_called()

    def test_execute_with_json_is_a_usage_error(self):
        # --json means a script is reading stdout, and a script cannot answer a
        # per-action prompt. Refusing keeps "JSON never executes" structural.
        self.seed()
        code, _out, _err, runner, asked = self.respond(
            ["--incident", str(self.incident_id), "--execute", "--json"])
        self.assertEqual(2, code)
        runner.assert_not_called()
        asked.assert_not_called()

    def test_undo_with_json_is_a_usage_error(self):
        code, _out, _err, runner, asked = self.respond(["--undo", "1", "--json"])
        self.assertEqual(2, code)
        runner.assert_not_called()
        asked.assert_not_called()

    def test_execute_with_undo_is_a_usage_error(self):
        code, _out, _err, runner, _asked = self.respond(
            ["--undo", "1", "--execute"])
        self.assertEqual(2, code)
        runner.assert_not_called()

    def test_the_shipped_pack_is_the_default_playbook_directory(self):
        # Run with no --playbooks-dir at all: the default is the shipped pack,
        # whose pb-brute-force matches TA0006 at HIGH. Read-only either way.
        self.assertTrue(Path(DEFAULT_PLAYBOOKS_DIR).is_dir())
        self.seed()
        with mock.patch.object(subprocess, "run") as runner:
            code, out = self.run_cli(["respond", "--incident",
                                      str(self.incident_id)])
        self.assertEqual(0, code)
        self.assertIn("pb-brute-force", "\n".join(text(out)))
        runner.assert_not_called()
        self.assertEqual([], self.logged())


class TestExecuteConfirmsEachAction(RespondCase):
    def test_execute_prompts_per_action_with_the_rendered_argv(self):
        self.seed()
        code, _out, _err, runner, asked = self.respond(
            ["--incident", str(self.incident_id), "--execute"],
            replies=["y", "n", "n"])
        self.assertEqual(0, code)
        prompts = [c.args[0] for c in asked.call_args_list]
        self.assertEqual(3, len(prompts))
        self.assertIn("cmd /c echo blocked " + IP, prompts[0])
        self.assertIn("cmd /c echo disabled " + USER, prompts[1])
        self.assertIn("cmd /c echo third", prompts[2])
        self.assertEqual([(["cmd", "/c", "echo", "blocked " + IP],)],
                         [c.args for c in runner.call_args_list])

    def test_anything_other_than_y_skips_that_action(self):
        # Exactly "y". A bare "Y" does NOT proceed: the comparison that makes
        # "Y " skip is the one that makes "Y" skip, and the stricter reading is
        # the right default for the verb that changes the host.
        # Seeded once: none of these replies runs anything, so there is no
        # state to reset between them (and re-running setUp would leak a
        # connection, which the ResourceWarning grep would catch).
        self.seed()
        for reply in ("", "n", "N", "Y", "Y ", " y", "y ", "yes", "yes\n",
                      "yolo", EOFError):
            with self.subTest(reply=reply):
                code, _out, _err, runner, asked = self.respond(
                    ["--incident", str(self.incident_id), "--execute"],
                    replies=[reply, reply, reply])
                self.assertEqual(3, asked.call_count)
                runner.assert_not_called()
                self.assertEqual([], self.logged())
                self.assertEqual(0, code)

    def test_exactly_y_proceeds(self):
        # The other half of the pin above: without this, rejecting everything
        # would pass every reply case.
        self.seed()
        _code, _out, _err, runner, _asked = self.respond(
            ["--incident", str(self.incident_id), "--execute"],
            replies=["y", "y", "y"])
        self.assertEqual(3, runner.call_count)
        self.assertEqual(3, len(self.logged()))

    def test_there_is_no_yes_to_all(self):
        # Three actions, three prompts. One "y" authorises one command.
        self.seed()
        _code, _out, _err, runner, asked = self.respond(
            ["--incident", str(self.incident_id), "--execute"],
            replies=["y", "y", "y"])
        self.assertEqual(3, asked.call_count)
        self.assertEqual(3, runner.call_count)

    def test_a_skipped_action_is_not_logged_as_executed(self):
        self.seed()
        _code, _out, _err, _runner, _asked = self.respond(
            ["--incident", str(self.incident_id), "--execute"],
            replies=["n", "y", "n"])
        rows = self.logged()
        self.assertEqual(["Echo the target user"], [r["action_name"] for r in rows])

    def test_shell_false_is_used(self):
        self.seed()
        _code, _out, _err, runner, _asked = self.respond(
            ["--incident", str(self.incident_id), "--execute"], replies=["y"])
        self.assertIs(False, runner.call_args.kwargs["shell"])

    def test_every_execution_is_logged_with_exit_code_and_operator(self):
        self.seed()
        with mock.patch.object(getpass, "getuser", return_value="analyst"):
            _code, _out, _err, _runner, _asked = self.respond(
                ["--incident", str(self.incident_id), "--execute"],
                replies=["y"], returncode=0)
        row = self.logged()[0]
        self.assertEqual(
            (self.incident_id, "pb-echo", "Echo the source IP", 0, "analyst"),
            (row["incident_id"], row["playbook_id"], row["action_name"],
             row["exit_code"], row["operator"]))
        self.assertEqual(["cmd", "/c", "echo", "blocked " + IP],
                         json.loads(row["command"]))
        self.assertEqual(["cmd", "/c", "echo", "unblocked " + IP],
                         json.loads(row["undo_command"]))
        # Stored at second resolution, like every other timestamp the store
        # holds: "2026-10-10 20:55:38" is 19 characters.
        self.assertRegex(str(row["executed_at"]),
                         r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$")

    def test_an_action_with_no_undo_is_logged_without_one(self):
        self.seed()
        self.respond(["--incident", str(self.incident_id), "--execute"],
                     replies=["n", "y"])
        self.assertIsNone(self.logged()[0]["undo_command"])

    def test_the_operator_falls_back_when_getpass_cannot_name_a_user(self):
        # getpass.getuser() raises on a host with no resolvable user, and a
        # traceback there would break spec 13.
        self.seed()
        with mock.patch.object(getpass, "getuser",
                               side_effect=OSError("No username set")):
            code, _out, _err, _runner, _asked = self.respond(
                ["--incident", str(self.incident_id), "--execute"], replies=["y"])
        self.assertEqual(0, code)
        self.assertEqual("unknown", self.logged()[0]["operator"])

    def test_ctrl_c_at_a_prompt_stops_the_run_without_a_traceback(self):
        # Ctrl-C at a confirmation is a refusal, not a crash (spec 13), and it
        # stops the run rather than moving on to the next prompt.
        self.seed()
        code, out, _err, runner, asked = self.respond(
            ["--incident", str(self.incident_id), "--execute"],
            replies=["y", KeyboardInterrupt, "y"])
        self.assertEqual(0, code)
        self.assertEqual(2, asked.call_count)
        self.assertEqual(1, runner.call_count)
        self.assertEqual(1, len(self.logged()))
        self.assertIn("Stopped at your request; nothing further has run.",
                      [line[4:] for line in text(out)])

    def test_declining_everything_exits_0(self):
        self.seed()
        code, _out, _err, _runner, _asked = self.respond(
            ["--incident", str(self.incident_id), "--execute"],
            replies=["n", "n", "n"])
        self.assertEqual(0, code)

    def test_a_nonzero_exit_code_is_logged_and_exits_3(self):
        self.seed()
        code, out, _err, _runner, _asked = self.respond(
            ["--incident", str(self.incident_id), "--execute"],
            replies=["y", "n", "n"], returncode=5)
        self.assertEqual(3, code)
        self.assertEqual(5, self.logged()[0]["exit_code"])
        self.assertIn("exit 5", "\n".join(text(out)))

    def test_a_command_that_cannot_be_started_is_reported_and_not_logged(self):
        # No netsh on this host, say. Nothing ran, so nothing is logged -- and
        # it must not be a traceback.
        self.seed()
        code, out, _err, _runner, _asked = self.respond(
            ["--incident", str(self.incident_id), "--execute"],
            replies=["y", "n", "n"],
            side_effect=FileNotFoundError("no such program"))
        self.assertEqual(3, code)
        self.assertEqual([], self.logged())
        self.assertIn("could not be started", "\n".join(text(out)))

    def test_an_action_whose_placeholder_fails_validation_is_skipped_by_name(self):
        self.seed(evidence=[{"source_ip": IP,
                             "target_user": "bob; net user hax /add"}])
        code, out, _err, runner, asked = self.respond(
            ["--incident", str(self.incident_id), "--execute"],
            replies=["y", "y"])
        self.assertEqual(3, code)
        # The named action is skipped and the run carries on to the next one.
        self.assertEqual(
            [(1, "Echo the source IP (risk: medium)"),
             (2, "Echo the target user (risk: high) -- SKIPPED"),
             (3, "Echo a constant (risk: low)"),
             (4, "Do this one by hand (manual)")], action_lines(out))
        joined = "\n".join(text(out))
        self.assertIn("Echo the target user: target_user:", joined)
        self.assertIn("is not 1 to 64 of letters", joined)
        # Two prompts, not three: the skipped action is never offered.
        self.assertEqual(2, asked.call_count)
        self.assertEqual([["cmd", "/c", "echo", "blocked " + IP],
                          ["cmd", "/c", "echo", "third"]],
                         [c.args[0] for c in runner.call_args_list])

    def test_an_action_whose_undo_cannot_be_rendered_is_not_offered(self):
        # The command itself renders -- one target_user -- but the undo names
        # a source_ip the incident has two of. Running something this tool
        # could not record an undo for is the one-way door the table exists to
        # avoid, so the action is skipped by name and never prompted for.
        self.write(UNDO_FAILS_PLAYBOOK)
        self.seed(evidence=[{"source_ip": "198.51.100.1", "target_user": USER},
                            {"source_ip": "198.51.100.2", "target_user": USER}])
        code, out, _err, runner, asked = self.respond(
            ["--incident", str(self.incident_id), "--execute"], replies=["y"])
        self.assertEqual(3, code)
        self.assertEqual(
            [(1, "Command renders but its undo cannot (risk: high) -- SKIPPED")],
            action_lines(out))
        self.assertIn("source_ip", "\n".join(text(out)))
        asked.assert_not_called()
        runner.assert_not_called()
        self.assertEqual([], self.logged())

    def test_a_validation_failure_is_reported_without_execute_too(self):
        self.seed(evidence=[{"source_ip": IP, "target_user": "a" * 65}])
        code, out, _err, runner, _asked = self.respond(
            ["--incident", str(self.incident_id)])
        self.assertEqual(3, code)
        self.assertIn("Echo the target user (risk: high) -- SKIPPED",
                      [t for _n, t in action_lines(out)])
        runner.assert_not_called()

    def test_a_target_user_of_the_not_recorded_sentinel_skips_that_action(self):
        # Ruling R150, and the shape gate item 10 hit for real on an IP-keyed
        # incident: the evidence records target_user as "-". Spec 11.2's
        # username pattern admits a bare hyphen, so without the filter this
        # printed `cmd /c echo disabled -` and OFFERED it -- a wrong-target
        # action presented as a right one. The IP action is unaffected.
        self.seed(evidence=[{"source_ip": IP, "target_user": "-"}])
        code, out, _err, runner, asked = self.respond(
            ["--incident", str(self.incident_id), "--execute"],
            replies=["n", "n"])
        self.assertEqual(3, code)
        self.assertEqual(
            [(1, "Echo the source IP (risk: medium)"),
             (2, "Echo the target user (risk: high) -- SKIPPED"),
             (3, "Echo a constant (risk: low)"),
             (4, "Do this one by hand (manual)")], action_lines(out))
        joined = "\n".join(text(out))
        # Named, and the honest reason: no value, not a pattern complaint.
        self.assertIn("Echo the target user: target_user: has no value in "
                      "this incident", joined)
        self.assertNotIn("is not 1 to 64 of letters", joined)
        self.assertNotIn("disabled -", joined)
        # The run CONTINUES: the two renderable actions are still offered, in
        # order, and the sentinel one is never among them.
        self.assertEqual(2, asked.call_count)
        self.assertIn("cmd /c echo blocked " + IP, asked.call_args_list[0].args[0])
        self.assertIn("cmd /c echo third", asked.call_args_list[1].args[0])
        runner.assert_not_called()
        self.assertEqual([], self.logged())

    def test_a_sentinel_target_user_is_skipped_without_execute_too(self):
        self.seed(evidence=[{"source_ip": IP, "target_user": "-"}])
        code, out, _err, runner, asked = self.respond(
            ["--incident", str(self.incident_id)])
        self.assertEqual(3, code)
        joined = "\n".join(text(out))
        self.assertIn("has no value in this incident", joined)
        # The IP action still renders in full: one absent placeholder costs
        # one action, never the run.
        self.assertIn("cmd /c echo blocked " + IP, text(out))
        runner.assert_not_called()
        asked.assert_not_called()
        self.assertEqual([], self.logged())

    def test_a_target_user_of_two_hyphens_still_renders(self):
        # Guard on the fix: only the BARE sentinel is absent. If "-" were
        # filtered by "contains a hyphen", this action would be skipped too
        # and a legitimate account name would be unactionable.
        self.seed(evidence=[{"source_ip": IP, "target_user": "--"}])
        code, out, _err, runner, _asked = self.respond(
            ["--incident", str(self.incident_id)])
        self.assertEqual(0, code)
        self.assertIn("cmd /c echo disabled --", text(out))
        self.assertEqual(
            [(1, "Echo the source IP (risk: medium)"),
             (2, "Echo the target user (risk: high)"),
             (3, "Echo a constant (risk: low)"),
             (4, "Do this one by hand (manual)")], action_lines(out))
        runner.assert_not_called()


class TestUndo(RespondCase):
    def execute_one(self):
        """Run action 1 so there is a logged action with an undo command."""
        self.seed()
        self.respond(["--incident", str(self.incident_id), "--execute"],
                     replies=["y"])
        return self.logged()[0]["id"]

    def test_undo_runs_the_stored_undo_under_the_same_confirmation(self):
        action_id = self.execute_one()
        code, _out, _err, runner, asked = self.respond(
            ["--undo", str(action_id)], replies=["y"])
        self.assertEqual(0, code)
        self.assertEqual(1, asked.call_count)
        self.assertIn("cmd /c echo unblocked " + IP, asked.call_args.args[0])
        self.assertEqual(["cmd", "/c", "echo", "unblocked " + IP],
                         runner.call_args.args[0])
        self.assertIs(False, runner.call_args.kwargs["shell"])

    def test_undo_declined_runs_nothing(self):
        action_id = self.execute_one()
        before = len(self.logged())
        code, _out, _err, runner, asked = self.respond(
            ["--undo", str(action_id)], replies=["n"])
        self.assertEqual(0, code)
        self.assertEqual(1, asked.call_count)
        runner.assert_not_called()
        self.assertEqual(before, len(self.logged()))

    def test_undo_of_an_unknown_action_id_exits_1(self):
        code, out, _err, runner, asked = self.respond(["--undo", "4242"])
        self.assertEqual(1, code)
        self.assertIn("No logged response action with id 4242",
                      "\n".join(text(out)))
        runner.assert_not_called()
        asked.assert_not_called()

    def test_undo_of_an_action_with_no_undo_command_exits_1_saying_so(self):
        self.seed()
        self.respond(["--incident", str(self.incident_id), "--execute"],
                     replies=["n", "y"])
        action_id = self.logged()[0]["id"]
        code, out, _err, runner, asked = self.respond(
            ["--undo", str(action_id)], replies=["y"])
        self.assertEqual(1, code)
        self.assertIn("was logged without an undo command",
                      "\n".join(text(out)))
        runner.assert_not_called()
        asked.assert_not_called()

    def test_an_undo_is_itself_logged_and_cannot_be_undone(self):
        action_id = self.execute_one()
        self.respond(["--undo", str(action_id)], replies=["y"])
        rows = self.logged()
        self.assertEqual(2, len(rows))
        self.assertEqual("undo: Echo the source IP", rows[1]["action_name"])
        self.assertEqual(["cmd", "/c", "echo", "unblocked " + IP],
                         json.loads(rows[1]["command"]))
        self.assertIsNone(rows[1]["undo_command"])
        code, out, _err, runner, _asked = self.respond(
            ["--undo", str(rows[1]["id"])], replies=["y"])
        self.assertEqual(1, code)
        self.assertIn("was logged without an undo command", "\n".join(text(out)))
        runner.assert_not_called()

    def test_a_hand_edited_undo_command_that_is_not_an_argv_exits_1(self):
        action_id = self.execute_one()
        for stored in ('"net user bob /active:yes"', "[]", "[1, 2]", "not json",
                       '["ok", ""]'):
            with self.subTest(stored=stored):
                self.conn.execute(
                    "UPDATE response_actions SET undo_command = ? WHERE id = ?",
                    (stored, action_id))
                self.conn.commit()
                code, out, _err, runner, _asked = self.respond(
                    ["--undo", str(action_id)], replies=["y"])
                self.assertEqual(1, code)
                self.assertIn("is not a stored argument list",
                              "\n".join(text(out)))
                runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()

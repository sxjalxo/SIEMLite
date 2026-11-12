import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

import cli
from cli.commands import rules as rules_command
from tests.test_cli_ingest import IngestTestCase
from tests.test_rule_loader_yaml import VALID


SINGLE_EVENT = """
id: win-log-cleared
title: Security Log Cleared
severity: CRITICAL
detection:
  sel:
    event_id: 1102
  condition: sel
fields: [host]
"""


class RulesCase(IngestTestCase):
    """The shared CLI harness (run_cli, run_cli_split) plus four rule packs.

    The temp database IngestTestCase opens is unused here: `rules` needs none.
    """

    def make_pack(self, **files):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        for name, text in files.items():
            (Path(directory.name) / (name + ".yml")).write_text(text, encoding="utf-8")
        return directory.name

    def setUp(self):
        super().setUp()
        self.pack = self.make_pack(rule=VALID)
        self.empty = self.make_pack()
        self.mixed = self.make_pack(good=VALID, bad="not: a rule\n")
        self.allbad = self.make_pack(bad="not: a rule\n")


class TestRulesParser(RulesCase):
    def test_rules_dir_defaults_to_the_shipped_pack(self):
        # The shipped-pack test below skips until Task 9, so this is the only
        # thing that pins the default now. Task 8 imports the constant.
        self.assertEqual(Path("rules/windows"), rules_command.DEFAULT_RULES_DIR)
        args = cli.build_parser().parse_args(["rules", "list"])
        self.assertEqual(rules_command.DEFAULT_RULES_DIR, args.rules_dir)

    def test_a_rule_id_is_refused_by_verbs_that_take_none(self):
        # `rules validate <dir>` would otherwise validate the default pack and
        # report it healthy, whatever the user pointed at.
        for action in ("list", "validate"):
            code, _ = self.run_cli(["rules", action, "somewhere", "--rules-dir", self.pack])
            self.assertEqual(2, code, action)


class TestRulesList(RulesCase):
    def test_list_names_every_rule(self):
        code, out = self.run_cli(["rules", "list", "--rules-dir", self.pack])
        self.assertEqual(0, code)
        self.assertIn("win-bruteforce-4625", out)

    def test_list_json_is_parseable_and_carries_the_fields(self):
        code, out, _ = self.run_cli_split(
            ["--json", "rules", "list", "--rules-dir", self.pack])
        self.assertEqual(0, code)
        payload = json.loads(out)
        self.assertEqual(1, payload["count"])
        self.assertEqual("win-bruteforce-4625", payload["rules"][0]["id"])
        self.assertEqual("HIGH", payload["rules"][0]["severity"])

    def test_an_empty_pack_exits_1_rather_than_reporting_success(self):
        # "0 rules loaded" is a broken install, not a clean run.
        code, out = self.run_cli(["rules", "list", "--rules-dir", self.empty])
        self.assertEqual(1, code)
        self.assertIn("No rules loaded", out)

    def test_list_json_on_an_empty_pack_is_still_json_and_still_exits_1(self):
        code, out, _ = self.run_cli_split(
            ["--json", "rules", "list", "--rules-dir", self.empty])
        self.assertEqual(1, code)
        self.assertEqual(0, json.loads(out)["count"])

    def test_a_directory_holding_only_subdirectories_exits_1(self):
        # rules/ rather than rules/windows/: load_rules reports no error for it.
        (Path(self.empty) / "windows").mkdir()
        code, _ = self.run_cli(["rules", "list", "--rules-dir", self.empty])
        self.assertEqual(1, code)

    def test_a_missing_directory_exits_1_with_the_path_named(self):
        # The loader prints the path through Path, so the separators are the
        # platform's: no/such/dir is no\such\dir on Windows.
        missing = "no/such/dir"
        code, out = self.run_cli(["rules", "list", "--rules-dir", missing])
        self.assertEqual(1, code)
        self.assertIn(str(Path(missing)), out)

    def test_a_half_loaded_pack_lists_what_loaded_and_exits_3(self):
        # Same pack, same meaning as validate: the answer is incomplete, so a
        # 0 here would let a half-loaded pack look healthy.
        code, out = self.run_cli(["rules", "list", "--rules-dir", self.mixed])
        self.assertEqual(3, code)
        self.assertIn("win-bruteforce-4625", out)
        self.assertIn("bad.yml", out)

    def test_list_json_on_a_half_loaded_pack_exits_3(self):
        code, out, _ = self.run_cli_split(
            ["--json", "rules", "list", "--rules-dir", self.mixed])
        self.assertEqual(3, code)
        payload = json.loads(out)
        self.assertEqual(1, payload["count"])
        self.assertEqual(1, len(payload["errors"]))

    def test_a_duplicate_id_is_a_rejected_file_so_list_exits_3(self):
        # load_rules keeps the first and reports the second as an error.
        twin = self.make_pack(a=VALID, b=VALID)
        code, out = self.run_cli(["rules", "list", "--rules-dir", twin])
        self.assertEqual(3, code)
        self.assertIn("already defined", out)


class TestRulesShow(RulesCase):
    def test_show_prints_the_detection_body(self):
        code, out = self.run_cli(
            ["rules", "show", "win-bruteforce-4625", "--rules-dir", self.pack])
        self.assertEqual(0, code)
        self.assertIn("4625", out)
        self.assertIn("T1110.001", out)
        self.assertIn("at least 5 in 5m", out)
        # "4625" is also in the rule's id, so it cannot show the body printed.
        self.assertIn("event_id: 4625", out)
        self.assertIn("sel and not filter", out)

    def test_show_names_the_source_file(self):
        code, out = self.run_cli(
            ["rules", "show", "win-bruteforce-4625", "--rules-dir", self.pack])
        self.assertIn(".yml", out)

    def test_show_json_is_parseable_and_carries_the_detection(self):
        code, out, _ = self.run_cli_split(
            ["--json", "rules", "show", "win-bruteforce-4625",
             "--rules-dir", self.pack])
        self.assertEqual(0, code)
        payload = json.loads(out)
        self.assertEqual("5m", payload["timeframe"])
        self.assertEqual("sel and not filter", payload["condition"])
        self.assertEqual({"event_id": 4625}, payload["selections"]["sel"])

    def test_a_single_event_rule_has_no_threshold(self):
        single = self.make_pack(cleared=SINGLE_EVENT)
        code, out = self.run_cli(
            ["rules", "show", "win-log-cleared", "--rules-dir", single])
        self.assertEqual(0, code)
        self.assertIn("Condition    : sel", out)
        self.assertNotIn("Threshold", out)
        code, out, _ = self.run_cli_split(
            ["--json", "rules", "show", "win-log-cleared", "--rules-dir", single])
        payload = json.loads(out)
        self.assertIsNone(payload["timeframe"])
        self.assertIsNone(payload["count_gte"])

    def test_show_does_not_read_the_rule_file_again(self):
        # The condition shown is the one the loader validated, not whatever the
        # file says by the time show runs; a deleted file must not traceback.
        real_load = rules_command.load_rules

        def load_then_delete(directory):
            rules, errors = real_load(directory)
            for rule in rules:
                Path(rule.source_file).unlink()
            return rules, errors

        with mock.patch.object(rules_command, "load_rules", load_then_delete):
            code, out = self.run_cli(
                ["rules", "show", "win-bruteforce-4625", "--rules-dir", self.pack])
        self.assertEqual(0, code)
        self.assertIn("sel and not filter", out)

    def test_an_unknown_id_exits_1_and_says_so(self):
        code, out = self.run_cli(["rules", "show", "nope", "--rules-dir", self.pack])
        self.assertEqual(1, code)
        self.assertIn("nope", out)

    def test_show_json_for_an_unknown_id_is_json_and_exits_1(self):
        code, out, _ = self.run_cli_split(
            ["--json", "rules", "show", "nope", "--rules-dir", self.pack])
        self.assertEqual(1, code)
        self.assertIn("nope", json.loads(out)["error"])

    def test_an_unknown_id_points_at_a_rejected_file_that_may_be_it(self):
        code, out = self.run_cli(["rules", "show", "nope", "--rules-dir", self.mixed])
        self.assertEqual(1, code)
        self.assertIn("bad.yml", out)
        self.assertIn("failed to load", out)

    def test_show_on_an_empty_pack_says_nothing_loaded_not_unknown_id(self):
        # Exit 1 either way; the message tells a broken install from a typo.
        code, out = self.run_cli(["rules", "show", "nope", "--rules-dir", self.empty])
        self.assertEqual(1, code)
        self.assertIn("No rules loaded", out)

    def test_show_without_an_id_is_a_usage_error(self):
        code, _ = self.run_cli(["rules", "show", "--rules-dir", self.pack])
        self.assertEqual(2, code)


class TestUsageErrorUnderJson(RulesCase):
    """dispatch's ValueError and empty --db handlers, which every verb shares."""

    def test_a_usage_error_goes_to_stderr_so_stdout_stays_json_only(self):
        code, out, err = self.run_cli_split(
            ["--json", "rules", "show", "--rules-dir", self.pack])
        self.assertEqual(2, code)
        self.assertEqual("", out)
        self.assertIn("needs a rule id", err)

    def test_an_empty_db_error_goes_to_stderr_under_json(self):
        code, out, err = self.run_cli_split(
            ["--json", "--db", "", "rules", "list", "--rules-dir", self.pack])
        self.assertEqual(2, code)
        self.assertEqual("", out)
        self.assertIn("--db needs a path", err)

    def test_without_json_the_message_stays_on_stdout(self):
        code, out, err = self.run_cli_split(
            ["rules", "show", "--rules-dir", self.pack])
        self.assertEqual(2, code)
        self.assertIn("needs a rule id", out)
        self.assertEqual("", err)


class TestDuration(unittest.TestCase):
    def test_a_timeframe_prints_in_the_unit_the_file_is_written_in(self):
        for delta, text in [
            (timedelta(minutes=5), "5m"), (timedelta(seconds=30), "30s"),
            (timedelta(seconds=90), "90s"), (timedelta(hours=2), "2h"),
            (timedelta(minutes=120), "2h"), (timedelta(days=1), "1d"),
        ]:
            self.assertEqual(text, rules_command._duration(delta))


class TestRulesValidate(RulesCase):
    def test_a_clean_pack_exits_0(self):
        code, out = self.run_cli(["rules", "validate", "--rules-dir", self.pack])
        self.assertEqual(0, code)
        # The brief asserted "1" in out, which any temp path containing a 1
        # satisfies; this pins the count itself.
        self.assertIn("Loaded 1 rule(s)", out)

    def test_a_pack_with_one_bad_file_exits_3_and_names_it(self):
        # 3 is "partial": the good rules loaded, one did not. Exit 0 would
        # report a half-loaded pack as healthy.
        code, out = self.run_cli(["rules", "validate", "--rules-dir", self.mixed])
        self.assertEqual(3, code)
        self.assertIn("bad.yml", out)

    def test_a_pack_where_everything_is_broken_exits_1(self):
        code, _ = self.run_cli(["rules", "validate", "--rules-dir", self.allbad])
        self.assertEqual(1, code)

    def test_an_empty_pack_exits_1(self):
        code, out = self.run_cli(["rules", "validate", "--rules-dir", self.empty])
        self.assertEqual(1, code)
        self.assertIn("No rules loaded", out)

    def test_validate_json_lists_the_errors(self):
        code, out, _ = self.run_cli_split(
            ["--json", "rules", "validate", "--rules-dir", self.mixed])
        self.assertEqual(3, code)
        payload = json.loads(out)
        self.assertEqual(1, payload["loaded"])
        self.assertEqual(1, len(payload["errors"]))

    def test_validate_runs_against_the_shipped_pack_by_default(self):
        # No --rules-dir: the real rules/windows/ must validate clean. Before
        # Task 9 this directory does not exist, so the test is skipped then
        # and becomes live as soon as the pack lands.
        if not Path("rules/windows").is_dir():
            self.skipTest("rule pack not written yet (Task 9)")
        code, _ = self.run_cli(["rules", "validate"])
        self.assertEqual(0, code)

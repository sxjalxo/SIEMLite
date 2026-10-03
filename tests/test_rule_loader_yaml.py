# tests/test_rule_loader_yaml.py
import tempfile, unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

from core.rule_engine.loader import (
    Rule, RuleError, SEVERITIES, load_rule_file, load_rules, parse_timeframe,
)

VALID = """
id: win-bruteforce-4625
title: Failed Logon Burst From Single Source
status: stable
severity: HIGH
logsource:
  product: windows
  service: security
detection:
  sel:
    event_id: 4625
  filter:
    target_user: ['HealthMailbox', 'DWM-1']
  timeframe: 5m
  count:
    gte: 5
    group_by: [source_ip, target_user]
  condition: sel and not filter
mitre:
  technique: T1110.001
  tactic: TA0006
fields: [source_ip, target_user, host]
description: Five or more failed logons for one user from one source IP.
falsepositives:
  - Service account password rotation
"""


class RuleFileCase(unittest.TestCase):
    def write(self, text, name="rule.yml"):
        path = Path(self.tmp.name) / name
        path.write_text(text, encoding="utf-8")
        return path

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)


class TestValidRule(RuleFileCase):
    def test_every_field_lands_where_the_engine_expects_it(self):
        rule = load_rule_file(self.write(VALID))
        self.assertEqual("win-bruteforce-4625", rule.id)
        self.assertEqual("HIGH", rule.severity)
        self.assertEqual(timedelta(minutes=5), rule.timeframe)
        self.assertEqual(5, rule.count_gte)
        self.assertEqual(("source_ip", "target_user"), rule.group_by)
        self.assertEqual(("source_ip", "target_user", "host"), rule.fields)
        self.assertEqual("T1110.001", rule.technique)
        self.assertEqual("TA0006", rule.tactic)
        self.assertEqual({"sel", "filter"}, set(rule.selections))
        self.assertTrue(rule.condition.evaluate({"sel": True, "filter": False}))

    def test_source_file_is_recorded_for_error_messages_and_rules_show(self):
        path = self.write(VALID)
        self.assertEqual(str(path), load_rule_file(path).source_file)

    def test_a_rule_is_hashable_so_the_engine_can_key_on_it(self):
        # Task 12 scores one contribution per distinct rule, which means
        # putting rules in a set. An unhashable Rule fails there, not here.
        rule = load_rule_file(self.write(VALID))
        self.assertEqual(1, len({rule, rule}))


class TestRejections(RuleFileCase):
    def assert_rejected(self, text, *expected_fragments):
        with self.assertRaises(RuleError) as caught:
            load_rule_file(self.write(text))
        message = str(caught.exception)
        for fragment in expected_fragments:
            self.assertIn(fragment, message)
        self.assertIn("rule.yml", message, "every error must name its file")

    def test_missing_id(self):
        self.assert_rejected(VALID.replace("id: win-bruteforce-4625", ""), "id")

    def test_missing_title(self):
        self.assert_rejected(
            VALID.replace("title: Failed Logon Burst From Single Source", ""), "title")

    def test_missing_severity(self):
        self.assert_rejected(VALID.replace("severity: HIGH", ""), "severity")

    def test_unknown_severity_names_the_allowed_set(self):
        self.assert_rejected(VALID.replace("severity: HIGH", "severity: SPICY"),
                             "SPICY", "CRITICAL")

    def test_unknown_field_name(self):
        self.assert_rejected(VALID.replace("event_id: 4625", "evnet_id: 4625"),
                             "evnet_id")

    def test_unknown_modifier(self):
        self.assert_rejected(
            VALID.replace("event_id: 4625", "event_id|contians: 4625"), "contians")

    def test_condition_naming_a_missing_selection(self):
        self.assert_rejected(
            VALID.replace("condition: sel and not filter",
                          "condition: sel and not fliter"), "fliter")

    def test_count_without_timeframe(self):
        self.assert_rejected(VALID.replace("  timeframe: 5m\n", ""), "timeframe")

    def test_group_by_naming_an_unknown_field(self):
        self.assert_rejected(
            VALID.replace("group_by: [source_ip, target_user]",
                          "group_by: [source_ip, nosuch]"), "nosuch")

    def test_fields_naming_an_unknown_field(self):
        self.assert_rejected(
            VALID.replace("fields: [source_ip, target_user, host]",
                          "fields: [source_ip, nosuch]"), "nosuch")

    def test_empty_detection_block(self):
        self.assert_rejected(VALID.split("detection:")[0] + "detection:\n", "detection")

    def test_detection_with_no_selection_only_metadata(self):
        # timeframe/count/condition are not selections; a rule needs at least one.
        self.assert_rejected(
            VALID.replace("  sel:\n    event_id: 4625\n", "")
                 .replace("  filter:\n    target_user: ['HealthMailbox', 'DWM-1']\n", ""),
            "selection")

    def test_malformed_yaml_is_a_RuleError_not_a_yaml_error(self):
        self.assert_rejected("id: [unclosed\n", "rule.yml")

    def test_a_yaml_file_that_is_not_a_mapping(self):
        self.assert_rejected("- just\n- a\n- list\n", "mapping")

    def test_an_empty_file(self):
        self.assert_rejected("", "empty")

    def test_count_gte_must_be_at_least_two(self):
        # count.gte of 1 is a per-event rule written confusingly; reject it so
        # the author picks one shape or the other.
        self.assert_rejected(VALID.replace("gte: 5", "gte: 1"), "gte")

    def test_a_per_event_rule_needs_fields_for_its_entity(self):
        # No group_by means the entity comes from fields[0] (spec 6.1), so a
        # rule with neither cannot be attributed to anything.
        text = (VALID.replace("  timeframe: 5m\n", "")
                     .replace("  count:\n    gte: 5\n    group_by: [source_ip, target_user]\n", "")
                     .replace("fields: [source_ip, target_user, host]", "fields: []"))
        self.assert_rejected(text, "fields")


class TestTimeframe(unittest.TestCase):
    def test_units(self):
        self.assertEqual(timedelta(minutes=5), parse_timeframe("5m"))
        self.assertEqual(timedelta(hours=2), parse_timeframe("2h"))
        self.assertEqual(timedelta(seconds=30), parse_timeframe("30s"))
        self.assertEqual(timedelta(days=1), parse_timeframe("1d"))

    def test_a_bad_timeframe_raises(self):
        for bad in ("5", "m", "5 minutes", "-5m", "0m", ""):
            with self.assertRaises(ValueError, msg=bad):
                parse_timeframe(bad)


class TestLoadRules(RuleFileCase):
    def test_a_directory_loads_every_yml_and_yaml_file(self):
        self.write(VALID, "a.yml")
        self.write(VALID.replace("win-bruteforce-4625", "other"), "b.yaml")
        rules, errors = load_rules(Path(self.tmp.name))
        self.assertEqual([], errors)
        self.assertEqual({"win-bruteforce-4625", "other"}, {r.id for r in rules})

    def test_one_bad_file_does_not_stop_the_others(self):
        self.write(VALID, "good.yml")
        self.write("id: [unclosed\n", "bad.yml")
        rules, errors = load_rules(Path(self.tmp.name))
        self.assertEqual(["win-bruteforce-4625"], [r.id for r in rules])
        self.assertEqual(1, len(errors))
        self.assertIn("bad.yml", str(errors[0]))

    def test_a_duplicate_rule_id_is_an_error_not_a_silent_overwrite(self):
        self.write(VALID, "a.yml")
        self.write(VALID, "b.yml")
        rules, errors = load_rules(Path(self.tmp.name))
        self.assertEqual(1, len(rules))
        self.assertEqual(1, len(errors))
        self.assertIn("win-bruteforce-4625", str(errors[0]))

    def test_rules_load_in_a_stable_order(self):
        for name in ("c.yml", "a.yml", "b.yml"):
            self.write(VALID.replace("win-bruteforce-4625", name[0]), name)
        rules, _ = load_rules(Path(self.tmp.name))
        self.assertEqual(["a", "b", "c"], [r.id for r in rules])

    def test_a_missing_directory_is_an_error_not_an_empty_pack(self):
        rules, errors = load_rules(Path(self.tmp.name) / "nope")
        self.assertEqual([], rules)
        self.assertEqual(1, len(errors))

    def test_non_yaml_files_are_ignored(self):
        self.write(VALID, "a.yml")
        self.write("not yaml at all", "README.md")
        rules, errors = load_rules(Path(self.tmp.name))
        self.assertEqual([], errors)
        self.assertEqual(1, len(rules))


class TestSeverities(unittest.TestCase):
    def test_ordered_lowest_to_highest(self):
        self.assertEqual(("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"), SEVERITIES)


class RejectionCase(RuleFileCase):
    def assert_rejected(self, text, *fragments):
        with self.assertRaises(RuleError) as caught:
            load_rule_file(self.write(text))
        for fragment in fragments:
            self.assertIn(fragment, str(caught.exception))


class TestErrorShape(RejectionCase):
    def test_a_RuleError_carries_the_path_and_the_key(self):
        path = self.write(VALID.replace("severity: HIGH", "severity: SPICY"))
        with self.assertRaises(RuleError) as caught:
            load_rule_file(path)
        self.assertEqual(str(path), str(caught.exception.path))
        self.assertEqual("severity", caught.exception.key)

    def test_a_non_text_id_is_rejected(self):
        with self.assertRaises(RuleError) as caught:
            load_rule_file(self.write(VALID.replace("win-bruteforce-4625", "4625")))
        self.assertEqual("id", caught.exception.key)


class TestYamlIsData(RejectionCase):
    def test_a_python_tag_is_refused_not_constructed(self):
        # yaml.load would build the object and fail later, for another reason.
        self.assert_rejected(
            VALID.replace("win-bruteforce-4625", "!!python/name:os.getcwd"),
            "python/name")

    def test_deep_nesting_is_a_RuleError_not_a_RecursionError(self):
        self.assert_rejected("id: " + "[" * 2000 + "]" * 2000 + "\n", "rule.yml")


class TestDuplicateKeys(RejectionCase):
    """safe_load keeps the last of two equal keys, so the first silently vanishes
    and takes its detection logic with it (ruling R62)."""

    def test_a_duplicate_key_inside_one_selection(self):
        self.assert_rejected(
            VALID.replace("    event_id: 4625\n", "    event_id: 4625\n    event_id: 4624\n"),
            "duplicate", "event_id", "line 12")

    def test_two_selections_with_the_same_name(self):
        self.assert_rejected(
            VALID.replace("  filter:\n", "  sel:\n    user: a\n  filter:\n"),
            "duplicate", "sel", "line 12")

    def test_a_duplicate_at_the_top_level(self):
        self.assert_rejected(VALID + "severity: LOW\n", "duplicate", "severity")

    def test_a_duplicate_under_count(self):
        self.assert_rejected(VALID.replace("gte: 5", "gte: 5\n    gte: 6"),
                             "duplicate", "gte")

    def test_a_duplicate_inside_a_list_of_mappings_is_found(self):
        self.assert_rejected(
            VALID.replace("falsepositives:\n  - Service account password rotation",
                          "falsepositives:\n  - {a: 1, a: 2}"), "duplicate")

    def test_a_shared_alias_is_not_a_duplicate(self):
        # Aliases make the node graph shared; the walk must neither report nor loop.
        text = (VALID.replace("    event_id: 4625\n", "    event_id: 4625\n    user: &u [a, b]\n")
                     .replace("    target_user: ['HealthMailbox', 'DWM-1']",
                              "    target_user: *u"))
        load_rule_file(self.write(text))


class TestUnknownKeys(RejectionCase):
    def test_a_misspelt_top_level_key_names_it_and_lists_the_allowed(self):
        self.assert_rejected(
            VALID.replace("fields:", "feilds:") + "fields: [host]\n",
            "feilds", "allowed", "falsepositives")

    def test_a_misspelt_mitre_key(self):
        self.assert_rejected(VALID.replace("technique:", "tecnique:"), "tecnique")

    def test_every_key_the_loader_reads_is_allowed(self):
        load_rule_file(self.write(VALID))


class TestYamlTypeTraps(RejectionCase):
    """YAML turns 0xC000006D into 3221225581 and `no` into False. Neither can
    equal the stored text, so the rule would load and never fire (ruling R61)."""

    def sel(self, line):
        return VALID.replace("event_id: 4625", line)

    def test_an_unquoted_hex_value_on_a_text_field(self):
        self.assert_rejected(self.sel("status: 0xC000006D"),
                             "status", "3221225581", "quote")

    def test_the_ntlm_shape_status_not_0x0(self):
        self.assert_rejected(self.sel("status|not: 0x0"), "status|not", "quote")

    def test_an_unquoted_bool_on_a_text_field(self):
        self.assert_rejected(self.sel("host: no"), "host", "False", "quote")

    def test_a_listed_value_is_checked_too(self):
        self.assert_rejected(self.sel("status: ['0x1', 0xC000006D]"),
                             "3221225581", "quote")

    def test_quoted_values_on_a_text_field_load(self):
        for line in ("status: '0xC000006D'", "status|not: '0x0'", "host: 'no'"):
            with self.subTest(line=line):
                load_rule_file(self.write(self.sel(line)))

    def test_a_string_on_an_int_field_stays_legal(self):
        # The matcher compares str() of both sides: event_id '4625' matches 4625.
        load_rule_file(self.write(self.sel("event_id: '4625'")))

    def test_a_nested_mapping_value_is_rejected(self):
        # An indentation slip turns `event_id: 4625` into a mapping.
        self.assert_rejected(self.sel("event_id:\n      gt: 5"), "event_id")

    def test_the_message_does_not_claim_a_cause_that_is_wrong_for_a_decimal(self):
        self.assert_rejected(self.sel("host: 1.10"), "host", "decimals", "quote")

    # Ruling R63: R61 extended to int fields. An int or a string is fine there
    # (the matcher compares str() of both sides); anything else YAML produced
    # compares against text that can never equal the stored number.

    def test_a_float_on_an_int_field(self):
        self.assert_rejected(self.sel("event_id: 4625.0"), "event_id", "4625.0", "float")

    def test_a_bool_on_an_int_field(self):
        # bool is a subclass of int, so a bare isinstance(want, int) lets this by.
        self.assert_rejected(self.sel("logon_type: yes"), "logon_type", "True", "bool")

    def test_a_date_on_an_int_field(self):
        self.assert_rejected(self.sel("event_id: 2026-01-01"), "event_id", "date")

    def test_a_listed_float_on_an_int_field(self):
        self.assert_rejected(self.sel("event_id: [4625, 4625.0]"), "4625.0")

    def test_int_and_string_both_load_on_an_int_field(self):
        for line in ("event_id: 4625", "event_id: '4625'", "event_id: [4624, '4625']",
                     "dest_port|gt: 1024", "event_id|startswith: '46'"):
            with self.subTest(line=line):
                load_rule_file(self.write(self.sel(line)))


class TestSelectionNames(RejectionCase):
    def test_a_name_the_condition_cannot_spell_is_rejected(self):
        for bad in ("bad-name", "1abc", "has space"):
            with self.subTest(name=bad):
                self.assert_rejected(
                    VALID.replace("  filter:", "  '{}':".format(bad)), "selection name")

    def test_an_operator_word_is_rejected_as_a_name(self):
        for word in ("and", "or", "not"):
            with self.subTest(name=word):
                self.assert_rejected(
                    VALID.replace("  filter:", "  {}:".format(word)),
                    "selection name", "'{}'".format(word))

    def test_a_non_text_name_is_rejected(self):
        # YAML reads `no:` as the key False.
        self.assert_rejected(VALID.replace("  filter:", "  no:"), "selection name")

    def test_an_uppercase_operator_is_named_with_the_selections_that_exist(self):
        # The tokenizer's own message already says what is wrong and what to use.
        self.assert_rejected(
            VALID.replace("sel and not filter", "sel AND NOT filter"),
            "detection.condition", "'AND'", "have: filter, sel")


class TestEveryFieldSpecIsChecked(RejectionCase):
    def sel(self, line):
        return VALID.replace("event_id: 4625", line)

    def test_a_typo_in_the_second_key(self):
        self.assert_rejected(
            VALID.replace("event_id: 4625\n", "event_id: 4625\n    nosuch_field: x\n"),
            "nosuch_field")

    def test_an_unknown_modifier_lists_the_valid_ones(self):
        self.assert_rejected(self.sel("event_id|contians: 4625"),
                             "contians", "contains", "hour_in")

    def test_a_bad_regex_after_a_good_one(self):
        # The matcher's any() stops at the first hit, so a bad later value would
        # only raise on events that miss the good one. The loader must not rely on it.
        self.assert_rejected(self.sel("command_line|re: ['.', '(']"), "invalid regex")

    def test_a_non_numeric_value_after_a_numeric_one(self):
        self.assert_rejected(self.sel("event_id|gte: [0, abc]"), "abc")

    def test_an_empty_substring(self):
        self.assert_rejected(self.sel("target_user|contains: ''"), "empty string")

    def test_a_key_with_no_value(self):
        self.assert_rejected(self.sel("event_id:"), "event_id")

    def test_an_empty_selection(self):
        self.assert_rejected(VALID.replace("    event_id: 4625\n", "    {}\n"), "sel")

    def test_a_bad_hour(self):
        self.assert_rejected(self.sel("timestamp|hour_in: [25]"), "hour")

    def test_hour_modifiers_need_a_timestamp_field(self):
        self.assert_rejected(self.sel("host|hour_in: [7]"), "timestamp")

    def test_two_operators(self):
        self.assert_rejected(self.sel("host|contains|endswith: x"), "operator")


class TestCountAndTimeframe(RejectionCase):
    COUNT_BLOCK = "  count:\n    gte: 5\n    group_by: [source_ip, target_user]\n"

    def test_a_timeframe_without_a_count_is_dead_text(self):
        self.assert_rejected(VALID.replace(self.COUNT_BLOCK, ""), "timeframe", "count")

    def test_an_unknown_key_under_count(self):
        self.assert_rejected(VALID.replace("group_by: [", "group-by: ["), "group-by")

    def test_gte_must_be_an_integer(self):
        for bad in ("true", "'5'", "5.5"):
            with self.subTest(gte=bad):
                self.assert_rejected(VALID.replace("gte: 5", "gte: " + bad), "gte")

    def test_count_without_gte(self):
        self.assert_rejected(VALID.replace("    gte: 5\n", ""), "gte")

    def test_a_timeframe_that_is_not_text(self):
        self.assert_rejected(VALID.replace("timeframe: 5m", "timeframe: 300"), "timeframe")

    def test_a_zero_timeframe(self):
        self.assert_rejected(VALID.replace("timeframe: 5m", "timeframe: 0m"), "timeframe")

    def test_a_per_event_rule_has_no_threshold_state(self):
        rule = load_rule_file(self.write(
            VALID.replace("  timeframe: 5m\n", "").replace(self.COUNT_BLOCK, "")))
        self.assertIsNone(rule.timeframe)
        self.assertIsNone(rule.count_gte)
        self.assertEqual((), rule.group_by)


class TestPackOrderDoesNotDependOnTheFilesystem(RuleFileCase):
    def test_order_and_first_wins_hold_when_the_filesystem_lists_backwards(self):
        # NTFS lists names alphabetically, so only a hostile listing proves the sort.
        self.write(VALID.replace("win-bruteforce-4625", "dup"), "a.yml")
        self.write(VALID.replace("win-bruteforce-4625", "dup"), "z.yml")
        self.write(VALID.replace("win-bruteforce-4625", "m"), "m.yml")
        real = Path.iterdir
        with mock.patch.object(
                Path, "iterdir", lambda self: iter(sorted(real(self), reverse=True))):
            rules, errors = load_rules(Path(self.tmp.name))
        self.assertEqual(["dup", "m"], [r.id for r in rules])
        self.assertTrue(rules[0].source_file.endswith("a.yml"))
        self.assertIn("z.yml", str(errors[0]))

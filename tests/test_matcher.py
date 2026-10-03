# tests/test_matcher.py
import unittest
from datetime import datetime

from core.rule_engine.matcher import (
    MODIFIERS, match_event, match_selection, parse_condition, parse_field_spec,
)
from ingestion.normalizer import NormalizedEvent


def event(**kwargs):
    """A NormalizedEvent with the four required fields filled in."""
    base = dict(
        timestamp=datetime(2026, 10, 3, 14, 30, 0), source_type="windows",
        host="PC-01", channel="Security", event_id=4625, record_id=1,
        action="LOGIN_FAIL", raw="<Event/>",
    )
    base.update(kwargs)
    return NormalizedEvent(**base)


class TestParseFieldSpec(unittest.TestCase):
    def test_bare_field_has_no_modifiers(self):
        self.assertEqual(("event_id", ()), parse_field_spec("event_id"))

    def test_single_modifier(self):
        self.assertEqual(("command_line", ("contains",)),
                         parse_field_spec("command_line|contains"))

    def test_modifiers_keep_their_order(self):
        # The parse keeps the order as written. The matcher negates by parity,
        # so `not|contains` and `contains|not` mean the same thing.
        self.assertEqual(("command_line", ("not", "contains")),
                         parse_field_spec("command_line|not|contains"))

    def test_whitespace_is_tolerated(self):
        self.assertEqual(("user", ("contains",)), parse_field_spec(" user | contains "))

    def test_empty_field_name_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_field_spec("|contains")


class TestEquality(unittest.TestCase):
    def test_int_equality(self):
        self.assertTrue(match_selection(event(event_id=4625), {"event_id": 4625}))
        self.assertFalse(match_selection(event(event_id=4624), {"event_id": 4625}))

    def test_string_equality_is_case_insensitive(self):
        self.assertTrue(match_selection(event(user="Administrator"), {"user": "administrator"}))

    def test_a_list_is_or_over_values(self):
        sel = {"event_id": [4728, 4732]}
        self.assertTrue(match_selection(event(event_id=4732), sel))
        self.assertFalse(match_selection(event(event_id=4625), sel))

    def test_multiple_fields_are_and(self):
        sel = {"event_id": 4625, "logon_type": 10}
        self.assertTrue(match_selection(event(event_id=4625, logon_type=10), sel))
        self.assertFalse(match_selection(event(event_id=4625, logon_type=2), sel))

    def test_an_int_field_compared_to_a_string_value_still_matches(self):
        # YAML quoting is an authoring accident, not a semantic choice.
        self.assertTrue(match_selection(event(event_id=4625), {"event_id": "4625"}))

    def test_unknown_field_raises_rather_than_never_matching(self):
        # A typo must be loud. Task 3 catches it at load time; this is the backstop.
        with self.assertRaises(ValueError):
            match_selection(event(), {"nosuchfield": 1})


class TestStringModifiers(unittest.TestCase):
    def test_contains_is_case_insensitive(self):
        ev = event(command_line="powershell -EncodedCommand ABC")
        self.assertTrue(match_selection(ev, {"command_line|contains": "encodedcommand"}))

    def test_contains_over_a_list_is_or(self):
        ev = event(command_line="certutil -urlcache -f http://x/y")
        self.assertTrue(match_selection(
            ev, {"command_line|contains": ["mshta", "certutil"]}))

    def test_startswith_and_endswith(self):
        self.assertTrue(match_selection(event(object_name="ADMIN$"),
                                        {"object_name|endswith": "$"}))
        self.assertTrue(match_selection(event(process="C:\\Windows\\cmd.exe"),
                                        {"process|startswith": "c:\\windows"}))

    def test_re_is_searched_not_fullmatched(self):
        ev = event(command_line="cmd /c whoami")
        self.assertTrue(match_selection(ev, {"command_line|re": r"/c\s+whoami"}))

    def test_an_invalid_regex_raises_a_clear_error(self):
        with self.assertRaises(ValueError):
            match_selection(event(), {"command_line|re": "("})

    def test_not_negates(self):
        ev = event(user="svc_backup")
        self.assertFalse(match_selection(ev, {"user|not": "svc_backup"}))
        self.assertTrue(match_selection(ev, {"user|not": "administrator"}))

    def test_not_contains_combines(self):
        ev = event(command_line="powershell -nop -w hidden")
        self.assertTrue(match_selection(ev, {"command_line|not|contains": "encoded"}))
        self.assertFalse(match_selection(ev, {"command_line|not|contains": "hidden"}))

    def test_not_negates_the_whole_value_list(self):
        # not(any(...)), never any(not ...): with the second reading a list
        # that contains the actual value would still match.
        ev = event(user="alice")
        self.assertFalse(match_selection(ev, {"user|not": ["alice", "bob"]}))
        self.assertFalse(match_selection(
            ev, {"user|not|contains": ["alic", "zzz"]}))
        self.assertTrue(match_selection(ev, {"user|not": ["bob", "carol"]}))

    def test_in_is_explicit_or(self):
        self.assertTrue(match_selection(event(action="LOGIN_FAIL"),
                                        {"action|in": ["LOGIN_FAIL", "LOGIN_OK"]}))


class TestNumericModifiers(unittest.TestCase):
    def test_gt_lt_gte_lte(self):
        ev = event(dest_port=4444)
        self.assertTrue(match_selection(ev, {"dest_port|gt": 1024}))
        self.assertFalse(match_selection(ev, {"dest_port|lt": 1024}))
        self.assertTrue(match_selection(ev, {"dest_port|gte": 4444}))
        self.assertTrue(match_selection(ev, {"dest_port|lte": 4444}))

    def test_a_non_numeric_field_value_does_not_match_rather_than_raising(self):
        # `-` is the unknown token for strings; comparing it numerically is
        # a no-match, not a crash. A rule must not be able to kill a run.
        self.assertFalse(match_selection(event(user="-"), {"user|gt": 5}))


class TestHourModifiers(unittest.TestCase):
    def test_hour_in_accepts_a_bare_hour(self):
        ev = event(timestamp=datetime(2026, 10, 3, 3, 0, 0))
        self.assertTrue(match_selection(ev, {"timestamp|hour_in": [3]}))

    def test_hour_in_accepts_a_range_string(self):
        ev = event(timestamp=datetime(2026, 10, 3, 14, 30, 0))
        self.assertTrue(match_selection(ev, {"timestamp|hour_in": ["7..19"]}))

    def test_a_range_is_inclusive_at_both_ends(self):
        self.assertTrue(match_selection(event(timestamp=datetime(2026, 10, 3, 7, 0)),
                                        {"timestamp|hour_in": ["7..19"]}))
        self.assertTrue(match_selection(event(timestamp=datetime(2026, 10, 3, 19, 59)),
                                        {"timestamp|hour_in": ["7..19"]}))

    def test_hour_not_in_is_the_off_hours_case(self):
        # Rule 13: an interactive logon outside 07:00-19:59.
        self.assertTrue(match_selection(event(timestamp=datetime(2026, 10, 3, 2, 15)),
                                        {"timestamp|hour_not_in": ["7..19"]}))
        self.assertFalse(match_selection(event(timestamp=datetime(2026, 10, 3, 9, 15)),
                                         {"timestamp|hour_not_in": ["7..19"]}))

    def test_a_wrapping_range_covers_midnight(self):
        # 22..5 means the night shift, not the empty set.
        for hour in (23, 0, 4):
            self.assertTrue(
                match_selection(event(timestamp=datetime(2026, 10, 3, hour)),
                                {"timestamp|hour_in": ["22..5"]}),
                "hour {} should be inside 22..5".format(hour))
        self.assertFalse(match_selection(event(timestamp=datetime(2026, 10, 3, 12)),
                                         {"timestamp|hour_in": ["22..5"]}))

    def test_hour_modifiers_on_a_non_timestamp_field_raise(self):
        with self.assertRaises(ValueError):
            match_selection(event(), {"user|hour_in": [3]})


class TestCondition(unittest.TestCase):
    def test_single_selection(self):
        cond = parse_condition("sel", {"sel"})
        self.assertTrue(cond.evaluate({"sel": True}))
        self.assertFalse(cond.evaluate({"sel": False}))

    def test_and_or_not(self):
        cond = parse_condition("sel and not filter", {"sel", "filter"})
        self.assertTrue(cond.evaluate({"sel": True, "filter": False}))
        self.assertFalse(cond.evaluate({"sel": True, "filter": True}))

    def test_not_binds_tighter_than_and(self):
        cond = parse_condition("not a and b", {"a", "b"})
        self.assertTrue(cond.evaluate({"a": False, "b": True}))
        self.assertFalse(cond.evaluate({"a": True, "b": True}))

    def test_and_binds_tighter_than_or(self):
        # a or (b and c), so a alone is enough.
        cond = parse_condition("a or b and c", {"a", "b", "c"})
        self.assertTrue(cond.evaluate({"a": True, "b": False, "c": False}))
        self.assertFalse(cond.evaluate({"a": False, "b": True, "c": False}))

    def test_parentheses_override_precedence(self):
        cond = parse_condition("(a or b) and c", {"a", "b", "c"})
        self.assertFalse(cond.evaluate({"a": True, "b": False, "c": False}))
        self.assertTrue(cond.evaluate({"a": True, "b": False, "c": True}))

    def test_an_unknown_selection_name_is_rejected_by_name(self):
        with self.assertRaisesRegex(ValueError, "typo"):
            parse_condition("sel and typo", {"sel"})

    def test_unbalanced_parentheses_are_rejected(self):
        with self.assertRaises(ValueError):
            parse_condition("(a and b", {"a", "b"})

    def test_a_trailing_operator_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_condition("a and", {"a"})

    def test_an_empty_condition_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_condition("   ", {"a"})

    def test_rule_text_cannot_execute(self):
        # The condition is parsed, never eval()'d. This is the regression
        # guard for that: a payload is an unknown token, not code.
        with self.assertRaises(ValueError):
            parse_condition("__import__('os').system('echo pwned')", {"sel"})


class TestMatchEvent(unittest.TestCase):
    def test_selection_and_negated_filter(self):
        selections = {
            "sel": {"event_id": 4625},
            "filter": {"target_user": ["HealthMailbox", "DWM-1"]},
        }
        cond = parse_condition("sel and not filter", set(selections))
        self.assertTrue(match_event(event(target_user="alice"), selections, cond))
        self.assertFalse(match_event(event(target_user="DWM-1"), selections, cond))

    def test_modifiers_frozenset_is_the_validation_source(self):
        # Task 3 validates rule files against this, so it must be exact:
        # a missing name rejects a valid rule, an extra one admits a dead rule.
        self.assertEqual(
            {"contains", "startswith", "endswith", "re", "gt", "lt", "gte",
             "lte", "in", "not", "hour_in", "hour_not_in"},
            MODIFIERS,
        )


class TestHostileInput(unittest.TestCase):
    """Beyond the brief: a shared rule file must not be able to crash a run."""

    def test_an_unknown_modifier_raises(self):
        with self.assertRaisesRegex(ValueError, "bogus"):
            match_selection(event(), {"user|bogus": "x"})

    def test_two_operators_in_one_chain_raise(self):
        with self.assertRaises(ValueError):
            match_selection(event(), {"user|contains|startswith": "x"})

    def test_an_empty_selection_raises_rather_than_matching_everything(self):
        with self.assertRaises(ValueError):
            match_selection(event(), {})

    def test_a_valueless_or_empty_list_key_raises(self):
        for value in (None, []):
            with self.assertRaises(ValueError, msg=repr(value)):
                match_selection(event(), {"user": value})

    def test_a_non_numeric_rule_value_for_gt_raises(self):
        with self.assertRaises(ValueError):
            match_selection(event(), {"dest_port|gt": "high"})

    def test_an_out_of_range_hour_raises(self):
        for bad in ([24], ["7..30"], ["a..b"], ["x"]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                match_selection(event(), {"timestamp|hour_in": bad})

    def test_evaluate_with_a_missing_result_raises_even_after_a_short_circuit(self):
        # `a or b` with a=True must still notice that the engine forgot b.
        cond = parse_condition("a or b", {"a", "b"})
        with self.assertRaises(KeyError):
            cond.evaluate({"a": True})

    def test_an_overlong_condition_is_rejected_not_a_recursion_error(self):
        deep = "(" * 150 + "a" + ")" * 150
        with self.assertRaises(ValueError):
            parse_condition(deep, {"a"})
        with self.assertRaises(ValueError):
            parse_condition(" and ".join(["a"] * 150), {"a"})

    def test_the_longest_allowed_condition_parses_and_evaluates(self):
        cond = parse_condition("(" * 99 + "a" + ")" * 99, {"a"})
        self.assertTrue(cond.evaluate({"a": True}))
        cond = parse_condition(" and ".join(["a"] * 100), {"a"})
        self.assertTrue(cond.evaluate({"a": True}))

    def test_stray_tokens_are_rejected_by_name(self):
        for text in ("a b", "a )", "a && b", "AND a", "or a"):
            with self.assertRaises(ValueError, msg=text):
                parse_condition(text, {"a", "b"})

    def test_a_bad_key_raises_even_when_an_earlier_key_does_not_match(self):
        # event_id is 4624, so the first key fails; the second must still be
        # checked, or a typo raises only for events that happen to match.
        ev = event(event_id=4624)
        for bad in ({"nosuchfield": 1},
                    {"command_line|re": "("},
                    {"user|bogus": "x"},
                    {"timestamp|hour_in": [99]},
                    {"user": None},
                    {"user|contains": ""}):
            selection = dict({"event_id": 4625}, **bad)
            with self.assertRaises(ValueError, msg=repr(bad)):
                match_selection(ev, selection)

    def test_a_huge_rule_number_raises_valueerror_not_overflowerror(self):
        with self.assertRaises(ValueError):
            match_selection(event(), {"dest_port|gt": 10 ** 400})

    def test_a_huge_field_number_is_a_no_match_not_overflowerror(self):
        # _to_int is unbounded, so a crafted 400-digit port reaches float().
        self.assertFalse(match_selection(event(dest_port=10 ** 400),
                                         {"dest_port|gt": 5}))

    def test_a_hostile_regex_raises_valueerror_naming_the_field_briefly(self):
        for pattern in ("(" * 5000 + ")" * 5000, "a{99999999999}"):
            with self.assertRaises(ValueError, msg=pattern[:12]) as ctx:
                match_selection(event(), {"user|re": pattern})
            self.assertIn("user|re", str(ctx.exception))
            self.assertLess(len(str(ctx.exception)), 300)

    def test_an_empty_string_substring_is_rejected_not_match_all(self):
        for op in ("contains", "startswith", "endswith", "re"):
            for value in ("", ["x", ""]):
                with self.assertRaises(ValueError, msg=(op, value)):
                    match_selection(event(), {"user|" + op: value})


class TestEveryValueInAListIsChecked(unittest.TestCase):
    """`any()` stops at the first value that matches, so a bad value after it was
    never evaluated: the typo raised only for events the earlier values missed.
    These events MATCH the first value, which is the case short-circuiting hid."""

    def test_a_bad_regex_after_one_that_matches(self):
        with self.assertRaisesRegex(ValueError, "invalid regex"):
            match_selection(event(command_line="powershell"),
                            {"command_line|re": ["power", "("]})

    def test_a_non_numeric_value_after_one_that_matches(self):
        with self.assertRaisesRegex(ValueError, "abc"):
            match_selection(event(event_id=4625), {"event_id|gte": [0, "abc"]})

    def test_a_malformed_hour_range_after_one_that_contains_the_hour(self):
        # The default event is at 14:30, inside 0..23, so the first range matches.
        for op in ("hour_in", "hour_not_in"):
            for bad in ("99", "a..b", "7..30"):
                with self.subTest(op=op, bad=bad), self.assertRaisesRegex(ValueError, "hour"):
                    match_selection(event(), {"timestamp|" + op: ["0..23", bad]})

    def test_a_good_list_still_matches_and_still_misses(self):
        self.assertTrue(match_selection(event(user="bob"), {"user": ["bob", "alice"]}))
        self.assertFalse(match_selection(event(user="eve"), {"user": ["bob", "alice"]}))


if __name__ == "__main__":
    unittest.main()

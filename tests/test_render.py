"""cli/render.py on its own, without a verb in front of it.

The verbs' tests cover these functions through the output they produce. These
pin the cases a verb would have to go out of its way to reach: ruling R104's
empty-cells crash, which every caller so far happened to guard against, and the
column widths the padding is built from.
"""

import contextlib
import io
import unittest

from cli.render import clip, event_fields, hashes, plain, print_table, tactic_ids
from tests import helpers_rules
from tests.test_cli_alerts import ANSI


def printed(*args, **kwargs):
    """print_table's output as lines, with the colour codes removed."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        print_table(*args, **kwargs)
    return ANSI.sub("", out.getvalue()).splitlines()


class TestPrintTable(unittest.TestCase):
    def test_no_cells_prints_the_headers_alone(self):
        # Ruling R104: this raised TypeError: 'int' object is not iterable,
        # because max(len(h), *(...)) gets one argument when there are no
        # cells. Two agents hit it independently while writing callers that
        # guard, so the guard-by-convention was not holding.
        self.assertEqual(["  A  B"], printed(("A", "B"), []))

    def test_a_cell_wider_than_its_header_widens_the_whole_column(self):
        # The width is the widest of the header and every cell, so the second
        # column starts in the same place on both rows. A width taken from the
        # headers alone would leave the rows ragged.
        self.assertEqual(["  A     B", "  xxxx  y", "  z     w"],
                         printed(("A", "B"), [("xxxx", "y"), ("z", "w")]))

    def test_a_header_wider_than_its_cells_still_fits(self):
        self.assertEqual(["  LONG  B", "  x     y"],
                         printed(("LONG", "B"), [("x", "y")]))


class TestEventFields(unittest.TestCase):
    def test_only_the_recorded_fields_are_listed(self):
        # "-" is Windows' "not recorded" and is left out, so the column says
        # what the event has rather than what it lacks.
        event = helpers_rules.event(user="alice", source_ip="1.2.3.4")
        self.assertEqual("user=alice source_ip=1.2.3.4", event_fields(event))

    def test_a_control_character_cannot_reach_the_terminal(self):
        self.assertEqual("user=a?b", event_fields(helpers_rules.event(user="a\x1bb")))

    def test_a_long_command_line_is_clipped_to_one_column(self):
        value = event_fields(helpers_rules.event(command_line="x" * 200))
        self.assertEqual(70, len(value))
        self.assertTrue(value.endswith("..."))


class TestPlainAndClip(unittest.TestCase):
    def test_clip_leaves_text_at_the_width_alone(self):
        # Exactly the width is not cut: the "..." would lose three characters
        # to say nothing.
        self.assertEqual("x" * 70, clip("x" * 70))
        self.assertEqual("x" * 67 + "...", clip("x" * 71))

    def test_plain_keeps_printable_non_ascii(self):
        # The mitre strip's separator is non-ASCII on purpose, and a hostname
        # may be too: printable is the test, not ASCII.
        self.assertEqual("café · x", plain("café · x"))


class TestHashesAndTacticIds(unittest.TestCase):
    """A hand-edited JSON column must not become a traceback."""

    def test_hashes_of_a_well_formed_list(self):
        self.assertEqual(["aa", "bb"], hashes({"event_ids": '["aa", "bb"]'}))

    def test_hashes_drops_what_is_not_a_string(self):
        self.assertEqual(["aa"], hashes({"event_ids": '["aa", 1, null]'}))

    def test_hashes_of_junk_is_nothing(self):
        for bad in (None, "not json", '"aa"', '{"a": 1}'):
            with self.subTest(bad=bad):
                self.assertEqual([], hashes({"event_ids": bad}))

    def test_tactic_ids_are_strings_even_when_stored_as_numbers(self):
        self.assertEqual(["1", "TA0006"], tactic_ids({"tactics": '[1, "TA0006"]'}))

    def test_tactic_ids_of_junk_is_nothing(self):
        for bad in (None, "oops", '"TA0006"', '{"a": 1}'):
            with self.subTest(bad=bad):
                self.assertEqual([], tactic_ids({"tactics": bad}))


if __name__ == "__main__":
    unittest.main()

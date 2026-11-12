import io
import json
import re
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timedelta
from pathlib import Path

import cli
from core import store
from tests.helpers_rules import sample_alert
from tests.test_cli_ingest import IngestTestCase

ANSI = re.compile(r"\033\[[0-9;]*m")
ROW = re.compile(r"\s*\d{4}-\d\d-\d\d \d\d:\d\d:\d\d  ")


def table(out):
    """The alert rows of text output as columns: timestamp, severity, rule,
    entity, evidence. Anchoring to a column is what lets a test say "r2 is not
    listed" without a stray "r2" in a timestamp or detail satisfying it."""
    lines = (ANSI.sub("", line) for line in out.splitlines())
    return [re.split(r"\s{2,}", line.strip(), maxsplit=4)
            for line in lines if ROW.match(line)]


def rule_ids(out):
    return [row[2] for row in table(out)]


class AlertsCase(IngestTestCase):
    def add(self, *alerts):
        store.insert_alerts(self.conn, alerts)

    def seed_two(self):
        self.add(
            sample_alert(rule_id="r1", severity="HIGH", entity_value="1.2.3.4",
                         timestamp=datetime.now()),
            sample_alert(rule_id="r2", severity="LOW", entity_value="alice",
                         entity_type="user",
                         timestamp=datetime.now() - timedelta(days=3)))

    def add_legacy(self, timestamp="2999-01-01 00:00:00"):
        """A row as the legacy scanner path writes it: no rule_id, no entity.
        The far-future timestamp sorts it first in a newest-first listing."""
        self.conn.execute(
            "INSERT INTO alerts (timestamp, category, severity, detail, source) "
            "VALUES (?, 'SQLi', 'HIGH', 'legacy finding', 'scanner')", (timestamp,))
        self.conn.commit()


class TestAlertsVerb(AlertsCase):
    def test_listing_shows_both_newest_first(self):
        self.seed_two()
        code, out = self.run_cli(["alerts"])
        self.assertEqual(0, code)
        self.assertEqual(["r1", "r2"], rule_ids(out))

    def test_the_columns_are_timestamp_severity_rule_entity(self):
        self.seed_two()
        _, out = self.run_cli(["alerts"])
        first, second = table(out)
        self.assertEqual(["HIGH", "r1", "1.2.3.4"], first[1:4])
        self.assertEqual(["LOW", "r2", "alice"], second[1:4])

    def test_severity_filter(self):
        self.seed_two()
        code, out = self.run_cli(["alerts", "--severity", "HIGH"])
        self.assertEqual(0, code)
        self.assertEqual(["r1"], rule_ids(out))

    def test_since_filter(self):
        self.seed_two()
        _, out = self.run_cli(["alerts", "--since", "1d"])
        self.assertEqual(["r1"], rule_ids(out))

    def test_until_filter(self):
        self.seed_two()
        _, out = self.run_cli(["alerts", "--until", "1d"])
        self.assertEqual(["r2"], rule_ids(out))

    def test_rule_filter(self):
        self.seed_two()
        _, out = self.run_cli(["alerts", "--rule", "r2"])
        self.assertEqual(["r2"], rule_ids(out))

    def test_entity_filter(self):
        self.seed_two()
        _, out = self.run_cli(["alerts", "--entity", "alice"])
        self.assertEqual(["r2"], rule_ids(out))

    def test_status_filter(self):
        self.seed_two()
        self.conn.execute("UPDATE alerts SET status = 'CLOSED' WHERE rule_id = 'r2'")
        self.conn.commit()
        _, out = self.run_cli(["alerts", "--status", "CLOSED"])
        self.assertEqual(["r2"], rule_ids(out))

    def test_an_empty_result_is_exit_0_and_says_so(self):
        self.seed_two()
        code, out = self.run_cli(["alerts", "--severity", "CRITICAL"])
        self.assertEqual(0, code, "no matches is a valid answer, not a failure")
        # Anchored to the marker: the ANSI reset code contains a "0", so a bare
        # assertIn("0", out) passes against any coloured output.
        self.assertRegex(out, r"\[~\] 0 alerts\b")
        self.assertEqual([], table(out))

    def test_json_is_parseable(self):
        self.seed_two()
        code, out, _ = self.run_cli_split(["--json", "alerts"])
        self.assertEqual(0, code)
        payload = json.loads(out)
        self.assertEqual((2, 2), (payload["count"], payload["total"]))
        self.assertEqual(["r1", "r2"], [a["rule_id"] for a in payload["alerts"]])

    def test_an_empty_json_result_is_still_json(self):
        code, out, _ = self.run_cli_split(["--json", "alerts"])
        self.assertEqual(0, code)
        self.assertEqual({"count": 0, "total": 0, "legacy_hidden": 0, "alerts": []},
                         json.loads(out))

    def test_an_unknown_severity_is_a_usage_error(self):
        # argparse's own exit: a SystemExit, not a code dispatch returns (the
        # brief's run_cli version of this test errors on it).
        err = io.StringIO()
        with self.assertRaises(SystemExit) as raised, redirect_stderr(err):
            cli.dispatch(["--db", self.db_path, "alerts", "--severity", "SPICY"])
        self.assertEqual(2, raised.exception.code)
        self.assertIn("invalid choice: 'SPICY'", err.getvalue())

    def test_a_bad_since_is_a_usage_error(self):
        code, _ = self.run_cli(["alerts", "--since", "yesterday"])
        self.assertEqual(2, code)

    def test_store_filters_default_to_none(self):
        # cli/__init__.py: a falsy default means "match nothing".
        args = cli.build_parser().parse_args(["alerts"])
        for name in ("severity", "since", "until", "rule", "entity", "status"):
            self.assertIsNone(getattr(args, name), name)

    def test_a_store_with_no_alerts_table_yet_is_not_a_traceback(self):
        # `alerts` is in store.SCHEMA (ruling R48), so init_schema creates it.
        # This pins that: a fresh --db must answer, not raise.
        fresh = tempfile.TemporaryDirectory()
        self.addCleanup(fresh.cleanup)
        code, out = self.run_cli(["--db", str(Path(fresh.name) / "new.db"), "alerts"])
        self.assertEqual(0, code)
        self.assertRegex(out, r"\[~\] 0 alerts\b")


class TestAlertsLimit(AlertsCase):
    def seed_many(self, n):
        now = datetime.now()
        self.add(*(sample_alert(
            rule_id="r1", entity_value="host-{}".format(i),
            event_hashes=("h{}".format(i),), timestamp=now - timedelta(seconds=i))
            for i in range(n)))

    def test_text_shows_50_by_default_and_says_how_many_it_hid(self):
        self.seed_many(51)
        _, out = self.run_cli(["alerts"])
        self.assertEqual(50, len(table(out)))
        self.assertRegex(ANSI.sub("", out), r"showing 50 of 51")

    def test_json_is_not_capped_by_default(self):
        # A script that reads `alerts` must not silently get the first 50.
        self.seed_many(51)
        _, out, _ = self.run_cli_split(["--json", "alerts"])
        payload = json.loads(out)
        self.assertEqual((51, 51), (payload["count"], payload["total"]))

    def test_limit_applies_to_json_too_and_total_still_counts_all(self):
        self.seed_many(5)
        _, out, _ = self.run_cli_split(["--json", "alerts", "--limit", "2"])
        payload = json.loads(out)
        self.assertEqual((2, 5), (payload["count"], payload["total"]))
        # Newest first: the two kept are the newest two.
        self.assertEqual(["host-0", "host-1"],
                         [a["entity_value"] for a in payload["alerts"]])

    def test_a_limit_below_one_is_a_usage_error(self):
        for bad in ("0", "-1"):
            code, _ = self.run_cli(["alerts", "--limit", bad])
            self.assertEqual(2, code, bad)


class TestAlertsLegacyRows(AlertsCase):
    """Ruling R74: legacy scanner rows have no rule_id or entity and UTC
    timestamps, rule-engine rows are local naive. Never list them together."""

    def test_legacy_rows_are_not_listed(self):
        self.seed_two()
        self.add_legacy()
        _, out = self.run_cli(["alerts"])
        self.assertEqual(["r1", "r2"], rule_ids(out))
        self.assertNotIn("legacy finding", out)

    def test_legacy_rows_are_not_in_the_json(self):
        self.seed_two()
        self.add_legacy()
        _, out, _ = self.run_cli_split(["--json", "alerts"])
        payload = json.loads(out)
        self.assertEqual((2, 2), (payload["count"], payload["total"]))

    def test_the_json_counts_the_legacy_rows_it_left_out(self):
        # The text note is for humans; a script must see the same fact.
        self.seed_two()
        self.add_legacy()
        self.add_legacy("2999-01-02 00:00:00")
        _, out, _ = self.run_cli_split(["--json", "alerts"])
        payload = json.loads(out)
        self.assertEqual((2, 2, 2), (payload["count"], payload["total"],
                                     payload["legacy_hidden"]))

    def test_the_json_says_zero_when_nothing_was_left_out(self):
        self.seed_two()
        _, out, _ = self.run_cli_split(["--json", "alerts"])
        self.assertEqual(0, json.loads(out)["legacy_hidden"])

    def test_legacy_rows_do_not_use_up_the_limit(self):
        # The legacy row sorts first. A limit applied before the legacy rows
        # are dropped would leave this listing empty.
        self.seed_two()
        self.add_legacy()
        _, out = self.run_cli(["alerts", "--limit", "1"])
        self.assertEqual(["r1"], rule_ids(out))

    def test_a_store_holding_only_legacy_rows_says_they_are_hidden(self):
        # Otherwise the user's 149 alerts vanish without a word.
        self.add_legacy()
        _, out = self.run_cli(["alerts"])
        plain = ANSI.sub("", out)
        self.assertRegex(plain, r"\[~\] 0 alerts\b")
        self.assertRegex(plain, r"Legacy scanner alerts are not listed")

    def test_no_legacy_note_when_there_are_none(self):
        self.seed_two()
        _, out = self.run_cli(["alerts"])
        self.assertNotRegex(out, r"(?i)legacy")


class TestAlertsRender(AlertsCase):
    def test_headers_line_up_with_their_columns_on_short_data(self):
        # A rule id shorter than "RULE" or an entity shorter than "ENTITY"
        # must not pull the columns after it out from under their headers.
        self.add(sample_alert(rule_id="r1", entity_value="ab",
                              evidence=json.dumps([{"user": "u1"}])))
        _, out = self.run_cli(["alerts"])
        lines = [ANSI.sub("", line) for line in out.splitlines()]
        header = next(line for line in lines if "SEVERITY" in line)
        row = next(line for line in lines if ROW.match(line))
        self.assertEqual(header.index("RULE"), row.index("r1"))
        self.assertEqual(header.index("ENTITY"), row.index("ab"))
        self.assertEqual(header.index("EVIDENCE"), row.index("user=u1"))

    def test_a_field_value_with_markup_is_not_interpreted(self):
        # Carried from ruling R30: flat fields are stored verbatim on purpose,
        # so the render boundary is where hostile text must be defanged. The
        # literal tags must survive: rich would swallow "[red]" and leave a
        # bare FORGED, which the weaker assertIn("FORGED") could not tell apart.
        self.add(sample_alert(entity_value="[red]FORGED[/red]", rule_id="r1"))
        code, out = self.run_cli(["alerts"])
        self.assertEqual(0, code)
        self.assertEqual("[red]FORGED[/red]", table(out)[0][3])

    def test_control_characters_in_a_field_do_not_reach_the_terminal(self):
        self.add(sample_alert(entity_value="evil\x1b[2Jhost", rule_id="r1"))
        _, out = self.run_cli(["alerts"])
        self.assertNotIn("\x1b[2J", out)
        self.assertEqual("evil?[2Jhost", table(out)[0][3])

    def test_a_newline_in_a_field_cannot_forge_a_second_row(self):
        forged = "x\n2026-10-04 10:00:00  CRITICAL  forged-rule  attacker"
        self.add(sample_alert(entity_value=forged, rule_id="r1"))
        _, out = self.run_cli(["alerts"])
        self.assertEqual(["r1"], rule_ids(out))

    def test_a_newline_in_a_rule_id_cannot_forge_a_second_row(self):
        # Surfaced when the render helpers moved to cli/render.py (ruling R94):
        # removing plain() from the rule id column survived the whole suite.
        forged = "r1\n2026-10-04 10:00:00  CRITICAL  forged-rule  attacker"
        self.add(sample_alert(rule_id=forged))
        _, out = self.run_cli(["alerts"])
        self.assertEqual(["r1?2026-10-04 10:00:00"], [r[2] for r in table(out)][:1])
        self.assertEqual(1, len(table(out)))

    def test_the_rule_id_column_is_the_rule_id_not_the_title(self):
        self.add(sample_alert(rule_id="r1", rule_title="A Very Long Title"))
        _, out = self.run_cli(["alerts"])
        self.assertEqual("r1", table(out)[0][2])

    def test_evidence_tells_alerts_of_one_rule_apart(self):
        # Every alert of a rule on one host carries the same detail (the rule
        # description plus the entity); the service name lives only in evidence.
        for name, record in (("EvilSvc", 1), ("OtherSvc", 2)):
            self.add(sample_alert(
                rule_id="win-service-installed", entity_value="PC-01",
                event_hashes=(name,), timestamp=datetime.now() - timedelta(minutes=record),
                evidence=json.dumps([{"host": "PC-01", "service_name": name,
                                      "process": "C:\\x.exe", "user": "-"}])))
        _, out = self.run_cli(["alerts"])
        evidence = [row[4] for row in table(out)]
        self.assertEqual(2, len(evidence))
        self.assertEqual("service_name=EvilSvc process=C:\\x.exe", evidence[0])
        self.assertEqual("service_name=OtherSvc process=C:\\x.exe", evidence[1])

    def test_evidence_shows_the_newest_event_of_the_alert(self):
        self.add(sample_alert(evidence=json.dumps(
            [{"user": "first"}, {"user": "last"}])))
        _, out = self.run_cli(["alerts"])
        self.assertEqual("user=last", table(out)[0][4])

    def test_unreadable_evidence_is_a_blank_column_not_a_traceback(self):
        for i, bad in enumerate(("not json", "[]", "null", "[1]", '{"a": 1}', None)):
            self.add(sample_alert(evidence=bad, event_hashes=("h{}".format(i),),
                                  entity_value="e{}".format(i)))
        code, out = self.run_cli(["alerts"])
        self.assertEqual(0, code)
        self.assertEqual(6, len(table(out)))

    def test_a_long_evidence_is_cut_and_marked(self):
        self.add(sample_alert(evidence=json.dumps([{"process": "x" * 300}])))
        _, out = self.run_cli(["alerts"])
        cell = table(out)[0][4]
        self.assertLessEqual(len(cell), 70)
        self.assertTrue(cell.endswith("..."))


if __name__ == "__main__":
    unittest.main()

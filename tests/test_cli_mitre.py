import json
import re
import unittest
from datetime import timedelta

from cli.commands import mitre as mitre_command
from core import store
from core.correlator import correlate
from tests.helpers_rules import T0, sample_alert
from tests.test_cli_alerts import ANSI
from tests.test_cli_incidents import hostile, sections
from tests.test_cli_ingest import IngestTestCase

# The ATT&CK matrix's order, written out here rather than read from the module:
# it starts at Reconnaissance (spec section 9), Command and Control comes BEFORE
# Exfiltration, and Impact is last -- all three of which dict order (by id) gets
# wrong. Ruling R103.
CHAIN_NAMES = ["Reconnaissance", "Resource Development", "Initial Access", "Execution",
               "Persistence", "Privilege Escalation", "Defense Evasion",
               "Credential Access", "Discovery", "Lateral Movement", "Collection",
               "Command and Control", "Exfiltration", "Impact"]
CHAIN_IDS = ("TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
             "TA0006", "TA0007", "TA0008", "TA0009", "TA0011", "TA0010", "TA0040")


def _lines(out):
    """The strip's printed lines, in print order: everything after the header
    `print_info` line. Not "the lines containing the separator" -- the strip
    wraps at stage boundaries (R110) and a wrapped line can hold one stage."""
    lines = [l for l in ANSI.sub("", out).splitlines() if l.strip()]
    header = max(i for i, l in enumerate(lines) if l.lstrip().startswith("[~]"))
    return lines[header + 1:]


def _stages(out):
    """Every stage of the strip, across however many lines it took."""
    return " · ".join(l.strip() for l in _lines(out)).split(" · ")


def strip(out):
    """The kill-chain strip as [(stage, marked)] in print order. A hit chain
    stage wears [brackets] and an off-chain extra wears {braces}; both count as
    marked, and `extras` is what tells them apart."""
    return [(s[1:-1], True) if s[0] + s[-1] in ("[]", "{}") else (s, False)
            for s in _stages(out)]


def extras(out):
    """The stage names shown as off-chain extras: {name}, not [name]."""
    return [s[1:-1] for s in _stages(out) if s[0] + s[-1] == "{}"]


def marked(out):
    return {name for name, hit in strip(out) if hit}


def matrix_rows(out):
    """The matrix rows as columns: technique, tactic, incidents, alerts."""
    body = next((v for k, v in sections(out).items() if k.startswith("Technique matrix")), [])
    return [re.split(r"\s{2,}", l.strip()) for l in body[1:] if l.strip()]


class MitreCase(IngestTestCase):
    def incident(self, tactics, entity="1.2.3.4", title="an incident", at=T0):
        """An incident with exactly these tactic ids, in this order (the
        correlator would store them sorted)."""
        return store.open_incident(self.conn, at, at, "ip", entity, "HIGH",
                                   tactics=tactics, title=title)

    def alerts(self, entity, *specs, at=T0):
        """Correlate one alert per (technique, tactic[, rule]) spec for one
        entity, a minute apart; returns the incident id."""
        made = [sample_alert(
            rule_id=(spec[2] if len(spec) > 2 else "r{}".format(i)), entity_value=entity,
            technique=spec[0], tactic=spec[1], event_hashes=("{}{}".format(entity, i),),
            timestamp=at + timedelta(minutes=i)) for i, spec in enumerate(specs)]
        return correlate(self.conn, made)["incident_ids"][0]


class TestMitreIncident(MitreCase):
    def test_the_strip_marks_exactly_the_incidents_tactics(self):
        # The marked set, not a substring.
        i = self.incident(["TA0002", "TA0003", "TA0006"])
        code, out = self.run_cli(["mitre", "--incident", str(i)])
        self.assertEqual(0, code)
        self.assertEqual({"Execution", "Persistence", "Credential Access"}, marked(out))
        self.assertEqual(14, len(strip(out)))
        self.assertEqual([], extras(out))

    def test_an_incident_with_no_tactics_marks_nothing(self):
        i = self.incident([])
        code, out = self.run_cli(["mitre", "--incident", str(i)])
        self.assertEqual(0, code)
        self.assertEqual(set(), marked(out))
        self.assertEqual(CHAIN_NAMES, [n for n, _ in strip(out)])

    def test_stages_are_in_kill_chain_order_not_dict_order(self):
        i = self.incident(["TA0010", "TA0011"])
        _, out = self.run_cli(["mitre", "--incident", str(i)])
        self.assertEqual(CHAIN_NAMES, [n for n, _ in strip(out)])
        self.assertEqual(CHAIN_IDS, mitre_command.KILL_CHAIN)

    def test_the_marked_tactics_come_through_the_correlator_too(self):
        i = self.alerts("1.2.3.4", ("T1110", "TA0006"), ("T1136.001", "TA0003"))
        _, out = self.run_cli(["mitre", "--incident", str(i)])
        self.assertEqual({"Credential Access", "Persistence"}, marked(out))

    def test_an_unknown_tactic_id_is_shown_as_itself_not_dropped(self):
        # tactic_name returns the id unchanged; a dropped stage would hide data.
        i = self.incident(["TA0006", "TA9998", "TA9999"])
        code, out = self.run_cli(["mitre", "--incident", str(i)])
        self.assertEqual(0, code)
        stages = strip(out)
        self.assertEqual(CHAIN_NAMES + ["TA9998", "TA9999"], [n for n, _ in stages])
        self.assertEqual({"Credential Access", "TA9998", "TA9999"}, marked(out))
        self.assertEqual(["TA9998", "TA9999"], extras(out))

    def test_a_hostile_tactic_id_cannot_forge_another_stage(self):
        # "]" "[" and the separator are what the strip is made of: a stored
        # tactic that contained them would read as a second, marked stage.
        i = self.incident(["TA0002", "x] · [Discovery", "y} · {Collection"])
        _, out = self.run_cli(["mitre", "--incident", str(i)])
        self.assertEqual(16, len(strip(out)))
        self.assertEqual({"Execution", "x? ? ?Discovery", "y? ? ?Collection"}, marked(out))

    def test_an_off_chain_extra_is_not_read_as_the_chain_stage_it_names(self):
        # A stored tactic value of "Execution" is TA0002's NAME, so a strip that
        # marked extras the same way as hits printed [Execution] twice and no
        # reader could tell which was the real stage.
        i = self.incident(["TA0002", "Execution"])
        _, out = self.run_cli(["mitre", "--incident", str(i)])
        stages = _stages(out)
        self.assertEqual(1, stages.count("[Execution]"))
        self.assertEqual(1, stages.count("{Execution}"))
        self.assertEqual(["Execution"], extras(out))

    def test_an_extras_name_is_clipped_so_one_stage_still_fits_a_line(self):
        # An extra is a stored tactic id of any length; the strip wraps between
        # stages but never inside one, so a stage has to fit a line by itself.
        i = self.incident(["x" * 200])
        _, out = self.run_cli(["mitre", "--incident", str(i)])
        self.assertEqual(["x" * 67 + "..."], extras(out))
        self.assertTrue(all(len(l) <= 78 for l in _lines(out)), _lines(out))

    def test_the_strip_wraps_at_stage_boundaries_and_never_mid_name(self):
        # The 14 stages are 235 characters: three wrapped lines in an 80-column
        # terminal, breaking mid-name, which destroys the left-to-right scan the
        # strip exists for (R110). Four lines at width 76, broken only at the
        # separator -- so re-joining them must give back the unwrapped strip,
        # which a wrap that dropped, duplicated or moved a stage would not.
        i = self.incident(["TA0002", "TA0006"])
        _, out = self.run_cli(["mitre", "--incident", str(i)])
        lines = _lines(out)
        self.assertEqual(4, len(lines), lines)
        for line in lines:
            self.assertLessEqual(len(line), 78, line)  # 76 plus the two-space indent
        self.assertEqual(["  " + l.strip() for l in lines], lines)  # every line indented
        self.assertEqual(
            " · ".join("[{}]".format(n) if n in ("Execution", "Credential Access") else n
                       for n in CHAIN_NAMES),
            " · ".join(l.strip() for l in lines))

    def test_a_stage_wider_than_the_width_takes_a_line_rather_than_breaking(self):
        # Every name is wider than 10, so each takes its own line whole: a
        # wrapper that broke on spaces would split "Resource Development".
        chain = mitre_command.stages(["TA0002"])
        self.assertEqual(["[Execution]" if n == "Execution" else n for n in CHAIN_NAMES],
                         mitre_command.strip_lines(chain, width=10))

    def test_unknown_incident_exits_1_naming_the_id(self):
        code, out = self.run_cli(["mitre", "--incident", "99"])
        self.assertEqual(1, code)
        self.assertIn("No incident with id 99", out)
        code, out, _ = self.run_cli_split(["--json", "mitre", "--incident", "99"])
        self.assertEqual(1, code)
        self.assertEqual({"error": "No incident with id 99"}, json.loads(out))

    def test_a_tactics_column_that_is_not_a_list_is_no_tactics(self):
        i = self.incident([])
        self.conn.execute("UPDATE incidents SET tactics = 'oops'")
        self.conn.commit()
        code, out = self.run_cli(["mitre", "--incident", str(i)])
        self.assertEqual(0, code)
        self.assertEqual(set(), marked(out))

    def test_a_repeated_tactic_is_one_stage(self):
        i = self.incident(["TA9999", "TA9999", "TA0006", "TA0006"])
        _, out = self.run_cli(["mitre", "--incident", str(i)])
        self.assertEqual(15, len(strip(out)))

    def test_json_for_an_incident(self):
        i = self.incident(["TA0006", "TA9999"], title="T")
        code, out, err = self.run_cli_split(["--json", "mitre", "--incident", str(i)])
        self.assertEqual(0, code)
        self.assertEqual("", err)
        payload = json.loads(out)
        self.assertEqual((i, ["TA0006", "TA9999"]),
                         (payload["incident"]["id"], payload["incident"]["tactics"]))
        stages = payload["stages"]
        self.assertEqual(list(CHAIN_IDS) + ["TA9999"], [s["tactic"] for s in stages])
        self.assertEqual(CHAIN_NAMES + ["TA9999"], [s["name"] for s in stages])
        self.assertEqual({"TA0006", "TA9999"}, {s["tactic"] for s in stages if s["hit"]})
        self.assertEqual(["TA9999"], [s["tactic"] for s in stages if s["extra"]])


class TestMitreMatrix(MitreCase):
    def seed(self):
        """Incident A (1.1.1.1): T1110 twice (two rules) and T1078. Incident B
        (2.2.2.2): T1110 once. So T1110 is 2 incidents and 3 alerts, T1078 is
        1 and 1. One more alert belongs to no incident, and its technique
        appears nowhere."""
        self.alerts("1.1.1.1", ("T1110", "TA0006", "bf1"), ("T1110", "TA0006", "bf2"),
                    ("T1078", "TA0001", "valid"))
        self.alerts("2.2.2.2", ("T1110", "TA0006", "bf1"))
        store.insert_alerts(self.conn, [sample_alert(
            rule_id="loose", technique="T1486", tactic="TA0040", entity_value="3.3.3.3",
            event_hashes=("loose",))])

    def test_matrix_counts_techniques_across_incidents_in_range(self):
        self.seed()
        code, out = self.run_cli(["mitre", "--matrix"])
        self.assertEqual(0, code)
        self.assertEqual([["T1110", "Credential Access", "2", "3"],
                          ["T1078", "Initial Access", "1", "1"]], matrix_rows(out))
        self.assertIn("Technique matrix (2 incident(s))", ANSI.sub("", out))

    def test_rows_are_ordered_by_incidents_before_alerts(self):
        # T1000 fires four times in one incident; T2000 once in each of two.
        # Spread across incidents is the stronger signal, as in scoring.
        self.alerts("1.1.1.1", *[("T1000", "TA0006", "r{}".format(i)) for i in range(4)])
        self.alerts("2.2.2.2", ("T2000", "TA0001", "x"))
        self.alerts("3.3.3.3", ("T2000", "TA0001", "x"))
        _, out = self.run_cli(["mitre", "--matrix"])
        self.assertEqual([["T2000", "Initial Access", "2", "2"],
                          ["T1000", "Credential Access", "1", "4"]], matrix_rows(out))

    def test_an_alert_in_no_incident_is_not_counted(self):
        self.seed()
        _, out = self.run_cli(["mitre", "--matrix"])
        self.assertNotIn("T1486", out)

    def test_the_same_technique_under_two_tactics_is_two_rows(self):
        # T1078 is valid-accounts under initial access AND defense evasion.
        self.alerts("1.1.1.1", ("T1078", "TA0001", "a"), ("T1078", "TA0005", "b"))
        _, out = self.run_cli(["mitre", "--matrix"])
        self.assertEqual({("T1078", "Initial Access"), ("T1078", "Defense Evasion")},
                         {(r[0], r[1]) for r in matrix_rows(out)})

    def test_a_technique_with_none_is_a_dash_not_a_crash(self):
        self.alerts("1.1.1.1", (None, None))
        code, out = self.run_cli(["mitre", "--matrix"])
        self.assertEqual(0, code)
        self.assertEqual([["-", "-", "1", "1"]], matrix_rows(out))

    def test_matrix_since_bounds_the_range(self):
        # Bounds an incident by its last_seen, as `incidents` does.
        self.alerts("1.1.1.1", ("T1110", "TA0006", "bf"), at=T0)
        self.alerts("2.2.2.2", ("T1078", "TA0001", "valid"), at=T0 + timedelta(days=2))
        _, out = self.run_cli(["mitre", "--matrix", "--since", "2026-10-04 00:00:00"])
        self.assertEqual([["T1078", "Initial Access", "1", "1"]], matrix_rows(out))
        self.assertIn("Technique matrix (1 incident(s))", ANSI.sub("", out))
        _, out = self.run_cli(["mitre", "--matrix"])
        self.assertEqual({"T1110", "T1078"}, {r[0] for r in matrix_rows(out)})

    def test_a_since_that_excludes_everything_exits_0_and_says_so(self):
        self.seed()
        code, out = self.run_cli(["mitre", "--matrix", "--since", "2999-01-01"])
        self.assertEqual(0, code)
        self.assertIn("0 incidents in range", ANSI.sub("", out))

    def test_an_empty_store_exits_0_and_says_so(self):
        code, out = self.run_cli(["mitre", "--matrix"])
        self.assertEqual(0, code)
        self.assertIn("0 incidents in range", ANSI.sub("", out))

    def test_an_unreadable_since_is_a_usage_error(self):
        code, _ = self.run_cli(["mitre", "--matrix", "--since", "whenever"])
        self.assertEqual(2, code)

    def test_json_for_the_matrix(self):
        self.seed()
        code, out, err = self.run_cli_split(["--json", "mitre", "--matrix"])
        self.assertEqual(0, code)
        self.assertEqual("", err)
        payload = json.loads(out)
        self.assertEqual(2, payload["incidents"])
        self.assertEqual(
            [{"technique": "T1110", "tactic": "TA0006", "tactic_name": "Credential Access",
              "incidents": 2, "alerts": 3},
             {"technique": "T1078", "tactic": "TA0001", "tactic_name": "Initial Access",
              "incidents": 1, "alerts": 1}], payload["techniques"])

    def test_json_empty_matrix_is_still_json(self):
        _, out, _ = self.run_cli_split(["--json", "mitre", "--matrix"])
        self.assertEqual({"incidents": 0, "techniques": []}, json.loads(out))


class TestMitreUsage(MitreCase):
    def test_exactly_one_of_incident_and_matrix(self):
        i = self.incident(["TA0006"])
        for argv in ([], ["--incident", str(i), "--matrix"]):
            with self.subTest(argv=argv):
                code, out = self.run_cli(["mitre"] + argv)
                self.assertEqual(2, code)
                self.assertIn("give exactly one of --incident, --matrix", out)

    def test_since_goes_with_the_matrix_only(self):
        i = self.incident(["TA0006"])
        code, out = self.run_cli(["mitre", "--incident", str(i), "--since", "1d"])
        self.assertEqual(2, code)
        self.assertIn("--since goes with --matrix only", out)


class TestMitreMarkup(MitreCase):
    """Ruling R30/R96: stored text never goes through rich markup and a control
    character cannot reach the terminal or forge a row."""

    def test_markup_in_a_stored_field_is_not_interpreted(self):
        # rich swallows "[red]" and leaves a bare FORGED, so assert the literal.
        i = self.incident(["TA0006", "[red]FORGED[/red]"], title="[bold]T[/bold]")
        _, out = self.run_cli(["mitre", "--incident", str(i)])
        # The strip is made of brackets and braces, so the stage's own become
        # "?"; the literal survives where they are not syntax (the header).
        self.assertIn("?red?FORGED?/red?", marked(out))
        self.assertIn("[bold]T[/bold]", ANSI.sub("", out))

    def test_matrix_markup_is_not_interpreted(self):
        self.alerts("1.1.1.1", ("[red]FORGED[/red]", "[red]FORGED[/red]"))
        _, out = self.run_cli(["mitre", "--matrix"])
        self.assertEqual([["[red]FORGED[/red]", "[red]FORGED[/red]", "1", "1"]],
                         matrix_rows(out))


class TestEveryColumnIsDefanged(MitreCase):
    """One hostile value in every column `mitre` prints, each with its own
    tag. Raw SQL, the stronger position."""

    def check(self, out, expected):
        self.assertNotIn("\x1b[2J", out)
        plain_out = ANSI.sub("", out)
        for tag, text in expected.items():
            self.assertIn(text, plain_out, tag)
        self.assertEqual([], [l for l in plain_out.splitlines()
                              if l.strip().startswith("forged")],
                         "a newline in a column started a line of its own")

    def test_the_incident_header_and_an_extra_stage(self):
        i = self.incident(["TA0006"])
        self.conn.execute(
            "UPDATE incidents SET title=?, entity_type=?, entity_value=?, tactics=?",
            (hostile("TITLE"), hostile("ETYPE"), hostile("ENT"), json.dumps([hostile("TACT")])))
        self.conn.commit()
        code, out = self.run_cli(["mitre", "--incident", str(i)])
        self.assertEqual(0, code)
        # The tactic also loses its "[", which the strip is made of.
        self.check(out, {"TITLE": "TITLE?[2J?forged", "ETYPE": "ETYPE?[2J?forged",
                         "ENT": "ENT?[2J?forged", "TACT": "TACT??2J?forged"})

    def test_every_column_of_the_matrix(self):
        i = self.alerts("1.1.1.1", ("T1110", "TA0006"))
        self.conn.execute("UPDATE alerts SET mitre_technique_id=?, mitre_tactic_id=?",
                          (hostile("TECH"), hostile("TAC")))
        self.conn.commit()
        code, out = self.run_cli(["mitre", "--matrix"])
        self.assertEqual(0, code)
        self.check(out, {"TECH": "TECH?[2J?forged", "TAC": "TAC?[2J?forged"})


if __name__ == "__main__":
    unittest.main()

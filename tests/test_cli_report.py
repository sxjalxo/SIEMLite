#!/usr/bin/env python3
"""`siem report` and the dashboard's rich-markup path.

The report is a Markdown FILE (ruling R130), so these tests read the file
rather than stdout. Defanging is asserted inside the file for the reason R130
gives: the file is very likely to be `type`d to a terminal later, where an ESC
fires exactly as it would have at the console, and a newline can forge a
Markdown table row or a heading.
"""

import io
import json
import os
import re
import tempfile
import unittest
from unittest import mock

from cli.commands import mitre as mitre_command
from cli.commands import report as report_command
from tests.test_cli_incidents import defanged, hostile
from tests.test_cli_timeline import MARK, TimelineCase

try:
    from rich.console import Console
    RICH_AVAILABLE = True
except ImportError:                                           # pragma: no cover
    RICH_AVAILABLE = False

from ui import dashboard as dashboard_module

ANSI = re.compile(r"\x1b\[[0-9;]*m")

# "--incident was not given" is distinct from "--incident None".
OMIT = object()


class ReportCase(TimelineCase):
    def setUp(self):
        super().setUp()
        self.out_dir = tempfile.mkdtemp()
        self.out_path = os.path.join(self.out_dir, "report.md")

    def tearDown(self):
        for name in os.listdir(self.out_dir):
            try:
                os.unlink(os.path.join(self.out_dir, name))
            except OSError:
                pass
        try:
            os.rmdir(self.out_dir)
        except OSError:
            pass
        super().tearDown()

    def report(self, *extra, incident=OMIT, out=True, as_json=False):
        """Run `report`, returning (code, stdout, stderr). --json is a GLOBAL
        flag and has to come before the verb."""
        argv = ["--json"] if as_json else []
        argv.append("report")
        incident = self.incident_id if incident is OMIT else incident
        if incident is not None:
            argv += ["--incident", str(incident)]
        if out:
            argv += ["--out", self.out_path]
        return self.run_cli_split(argv + list(extra))

    def plant(self):
        """A file already sitting at --out, written LF-only so an assertion
        about it is about the report's newlines and not the platform's."""
        with open(self.out_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("the previous report\n")

    def printed(self, out, err):
        """Everything the operator saw. print_error writes to stdout unless
        --json is set, so a message is asserted against both streams."""
        return ANSI.sub("", out + err)

    def text(self):
        """The written report, bytes decoded, newlines untranslated."""
        with open(self.out_path, "rb") as handle:
            return handle.read().decode("utf-8")

    def fenced(self, heading):
        """The lines inside the code fence under the `## heading...` section."""
        lines = self.text().splitlines()
        start = next(i for i, line in enumerate(lines)
                     if line.startswith("## " + heading))
        fence = lines.index("```", start)
        return lines[fence + 1:lines.index("```", fence + 1)]


class TestReport(ReportCase):
    def test_the_report_contains_the_incident_its_alerts_and_its_timeline(self):
        self.seed()
        code, _out, _err = self.report()
        self.assertEqual(0, code)
        text = self.text()
        # The header, the kill chain, the alerts and the timeline: each of the
        # four sections the brief names, found by its own content and not by
        # the heading alone.
        self.assertIn("# Incident {}".format(self.incident_id), text)
        self.assertIn("ip 1.2.3.4", text)
        self.assertIn("[Credential Access]", text)
        rules = [line for line in self.fenced("Alerts") if "r-burst" in line]
        self.assertEqual(1, len(rules), text)
        self.assertIn("HIGH", rules[0])
        self.assertIn("TA0006 Credential Access", rules[0])
        timeline = self.fenced("Timeline")
        self.assertEqual(["BEFORE", "LOGIN_FAIL", "LOGIN_FAIL2", "LOGIN_OK", "AFTER"],
                         [line.split()[3] for line in timeline
                          if line.startswith("2026-") and MARK not in line])
        # Four marks for two alerts: each is marked under every event it cites,
        # exactly as `siem timeline` prints it. The Alerts section above is
        # where each alert appears once.
        self.assertEqual(4, sum(1 for line in timeline if MARK in line), timeline)
        self.assertEqual(2, len(self.fenced("Alerts")) - 1)

    def test_out_writes_the_file_and_says_where(self):
        self.seed()
        code, out, _err = self.report()
        self.assertEqual(0, code)
        self.assertTrue(os.path.exists(self.out_path))
        self.assertIn(self.out_path, ANSI.sub("", out))

    def test_out_is_required(self):
        # Spec section 12 writes --out unbracketed, and a report dumped into a
        # pipe because the flag was forgotten is not the product asked for.
        self.seed()
        code, out, err = self.report(out=False)
        self.assertEqual(2, code)
        self.assertIn("--out", self.printed(out, err))

    def test_incident_is_required(self):
        self.seed()
        code, out, err = self.report(incident=None)
        self.assertEqual(2, code)
        self.assertIn("--incident", self.printed(out, err))

    def test_a_failed_write_exits_1_rather_than_reporting_success(self):
        self.seed()
        with mock.patch.object(report_command, "open",
                               mock.mock_open(), create=True) as opener:
            opener.side_effect = OSError("Permission denied")
            code, out, err = self.report()
        self.assertEqual(1, code)
        printed = self.printed(out, err)
        self.assertIn("Permission denied", printed)
        # The mutation this exists for: print the path, then write. A verb that
        # names a file it did not write is worse than one that fails loudly.
        self.assertNotIn("Wrote", printed)

    def test_unknown_incident_exits_1_and_writes_no_file(self):
        self.seed()
        code, out, err = self.report(incident=self.incident_id + 99)
        self.assertEqual(1, code)
        self.assertIn("No incident with id", self.printed(out, err))
        self.assertFalse(os.path.exists(self.out_path))

    def test_an_existing_file_is_not_overwritten_without_force(self):
        self.seed()
        self.plant()
        code, out, err = self.report()
        self.assertEqual(1, code)
        self.assertIn("--force", self.printed(out, err))
        self.assertEqual("the previous report\n", self.text())

    def test_force_overwrites(self):
        self.seed()
        self.plant()
        code, _out, _err = self.report("--force")
        self.assertEqual(0, code)
        self.assertNotIn("the previous report", self.text())

    def test_missing_events_exit_3_and_the_file_is_still_written(self):
        # Ruling R51's 3 is "something asked for was not stored", and R102 fixed
        # that meaning across the CLI. A report whose timeline is missing events
        # its alerts cite is partial, exactly as `timeline` and `incidents show`
        # already report it -- and the partial report is still worth having.
        self.seed()
        self.purge(self.e1)
        code, _out, _err = self.report()
        self.assertEqual(3, code)
        self.assertIn("1 referenced event(s) are no longer stored", self.text())

    def test_hostile_text_is_defanged_in_the_written_file(self):
        self.seed()
        self.add(0, event_id=4625, action=hostile("ACT"), record_id=99)
        self.conn.execute("UPDATE incidents SET title = ? WHERE id = ?",
                          (hostile("TITLE"), self.incident_id))
        self.conn.commit()
        code, _out, _err = self.report()
        self.assertEqual(0, code)
        text = self.text()
        self.assertIn(defanged("ACT"), text)
        self.assertIn(defanged("TITLE"), text)
        # Neither raw control character reached the file: the ESC that would
        # drive the terminal on `type`, nor the newline that would forge a row.
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\nforged", text)

    def test_a_pipe_in_stored_text_cannot_forge_a_markdown_column(self):
        self.seed()
        self.conn.execute("UPDATE incidents SET entity_value = ? WHERE id = ?",
                          ("1.2.3.4 | x | y", self.incident_id))
        self.conn.commit()
        code, _out, _err = self.report()
        self.assertEqual(0, code)
        row = [line for line in self.text().splitlines()
               if line.startswith("| Entity ")][0]
        self.assertEqual(3, row.count("|"), row)
        self.assertIn("1.2.3.4 ? x ? y", row)

    def test_a_code_fence_in_stored_text_cannot_close_the_block(self):
        # An unknown tactic id is stored text and starts a strip line, so it
        # reaches a line start inside the fence; "```" there would end the
        # block and let everything after it be read as Markdown.
        self.seed()
        self.conn.execute("UPDATE incidents SET tactics = ? WHERE id = ?",
                          (json.dumps(["```"]), self.incident_id))
        self.conn.commit()
        code, _out, _err = self.report()
        self.assertEqual(0, code)
        text = self.text()
        self.assertEqual(text.count("\n```\n"), text.count("```"), text)
        self.assertIn("{???}", text)

    def test_the_kill_chain_strip_is_wrapped_in_the_file(self):
        # Ruling R110: 14 stages are 235 characters and must not be one line.
        self.seed()
        code, _out, _err = self.report()
        self.assertEqual(0, code)
        lines = self.fenced("Kill chain")
        self.assertGreater(len(lines), 1)
        self.assertLessEqual(max(len(line) for line in lines), mitre_command.WIDTH)
        joined = report_command.SEPARATOR.join(lines)
        self.assertEqual(14, joined.count("Initial Access")
                         + joined.count("Execution") + joined.count("Persistence")
                         + joined.count("Privilege Escalation")
                         + joined.count("Defense Evasion")
                         + joined.count("Credential Access")
                         + joined.count("Discovery") + joined.count("Lateral Movement")
                         + joined.count("Collection")
                         + joined.count("Command and Control")
                         + joined.count("Exfiltration") + joined.count("Impact")
                         + joined.count("Reconnaissance")
                         + joined.count("Resource Development"))
        self.assertIn("[Credential Access]", joined)

    def test_the_reports_own_text_is_ascii(self):
        # Ruling R120's reason, applied to a file the brief says will be
        # `type`d: a cp1252 console renders a non-ASCII byte as a replacement
        # character, and mitre's separator is U+00B7.
        self.seed()
        code, _out, _err = self.report()
        self.assertEqual(0, code)
        self.assertEqual([], [hex(ord(c)) for c in self.text() if ord(c) > 127])

    def test_the_file_is_lf_only_with_one_trailing_newline(self):
        self.seed()
        self.report()
        with open(self.out_path, "rb") as handle:
            raw = handle.read()
        self.assertNotIn(b"\r", raw)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))

    def test_json_reports_the_path_and_the_counts_on_stdout_alone(self):
        self.seed()
        code, out, err = self.report(as_json=True)
        self.assertEqual(0, code)
        payload = json.loads(out)
        self.assertEqual(self.out_path, payload["out"])
        self.assertEqual(self.incident_id, payload["incident"]["id"])
        self.assertEqual(2, payload["alerts"])
        self.assertEqual(5, payload["events"])
        self.assertEqual(0, payload["events_missing"])
        self.assertEqual(os.path.getsize(self.out_path), payload["bytes"])
        # Ruling R77: stdout is JSON alone, human text goes to stderr.
        self.assertIn(self.out_path, ANSI.sub("", err))

    def test_json_on_an_unknown_incident_is_an_error_object(self):
        self.seed()
        code, out, _err = self.report(incident=self.incident_id + 99, as_json=True)
        self.assertEqual(1, code)
        self.assertIn("No incident with id", json.loads(out)["error"])


ALERT = {"severity": "HIGH", "category": "[red]FORGED[/red]",
         "detail": "detail [bold]FORGED[/bold] here"}


def rendered(panel):
    """A rich renderable as plain text, wide enough not to wrap a cell."""
    console = Console(file=io.StringIO(), width=220, no_color=True,
                      legacy_windows=False)
    console.print(panel)
    return console.file.getvalue()


@unittest.skipUnless(RICH_AVAILABLE, "rich is not installed")
class TestDashboardMarkup(unittest.TestCase):
    """Ruling R30, carried since the first plan: ui/dashboard.py passed stored
    alert text to rich's table.add_row() unescaped.

    Every assertion here is on the LITERAL tag, because rich SWALLOWS a tag it
    interprets -- asserting "FORGED" alone passes whether or not the fix is
    present, and that exact mistake has been made once already on this project.
    """

    def setUp(self):
        self.dashboard = dashboard_module.CLIDashboard()

    def test_markup_in_an_alert_field_is_not_interpreted(self):
        text = rendered(self.dashboard.create_alerts_panel([ALERT]))
        self.assertIn("[red]FORGED[/red]", text)
        self.assertIn("[bold]FORGED[/bold]", text)

    def test_the_severity_cell_was_already_safe(self):
        # Ruling R129: severity is a rich Text and Text is not markup-parsed,
        # so a fix aimed at it would change nothing. Pinned so nobody "fixes"
        # the wrong cell again and reports the row as done.
        text = rendered(self.dashboard.create_alerts_panel(
            [dict(ALERT, severity="[b]S[/b]")]))
        self.assertIn("[b]S[/b]", text)

    def test_control_characters_in_an_alert_field_are_defanged(self):
        text = rendered(self.dashboard.create_alerts_panel(
            [dict(ALERT, category=hostile("CAT"))]))
        self.assertIn(defanged("CAT"), text)
        self.assertNotIn("\x1b", text)

    def test_markup_in_the_other_panels_is_not_interpreted(self):
        # The same unescaped add_row in three sibling panels. The ticket named
        # line 201; leaving the siblings would be a symptom fix.
        for panel in (
                self.dashboard.create_ips_panel(
                    [{"ip": "[red]IP[/red]", "request_count": 1}]),
                self.dashboard.create_timeline_panel(
                    [{"hour": "[red]H", "severity": "HIGH", "count": 1}]),
                self.dashboard.create_scans_panel(
                    [{"target_url": "[red]URL[/red]", "total_findings": 1,
                      "critical_count": 0}])):
            text = rendered(panel)
            self.assertIn("[red]", text, text)

    def test_the_severity_column_still_renders_its_text(self):
        # The escaping must not swallow the value itself.
        text = rendered(self.dashboard.create_alerts_panel(
            [{"severity": "HIGH", "category": "Brute force", "detail": "five tries"}]))
        self.assertIn("Brute force", text)
        self.assertIn("five tries", text)
        self.assertIn("HIGH", text)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""
siem report
===========
One incident as a file an analyst can keep, attach or hand over: the header,
the kill-chain strip, the member alerts, and the timeline.

Markdown (ruling R130), because it reads fine unrendered -- `type report.md` in
CMD is the operating requirement -- the timeline and the 14-stage strip survive
as plain text inside a code fence, and it needs no dependency.

Nothing is re-queried: `build_timeline` already collects the incident, its
alerts and its events, and `stages`/`strip_lines` already lay out the chain, so
both are imported and reused (ruling R131). A second copy of either would drift
from the console view this file is meant to be a record of.

Defanging applies IN A FILE, and R130 says why: a newline can forge a Markdown
table row or a heading, and the file is very likely to be `type`d to a terminal
later, where an ESC fires exactly as it would have at the console. Every stored
value therefore goes through `cell()`, and every code fence through `fence()`.
"""

import json
import os
import sys
from contextlib import redirect_stdout
from datetime import datetime

from cli.commands.mitre import SEPARATOR as STRIP_SEPARATOR
from cli.commands.mitre import stages, strip_lines
from cli.commands.timeline import DEFAULT_CONTEXT, build_timeline, mark
from cli.render import EVENT_HEADERS, event_fields, fail, no_incident, plain
from core import store
from core.report import print_info, print_ok
from core.timeutil import parse_duration

NAME = "report"

ALERT_HEADERS = ("TIME", "SEVERITY", "RULE", "TACTIC")

# The strip's separator in the file. mitre's is U+00B7, and a cp1252 console
# renders a non-ASCII byte as a replacement character on `type` -- the exposure
# ruling R120 removed from rules/, in a file the brief says will be typed. Same
# width as the original, so the wrap stays inside mitre's WIDTH.
SEPARATOR = " - "


def add_parser(subparsers):
    """Register the `report` subcommand."""
    parser = subparsers.add_parser(NAME, help="write an incident report to a file")
    # --incident is a store filter (see cli/__init__.py): None, never 0.
    parser.add_argument("--incident", type=int, default=None, help="the incident")
    # Required, and spec section 12 writes it unbracketed: the product of this
    # verb is the file. A report dumped into a pipe because the flag was
    # forgotten is not what was asked for, and `timeline` and `mitre` already
    # print to a terminal.
    parser.add_argument("--out", default=None, help="the Markdown file to write")
    parser.add_argument("--force", action="store_true",
                        help="overwrite --out if it already exists")
    parser.set_defaults(func=run)
    return parser


def cell(value):
    """A stored value as one line of Markdown table or fence content.

    `plain` makes every control character visible, so a newline cannot forge a
    row and an ESC cannot drive the terminal the file is typed to. "|" becomes
    "?" on top of that: inside a table it would forge a column, and "?" is the
    convention `plain` already set rather than a backslash an operator reading
    the file unrendered would have to see.
    """
    return plain(value).replace("|", "?")


def fence(lines):
    """`lines` inside a Markdown code fence.

    A backtick becomes "?": stored text does reach the start of a line inside a
    block -- an unknown tactic id is the first thing on a strip line -- and
    "```" there would close the fence and let the rest be read as Markdown.
    """
    return ["```"] + [line.replace("`", "?") for line in lines] + ["```"]


def block(headers, cells):
    """`cells` under `headers` as fixed-width text lines.

    Not `cli.render.print_table`: that writes ANSI colour to stdout
    unconditionally, and an ESC in the file is the thing R130 defangs against.
    The width expression is print_table's, including ruling R104's single list
    argument so no cells does not raise.
    """
    widths = [max([len(h)] + [len(c[i]) for c in cells]) for i, h in enumerate(headers)]
    return ["  ".join(v.ljust(w) for v, w in zip(row, widths)).rstrip()
            for row in [headers] + list(cells)]


def member_alerts(rows):
    """The incident's alerts, oldest first, once each.

    Taken from the timeline rather than re-queried. An alert citing several
    live events is marked under each of them, so it appears in several rows and
    is de-duplicated here by id.
    """
    found = {}
    for row in rows:
        for alert in row["alerts"]:
            found.setdefault(alert["id"], alert)
    return sorted(found.values(), key=lambda a: (a["timestamp"], a["id"]))


def _tactic(alert):
    tactic = alert["tactic"]
    if not tactic:
        return "-"
    if alert["tactic_name"] == tactic:
        return tactic
    return "{} {}".format(tactic, alert["tactic_name"])


def _timeline_lines(rows):
    """The timeline exactly as `siem timeline` prints its table, marks and all,
    so the file is a record of the console view and not a second layout."""
    cells = []
    for row in rows:
        event = row["event"]
        if event is not None:
            cells.append((row["time"][:19], cell(event.event_id), cell(event.action),
                          cell(event.host), cell(event_fields(event))))
        for alert in row["alerts"]:
            # An alert whose events are all gone has no event row to sit under,
            # so it takes the time column itself.
            cells.append((cell(row["time"])[:19] if event is None else "", "", "", "",
                          cell(mark(alert))))
    return block(EVENT_HEADERS, cells) if cells else ["0 events or alerts"]


def render(built, context, generated=None):
    """The whole report as text, ending in exactly one newline.

    `built` is `build_timeline`'s result and `context` the string it was built
    with. `generated` is the time written into the header, injected only so a
    test can pin it.
    """
    incident, rows = built["incident"], built["rows"]
    alerts = member_alerts(rows)
    events = [r for r in rows if r["kind"] == "event"]
    generated = datetime.now() if generated is None else generated

    lines = ["# Incident {} - {}".format(incident["id"], cell(incident["title"] or "-")),
             "", "| Field | Value |", "| --- | --- |"]
    for label, value in (
            ("Severity", incident["severity"]), ("Score", incident["score"]),
            ("Status", incident["status"]),
            ("Entity", "{} {}".format(incident["entity_type"], incident["entity_value"])),
            ("Opened", str(incident["opened_at"])[:19]),
            ("Last seen", str(incident["last_seen"])[:19]),
            ("Alerts", len(alerts)), ("Events", len(events)),
            ("Context", context),
            ("Generated", generated.isoformat(sep=" ")[:19])):
        lines.append("| {} | {} |".format(label, cell(value)))

    lines += ["", "## Kill chain", ""]
    lines += fence([line.replace(STRIP_SEPARATOR, SEPARATOR)
                    for line in strip_lines(stages(incident["tactics"]))])

    lines += ["", "## Alerts ({})".format(len(alerts)), ""]
    lines += fence(block(ALERT_HEADERS, [
        (cell(a["timestamp"])[:19], cell(a["severity"]), cell(a["rule_id"]),
         cell(_tactic(a))) for a in alerts]))

    lines += ["", "## Timeline ({} events, {} cited by alerts)".format(
        len(events), sum(1 for r in events if r["referenced"])), ""]
    lines += fence(_timeline_lines(rows))

    if built["events_missing"]:
        lines += ["", "{} referenced event(s) are no longer stored".format(
            built["events_missing"])]
    return "\n".join(lines) + "\n"


def run(args):
    """Write the report. Returns a process exit code: 0; 1 for an incident that
    does not exist, a file that is already there without --force, or a write
    that failed; 3 when the alerts cite events the store no longer has -- the
    partial report is still written. A bad argument is 2, from dispatch."""
    if args.incident is None:
        raise ValueError("report needs an incident, e.g. report --incident 3 --out r.md")
    if not args.out or not args.out.strip():
        raise ValueError("report needs a file to write, e.g. report --incident {} "
                         "--out incident-{}.md".format(args.incident, args.incident))
    context = parse_duration(DEFAULT_CONTEXT)

    conn = store.connect(args.db)
    try:
        store.init_schema(conn)
        try:
            built = build_timeline(conn, args.incident, context)
        except ValueError as exc:
            return fail(args, str(exc))
    finally:
        conn.close()
    if built is None:
        return no_incident(args, args.incident)

    # Checked before rendering: an operator who mistyped --incident would
    # otherwise replace one incident's saved report with another's, and there
    # is no point building the text we are about to refuse to write.
    if os.path.exists(args.out) and not args.force:
        return fail(args, "{} already exists; pass --force to overwrite it".format(
            args.out))
    text = render(built, DEFAULT_CONTEXT)
    try:
        # newline="\n" so the file is byte-identical on every platform, and the
        # write happens before anything claims it did: a verb that names a file
        # it did not write is worse than one that fails loudly.
        with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    except OSError as exc:
        return fail(args, "Cannot write {}: {}".format(args.out, exc))

    missing = built["events_missing"]
    code = 3 if missing else 0
    if args.json:
        print(json.dumps({
            "incident": built["incident"], "out": args.out,
            "bytes": os.path.getsize(args.out),
            "alerts": len(member_alerts(built["rows"])),
            "events": sum(1 for r in built["rows"] if r["kind"] == "event"),
            "events_missing": missing,
        }, indent=2, default=str))
    # Text goes to stderr under --json so stdout stays JSON-only (ruling R77).
    with redirect_stdout(sys.stderr if args.json else sys.stdout):
        print_ok("Wrote {}".format(plain(args.out)))
        if missing:
            print_info("{} referenced event(s) are no longer stored".format(missing))
    return code

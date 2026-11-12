#!/usr/bin/env python3
"""
How stored text reaches a terminal
==================================
Every field a verb prints was written by something outside the tool: a log line
an attacker controlled, a rule file, a hand-edited row. This module is the one
place that neutralises it, so a verb that prints through it cannot be driven by
what it prints. A newline would forge a table row and an ESC would drive the
terminal; and nothing goes through rich markup (ruling R30): output is plain
text.
"""

import json

from core.report import Colors, print_error, severity_color

FIELD_WIDTH = 70

ALERT_HEADERS = ("TIME", "SEVERITY", "RULE", "ENTITY", "EVIDENCE")
EVENT_HEADERS = ("TIME", "EVENT", "ACTION", "HOST", "FIELDS")

# The event fields worth their own column: who, from where, doing what. "-" is
# Windows' "not recorded" and is left out.
FIELD_COLUMNS = ("user", "target_user", "source_ip", "process", "service_name",
                 "command_line")


def plain(value):
    """`value` as text with every control character made visible."""
    return "".join(c if c.isprintable() else "?" for c in str(value))


def clip(text, width=FIELD_WIDTH):
    """`text` cut to `width` characters, ending in "..." when it was cut."""
    return text if len(text) <= width else text[:width - 3] + "..."


def event_fields(event):
    """An event's identifying fields as one clipped, neutralised column."""
    return clip(plain(" ".join("{}={}".format(f, getattr(event, f)) for f in FIELD_COLUMNS
                               if getattr(event, f) not in ("-", "", None))))


def hashes(alert):
    """The event hashes an alert cites. A hand-edited `event_ids` that is not
    a JSON list of strings cites nothing."""
    try:
        cited = json.loads(alert["event_ids"])
    except (ValueError, TypeError):
        return []
    return [h for h in cited if isinstance(h, str)] if isinstance(cited, list) else []


def tactic_ids(row):
    """An incident's tactic ids. A hand-edited column that is not a JSON list
    is no tactics."""
    try:
        ids = json.loads(row["tactics"])
    except (ValueError, TypeError):
        return []
    return [str(t) for t in ids] if isinstance(ids, list) else []


def incident_dict(row):
    """An incident row as a JSON-ready dict, with `tactics` decoded."""
    return dict(row, tactics=tactic_ids(row))


def fail(args, message):
    """Report `message` on the chosen output and return exit code 1."""
    if args.json:
        print(json.dumps({"error": message}))
    else:
        print_error(message)
    return 1


def no_incident(args, incident_id):
    """`incidents`, `mitre` and `timeline` all refuse an unknown incident id,
    and said it three different places until this was one function."""
    return fail(args, "No incident with id {}".format(incident_id))


def evidence(row):
    """What distinguishes this alert: the newest event's alert fields.

    `detail` is the rule description plus the entity, so every alert of a rule
    on one host reads the same; the service name, command line or account is
    only in evidence. The entity and "-" (Windows' "not recorded") are left
    out as noise. Evidence that is not the list of dicts the engine writes
    (a hand-edited row) is a blank column.
    """
    try:
        newest = json.loads(row["evidence"])[-1]
        pairs = ["{}={}".format(k, v) for k, v in newest.items()
                 if v not in ("-", "", None, row["entity_value"])]
    except (ValueError, TypeError, LookupError, AttributeError):
        return ""
    return clip(plain(" ".join(pairs)))


def print_table(headers, cells, severity_column=None):
    """Print `cells` (rows of text, already `plain`) under `headers`, padded to
    the widest value in each column. The severity column is padded before it is
    coloured: the escape codes would count towards the width.

    No `cells` prints the headers alone. The width list is built from a single
    list argument, not from `max(len(h), *gen)`: with no cells that spreads to
    one argument and raises TypeError (ruling R104).
    """
    widths = [max([len(h)] + [len(c[i]) for c in cells]) for i, h in enumerate(headers)]
    print("  {}{}{}".format(Colors.DIM, "  ".join(
        h.ljust(w) for h, w in zip(headers, widths)).rstrip(), Colors.RESET))
    for cell in cells:
        padded = [v.ljust(w) for v, w in zip(cell, widths)]
        if severity_column is not None:
            padded[severity_column] = (severity_color(cell[severity_column])
                                       + padded[severity_column] + Colors.RESET)
        print("  " + "  ".join(padded).rstrip())


def print_alerts(rows):
    """The alert table: time, severity, rule id, entity, evidence."""
    print_table(ALERT_HEADERS, [
        (plain(r["timestamp"])[:19], plain(r["severity"]), plain(r["rule_id"]),
         plain(r["entity_value"]), evidence(r)) for r in rows], severity_column=1)

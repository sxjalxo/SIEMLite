#!/usr/bin/env python3
"""
siem timeline
=============
An incident as a story: every event its alerts cite, plus the entity's other
events around them, oldest first, with each alert marked under the event that
raised it.

There is no timeline table. It is built on demand from the incident's alerts
and the events, and nothing is written.
"""

import json
from dataclasses import asdict
from datetime import datetime

from cli.commands.investigate import FILTER
from cli.render import (EVENT_HEADERS, event_fields, fail, hashes, incident_dict,
                        no_incident, plain, print_table)
from core import store
from core.report import print_info, print_section
from core.timeutil import parse_duration
from modules.mitre_mapping import tactic_name

NAME = "timeline"

DEFAULT_CONTEXT = "10m"


def add_parser(subparsers):
    """Register the `timeline` subcommand."""
    parser = subparsers.add_parser(NAME, help="an incident's events and alerts, in order")
    # --incident is a store filter (see cli/__init__.py): None, never 0.
    parser.add_argument("--incident", type=int, default=None, help="the incident")
    parser.add_argument("--context", default=DEFAULT_CONTEXT,
                        help="also show the entity's events this long before the "
                             "incident opened and after it was last seen: 30s, 5m, 2h "
                             "(default: {})".format(DEFAULT_CONTEXT))
    parser.set_defaults(func=run)
    return parser


def _alert_dict(row):
    tactic = row["mitre_tactic_id"]
    return {"id": row["id"], "rule_id": row["rule_id"], "severity": row["severity"],
            "tactic": tactic, "tactic_name": tactic_name(tactic) if tactic else None,
            "timestamp": str(row["timestamp"])}


def _local(incident, column):
    """An incident time as a datetime. Stored text is local naive, so no
    conversion is owed; text that is not a time is an error, not a guess."""
    try:
        return datetime.fromisoformat(str(incident[column]))
    except ValueError:
        raise ValueError("incident {} has an unreadable {}: {!r}".format(
            incident["id"], column, incident[column]))


def build_timeline(conn, incident_id, context):
    """The incident's timeline, or None when there is no such incident.

    Returns {"incident": dict, "rows": [...], "events_missing": int}. A row is
    {"kind", "time", "event", "event_hash", "referenced", "alerts"}:
      - kind "event": a stored event, under the hash it is STORED under.
        `referenced` says an alert cites it; the alerts that do are in
        `alerts`, once each however many events they cite, and an event several
        alerts cite is one row carrying all of them.
      - kind "alert": an alert none of whose events is stored any more, at its
        own time, so an alert is never lost with its events.
    Rows are oldest first. `events_missing` counts distinct event hashes the
    alerts cite that the store no longer has (`db purge` can remove them).
    `context` is a timedelta; the entity's events from opened_at - context to
    last_seen + context are added, and events an alert cites are present
    whether or not they fall inside that window.
    """
    found = store.query_incidents(conn, incident_id=incident_id)
    if not found:
        return None
    incident = found[0]
    alerts = store.query_alerts(conn, incident_id=incident_id, limit=None, order="asc")
    wanted = list(dict.fromkeys(h for a in alerts for h in hashes(a)))
    # Keyed on the STORED hash (ruling R105), so an event whose fields were
    # edited after it was written stays hooked to the alerts citing it, and
    # events_missing counts what is really gone rather than what no longer
    # hashes the same.
    cited = dict(store.events_by_hash(conn, wanted))
    # Context events come from query_events, which does not carry the stored
    # hash, so they are de-duplicated against the cited ones by RECOMPUTED
    # hash: both sides recompute it the same way, so one row is never two rows
    # even when the stored hash and the recomputed one have diverged.
    context_events, seen = [], {e.event_hash for e in cited.values()}
    if incident["entity_type"] in FILTER:
        # ponytail: every event of the entity in the window, uncapped, like
        # `incidents show`'s source list. A busy host over a wide --context
        # prints a long timeline; the caller chose the width.
        for e in store.query_events(
                conn, since=_local(incident, "opened_at") - context,
                until=_local(incident, "last_seen") + context, limit=None, order="asc",
                **{FILTER[incident["entity_type"]]: incident["entity_value"]}):
            if e.event_hash not in seen:
                seen.add(e.event_hash)
                context_events.append(e)

    marks, orphans = {}, []
    for a in alerts:
        live = [h for h in dict.fromkeys(hashes(a)) if h in cited]
        for h in live:
            marks.setdefault(h, []).append(_alert_dict(a))
        if not live:
            orphans.append(_alert_dict(a))

    rows = [_event_row(h, e, marks.get(h, [])) for h, e in cited.items()]
    rows += [_event_row(e.event_hash, e, []) for e in context_events]
    rows += [{"kind": "alert", "time": m["timestamp"], "event": None,
              "event_hash": None, "referenced": False, "alerts": [m]} for m in orphans]
    # The two sources arrive from different queries, so sort here. At one
    # instant the event comes before the alert it raised.
    rows.sort(key=lambda r: (r["time"], r["kind"] == "alert",
                             r["event"].record_id if r["event"] else 0))
    return {"incident": incident_dict(incident), "rows": rows,
            "events_missing": len(wanted) - len(cited)}


def _event_row(event_hash, event, alerts):
    """An event's row. Only a cited event has alerts, so `alerts` is also what
    says whether it is referenced."""
    return {"kind": "event", "time": event.timestamp.isoformat(sep=" "), "event": event,
            "event_hash": event_hash, "referenced": bool(alerts), "alerts": alerts}


def mark(alert):
    """An alert's inline mark, in spec section 10's layout. Public because
    `report` writes the same timeline into a file and a second copy of this
    format string would drift from this one (ruling R131)."""
    tactic = alert["tactic"]
    if not tactic:
        label = "-"
    elif alert["tactic_name"] == tactic:
        label = tactic
    else:
        label = "{} {}".format(tactic, alert["tactic_name"])
    # Two spaces between the columns, as spec section 10 shows them.
    return ">> ALERT  {}  {}  [{}]".format(
        plain(alert["rule_id"]), plain(alert["severity"]), plain(label))


def _json_row(row):
    # The event carries the hash it is STORED under, which is the one that
    # resolves back through events_by_hash, not the recomputed one.
    event = row["event"]
    return dict(row, event=None if event is None else dict(
        asdict(event), event_hash=row["event_hash"]))


def run(args):
    """Print the timeline. Returns a process exit code: 0; 1 for an incident
    that does not exist; 3 when alerts cite events the store no longer has. A
    bad argument is 2, from dispatch."""
    if args.incident is None:
        raise ValueError("timeline needs an incident, e.g. timeline --incident 3")
    context = parse_duration(args.context)

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
    incident, rows, missing = built["incident"], built["rows"], built["events_missing"]
    code = 3 if missing else 0

    if args.json:
        print(json.dumps({"incident": incident, "context": args.context,
                          "rows": [_json_row(r) for r in rows],
                          "events_missing": missing}, indent=2, default=str))
        return code

    print_section("Timeline for incident {}".format(incident["id"]))
    shown = [r for r in rows if r["kind"] == "event"]
    for label, value in (
            ("Entity", "{} {}".format(incident["entity_type"], incident["entity_value"])),
            ("Window", "{} to {}, {} either side".format(
                str(incident["opened_at"])[:19], str(incident["last_seen"])[:19], args.context)),
            ("Events", "{} ({} cited by alerts)".format(
                len(shown), sum(1 for r in shown if r["referenced"])))):
        print_info("{:<7}: {}".format(label, plain(value)))
    cells = []
    for row in rows:
        event = row["event"]
        if event is not None:
            cells.append((row["time"][:19], plain(event.event_id), plain(event.action),
                          plain(event.host), event_fields(event)))
        for alert in row["alerts"]:
            # An alert mark sits under its event, in the last column. One whose
            # events are gone has no event row to sit under, so it takes the
            # time column itself.
            cells.append((plain(row["time"])[:19] if event is None else "", "", "", "",
                          mark(alert)))
    if cells:
        print_table(EVENT_HEADERS, cells)
    else:
        print_info("0 events or alerts")
    if missing:
        print_info("{} referenced event(s) are no longer stored".format(missing))
    return code

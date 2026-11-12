#!/usr/bin/env python3
"""
siem incidents
==============
List, show and close the incidents the correlator groups alerts into.

Reading never writes: `list` and `show` change nothing. Closing is `close <id>`
for one incident, or `--close-idle` for every incident idle past the timeout.
"""

import json
from dataclasses import asdict

from cli.render import (EVENT_HEADERS, event_fields, hashes, incident_dict,
                        no_incident, plain, print_alerts, print_table, tactic_ids)
from core import store
from core.report import print_info, print_ok, print_section
from modules.mitre_mapping import tactic_name

NAME = "incidents"

# Text output stops here unless --top says otherwise. JSON has no default cap,
# as in `alerts`: a script that reads it must not get the first 20 unannounced.
DEFAULT_TOP = 20
# `show` lists at most this many alerts and this many events, and says how many
# it left out. An incident can reference thousands of events.
SHOW_LIMIT = 50

LIST_HEADERS = ("ID", "SEVERITY", "SCORE", "STATUS", "TYPE", "ENTITY",
                "LAST SEEN", "TACTICS", "FIRST ALERT")


def add_parser(subparsers):
    """Register the `incidents` subcommand."""
    parser = subparsers.add_parser(NAME, help="list, show and close incidents")
    parser.add_argument("action", nargs="?", choices=["list", "show", "close"],
                        default="list", help="what to do (default: list)")
    parser.add_argument("incident_id", nargs="?", type=int, default=None,
                        help="the incident (show and close)")
    # --open is a store filter (see cli/__init__.py): _list passes None, not "".
    parser.add_argument("--open", action="store_true", help="only OPEN incidents")
    # Not a store filter, so a real default is correct; None means "by output".
    parser.add_argument("--top", type=int, default=None,
                        help="most incidents to list (default: {} as text, all as JSON)".format(
                            DEFAULT_TOP))
    parser.add_argument("--close-idle", action="store_true",
                        help="close every incident idle for over 2 hours, instead of listing")
    parser.set_defaults(func=run)
    return parser


def run(args):
    """Execute the chosen action. Returns a process exit code: 0; 1 for an
    incident id that does not exist; 3 when `show` reports referenced events
    the store no longer has. A bad argument is 2, from dispatch."""
    if args.top is not None and args.top < 1:
        raise ValueError("--top must be at least 1, got {}".format(args.top))
    if args.action == "list" and args.incident_id is not None:
        raise ValueError("incidents list takes no incident id (got {0}); "
                         "use incidents show {0}".format(args.incident_id))
    if args.action != "list" and args.incident_id is None:
        raise ValueError("incidents {0} needs an incident id, e.g. incidents {0} 3".format(
            args.action))
    if args.action != "list":
        # A flag that does nothing is worse than one that complains.
        for flag, given in (("--close-idle", args.close_idle), ("--open", args.open),
                            ("--top", args.top is not None)):
            if given:
                raise ValueError("{} goes with the list action only".format(flag))

    conn = store.connect(args.db)
    try:
        store.init_schema(conn)
        if args.close_idle:
            return _close_idle(conn, args)
        return {"list": _list, "show": _show, "close": _close}[args.action](conn, args)
    finally:
        conn.close()


def _tactic_names(row):
    return ", ".join(plain(tactic_name(t)) for t in tactic_ids(row)) or "-"


def _close_idle(conn, args):
    closed = store.close_idle_incidents(conn)
    if args.json:
        print(json.dumps({"closed_idle": closed}))
    else:
        print_ok("Closed {} idle incident(s)".format(closed))
    return 0


def _close(conn, args):
    # Closing a CLOSED incident still matches its row: idempotent, exit 0.
    if not store.close_incident(conn, args.incident_id):
        return no_incident(args, args.incident_id)
    if args.json:
        print(json.dumps({"closed": args.incident_id}))
    else:
        print_ok("Closed incident {}".format(args.incident_id))
    return 0


def _list(conn, args):
    rows = store.query_incidents(conn, status="OPEN" if args.open else None, limit=None)
    limit = args.top if args.top is not None else (None if args.json else DEFAULT_TOP)
    shown = rows if limit is None else rows[:limit]
    if args.json:
        print(json.dumps({"count": len(shown), "total": len(rows),
                          "incidents": [incident_dict(r) for r in shown]},
                         indent=2, default=str))
        return 0
    if not shown:
        print_info("0 incidents match")
        return 0
    print_section(_title("Incidents", len(shown), len(rows)))
    print_table(LIST_HEADERS, [
        (str(r["id"]), plain(r["severity"]), plain(r["score"]), plain(r["status"]),
         plain(r["entity_type"]), plain(r["entity_value"]), plain(r["last_seen"])[:19],
         _tactic_names(r), plain(r["title"] or "-")) for r in shown], severity_column=1)
    return 0


def _title(name, shown, total, which=""):
    if shown < total:
        return "{} (showing {}{} of {})".format(name, which, shown, total)
    return "{} ({})".format(name, total)


def _show(conn, args):
    found = store.query_incidents(conn, incident_id=args.incident_id)
    if not found:
        return no_incident(args, args.incident_id)
    incident = found[0]
    alerts = store.query_alerts(conn, incident_id=incident["id"], limit=None)
    # Alerts cite events by event_hash (not row id), and several alerts often
    # cite the same event; events_by_hash de-duplicates and sorts oldest first.
    cited = list(dict.fromkeys(h for a in alerts for h in hashes(a)))
    events = [e for _, e in store.events_by_hash(conn, cited)]
    missing = len(cited) - len(events)
    # Ruling R102: referenced events that are gone are "something asked for was
    # not stored" (R51), which is 3 across the CLI — as `timeline` already did.
    code = 3 if missing else 0

    if args.json:
        print(json.dumps({
            "incident": incident_dict(incident), "alerts": [dict(a) for a in alerts],
            "events": [asdict(e) for e in events], "events_missing": missing,
        }, indent=2, default=str))
        return code

    # The entity is shown as stored: a user-keyed rule falls back to the host
    # when the user is unknown (R90), so it is not always the declared type.
    print_section("Incident {}".format(incident["id"]))
    for label, value in (
            ("First alert", incident["title"] or "-"), ("Severity", incident["severity"]),
            ("Score", incident["score"]), ("Status", incident["status"]),
            ("Entity", "{} {}".format(incident["entity_type"], incident["entity_value"])),
            ("Opened", str(incident["opened_at"])[:19]),
            ("Last seen", str(incident["last_seen"])[:19]),
            ("Tactics", _tactic_names(incident))):
        print_info("{:<11}: {}".format(label, plain(value)))

    shown = alerts[:SHOW_LIMIT]
    print_section(_title("Alerts", len(shown), len(alerts)))
    if shown:
        print_alerts(shown)
    shown = events[:SHOW_LIMIT]
    print_section(_title("Events", len(shown), len(events), "first "))
    if shown:
        print_table(EVENT_HEADERS, [
            (e.timestamp.isoformat(sep=" ")[:19], plain(e.event_id), plain(e.action),
             plain(e.host), event_fields(e)) for e in shown])
    if missing:
        print_info("{} referenced event(s) are no longer stored".format(missing))
    return code

#!/usr/bin/env python3
"""
siem investigate
================
"What else touched this thing": every event and alert for one IP, user or host
in a time range, oldest first, and with --related a pivot to what that entity
is connected to.

Read-only. Only rule-engine alerts are listed: the table also holds the legacy
scanner's alerts, whose timestamps are UTC where the rule engine's are local
naive, so one time-ordered view of both would be wrong.
"""

import json
from collections import Counter
from dataclasses import asdict

from cli.render import EVENT_HEADERS, event_fields, plain, print_alerts, print_table
from core import store
from core.report import print_info, print_section
from core.timeutil import parse_since

NAME = "investigate"

# Text output stops here unless --limit says otherwise. JSON has no default
# cap, as in `alerts`: a script that reads it must not get the first 50
# unannounced.
TEXT_LIMIT = 50
# Most nodes printed per pivot level; the rest are counted, not printed.
PIVOT_CAP = 10
# An entity's events are read newest first, at most this many, when pivoting.
# ponytail: a host with more events than this pivots on its newest ones and
# says so. A DISTINCT query in the store would lift it; add that if it bites.
PIVOT_SCAN = 5000

# The pivot walks the ring ip -> user -> host -> ip. It starts at the kind of
# entity it was given and takes THREE steps, one level each, then stops: from
# an IP that is users, their hosts, and those hosts' other IPs. A fourth step
# would be a second lap and an unbounded walk.
RING = ("ip", "user", "host")
DEPTH = len(RING)
# The event columns an entity of each kind is matched against, and read from.
# An account is both sides of an action (query_events(user=) matches both).
FILTER = {"ip": "source_ip", "user": "user", "host": "host"}
VALUES = {"ip": ("source_ip",), "user": ("user", "target_user"), "host": ("host",)}


def add_parser(subparsers):
    """Register the `investigate` subcommand."""
    parser = subparsers.add_parser(NAME, help="every event and alert for an IP, user or host")
    # Store filters (see cli/__init__.py): None, never "".
    parser.add_argument("--ip", default=None, help="investigate this IP address")
    parser.add_argument("--user", default=None,
                        help="investigate this account, as actor or as target")
    parser.add_argument("--host", default=None, help="investigate this host")
    parser.add_argument("--since", default=None,
                        help="from this time: 30m, 24h, 7d or an ISO time (default: all)")
    parser.add_argument("--until", default=None, help="up to this time")
    parser.add_argument("--related", action="store_true",
                        help="also pivot: ip -> users -> hosts -> other ips, one level each")
    # Not store filters, so real defaults are right; None means "by output".
    parser.add_argument("--limit", type=int, default=None,
                        help="most events and alerts to list (default: {} as text, "
                             "all as JSON)".format(TEXT_LIMIT))
    parser.add_argument("--cap", type=int, default=PIVOT_CAP,
                        help="most nodes per pivot level (default: {})".format(PIVOT_CAP))
    parser.set_defaults(func=run)
    return parser


def _entity(args):
    """(kind, value) from the one of --ip/--user/--host that was given."""
    given = [(k, getattr(args, k)) for k in RING if getattr(args, k) is not None]
    if len(given) != 1:
        raise ValueError("give exactly one of --ip, --user, --host")
    kind, value = given[0]
    if not value.strip():
        raise ValueError("--{} needs a value".format(kind))
    return kind, value


def _known(value):
    """False for what the normalizer writes for "not recorded"."""
    return value not in ("-", "", None, 0)


def pivot(conn, entity_type, entity_value, since, until, cap):
    """The pivot tree: a list of DEPTH levels, each the next kind of entity
    around the ring, read from the events of the level before.

    Returns {"levels": [{"type", "total", "nodes": [{"value", "parent",
    "events"}]}], "truncated": bool}. A level keeps its `cap` busiest nodes (by
    events, then name) and `total` says how many it found. `truncated` is True
    when any entity had more events than PIVOT_SCAN and only the newest were
    read. A node is listed under the first parent that reached it.
    """
    levels, truncated = [], False
    kind, parents = entity_type, [entity_value]
    for _ in range(DEPTH):
        parent_kind, kind = kind, RING[(RING.index(kind) + 1) % len(RING)]
        counts, first = Counter(), {}
        for parent in parents:
            events = store.query_events(
                conn, since=since, until=until, limit=PIVOT_SCAN + 1, order="desc",
                **{FILTER[parent_kind]: parent})
            # One past the limit is how "exactly PIVOT_SCAN" is told from "more".
            truncated = truncated or len(events) > PIVOT_SCAN
            events = events[:PIVOT_SCAN]
            for event in events:
                for value in {getattr(event, f) for f in VALUES[kind]}:
                    # The third step comes back round to the kind it started
                    # from; the entity itself is not "related" to itself.
                    if _known(value) and not (kind == entity_type and value == entity_value):
                        counts[value] += 1
                        first.setdefault(value, parent)
        kept = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:cap]
        levels.append({"type": kind, "total": len(counts), "nodes": [
            {"value": v, "parent": first[v], "events": n} for v, n in kept]})
        parents = [v for v, _ in kept]
    return {"levels": levels, "truncated": truncated}


def _print_tree(entity_type, entity_value, tree, cap):
    print_section("Related")
    levels = tree["levels"]

    def walk(depth, parent, indent):
        if depth == len(levels):
            return
        for node in levels[depth]["nodes"]:
            if node["parent"] == parent:
                print("  {}{} {} events={}".format(
                    "  " * indent, levels[depth]["type"], plain(node["value"]),
                    node["events"]))
                walk(depth + 1, node["value"], indent + 1)

    print("  {} {}".format(entity_type, plain(entity_value)))
    walk(0, entity_value, 1)
    for level in levels:
        if level["total"] > len(level["nodes"]):
            print_info("+{} more {}(s) not shown (cap {})".format(
                level["total"] - len(level["nodes"]), level["type"], cap))
    if tree["truncated"]:
        print_info("An entity had over {} events; only its newest {} events were read".format(
            PIVOT_SCAN, PIVOT_SCAN))


def _title(name, shown, total):
    if shown < total:
        return "{} (showing first {} of {})".format(name, shown, total)
    return "{} ({})".format(name, total)


def run(args):
    """Investigate one entity. Returns a process exit code: 0, whatever the
    count, since "no history" is an answer. A bad argument is 2, from dispatch."""
    kind, value = _entity(args)
    since = None if args.since is None else parse_since(args.since)
    until = None if args.until is None else parse_since(args.until)
    if args.limit is not None and args.limit < 1:
        raise ValueError("--limit must be at least 1, got {}".format(args.limit))
    if args.cap < 1:
        raise ValueError("--cap must be at least 1, got {}".format(args.cap))
    limit = args.limit if args.limit is not None else (None if args.json else TEXT_LIMIT)

    conn = store.connect(args.db)
    try:
        store.init_schema(conn)
        # ponytail: both lists are read whole and cut afterwards, so the count
        # is exact. Holds every match in memory; page them if one entity ever
        # has more events than fit.
        events = store.query_events(conn, since=since, until=until, limit=None,
                                    order="asc", **{FILTER[kind]: value})
        # Not mixing the legacy rows in (no rule_id, UTC timestamps), and not
        # an alert about another kind of entity with the same text.
        alerts = [a for a in store.query_alerts(
            conn, since=since, until=until, entity=value, limit=None, order="asc")
            if a["rule_id"] is not None and a["entity_type"] == kind]
        tree = pivot(conn, kind, value, since, until, args.cap) if args.related else None
    finally:
        conn.close()

    shown_events = events if limit is None else events[:limit]
    shown_alerts = alerts if limit is None else alerts[:limit]

    if args.json:
        payload = {
            "entity": {"type": kind, "value": value},
            "counts": {"events": len(events), "alerts": len(alerts)},
            "events": [asdict(e) for e in shown_events],
            "alerts": [dict(a) for a in shown_alerts],
        }
        if tree is not None:
            payload["related"] = tree
        print(json.dumps(payload, indent=2, default=str))
        return 0

    label = "{} {}".format(kind, plain(value))
    if not events and not alerts:
        print_info("No events or alerts for {}".format(label))
    else:
        print_section("Investigate {}".format(label))
    if alerts:
        print_section(_title("Alerts", len(shown_alerts), len(alerts)))
        print_alerts(shown_alerts)
    if events:
        print_section(_title("Events", len(shown_events), len(events)))
        print_table(EVENT_HEADERS, [
            (e.timestamp.isoformat(sep=" ")[:19], plain(e.event_id), plain(e.action),
             plain(e.host), event_fields(e)) for e in shown_events])
    if tree is not None:
        _print_tree(kind, value, tree, args.cap)
    return 0

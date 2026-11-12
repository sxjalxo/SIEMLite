#!/usr/bin/env python3
"""
siem alerts
===========
List the alerts the rule engine stored, newest first.

Only rule-engine alerts are listed. The table also holds the legacy scanner's
alerts: no rule id, no entity, and UTC timestamps where the rule engine's are
local naive, about five hours apart on a host in IST. One time-ordered list of
both would be wrong, so they are not mixed.
"""

import json

from cli.render import print_alerts
from core import store
from core.report import print_info, print_section
from core.rule_engine.loader import SEVERITIES
from core.timeutil import parse_since

NAME = "alerts"

# Text output stops here unless --limit says otherwise. JSON has no default
# cap: a script that reads it must not get the first 50 without noticing.
TEXT_LIMIT = 50


def add_parser(subparsers):
    """Register the `alerts` subcommand."""
    parser = subparsers.add_parser(NAME, help="list stored detection alerts")
    # Every one of these is a store filter (see cli/__init__.py): None, never "".
    parser.add_argument("--severity", choices=SEVERITIES, default=None,
                        help="only this severity")
    parser.add_argument("--since", default=None,
                        help="only alerts at or after this time: 30m, 24h, 7d or an ISO time")
    parser.add_argument("--until", default=None, help="only alerts at or before this time")
    parser.add_argument("--rule", default=None, help="only this rule id")
    parser.add_argument("--entity", default=None,
                        help="only this entity: an IP address, user or host")
    parser.add_argument("--status", default=None, help="only this status (new alerts are NEW)")
    # Not a store filter, so a real default is correct; None means "by output".
    parser.add_argument("--limit", type=int, default=None,
                        help="most alerts to list (default: {} as text, all as JSON)".format(
                            TEXT_LIMIT))
    parser.set_defaults(func=run)
    return parser


def run(args):
    """List alerts. Returns a process exit code: 0, whatever the count."""
    since = None if args.since is None else parse_since(args.since)
    until = None if args.until is None else parse_since(args.until)
    if args.limit is not None and args.limit < 1:
        raise ValueError("--limit must be at least 1, got {}".format(args.limit))
    limit = args.limit if args.limit is not None else (None if args.json else TEXT_LIMIT)

    conn = store.connect(args.db)
    try:
        store.init_schema(conn)
        # ponytail: the store has no "rule-engine rows only" filter, so the
        # legacy rows are dropped here and the limit applied after: a limit in
        # the query would be spent on them. Holds every matching row in memory;
        # add a filter to query_alerts if alerts ever stop fitting.
        rows = store.query_alerts(
            conn, since=since, until=until, severity=args.severity,
            rule_id=args.rule, entity=args.entity, status=args.status, limit=None)
    finally:
        conn.close()
    matched = [r for r in rows if r["rule_id"] is not None]
    legacy_hidden = len(matched) < len(rows)
    shown = matched if limit is None else matched[:limit]

    if args.json:
        print(json.dumps({
            # legacy_hidden: the rows the text note mentions, counted among those
            # matching the other filters (a --since compares against their UTC
            # timestamps, so near the bound it can be off by the offset).
            "count": len(shown), "total": len(matched),
            "legacy_hidden": len(rows) - len(matched), "alerts": [dict(r) for r in shown],
        }, indent=2, default=str))
        return 0

    if not shown:
        print_info("0 alerts match")
    else:
        title = "Alerts ({})".format(len(shown))
        if len(shown) < len(matched):
            title = "Alerts (showing {} of {})".format(len(shown), len(matched))
        print_section(title)
        print_alerts(shown)
    if legacy_hidden:
        print_info("Legacy scanner alerts are not listed (no rule id; their timestamps are UTC)")
    return 0

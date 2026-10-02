#!/usr/bin/env python3
"""
siem db
=======
Create, inspect and prune the event store.
"""

import json

from core import store
from core.report import print_info, print_ok, print_section
from core.timeutil import parse_since

NAME = "db"


def add_parser(subparsers):
    """Register the `db` subcommand."""
    parser = subparsers.add_parser(NAME, help="manage the event store")
    parser.add_argument(
        "action", choices=["init", "stats", "purge"], help="what to do"
    )
    # Not a store filter, so a real default is correct here. Store filters
    # (see cli/__init__.py) must default to None.
    parser.add_argument(
        "--older-than", default="30d",
        help="purge cutoff, e.g. 30d (purge only)",
    )
    parser.set_defaults(func=run)
    return parser


def run(args):
    """Execute the chosen db action. Returns a process exit code."""
    conn = store.connect(args.db)
    try:
        store.init_schema(conn)
        if args.action == "init":
            return _init(args)
        if args.action == "stats":
            return _stats(conn, args)
        return _purge(conn, args)
    finally:
        conn.close()


def _init(args):
    target = args.db or store.DEFAULT_DB_PATH
    if args.json:
        print(json.dumps({"status": "ok", "db": str(target)}))
    else:
        print_ok("Event store ready at {}".format(target))
    return 0


def _stats(conn, args):
    summary = store.stats(conn)

    if args.json:
        print(json.dumps(summary, indent=2))
        return 0

    print_section("Event Store")
    print_info("Total events : {}".format(summary["total"]))
    print_info("Earliest     : {}".format(summary["earliest"] or "-"))
    print_info("Latest       : {}".format(summary["latest"] or "-"))

    if summary["by_channel"]:
        print_section("By Channel")
        for channel, count in summary["by_channel"].items():
            print_info("{:<45} {}".format(channel, count))

    if summary["by_event_id"]:
        print_section("Top Event IDs")
        for event_id, count in summary["by_event_id"].items():
            print_info("{:<45} {}".format(event_id, count))

    return 0


def _purge(conn, args):
    cutoff = parse_since(args.older_than)
    with conn:
        cursor = conn.execute(
            "DELETE FROM events WHERE timestamp < ?", (cutoff.isoformat(sep=" "),)
        )
    removed = cursor.rowcount

    if args.json:
        print(json.dumps({"removed": removed, "cutoff": cutoff.isoformat()}))
    else:
        print_ok("Removed {} events older than {}".format(removed, cutoff))
    return 0

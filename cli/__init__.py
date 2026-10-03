#!/usr/bin/env python3
"""
SIEM-Lite CLI
=============
Subcommand dispatcher. Each verb lives in cli/commands/<verb>.py, defines a
NAME constant, and registers itself with add_parser(subparsers).

To add a verb: import its module below and append it to COMMAND_MODULES.

Every store-filter argument a verb adds (--source-ip, --user, --event-id,
--host, --channel, --since, ...) MUST default to None. core.store.query_events
filters with `is not None`, so a default of "" or 0 means "match nothing",
not "no filter".
"""

import argparse

from cli.commands import db as db_command
from cli.commands import ingest as ingest_command
from core.report import print_error

COMMAND_MODULES = [db_command, ingest_command]


def build_parser():
    """Build the top-level parser with every registered subcommand."""
    parser = argparse.ArgumentParser(
        prog="siem",
        description="SIEM-Lite — Windows log ingestion, detection and response",
    )
    parser.add_argument(
        "--db", default=None,
        help="path to the SQLite store (default: db/siem_lite.db)",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON"
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")
    for module in COMMAND_MODULES:
        module.add_parser(subparsers)

    return parser


def command_names():
    """Names of every registered subcommand."""
    return {module.NAME for module in COMMAND_MODULES}


def is_subcommand(argv):
    """True when argv is a registered subcommand, after any leading global flags.

    main.py uses this to route without breaking the legacy --scan/--analyze
    invocation that predates the subcommand CLI. The global flags come before
    the subcommand (`--db PATH db stats`), so skip them first. Legacy flags
    never start with --db or --json, so they still fall through.
    """
    i = 0
    while i < len(argv):
        if argv[i] == "--json" or argv[i].startswith("--db="):
            i += 1
        elif argv[i] == "--db":
            i += 2
        else:
            break
    return i < len(argv) and argv[i] in command_names()


def dispatch(argv):
    """Parse argv and run the selected command. Returns an exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # store.connect() treats a falsy path as "use the default database", so an
    # empty --db (e.g. an unset shell variable) would silently hit the real one.
    if args.db is not None and not args.db.strip():
        print_error("--db needs a path, got an empty value.")
        return 2

    if not args.command:
        parser.print_help()
        return 2

    # One handler for every verb: parse_since and friends raise ValueError with
    # a message already worded for the user.
    try:
        return args.func(args)
    except ValueError as exc:
        print_error(str(exc))
        return 2

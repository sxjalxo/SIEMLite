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
import sqlite3
import sys
from contextlib import redirect_stdout

from cli.commands import alerts as alerts_command
from cli.commands import db as db_command
from cli.commands import detect as detect_command
from cli.commands import incidents as incidents_command
from cli.commands import ingest as ingest_command
from cli.commands import investigate as investigate_command
from cli.commands import mitre as mitre_command
from cli.commands import monitor as monitor_command
from cli.commands import report as report_command
from cli.commands import respond as respond_command
from cli.commands import rules as rules_command
from cli.commands import timeline as timeline_command
from core.report import print_error

COMMAND_MODULES = [db_command, ingest_command, rules_command, detect_command,
                   alerts_command, incidents_command, investigate_command,
                   timeline_command, mitre_command, respond_command,
                   report_command, monitor_command]


def build_parser():
    """Build the top-level parser with every registered subcommand."""
    parser = argparse.ArgumentParser(
        prog="siem",
        # ASCII only: this prints on every `siem --help`, and a cp1252 console
        # renders a non-ASCII byte as a replacement character (ruling R120).
        description="SIEM-Lite - Windows log ingestion, detection and response",
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


def _error(args, message):
    """print_error, to stderr under --json so stdout stays JSON-only."""
    if args.json:
        with redirect_stdout(sys.stderr):
            print_error(message)
    else:
        print_error(message)


def dispatch(argv):
    """Parse argv and run the selected command. Returns an exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # store.connect() treats a falsy path as "use the default database", so an
    # empty --db (e.g. an unset shell variable) would silently hit the real one.
    if args.db is not None and not args.db.strip():
        _error(args, "--db needs a path, got an empty value.")
        return 2

    if not args.command:
        parser.print_help()
        return 2

    # One handler for every verb: parse_since and friends raise ValueError with
    # a message already worded for the user; sqlite3.Error is handled below it.
    try:
        return args.func(args)
    except ValueError as exc:
        _error(args, str(exc))
        return 2
    except sqlite3.Error as exc:
        # A file that is not a database, or one that is locked: the operation
        # could not run (1), not a usage error (2). Every verb that opens the
        # store gets this, so none of them handles it on its own.
        _error(args, "Cannot use the database: {}".format(exc))
        return 1

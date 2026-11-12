#!/usr/bin/env python3
"""
siem detect
===========
Read a window of stored events, run the YAML rule pack over it, store the
alerts and group them into incidents. Safe to re-run over overlapping windows:
an alert already stored is counted as a duplicate, not stored again, and one
already grouped is not grouped twice.

Detection never closes incidents. Closing is time-based (idle for two hours),
so doing it here would let `--since 90d` over old events close incidents that
are current. It belongs to `siem incidents`.
"""

import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

from cli.rulepack import DEFAULT_RULES_DIR, error_dicts, print_errors
from core import store
from core.correlator import correlate
from core.report import print_error, print_info, print_section, print_warn
from core.rule_engine.engine import load_plugins, run_rules
from core.rule_engine.loader import load_rules
from core.timeutil import parse_since

NAME = "detect"

DEFAULT_PLUGINS_DIR = Path("rules/plugins")


def add_parser(subparsers):
    """Register the `detect` subcommand."""
    parser = subparsers.add_parser(NAME, help="run the detection rules over stored events")
    # The window bounds are store filters (see cli/__init__.py): --until
    # defaults to None, "no bound". --since's "24h" is not falsy: it always
    # parses to a datetime, so it cannot mean "match nothing".
    parser.add_argument("--since", default="24h",
                        help="start of the window: 30m, 24h, 7d or an ISO time (default: 24h)")
    parser.add_argument("--until", default=None, help="end of the window (default: now)")
    parser.add_argument("--rule", default=None, help="run only the rule with this id")
    parser.add_argument(
        "--rules-dir", default=DEFAULT_RULES_DIR,
        help="directory of rule files (default: {})".format(DEFAULT_RULES_DIR),
    )
    parser.add_argument("--no-plugins", action="store_true",
                        help="skip the plugin rules in {}".format(DEFAULT_PLUGINS_DIR))
    parser.add_argument("--no-correlate", action="store_true",
                        help="store the alerts but do not group them into incidents")
    parser.set_defaults(func=run)
    return parser


def _fail(args, message, errors):
    """Detection could not run. Exit 1."""
    if args.json:
        print(json.dumps({"error": message, "rule_errors": error_dicts(errors)}, indent=2))
    else:
        print_error(message)
        print_errors(errors)
    return 1


def run(args):
    """Detect over the window and store the alerts. Returns a process exit code.

    Exit codes: 0 clean, including a window with no events or no matches; 1
    nothing could run (no rules loaded, or --rule names none of them); 3 the
    pass was incomplete: a rule file or plugin was rejected, a rule or plugin
    failed while matching, or grouping the alerts into incidents failed (the
    alerts are stored; running detect again retries the grouping). 2 (a bad --since or --until, or an --until before --since) comes from dispatch.
    """
    since = parse_since(args.since)
    until = None if args.until is None else parse_since(args.until)
    if until is not None and until < since:
        # An inverted window reads nothing, which would look like a quiet run.
        raise ValueError("--until {} is earlier than --since {}: the window is empty".format(
            until.isoformat(sep=" ", timespec="seconds"),
            since.isoformat(sep=" ", timespec="seconds")))

    rules, errors = load_rules(args.rules_dir)
    if not rules:
        return _fail(args, "No rules loaded from {}".format(args.rules_dir), errors)
    plugins = []
    # A missing default directory is "no plugins here" (run from another
    # directory, say), not a failure that would make every run exit 3.
    if not args.no_plugins and DEFAULT_PLUGINS_DIR.is_dir():
        plugins, plugin_errors = load_plugins(DEFAULT_PLUGINS_DIR)
        errors = errors + plugin_errors
    if args.rule is not None:
        rules = [r for r in rules if r.id == args.rule]
        plugins = [p for p in plugins if p.id == args.rule]
        if not rules and not plugins:
            message = "No rule with id {!r} in {}".format(args.rule, args.rules_dir)
            if errors:
                message += ". {} file(s) failed to load and one may be it".format(len(errors))
            return _fail(args, message, errors)

    conn = store.connect(args.db)
    try:
        store.init_schema(conn)
        # limit=None: with order="asc" the default 1000 keeps the OLDEST 1000
        # events and drops the newest without a word. order="asc":
        # threshold windows are measured against the newest timestamp seen.
        # ponytail: the whole window is held in memory. Fine for a day of one
        # host's Security channel; stream query_events in timestamp chunks if
        # a window ever stops fitting.
        events = store.query_events(conn, since=since, until=until,
                                    limit=None, order="asc")
        alerts, failures = run_rules(events, rules, plugins)
        # Insert before correlating, and keep the count: correlate stores
        # what it is given too, so correlating first would report 0 new.
        new = store.insert_alerts(conn, alerts)
        incidents, correlation_error = None, None
        if not args.no_correlate:
            try:
                # Every alert of the run, not just the new ones: correlate skips
                # those already grouped and attaches any left ungrouped by a run
                # that died between the two steps.
                incidents = correlate(conn, alerts)
            except Exception as exc:  # the alerts are stored; do not lose the report
                correlation_error = "{}: {}".format(type(exc).__name__, exc)
    finally:
        conn.close()

    duplicate = len(alerts) - new
    # Text goes to stderr under --json so stdout stays JSON-only.
    with redirect_stdout(sys.stderr if args.json else sys.stdout):
        print_section("Detection ({} rule(s))".format(len(rules) + len(plugins)))
        print_info("Events read      : {}".format(len(events)))
        print_info("Alerts new       : {}".format(new))
        print_info("Alerts duplicate : {}".format(duplicate))
        for error in errors:
            print_warn(str(error))
        for rule_id, message in failures:
            print_warn("Rule {} failed while matching: {}".format(rule_id, message))
        if args.no_correlate:
            print_info("Incidents        : skipped (--no-correlate)")
        elif incidents is not None:
            print_info("Incidents opened : {}".format(incidents["opened"]))
            # Not "incidents attached": it counts alerts, and only those that
            # joined an incident someone else had already opened.
            print_info("Alerts attached  : {}".format(incidents["attached"]))
            print_info("  (alerts that joined an incident already open;")
            print_info("  the alert that opens an incident is not counted)")
        else:
            print_error("Correlation failed: {}. The alerts are stored; run detect "
                        "again to group them.".format(correlation_error))

    if args.json:
        print(json.dumps({
            "events_read": len(events), "rules": len(rules) + len(plugins),
            "alerts_new": new, "alerts_duplicate": duplicate,
            # null when correlation did not run or failed: 0 would claim it ran
            # and found nothing to group. incidents_attached counts alerts that
            # joined an already-open incident, excluding the one that opens it.
            "incidents_opened": (incidents or {}).get("opened"),
            "incidents_attached": (incidents or {}).get("attached"),
            "correlation_error": correlation_error,
            "rule_errors": error_dicts(errors),
            "rule_failures": [{"rule_id": r, "message": m} for r, m in failures],
        }, indent=2))
    # Something ran here, so a rejected file or a failed rule or plugin is a 3.
    return 3 if failures or errors or correlation_error else 0

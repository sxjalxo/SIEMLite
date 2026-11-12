#!/usr/bin/env python3
"""
siem rules
==========
List, show and validate the YAML detection rules. Needs no database.
"""

import json

import yaml

from cli.rulepack import (DEFAULT_RULES_DIR, error_dicts, exit_code,
                          print_errors)
from core.report import print_error, print_info, print_ok, print_section
from core.rule_engine.loader import load_rules

NAME = "rules"


def add_parser(subparsers):
    """Register the `rules` subcommand."""
    parser = subparsers.add_parser(NAME, help="inspect the detection rule pack")
    parser.add_argument(
        "action", choices=["list", "show", "validate"], help="what to do"
    )
    parser.add_argument(
        "rule_id", nargs="?", default=None, help="rule to show (show only)"
    )
    # Not a store filter, so a real default is correct here. Store filters
    # (see cli/__init__.py) must default to None.
    parser.add_argument(
        "--rules-dir", default=DEFAULT_RULES_DIR,
        help="directory of rule files (default: {})".format(DEFAULT_RULES_DIR),
    )
    parser.set_defaults(func=run)
    return parser


def run(args):
    """Execute the chosen rules action. Returns a process exit code.

    Exit codes: 0 clean; 1 nothing loaded (an empty or missing pack is a broken
    install, not a clean run) or, for show, an unknown id; 3 (list and validate)
    some rules loaded and some files were rejected.
    """
    if args.action == "show" and not args.rule_id:
        raise ValueError("rules show needs a rule id, e.g. rules show win-bruteforce-4625")
    if args.action != "show" and args.rule_id:
        # `rules validate <dir>` would otherwise validate the default pack and
        # report it healthy, whatever the user pointed at.
        raise ValueError("rules {} takes no rule id (got {!r}); pick a pack with "
                         "--rules-dir".format(args.action, args.rule_id))

    rules, errors = load_rules(args.rules_dir)
    if args.action == "list":
        return _list(args, rules, errors)
    if args.action == "show":
        return _show(args, rules, errors)
    return _validate(args, rules, errors)


def _duration(delta):
    """timedelta(minutes=5) -> '5m': the largest unit that divides it evenly.

    24h gives '1d' and 120m gives '2h'; both parse back to the same timedelta.
    """
    seconds = int(delta.total_seconds())
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds % size == 0:
            return "{}{}".format(seconds // size, unit)
    return "{}s".format(seconds)


def _summary(rule):
    return {
        "id": rule.id, "title": rule.title, "severity": rule.severity,
        "status": rule.status, "technique": rule.technique, "tactic": rule.tactic,
        "source_file": rule.source_file,
    }


def _detail(rule):
    detail = _summary(rule)
    detail.update(
        logsource=rule.logsource, selections=rule.selections,
        condition=rule.condition_text,
        timeframe=_duration(rule.timeframe) if rule.timeframe else None,
        count_gte=rule.count_gte, group_by=list(rule.group_by),
        fields=list(rule.fields), description=rule.description,
        falsepositives=list(rule.falsepositives),
    )
    return detail


def _list(args, rules, errors):
    if args.json:
        print(json.dumps({
            "count": len(rules), "rules": [_summary(r) for r in rules],
            "errors": error_dicts(errors),
        }, indent=2, default=str))
        return exit_code(rules, errors)

    if not rules:
        print_error("No rules loaded from {}".format(args.rules_dir))
    else:
        print_section("Rules ({})".format(len(rules)))
        width = max(len(r.id) for r in rules)
        for rule in rules:
            print_info("{:<{}}  {:<8}  {}".format(rule.id, width, rule.severity, rule.title))
    # A rejected file is shown here too: a list that hid it would look healthy.
    print_errors(errors)
    return exit_code(rules, errors)


def _fail(args, message, errors):
    """show could not produce a rule. Exit 1."""
    if args.json:
        print(json.dumps({"error": message, "errors": error_dicts(errors)}, indent=2))
    else:
        print_error(message)
        print_errors(errors)
    return 1


def _show(args, rules, errors):
    if not rules:
        return _fail(args, "No rules loaded from {}".format(args.rules_dir), errors)
    rule = next((r for r in rules if r.id == args.rule_id), None)
    if rule is None:
        message = "No rule with id {!r} in {}".format(args.rule_id, args.rules_dir)
        if errors:
            message += ". {} file(s) failed to load and one may be it".format(len(errors))
        return _fail(args, message, errors)

    detail = _detail(rule)
    if args.json:
        print(json.dumps(detail, indent=2, default=str))
        return 0

    print_section(rule.id)
    print_info("Title        : {}".format(rule.title))
    print_info("Severity     : {}".format(rule.severity))
    print_info("Status       : {}".format(rule.status or "-"))
    print_info("MITRE        : {} / {}".format(rule.technique or "-", rule.tactic or "-"))
    print_info("Source file  : {}".format(rule.source_file))
    if rule.logsource:
        print_info("Log source   : {}".format(
            ", ".join("{}={}".format(k, v) for k, v in rule.logsource.items())))
    print_section("Detection")
    for line in yaml.safe_dump(rule.selections, sort_keys=False).splitlines():
        print_info(line)
    print_info("Condition    : {}".format(detail["condition"]))
    if rule.count_gte:
        print_info("Threshold    : at least {} in {}, per {}".format(
            rule.count_gte, detail["timeframe"],
            ", ".join(rule.group_by) or "all matching events"))
    print_info("Alert fields : {}".format(", ".join(rule.fields) or "-"))
    if rule.description:
        print_info("Description  : {}".format(rule.description))
    for note in rule.falsepositives:
        print_info("False positive: {}".format(note))
    return 0


def _validate(args, rules, errors):
    if args.json:
        print(json.dumps(
            {"loaded": len(rules), "errors": error_dicts(errors)}, indent=2
        ))
    else:
        if rules:
            print_ok("Loaded {} rule(s) from {}".format(len(rules), args.rules_dir))
        print_errors(errors)
        if not rules:
            print_error("No rules loaded from {}".format(args.rules_dir))
    return exit_code(rules, errors)

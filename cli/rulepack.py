#!/usr/bin/env python3
"""
Rule-pack helpers for the verbs that load the YAML pack: where the pack lives
(`rules` and `detect`), how a load's rejected files are reported (`rules` and
`detect`), and how a load maps to an exit code (`rules` only, today).
"""

from pathlib import Path

from core.report import print_error

DEFAULT_RULES_DIR = Path("rules/windows")


def exit_code(rules, errors):
    """0 clean, 1 nothing loaded, 3 partial. Used by list and validate.

    3 is "something asked for was not evaluated": a half-loaded pack must not
    exit 0, so a rejected file (or a duplicate id, which is also an error) is
    a 3 whichever verb noticed it.
    """
    if not rules:
        return 1
    return 3 if errors else 0


def error_dicts(errors):
    return [{"path": e.path, "key": e.key, "message": str(e)} for e in errors]


def print_errors(errors):
    # Each RuleError already names the file and the key.
    for error in errors:
        print_error(str(error))

#!/usr/bin/env python3
"""
siem respond
============
What to do about an incident, and -- only when asked, one action at a time --
doing it.

The safety model is the feature (spec 11.2), so it is worth stating in full:

* `respond --incident N` **prints**. Nothing executes, nothing is logged.
* `--execute` runs the non-`manual` actions **one at a time**. Each one prompts
  with the exact rendered argument list and runs only on an explicit `y`;
  anything else -- including `"Y"`, `"yes"`, a blank line, and end of input --
  skips that action. **There is no "yes to all"**: the prompt count always
  equals the number of runnable actions, because an operator who can authorise
  everything with one keystroke has not read anything.
* Actions marked `manual: true` are never executable. They print `guidance`.
* Every execution writes to `response_actions`: the rendered command, its undo,
  the exit code, the time and the operator. A *skipped* action is not logged,
  and neither is a command that could not be started -- that table is the
  record of what this tool changed on this host.
* `--undo <action-id>` runs the stored undo command under the same single
  confirmation.

`core/response.py` is the trust boundary and is not duplicated here: this
module calls `render()` for both the command and its undo, and an action whose
placeholder fails validation is printed as SKIPPED **by name** while the run
carries on to the next one. Commands reach `subprocess.run` as argument lists
with `shell=False`, so no value can add an argument however hostile it is.

`--json` goes with `--incident` alone: a script reading stdout cannot answer a
per-action confirmation, so refusing the combination is what makes "JSON never
executes" structural rather than a property of this file.
"""

import getpass
import json
import subprocess
import textwrap
from datetime import datetime

from cli.render import fail, incident_dict, no_incident, plain, tactic_ids
from cli.rulepack import error_dicts, print_errors
from core import store
from core.report import (print_error, print_info, print_ok, print_section,
                         print_warn)
from core.response import (DEFAULT_PLAYBOOKS_DIR, PlaybookError, load_playbooks,
                           match_playbooks, placeholder_values, render)
from core.timeutil import to_local_naive
from modules.mitre_mapping import tactic_name

NAME = "respond"

# Commands, guidance and undo lines are printed under the action they belong
# to, undecorated: a command an operator may be about to run should not be
# dressed up as one more "[~]" information line.
INDENT = "      "

# Wrapped because a playbook's guidance is a folded YAML paragraph of a couple
# of hundred characters, and this is the text an operator reads under pressure.
GUIDANCE_WIDTH = 72

_INSERT = ("INSERT INTO response_actions (incident_id, playbook_id, action_name, "
           "command, undo_command, executed_at, exit_code, operator) "
           "VALUES (?, ?, ?, ?, ?, ?, ?, ?)")


def add_parser(subparsers):
    """Register the `respond` subcommand."""
    parser = subparsers.add_parser(
        NAME, help="matched playbooks for an incident; --execute to run one action at a time")
    # Store filters (see cli/__init__.py): None, never 0 or "".
    parser.add_argument("--incident", type=int, default=None,
                        help="the incident to respond to")
    parser.add_argument("--execute", action="store_true",
                        help="offer each non-manual action in turn; each needs an explicit y")
    parser.add_argument("--undo", type=int, default=None,
                        help="run the stored undo command of this logged action id")
    parser.add_argument(
        "--playbooks-dir", default=DEFAULT_PLAYBOOKS_DIR,
        help="directory of playbook files (default: {})".format(DEFAULT_PLAYBOOKS_DIR))
    parser.set_defaults(func=run)
    return parser


def _operator():
    """Who to record in `response_actions.operator`.

    `getpass.getuser()` raises when the host cannot name a user: there is no
    LOGNAME/USER/LNAME/USERNAME in the environment and no `pwd` entry for the
    uid (a bare container, a service account, a stripped Windows session).
    Spec 13 says never crash with a traceback, and losing the whole execution
    record over the operator's name would be worse than recording "unknown".
    Python 3.13+ raises OSError; older versions raise ImportError or KeyError
    from the `pwd` lookup, so all three are caught.
    """
    try:
        return getpass.getuser()
    except (OSError, ImportError, KeyError):
        return "unknown"


def command_text(argv):
    """A rendered argument list as one printable line.

    Through `plain()` because a playbook's own literal argument is text this
    tool prints and an ESC in it would drive the terminal (R30, R94) -- the
    placeholder values were already validated by `core/response.py`, the
    surrounding literals never were. Joined with a space because that is what
    an operator reads; nothing here is ever handed to a shell to split again.
    """
    return plain(" ".join(argv))


def plan(playbooks, incident, alerts):
    """`playbooks` as printable/serialisable rows, with every command rendered.

    One row per playbook, each with its actions numbered from 1. An action
    carries either a `command` (plus `undo`, when it has one), or a `guidance`
    when it is manual, or an `error` naming why it cannot be rendered -- never
    a half-rendered command. Rendering happens here, once, so the text that is
    printed is the same text a confirmation offers and the same list that runs.
    """
    values = placeholder_values(incident, alerts)
    rows = []
    for book in playbooks:
        actions = [_plan_action(action, values, number)
                   for number, action in enumerate(book.actions, 1)]
        rows.append({"id": book.id, "title": book.title, "tactic": book.tactic,
                     "min_severity": book.min_severity,
                     "source_file": book.source_file, "actions": actions})
    return rows


def _plan_action(action, values, number):
    row = {"number": number, "name": action.name, "risk": action.risk,
           "manual": action.manual, "guidance": action.guidance,
           "command": None, "undo": None, "error": None}
    if action.manual:
        return row
    try:
        # Both through render(): an undo that cannot be rendered means the
        # action could not be reversed from the record, so it is not offered.
        command = render(action, values)
        undo = render(action, values, undo=True) if action.undo else None
    except PlaybookError as exc:
        row["error"] = str(exc)
        return row
    row["command"], row["undo"] = command, undo
    return row


def _print_plan(matched):
    for book in matched:
        print_section("{} - {}".format(plain(book["id"]), plain(book["title"])))
        for action in book["actions"]:
            head = "{}. {} ({})".format(
                action["number"], plain(action["name"]),
                "manual" if action["manual"] else "risk: {}".format(plain(action["risk"])))
            if action["error"]:
                print_warn(head + " -- SKIPPED")
                print_warn("    " + plain(action["error"]))
            else:
                print_info(head)
            if action["manual"]:
                print(textwrap.fill(plain(action["guidance"]), width=GUIDANCE_WIDTH,
                                    initial_indent=INDENT, subsequent_indent=INDENT))
            elif action["command"]:
                print(INDENT + command_text(action["command"]))
                if action["undo"]:
                    print(INDENT + "undo: " + command_text(action["undo"]))


def confirm(prompt):
    """True only for exactly `"y"`.

    No `.strip()` and no `.lower()`: stripping would turn `"Y "` into a yes,
    and spec 11.2 says anything other than an explicit `y` skips. End of input
    is not consent either, so EOFError is a skip. There is deliberately no
    answer here that means "and all the rest".
    """
    try:
        return input(prompt) == "y"
    except EOFError:
        return False


def _prompt(label, risk, argv):
    return "\n".join([
        "",
        "  [!] RUN {}{}".format(plain(label),
                                "" if risk is None else " (risk: {})".format(plain(risk))),
        INDENT + command_text(argv),
        "  Type y to run it; anything else skips. There is no yes-to-all: ",
    ])


def _log(conn, incident_id, playbook_id, name, argv, undo, code, operator):
    """Write one executed action to `response_actions`; return its row id.

    The command and its undo are stored as JSON argument lists, never as a
    shell string, so `--undo` reads back exactly the list that was validated
    and nothing is re-parsed or re-rendered later.
    """
    with conn:
        return conn.execute(_INSERT, (
            incident_id, playbook_id, name, json.dumps(list(argv)),
            None if not undo else json.dumps(list(undo)),
            # Second resolution, like every other timestamp the store holds:
            # datetime.now() carries microseconds and nothing else does.
            to_local_naive(datetime.now()).isoformat(sep=" ", timespec="seconds"),
            code, operator,
        )).lastrowid


def _run_and_log(conn, incident_id, playbook_id, name, argv, undo):
    """Run one argument list, log it, report it. True when it did not succeed.

    `shell=False` is passed explicitly rather than left to the default: it is
    the property the whole module rests on, so it is written where a reader
    looks for it. A command that could not be started is reported and NOT
    logged -- a process that never began changed nothing on this host.
    """
    try:
        result = subprocess.run(list(argv), shell=False)
    except OSError as exc:
        print_error("{} could not be started: {}".format(plain(name), plain(exc)))
        return True
    action_id = _log(conn, incident_id, playbook_id, name, argv, undo,
                     result.returncode, _operator())
    message = "{} finished with exit {}, logged as action {}".format(
        plain(name), result.returncode, action_id)
    if result.returncode:
        print_warn(message)
        return True
    print_ok(message)
    return False


def _execute(conn, incident_id, matched):
    """Offer every runnable action in turn. True when one of them failed.

    Manual actions and actions that could not be rendered are never offered,
    so the number of prompts is the number of commands that could run.
    KeyboardInterrupt stops the run rather than tracebacking out of it
    (spec 13): Ctrl-C at a confirmation is a refusal, not a crash.
    """
    failed = False
    for book in matched:
        for action in book["actions"]:
            if action["manual"] or not action["command"]:
                continue
            try:
                agreed = confirm(_prompt("action {} of {}".format(
                    action["number"], book["id"]), action["risk"], action["command"]))
            except KeyboardInterrupt:
                print()
                print_info("Stopped at your request; nothing further has run.")
                return failed
            if not agreed:
                print_info("Skipped: {}".format(plain(action["name"])))
                continue
            failed = _run_and_log(conn, incident_id, book["id"], action["name"],
                                  action["command"], action["undo"]) or failed
    return failed


def stored_argv(value):
    """A stored command column as an argument list, or None.

    This tool wrote the column, but SQLite hands back whatever is in the row
    whatever the declared type (R96) and a row can be hand-edited, so it is
    re-checked before it reaches `subprocess`: a non-empty list of non-empty
    strings, nothing else. `shell=False` means a bad value can at worst name a
    different program, which is still not something to run on a stored string.
    """
    try:
        argv = json.loads(value)
    except (ValueError, TypeError):
        return None
    if not isinstance(argv, list) or not argv:
        return None
    if not all(isinstance(element, str) and element for element in argv):
        return None
    return argv


def _undo(conn, args):
    """Run a logged action's stored undo command under one confirmation."""
    row = conn.execute("SELECT * FROM response_actions WHERE id = ?",
                       (args.undo,)).fetchone()
    if row is None:
        return fail(args, "No logged response action with id {}".format(args.undo))
    if row["undo_command"] is None:
        # Includes the undo rows this verb writes itself, so an undo cannot be
        # undone into an endless pair of commands.
        return fail(args, "Action {} ({}) was logged without an undo command".format(
            args.undo, plain(row["action_name"])))
    argv = stored_argv(row["undo_command"])
    if argv is None:
        return fail(args, "Action {}'s undo_command is not a stored argument list: "
                          "{}".format(args.undo, plain(repr(row["undo_command"]))))

    print_section("Undo action {}".format(args.undo))
    print_info("Incident : {}".format(plain(row["incident_id"])))
    print_info("Playbook : {}".format(plain(row["playbook_id"])))
    print_info("Action   : {}".format(plain(row["action_name"])))
    print_info("Ran      : {} by {}, exit {}".format(
        plain(row["executed_at"]), plain(row["operator"]), plain(row["exit_code"])))
    try:
        agreed = confirm(_prompt("the undo of action {}".format(args.undo), None, argv))
    except KeyboardInterrupt:
        print()
        print_info("Stopped at your request; nothing has run.")
        return 0
    if not agreed:
        print_info("Skipped: nothing has run.")
        return 0
    failed = _run_and_log(conn, row["incident_id"], row["playbook_id"],
                          "undo: " + row["action_name"], argv, None)
    return 3 if failed else 0


def _fail(args, message, errors):
    """Nothing could be matched, let alone run. Exit 1."""
    if args.json:
        print(json.dumps({"error": message,
                          "playbook_errors": error_dicts(errors)}, indent=2))
    else:
        print_error(message)
        print_errors(errors)
    return 1


def _respond(conn, args):
    playbooks, errors = load_playbooks(args.playbooks_dir)
    if not playbooks:
        return _fail(args, "No playbooks loaded from {}".format(args.playbooks_dir),
                     errors)
    found = store.query_incidents(conn, incident_id=args.incident)
    if not found:
        return no_incident(args, args.incident)
    incident = found[0]
    alerts = store.query_alerts(conn, incident_id=incident["id"], limit=None)
    matched = plan(match_playbooks(playbooks, incident, alerts), incident, alerts)
    skipped = sum(1 for b in matched for a in b["actions"] if a["error"])

    if args.json:
        print(json.dumps({
            "incident": incident_dict(incident), "playbooks": matched,
            # Always empty: --json refuses --execute and --undo, so this verb
            # cannot run anything in JSON mode. The key is here so a consumer's
            # shape does not change between modes.
            "executed": [], "actions_skipped": skipped,
            "playbook_errors": error_dicts(errors),
        }, indent=2, default=str))
        return 3 if errors or skipped else 0

    print_section("Response for incident {}".format(incident["id"]))
    print_info("Entity    : {} {}".format(plain(incident["entity_type"]),
                                          plain(incident["entity_value"])))
    print_info("Severity  : {}".format(plain(incident["severity"])))
    print_info("Tactics   : {}".format(", ".join(
        plain(tactic_name(t)) for t in tactic_ids(incident)) or "-"))
    print_info("Playbooks : {} matched".format(len(matched)))
    print_errors(errors)
    if not matched:
        print_info("0 playbooks match: none covers this incident's tactics with a "
                   "min_severity of {} or lower.".format(plain(incident["severity"])))
    _print_plan(matched)

    failed = False
    if args.execute:
        failed = _execute(conn, incident["id"], matched)
    elif any(a["command"] for b in matched for a in b["actions"]):
        print()
        print_info("Nothing has run. Add --execute to be asked about each action "
                   "in turn; there is no yes-to-all.")
    # 3 is "something asked for was not evaluated" (R51): a rejected playbook
    # file, an action whose value failed the trust boundary, or a command that
    # ran and failed. An action the operator declined is their choice, not a
    # partial run, and stays 0.
    return 3 if errors or skipped or failed else 0


def run(args):
    """Print or run the response plan. Returns a process exit code: 0 clean;
    1 the incident, the playbook pack or the logged action could not be found;
    3 partial -- a playbook file was rejected, an action was skipped by the
    trust boundary, or a command that ran did not succeed. 2 (a bad flag
    combination) comes from dispatch."""
    if (args.incident is None) == (args.undo is None):
        raise ValueError("give exactly one of --incident, --undo")
    if args.undo is not None and args.execute:
        raise ValueError("--execute goes with --incident only: --undo always asks "
                         "for confirmation before it runs")
    if args.json and (args.execute or args.undo is not None):
        raise ValueError("--json goes with --incident alone: a script reading "
                         "stdout cannot answer a per-action confirmation")

    conn = store.connect(args.db)
    try:
        store.init_schema(conn)
        if args.undo is not None:
            return _undo(conn, args)
        return _respond(conn, args)
    finally:
        conn.close()

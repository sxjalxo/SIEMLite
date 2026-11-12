#!/usr/bin/env python3
"""
Response playbooks and the trust boundary
=========================================
A playbook file says what to do about an incident; this module decides what may
reach a command line. It loads, matches, validates and renders. It never runs
anything -- `cli/commands/respond.py` does that, under a per-action
confirmation.

Everything a placeholder can be filled with came from a log: an attacker chose
the username in a failed logon and the source IP of the connection. So the
rules here are deliberately narrow and fail closed:

* A command is an **argument list**, never a string. A string would have to be
  split by a shell, and nothing here runs a shell (`subprocess.run(...,
  shell=False)`). A string `command:` is rejected at load time.
* Only the placeholders in `PLACEHOLDER_KINDS` exist. One that is not in that
  map has no validator, so it aborts the action rather than rendering as its
  own literal text.
* Every value is validated before it is substituted, and what is substituted
  is the validator's **return** -- for an IP, the canonical form rebuilt from
  the parsed address object, so nothing reaches an argument list that was not
  reconstructed from a parsed value (ruling R113).
* A value that fails, is missing, or is one of several, aborts that one action
  with a named error. The caller prints the name and carries on to the next
  action: that is spec 11.2's behaviour for a failing value, and it is why
  `DOMAIN\\bob` being refused costs one action rather than a whole run
  (ruling R106).
* `"-"` is the project's **not-recorded** sentinel, so it is collected as no
  value at all rather than validated as a username -- spec 11.2's pattern
  admits a bare hyphen, and an action rendered against it would be a
  wrong-target action offered as a right one (ruling R150).

The placeholder map is exactly: the incident's `entity_type` -> its
`entity_value`, plus every field name found in the member alerts' `evidence`
JSON. Nothing else. `guidance` is never rendered -- it is prose for an
operator, not a command.
"""

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from core.rule_engine.loader import SEVERITIES, duplicate_key

DEFAULT_PLAYBOOKS_DIR = Path("rules/playbooks")

# What an action's `risk:` may say. Ordered low to high for display.
RISKS = ("low", "medium", "high")

# Placeholder name -> the validator that decides what may reach a command line.
# This is the whole surface: a name that is not a key here cannot be rendered.
# It is spelled out rather than derived from the engine's ENTITY_TYPES, so
# adding an event field to the engine cannot quietly widen this boundary.
PLACEHOLDER_KINDS = {
    "ip": "ip", "source_ip": "ip", "dest_ip": "ip",
    "user": "user", "target_user": "user", "host": "host",
}

_PLAYBOOK_KEYS = ("id", "title", "match", "actions")
_MATCH_KEYS = ("tactic", "min_severity")
_ACTION_KEYS = ("name", "command", "undo", "risk", "manual", "guidance")

_PLACEHOLDER = re.compile(r"\{([^{}]*)\}")

# Spec 11.2: ^[A-Za-z0-9._\-$]{1,64}$. Matched with fullmatch and written
# without anchors, because `$` in a re.match would accept a trailing newline.
_USER = re.compile(r"[A-Za-z0-9._\-$]{1,64}")

# Ruling R112: a DNS name, not a single label -- labels joined by ".", each
# 1-63 of [A-Za-z0-9-] and neither starting nor ending with "-". That accepts
# web01.corp.example and still rejects "PC 01", "-/-" and "a" * 64.
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOST = re.compile(_LABEL + r"(?:\." + _LABEL + r")*")
_HOST_MAX = 253

_SHOW = 70


class PlaybookError(ValueError):
    """A playbook that cannot be loaded, or an action that cannot be rendered.

    `path` is the file at load time and the action name at render time; `key`
    is the YAML key or the placeholder. str() names both, so `cli/rulepack.py`
    prints and serialises these exactly as it does a RuleError.
    """

    def __init__(self, path, key, message):
        self.path, self.key = path, key
        super().__init__("{}: {}{}".format(path, key + ": " if key else "", message))


@dataclass(frozen=True)
class Action:
    """One step of a playbook. Either `command` is set or `manual` is true,
    never both: a manual action has guidance and is never executable."""
    name: str
    command: tuple
    undo: tuple
    risk: str
    manual: bool
    guidance: str


@dataclass(frozen=True)
class Playbook:
    id: str
    title: str
    tactic: str
    min_severity: str
    actions: tuple
    source_file: str


def _show(value):
    """`value` as a safe, bounded fragment of an error message.

    repr() escapes every non-printable character, so a newline in a log field
    cannot forge a line of error output and an ESC cannot drive the terminal --
    cli/render.plain's job, done without core importing cli. Bounded because
    an evidence field has no length limit.
    """
    text = repr(value)
    return text if len(text) <= _SHOW else text[:_SHOW - 3] + "..."


def validate_value(kind, value):
    """The validated text for `value` as a `kind`, or raise ValueError.

    Requires a `str`: `ipaddress.ip_address(5)` is 0.0.0.5 and
    `ip_address(True)` is 0.0.0.1, so an integer would validate cleanly and
    render a *different* address. `evidence` is JSON, which has real integers,
    and SQLite returns whatever type was written whatever the column says
    (rulings R113, R96). There is no final `return value`: a kind with no
    validator is an error, never a pass.
    """
    if not isinstance(value, str):
        raise ValueError("{} value must be text, got {} {}".format(
            kind, type(value).__name__, _show(value)))
    if kind == "ip":
        try:
            # The canonical form of the parsed object, not the input text.
            return str(ipaddress.ip_address(value))
        except ValueError:
            raise ValueError("ip value {} is not an IP address".format(_show(value)))
    if kind == "user":
        if not _USER.fullmatch(value):
            raise ValueError("user value {} is not 1 to 64 of letters, digits, "
                             "dot, underscore, hyphen or $".format(_show(value)))
        return value
    if kind == "host":
        if len(value) > _HOST_MAX or not _HOST.fullmatch(value):
            raise ValueError("host value {} is not a DNS name of up to {} "
                             "characters".format(_show(value), _HOST_MAX))
        return value
    raise ValueError("no validator for placeholder kind {}".format(_show(kind)))


def _evidence(row):
    """An alert's evidence as the list of dicts the engine writes. A
    hand-edited column that is not that is no evidence."""
    try:
        entries = json.loads(row["evidence"])
    except (ValueError, TypeError):
        return []
    if not isinstance(entries, list):
        return []
    return [e for e in entries if isinstance(e, dict)]


def _collect(values, name, value):
    if not isinstance(name, str):
        return
    # Ruling R150: "-" is this project's not-recorded sentinel -- R90 falls
    # back from it when choosing an entity, render.event_fields leaves it out
    # of the FIELDS column, and the pivot excludes it as a node. Spec 11.2's
    # username pattern admits a bare hyphen, so without this `net user -
    # /active:no` renders and is OFFERED: a wrong-target action presented as a
    # right one. Filtered HERE and not in validate_value because "-" is an
    # absent value, not an invalid username -- the placeholder is then simply
    # one with no value, which _rendered already aborts by name with the
    # honest message, and one filter covers every placeholder kind. The
    # pattern itself stays exactly as the spec writes it. Only the bare
    # sentinel (and a blank, if one gets this far) is absent: "--" and "-x-"
    # are real text and still collect.
    if isinstance(value, str) and (value == "-" or not value.strip()):
        return
    seen = values.setdefault(name, [])
    if value not in seen:
        seen.append(value)


def placeholder_values(incident, alerts):
    """{placeholder name: [distinct values, first seen first]}.

    The map is the incident's `entity_type` -> `entity_value`, plus every field
    name in the member alerts' `evidence` JSON. Values are returned exactly as
    stored, including the wrong types: `validate_value` is the only place that
    decides what is acceptable. The one exception is the `"-"` not-recorded
    sentinel, which is ABSENT rather than invalid and so is never collected --
    a placeholder left with no value aborts its action by name (ruling R150).
    """
    values = {}
    _collect(values, incident["entity_type"], incident["entity_value"])
    for row in alerts:
        for entry in _evidence(row):
            for name, value in entry.items():
                _collect(values, name, value)
    return values


def match_playbooks(playbooks, incident, alerts):
    """The playbooks whose tactic the incident covers at or above its severity.

    `min_severity` is a floor, not an equality. The tactics come from the
    member alert rows' `mitre_tactic_id` column, which is where the correlator
    derives `incidents.tactics` from too -- a column rather than a JSON blob a
    hand edit can quietly empty. An incident severity that is not one of
    SEVERITIES matches nothing: a hand-edited row must not become its own
    floor. No match is an empty list, not an error.
    """
    tactics = {row["mitre_tactic_id"] for row in alerts if row["mitre_tactic_id"]}
    try:
        level = SEVERITIES.index(incident["severity"])
    except ValueError:
        return []
    return [p for p in playbooks
            if p.tactic in tactics and level >= SEVERITIES.index(p.min_severity)]


def _rendered(name, values, fail):
    kind = PLACEHOLDER_KINDS.get(name)
    if kind is None:
        raise fail(name, "is not a placeholder this tool can fill, so it cannot "
                         "be validated (known: {})".format(
                             ", ".join(sorted(PLACEHOLDER_KINDS))))
    candidates = values.get(name)
    if not candidates:
        raise fail(name, "has no value in this incident")
    if not isinstance(candidates, (list, tuple)):
        raise fail(name, "must be a list of candidate values, got {}".format(
            _show(candidates)))
    if len(candidates) > 1:
        # Ruling R114: an incident can hold alerts from two source IPs and
        # nothing says which to act on. Acting on the wrong one is the worst
        # outcome this verb has, so neither is chosen.
        raise fail(name, "is ambiguous: this incident has {} values ({})".format(
            len(candidates), ", ".join(_show(c) for c in candidates)))
    try:
        return validate_value(kind, candidates[0])
    except ValueError as exc:
        raise fail(name, str(exc))


def render(action, values, undo=False):
    """`action`'s command (or its undo) as a list of arguments, or raise.

    One element in, one element out: a value is substituted inside its element
    and the list is never joined, so an argument that legitimately contains a
    space stays one argument and a hostile value could not add one even if it
    got this far.
    """
    def fail(key, message):
        return PlaybookError(action.name, key, message)

    if action.manual:
        raise fail(None, "is a manual action: it has guidance, not a command")
    rendered = []
    for element in action.undo if undo else action.command:
        text = _PLACEHOLDER.sub(lambda m: _rendered(m.group(1), values, fail), element)
        if "{" in text or "}" in text:
            raise fail(None, "argument {} has an unbalanced brace: a placeholder "
                             "is written {{name}}".format(_show(element)))
        rendered.append(text)
    return rendered


def _text(value, key, fail, required=True):
    if value is None and not required:
        return ""
    if not isinstance(value, str) or not value.strip():
        if value is None:
            raise fail(key, "is required")
        raise fail(key, "must be text, got {}".format(_show(value)))
    return value


def _reject_unknown(mapping, allowed, key, fail):
    for name in mapping:
        if name not in allowed:
            raise fail(key, "unknown key {} (allowed: {})".format(
                _show(name), ", ".join(allowed)))


def _args(value, key, fail, required):
    """A YAML `command:`/`undo:` as a tuple of argument strings.

    A string is the single most dangerous mistake a playbook file can make, so
    it is named as such rather than iterated one character per argument.
    """
    if value is None:
        if required:
            raise fail(key, "is required: the argument list to run, such as "
                            "['net', 'user', '{user}', '/active:no']")
        return ()
    if isinstance(value, str) or not isinstance(value, list) or not value:
        raise fail(key, "must be a non-empty list of text arguments, not {}. A "
                        "string would have to be split by a shell, and this tool "
                        "never runs one: subprocess.run(args, shell=False)".format(
                            _show(value)))
    for element in value:
        if not isinstance(element, str) or not element:
            raise fail(key, "argument {} must be non-empty text".format(_show(element)))
    return tuple(value)


def _action(data, index, fail):
    where = "actions[{}]".format(index)
    if not isinstance(data, dict) or not data:
        raise fail(where, "must be a mapping with a name, a risk and either a "
                          "command or manual: true, got {}".format(_show(data)))
    _reject_unknown(data, _ACTION_KEYS, where, fail)
    name = _text(data.get("name"), where + ".name", fail)
    manual = data.get("manual", False)
    if not isinstance(manual, bool):
        raise fail(where + ".manual", "must be true or false, got {}".format(_show(manual)))
    # Required for anything that can run; optional for a manual action, which
    # never runs and whose risk would be decoration. Spec 11.1's own manual
    # action carries no risk, and that file ships verbatim.
    risk = _text(data.get("risk"), where + ".risk", fail, required=not manual)
    if risk and risk not in RISKS:
        raise fail(where + ".risk", "{} is not one of {}".format(
            _show(risk), ", ".join(RISKS)))
    if manual:
        if "command" in data:
            raise fail(where, "has both a command and manual: true. A manual "
                              "action is never executable -- remove one of them")
        if "undo" in data:
            raise fail(where, "is manual, so its undo could never run: remove it")
        return Action(name=name, command=(), undo=(), risk=risk, manual=True,
                      guidance=" ".join(_text(data.get("guidance"),
                                              where + ".guidance", fail).split()))
    if "guidance" in data:
        raise fail(where, "has guidance but is not manual: true. Guidance is "
                          "printed instead of a command, never beside one")
    return Action(name=name,
                  command=_args(data.get("command"), where + ".command", fail, True),
                  undo=_args(data.get("undo"), where + ".undo", fail, False),
                  risk=risk, manual=False, guidance="")


def load_playbook_file(path):
    """Load and validate one playbook; PlaybookError names the file and key."""
    source = str(path)

    def fail(key, message):
        return PlaybookError(source, key, message)

    try:
        text = Path(path).read_text(encoding="utf-8")
        # Ruling R119: safe_load keeps the LAST of two equal keys, so a file
        # with `actions:` twice would silently drop a whole list of actions
        # and an operator would read a playbook covering less than its author
        # wrote. The same check load_rule_file already makes, through the same
        # function rather than a second copy of it.
        duplicate = duplicate_key(yaml.compose(text, Loader=yaml.SafeLoader))
        # safe_load only: a playbook file is data, and may be shared.
        data = yaml.safe_load(text)
    except (OSError, ValueError, yaml.YAMLError, RecursionError) as exc:
        raise fail(None, "cannot read: {}".format(" ".join(str(exc).split())))
    if duplicate is not None:
        raise fail(duplicate.value, "duplicate key at line {}: the earlier value "
                   "would be silently dropped".format(duplicate.start_mark.line + 1))
    if data is None:
        raise fail(None, "file is empty")
    if not isinstance(data, dict):
        raise fail(None, "must be a mapping of keys to values, got a {}".format(
            type(data).__name__))

    _reject_unknown(data, _PLAYBOOK_KEYS, None, fail)
    match = data.get("match")
    if not isinstance(match, dict) or not match:
        raise fail("match", "is required: a mapping of tactic and min_severity")
    _reject_unknown(match, _MATCH_KEYS, "match", fail)
    min_severity = _text(match.get("min_severity"), "match.min_severity", fail)
    if min_severity not in SEVERITIES:
        raise fail("match.min_severity", "{} is not one of {}".format(
            _show(min_severity), ", ".join(SEVERITIES)))

    actions = data.get("actions")
    if not isinstance(actions, list) or not actions:
        raise fail("actions", "is required: a list of at least one action")
    return Playbook(
        id=_text(data.get("id"), "id", fail),
        title=_text(data.get("title"), "title", fail),
        tactic=_text(match.get("tactic"), "match.tactic", fail),
        min_severity=min_severity,
        actions=tuple(_action(a, i, fail) for i, a in enumerate(actions)),
        source_file=source,
    )


def load_playbooks(directory):
    """Load every .yml/.yaml file in `directory` -> (playbooks, errors).

    The sibling of load_rules, and deliberately the same shape: files load in
    name order, the first of two equal ids wins, and a bad file is an error in
    the list rather than an exception, so one typo cannot hide every playbook.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return [], [PlaybookError(str(directory), None,
                                  "playbook directory does not exist")]
    by_id, errors = {}, []
    for path in sorted(directory.iterdir(), key=lambda p: p.name):
        if path.suffix.lower() not in (".yml", ".yaml"):
            continue
        try:
            playbook = load_playbook_file(path)
        except PlaybookError as exc:
            errors.append(exc)
            continue
        if playbook.id in by_id:
            errors.append(PlaybookError(str(path), "id", "{} is already defined "
                                        "by {}".format(_show(playbook.id),
                                                       by_id[playbook.id].source_file)))
        else:
            by_id[playbook.id] = playbook
    return list(by_id.values()), errors

#!/usr/bin/env python3
"""
Rule Loader
===========
YAML files on disk become validated Rule objects. A rule pack is edited by
hand, so the one thing this module must never do is accept a rule that can
never fire: every rejection names the file and the key.

Validation is load-time on purpose. The matcher raises on a bad field spec too,
but only when a rule runs against an event; here a broken rule never ships.
Each selection is checked by running the matcher itself on a dummy event, so
"valid" cannot drift from "what the matcher accepts". It is run once per
wanted value, because the matcher stops at the first value that matches and
would otherwise never look at a bad one after it.

YAML is read with safe_load: a rule file is data, and may be shared.
"""

import dataclasses
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import yaml

from core.rule_engine.matcher import (
    MODIFIERS, Condition, match_selection, parse_condition, parse_field_spec,
)
from core.timeutil import parse_duration
from ingestion.normalizer import EVENT_FIELDS, NormalizedEvent

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

# The condition tokenizer reads exactly these as operators, and only a name of
# this shape as a selection: any other selection name is unreachable.
_OPERATORS = ("and", "or", "not")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Keys of `detection` that are not selections.
_DETECTION_KEYS = ("timeframe", "count", "condition")

# Each field's declared type. YAML reads 0xC000006D as the int 3221225581 and
# `no` as False, and neither equals the stored text, so a rule value of the
# wrong type on a text field is a rule that loads and never fires (ruling R61).
# The same goes for 4625.0 or `yes` on an int field (ruling R63). A string on an
# int field stays legal: the matcher compares str() of both sides, so '4625'
# matches 4625.
_FIELD_TYPES = {f.name: f.type for f in dataclasses.fields(NormalizedEvent)}

# Keys the loader reads. A misspelt one would otherwise be ignored in silence.
_RULE_KEYS = ("id", "title", "status", "severity", "logsource", "detection", "mitre",
              "fields", "description", "falsepositives")

# Every ValueError the matcher raises for a field spec comes from the spec or
# the value, never the event, so any event will do.
_PROBE = NormalizedEvent(timestamp=datetime(2000, 1, 1), source_type="", host="",
                         channel="", event_id=0, record_id=0)


class RuleError(ValueError):
    """A rule file that cannot be loaded; str() names the file and the key."""

    def __init__(self, path, key, message):
        self.path, self.key = path, key
        super().__init__("{}: {}{}".format(path, key + ": " if key else "", message))


# eq=False keeps identity hashing: `selections` is a dict and `condition` a plain
# object, so a generated __hash__ would fail, and Task 12 puts rules in a set.
@dataclass(frozen=True, eq=False)
class Rule:
    id: str
    title: str
    severity: str
    status: str
    selections: dict
    condition: Condition
    timeframe: Optional[timedelta]
    count_gte: Optional[int]
    group_by: tuple
    fields: tuple
    technique: str
    tactic: str
    logsource: dict
    description: str
    falsepositives: tuple
    source_file: str


def parse_timeframe(text):
    """'5m' -> timedelta(minutes=5). Zero is rejected: that window can never fill."""
    duration = parse_duration(text)
    if duration <= timedelta(0):
        raise ValueError("timeframe {!r} must be longer than zero".format(text))
    return duration


def _text(value, key, fail, required):
    if value is None:
        if required:
            raise fail(key, "is required")
        return ""
    if not isinstance(value, str) or not value.strip():
        raise fail(key, "must be text, got {!r}".format(value))
    return value


def _mapping(value, key, fail):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise fail(key, "must be a mapping, got {!r}".format(value))
    return value


def _texts(value, key, fail):
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise fail(key, "must be a list of text, got {!r}".format(value))
    return tuple(value)


def _field_names(value, key, fail):
    names = _texts(value, key, fail)
    for name in names:
        if name not in EVENT_FIELDS:
            raise fail(key, "{!r} is not an event field".format(name))
    return names


def _reject_unknown(mapping, allowed, key, fail):
    for name in mapping:
        if name not in allowed:
            raise fail(key, "unknown key {!r} (allowed: {})".format(
                name, ", ".join(allowed)))


def _duplicate_key(root):
    """The first mapping key that appears twice in a composed YAML tree, or None.

    safe_load keeps the last of two equal keys, so the first would vanish
    silently. Works on the node tree compose() builds, which constructs nothing.
    Iterative with a visited set: an alias shares nodes, and a deeply nested or
    alias-heavy file must not recurse or loop.
    """
    stack, visited = [root], set()
    while stack:
        node = stack.pop()
        if id(node) in visited:
            continue
        visited.add(id(node))
        if isinstance(node, yaml.MappingNode):
            seen = set()
            for key, value in node.value:
                if isinstance(key, yaml.ScalarNode):
                    if (key.tag, key.value) in seen:
                        return key
                    seen.add((key.tag, key.value))
                stack.append(value)
        elif isinstance(node, yaml.SequenceNode):
            stack.extend(node.value)
    return None


def _check_selection(name, selection, fail):
    where = "detection.{}".format(name)
    if not (isinstance(name, str) and _NAME.fullmatch(name)) or name in _OPERATORS:
        raise fail(where, "selection name {!r} must match [A-Za-z_][A-Za-z0-9_]* and "
                          "not be and, or or not, or no condition can name it".format(name))
    if not isinstance(selection, dict) or not selection:
        raise fail(where, "a selection is a mapping of field to value, "
                          "with at least one entry")
    for spec, value in selection.items():
        key = "{}.{}".format(where, spec)
        try:
            field, modifiers = parse_field_spec(spec)
        except ValueError as exc:
            raise fail(where, str(exc))
        unknown = [m for m in modifiers if m not in MODIFIERS]
        if unknown:
            raise fail(key, "unknown modifier {!r} (have: {})".format(
                unknown[0], ", ".join(sorted(MODIFIERS))))
        for want in value if isinstance(value, list) and value else [value]:
            try:
                match_selection(_PROBE, {spec: want})
            except ValueError as exc:
                raise fail(where, str(exc))
            if isinstance(want, (dict, list)):
                raise fail(key, "value must be a single text or number, "
                                "got {!r}".format(want))
            kind, got = _FIELD_TYPES.get(field), type(want).__name__
            if kind is str and not isinstance(want, str):
                raise fail(key, "value {!r} was read as {}, but {} holds text. YAML "
                                "converts unquoted hex (0x1F), yes/no/on/off, decimals "
                                "and dates: quote the value in the file".format(
                                    want, got, field))
            # bool is an int subclass, so it needs its own test.
            if kind is int and not isinstance(want, str) and (
                    isinstance(want, bool) or not isinstance(want, int)):
                raise fail(key, "value {!r} was read as {}, but {} holds a whole "
                                "number: write one, such as 4625".format(
                                    want, got, field))


def _check_condition(text, selections, fail):
    key = "detection.condition"
    if not isinstance(text, str):
        raise fail(key, "is required, e.g. 'sel and not filter'")
    try:
        return parse_condition(text, set(selections))
    except ValueError as exc:
        raise fail(key, str(exc))


def load_rule_file(path):
    """Load and validate one rule file; RuleError names the file and the key."""
    source = str(path)

    def fail(key, message):
        return RuleError(source, key, message)

    try:
        text = Path(path).read_text(encoding="utf-8")
        duplicate = _duplicate_key(yaml.compose(text, Loader=yaml.SafeLoader))
        data = yaml.safe_load(text)
    except (OSError, ValueError, yaml.YAMLError, RecursionError) as exc:
        raise fail(None, "cannot read: {}".format(" ".join(str(exc).split())))
    if duplicate is not None:
        raise fail(duplicate.value, "duplicate key at line {}: the earlier value would "
                   "be silently dropped".format(duplicate.start_mark.line + 1))
    if data is None:
        raise fail(None, "file is empty")
    if not isinstance(data, dict):
        raise fail(None, "must be a mapping of keys to values, "
                         "got a {}".format(type(data).__name__))

    _reject_unknown(data, _RULE_KEYS, None, fail)
    rule_id = _text(data.get("id"), "id", fail, True)
    title = _text(data.get("title"), "title", fail, True)
    severity = _text(data.get("severity"), "severity", fail, True)
    if severity not in SEVERITIES:
        raise fail("severity", "{!r} is not one of {}".format(severity, ", ".join(SEVERITIES)))

    detection = data.get("detection")
    if not isinstance(detection, dict) or not detection:
        raise fail("detection", "is required: a mapping of named selections and a condition")
    selections = {k: v for k, v in detection.items() if k not in _DETECTION_KEYS}
    if not selections:
        raise fail("detection", "has no selection: add a named mapping of field to value")
    for name, selection in selections.items():
        _check_selection(name, selection, fail)

    timeframe, count_gte, group_by = None, None, ()
    if "count" in detection:
        count = _mapping(detection["count"], "detection.count", fail)
        _reject_unknown(count, ("gte", "group_by"), "detection.count", fail)
        count_gte = count.get("gte")
        if not isinstance(count_gte, int) or count_gte < 2:
            raise fail("detection.count.gte", "must be a whole number of at least 2, got "
                       "{!r}; for one alert per event, leave count out".format(count_gte))
        group_by = _field_names(count.get("group_by"), "detection.count.group_by", fail)
        if "timeframe" not in detection:
            raise fail("detection.timeframe", "is required with count: the window to count in")
    elif "timeframe" in detection:
        raise fail("detection.timeframe", "has no count to apply to: add detection.count "
                                          "or remove it")
    if "timeframe" in detection:
        try:
            timeframe = parse_timeframe(detection["timeframe"])
        except ValueError as exc:
            raise fail("detection.timeframe", str(exc))

    fields = _field_names(data.get("fields"), "fields", fail)
    if not group_by and not fields:
        raise fail("fields", "needs at least one field: with no group_by the alert's "
                             "entity comes from fields[0]")

    condition = _check_condition(detection.get("condition"), selections, fail)
    mitre = _mapping(data.get("mitre"), "mitre", fail)
    _reject_unknown(mitre, ("technique", "tactic"), "mitre", fail)
    return Rule(
        id=rule_id,
        title=title,
        severity=severity,
        status=_text(data.get("status"), "status", fail, False),
        selections=selections,
        condition=condition,
        timeframe=timeframe,
        count_gte=count_gte,
        group_by=group_by,
        fields=fields,
        technique=_text(mitre.get("technique"), "mitre.technique", fail, False),
        tactic=_text(mitre.get("tactic"), "mitre.tactic", fail, False),
        logsource=dict(_mapping(data.get("logsource"), "logsource", fail)),
        description=_text(data.get("description"), "description", fail, False),
        falsepositives=_texts(data.get("falsepositives"), "falsepositives", fail),
        source_file=source,
    )


def load_rules(directory):
    """Load every .yml/.yaml file in `directory` -> (rules, errors).

    Files load in name order and the first of two equal ids wins, so a pack
    behaves the same whatever order the filesystem lists it in. A bad file is an
    error in the list, never an exception: one typo must not stop the pack.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return [], [RuleError(str(directory), None, "rules directory does not exist")]
    by_id, errors = {}, []
    for path in sorted(directory.iterdir(), key=lambda p: p.name):
        if path.suffix.lower() not in (".yml", ".yaml"):
            continue
        try:
            rule = load_rule_file(path)
        except RuleError as exc:
            errors.append(exc)
            continue
        if rule.id in by_id:
            errors.append(RuleError(str(path), "id", "{!r} is already defined by {}".format(
                rule.id, by_id[rule.id].source_file)))
        else:
            by_id[rule.id] = rule
    return list(by_id.values()), errors

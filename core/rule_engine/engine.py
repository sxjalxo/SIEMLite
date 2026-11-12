#!/usr/bin/env python3
"""
Rule Engine
===========
One pass over an event sequence, every rule applied to every event.

Threshold state is created per run_rules call, not per process: a batch
`siem detect` run must not inherit a window from a previous run, or re-running
the same window would fire on events it already alerted about.

A rule that raises costs that rule on that event, not the run. A pack of
twenty rules where one has a pathological regex must still deliver the other
nineteen, and one crafted event must not silence a rule for the events after
it. The rule is reported once per pass, not once per event.

An alert names its events by event_hash, never by row id: NormalizedEvent has
no id, and EVENT_FIELDS is derived from its fields, so adding one would make
the row id a field a rule could match.

Plugins are the rules YAML cannot express: an ordered sequence across two
EventIDs. They subclass PluginRule below and are evaluated once over the whole
event list, not per event, because a sequence is only visible across events.
They are Python files run with the engine's own privileges, so a plugins
directory is code you trust, unlike a YAML pack.
"""

import hashlib
import importlib.util
import json
from dataclasses import dataclass, replace
from pathlib import Path

from core.rule_engine.loader import RuleError
from core.rule_engine.matcher import match_event
from core.rule_engine.threshold import ThresholdTracker

SEVERITY_WEIGHTS = {"INFO": 1, "LOW": 2, "MEDIUM": 4, "HIGH": 8, "CRITICAL": 16}

ENTITY_TYPES = {
    "source_ip": "ip", "dest_ip": "ip",
    "user": "user", "target_user": "user",
    "host": "host",
}


def _one_line(text):
    return " ".join(str(text).split())


def _text(value):
    """str(value), with None as "" like the matcher, not "None"."""
    return "" if value is None else str(value)


@dataclass(frozen=True)
class RuleAlert:
    rule_id: str
    rule_title: str
    severity: str
    entity_type: str
    entity_value: str
    event_hashes: tuple
    timestamp: object
    technique: str
    tactic: str
    category: str
    source: str
    detail: str
    evidence: str

    @property
    def alert_hash(self):
        """Content address for this alert, so `detect` can be re-run.

        Sorted event hashes, so a window assembled in a different order is the
        same alert rather than a duplicate. entity_value is defensive: it is
        read from the alert's own events, so the rule and event set already
        imply it.
        """
        parts = [self.rule_id, self.entity_value] + sorted(self.event_hashes)
        return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def entity_for(rule, event):
    """(entity_type, entity_value): group_by[0] for a threshold rule, else fields[0].

    R90: when that value is not known ("-" is Windows' "not recorded", or
    empty), the next declared field whose value is known, and finally host. An
    entity of "-" would give every such alert of a rule the same entity, and
    the correlator would merge unrelated machines into one incident. host is
    never "-": parse_event_xml requires Computer.
    """
    first = (rule.group_by or rule.fields)[0]
    for name in (first, *rule.fields, "host"):
        value = _text(getattr(event, name))
        if value not in ("", "-"):
            return ENTITY_TYPES.get(name, name), value
    return ENTITY_TYPES.get(first, first), _text(getattr(event, first))


def _alert(rule, events, entity=None):
    """The alert for the events that fired `rule`.

    `entity` is an (entity_type, entity_value) a plugin names itself; a YAML
    rule's entity is read from its newest event.
    """
    # Oldest first, ties broken by hash, not by arrival: a window with no
    # group_by spans entities, and the same window re-detected in a different
    # order must name the same entity and store the same evidence.
    events = sorted(events, key=lambda e: (e.timestamp, e.event_hash))
    newest = events[-1]
    entity_type, entity_value = entity or entity_for(rule, newest)
    names = rule.fields or rule.group_by
    return RuleAlert(
        rule_id=rule.id,
        rule_title=rule.title,
        severity=rule.severity,
        entity_type=entity_type,
        entity_value=entity_value,
        event_hashes=tuple(e.event_hash for e in events),
        timestamp=newest.timestamp,
        technique=rule.technique,
        tactic=rule.tactic,
        category=rule.title,
        source="rule_engine",
        detail=_one_line("{} ({}: {})".format(rule.description, entity_type, entity_value)),
        # ponytail: one alert row holds every event of its window, so a rule
        # with count gte: 100000 stores a huge evidence and event_hashes. Cap
        # evidence (keep event_hashes whole) if a real rule ever needs that.
        evidence=json.dumps([{n: getattr(e, n) for n in names} for e in events],
                            default=str),
    )


def _failure(rule_id, exc):
    message = str(exc) if isinstance(exc, ValueError) else (
        "{}: {}".format(type(exc).__name__, exc))
    return rule_id, _one_line(message)


class PluginRule:
    """Base class for a rule that detects a sequence YAML cannot express.

    Subclass it in a module under rules/plugins/ named `Rule`, set the class
    attributes and implement evaluate(). Build alerts with make_alert, never by
    hand: it gets alert_hash, the canonical event order and the stored columns
    right. This deliberately does not extend core.detection_engine.DetectionRule,
    which takes legacy LogEvents, not NormalizedEvents.

    A module is loaded without being registered in sys.modules, so a plugin
    that uses @dataclass together with `from __future__ import annotations`
    fails to load (an AttributeError in the errors list): leave that import out.
    """

    id = title = severity = technique = tactic = description = entity_field = None
    # Evidence columns stored per event, like a YAML rule's `fields`.
    fields = ("event_id", "action", "user", "target_user", "source_ip", "host")

    def evaluate(self, events):
        """Every RuleAlert for this list of NormalizedEvents (once per run)."""
        raise NotImplementedError

    def make_alert(self, events, entity_value, **overrides):
        """The RuleAlert for `events`, about `entity_value` (a `entity_field`).

        R92: an unknown entity ("-" or empty) falls back to the newest event's
        host, as entity_for does for a YAML rule. The correlator groups by
        entity, so "-" would merge unrelated machines into one incident.
        """
        entity = (ENTITY_TYPES.get(self.entity_field, self.entity_field),
                  _text(entity_value))
        if entity[1] in ("", "-"):
            newest = max(events, key=lambda e: (e.timestamp, e.event_hash))
            entity = ("host", _text(newest.host))
        alert = _alert(self, events, entity)
        return replace(alert, **overrides) if overrides else alert


def load_plugins(directory):
    """Load each rules/plugins-style *.py in `directory` -> (plugins, errors).

    A module's `Rule` class, if it subclasses PluginRule, is instantiated; a
    module without one is a helper and skipped silently. Names starting with an
    underscore (__init__) are skipped. A plugin that fails to import or build is
    an error in the list, never an exception, and the first of two equal ids
    wins. Modules are loaded from their path and not registered in sys.modules.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return [], [RuleError(str(directory), None, "plugins directory does not exist")]
    by_id, errors = {}, []
    for path in sorted(directory.glob("*.py"), key=lambda p: p.name):
        if path.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location("siem_plugin_" + path.stem, path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            cls = getattr(module, "Rule", None)
            if not (isinstance(cls, type) and issubclass(cls, PluginRule)):
                continue
            plugin = cls()
            if not plugin.id or plugin.severity not in SEVERITY_WEIGHTS:
                raise ValueError("needs an id and a severity of {}, got {!r} and {!r}".format(
                    "/".join(SEVERITY_WEIGHTS), plugin.id, plugin.severity))
        except Exception as exc:
            errors.append(RuleError(
                str(path), None, "{}: {}".format(type(exc).__name__, _one_line(exc))))
            continue
        if plugin.id in by_id:
            errors.append(RuleError(str(path), "id", "{!r} is already defined by {}".format(
                plugin.id, by_id[plugin.id][1])))
        else:
            by_id[plugin.id] = (plugin, path)
    return [plugin for plugin, _ in by_id.values()], errors


def run_rules(events, rules, plugins=()):
    """Apply every rule to every event, then every plugin to all of them.

    Always a two-tuple (alerts, failures). `failures` is a list of
    (rule_id, message), one per failing rule or plugin.
    """
    events = list(events)
    alerts, failures, reported, trackers = [], [], set(), {}
    for event in events:
        for i, rule in enumerate(rules):
            try:
                if rule.count_gte is not None and i not in trackers:
                    trackers[i] = ThresholdTracker(rule.timeframe, rule.count_gte)
                if not match_event(event, rule.selections, rule.condition):
                    continue
                if rule.count_gte is None:
                    fired = (event,)
                else:
                    # Lower-cased like the matcher, so a burst that alternates
                    # the case of a username is one window, not three.
                    key = tuple(_text(getattr(event, f)).lower() for f in rule.group_by)
                    fired = trackers[i].add(key, event.timestamp, event)
                    if fired is None:
                        continue
                alerts.append(_alert(rule, fired))
            except Exception as exc:
                if i not in reported:
                    reported.add(i)
                    failures.append(_failure(rule.id, exc))
    for plugin in plugins:
        try:
            # list() inside the try: a generator that fails halfway costs the
            # whole plugin, not a random prefix of its alerts.
            alerts.extend(list(plugin.evaluate(events)))
        except Exception as exc:
            failures.append(_failure(plugin.id, exc))
    return alerts, failures

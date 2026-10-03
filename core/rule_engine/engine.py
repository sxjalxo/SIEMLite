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
"""

import hashlib
import json
from dataclasses import dataclass

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
    """(entity_type, entity_value): group_by[0] for a threshold rule, else fields[0]."""
    name = (rule.group_by or rule.fields)[0]
    return ENTITY_TYPES.get(name, name), _text(getattr(event, name))


def _alert(rule, events):
    """The alert for the events that fired `rule`."""
    # Oldest first, ties broken by hash, not by arrival: a window with no
    # group_by spans entities, and the same window re-detected in a different
    # order must name the same entity and store the same evidence.
    events = sorted(events, key=lambda e: (e.timestamp, e.event_hash))
    newest = events[-1]
    entity_type, entity_value = entity_for(rule, newest)
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


def run_rules(events, rules, plugins=()):
    """Apply every rule to every event -> (alerts, failures).

    Always a two-tuple. `failures` is a list of (rule_id, message), one per
    failing rule.
    """
    if plugins:
        raise NotImplementedError("plugin rules are not supported yet")
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
                    message = str(exc) if isinstance(exc, ValueError) else (
                        "{}: {}".format(type(exc).__name__, exc))
                    failures.append((rule.id, _one_line(message)))
    return alerts, failures

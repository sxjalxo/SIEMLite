#!/usr/bin/env python3
"""Shared helpers for the rule-engine tests.

rule_from_yaml goes through the real loader rather than constructing a Rule,
so a loader change that breaks the engine's expectations fails these tests
instead of passing them.
"""

import tempfile
from datetime import datetime
from pathlib import Path

from core.rule_engine.engine import RuleAlert
from core.rule_engine.loader import load_rule_file
from ingestion.normalizer import NormalizedEvent

T0 = datetime(2026, 10, 3, 12, 0, 0)


def rule_from_yaml(text, name="rule.yml"):
    """Load a Rule from YAML held in a string."""
    directory = tempfile.mkdtemp()
    path = Path(directory) / name
    path.write_text(text, encoding="utf-8")
    return load_rule_file(path)


def event(**kwargs):
    """A NormalizedEvent with the required fields filled in."""
    base = dict(
        timestamp=T0, source_type="windows", host="PC-01", channel="Security",
        event_id=4625, record_id=1, action="LOGIN_FAIL", raw="<Event/>",
    )
    base.update(kwargs)
    return NormalizedEvent(**base)


def sample_alert(**overrides):
    """A RuleAlert with every field filled."""
    base = dict(
        rule_id="r1", rule_title="Failed Logon Burst", severity="HIGH",
        entity_type="ip", entity_value="1.2.3.4", event_hashes=("aa", "bb"),
        timestamp=T0, technique="T1110", tactic="TA0006",
        category="Failed Logon Burst", source="rule_engine",
        detail="five failures (ip: 1.2.3.4)", evidence="[]",
    )
    base.update(overrides)
    return RuleAlert(**base)

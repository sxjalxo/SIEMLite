#!/usr/bin/env python3
"""
Correlator
==========
Alerts become incidents by entity and time. One attacker working one target
produces a stream of alerts; an analyst wants one thing to look at.

Severity is the maximum of the member alerts, escalated one level when the
incident spans three or more distinct MITRE tactics: breadth across the kill
chain is itself a signal, independent of how severe any single step looked.

Score ranks output and nothing else. It never decides whether an incident
opens, so a scoring change can never silently stop incidents appearing,
which is why the rule is "ranking only" and not "ranking and triage".

ponytail: no cross-entity linking. Two incidents sharing a host stay separate
(spec section 17). Linking them needs a second grouping pass and a rule for
when a link is real; defer it until there is a question it answers.
"""

from datetime import timedelta

from core import store
from core.rule_engine.engine import SEVERITY_WEIGHTS
from core.rule_engine.loader import SEVERITIES

CORRELATION_WINDOW = timedelta(minutes=30)

# Alerts this many distinct tactics wide are escalated one level.
ESCALATION_TACTICS = 3


def _sev(value):
    """A severity as the ladder spells it, so a hand-edited "high" is HIGH."""
    return str(value).upper()


def escalate(severity):
    """One level up the ladder; CRITICAL and unrecognised values stay as given."""
    level = _sev(severity)
    if level not in SEVERITIES:
        return severity
    return SEVERITIES[min(SEVERITIES.index(level) + 1, len(SEVERITIES) - 1)]


def _tactics(rows):
    return {r["tactic"] for r in rows if r["tactic"]}


def incident_severity(rows):
    """Highest member severity, escalated once at three or more distinct tactics.

    `rows` are mappings with `severity`, `rule_id` and `tactic`. An
    unrecognised severity ranks below every real one (case is ignored), so a
    hand-edited row cannot stop a run; the result is always one of SEVERITIES.
    """
    top = max((_sev(r["severity"]) for r in rows if _sev(r["severity"]) in SEVERITIES),
              key=SEVERITIES.index, default=SEVERITIES[0])
    return escalate(top) if len(_tactics(rows)) >= ESCALATION_TACTICS else top


def score_incident(rows):
    """Spec 7: severity weight of each DISTINCT rule, plus 2 per distinct tactic.

    A rule firing fifty times is one rule's worth of evidence, not fifty.
    """
    by_rule = {}
    for r in rows:
        weight = SEVERITY_WEIGHTS.get(_sev(r["severity"]), 0)
        by_rule[r["rule_id"]] = max(weight, by_rule.get(r["rule_id"], 0))
    return sum(by_rule.values()) + 2 * len(_tactics(rows))


def _refresh(conn, incident_id):
    """Recompute an incident's summary from all of its member alerts.

    The tactic is read back from the table (`mitre_tactic_id`, R53), so it
    survives from one run to the next.

    ponytail: recomputed from the full member set rather than incrementally.
    An incremental tactic union and a running max are two more places to be
    wrong, and an incident has tens of alerts, not millions. Recompute
    incrementally only if an incident ever grows large enough to matter.
    """
    rows = store.query_alerts(conn, incident_id=incident_id, limit=None)
    members = [{"severity": r["severity"], "rule_id": r["rule_id"],
                "tactic": r["mitre_tactic_id"]} for r in rows]
    store.update_incident(
        conn, incident_id,
        last_seen=max(r["timestamp"] for r in rows),
        severity=incident_severity(members), score=score_incident(members),
        tactics=sorted(_tactics(members)))


def correlate(conn, alerts, window=CORRELATION_WINDOW):
    """Store `alerts` and group them into incidents by entity and time.

    An alert joins the open incident for its (entity_type, entity_value) whose
    last_seen is within `window` of it (inclusive), else opens a new one.
    Returns {"opened": incidents opened, "attached": alerts that joined an
    incident already open (the alert that opens one is not counted),
    "incident_ids": the incidents touched}.

    Re-runnable: an alert already stored and attached is skipped, so running
    `detect` twice over the same events opens and attaches nothing. An alert
    stored but never attached (a run that died between commits) is attached
    now. The incidents of skipped alerts are refreshed once at the end, not
    reported in the result, so a run that died after attaching but before
    recomputing is repaired by the next one.
    Only the rows for `alerts` are correlated, never the rest of the table, so
    legacy scanner rows (no rule_id, no entity, UTC timestamps; R74) stay out.
    """
    unique = {a.alert_hash: a for a in alerts}
    result = {"opened": 0, "attached": 0, "incident_ids": []}
    if not unique:
        return result
    store.insert_alerts(conn, unique.values())
    times = [a.timestamp for a in unique.values()]
    stored = {r["alert_hash"]: r for r in store.query_alerts(
        conn, since=min(times), until=max(times), limit=None)}

    already = set()
    for alert in sorted(unique.values(), key=lambda a: a.timestamp):
        row = stored.get(alert.alert_hash)
        if row is None:
            continue
        if row["incident_id"] is not None:
            already.add(row["incident_id"])
            continue
        found = store.find_open_incident(
            conn, alert.entity_type, alert.entity_value, alert.timestamp - window)
        if found is not None:
            incident_id = found["id"]
            result["attached"] += 1
        else:
            incident_id = store.open_incident(
                conn, alert.timestamp, alert.timestamp, alert.entity_type,
                alert.entity_value, alert.severity, title="{} on {}".format(
                    alert.rule_title, alert.entity_value))
            result["opened"] += 1
        store.attach_alerts(conn, incident_id, [row["id"]])
        _refresh(conn, incident_id)
        if incident_id not in result["incident_ids"]:
            result["incident_ids"].append(incident_id)
    for incident_id in sorted(already):
        _refresh(conn, incident_id)
    return result

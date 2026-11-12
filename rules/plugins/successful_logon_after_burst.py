"""Successful logon after a failed burst.

Detects: five or more failed logons (4625) for one account from one source
within five minutes, followed within thirty minutes by a successful logon (4624)
for the same account from the same source. Password guessing that worked.

Why not YAML: a YAML rule matches one event at a time, or counts one kind of
event in a window. This needs two EventIDs in a given order, and the second
only matters if the first happened, which the matcher deliberately cannot say.

A source address of "-" (Windows writes it when the address was not recorded)
is never a source: it would pool unrelated machines into one burst and then
pair that with any later success.

Failures for the session-helper and Exchange service accounts that
win-failed-logon-burst deliberately ignores are ignored here too, whole names
only, so the two rules do not disagree about the same events. Fires once per
burst: the success consumes it. An event with no recorded account ("-") is
skipped, as is one with no recorded source.

False positives (a CRITICAL, so these are written down, not discovered):
  - A stale saved password: a mail client or mapped drive retries five times,
    the user corrects it, and the next logon succeeds. This is indistinguishable
    from guessing that worked, and no filter removes it. The sequence is
    CRITICAL by design.
  - A user who mistypes five times in five minutes and then gets it right.
  - A vulnerability scanner or monitoring probe that tests logons, then logs on.
"""

import re
from datetime import timedelta

from core.rule_engine.engine import PluginRule
from core.rule_engine.threshold import ThresholdTracker

BURST_WINDOW = timedelta(minutes=5)
BURST_COUNT = 5
# Measured from the last failure of the burst.
FOLLOW_UP = timedelta(minutes=30)
# The same whole-name filter as win-failed-logon-burst: dwm-n and umfd-n session
# helpers and Exchange HealthMailbox + hex. \Z, not $, which accepts a trailing
# newline; whole names, so "umfd-bob" is an ordinary account and still counts.
SERVICE_ACCOUNT = re.compile(r"^(dwm-\d+|umfd-\d+|healthmailbox[0-9a-f]+)\Z", re.IGNORECASE)


class Rule(PluginRule):
    id = "win-success-after-burst"
    title = "Successful Logon After a Failed Logon Burst"
    severity = "CRITICAL"
    technique = "T1110.001"
    tactic = "TA0006"
    entity_field = "source_ip"
    description = (
        "A successful logon (EventID 4624) for an account within thirty minutes "
        "of five or more failed logons (EventID 4625) for that account from the "
        "same source address within five minutes: password guessing that worked."
    )

    def evaluate(self, events):
        bursts = ThresholdTracker(BURST_WINDOW, BURST_COUNT)
        armed, alerts = {}, []
        # Timestamp order, not list order; sorted() is stable, so a tie keeps
        # the order it arrived in.
        for event in sorted(events, key=lambda e: e.timestamp):
            ip = event.source_ip
            if not ip or ip == "-" or event.target_user in ("", "-"):
                continue
            # Lower-cased like the matcher and the YAML burst rules.
            key = (ip, event.target_user.lower())
            if event.event_id == 4625 and event.action == "LOGIN_FAIL":
                if SERVICE_ACCOUNT.search(event.target_user):
                    continue
                burst = bursts.add(key, event.timestamp, event)
                if burst is not None:
                    armed[key] = burst
            elif event.event_id == 4624 and event.action == "LOGIN_OK" and key in armed:
                burst = armed.pop(key)
                if event.timestamp - burst[-1].timestamp <= FOLLOW_UP:
                    alerts.append(self.make_alert(burst + (event,), ip))
        return alerts

#!/usr/bin/env python3
"""
Synthetic Windows Attack Scenario
=================================
One attacker at 203.0.113.77 against PC-01, over eleven minutes:

    +00:00-+00:40  six failed logons for `alice`        (4625 x6)
    +01:00         a successful logon for `alice`        (4624)
    +03:00         a new account `svc_update` created    (4720)
    +04:00         special privileges assigned to it     (4672)
    +06:00         encoded PowerShell from that account  (4688)
    +11:00         the security log is cleared           (1102)

Every stage exercises a different part of the pipeline: a threshold rule, a
sequence plugin, two per-event rules, a second sequence plugin, and the
highest-severity rule in the pack. The story shares one host, but the
correlator groups by entity, not host (no cross-entity linking), so it
produces two incidents: the attacker's address (the burst and the success
that followed it) and the planted account (everything else).

TIMESTAMPS ARE RELATIVE TO NOW. BASE is one hour ago, taken when this module
is imported, and every event sits at BASE plus its offset above. A fixed date
is a time bomb: detect reads the last 24 hours by default, so a fixed one
silently reads nothing once it ages out, and a "0 alerts" run passes for
nothing. One hour is chosen against both limits that read these events:
  - detect's default window is 24 hours, so the story is 23 hours inside it;
  - an incident closes when idle for 2 hours (store.IDLE_TIMEOUT), and the
    newest event is 49 minutes old, so there is a 71-minute margin. A base of
    three hours would let close_idle_incidents close the incident under test.
The story must also stay clear of the office-hours rule (4624 type 2 outside
07:00-19:59), which depends on the wall clock: the logon here is type 3.

event_hash is (host, channel, record_id), not the timestamp, so building this
module again later gives the same events: a store that already holds them
takes no duplicates.
"""

from datetime import datetime, timedelta

from ingestion.normalizer import NormalizedEvent

ATTACKER_IP = "203.0.113.77"
HOST = "PC-01"

BASE = datetime.now().replace(microsecond=0) - timedelta(hours=1)

PS_PATH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def _event(offset_seconds, record_id, event_id, action, host=HOST, **fields):
    """A Security event `offset_seconds` after BASE, shaped like the
    normalizer's output for that EventID (4624 sets user and target_user)."""
    return NormalizedEvent(
        timestamp=BASE + timedelta(seconds=offset_seconds), source_type="windows",
        host=host, channel="Security", event_id=event_id, record_id=record_id,
        action=action, raw="<synthetic {} {}/>".format(event_id, record_id),
        metadata={"stable_record_id": True}, **fields)


def _failed_logon(offset_seconds, record_id):
    return _event(offset_seconds, record_id, 4625, "LOGIN_FAIL", target_user="alice",
                  source_ip=ATTACKER_IP, logon_type=3, status="0xc000006d",
                  workstation="KALI")


EVENTS = [
    # Password guessing: six failures in 40 seconds. The fifth completes the burst.
    *(_failed_logon(8 * i, 1000 + i) for i in range(6)),
    # ...and it worked.
    _event(60, 1006, 4624, "LOGIN_OK", user="alice", target_user="alice",
           source_ip=ATTACKER_IP, logon_type=3),
    # alice creates a backdoor account.
    _event(180, 1007, 4720, "ACCOUNT_CREATE", user="alice", target_user="svc_update"),
    # The new account logs on with administrator rights.
    _event(240, 1008, 4672, "PRIVILEGE_ASSIGN", user="svc_update"),
    # It runs an encoded PowerShell command (-enc, a prefix of -EncodedCommand).
    _event(360, 1009, 4688, "PROCESS_CREATE", user="svc_update", process=PS_PATH,
           parent_process=r"C:\Windows\System32\cmd.exe",
           command_line="powershell.exe -NoProfile -enc SQBFAFgAIAAoAGcAYwBtACAAaQApAA== "),
    # And it covers its tracks.
    _event(660, 1010, 1102, "LOG_CLEARED", user="svc_update"),
]

# A second, quieter story on another machine, for the one thing the story above
# cannot show: severity escalation. The story above already holds a CRITICAL
# alert, so its incident cannot rise further. These three alerts are MEDIUM,
# MEDIUM and HIGH for one account, in three different tactics (persistence,
# privilege escalation, defense evasion), so the incident is CRITICAL only
# because it is wide. There is no 4672, so no CRITICAL plugin alert.
ESCALATION_EVENTS = [
    _event(0, 2000, 4720, "ACCOUNT_CREATE", host="PC-02", user="it-admin",
           target_user="helpdesk2"),
    _event(60, 2001, 4728, "GROUP_ADD_GLOBAL", host="PC-02", user="it-admin",
           target_user="helpdesk2", object_name="Domain Admins"),
    _event(120, 2002, 4688, "PROCESS_CREATE", host="PC-02", user="helpdesk2",
           process=PS_PATH,
           command_line="powershell.exe -enc SQBFAFgAIAAoAGcAYwBtACAAaQApAA== "),
]

"""Special privileges assigned to an account created in the same window.

Detects: an account creation (4720) followed, within 24 hours, by special
privileges assigned to that account at logon (4672). A new account that logs on
with administrator-level rights is how a backdoor account is used.

Why not YAML: this needs two EventIDs in a given order about one account, and
the two events name it in different fields: 4720's `target_user` is the new
account (its `user` is the creator), while 4672 has only `user`. The matcher
compares one event's fields to constants, never one event to another.

Fires once per creation: the first privileged logon consumes it. An unnamed
account ("-") is never matched.
"""

from datetime import timedelta

from core.rule_engine.engine import PluginRule

NEW_ACCOUNT_WINDOW = timedelta(hours=24)


class Rule(PluginRule):
    id = "win-new-account-privileged"
    title = "Special Privileges Assigned to a Newly Created Account"
    severity = "CRITICAL"
    technique = "T1098"
    tactic = "TA0004"
    entity_field = "target_user"
    description = (
        "Special privileges were assigned (EventID 4672) to an account within "
        "24 hours of its creation (EventID 4720): a new account holding "
        "administrator-level rights."
    )

    def evaluate(self, events):
        created, alerts = {}, []
        for event in sorted(events, key=lambda e: e.timestamp):
            if event.event_id == 4720 and event.action == "ACCOUNT_CREATE":
                if event.target_user not in ("", "-"):
                    created[event.target_user.lower()] = event
            elif event.event_id == 4672 and event.action == "PRIVILEGE_ASSIGN":
                made = created.pop(event.user.lower(), None)
                if made is not None and event.timestamp - made.timestamp <= NEW_ACCOUNT_WINDOW:
                    alerts.append(self.make_alert((made, event), made.target_user))
        return alerts

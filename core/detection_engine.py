#!/usr/bin/env python3
"""
Detection Engine — SIGMA-Inspired Rule-Based Threat Detection
==============================================================
Evaluates normalized LogEvents against detection rules mapped to
MITRE ATT&CK tactics and techniques.

Each rule is a class with an ``evaluate()`` method that returns Alerts.
"""

import re
from datetime import timedelta
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict

from core.report import Colors, Finding


# ─────────────────────────────────────────────
# Alert Data Structure
# ─────────────────────────────────────────────

@dataclass
class Alert:
    """A detection alert produced by a rule."""
    rule_name: str
    severity: str            # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    evidence: str
    source_ips: list = field(default_factory=list)
    mitre_tactic: str = ""
    mitre_technique: str = ""
    event_count: int = 0
    timestamp: str = ""

    def to_dict(self):
        return asdict(self)

    def to_finding(self):
        """Convert to a Finding for the legacy report system."""
        return Finding(
            category=self.rule_name,
            severity=self.severity,
            detail=self.description,
            evidence=self.evidence,
        )


# ─────────────────────────────────────────────
# Base Rule
# ─────────────────────────────────────────────

class DetectionRule:
    """Base class for all detection rules."""
    name = "Base Rule"
    description = ""
    severity = "INFO"
    mitre_tactic = ""
    mitre_technique = ""

    def evaluate(self, events):
        """Evaluate events and return list of Alert objects."""
        raise NotImplementedError


# ─────────────────────────────────────────────
# Rule 1: SSH Brute Force
# ─────────────────────────────────────────────

class SSHBruteForceRule(DetectionRule):
    name = "SSH Brute Force"
    description = "Multiple failed SSH logins from the same IP"
    severity = "CRITICAL"
    mitre_tactic = "TA0006 - Credential Access"
    mitre_technique = "T1110 - Brute Force"

    THRESHOLD = 5
    WINDOW_MINUTES = 5

    def evaluate(self, events):
        alerts = []
        ssh_fails = defaultdict(list)

        for e in events:
            if e.source_type == "ssh" and e.action == "LOGIN_FAIL":
                ssh_fails[e.source_ip].append(e)

        for ip, fails in ssh_fails.items():
            if len(fails) < self.THRESHOLD:
                continue

            fails.sort(key=lambda x: x.timestamp)
            # Sliding window check
            window_start = 0
            for i in range(len(fails)):
                while (fails[i].timestamp - fails[window_start].timestamp) > timedelta(minutes=self.WINDOW_MINUTES):
                    window_start += 1
                window_count = i - window_start + 1
                if window_count >= self.THRESHOLD:
                    users = Counter(f.user for f in fails)
                    user_str = ", ".join(f"{u} (x{c})" for u, c in users.most_common(5))
                    alerts.append(Alert(
                        rule_name=self.name,
                        severity=self.severity,
                        description=f"SSH brute-force from {ip} — {len(fails)} failed attempts",
                        evidence=f"Targeted users: {user_str}\nMITRE: {self.mitre_technique}",
                        source_ips=[ip],
                        mitre_tactic=self.mitre_tactic,
                        mitre_technique=self.mitre_technique,
                        event_count=len(fails),
                        timestamp=fails[0].timestamp.isoformat(),
                    ))
                    break

        return alerts


# ─────────────────────────────────────────────
# Rule 2: HTTP Brute Force
# ─────────────────────────────────────────────

AUTH_ENDPOINTS = [
    "/login", "/signin", "/auth", "/admin", "/wp-login.php",
    "/wp-admin", "/user/login", "/account/login", "/api/login",
    "/api/auth", "/oauth", "/sso", "/session",
]

class HTTPBruteForceRule(DetectionRule):
    name = "HTTP Brute Force"
    description = "Multiple failed HTTP logins from the same IP"
    severity = "HIGH"
    mitre_tactic = "TA0006 - Credential Access"
    mitre_technique = "T1110 - Brute Force"

    THRESHOLD = 5

    def evaluate(self, events):
        alerts = []
        ip_fails = defaultdict(list)

        for e in events:
            if e.source_type == "apache" and e.action == "LOGIN_FAIL":
                ip_fails[e.source_ip].append(e)

        for ip, fails in ip_fails.items():
            if len(fails) >= self.THRESHOLD:
                paths = Counter(e.metadata.get("path", "") for e in fails)
                path_str = ", ".join(f"{p} (x{c})" for p, c in paths.most_common(3))
                alerts.append(Alert(
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"HTTP brute-force from {ip} — {len(fails)} failed logins",
                    evidence=f"Targets: {path_str}\nMITRE: {self.mitre_technique}",
                    source_ips=[ip],
                    mitre_tactic=self.mitre_tactic,
                    mitre_technique=self.mitre_technique,
                    event_count=len(fails),
                    timestamp=fails[0].timestamp.isoformat(),
                ))

        return alerts


# ─────────────────────────────────────────────
# Rule 3: Login from Unusual IP
# ─────────────────────────────────────────────

KNOWN_INTERNAL = {"10.", "192.168.", "172.16.", "172.17.", "172.18.",
                  "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                  "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                  "172.29.", "172.30.", "172.31.", "127."}

class UnusualIPLoginRule(DetectionRule):
    name = "Unusual IP Login"
    description = "Successful login from a non-internal IP address"
    severity = "MEDIUM"
    mitre_tactic = "TA0001 - Initial Access"
    mitre_technique = "T1078 - Valid Accounts"

    def evaluate(self, events):
        alerts = []
        successful_logins = [e for e in events if e.action == "LOGIN_OK"]

        for e in successful_logins:
            ip = e.source_ip
            if ip == "local":
                continue
            is_internal = any(ip.startswith(prefix) for prefix in KNOWN_INTERNAL)
            if not is_internal:
                alerts.append(Alert(
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Login from external IP {ip} (user: {e.user}, source: {e.source_type})",
                    evidence=f"Detail: {e.detail}\nMITRE: {self.mitre_technique}",
                    source_ips=[ip],
                    mitre_tactic=self.mitre_tactic,
                    mitre_technique=self.mitre_technique,
                    event_count=1,
                    timestamp=e.timestamp.isoformat(),
                ))

        return alerts


# ─────────────────────────────────────────────
# Rule 4: Sensitive Endpoint Access
# ─────────────────────────────────────────────

SENSITIVE_PATHS = [
    "/.env", "/.git", "/wp-config", "/config", "/debug",
    "/server-status", "/server-info", "/phpinfo", "/phpmyadmin",
    "/adminer", "/.htaccess", "/.htpasswd", "/api/v1/internal",
    "/actuator", "/console", "/manager", "/jmx-console",
]

class SensitiveEndpointRule(DetectionRule):
    name = "Sensitive Endpoint Access"
    description = "Access to sensitive/admin endpoints"
    severity = "HIGH"
    mitre_tactic = "TA0001 - Initial Access"
    mitre_technique = "T1190 - Exploit Public-Facing Application"

    def evaluate(self, events):
        alerts = []
        ip_hits = defaultdict(list)

        for e in events:
            if e.source_type != "apache":
                continue
            path = e.metadata.get("path", "").lower()
            for sp in SENSITIVE_PATHS:
                if sp in path:
                    ip_hits[e.source_ip].append((sp, e))
                    break

        for ip, hits in ip_hits.items():
            paths_accessed = list(set(h[0] for h in hits))
            alerts.append(Alert(
                rule_name=self.name,
                severity=self.severity,
                description=f"Sensitive endpoint access from {ip} — {len(hits)} hit(s)",
                evidence=f"Endpoints: {', '.join(paths_accessed[:8])}\nMITRE: {self.mitre_technique}",
                source_ips=[ip],
                mitre_tactic=self.mitre_tactic,
                mitre_technique=self.mitre_technique,
                event_count=len(hits),
                timestamp=hits[0][1].timestamp.isoformat(),
            ))

        return alerts


# ─────────────────────────────────────────────
# Rule 5: Path Traversal
# ─────────────────────────────────────────────

TRAVERSAL_PATTERN = re.compile(r'(\.\./|\.\.\\)', re.I)

class PathTraversalRule(DetectionRule):
    name = "Path Traversal"
    description = "Directory traversal attempts in URI"
    severity = "HIGH"
    mitre_tactic = "TA0009 - Collection"
    mitre_technique = "T1083 - File and Directory Discovery"

    def evaluate(self, events):
        alerts = []
        ip_hits = defaultdict(list)

        for e in events:
            if e.source_type != "apache":
                continue
            path = e.metadata.get("path", "")
            if TRAVERSAL_PATTERN.search(path):
                ip_hits[e.source_ip].append(e)

        for ip, hits in ip_hits.items():
            sample = hits[0].metadata.get("path", "")[:120]
            alerts.append(Alert(
                rule_name=self.name,
                severity=self.severity,
                description=f"Path traversal from {ip} — {len(hits)} attempt(s)",
                evidence=f"Sample: {sample}\nMITRE: {self.mitre_technique}",
                source_ips=[ip],
                mitre_tactic=self.mitre_tactic,
                mitre_technique=self.mitre_technique,
                event_count=len(hits),
                timestamp=hits[0].timestamp.isoformat(),
            ))

        return alerts


# ─────────────────────────────────────────────
# Rule 6: SQLi / XSS in URI
# ─────────────────────────────────────────────

INJECTION_PATTERNS = [
    (re.compile(r"(union\s+select|order\s+by\s+\d|'.*or.*')", re.I), "SQLi"),
    (re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=)", re.I), "XSS"),
    (re.compile(r"(/etc/passwd|/etc/shadow|cmd\.exe|powershell)", re.I), "OS Command"),
]

class InjectionRule(DetectionRule):
    name = "Injection Attack"
    description = "SQLi/XSS/Command injection patterns in URI"
    severity = "HIGH"
    mitre_tactic = "TA0001 - Initial Access"
    mitre_technique = "T1190 - Exploit Public-Facing Application"

    def evaluate(self, events):
        alerts = []
        ip_hits = defaultdict(list)

        for e in events:
            if e.source_type != "apache":
                continue
            path = e.metadata.get("path", "")
            for pattern, label in INJECTION_PATTERNS:
                if pattern.search(path):
                    ip_hits[e.source_ip].append((label, e))

        for ip, hits in ip_hits.items():
            types = Counter(h[0] for h in hits)
            type_str = ", ".join(f"{t} (x{c})" for t, c in types.most_common())
            alerts.append(Alert(
                rule_name=self.name,
                severity=self.severity,
                description=f"Injection attacks from {ip} — {len(hits)} attempt(s)",
                evidence=f"Types: {type_str}\nMITRE: {self.mitre_technique}",
                source_ips=[ip],
                mitre_tactic=self.mitre_tactic,
                mitre_technique=self.mitre_technique,
                event_count=len(hits),
                timestamp=hits[0][1].timestamp.isoformat(),
            ))

        return alerts


# ─────────────────────────────────────────────
# Rule 7: Web Shell Access
# ─────────────────────────────────────────────

WEBSHELL_NAMES = [
    "c99.php", "r57.php", "wso.php", "b374k.php", "shell.php",
    "cmd.php", "webshell.php", "backdoor.php", "evil.php",
]

class WebShellRule(DetectionRule):
    name = "Web Shell Access"
    description = "Access to known web shell filenames"
    severity = "CRITICAL"
    mitre_tactic = "TA0003 - Persistence"
    mitre_technique = "T1505.003 - Web Shell"

    def evaluate(self, events):
        alerts = []
        ip_hits = defaultdict(list)

        for e in events:
            if e.source_type != "apache":
                continue
            path = e.metadata.get("path", "").lower()
            for shell in WEBSHELL_NAMES:
                if shell in path:
                    ip_hits[e.source_ip].append(e)
                    break

        for ip, hits in ip_hits.items():
            if len(hits) >= 2:
                paths = list(set(h.metadata.get("path", "") for h in hits))
                alerts.append(Alert(
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Web shell access from {ip} — {len(hits)} hit(s)",
                    evidence=f"Paths: {', '.join(paths[:5])}\nMITRE: {self.mitre_technique}",
                    source_ips=[ip],
                    mitre_tactic=self.mitre_tactic,
                    mitre_technique=self.mitre_technique,
                    event_count=len(hits),
                    timestamp=hits[0].timestamp.isoformat(),
                ))

        return alerts


# ─────────────────────────────────────────────
# Rule 8: Windows Privilege Escalation
# ─────────────────────────────────────────────

class PrivilegeEscalationRule(DetectionRule):
    name = "Privilege Escalation"
    description = "Privilege changes on Windows systems"
    severity = "CRITICAL"
    mitre_tactic = "TA0004 - Privilege Escalation"
    mitre_technique = "T1068 - Exploitation for Privilege Escalation"

    KNOWN_ADMINS = {"SYSTEM", "administrator", "admin"}

    def evaluate(self, events):
        alerts = []

        for e in events:
            if e.source_type != "windows":
                continue
            if e.action == "PRIVILEGE_CHANGE" and e.user.lower() not in {a.lower() for a in self.KNOWN_ADMINS}:
                alerts.append(Alert(
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Privilege escalation by non-admin user: {e.user}",
                    evidence=f"Event: {e.detail[:150]}\nMITRE: {self.mitre_technique}",
                    source_ips=[e.source_ip],
                    mitre_tactic=self.mitre_tactic,
                    mitre_technique=self.mitre_technique,
                    event_count=1,
                    timestamp=e.timestamp.isoformat(),
                ))

        return alerts


# ─────────────────────────────────────────────
# Rule 9: Account Manipulation
# ─────────────────────────────────────────────

class AccountManipulationRule(DetectionRule):
    name = "Account Manipulation"
    description = "User account creation or deletion"
    severity = "HIGH"
    mitre_tactic = "TA0003 - Persistence"
    mitre_technique = "T1136 - Create Account"

    def evaluate(self, events):
        alerts = []

        for e in events:
            if e.source_type != "windows":
                continue
            if e.action in ("ACCOUNT_CREATE", "ACCOUNT_DELETE"):
                new_acct = e.metadata.get("new_account", "unknown")
                action_label = "created" if e.action == "ACCOUNT_CREATE" else "deleted"
                alerts.append(Alert(
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Account {action_label}: {new_acct} (by {e.user})",
                    evidence=f"Event: {e.detail[:150]}\nMITRE: {self.mitre_technique}",
                    source_ips=[e.source_ip],
                    mitre_tactic=self.mitre_tactic,
                    mitre_technique=self.mitre_technique,
                    event_count=1,
                    timestamp=e.timestamp.isoformat(),
                ))

        return alerts


# ─────────────────────────────────────────────
# Rule 10: Rapid 404 Scanning
# ─────────────────────────────────────────────

class Rapid404ScanRule(DetectionRule):
    name = "Directory Scanning"
    description = "Rapid 404 responses indicating path enumeration"
    severity = "MEDIUM"
    mitre_tactic = "TA0043 - Reconnaissance"
    mitre_technique = "T1595 - Active Scanning"

    THRESHOLD = 10

    def evaluate(self, events):
        alerts = []
        ip_404s = defaultdict(list)

        for e in events:
            if e.source_type == "apache" and e.status_code == 404:
                ip_404s[e.source_ip].append(e)

        for ip, hits in ip_404s.items():
            if len(hits) >= self.THRESHOLD:
                paths = [h.metadata.get("path", "") for h in hits[:5]]
                alerts.append(Alert(
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Directory scanning from {ip} — {len(hits)} 404s",
                    evidence=f"Sample: {', '.join(paths)}\nMITRE: {self.mitre_technique}",
                    source_ips=[ip],
                    mitre_tactic=self.mitre_tactic,
                    mitre_technique=self.mitre_technique,
                    event_count=len(hits),
                    timestamp=hits[0].timestamp.isoformat(),
                ))

        return alerts


# ─────────────────────────────────────────────
# Correlation Rules
# ─────────────────────────────────────────────

class ExploitationChainRule(DetectionRule):
    """404 scanning -> injection attempts -> web shell = exploitation chain."""
    name = "Exploitation Chain"
    severity = "CRITICAL"
    mitre_tactic = "TA0001 - Initial Access"
    mitre_technique = "T1190 - Exploit Public-Facing Application"

    def evaluate(self, events):
        alerts = []
        ip_phases = defaultdict(lambda: {"scan": False, "inject": False, "shell": False})

        for e in events:
            if e.source_type != "apache":
                continue
            ip = e.source_ip
            path = e.metadata.get("path", "").lower()

            if e.status_code == 404:
                ip_phases[ip]["scan"] = True
            for pattern, _ in INJECTION_PATTERNS:
                if pattern.search(path):
                    ip_phases[ip]["inject"] = True
            for shell in WEBSHELL_NAMES:
                if shell in path:
                    ip_phases[ip]["shell"] = True

        for ip, phases in ip_phases.items():
            count = sum(phases.values())
            if count >= 2:
                chain = " → ".join(k for k, v in phases.items() if v)
                alerts.append(Alert(
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Exploitation chain detected from {ip}",
                    evidence=f"Phases: {chain}\nMITRE: {self.mitre_technique}",
                    source_ips=[ip],
                    mitre_tactic=self.mitre_tactic,
                    mitre_technique=self.mitre_technique,
                    event_count=count,
                    timestamp="",
                ))

        return alerts


class LateralMovementRule(DetectionRule):
    """Failed logins followed by success + sensitive access from same IP."""
    name = "Lateral Movement"
    severity = "CRITICAL"
    mitre_tactic = "TA0008 - Lateral Movement"
    mitre_technique = "T1021 - Remote Services"

    def evaluate(self, events):
        alerts = []
        ip_actions = defaultdict(lambda: {"fail": 0, "success": False, "sensitive": False})

        for e in events:
            ip = e.source_ip
            if e.action == "LOGIN_FAIL":
                ip_actions[ip]["fail"] += 1
            elif e.action == "LOGIN_OK":
                ip_actions[ip]["success"] = True
            if e.source_type == "apache":
                path = e.metadata.get("path", "").lower()
                for sp in SENSITIVE_PATHS:
                    if sp in path:
                        ip_actions[ip]["sensitive"] = True
                        break

        for ip, actions in ip_actions.items():
            if actions["fail"] >= 3 and actions["success"] and actions["sensitive"]:
                alerts.append(Alert(
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Possible lateral movement from {ip}",
                    evidence=(
                        f"Failed logins: {actions['fail']} → Successful login → Sensitive endpoint access\n"
                        f"MITRE: {self.mitre_technique}"
                    ),
                    source_ips=[ip],
                    mitre_tactic=self.mitre_tactic,
                    mitre_technique=self.mitre_technique,
                    event_count=actions["fail"] + 1,
                    timestamp="",
                ))

        return alerts


# ─────────────────────────────────────────────
# Engine
# ─────────────────────────────────────────────

ALL_RULES = [
    SSHBruteForceRule(),
    HTTPBruteForceRule(),
    UnusualIPLoginRule(),
    SensitiveEndpointRule(),
    PathTraversalRule(),
    InjectionRule(),
    WebShellRule(),
    PrivilegeEscalationRule(),
    AccountManipulationRule(),
    Rapid404ScanRule(),
    ExploitationChainRule(),
    LateralMovementRule(),
]


def run_detection(events, rules=None):
    """
    Run all detection rules against the ingested events.

    Returns
    -------
    list[Alert]
        All alerts from all rules.
    """
    if rules is None:
        rules = ALL_RULES

    all_alerts = []
    for rule in rules:
        alerts = rule.evaluate(events)
        all_alerts.extend(alerts)

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_alerts.sort(key=lambda a: severity_order.get(a.severity, 5))

    return all_alerts

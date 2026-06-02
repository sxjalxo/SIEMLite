#!/usr/bin/env python3
"""
Log Ingestor — Multi-Format Log Ingestion
==========================================
Parses multiple log formats into a normalized internal representation:

  - Apache / Nginx combined access logs
  - SSH auth logs (auth.log / secure)
  - Windows Security Event logs (CSV export)

Auto-detects format by sniffing the first lines of the file.

Usage (standalone):
    python log_ingestor.py <logfile_or_directory>

Design Decision:
    CSV-based Windows log ingestion is used instead of native .evtx parsing
    to reduce dependencies and focus on detection logic rather than binary
    format handling.
"""

import re
import os
import csv
import io
from datetime import datetime
from dataclasses import dataclass, field, asdict

from report import (
    Colors, print_section, print_ok, print_info, print_warn, print_error,
    fix_encoding,
)

# ─────────────────────────────────────────────
# Normalized Event Schema
# ─────────────────────────────────────────────

@dataclass
class LogEvent:
    """Normalized log event — the universal schema that all parsers emit."""
    timestamp: datetime
    source_type: str          # "apache" | "ssh" | "windows"
    source_ip: str
    user: str                 # "-" if unknown
    action: str               # "LOGIN_FAIL", "LOGIN_OK", "REQUEST", "PRIVILEGE_CHANGE", etc.
    detail: str               # path, command, event description
    status_code: int          # HTTP status, Windows event ID, or 0
    raw_line: str
    metadata: dict = field(default_factory=dict)  # UA, referrer, ssh_port, etc.

    def to_dict(self):
        """Convert to a JSON-serializable dict."""
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


# ─────────────────────────────────────────────
# Apache / Nginx Combined Log Parser
# ─────────────────────────────────────────────

APACHE_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'\S+\s+'
    r'\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+'
    r'(?P<path>\S+)\s+'
    r'\S+"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

APACHE_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

AUTH_ENDPOINTS = [
    "/login", "/signin", "/auth", "/admin", "/wp-login.php",
    "/wp-admin", "/user/login", "/account/login", "/api/login",
    "/api/auth", "/oauth", "/sso", "/session",
]


def _classify_apache_action(method, path, status):
    """Classify an Apache log entry into a semantic action."""
    path_lower = path.lower().split("?")[0]
    status = int(status)

    if status in (401, 403) and any(ep in path_lower for ep in AUTH_ENDPOINTS):
        return "LOGIN_FAIL"
    if status == 200 and any(ep in path_lower for ep in AUTH_ENDPOINTS):
        if method.upper() == "POST":
            return "LOGIN_OK"
    return "REQUEST"


def parse_apache(filepath):
    """Parse Apache/Nginx combined log format."""
    events = []
    skipped = 0

    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            m = APACHE_PATTERN.match(line)
            if not m:
                skipped += 1
                continue

            try:
                ts = datetime.strptime(m.group("time"), APACHE_TIME_FMT)
            except ValueError:
                ts = datetime.now()

            action = _classify_apache_action(
                m.group("method"), m.group("path"), m.group("status")
            )

            events.append(LogEvent(
                timestamp=ts,
                source_type="apache",
                source_ip=m.group("ip"),
                user="-",
                action=action,
                detail=f"{m.group('method')} {m.group('path')}",
                status_code=int(m.group("status")),
                raw_line=line,
                metadata={
                    "method": m.group("method"),
                    "path": m.group("path"),
                    "size": m.group("size"),
                    "referrer": m.group("referrer") or "",
                    "ua": m.group("ua") or "",
                },
            ))

    return events, skipped


# ─────────────────────────────────────────────
# SSH Auth Log Parser (auth.log / secure)
# ─────────────────────────────────────────────

SSH_FAILED = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+'
    r'Failed password for (?:invalid user )?(?P<user>\S+)\s+'
    r'from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)',
    re.IGNORECASE,
)

SSH_ACCEPTED = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+'
    r'Accepted (?P<auth_method>\S+) for (?P<user>\S+)\s+'
    r'from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)',
    re.IGNORECASE,
)

SSH_DISCONNECT = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+'
    r'Disconnected from user (?P<user>\S+)\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)',
    re.IGNORECASE,
)

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_ssh_timestamp(month_str, day_str, time_str):
    """Parse SSH log timestamp (no year — assume current year)."""
    month = MONTH_MAP.get(month_str, 1)
    day = int(day_str)
    parts = time_str.split(":")
    hour, minute, second = int(parts[0]), int(parts[1]), int(parts[2])
    year = datetime.now().year
    return datetime(year, month, day, hour, minute, second)


def parse_ssh(filepath):
    """Parse SSH auth.log / secure format."""
    events = []
    skipped = 0

    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue

            # Failed password
            m = SSH_FAILED.match(line)
            if m:
                ts = _parse_ssh_timestamp(m.group("month"), m.group("day"), m.group("time"))
                events.append(LogEvent(
                    timestamp=ts,
                    source_type="ssh",
                    source_ip=m.group("ip"),
                    user=m.group("user"),
                    action="LOGIN_FAIL",
                    detail=f"Failed SSH password for {m.group('user')}",
                    status_code=0,
                    raw_line=line,
                    metadata={
                        "ssh_port": m.group("port"),
                        "host": m.group("host"),
                    },
                ))
                continue

            # Accepted login
            m = SSH_ACCEPTED.match(line)
            if m:
                ts = _parse_ssh_timestamp(m.group("month"), m.group("day"), m.group("time"))
                events.append(LogEvent(
                    timestamp=ts,
                    source_type="ssh",
                    source_ip=m.group("ip"),
                    user=m.group("user"),
                    action="LOGIN_OK",
                    detail=f"Accepted SSH {m.group('auth_method')} for {m.group('user')}",
                    status_code=0,
                    raw_line=line,
                    metadata={
                        "ssh_port": m.group("port"),
                        "host": m.group("host"),
                        "auth_method": m.group("auth_method"),
                    },
                ))
                continue

            # Disconnect
            m = SSH_DISCONNECT.match(line)
            if m:
                ts = _parse_ssh_timestamp(m.group("month"), m.group("day"), m.group("time"))
                events.append(LogEvent(
                    timestamp=ts,
                    source_type="ssh",
                    source_ip=m.group("ip"),
                    user=m.group("user"),
                    action="DISCONNECT",
                    detail=f"SSH disconnect for {m.group('user')}",
                    status_code=0,
                    raw_line=line,
                    metadata={
                        "ssh_port": m.group("port"),
                        "host": m.group("host"),
                    },
                ))
                continue

            # Check if line looks like an SSH log at all (has 'sshd[')
            if "sshd[" in line:
                skipped += 1

    return events, skipped


# ─────────────────────────────────────────────
# Windows Security Event Log Parser (CSV)
# ─────────────────────────────────────────────

# Windows Event IDs we care about
WIN_EVENT_ACTIONS = {
    4624: "LOGIN_OK",
    4625: "LOGIN_FAIL",
    4634: "LOGOFF",
    4647: "LOGOFF",
    4672: "PRIVILEGE_CHANGE",
    4688: "PROCESS_CREATE",
    4720: "ACCOUNT_CREATE",
    4722: "ACCOUNT_ENABLE",
    4726: "ACCOUNT_DELETE",
    4732: "GROUP_ADD_MEMBER",
    4756: "GROUP_ADD_MEMBER",
}

# Regex to extract Source IP from Windows log messages
WIN_IP_PATTERN = re.compile(r'Source\s+IP:\s*(\S+)', re.IGNORECASE)
WIN_USER_FROM_MSG = re.compile(r'User:\s*(\S+)', re.IGNORECASE)
WIN_NEWACCT_PATTERN = re.compile(r'New Account:\s*(\S+)', re.IGNORECASE)
WIN_PROCESS_PATTERN = re.compile(r'Process:\s*(\S+)', re.IGNORECASE)
WIN_CMDLINE_PATTERN = re.compile(r'CommandLine:\s*(.*)', re.IGNORECASE)


def parse_windows_csv(filepath):
    """Parse Windows Security Event Log in CSV format."""
    events = []
    skipped = 0

    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        # Sniff for CSV header
        first_line = fh.readline().strip()
        fh.seek(0)

        if "," not in first_line:
            return events, 0  # Not CSV

        reader = csv.DictReader(fh)
        required_fields = {"EventID", "Message"}

        # Check if the CSV has the required fields (case-insensitive match)
        if not reader.fieldnames:
            return events, 0

        field_map = {}
        for actual in reader.fieldnames:
            for expected in ["TimeGenerated", "EventID", "SourceName", "Category",
                             "UserName", "ComputerName", "Message"]:
                if actual.strip().lower() == expected.lower():
                    field_map[expected] = actual
                    break

        if "EventID" not in field_map or "Message" not in field_map:
            return events, 0

        for row in reader:
            try:
                event_id = int(row.get(field_map.get("EventID", "EventID"), "0").strip())
            except (ValueError, AttributeError):
                skipped += 1
                continue

            action = WIN_EVENT_ACTIONS.get(event_id, "OTHER")
            message = row.get(field_map.get("Message", "Message"), "").strip()
            username = row.get(field_map.get("UserName", "UserName"), "-").strip()
            computer = row.get(field_map.get("ComputerName", "ComputerName"), "-").strip()
            time_str = row.get(field_map.get("TimeGenerated", "TimeGenerated"), "").strip()

            # Parse timestamp
            try:
                ts = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
            except (ValueError, AttributeError):
                ts = datetime.now()

            # Extract source IP from message
            ip_match = WIN_IP_PATTERN.search(message)
            source_ip = ip_match.group(1) if ip_match else "local"

            # Extract target user from message (for failed logins)
            user_from_msg = WIN_USER_FROM_MSG.search(message)
            if user_from_msg and action == "LOGIN_FAIL":
                username = user_from_msg.group(1)

            # Build detail
            detail = message[:200]

            # Enrich metadata
            meta = {
                "computer": computer,
                "event_id": event_id,
                "category": row.get(field_map.get("Category", "Category"), "").strip(),
            }

            # Extract new account name
            new_acct = WIN_NEWACCT_PATTERN.search(message)
            if new_acct:
                meta["new_account"] = new_acct.group(1)

            # Extract process info
            proc_match = WIN_PROCESS_PATTERN.search(message)
            if proc_match:
                meta["process"] = proc_match.group(1)

            cmd_match = WIN_CMDLINE_PATTERN.search(message)
            if cmd_match:
                meta["command_line"] = cmd_match.group(1).strip()

            raw_line = ",".join(row.get(f, "") for f in (reader.fieldnames or []))

            events.append(LogEvent(
                timestamp=ts,
                source_type="windows",
                source_ip=source_ip,
                user=username,
                action=action,
                detail=detail,
                status_code=event_id,
                raw_line=raw_line,
                metadata=meta,
            ))

    return events, skipped


# ─────────────────────────────────────────────
# Format Auto-Detection
# ─────────────────────────────────────────────

def detect_format(filepath):
    """
    Sniff the first 10 lines to auto-detect log format.
    Returns: "apache", "ssh", "windows", or "unknown"
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            lines = []
            for i, line in enumerate(fh):
                if i >= 10:
                    break
                lines.append(line.strip())
    except (IOError, OSError):
        return "unknown"

    if not lines:
        return "unknown"

    # Check for Windows CSV (header row with EventID)
    first = lines[0].lower()
    if "eventid" in first and "," in first:
        return "windows"

    # Check for SSH auth log
    ssh_indicators = 0
    apache_indicators = 0

    for line in lines:
        if "sshd[" in line:
            ssh_indicators += 1
        if APACHE_PATTERN.match(line):
            apache_indicators += 1

    if ssh_indicators > apache_indicators:
        return "ssh"
    if apache_indicators > 0:
        return "apache"

    return "unknown"


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

PARSERS = {
    "apache": parse_apache,
    "ssh": parse_ssh,
    "windows": parse_windows_csv,
}


def ingest_file(filepath, force_format=None):
    """
    Ingest a single log file.

    Parameters
    ----------
    filepath : str
        Path to the log file.
    force_format : str or None
        Force a specific format ("apache", "ssh", "windows").
        If None, auto-detect.

    Returns
    -------
    list[LogEvent]
        Parsed events.
    dict
        Ingestion stats.
    """
    if not os.path.isfile(filepath):
        print_error(f"File not found: {filepath}")
        return [], {"error": f"File not found: {filepath}"}

    fmt = force_format or detect_format(filepath)
    if fmt == "unknown":
        print_warn(f"Could not detect format for: {filepath}")
        return [], {"format": "unknown", "total": 0, "skipped": 0}

    parser = PARSERS.get(fmt)
    if not parser:
        print_error(f"No parser for format: {fmt}")
        return [], {"format": fmt, "total": 0, "skipped": 0}

    events, skipped = parser(filepath)

    stats = {
        "filepath": filepath,
        "format": fmt,
        "total": len(events),
        "skipped": skipped,
        "unique_ips": len(set(e.source_ip for e in events)),
    }

    return events, stats


def ingest_directory(dirpath):
    """
    Ingest all log files from a directory.

    Returns
    -------
    list[LogEvent]
        All parsed events from all files, sorted by timestamp.
    list[dict]
        Per-file ingestion stats.
    """
    all_events = []
    all_stats = []

    log_extensions = {".log", ".txt", ".csv"}

    for fname in sorted(os.listdir(dirpath)):
        fpath = os.path.join(dirpath, fname)
        if not os.path.isfile(fpath):
            continue

        _, ext = os.path.splitext(fname)
        if ext.lower() not in log_extensions:
            continue

        events, stats = ingest_file(fpath)
        if events:
            all_events.extend(events)
            all_stats.append(stats)
            print_ok(f"  {fname}: {stats['total']} events ({stats['format']})")

    # Sort by timestamp
    all_events.sort(key=lambda e: e.timestamp)

    return all_events, all_stats


def ingest(path):
    """
    Ingest a file or directory of log files.

    Returns
    -------
    list[LogEvent], list[dict]
    """
    print_section("Log Ingestion", ">>>")

    if os.path.isdir(path):
        print_info(f"Scanning directory: {path}")
        events, stats = ingest_directory(path)
        total = sum(s["total"] for s in stats)
        unique_ips = len(set(e.source_ip for e in events))
        formats = set(s["format"] for s in stats)
        print_ok(
            f"Ingested {total} events from {len(stats)} file(s) "
            f"({', '.join(formats)}) — {unique_ips} unique IPs"
        )
        return events, stats

    else:
        print_info(f"Ingesting file: {path}")
        events, stats = ingest_file(path)
        print_ok(
            f"Ingested {stats.get('total', 0)} events "
            f"({stats.get('format', '?')}) — {stats.get('unique_ips', 0)} unique IPs"
        )
        return events, [stats]


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def severity_action_color(action):
    """Return color for an action type."""
    return {
        "LOGIN_FAIL": Colors.RED,
        "LOGIN_OK": Colors.GREEN,
        "PRIVILEGE_CHANGE": Colors.MAGENTA,
        "ACCOUNT_CREATE": Colors.YELLOW,
        "ACCOUNT_DELETE": Colors.RED,
        "PROCESS_CREATE": Colors.YELLOW,
        "REQUEST": Colors.DIM,
        "DISCONNECT": Colors.DIM,
    }.get(action, Colors.RESET)


# ─────────────────────────────────────────────
# Standalone Entry Point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    fix_encoding()

    if len(sys.argv) < 2:
        print(f"  {Colors.RED}Usage: python log_ingestor.py <logfile_or_directory>{Colors.RESET}")
        sys.exit(1)

    target = sys.argv[1]
    events, stats = ingest(target)

    # Print summary
    print_section("Ingestion Summary", ">>>")
    for evt in events[:20]:
        ts = evt.timestamp.strftime("%H:%M:%S")
        print(f"  {Colors.DIM}[{ts}]{Colors.RESET} "
              f"{Colors.CYAN}{evt.source_type:>8}{Colors.RESET} "
              f"{evt.source_ip:>16} "
              f"{severity_action_color(evt.action)}{evt.action:<18}{Colors.RESET} "
              f"{evt.detail[:60]}")

    if len(events) > 20:
        print(f"  {Colors.DIM}... and {len(events) - 20} more events{Colors.RESET}")



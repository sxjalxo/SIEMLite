#!/usr/bin/env python3
"""
Log Analyzer Module
====================
Parses web server access logs (Apache / Nginx combined format) and detects:

  - Brute-force login attempts (repeated 401/403 to auth endpoints)
  - Suspicious IP frequency (abnormally high request counts)
  - Directory / path scanning (burst of 404 responses)
  - Potential web shell access patterns
  - SQL injection / XSS attempts in request URIs

Usage (standalone):
    python log_analyzer.py access.log

The module also exposes ``analyze_log(path)`` so it can be imported by main.py.
"""

import re
import sys
import os
from collections import defaultdict, Counter
from datetime import datetime

from report import (
    Colors, Finding,
    print_section, print_finding, print_ok, print_info, print_warn, print_error,
    fix_encoding,
)

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

# Thresholds (tune these for real-world use)
BRUTE_FORCE_THRESHOLD = 5        # failed logins from one IP
HIGH_FREQ_THRESHOLD = 100        # total requests from one IP
SCAN_404_THRESHOLD = 10          # 404 responses from one IP
SHELL_PATTERNS_THRESHOLD = 2     # suspicious shell-like accesses from one IP

# Endpoints commonly targeted by brute-force attacks
AUTH_ENDPOINTS = [
    "/login", "/signin", "/auth", "/admin", "/wp-login.php",
    "/wp-admin", "/user/login", "/account/login", "/api/login",
    "/api/auth", "/oauth", "/sso", "/session",
]

# Regex for Apache / Nginx combined log format:
#   IP - - [datetime] "METHOD /path HTTP/x.x" status size "referrer" "UA"
# Also handles common log format (without referrer/UA).
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+'           # client IP
    r'\S+\s+'                     # ident (usually -)
    r'\S+\s+'                     # auth user (usually -)
    r'\[(?P<time>[^\]]+)\]\s+'    # [datetime]
    r'"(?P<method>\S+)\s+'        # "METHOD
    r'(?P<path>\S+)\s+'           #  /path
    r'\S+"\s+'                    #  HTTP/x.x"
    r'(?P<status>\d{3})\s+'       # status code
    r'(?P<size>\S+)'              # response size
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)")?'  # optional referrer & UA
)

# Suspicious URI patterns (SQLi / XSS / traversal in the URL itself)
SUSPICIOUS_URI_PATTERNS = [
    (re.compile(r"(\.\./|\.\.\\)", re.I), "Path traversal"),
    (re.compile(r"(union\s+select|order\s+by\s+\d|'.*or.*')", re.I), "SQL Injection"),
    (re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=)", re.I), "XSS attempt"),
    (re.compile(r"(/etc/passwd|/etc/shadow|cmd\.exe|powershell)", re.I), "OS command / file access"),
    (re.compile(r"(\.php\?|\.asp\?|\.jsp\?).*=.*(select|union|concat|char\()", re.I), "SQLi via query"),
]

# Common web-shell filenames
WEBSHELL_NAMES = [
    "c99.php", "r57.php", "wso.php", "b374k.php", "shell.php",
    "cmd.php", "webshell.php", "backdoor.php", "evil.php",
    "upload.php", "filemanager.php",
]


# ─────────────────────────────────────────────
# Log Parser
# ─────────────────────────────────────────────

def parse_log_file(filepath):
    """
    Parse each line of a log file into structured dicts.
    Returns (entries, skipped_count).
    """
    entries = []
    skipped = 0

    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            m = LOG_PATTERN.match(line)
            if m:
                entries.append({
                    "ip": m.group("ip"),
                    "time": m.group("time"),
                    "method": m.group("method"),
                    "path": m.group("path"),
                    "status": int(m.group("status")),
                    "size": m.group("size"),
                    "referrer": m.group("referrer") or "",
                    "ua": m.group("ua") or "",
                    "line_no": line_no,
                    "raw": line,
                })
            else:
                skipped += 1

    return entries, skipped


# ─────────────────────────────────────────────
# Detection Functions
# ─────────────────────────────────────────────

def detect_brute_force(entries):
    """Detect brute-force login attempts (multiple 401/403 to auth endpoints)."""
    findings = []
    failed_logins = defaultdict(list)  # ip -> [path, ...]

    for e in entries:
        if e["status"] in (401, 403):
            path_lower = e["path"].lower().split("?")[0]
            if any(ep in path_lower for ep in AUTH_ENDPOINTS):
                failed_logins[e["ip"]].append(e["path"])

    for ip, attempts in sorted(failed_logins.items(), key=lambda x: len(x[1]), reverse=True):
        if len(attempts) >= BRUTE_FORCE_THRESHOLD:
            targets = Counter(attempts).most_common(3)
            target_str = ", ".join(f"{p} (x{c})" for p, c in targets)
            f = Finding(
                category="Brute Force",
                severity="HIGH",
                detail=f"Possible brute-force attack from {ip} — {len(attempts)} failed login attempts",
                evidence=f"Targets: {target_str}",
            )
            findings.append(f)

    return findings


def detect_high_frequency(entries):
    """Detect IPs with abnormally high request counts."""
    findings = []
    ip_counts = Counter(e["ip"] for e in entries)

    for ip, count in ip_counts.most_common():
        if count >= HIGH_FREQ_THRESHOLD:
            # Gather status distribution
            statuses = Counter(e["status"] for e in entries if e["ip"] == ip)
            status_str = ", ".join(f"{s}: {c}" for s, c in statuses.most_common(5))
            f = Finding(
                category="Suspicious Frequency",
                severity="MEDIUM",
                detail=f"High request volume from {ip} — {count} requests",
                evidence=f"Status distribution: {status_str}",
            )
            findings.append(f)

    return findings


def detect_404_scanning(entries):
    """Detect directory / path scanning (burst of 404 responses from one IP)."""
    findings = []
    ip_404s = defaultdict(list)

    for e in entries:
        if e["status"] == 404:
            ip_404s[e["ip"]].append(e["path"])

    for ip, paths in sorted(ip_404s.items(), key=lambda x: len(x[1]), reverse=True):
        if len(paths) >= SCAN_404_THRESHOLD:
            sample = paths[:5]
            sample_str = ", ".join(sample)
            if len(paths) > 5:
                sample_str += f" ... (+{len(paths) - 5} more)"
            f = Finding(
                category="404 Scanning",
                severity="MEDIUM",
                detail=f"Path enumeration from {ip} — {len(paths)} 404 responses",
                evidence=f"Sample paths: {sample_str}",
            )
            findings.append(f)

    return findings


def detect_suspicious_uris(entries):
    """Detect SQLi / XSS / traversal attempts embedded in request URIs."""
    findings = []
    ip_hits = defaultdict(list)  # ip -> [(pattern_name, path), ...]

    for e in entries:
        for pattern, name in SUSPICIOUS_URI_PATTERNS:
            if pattern.search(e["path"]):
                ip_hits[e["ip"]].append((name, e["path"]))

    for ip, hits in sorted(ip_hits.items(), key=lambda x: len(x[1]), reverse=True):
        if hits:
            by_type = Counter(h[0] for h in hits)
            type_str = ", ".join(f"{t} (x{c})" for t, c in by_type.most_common())
            sample_path = hits[0][1][:120]
            f = Finding(
                category="Malicious URI",
                severity="HIGH",
                detail=f"Suspicious URI patterns from {ip} — {len(hits)} hit(s)",
                evidence=f"Types: {type_str}\nSample: {sample_path}",
            )
            findings.append(f)

    return findings


def detect_webshell_access(entries):
    """Detect attempts to access known web-shell filenames."""
    findings = []
    ip_hits = defaultdict(list)

    for e in entries:
        path_lower = e["path"].lower()
        for shell_name in WEBSHELL_NAMES:
            if shell_name in path_lower:
                ip_hits[e["ip"]].append(e["path"])

    for ip, paths in ip_hits.items():
        if len(paths) >= SHELL_PATTERNS_THRESHOLD:
            f = Finding(
                category="Web Shell",
                severity="HIGH",
                detail=f"Possible web-shell access from {ip} — {len(paths)} hit(s)",
                evidence=f"Paths: {', '.join(list(set(paths))[:5])}",
            )
            findings.append(f)

    return findings


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def analyze_log(filepath):
    """
    Run all log-analysis detections on the given file.

    Returns
    -------
    list[Finding]
        All findings from every detection module.
    dict
        Summary stats (total_entries, skipped_lines, unique_ips, etc.)
    """
    print_section("Log Analysis", ">>>")

    if not os.path.isfile(filepath):
        print_error(f"File not found: {filepath}")
        return [], {}

    print_info(f"Parsing {filepath} ...")
    entries, skipped = parse_log_file(filepath)
    unique_ips = len(set(e["ip"] for e in entries))

    stats = {
        "total_entries": len(entries),
        "skipped_lines": skipped,
        "unique_ips": unique_ips,
        "filepath": filepath,
    }

    print_ok(f"Parsed {len(entries)} entries ({skipped} skipped, {unique_ips} unique IPs).")

    if not entries:
        print_warn("No parseable log entries found. Check format (Apache/Nginx combined).")
        return [], stats

    all_findings = []

    # Run detectors
    print_section("Brute-Force Detection", ">>>")
    bf = detect_brute_force(entries)
    all_findings.extend(bf)
    if bf:
        for f in bf:
            print_finding(f)
    else:
        print_ok("No brute-force patterns detected.")

    print_section("Request Frequency Analysis", ">>>")
    hf = detect_high_frequency(entries)
    all_findings.extend(hf)
    if hf:
        for f in hf:
            print_finding(f)
    else:
        print_ok("No unusually high-frequency IPs detected.")

    print_section("404 Path Scanning Detection", ">>>")
    s404 = detect_404_scanning(entries)
    all_findings.extend(s404)
    if s404:
        for f in s404:
            print_finding(f)
    else:
        print_ok("No 404-scanning patterns detected.")

    print_section("Malicious URI Detection", ">>>")
    sus = detect_suspicious_uris(entries)
    all_findings.extend(sus)
    if sus:
        for f in sus:
            print_finding(f)
    else:
        print_ok("No suspicious URI patterns detected.")

    print_section("Web Shell Access Detection", ">>>")
    ws = detect_webshell_access(entries)
    all_findings.extend(ws)
    if ws:
        for f in ws:
            print_finding(f)
    else:
        print_ok("No web-shell access patterns detected.")

    return all_findings, stats


# ─────────────────────────────────────────────
# Standalone Entry Point
# ─────────────────────────────────────────────

def main():
    fix_encoding()

    if len(sys.argv) < 2:
        print(f"  {Colors.RED}Usage: python log_analyzer.py <logfile>{Colors.RESET}")
        print(f"  {Colors.DIM}Example: python log_analyzer.py access.log{Colors.RESET}\n")
        sys.exit(1)

    from report import generate_report
    filepath = sys.argv[1]
    findings, stats = analyze_log(filepath)
    generate_report(f"Log Analysis — {filepath}", findings)


if __name__ == "__main__":
    main()

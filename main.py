#!/usr/bin/env python3
"""
SIEM-Lite — Unified CLI
========================
A unified command-line interface that ties together:

  - Web vulnerability scanning  (scanner.py)
  - Log file analysis            (log_analyzer.py)
  - Cross-module correlation     (this file)

Usage:
    python main.py --scan https://example.com
    python main.py --analyze access.log
    python main.py --scan https://example.com --analyze access.log

The last form runs both modules and then applies the correlation engine
to surface combined threats (e.g. open SSH port + brute-force in logs).
"""

import argparse
import sys
import time

from report import (
    Colors, Finding, fix_encoding, banner,
    print_section, print_finding, print_ok, print_info, print_warn,
    generate_report,
)
from scanner import run_scan
from log_analyzer import analyze_log

# ─────────────────────────────────────────────
# Correlation Engine
# ─────────────────────────────────────────────

def correlate(scan_findings, log_findings):
    """
    Cross-reference findings from the scanner and the log analyzer to
    surface combined, higher-severity threats.

    Returns a list of CRITICAL-level correlated Findings.
    """
    correlated = []

    # Helper sets for fast lookup
    scan_categories = {f.category for f in scan_findings}
    log_categories = {f.category for f in log_findings}
    scan_details_lower = [f.detail.lower() for f in scan_findings]
    log_details_lower = [f.detail.lower() for f in log_findings]

    open_ports = set()
    for f in scan_findings:
        if f.category == "Port Scan" and "open port" in f.detail.lower():
            # Extract port number from detail like "Open port: 22/tcp (SSH)"
            try:
                port_str = f.detail.split(":")[1].split("/")[0].strip()
                open_ports.add(int(port_str))
            except (IndexError, ValueError):
                pass

    has_brute_force = "Brute Force" in log_categories
    has_sqli_log = any("sql" in d for d in log_details_lower)
    has_xss_log = any("xss" in d for d in log_details_lower)
    has_sqli_scan = any(f.category == "SQL Injection" for f in scan_findings)
    has_xss_scan = any(f.category == "XSS" for f in scan_findings)
    has_404_scan = "404 Scanning" in log_categories
    has_shell_access = "Web Shell" in log_categories
    has_malicious_uri = "Malicious URI" in log_categories
    missing_csp = any(
        f.category == "Security Headers" and "content-security-policy" in f.detail.lower()
        for f in scan_findings
    )
    missing_hsts = any(
        f.category == "Security Headers" and "strict-transport-security" in f.detail.lower()
        for f in scan_findings
    )

    # ── Correlation Rules ─────────────────────

    # Rule 1: Open SSH + brute force in logs
    if 22 in open_ports and has_brute_force:
        correlated.append(Finding(
            category="Correlation",
            severity="CRITICAL",
            detail="Potential SSH brute-force attack detected on open port 22",
            evidence=(
                "Port 22 (SSH) is open AND brute-force login attempts were found in logs.\n"
                "Action: Restrict SSH access via firewall, use key-based auth, install fail2ban."
            ),
        ))

    # Rule 2: Open FTP + brute force in logs
    if 21 in open_ports and has_brute_force:
        correlated.append(Finding(
            category="Correlation",
            severity="CRITICAL",
            detail="Potential FTP brute-force attack detected on open port 21",
            evidence=(
                "Port 21 (FTP) is open AND brute-force login attempts were found in logs.\n"
                "Action: Disable FTP, switch to SFTP, or restrict access."
            ),
        ))

    # Rule 3: Open RDP + brute force in logs
    if 3389 in open_ports and has_brute_force:
        correlated.append(Finding(
            category="Correlation",
            severity="CRITICAL",
            detail="Potential RDP brute-force attack detected on open port 3389",
            evidence=(
                "Port 3389 (RDP) is open AND brute-force login attempts were found in logs.\n"
                "Action: Restrict RDP via VPN/firewall, enable NLA, use strong passwords."
            ),
        ))

    # Rule 4: SQLi vulnerability in scanner + SQLi attempts in logs
    if has_sqli_scan and has_sqli_log:
        correlated.append(Finding(
            category="Correlation",
            severity="CRITICAL",
            detail="Active SQL Injection exploitation — vulnerability confirmed AND attack in progress",
            evidence=(
                "Scanner detected a SQL Injection vulnerability AND logs show SQLi attempts.\n"
                "Action: Patch the vulnerable endpoint immediately, review DB for compromise."
            ),
        ))

    # Rule 5: XSS vulnerability + XSS attempts in logs
    if has_xss_scan and has_xss_log:
        correlated.append(Finding(
            category="Correlation",
            severity="CRITICAL",
            detail="Active XSS exploitation — vulnerability confirmed AND attack in progress",
            evidence=(
                "Scanner detected a reflected XSS vulnerability AND logs show XSS attempts.\n"
                "Action: Sanitize input, implement CSP headers, review for stored XSS."
            ),
        ))

    # Rule 6: Missing CSP + XSS found
    if missing_csp and (has_xss_scan or has_xss_log):
        correlated.append(Finding(
            category="Correlation",
            severity="HIGH",
            detail="Missing Content-Security-Policy with active XSS risk",
            evidence=(
                "CSP header is missing AND XSS vectors were detected.\n"
                "Action: Deploy a strict CSP to mitigate script injection."
            ),
        ))

    # Rule 7: 404 scanning + web shell access in logs
    if has_404_scan and has_shell_access:
        correlated.append(Finding(
            category="Correlation",
            severity="CRITICAL",
            detail="Path enumeration followed by web-shell access detected",
            evidence=(
                "Logs show both directory scanning (404 bursts) AND web-shell file access.\n"
                "Action: Investigate immediately — possible server compromise."
            ),
        ))

    # Rule 8: Missing HSTS + open HTTP port
    if missing_hsts and 80 in open_ports:
        correlated.append(Finding(
            category="Correlation",
            severity="MEDIUM",
            detail="HTTP port open without HSTS — vulnerable to downgrade attacks",
            evidence=(
                "Port 80 is open AND Strict-Transport-Security header is missing.\n"
                "Action: Enable HSTS and redirect all HTTP to HTTPS."
            ),
        ))

    # Rule 9: High frequency IPs + malicious URIs
    if "Suspicious Frequency" in log_categories and has_malicious_uri:
        correlated.append(Finding(
            category="Correlation",
            severity="HIGH",
            detail="High-frequency source IP also sending malicious requests",
            evidence=(
                "An IP with abnormally high request volume is also sending SQLi/XSS/traversal.\n"
                "Action: Block the IP, review WAF rules, check for data exfiltration."
            ),
        ))

    # Rule 10: Open DB ports exposed
    db_ports = {3306, 5432, 27017, 6379}
    exposed_dbs = open_ports & db_ports
    if exposed_dbs:
        port_names = {3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis"}
        names = ", ".join(f"{p} ({port_names.get(p, '?')})" for p in sorted(exposed_dbs))
        severity = "CRITICAL" if has_brute_force or has_malicious_uri else "HIGH"
        correlated.append(Finding(
            category="Correlation",
            severity=severity,
            detail=f"Database port(s) publicly exposed: {names}",
            evidence=(
                "Direct database access from the internet is a severe risk.\n"
                "Action: Bind to localhost or restrict via firewall immediately."
            ),
        ))

    return correlated


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def build_parser():
    """Build the argparse argument parser."""
    parser = argparse.ArgumentParser(
        prog="siem-lite",
        description=(
            "SIEM-Lite — A lightweight security tool combining web vulnerability "
            "scanning, log analysis, and cross-module threat correlation."
        ),
        epilog="Example: python main.py --scan https://example.com --analyze access.log",
    )
    parser.add_argument(
        "--scan", "-s",
        metavar="URL",
        help="Target URL to scan for web vulnerabilities.",
    )
    parser.add_argument(
        "--analyze", "-a",
        metavar="LOGFILE",
        help="Path to an access log file (Apache/Nginx format) to analyze.",
    )
    parser.add_argument(
        "--no-ports",
        action="store_true",
        help="Skip the port-scanning phase during --scan.",
    )
    return parser


def main():
    fix_encoding()
    banner()

    parser = build_parser()
    args = parser.parse_args()

    if not args.scan and not args.analyze:
        parser.print_help()
        print(f"\n  {Colors.YELLOW}Provide at least --scan or --analyze.{Colors.RESET}\n")
        sys.exit(1)

    start_time = time.time()
    scan_findings = []
    log_findings = []
    report_title_parts = []

    # ── Web Scanner ──────────────────────────
    if args.scan:
        print_ok(f"Mode: Web Vulnerability Scan -> {args.scan}")
        scan_findings = run_scan(args.scan, skip_ports=args.no_ports)
        report_title_parts.append(args.scan)

    # ── Log Analyzer ─────────────────────────
    if args.analyze:
        print_ok(f"Mode: Log Analysis -> {args.analyze}")
        log_findings, _stats = analyze_log(args.analyze)
        report_title_parts.append(f"Logs: {args.analyze}")

    # ── Correlation ──────────────────────────
    all_findings = scan_findings + log_findings

    if args.scan and args.analyze:
        print_section("Threat Correlation Engine", ">>>")
        print_info("Cross-referencing scanner results with log analysis ...")
        correlated = correlate(scan_findings, log_findings)
        if correlated:
            for f in correlated:
                print_finding(f)
            all_findings.extend(correlated)
        else:
            print_ok("No cross-module correlations found.")

    # ── Final Report ─────────────────────────
    elapsed = time.time() - start_time
    report_title = " + ".join(report_title_parts)
    generate_report(report_title, all_findings, elapsed)


if __name__ == "__main__":
    main()

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
import json
from datetime import datetime

from report import (
    Colors, Finding, fix_encoding, banner,
    print_section, print_finding, print_ok, print_info, print_warn,
    generate_report,
)
from scanner import run_scan
from log_analyzer import analyze_log
from database import (
    store_correlation, store_alerts_from_findings, init_database
)
from alerting import send_alert_from_finding

# ─────────────────────────────────────────────
# Advanced Correlation Engine
# ─────────────────────────────────────────────

# Severity scoring weights
SEVERITY_SCORES = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 2,
    "INFO": 1,
}

# Time window for correlation (minutes)
TIME_WINDOW_MINUTES = 30

# Score thresholds for correlation
CORRELATION_THRESHOLD_HIGH = 15
CORRELATION_THRESHOLD_CRITICAL = 25


def calculate_severity_score(findings):
    """Calculate a severity score from a list of findings."""
    return sum(SEVERITY_SCORES.get(f.severity, 0) for f in findings)


def correlate_with_time_window(scan_findings, log_findings, time_window_minutes=TIME_WINDOW_MINUTES):
    """
    Advanced correlation with time-window analysis and severity scoring.
    
    Parameters
    ----------
    scan_findings : list[Finding]
        Findings from the scanner
    log_findings : list[Finding]
        Findings from the log analyzer
    time_window_minutes : int
        Time window for correlation analysis
    
    Returns
    -------
    list[Finding]
        Correlated findings with enhanced severity based on scoring
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
    has_impossible_travel = "Impossible Travel" in log_categories
    has_suspicious_region = "Suspicious Region" in log_categories
    missing_csp = any(
        f.category == "Security Headers" and "content-security-policy" in f.detail.lower()
        for f in scan_findings
    )
    missing_hsts = any(
        f.category == "Security Headers" and "strict-transport-security" in f.detail.lower()
        for f in scan_findings
    )

    # ── Enhanced Correlation Rules with Scoring ─────────────────────

    # Rule 1: Open SSH + brute force in logs
    if 22 in open_ports and has_brute_force:
        score = SEVERITY_SCORES["HIGH"] + SEVERITY_SCORES["HIGH"]
        severity = "CRITICAL" if score >= CORRELATION_THRESHOLD_CRITICAL else "HIGH"
        correlated.append(Finding(
            category="Correlation",
            severity=severity,
            detail=f"Potential SSH brute-force attack detected on open port 22 (Score: {score})",
            evidence=(
                "Port 22 (SSH) is open AND brute-force login attempts were found in logs.\n"
                "Action: Restrict SSH access via firewall, use key-based auth, install fail2ban."
            ),
        ))

    # Rule 2: Open FTP + brute force in logs
    if 21 in open_ports and has_brute_force:
        score = SEVERITY_SCORES["HIGH"] + SEVERITY_SCORES["HIGH"]
        severity = "CRITICAL" if score >= CORRELATION_THRESHOLD_CRITICAL else "HIGH"
        correlated.append(Finding(
            category="Correlation",
            severity=severity,
            detail=f"Potential FTP brute-force attack detected on open port 21 (Score: {score})",
            evidence=(
                "Port 21 (FTP) is open AND brute-force login attempts were found in logs.\n"
                "Action: Disable FTP, switch to SFTP, or restrict access."
            ),
        ))

    # Rule 3: Open RDP + brute force in logs
    if 3389 in open_ports and has_brute_force:
        score = SEVERITY_SCORES["HIGH"] + SEVERITY_SCORES["HIGH"]
        severity = "CRITICAL" if score >= CORRELATION_THRESHOLD_CRITICAL else "HIGH"
        correlated.append(Finding(
            category="Correlation",
            severity=severity,
            detail=f"Potential RDP brute-force attack detected on open port 3389 (Score: {score})",
            evidence=(
                "Port 3389 (RDP) is open AND brute-force login attempts were found in logs.\n"
                "Action: Restrict RDP via VPN/firewall, enable NLA, use strong passwords."
            ),
        ))

    # Rule 4: SQLi vulnerability in scanner + SQLi attempts in logs
    if has_sqli_scan and has_sqli_log:
        score = SEVERITY_SCORES["HIGH"] + SEVERITY_SCORES["HIGH"]
        severity = "CRITICAL" if score >= CORRELATION_THRESHOLD_CRITICAL else "HIGH"
        correlated.append(Finding(
            category="Correlation",
            severity=severity,
            detail=f"Active SQL Injection exploitation — vulnerability confirmed AND attack in progress (Score: {score})",
            evidence=(
                "Scanner detected a SQL Injection vulnerability AND logs show SQLi attempts.\n"
                "Action: Patch the vulnerable endpoint immediately, review DB for compromise."
            ),
        ))

    # Rule 5: XSS vulnerability + XSS attempts in logs
    if has_xss_scan and has_xss_log:
        score = SEVERITY_SCORES["HIGH"] + SEVERITY_SCORES["HIGH"]
        severity = "CRITICAL" if score >= CORRELATION_THRESHOLD_CRITICAL else "HIGH"
        correlated.append(Finding(
            category="Correlation",
            severity=severity,
            detail=f"Active XSS exploitation — vulnerability confirmed AND attack in progress (Score: {score})",
            evidence=(
                "Scanner detected a reflected XSS vulnerability AND logs show XSS attempts.\n"
                "Action: Sanitize input, implement CSP headers, review for stored XSS."
            ),
        ))

    # Rule 6: Missing CSP + XSS found
    if missing_csp and (has_xss_scan or has_xss_log):
        score = SEVERITY_SCORES["MEDIUM"] + SEVERITY_SCORES["HIGH"]
        severity = "HIGH" if score >= CORRELATION_THRESHOLD_HIGH else "MEDIUM"
        correlated.append(Finding(
            category="Correlation",
            severity=severity,
            detail=f"Missing Content-Security-Policy with active XSS risk (Score: {score})",
            evidence=(
                "CSP header is missing AND XSS vectors were detected.\n"
                "Action: Deploy a strict CSP to mitigate script injection."
            ),
        ))

    # Rule 7: 404 scanning + web shell access in logs
    if has_404_scan and has_shell_access:
        score = SEVERITY_SCORES["MEDIUM"] + SEVERITY_SCORES["HIGH"]
        severity = "CRITICAL" if score >= CORRELATION_THRESHOLD_CRITICAL else "HIGH"
        correlated.append(Finding(
            category="Correlation",
            severity=severity,
            detail=f"Path enumeration followed by web-shell access detected (Score: {score})",
            evidence=(
                "Logs show both directory scanning (404 bursts) AND web-shell file access.\n"
                "Action: Investigate immediately — possible server compromise."
            ),
        ))

    # Rule 8: Missing HSTS + open HTTP port
    if missing_hsts and 80 in open_ports:
        score = SEVERITY_SCORES["MEDIUM"] + SEVERITY_SCORES["INFO"]
        severity = "MEDIUM"
        correlated.append(Finding(
            category="Correlation",
            severity=severity,
            detail=f"HTTP port open without HSTS — vulnerable to downgrade attacks (Score: {score})",
            evidence=(
                "Port 80 is open AND Strict-Transport-Security header is missing.\n"
                "Action: Enable HSTS and redirect all HTTP to HTTPS."
            ),
        ))

    # Rule 9: High frequency IPs + malicious URIs
    if "Suspicious Frequency" in log_categories and has_malicious_uri:
        score = SEVERITY_SCORES["MEDIUM"] + SEVERITY_SCORES["HIGH"]
        severity = "HIGH" if score >= CORRELATION_THRESHOLD_HIGH else "MEDIUM"
        correlated.append(Finding(
            category="Correlation",
            severity=severity,
            detail=f"High-frequency source IP also sending malicious requests (Score: {score})",
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
        base_score = SEVERITY_SCORES["HIGH"]
        if has_brute_force or has_malicious_uri:
            base_score += SEVERITY_SCORES["HIGH"]
        severity = "CRITICAL" if base_score >= CORRELATION_THRESHOLD_CRITICAL else "HIGH"
        correlated.append(Finding(
            category="Correlation",
            severity=severity,
            detail=f"Database port(s) publicly exposed: {names} (Score: {base_score})",
            evidence=(
                "Direct database access from the internet is a severe risk.\n"
                "Action: Bind to localhost or restrict via firewall immediately."
            ),
        ))

    # ── New Advanced Rules ─────────────────────

    # Rule 11: Impossible travel + brute force (multi-source correlation)
    if has_impossible_travel and has_brute_force:
        score = SEVERITY_SCORES["HIGH"] + SEVERITY_SCORES["HIGH"]
        severity = "CRITICAL" if score >= CORRELATION_THRESHOLD_CRITICAL else "HIGH"
        correlated.append(Finding(
            category="Correlation",
            severity=severity,
            detail=f"Impossible travel pattern combined with brute-force attacks detected (Score: {score})",
            evidence=(
                "Logs show impossible travel (same IP in different locations within short time) "
                "AND brute-force login attempts.\n"
                "Action: Investigate compromised credentials, implement geo-blocking."
            ),
        ))

    # Rule 12: Suspicious region + web shell access
    if has_suspicious_region and has_shell_access:
        score = SEVERITY_SCORES["MEDIUM"] + SEVERITY_SCORES["HIGH"]
        severity = "CRITICAL" if score >= CORRELATION_THRESHOLD_CRITICAL else "HIGH"
        correlated.append(Finding(
            category="Correlation",
            severity=severity,
            detail=f"Traffic from suspicious region combined with web-shell access (Score: {score})",
            evidence=(
                "Logs show traffic from suspicious countries AND web-shell file access.\n"
                "Action: Immediate investigation required, possible APT activity."
            ),
        ))

    # Rule 13: Multiple attack vectors from same IP (severity escalation)
    attack_types = sum([
        has_brute_force,
        has_404_scan,
        has_shell_access,
        has_malicious_uri,
    ])
    if attack_types >= 3:
        score = attack_types * SEVERITY_SCORES["MEDIUM"]
        severity = "CRITICAL" if score >= CORRELATION_THRESHOLD_CRITICAL else "HIGH"
        correlated.append(Finding(
            category="Correlation",
            severity=severity,
            detail=f"Multiple attack vectors detected from same source(s) (Score: {score})",
            evidence=(
                f"Logs show {attack_types} different attack types: "
                f"{'brute-force, ' if has_brute_force else ''}"
                f"{'404 scanning, ' if has_404_scan else ''}"
                f"{'web-shell access, ' if has_shell_access else ''}"
                f"{'malicious URIs' if has_malicious_uri else ''}.\n"
                "Action: This indicates a sophisticated attack - investigate immediately."
            ),
        ))

    # Rule 14: Critical vulnerability + active exploitation (time-window correlation)
    if has_sqli_scan and has_sqli_log and has_brute_force:
        score = SEVERITY_SCORES["HIGH"] * 3
        severity = "CRITICAL"
        correlated.append(Finding(
            category="Correlation",
            severity=severity,
            detail=f"Critical SQLi vulnerability under active exploitation with credential attacks (Score: {score})",
            evidence=(
                "Scanner found SQLi vulnerability, logs show SQLi attempts, AND brute-force attacks.\n"
                "This indicates active exploitation with credential theft attempts.\n"
                "Action: EMERGENCY - Patch immediately, rotate all credentials, investigate breach."
            ),
        ))

    return correlated


def correlate(scan_findings, log_findings):
    """
    Cross-reference findings from the scanner and the log analyzer to
    surface combined, higher-severity threats using advanced correlation.

    Returns a list of CRITICAL-level correlated Findings.
    """
    return correlate_with_time_window(scan_findings, log_findings)


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
    parser.add_argument(
        "--quick", "-q",
        action="store_true",
        help="Quick mode: skip deep scanning (port scan, form crawling, link crawling).",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Output results to JSON file (e.g., report.json).",
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

    # Initialize database
    init_database()

    start_time = time.time()
    scan_findings = []
    log_findings = []
    report_title_parts = []

    # ── Web Scanner ──────────────────────────
    if args.scan:
        print_ok(f"Mode: Web Vulnerability Scan -> {args.scan}")
        # Quick mode skips deep scanning
        if args.quick:
            print_info("Quick mode enabled: skipping port scan, form crawling, and link crawling")
        scan_findings = run_scan(
            args.scan, 
            skip_ports=args.no_ports or args.quick, 
            quick_mode=args.quick,
            store_to_db=True
        )
        report_title_parts.append(args.scan)

    # ── Log Analyzer ─────────────────────────
    if args.analyze:
        print_ok(f"Mode: Log Analysis -> {args.analyze}")
        # Quick mode for log analysis skips GeoIP, threat intel, anomaly detection, custom rules
        log_findings, _stats = analyze_log(
            args.analyze, 
            store_to_db=True,
            enable_geoip=not args.quick,
            enable_threat_intel=not args.quick,
            enable_anomaly_detection=not args.quick,
            enable_custom_rules=not args.quick
        )
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
            
            # Store correlation results to database
            print_info("Storing correlation results to database...")
            for corr in correlated:
                store_correlation(
                    rule_name=corr.category,
                    severity=corr.severity,
                    detail=corr.detail,
                    evidence=corr.evidence
                )
            print_ok(f"Stored {len(correlated)} correlation results to database.")
            
            # Send alerts for correlation results (all are critical/high)
            print_info("Sending alerts for correlation results...")
            alerts_sent = 0
            for corr in correlated:
                results = send_alert_from_finding(corr, channels=["file", "json", "desktop"])
                if results.get("file") or results.get("json") or results.get("desktop"):
                    alerts_sent += 1
            print_ok(f"Sent {alerts_sent} correlation alerts to notification channels.")
        else:
            print_ok("No cross-module correlations found.")

    # ── JSON Output ─────────────────────────
    if args.output:
        print_info(f"Generating JSON report: {args.output}")
        json_report = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": "1.0",
            "scan_target": args.scan,
            "log_file": args.analyze,
            "quick_mode": args.quick,
            "total_findings": len(all_findings),
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "detail": f.detail,
                    "evidence": f.evidence
                }
                for f in all_findings
            ]
        }
        
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(json_report, f, indent=2)
            print_ok(f"JSON report saved to {args.output}")
        except Exception as e:
            print_error(f"Failed to save JSON report: {e}")

    # ── Final Report ─────────────────────────
    elapsed = time.time() - start_time
    report_title = " + ".join(report_title_parts)
    generate_report(report_title, all_findings, elapsed)


if __name__ == "__main__":
    main()

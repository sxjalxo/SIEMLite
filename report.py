#!/usr/bin/env python3
"""
Report Module — Shared Utilities
=================================
Provides the unified severity system, colored output helpers, the Finding
data-class, and the final report generator used by all SIEM-Lite modules.
"""

import sys
import os
from datetime import datetime
from collections import namedtuple

# ─────────────────────────────────────────────
# ANSI Color Codes
# ─────────────────────────────────────────────

class Colors:
    """ANSI escape sequences for terminal styling."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


# ─────────────────────────────────────────────
# Severity System
# ─────────────────────────────────────────────

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def severity_color(severity):
    """Return the ANSI color code for a given severity level."""
    return {
        "CRITICAL": Colors.MAGENTA,
        "HIGH": Colors.RED,
        "MEDIUM": Colors.YELLOW,
        "LOW": Colors.CYAN,
        "INFO": Colors.DIM,
    }.get(severity, Colors.RESET)


def severity_icon(severity):
    """Return a marker icon based on severity."""
    return {
        "CRITICAL": "[!!!]",
        "HIGH": "[!!]",
        "MEDIUM": "[!]",
        "LOW": "[*]",
        "INFO": "[~]",
    }.get(severity, "[?]")


# ─────────────────────────────────────────────
# Finding Data Structure
# ─────────────────────────────────────────────

Finding = namedtuple("Finding", ["category", "severity", "detail", "evidence"])


# ─────────────────────────────────────────────
# Output Helpers
# ─────────────────────────────────────────────

def fix_encoding():
    """Fix Windows console encoding to handle emoji / unicode."""
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            os.environ.setdefault("PYTHONIOENCODING", "utf-8")


def print_section(title, icon=">>>"):
    """Print a formatted section header."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'─' * 60}")
    print(f"  {icon}  {title}")
    print(f"{'─' * 60}{Colors.RESET}")


def print_finding(finding):
    """Pretty-print a single Finding."""
    color = severity_color(finding.severity)
    marker = severity_icon(finding.severity)
    print(f"  {color}{marker} [{finding.severity}] {finding.detail}{Colors.RESET}")
    if finding.evidence:
        for line in finding.evidence.split("\n"):
            print(f"      {Colors.DIM}-> {line}{Colors.RESET}")


def print_ok(message):
    """Print a success / positive message."""
    print(f"  {Colors.GREEN}[+] {message}{Colors.RESET}")


def print_info(message):
    """Print an informational message."""
    print(f"  {Colors.DIM}[~] {message}{Colors.RESET}")


def print_warn(message):
    """Print a warning message."""
    print(f"  {Colors.YELLOW}[!] {message}{Colors.RESET}")


def print_error(message):
    """Print an error message."""
    print(f"  {Colors.RED}[x] {message}{Colors.RESET}")


# ─────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────

def banner():
    """Print the tool banner."""
    print(f"""
{Colors.CYAN}{Colors.BOLD}
 ╔══════════════════════════════════════════════════════════╗
 ║            SIEM-Lite  //  Web Vulnerability Scanner      ║
 ║         Scan  ·  Analyze  ·  Correlate  ·  Report        ║
 ╚══════════════════════════════════════════════════════════╝{Colors.RESET}
{Colors.DIM}  Educational tool — use only on authorized targets.{Colors.RESET}
""")


# ─────────────────────────────────────────────
# Final Report
# ─────────────────────────────────────────────

def generate_report(title, all_findings, elapsed=None):
    """
    Print a final summary report for all collected findings.

    Parameters
    ----------
    title : str
        Banner title for the report (e.g. the scanned URL or log file path).
    all_findings : list[Finding]
        Every finding from all modules.
    elapsed : float or None
        Wall-clock seconds the scan took.
    """
    # Sort findings by severity (most critical first)
    sorted_findings = sorted(
        all_findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
        reverse=True,
    )

    print(f"\n\n{Colors.BOLD}{Colors.CYAN}{'=' * 60}")
    print(f"  SCAN REPORT — {title}")
    print(f"{'=' * 60}{Colors.RESET}")
    print(f"  {Colors.DIM}Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if elapsed is not None:
        print(f"  Duration: {elapsed:.1f}s")
    print(f"{Colors.RESET}")

    # ── Tallies ──
    severity_counts = {}
    category_counts = {}
    for f in sorted_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    total = len(sorted_findings)
    critical = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)
    medium = severity_counts.get("MEDIUM", 0)
    low = severity_counts.get("LOW", 0)
    info = severity_counts.get("INFO", 0)

    print(f"  {Colors.BOLD}Total findings: {total}{Colors.RESET}")
    if critical:
        print(f"    {Colors.MAGENTA}■ CRITICAL : {critical}{Colors.RESET}")
    if high:
        print(f"    {Colors.RED}■ HIGH     : {high}{Colors.RESET}")
    if medium:
        print(f"    {Colors.YELLOW}■ MEDIUM   : {medium}{Colors.RESET}")
    if low:
        print(f"    {Colors.CYAN}■ LOW      : {low}{Colors.RESET}")
    if info:
        print(f"    {Colors.DIM}■ INFO     : {info}{Colors.RESET}")

    if category_counts:
        print(f"\n  {Colors.BOLD}Findings by category:{Colors.RESET}")
        for cat, count in sorted(category_counts.items()):
            print(f"    - {cat}: {count}")

    # ── Full listing ──
    if sorted_findings:
        print(f"\n  {Colors.BOLD}All findings:{Colors.RESET}")
        for i, f in enumerate(sorted_findings, 1):
            color = severity_color(f.severity)
            icon = severity_icon(f.severity)
            print(f"    {color}{i:>3}. {icon} [{f.severity}] {f.category} — {f.detail}{Colors.RESET}")

    # ── Risk assessment ──
    print(f"\n  {Colors.BOLD}Risk Assessment:{Colors.RESET}")
    if critical >= 1:
        print(f"    {Colors.MAGENTA}[!!!] CRITICAL — Critical correlated threats detected. "
              f"Immediate action required.{Colors.RESET}")
    elif high >= 3:
        print(f"    {Colors.RED}[!!] HIGH — Multiple high-severity issues found. "
              f"Immediate remediation recommended.{Colors.RESET}")
    elif high >= 1:
        print(f"    {Colors.RED}[!] HIGH — High-severity issues found. "
              f"Remediation recommended.{Colors.RESET}")
    elif medium >= 2:
        print(f"    {Colors.YELLOW}[*] MEDIUM — Several medium-severity issues. "
              f"Review and harden.{Colors.RESET}")
    elif total > 0:
        print(f"    {Colors.CYAN}[~] LOW — Minor issues found. Good overall posture.{Colors.RESET}")
    else:
        print(f"    {Colors.GREEN}[+] CLEAN — No significant issues detected.{Colors.RESET}")

    print(f"\n{Colors.CYAN}{'=' * 60}{Colors.RESET}")
    print(f"  {Colors.DIM}Disclaimer: This is a basic scanner. Always perform")
    print(f"  thorough manual testing and use professional tools.{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.RESET}\n")

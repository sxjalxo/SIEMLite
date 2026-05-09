#!/usr/bin/env python3
"""
Smart Web Vulnerability Scanner
================================
A lightweight Python-based security tool that performs basic web vulnerability
assessment including XSS, SQL Injection detection, security header analysis,
and port scanning.

Usage (standalone):
    python scanner.py <target_url>

Example:
    python scanner.py https://example.com

The module also exposes ``run_scan(url)`` so it can be imported by main.py.

DISCLAIMER: This tool is for educational and authorized testing purposes only.
Do NOT use it against websites you do not own or have explicit permission to test.
"""

import sys
import os
import socket
import time
import urllib.parse
from datetime import datetime

import requests
from bs4 import BeautifulSoup

from report import (
    Colors, Finding, fix_encoding,
    print_section, print_finding, print_ok, print_info, print_warn,
    banner as report_banner,
    generate_report,
)

# ─────────────────────────────────────────────
# Configuration & Constants
# ─────────────────────────────────────────────

REQUEST_TIMEOUT = 10  # seconds
PORT_SCAN_TIMEOUT = 1.5  # seconds per port

# SQL Injection payloads and corresponding error signatures
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' ORDER BY 1--",
    "1 UNION SELECT NULL--",
    "' AND 1=CONVERT(int, @@version)--",
    "1; DROP TABLE users--",
    "admin' --",
    "' OR 1=1#",
    "\" OR \"\"=\"",
]

SQL_ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "mysql_fetch",
    "mysql_num_rows",
    # PostgreSQL
    "pg_query",
    "pg_exec",
    "postgresql",
    "psql",
    # MSSQL
    "microsoft sql server",
    "odbc sql server driver",
    "sqlserver",
    "mssql",
    # SQLite
    "sqlite3.operationalerror",
    "sqlite_error",
    # Oracle
    "ora-00933",
    "ora-01756",
    "oracle error",
    # Generic
    "sql syntax",
    "sql error",
    "syntax error",
    "database error",
    "db error",
    "query failed",
    "unterminated string",
    "quoted string not properly terminated",
]

# XSS payloads
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "';alert(1)//",
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<body onload=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '{{7*7}}',  # Template injection probe
]

# Security headers to check
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Prevents XSS, clickjacking, and other code injection attacks",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Prevents clickjacking by controlling iframe embedding",
    },
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "Enforces HTTPS connections to prevent downgrade attacks",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Prevents MIME-type sniffing attacks",
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "Legacy XSS filter (deprecated but still useful for older browsers)",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controls referrer information sent with requests",
    },
    "Permissions-Policy": {
        "severity": "MEDIUM",
        "description": "Controls browser features like camera, microphone, geolocation",
    },
}

# Common ports to scan
PORT_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


# ─────────────────────────────────────────────
# Utility Functions
# ─────────────────────────────────────────────

def get_session():
    """Return a requests.Session with a realistic User-Agent."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        )
    })
    return session


def normalize_url(url):
    """Ensure the URL has a scheme."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def extract_hostname(url):
    """Extract hostname from a URL."""
    parsed = urllib.parse.urlparse(url)
    return parsed.hostname


# ─────────────────────────────────────────────
# Scanner Modules
# ─────────────────────────────────────────────

def crawl_forms(session, url):
    """
    Crawl the target URL and extract HTML forms with their inputs.
    Returns a list of dicts: {action, method, inputs: [{name, type, value}]}
    """
    forms_found = []
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action", "")
            # Resolve relative action URLs
            action = urllib.parse.urljoin(url, action)
            method = form.get("method", "get").lower()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })
            forms_found.append({
                "action": action,
                "method": method,
                "inputs": inputs,
            })
    except requests.RequestException:
        pass
    return forms_found


def crawl_links(session, url):
    """
    Crawl the target URL and extract same-origin links with query parameters.
    Returns a list of URLs that contain query parameters (potential injection points).
    """
    links = set()
    base_host = extract_hostname(url)
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = urllib.parse.urljoin(url, a["href"])
            parsed = urllib.parse.urlparse(href)
            if parsed.hostname == base_host and parsed.query:
                links.add(href)
    except requests.RequestException:
        pass
    return list(links)


def scan_sql_injection(session, url, forms, links):
    """
    Test for SQL Injection vulnerabilities by:
    1. Injecting payloads into form inputs
    2. Injecting payloads into URL query parameters
    3. Comparing response lengths / checking for SQL error signatures
    """
    print_section("SQL Injection Detection", ">>>")
    findings = []
    tested = 0

    # --- Test forms ---
    for form in forms:
        for payload in SQL_PAYLOADS:
            data = {}
            for inp in form["inputs"]:
                if inp["name"]:
                    data[inp["name"]] = payload if inp["type"] != "hidden" else inp["value"]
            try:
                if form["method"] == "post":
                    resp = session.post(form["action"], data=data, timeout=REQUEST_TIMEOUT, verify=False)
                else:
                    resp = session.get(form["action"], params=data, timeout=REQUEST_TIMEOUT, verify=False)
                tested += 1

                body_lower = resp.text.lower()
                for sig in SQL_ERROR_SIGNATURES:
                    if sig in body_lower:
                        f = Finding(
                            category="SQL Injection",
                            severity="HIGH",
                            detail=f"Possible SQLi at {form['action']} (form, {form['method'].upper()})",
                            evidence=f"Payload: {payload}\nSignature matched: {sig}",
                        )
                        findings.append(f)
                        print_finding(f)
                        break  # one finding per form per payload is enough
            except requests.RequestException:
                continue

    # --- Test URL parameters ---
    for link in links:
        parsed = urllib.parse.urlparse(link)
        params = urllib.parse.parse_qs(parsed.query)

        # Get baseline response length
        try:
            baseline = session.get(link, timeout=REQUEST_TIMEOUT, verify=False)
            baseline_len = len(baseline.text)
        except requests.RequestException:
            continue

        for param_name in params:
            for payload in SQL_PAYLOADS[:5]:  # use top payloads for URL params
                test_params = dict(params)
                test_params[param_name] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                try:
                    resp = session.get(test_url, params=test_params, timeout=REQUEST_TIMEOUT, verify=False)
                    tested += 1
                    body_lower = resp.text.lower()

                    # Check for SQL error signatures
                    for sig in SQL_ERROR_SIGNATURES:
                        if sig in body_lower:
                            f = Finding(
                                category="SQL Injection",
                                severity="HIGH",
                                detail=f"Possible SQLi in param '{param_name}' at {test_url}",
                                evidence=f"Payload: {payload}\nSignature matched: {sig}",
                            )
                            findings.append(f)
                            print_finding(f)
                            break

                    # Check for significant response length difference (heuristic)
                    resp_len = len(resp.text)
                    if abs(resp_len - baseline_len) > baseline_len * 0.3 and baseline_len > 100:
                        f = Finding(
                            category="SQL Injection",
                            severity="MEDIUM",
                            detail=f"Response size anomaly for param '{param_name}' at {test_url}",
                            evidence=(
                                f"Payload: {payload}\n"
                                f"Baseline length: {baseline_len} -> Response length: {resp_len} "
                                f"(delta {abs(resp_len - baseline_len)})"
                            ),
                        )
                        findings.append(f)
                        print_finding(f)

                except requests.RequestException:
                    continue

    if not findings:
        print_ok("No SQL Injection indicators detected.")
    print_info(f"Tested {tested} request(s) with {len(SQL_PAYLOADS)} payloads.")
    return findings


def scan_xss(session, url, forms, links):
    """
    Test for reflected XSS by injecting payloads into forms and URL parameters,
    then checking if the payload appears unencoded in the response body.
    """
    print_section("Cross-Site Scripting (XSS) Detection", ">>>")
    findings = []
    tested = 0

    # --- Test forms ---
    for form in forms:
        for payload in XSS_PAYLOADS:
            data = {}
            for inp in form["inputs"]:
                if inp["name"]:
                    data[inp["name"]] = payload if inp["type"] != "hidden" else inp["value"]
            try:
                if form["method"] == "post":
                    resp = session.post(form["action"], data=data, timeout=REQUEST_TIMEOUT, verify=False)
                else:
                    resp = session.get(form["action"], params=data, timeout=REQUEST_TIMEOUT, verify=False)
                tested += 1

                if payload in resp.text:
                    f = Finding(
                        category="XSS",
                        severity="HIGH",
                        detail=f"Reflected XSS at {form['action']} (form, {form['method'].upper()})",
                        evidence=f"Payload reflected: {payload}",
                    )
                    findings.append(f)
                    print_finding(f)
                    break  # one finding per form is enough
            except requests.RequestException:
                continue

    # --- Test URL parameters ---
    for link in links:
        parsed = urllib.parse.urlparse(link)
        params = urllib.parse.parse_qs(parsed.query)

        for param_name in params:
            for payload in XSS_PAYLOADS[:5]:
                test_params = dict(params)
                test_params[param_name] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                try:
                    resp = session.get(test_url, params=test_params, timeout=REQUEST_TIMEOUT, verify=False)
                    tested += 1

                    if payload in resp.text:
                        f = Finding(
                            category="XSS",
                            severity="HIGH",
                            detail=f"Reflected XSS via param '{param_name}' at {test_url}",
                            evidence=f"Payload reflected: {payload}",
                        )
                        findings.append(f)
                        print_finding(f)
                        break
                except requests.RequestException:
                    continue

    if not findings:
        print_ok("No reflected XSS vulnerabilities detected.")
    print_info(f"Tested {tested} request(s) with {len(XSS_PAYLOADS)} payloads.")
    return findings


def scan_security_headers(session, url):
    """
    Analyze HTTP response headers for security best-practices.
    """
    print_section("Security Headers Analysis", ">>>")
    findings = []

    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT, verify=False)
        headers = resp.headers

        present = []
        missing = []

        for header, meta in SECURITY_HEADERS.items():
            if header in headers:
                present.append((header, headers[header]))
            else:
                missing.append((header, meta))

        # Report present headers
        if present:
            print_ok("Headers present:")
            for name, value in present:
                val_preview = value[:80] + ("..." if len(value) > 80 else "")
                print(f"      {Colors.GREEN}+ {name}: {val_preview}{Colors.RESET}")

        # Report missing headers as findings
        if missing:
            print_warn("Missing security headers:")
            for name, meta in missing:
                f = Finding(
                    category="Security Headers",
                    severity=meta["severity"],
                    detail=f"Missing header: {name}",
                    evidence=meta["description"],
                )
                findings.append(f)
                print_finding(f)

        # Extra checks
        server = headers.get("Server", "")
        if server:
            f = Finding(
                category="Security Headers",
                severity="LOW",
                detail="Server header discloses technology",
                evidence=f"Server: {server}",
            )
            findings.append(f)
            print_finding(f)

        x_powered = headers.get("X-Powered-By", "")
        if x_powered:
            f = Finding(
                category="Security Headers",
                severity="LOW",
                detail="X-Powered-By header discloses technology",
                evidence=f"X-Powered-By: {x_powered}",
            )
            findings.append(f)
            print_finding(f)

    except requests.RequestException as e:
        print_warn(f"Could not retrieve headers: {e}")

    if not findings:
        print_ok("All checked security headers are present.")
    return findings


def scan_ports(hostname):
    """
    Perform a basic TCP port scan on the top common ports.
    """
    print_section("Port Scan", ">>>")
    findings = []
    open_ports = []

    print_info(f"Scanning {len(PORT_MAP)} common ports on {hostname}...")
    print()

    for port, service in sorted(PORT_MAP.items()):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(PORT_SCAN_TIMEOUT)
            result = sock.connect_ex((hostname, port))
            if result == 0:
                open_ports.append((port, service))
                print(f"      {Colors.GREEN}* {port:>5}/tcp   OPEN    {service}{Colors.RESET}")
            sock.close()
        except (socket.error, OSError):
            pass

    if open_ports:
        for port, service in open_ports:
            f = Finding(
                category="Port Scan",
                severity="INFO",
                detail=f"Open port: {port}/tcp ({service})",
                evidence=None,
            )
            findings.append(f)
    else:
        print_ok("No open ports detected (all scanned ports filtered/closed).")

    print_info(f"Scanned {len(PORT_MAP)} ports total, {len(open_ports)} open.")
    return findings


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def run_scan(target_url, skip_ports=False):
    """
    Run the full web vulnerability scan on target_url.

    Parameters
    ----------
    target_url : str
        The URL to scan.
    skip_ports : bool
        If True, skip the port-scanning phase.

    Returns
    -------
    list[Finding]
        All findings from every scan module.
    """
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    target = normalize_url(target_url)
    hostname = extract_hostname(target)

    if not hostname:
        print_warn(f"Invalid URL: {target_url}")
        return []

    print_ok(f"Target  : {target}")
    print_ok(f"Hostname: {hostname}")
    print_info(f"Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    session = get_session()
    all_findings = []

    # Phase 1: Crawl
    print_section("Reconnaissance -- Crawling", ">>>")
    forms = crawl_forms(session, target)
    links = crawl_links(session, target)
    print_ok(f"Found {len(forms)} form(s) and {len(links)} parameterized link(s).")

    # Phase 2: SQL Injection
    all_findings.extend(scan_sql_injection(session, target, forms, links))

    # Phase 3: XSS
    all_findings.extend(scan_xss(session, target, forms, links))

    # Phase 4: Security Headers
    all_findings.extend(scan_security_headers(session, target))

    # Phase 5: Port Scan
    if not skip_ports:
        all_findings.extend(scan_ports(hostname))

    return all_findings


# ─────────────────────────────────────────────
# Standalone Entry Point
# ─────────────────────────────────────────────

def main():
    fix_encoding()
    report_banner()

    if len(sys.argv) < 2:
        print(f"  {Colors.RED}Usage: python scanner.py <target_url>{Colors.RESET}")
        print(f"  {Colors.DIM}Example: python scanner.py https://example.com{Colors.RESET}\n")
        sys.exit(1)

    target = sys.argv[1]
    start_time = time.time()
    findings = run_scan(target)
    elapsed = time.time() - start_time
    generate_report(normalize_url(target), findings, elapsed)


if __name__ == "__main__":
    main()

# SIEM-Lite — Smart Web Vulnerability Scanner

A lightweight Python-based security tool that combines **web vulnerability scanning**, **log analysis**, and **cross-module threat correlation** into a unified CLI.

> **Disclaimer:** This tool is for **educational and authorized testing purposes only**. Do NOT use it against websites you do not own or have explicit written permission to test.

---

## Features

| Module | Feature | Severity |
|---|---|---|
| **Scanner** | SQL Injection detection (10 payloads, 20+ error signatures) | HIGH |
| **Scanner** | Reflected XSS detection (10 payloads) | HIGH |
| **Scanner** | Security header analysis (7 headers + info disclosure) | HIGH-LOW |
| **Scanner** | TCP port scan (20 common ports) | INFO |
| **Log Analyzer** | Brute-force login detection | HIGH |
| **Log Analyzer** | Suspicious IP frequency analysis | MEDIUM |
| **Log Analyzer** | 404 path scanning / directory enumeration | MEDIUM |
| **Log Analyzer** | Malicious URI detection (SQLi/XSS/traversal in URLs) | HIGH |
| **Log Analyzer** | Web shell access detection | HIGH |
| **Correlation** | Cross-module threat correlation (10 rules) | CRITICAL |

### Correlation Rules (the SIEM flavor)

The correlation engine cross-references scanner and log findings to surface combined threats:

```
If:  Port 22 open  AND  brute-force attempts in logs
-->  [CRITICAL] Potential SSH brute-force attack detected on open port 22

If:  SQLi vulnerability found  AND  SQLi attempts in logs
-->  [CRITICAL] Active SQL Injection exploitation confirmed

If:  Missing CSP header  AND  XSS vectors detected
-->  [HIGH] Missing Content-Security-Policy with active XSS risk
```

---

## Quick Start

### Prerequisites

- Python 3.8+

### Installation

```bash
git clone https://github.com/sxjalxo/WebVul.git
cd WebVul
pip install -r requirements.txt
```

### Usage

```bash
# Scan a website for vulnerabilities
python main.py --scan https://example.com

# Analyze an access log file
python main.py --analyze access.log

# Both: scan + analyze + auto-correlate findings
python main.py --scan https://example.com --analyze access.log

# Skip port scanning (faster)
python main.py --scan https://example.com --no-ports

# Individual modules still work standalone
python scanner.py https://example.com
python log_analyzer.py access.log
```

---

## Severity System

| Level | Marker | Meaning |
|---|---|---|
| **CRITICAL** | `[!!!]` | Correlated threats, active exploitation |
| **HIGH** | `[!!]` | Confirmed vulnerabilities, brute-force attacks |
| **MEDIUM** | `[!]` | Missing headers, suspicious patterns |
| **LOW** | `[*]` | Info disclosure, deprecated protections |
| **INFO** | `[~]` | Open ports, general observations |

---

## Sample Output

```
 ╔══════════════════════════════════════════════════════════╗
 ║            SIEM-Lite  //  Web Vulnerability Scanner      ║
 ║         Scan  ·  Analyze  ·  Correlate  ·  Report        ║
 ╚══════════════════════════════════════════════════════════╝

────────────────────────────────────────────────────────────
  >>>  Threat Correlation Engine
────────────────────────────────────────────────────────────
  [!!!] [CRITICAL] Potential SSH brute-force attack detected on open port 22
      -> Port 22 (SSH) is open AND brute-force login attempts were found in logs.
      -> Action: Restrict SSH access via firewall, use key-based auth.

============================================================
  SCAN REPORT — https://example.com + Logs: access.log
============================================================
  Total findings: 18
    ■ CRITICAL : 2
    ■ HIGH     : 5
    ■ MEDIUM   : 4
    ■ LOW      : 3
    ■ INFO     : 4

  Risk Assessment:
    [!!!] CRITICAL — Critical correlated threats detected. Immediate action required.
```

---

## Project Structure

```
WebVul/
├── main.py              # Unified CLI + correlation engine
├── scanner.py           # Web vulnerability scanner module
├── log_analyzer.py      # Access log analyzer module
├── report.py            # Shared utilities (colors, severity, reporting)
├── requirements.txt     # Python dependencies
├── sample_access.log    # Sample log file for testing
└── README.md            # This file
```

---

## Tech Stack

- **Python 3** — Core language
- **requests** — HTTP client for web scanning
- **BeautifulSoup4** — HTML parsing & form extraction
- **socket** — TCP port scanning
- **argparse** — Unified CLI
- **re** — Log parsing & pattern matching

---

## License

MIT License — free for personal and educational use.

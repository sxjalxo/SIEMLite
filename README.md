# SIEM-Lite v1.0 — Security Monitoring & Vulnerability Toolkit

A lightweight Python-based security tool that combines **web vulnerability scanning**, **log analysis**, **cross-module threat correlation**, and **SIEM - inspired features** into a unified CLI.

> **Disclaimer:** This tool is for **educational and authorized testing purposes only**. Do NOT use it against websites you do not own or have explicit written permission to test.

---

## Features

### Core Security Modules

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
| **Correlation** | Cross-module threat correlation (14 rules with scoring) | CRITICAL |

### Advanced Features

| Feature | Description |
|---|---|
| **Real-time Monitoring** | Watchdog-based log file monitoring with event-driven analysis |
| **Alerting System** | Multi-channel alerts (file, JSON, email, desktop notifications) |
| **Persistent Storage** | SQLite database for logs, alerts, correlations, and statistics |
| **CLI Dashboard** | Interactive security metrics dashboard with rich library |
| **Geo-IP Tracking** | IP geolocation and impossible travel detection |
| **MITRE ATT&CK** | Automatic mapping of detections to MITRE techniques |
| **Threat Intelligence** | AbuseIPDB API integration and local blacklist |
| **Anomaly Detection** | Statistical analysis (Z-score) for request spikes |
| **Custom Rules** | Plugin-based rule system for extensible detection |

---

## Quick Start

### Prerequisites

- Python 3.8+

### Installation

```bash
git clone https://github.com/sxjalxo/SIEMLite-Security-Monitoring-Vulnerability-Toolkit.git
cd SIEMLite
pip install -r requirements.txt
```

### Usage

```bash
# Scan a website for vulnerabilities
python main.py --scan https://example.com

# Analyze an access log file
python main.py --analyze data/sample_access.log

# Both: scan + analyze + auto-correlate findings
python main.py --scan https://example.com --analyze data/sample_access.log

# Quick mode (skip deep scanning)
python main.py --scan https://example.com --quick

# Output results to JSON
python main.py --scan https://example.com --output report.json

# Skip port scanning (faster)
python main.py --scan https://example.com --no-ports

# Individual modules still work standalone
python -m core.scanner https://example.com
python -m core.log_analyzer data/sample_access.log
python -m ui.dashboard
```

---

## Advanced Correlation

The correlation engine cross-references scanner and log findings to surface combined threats using severity scoring:

```
If:  Port 22 open  AND  brute-force attempts in logs
-->  [CRITICAL] Potential SSH brute-force attack detected (Score: 14)

If:  SQLi vulnerability found  AND  SQLi attempts in logs
-->  [CRITICAL] Active SQL Injection exploitation (Score: 14)

If:  Impossible travel  AND  brute-force attacks
-->  [CRITICAL] Impossible travel + credential attacks (Score: 14)
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
 ║            SIEM-Lite v1.0  //  Security Monitoring Toolkit ║
 ║         Scan  ·  Analyze  ·  Correlate  ·  Report        ║
 ╚══════════════════════════════════════════════════════════╝

────────────────────────────────────────────────────────────
  >>>  Threat Correlation Engine
────────────────────────────────────────────────────────────
  [!!!] [CRITICAL] Potential SSH brute-force attack detected on open port 22 (Score: 14)
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
SIEMLite/
├── main.py              # Unified CLI + correlation engine
├── README.md            # This file
├── requirements.txt     # Python dependencies
├── LICENSE              # MIT License
│
├── core/                # Core security modules
│   ├── scanner.py       # Web vulnerability scanner
│   ├── log_analyzer.py  # Access log analyzer
│   ├── report.py        # Shared utilities (colors, severity, reporting)
│   ├── database.py      # SQLite persistent storage
│   ├── alerting.py      # Multi-channel alerting system
│   └── rule_loader.py   # Plugin-based custom rule system
│
├── modules/             # Advanced detection modules
│   ├── geo_ip.py        # Geo-IP tracking & impossible travel
│   ├── mitre_mapping.py # MITRE ATT&CK mapping
│   ├── threat_intel.py  # Threat intelligence (AbuseIPDB, blacklist)
│   └── anomaly_detection.py # Statistical anomaly detection
│
├── ingestion/           # Data ingestion modules
│   └── realtime_monitor.py # Real-time log monitoring with watchdog
│
├── ui/                  # User interface modules
│   └── dashboard.py     # Interactive CLI dashboard
│
├── rules/               # Custom detection rules
│   └── example_rule.py  # Example custom rule
│
├── data/                # Data files
│   ├── sample_access.log # Sample log file for testing
│   └── blacklist.json   # Local IP blacklist
│
├── output/              # Output files
│   ├── alerts.log       # Alert log file (auto-created)
│   └── alerts.json      # Alert JSON file (auto-created)
│
└── db/                  # Database files
    └── siem_lite.db     # SQLite database (auto-created)
```

---

## Tech Stack

- **Python 3** — Core language
- **requests** — HTTP client for web scanning
- **BeautifulSoup4** — HTML parsing & form extraction
- **socket** — TCP port scanning
- **argparse** — Unified CLI
- **re** — Log parsing & pattern matching
- **watchdog** — Real-time file monitoring
- **rich** — Interactive CLI dashboard
- **geoip2** — IP geolocation
- **sqlite3** — Persistent storage

---

## Configuration

### Alerting Configuration

Edit `core/alerting.py` to configure:
- Email alerts (SMTP settings)
- Desktop notifications
- Alert file paths (output/alerts.log, output/alerts.json)

### Geo-IP Configuration

Download GeoLite2-City.mmdb from MaxMind and place in `data/` directory for Geo-IP features.

### Threat Intelligence

Configure AbuseIPDB API key in `modules/threat_intel.py` for IP reputation checking. Local blacklist is stored in `data/blacklist.json`.

### Custom Rules

Add custom detection rules in the `rules/` directory. Each rule file must have a `detect(entries)` function.

---

## License

MIT License — free for personal and educational use.
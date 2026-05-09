# 🛡️ Smart Web Vulnerability Scanner

A lightweight Python-based security tool that performs basic web vulnerability assessment including **XSS**, **SQL Injection** detection, **security header analysis**, and **port scanning**.

> ⚠️ **Disclaimer:** This tool is for **educational and authorized testing purposes only**. Do NOT use it against websites you do not own or have explicit written permission to test.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🕷️ **XSS Detection** | Injects common XSS payloads into forms and URL parameters, checks for reflection |
| 💉 **SQL Injection Testing** | Tests with multiple SQLi payloads, detects error signatures and response anomalies |
| 🔒 **Security Header Analysis** | Checks for missing security headers (CSP, HSTS, X-Frame-Options, etc.) |
| 🌐 **Port Scanning** | Scans 20 common ports (HTTP, SSH, FTP, MySQL, Redis, etc.) |
| 🕸️ **Auto-Crawling** | Discovers forms and parameterized links on the target page |
| 📋 **Clean Report** | Color-coded terminal output with severity ratings and risk assessment |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+

### Installation

```bash
git clone https://github.com/your-username/smart-vuln-scanner.git
cd smart-vuln-scanner
pip install -r requirements.txt
```

### Usage

```bash
python scanner.py https://example.com
```

---

## 📸 Sample Output

```
 ╔══════════════════════════════════════════════════════════╗
 ║         🛡️  Smart Web Vulnerability Scanner  🛡️          ║
 ║              Mini Burp/ZAP — Python Edition              ║
 ╚══════════════════════════════════════════════════════════╝

  [+] Target  : https://example.com
  [+] Hostname: example.com

────────────────────────────────────────────────────────────
  🔒  Security Headers Analysis
────────────────────────────────────────────────────────────
  [!] Missing security headers:
      [!] [HIGH] Missing header: Content-Security-Policy
      [!] [MEDIUM] Missing header: X-Frame-Options

────────────────────────────────────────────────────────────
  🌐  Port Scan
────────────────────────────────────────────────────────────
      ●    80/tcp   OPEN    HTTP
      ●   443/tcp   OPEN    HTTPS

═══════════════════════════════════════════════════════════
  📋  SCAN REPORT — https://example.com
═══════════════════════════════════════════════════════════
  Total findings: 4
    ■ HIGH / CRITICAL : 1
    ■ MEDIUM          : 1
    ■ INFO            : 2

  Risk Assessment:
    🟠 HIGH — High-severity issues found. Remediation recommended.
```

---

## 🧠 Tech Stack

- **Python 3** — Core language
- **requests** — HTTP client
- **BeautifulSoup4** — HTML parsing & form extraction
- **socket** — TCP port scanning

---

## 📁 Project Structure

```
smart-vuln-scanner/
├── scanner.py          # Main scanner with all modules
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

---

## 🔍 How It Works

1. **Reconnaissance** — Crawls the target page, discovers forms and parameterized links
2. **SQL Injection** — Injects payloads into discovered inputs, checks for SQL error signatures and response length anomalies
3. **XSS Detection** — Injects script payloads, checks if they are reflected unencoded in the response
4. **Security Headers** — Inspects response headers against a checklist of security best-practices
5. **Port Scan** — Performs TCP connect scan on 20 common service ports
6. **Report** — Aggregates all findings with severity ratings and risk assessment

---

## 📄 License

MIT License — free for personal and educational use.

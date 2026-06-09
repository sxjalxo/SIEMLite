#!/usr/bin/env python3
"""
Alerting Module — Notification System
======================================
Handles alert notifications through multiple channels:
- Email alerts (SMTP)
- Desktop notifications (platform-specific)
- Alert file logging (JSON/Text)
"""

import smtplib
import json
import platform
import subprocess
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Optional, Dict, Any, List

from core.report import Colors, print_ok, print_warn, print_error


# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

ALERT_LOG_FILE = Path("output/alerts.log")
ALERT_JSON_FILE = Path("output/alerts.json")

# Email configuration (can be overridden via config file)
EMAIL_CONFIG = {
    "enabled": False,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_username": "",
    "smtp_password": "",
    "from_email": "",
    "to_emails": [],
}

# Severity-based notification thresholds
SEVERITY_THRESHOLD_EMAIL = "HIGH"      # Send email for HIGH and above
SEVERITY_THRESHOLD_DESKTOP = "CRITICAL"  # Desktop notifications for CRITICAL only


# ─────────────────────────────────────────────
# Alert File Logging
# ─────────────────────────────────────────────

def log_alert_to_file(alert: Dict[str, Any]) -> bool:
    """
    Log an alert to the alerts.log file (human-readable format).
    
    Parameters
    ----------
    alert : dict
        Alert data with keys: category, severity, detail, evidence, timestamp, etc.
    
    Returns
    -------
    bool
        True if successful, False otherwise
    """
    try:
        timestamp = alert.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        severity = alert.get("severity", "UNKNOWN")
        category = alert.get("category", "Unknown")
        detail = alert.get("detail", "")
        evidence = alert.get("evidence", "")
        
        with open(ALERT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] [{severity}] {category}: {detail}\n")
            if evidence:
                f.write(f"  Evidence: {evidence}\n")
            f.write("-" * 80 + "\n")
        return True
    except Exception as e:
        print_error(f"Failed to log alert to file: {e}")
        return False


def log_alert_to_json(alert: Dict[str, Any]) -> bool:
    """
    Log an alert to the alerts.json file (machine-readable format).
    
    Parameters
    ----------
    alert : dict
        Alert data with keys: category, severity, detail, evidence, timestamp, etc.
    
    Returns
    -------
    bool
        True if successful, False otherwise
    """
    try:
        # Read existing alerts
        existing_alerts = []
        if ALERT_JSON_FILE.exists():
            with open(ALERT_JSON_FILE, "r", encoding="utf-8") as f:
                existing_alerts = json.load(f)
        
        # Add new alert
        existing_alerts.append(alert)
        
        # Write back
        with open(ALERT_JSON_FILE, "w", encoding="utf-8") as f:
            json.dump(existing_alerts, f, indent=2)
        return True
    except Exception as e:
        print_error(f"Failed to log alert to JSON: {e}")
        return False


# ─────────────────────────────────────────────
# Email Alerts
# ─────────────────────────────────────────────

def send_email_alert(
    alert: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Send an alert via email using SMTP.
    
    Parameters
    ----------
    alert : dict
        Alert data with keys: category, severity, detail, evidence, timestamp, etc.
    config : dict, optional
        Email configuration (overrides default EMAIL_CONFIG)
    
    Returns
    -------
    bool
        True if successful, False otherwise
    """
    cfg = EMAIL_CONFIG.copy()
    if config:
        cfg.update(config)
    
    if not cfg.get("enabled"):
        return False
    
    if not cfg.get("to_emails"):
        print_warn("No recipient emails configured for alerts.")
        return False
    
    try:
        # Create message
        msg = MIMEMultipart()
        msg["From"] = cfg["from_email"]
        msg["To"] = ", ".join(cfg["to_emails"])
        msg["Subject"] = f"[SIEM-Lite Alert] {alert.get('severity', 'UNKNOWN')} - {alert.get('category', 'Unknown')}"
        
        # Build email body
        body = f"""
SIEM-Lite Security Alert
{'=' * 50}

Severity: {alert.get('severity', 'UNKNOWN')}
Category: {alert.get('category', 'Unknown')}
Timestamp: {alert.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}

Details:
{alert.get('detail', 'No details provided')}

"""
        if alert.get("evidence"):
            body += f"Evidence:\n{alert['evidence']}\n"
        
        if alert.get("related_ip"):
            body += f"\nRelated IP: {alert['related_ip']}\n"
        
        if alert.get("related_url"):
            body += f"Related URL: {alert['related_url']}\n"
        
        body += f"\n{'=' * 50}\n"
        body += "This is an automated alert from SIEM-Lite.\n"
        
        msg.attach(MIMEText(body, "plain"))
        
        # Send email
        with smtplib.SMTP(cfg["smtp_server"], cfg["smtp_port"]) as server:
            server.starttls()
            server.login(cfg["smtp_username"], cfg["smtp_password"])
            server.send_message(msg)
        
        print_ok(f"Email alert sent to {len(cfg['to_emails'])} recipient(s)")
        return True
        
    except Exception as e:
        print_error(f"Failed to send email alert: {e}")
        return False


def configure_email(
    smtp_server: str,
    smtp_port: int,
    username: str,
    password: str,
    from_email: str,
    to_emails: List[str]
):
    """
    Configure email settings for alerts.
    
    Parameters
    ----------
    smtp_server : str
        SMTP server address (e.g., smtp.gmail.com)
    smtp_port : int
        SMTP server port (e.g., 587 for TLS)
    username : str
        SMTP username
    password : str
        SMTP password (consider using app passwords)
    from_email : str
        Sender email address
    to_emails : list[str]
        List of recipient email addresses
    """
    global EMAIL_CONFIG
    EMAIL_CONFIG.update({
        "enabled": True,
        "smtp_server": smtp_server,
        "smtp_port": smtp_port,
        "smtp_username": username,
        "smtp_password": password,
        "from_email": from_email,
        "to_emails": to_emails,
    })
    print_ok("Email alerting configured successfully")


# ─────────────────────────────────────────────
# Desktop Notifications
# ─────────────────────────────────────────────

def send_desktop_notification(
    title: str,
    message: str,
    severity: str = "INFO"
) -> bool:
    """
    Send a desktop notification (platform-specific).
    
    Parameters
    ----------
    title : str
        Notification title
    message : str
        Notification message
    severity : str
        Alert severity (for icon/styling)
    
    Returns
    -------
    bool
        True if successful, False otherwise
    """
    try:
        system = platform.system()
        
        if system == "Windows":
            # Windows notification using PowerShell
            ps_script = f'''
            Add-Type -AssemblyName System.Windows.Forms
            $notify = New-Object System.Windows.Forms.NotifyIcon
            $notify.Icon = [System.Drawing.SystemIcons]::Warning
            $notify.BalloonTipIcon = "Warning"
            $notify.BalloonTipTitle = "{title}"
            $notify.BalloonTipText = "{message}"
            $notify.Visible = $true
            $notify.ShowBalloonTip(10000)
            Start-Sleep -Seconds 10
            $notify.Dispose()
            '''
            subprocess.run(["powershell", "-Command", ps_script], capture_output=True)
            
        elif system == "Darwin":  # macOS
            # macOS notification using osascript
            script = f'display notification "{message}" with title "{title}"'
            subprocess.run(["osascript", "-e", script], capture_output=True)
            
        elif system == "Linux":
            # Linux notification using notify-send
            try:
                subprocess.run([
                    "notify-send",
                    "-u", "critical" if severity == "CRITICAL" else "normal",
                    title,
                    message
                ], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Fallback: try libnotify
                print_warn("notify-send not available, skipping desktop notification")
                return False
        
        return True
        
    except Exception as e:
        print_error(f"Failed to send desktop notification: {e}")
        return False


# ─────────────────────────────────────────────
# Unified Alert Dispatcher
# ─────────────────────────────────────────────

def send_alert(
    alert: Dict[str, Any],
    channels: Optional[List[str]] = None,
    severity_threshold: Optional[str] = None
) -> Dict[str, bool]:
    """
    Send an alert through multiple channels.
    
    Parameters
    ----------
    alert : dict
        Alert data with keys: category, severity, detail, evidence, timestamp, etc.
    channels : list[str], optional
        List of channels to use: ["file", "json", "email", "desktop"]
        Default: ["file", "json"]
    severity_threshold : str, optional
        Minimum severity to send (default: INFO for file/json, HIGH for email, CRITICAL for desktop)
    
    Returns
    -------
    dict
        Dictionary with channel names as keys and success status as values
    """
    if channels is None:
        channels = ["file", "json"]
    
    severity = alert.get("severity", "INFO")
    
    # Severity order
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    alert_level = severity_order.get(severity, 0)
    
    results = {}
    
    # File logging (always enabled if in channels)
    if "file" in channels:
        results["file"] = log_alert_to_file(alert)
    
    # JSON logging (always enabled if in channels)
    if "json" in channels:
        results["json"] = log_alert_to_json(alert)
    
    # Email alerts
    if "email" in channels:
        email_threshold = severity_threshold or SEVERITY_THRESHOLD_EMAIL
        threshold_level = severity_order.get(email_threshold, 0)
        if alert_level >= threshold_level:
            results["email"] = send_email_alert(alert)
        else:
            results["email"] = None  # Skipped due to severity threshold
    
    # Desktop notifications
    if "desktop" in channels:
        desktop_threshold = severity_threshold or SEVERITY_THRESHOLD_DESKTOP
        threshold_level = severity_order.get(desktop_threshold, 0)
        if alert_level >= threshold_level:
            results["desktop"] = send_desktop_notification(
                title=f"SIEM-Lite: {alert.get('category', 'Alert')}",
                message=alert.get("detail", ""),
                severity=severity
            )
        else:
            results["desktop"] = None  # Skipped due to severity threshold
    
    return results


def send_alert_from_finding(
    finding,
    channels: Optional[List[str]] = None,
    severity_threshold: Optional[str] = None
) -> Dict[str, bool]:
    """
    Send an alert from a Finding namedtuple.
    
    Parameters
    ----------
    finding : Finding
        Finding namedtuple from the scanner/log analyzer
    channels : list[str], optional
        List of channels to use
    severity_threshold : str, optional
        Minimum severity to send
    
    Returns
    -------
    dict
        Dictionary with channel names as keys and success status as values
    """
    alert = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "category": finding.category,
        "severity": finding.severity,
        "detail": finding.detail,
        "evidence": finding.evidence,
    }
    return send_alert(alert, channels, severity_threshold)


# ─────────────────────────────────────────────
# Alert Summary
# ─────────────────────────────────────────────

def get_recent_alerts(hours: int = 24) -> List[Dict[str, Any]]:
    """
    Get recent alerts from the JSON log file.
    
    Parameters
    ----------
    hours : int
        Number of hours to look back
    
    Returns
    -------
    list[dict]
        List of recent alerts
    """
    try:
        if not ALERT_JSON_FILE.exists():
            return []
        
        with open(ALERT_JSON_FILE, "r", encoding="utf-8") as f:
            all_alerts = json.load(f)
        
        # Filter by time
        cutoff_time = datetime.now().timestamp() - (hours * 3600)
        recent = []
        
        for alert in all_alerts:
            try:
                alert_time = datetime.strptime(
                    alert.get("timestamp", ""),
                    "%Y-%m-%d %H:%M:%S"
                ).timestamp()
                if alert_time >= cutoff_time:
                    recent.append(alert)
            except (ValueError, KeyError):
                continue
        
        return recent
        
    except Exception as e:
        print_error(f"Failed to read recent alerts: {e}")
        return []


def get_alert_summary(hours: int = 24) -> Dict[str, Any]:
    """
    Get a summary of recent alerts.
    
    Parameters
    ----------
    hours : int
        Number of hours to look back
    
    Returns
    -------
    dict
        Summary statistics
    """
    alerts = get_recent_alerts(hours)
    
    summary = {
        "total": len(alerts),
        "by_severity": {},
        "by_category": {},
        "timeframe": f"Last {hours} hours"
    }
    
    for alert in alerts:
        # Count by severity
        severity = alert.get("severity", "UNKNOWN")
        summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
        
        # Count by category
        category = alert.get("category", "Unknown")
        summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
    
    return summary


# ─────────────────────────────────────────────
# Configuration Management
# ─────────────────────────────────────────────

def load_config_from_file(config_file: Path = Path("alert_config.json")):
    """
    Load alerting configuration from a JSON file.
    
    Parameters
    ----------
    config_file : Path
        Path to configuration file
    """
    global EMAIL_CONFIG
    
    try:
        if config_file.exists():
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
                
            if "email" in config:
                EMAIL_CONFIG.update(config["email"])
                print_ok("Email configuration loaded from file")
                
    except Exception as e:
        print_error(f"Failed to load config file: {e}")


def save_config_to_file(config_file: Path = Path("alert_config.json")):
    """
    Save current alerting configuration to a JSON file.
    
    Parameters
    ----------
    config_file : Path
        Path to configuration file
    """
    try:
        config = {
            "email": EMAIL_CONFIG
        }
        
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        
        print_ok(f"Configuration saved to {config_file}")
        
    except Exception as e:
        print_error(f"Failed to save config file: {e}")


if __name__ == "__main__":
    # Test alerting system
    print("Testing SIEM-Lite Alerting System...")
    
    test_alert = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "category": "Test Alert",
        "severity": "HIGH",
        "detail": "This is a test alert from SIEM-Lite",
        "evidence": "Test evidence for demonstration purposes",
        "related_ip": "192.168.1.1"
    }
    
    print("\nSending test alert to file and JSON channels...")
    results = send_alert(test_alert, channels=["file", "json"])
    
    for channel, success in results.items():
        status = "✓" if success else "✗"
        print(f"  {status} {channel}: {'Success' if success else 'Failed'}")
    
    print("\nAlert summary:")
    summary = get_alert_summary(hours=1)
    print(f"  Total alerts (last hour): {summary['total']}")
    print(f"  By severity: {summary['by_severity']}")
    print(f"  By category: {summary['by_category']}")

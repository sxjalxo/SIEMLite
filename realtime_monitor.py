#!/usr/bin/env python3
"""
Real-Time Log Monitor
=====================
Monitors log files for changes in real-time and processes new entries
as they are added. Uses watchdog for file system monitoring.

Usage:
    python realtime_monitor.py /path/to/access.log
"""

import sys
import time
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Optional, Callable

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

from report import Colors, print_ok, print_info, print_warn, print_error
from log_analyzer import (
    LOG_PATTERN, AUTH_ENDPOINTS, BRUTE_FORCE_THRESHOLD,
    HIGH_FREQ_THRESHOLD, SCAN_404_THRESHOLD, SHELL_PATTERNS_THRESHOLD,
    SUSPICIOUS_URI_PATTERNS, WEBSHELL_NAMES
)
from database import store_log_entry, store_alert, init_database
from alerting import send_alert


# ─────────────────────────────────────────────
# Real-Time Log Handler
# ─────────────────────────────────────────────

class LogFileHandler(FileSystemEventHandler):
    """Handles file system events for log monitoring."""
    
    def __init__(self, log_file: Path, callback: Optional[Callable] = None):
        self.log_file = log_file
        self.callback = callback
        self.last_position = 0
        self.last_size = 0
        
        # Initialize file position
        if log_file.exists():
            self.last_size = log_file.stat().st_size
            self.last_position = self.last_size
    
    def on_modified(self, event):
        """Called when the log file is modified."""
        if event.src_path == str(self.log_file.absolute()):
            self.process_new_lines()
    
    def process_new_lines(self):
        """Process new lines added to the log file."""
        try:
            current_size = self.log_file.stat().st_size
            
            if current_size <= self.last_position:
                return  # File was truncated or rotated
            
            with open(self.log_file, 'r', encoding='utf-8', errors='replace') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()
            
            if new_lines:
                if self.callback:
                    self.callback(new_lines)
                
        except Exception as e:
            print_error(f"Error processing new lines: {e}")


# ─────────────────────────────────────────────
# Real-Time Log Analyzer
# ─────────────────────────────────────────────

class RealTimeLogAnalyzer:
    """Analyzes log entries in real-time as they arrive."""
    
    def __init__(self, store_to_db: bool = True, send_alerts: bool = True):
        self.store_to_db = store_to_db
        self.send_alerts = send_alerts
        
        # Tracking state for real-time detection
        self.failed_logins = defaultdict(list)  # ip -> [path, ...]
        self.request_counts = defaultdict(int)  # ip -> count
        self._404_counts = defaultdict(list)  # ip -> [path, ...]
        self.webshell_hits = defaultdict(list)  # ip -> [path, ...]
        self.suspicious_uris = defaultdict(list)  # ip -> [(pattern_name, path), ...]
        
        # Event tracking for smart stats printing
        self.events_processed = 0
        
        # Initialize database if needed
        if self.store_to_db:
            init_database()
    
    def parse_line(self, line: str) -> Optional[dict]:
        """Parse a single log line."""
        line = line.strip()
        if not line:
            return None
        
        m = LOG_PATTERN.match(line)
        if m:
            return {
                "ip": m.group("ip"),
                "time": m.group("time"),
                "method": m.group("method"),
                "path": m.group("path"),
                "status": int(m.group("status")),
                "size": m.group("size"),
                "referrer": m.group("referrer") or "",
                "ua": m.group("ua") or "",
                "raw": line,
            }
        return None
    
    def process_entry(self, entry: dict):
        """Process a single log entry for real-time detection."""
        ip = entry["ip"]
        status = entry["status"]
        path = entry["path"]
        path_lower = path.lower().split("?")[0]
        
        # Store to database
        if self.store_to_db:
            store_log_entry(entry)
        
        # Track request counts
        self.request_counts[ip] += 1
        
        # Brute-force detection (401/403 to auth endpoints)
        if status in (401, 403):
            if any(ep in path_lower for ep in AUTH_ENDPOINTS):
                self.failed_logins[ip].append(path)
                if len(self.failed_logins[ip]) >= BRUTE_FORCE_THRESHOLD:
                    self.trigger_alert(
                        category="Brute Force",
                        severity="HIGH",
                        detail=f"Real-time brute-force attack from {ip} — {len(self.failed_logins[ip])} failed login attempts",
                        evidence=f"Targets: {', '.join(set(self.failed_logins[ip]))}",
                        related_ip=ip
                    )
        
        # 404 scanning detection
        if status == 404:
            self._404_counts[ip].append(path)
            if len(self._404_counts[ip]) >= SCAN_404_THRESHOLD:
                self.trigger_alert(
                    category="404 Scanning",
                    severity="MEDIUM",
                    detail=f"Real-time path enumeration from {ip} — {len(self._404_counts[ip])} 404 responses",
                    evidence=f"Sample paths: {', '.join(self._404_counts[ip][:5])}",
                    related_ip=ip
                )
        
        # Web shell detection
        for shell_name in WEBSHELL_NAMES:
            if shell_name in path_lower:
                self.webshell_hits[ip].append(path)
                if len(self.webshell_hits[ip]) >= SHELL_PATTERNS_THRESHOLD:
                    self.trigger_alert(
                        category="Web Shell",
                        severity="HIGH",
                        detail=f"Real-time web-shell access from {ip} — {len(self.webshell_hits[ip])} hit(s)",
                        evidence=f"Paths: {', '.join(set(self.webshell_hits[ip]))}",
                        related_ip=ip
                    )
                break
        
        # Malicious URI detection
        for pattern, name in SUSPICIOUS_URI_PATTERNS:
            if pattern.search(path):
                self.suspicious_uris[ip].append((name, path))
                if len(self.suspicious_uris[ip]) >= 3:  # Threshold for URI patterns
                    self.trigger_alert(
                        category="Malicious URI",
                        severity="HIGH",
                        detail=f"Real-time suspicious URI patterns from {ip} — {len(self.suspicious_uris[ip])} hit(s)",
                        evidence=f"Types: {', '.join(set(h[0] for h in self.suspicious_uris[ip]))}",
                        related_ip=ip
                    )
                break
        
        # High frequency detection
        if self.request_counts[ip] >= HIGH_FREQ_THRESHOLD:
            self.trigger_alert(
                category="Suspicious Frequency",
                severity="MEDIUM",
                detail=f"Real-time high request volume from {ip} — {self.request_counts[ip]} requests",
                evidence="Request rate exceeded threshold",
                related_ip=ip
            )
    
    def trigger_alert(self, category: str, severity: str, detail: str, 
                     evidence: str = None, related_ip: str = None):
        """Trigger an alert for detected activity."""
        alert_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "category": category,
            "severity": severity,
            "detail": detail,
            "evidence": evidence,
            "related_ip": related_ip,
        }
        
        # Store to database
        if self.store_to_db:
            store_alert(
                category=category,
                severity=severity,
                detail=detail,
                evidence=evidence,
                source="realtime_monitor",
                related_ip=related_ip
            )
        
        # Send alert notification
        if self.send_alerts and severity in ["CRITICAL", "HIGH"]:
            send_alert(alert_data, channels=["file", "json"])
        
        # Print alert
        color = {
            "CRITICAL": Colors.MAGENTA,
            "HIGH": Colors.RED,
            "MEDIUM": Colors.YELLOW,
            "LOW": Colors.CYAN,
        }.get(severity, Colors.RESET)
        
        icon = {
            "CRITICAL": "[!!!]",
            "HIGH": "[!!]",
            "MEDIUM": "[!]",
            "LOW": "[*]",
        }.get(severity, "[?]")
        
        print(f"{color}{icon} [{severity}] {category}: {detail}{Colors.RESET}")
        if evidence:
            print(f"      -> {evidence}")
    
    def process_lines(self, lines: list):
        """Process multiple log lines."""
        for line in lines:
            entry = self.parse_line(line)
            if entry:
                self.process_entry(entry)
                self.events_processed += 1
    
    def get_stats(self) -> dict:
        """Get current statistics."""
        return {
            "unique_ips": len(self.request_counts),
            "total_requests": sum(self.request_counts.values()),
            "brute_force_ips": len([ip for ip, attempts in self.failed_logins.items() 
                                   if len(attempts) >= BRUTE_FORCE_THRESHOLD]),
            "scanning_ips": len([ip for ip, paths in self._404_counts.items() 
                                if len(paths) >= SCAN_404_THRESHOLD]),
            "webshell_ips": len([ip for ip, hits in self.webshell_hits.items() 
                                if len(hits) >= SHELL_PATTERNS_THRESHOLD]),
        }


# ─────────────────────────────────────────────
# Main Monitor Function
# ─────────────────────────────────────────────

def monitor_log_file(
    log_file: str,
    store_to_db: bool = True,
    send_alerts: bool = True,
    initial_read: bool = True
):
    """
    Monitor a log file in real-time.
    
    Parameters
    ----------
    log_file : str
        Path to the log file to monitor
    store_to_db : bool
        Whether to store entries to the database
    send_alerts : bool
        Whether to send alerts for detections
    initial_read : bool
        Whether to read existing entries in the file on startup
    """
    log_path = Path(log_file)
    
    if not log_path.exists():
        print_error(f"Log file not found: {log_file}")
        return
    
    if not WATCHDOG_AVAILABLE:
        print_error("watchdog library not available. Install with: pip install watchdog")
        return
    
    print_ok(f"Starting real-time monitoring of: {log_file}")
    print_info("Press Ctrl+C to stop monitoring...")
    
    # Initialize analyzer
    analyzer = RealTimeLogAnalyzer(store_to_db=store_to_db, send_alerts=send_alerts)
    
    # Initial read if requested
    if initial_read:
        print_info("Reading existing log entries...")
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
            analyzer.process_lines(lines)
        print_ok(f"Processed {len(lines)} existing entries")
        print_info(f"Current stats: {analyzer.get_stats()}")
    
    # Setup file watcher
    event_handler = LogFileHandler(log_path, callback=analyzer.process_lines)
    observer = Observer()
    observer.schedule(event_handler, str(log_path.parent), recursive=False)
    
    try:
        observer.start()
        print_ok("Monitoring started. Waiting for new log entries...")
        
        # Print stats periodically or when events occur
        last_stats_time = time.time()
        STATS_INTERVAL = 10  # Print stats every 10 seconds if no events
        
        while True:
            time.sleep(1)
            
            current_time = time.time()
            time_since_last_stats = current_time - last_stats_time
            
            # Print stats if events were processed or it's been STATS_INTERVAL seconds
            if analyzer.events_processed > 0 or time_since_last_stats >= STATS_INTERVAL:
                stats = analyzer.get_stats()
                
                # Only print if events occurred or it's time for periodic update
                if analyzer.events_processed > 0:
                    print_info(f"Stats: {stats} (events processed: {analyzer.events_processed})")
                    analyzer.events_processed = 0  # Reset counter
                    last_stats_time = current_time
                elif time_since_last_stats >= STATS_INTERVAL:
                    print_info(f"Stats: {stats} (idle)")
                    last_stats_time = current_time
    
    except KeyboardInterrupt:
        print_info("\nStopping monitoring...")
        observer.stop()
        print_ok("Monitoring stopped.")
        print_info(f"Final stats: {analyzer.get_stats()}")
    
    observer.join()


# ─────────────────────────────────────────────
# Standalone Entry Point
# ─────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"{Colors.RED}Usage: python realtime_monitor.py <log_file>{Colors.RESET}")
        print(f"{Colors.DIM}Example: python realtime_monitor.py /var/log/apache2/access.log{Colors.RESET}")
        sys.exit(1)
    
    log_file = sys.argv[1]
    monitor_log_file(log_file)


if __name__ == "__main__":
    main()

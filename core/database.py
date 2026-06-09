#!/usr/bin/env python3
"""
Database Module — Persistent Storage
=====================================
SQLite-based persistent storage for logs, alerts, and correlation results.
Provides the foundation for real SIEM behavior and historical analysis.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any
from modules.mitre_mapping import enrich_alert_with_mitre

# ─────────────────────────────────────────────
# Database Configuration
# ─────────────────────────────────────────────

DB_PATH = Path("db/siem_lite.db")


# ─────────────────────────────────────────────
# Database Schema
# ─────────────────────────────────────────────

SCHEMA = """
-- Logs table: Stores parsed log entries
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip TEXT NOT NULL,
    time TEXT,
    method TEXT,
    path TEXT,
    status INTEGER,
    size TEXT,
    referrer TEXT,
    user_agent TEXT,
    line_number INTEGER,
    raw TEXT,
    source_file TEXT
);

-- Alerts table: Stores findings/detections
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail TEXT NOT NULL,
    evidence TEXT,
    source TEXT NOT NULL,  -- 'scanner', 'log_analyzer', 'correlation'
    related_ip TEXT,
    related_url TEXT,
    resolved BOOLEAN DEFAULT 0,
    mitre_technique_id TEXT,
    mitre_technique_name TEXT,
    mitre_tactic TEXT,
    mitre_tactic_id TEXT,
    mitre_url TEXT
);

-- Correlations table: Stores correlation results
CREATE TABLE IF NOT EXISTS correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail TEXT NOT NULL,
    evidence TEXT,
    scan_finding_ids TEXT,  -- JSON array of alert IDs
    log_finding_ids TEXT,   -- JSON array of alert IDs
    resolved BOOLEAN DEFAULT 0
);

-- Scans table: Stores web scan results
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    target_url TEXT NOT NULL,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    duration_seconds REAL,
    scan_config TEXT  -- JSON: skip_ports, etc.
);

-- Statistics table: For quick dashboard queries
CREATE TABLE IF NOT EXISTS statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    metric_name TEXT NOT NULL,
    metric_value REAL NOT NULL,
    metadata TEXT  -- JSON: additional context
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(ip);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);
CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source);
"""


# ─────────────────────────────────────────────
# Database Connection
# ─────────────────────────────────────────────

def get_connection() -> sqlite3.Connection:
    """Get a database connection with row factory for dict access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    """Initialize the database with schema and migrate if needed."""
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
        
        # Add MITRE columns if they don't exist (for existing databases)
        cursor = conn.execute("PRAGMA table_info(alerts)")
        columns = [row[1] for row in cursor.fetchall()]
        
        mitre_columns = [
            "mitre_technique_id",
            "mitre_technique_name", 
            "mitre_tactic",
            "mitre_tactic_id",
            "mitre_url"
        ]
        
        for column in mitre_columns:
            if column not in columns:
                try:
                    conn.execute(f"ALTER TABLE alerts ADD COLUMN {column} TEXT")
                    print(f"Added MITRE column: {column}")
                except sqlite3.Error:
                    pass  # Column might already exist
        
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")
        return False
    finally:
        conn.close()


# ─────────────────────────────────────────────
# Log Operations
# ─────────────────────────────────────────────

def store_log_entry(entry: Dict[str, Any], source_file: str = None) -> Optional[int]:
    """
    Store a parsed log entry in the database.
    
    Parameters
    ----------
    entry : dict
        Parsed log entry with keys: ip, time, method, path, status, size, referrer, ua, line_no, raw
    source_file : str, optional
        Path to the source log file
    
    Returns
    -------
    int or None
        The ID of the inserted row, or None on failure
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO logs (ip, time, method, path, status, size, referrer, user_agent, line_number, raw, source_file)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.get("ip"),
                entry.get("time"),
                entry.get("method"),
                entry.get("path"),
                entry.get("status"),
                entry.get("size"),
                entry.get("referrer", ""),
                entry.get("ua", ""),
                entry.get("line_no"),
                entry.get("raw"),
                source_file
            )
        )
        conn.commit()
        return cursor.lastrowid
    except sqlite3.Error as e:
        print(f"Error storing log entry: {e}")
        return None
    finally:
        conn.close()


def store_log_entries(entries: List[Dict[str, Any]], source_file: str = None) -> int:
    """
    Bulk store multiple log entries.
    
    Returns
    -------
    int
        Number of successfully stored entries
    """
    conn = get_connection()
    try:
        cursor = conn.executemany(
            """
            INSERT INTO logs (ip, time, method, path, status, size, referrer, user_agent, line_number, raw, source_file)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    e.get("ip"),
                    e.get("time"),
                    e.get("method"),
                    e.get("path"),
                    e.get("status"),
                    e.get("size"),
                    e.get("referrer", ""),
                    e.get("ua", ""),
                    e.get("line_no"),
                    e.get("raw"),
                    source_file
                )
                for e in entries
            ]
        )
        conn.commit()
        return cursor.rowcount
    except sqlite3.Error as e:
        print(f"Error bulk storing log entries: {e}")
        return 0
    finally:
        conn.close()


def get_logs_by_ip(ip: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieve logs for a specific IP."""
    conn = get_connection()
    try:
        cursor = conn.execute(
            "SELECT * FROM logs WHERE ip = ? ORDER BY timestamp DESC LIMIT ?",
            (ip, limit)
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_logs_by_time_range(start_time: str, end_time: str) -> List[Dict[str, Any]]:
    """Retrieve logs within a time range."""
    conn = get_connection()
    try:
        cursor = conn.execute(
            "SELECT * FROM logs WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp",
            (start_time, end_time)
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_log_stats() -> Dict[str, Any]:
    """Get overall log statistics."""
    conn = get_connection()
    try:
        cursor = conn.execute("""
            SELECT 
                COUNT(*) as total_entries,
                COUNT(DISTINCT ip) as unique_ips,
                AVG(status) as avg_status,
                MAX(timestamp) as latest_entry
            FROM logs
        """)
        row = cursor.fetchone()
        return dict(row) if row else {}
    finally:
        conn.close()


# ─────────────────────────────────────────────
# Alert Operations
# ─────────────────────────────────────────────

def store_alert(
    category: str,
    severity: str,
    detail: str,
    evidence: str = None,
    source: str = "unknown",
    related_ip: str = None,
    related_url: str = None
) -> Optional[int]:
    """
    Store an alert/finding in the database with MITRE ATT&CK enrichment.
    
    Parameters
    ----------
    category : str
        Alert category (e.g., "Brute Force", "SQL Injection")
    severity : str
        Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    detail : str
        Detailed description of the alert
    evidence : str, optional
        Supporting evidence
    source : str
        Source module (scanner, log_analyzer, correlation)
    related_ip : str, optional
        Related IP address
    related_url : str, optional
        Related URL
    
    Returns
    -------
    int or None
        The ID of the inserted alert
    """
    # Enrich with MITRE ATT&CK information
    alert_data = {
        "category": category,
        "severity": severity,
        "detail": detail,
        "evidence": evidence,
        "source": source,
        "related_ip": related_ip,
        "related_url": related_url,
    }
    
    enriched_alert = enrich_alert_with_mitre(alert_data)
    
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO alerts (category, severity, detail, evidence, source, related_ip, related_url, 
                               mitre_technique_id, mitre_technique_name, mitre_tactic, mitre_tactic_id, mitre_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                enriched_alert.get("category"),
                enriched_alert.get("severity"),
                enriched_alert.get("detail"),
                enriched_alert.get("evidence"),
                enriched_alert.get("source"),
                enriched_alert.get("related_ip"),
                enriched_alert.get("related_url"),
                enriched_alert.get("mitre_technique_id"),
                enriched_alert.get("mitre_technique_name"),
                enriched_alert.get("mitre_tactic"),
                enriched_alert.get("mitre_tactic_id"),
                enriched_alert.get("mitre_url"),
            )
        )
        conn.commit()
        return cursor.lastrowid
    except sqlite3.Error as e:
        print(f"Error storing alert: {e}")
        return None
    finally:
        conn.close()


def store_alerts_from_findings(findings: List, source: str = "unknown") -> List[int]:
    """
    Store multiple alerts from Finding objects.
    
    Parameters
    ----------
    findings : list[Finding]
        List of Finding namedtuples
    source : str
        Source module
    
    Returns
    -------
    list[int]
        List of inserted alert IDs
    """
    alert_ids = []
    for f in findings:
        alert_id = store_alert(
            category=f.category,
            severity=f.severity,
            detail=f.detail,
            evidence=f.evidence,
            source=source
        )
        if alert_id:
            alert_ids.append(alert_id)
    return alert_ids


def get_alerts(
    severity: str = None,
    category: str = None,
    source: str = None,
    resolved: bool = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """Retrieve alerts with optional filters."""
    conn = get_connection()
    try:
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if category:
            query += " AND category = ?"
            params.append(category)
        if source:
            query += " AND source = ?"
            params.append(source)
        if resolved is not None:
            query += " AND resolved = ?"
            params.append(1 if resolved else 0)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor = conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_alert_by_id(alert_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve a specific alert by ID."""
    conn = get_connection()
    try:
        cursor = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def resolve_alert(alert_id: int) -> bool:
    """Mark an alert as resolved."""
    conn = get_connection()
    try:
        conn.execute("UPDATE alerts SET resolved = 1 WHERE id = ?", (alert_id,))
        conn.commit()
        return True
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def get_alert_stats() -> Dict[str, Any]:
    """Get alert statistics."""
    conn = get_connection()
    try:
        cursor = conn.execute("""
            SELECT 
                COUNT(*) as total_alerts,
                SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low,
                SUM(CASE WHEN severity = 'INFO' THEN 1 ELSE 0 END) as info,
                SUM(CASE WHEN resolved = 1 THEN 1 ELSE 0 END) as resolved
            FROM alerts
        """)
        row = cursor.fetchone()
        return dict(row) if row else {}
    finally:
        conn.close()


# ─────────────────────────────────────────────
# Correlation Operations
# ─────────────────────────────────────────────

def store_correlation(
    rule_name: str,
    severity: str,
    detail: str,
    evidence: str = None,
    scan_finding_ids: List[int] = None,
    log_finding_ids: List[int] = None
) -> Optional[int]:
    """
    Store a correlation result.
    
    Parameters
    ----------
    rule_name : str
        Name of the correlation rule
    severity : str
        Severity level
    detail : str
        Detailed description
    evidence : str, optional
        Supporting evidence
    scan_finding_ids : list[int], optional
        Related scan alert IDs
    log_finding_ids : list[int], optional
        Related log alert IDs
    
    Returns
    -------
    int or None
        The ID of the inserted correlation
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO correlations (rule_name, severity, detail, evidence, scan_finding_ids, log_finding_ids)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                rule_name,
                severity,
                detail,
                evidence,
                json.dumps(scan_finding_ids) if scan_finding_ids else None,
                json.dumps(log_finding_ids) if log_finding_ids else None
            )
        )
        conn.commit()
        return cursor.lastrowid
    except sqlite3.Error as e:
        print(f"Error storing correlation: {e}")
        return None
    finally:
        conn.close()


def get_correlations(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve correlation results."""
    conn = get_connection()
    try:
        cursor = conn.execute(
            "SELECT * FROM correlations ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


# ─────────────────────────────────────────────
# Scan Operations
# ─────────────────────────────────────────────

def store_scan(
    target_url: str,
    total_findings: int,
    critical_count: int,
    high_count: int,
    medium_count: int,
    low_count: int,
    info_count: int,
    duration_seconds: float,
    scan_config: Dict[str, Any] = None
) -> Optional[int]:
    """Store a web scan result."""
    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO scans (target_url, total_findings, critical_count, high_count, medium_count, low_count, info_count, duration_seconds, scan_config)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target_url,
                total_findings,
                critical_count,
                high_count,
                medium_count,
                low_count,
                info_count,
                duration_seconds,
                json.dumps(scan_config) if scan_config else None
            )
        )
        conn.commit()
        return cursor.lastrowid
    except sqlite3.Error as e:
        print(f"Error storing scan: {e}")
        return None
    finally:
        conn.close()


def get_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve scan history."""
    conn = get_connection()
    try:
        cursor = conn.execute(
            "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


# ─────────────────────────────────────────────
# Statistics Operations
# ─────────────────────────────────────────────

def store_statistic(metric_name: str, metric_value: float, metadata: Dict[str, Any] = None):
    """Store a metric for dashboard/analytics."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO statistics (metric_name, metric_value, metadata)
            VALUES (?, ?, ?)
            """,
            (metric_name, metric_value, json.dumps(metadata) if metadata else None)
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error storing statistic: {e}")
    finally:
        conn.close()


def get_statistics(metric_name: str = None, limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieve statistics."""
    conn = get_connection()
    try:
        if metric_name:
            cursor = conn.execute(
                "SELECT * FROM statistics WHERE metric_name = ? ORDER BY timestamp DESC LIMIT ?",
                (metric_name, limit)
            )
        else:
            cursor = conn.execute(
                "SELECT * FROM statistics ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


# ─────────────────────────────────────────────
# Utility Functions
# ─────────────────────────────────────────────

def get_top_ips(limit: int = 10) -> List[Dict[str, Any]]:
    """Get top IPs by request count."""
    conn = get_connection()
    try:
        cursor = conn.execute("""
            SELECT ip, COUNT(*) as request_count
            FROM logs
            GROUP BY ip
            ORDER BY request_count DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_status_distribution() -> Dict[str, int]:
    """Get distribution of HTTP status codes."""
    conn = get_connection()
    try:
        cursor = conn.execute("""
            SELECT status, COUNT(*) as count
            FROM logs
            GROUP BY status
            ORDER BY count DESC
        """)
        return {str(row["status"]): row["count"] for row in cursor.fetchall()}
    finally:
        conn.close()


def get_alert_timeline(hours: int = 24) -> List[Dict[str, Any]]:
    """Get alerts grouped by hour for the last N hours."""
    conn = get_connection()
    try:
        cursor = conn.execute("""
            SELECT 
                datetime(timestamp, 'localtime') as hour,
                severity,
                COUNT(*) as count
            FROM alerts
            WHERE timestamp >= datetime('now', '-' || ? || ' hours')
            GROUP BY hour, severity
            ORDER BY hour DESC
        """, (hours,))
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def clear_old_data(days: int = 30):
    """Clear data older than N days."""
    conn = get_connection()
    try:
        cutoff = datetime.now().strftime(f'%Y-%m-%d %H:%M:%S')
        conn.execute(f"DELETE FROM logs WHERE timestamp < datetime('now', '-{days} days')")
        conn.execute(f"DELETE FROM alerts WHERE timestamp < datetime('now', '-{days} days')")
        conn.execute(f"DELETE FROM correlations WHERE timestamp < datetime('now', '-{days} days')")
        conn.execute(f"DELETE FROM statistics WHERE timestamp < datetime('now', '-{days} days')")
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error clearing old data: {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    # Initialize database when run directly
    print("Initializing SIEM-Lite database...")
    if init_database():
        print(f"Database created at: {DB_PATH.absolute()}")
        print("Schema initialized successfully.")
    else:
        print("Failed to initialize database.")

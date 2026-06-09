#!/usr/bin/env python3
"""
Anomaly Detection Module
========================
Statistical anomaly detection using mean and standard deviation.
Detects unusual patterns in request spikes, timing, and other metrics.

Features:
  - Request spike detection using Z-score
  - Time-based pattern analysis
  - Statistical baseline calculation
  - Integration with log analysis

Usage:
    from anomaly_detection import detect_request_spikes, calculate_baseline
    
    anomalies = detect_request_spikes(log_entries)
"""

import statistics
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict

from core.report import Colors, print_ok, print_warn, print_error, print_info


# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

# Z-score threshold for anomaly detection
Z_SCORE_THRESHOLD = 3.0  # 3 standard deviations from mean

# Minimum data points for statistical analysis
MIN_DATA_POINTS = 5

# Time window for baseline calculation (minutes)
BASELINE_WINDOW_MINUTES = 60


# ─────────────────────────────────────────────
# Statistical Functions
# ─────────────────────────────────────────────

def calculate_z_score(value: float, mean: float, std_dev: float) -> float:
    """
    Calculate Z-score for a value.
    
    Parameters
    ----------
    value : float
        Value to calculate Z-score for
    mean : float
        Mean of the dataset
    std_dev : float
        Standard deviation of the dataset
    
    Returns
    -------
    float
        Z-score
    """
    if std_dev == 0:
        return 0.0
    return (value - mean) / std_dev


def calculate_baseline(values: List[float]) -> Dict[str, float]:
    """
    Calculate statistical baseline from values.
    
    Parameters
    ----------
    values : list[float]
        List of values to calculate baseline from
    
    Returns
    -------
    dict
        Dictionary with mean, std_dev, min, max, median
    """
    if len(values) < MIN_DATA_POINTS:
        return {
            "mean": 0.0,
            "std_dev": 0.0,
            "min": 0.0,
            "max": 0.0,
            "median": 0.0,
            "count": len(values)
        }
    
    return {
        "mean": statistics.mean(values),
        "std_dev": statistics.stdev(values) if len(values) > 1 else 0.0,
        "min": min(values),
        "max": max(values),
        "median": statistics.median(values),
        "count": len(values)
    }


def is_anomaly(value: float, baseline: Dict[str, float], threshold: float = Z_SCORE_THRESHOLD) -> bool:
    """
    Check if a value is anomalous based on baseline.
    
    Parameters
    ----------
    value : float
        Value to check
    baseline : dict
        Baseline statistics
    threshold : float
        Z-score threshold
    
    Returns
    -------
    bool
        True if value is anomalous
    """
    if baseline["std_dev"] == 0:
        return False
    
    z_score = calculate_z_score(value, baseline["mean"], baseline["std_dev"])
    return abs(z_score) > threshold


def get_anomaly_severity(z_score: float) -> str:
    """
    Get severity level based on Z-score.
    
    Parameters
    ----------
    z_score : float
        Z-score value
    
    Returns
    -------
    str
        Severity level (LOW, MEDIUM, HIGH, CRITICAL)
    """
    abs_z = abs(z_score)
    if abs_z >= 5.0:
        return "CRITICAL"
    elif abs_z >= 4.0:
        return "HIGH"
    elif abs_z >= 3.0:
        return "MEDIUM"
    else:
        return "LOW"


# ─────────────────────────────────────────────
# Request Spike Detection
# ─────────────────────────────────────────────

def detect_request_spikes(log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect request spikes using statistical analysis.
    
    Parameters
    ----------
    log_entries : list[dict]
        List of log entries
    
    Returns
    -------
    list[dict]
        List of detected anomalies
    """
    anomalies = []
    
    # Group requests by minute
    minute_counts = defaultdict(int)
    for entry in log_entries:
        try:
            timestamp = entry.get("time", "")
            if timestamp:
                # Parse timestamp and round to minute
                dt = datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S")
                minute_key = dt.strftime("%Y-%m-%d %H:%M")
                minute_counts[minute_key] += 1
        except (ValueError, KeyError):
            continue
    
    if len(minute_counts) < MIN_DATA_POINTS:
        return anomalies
    
    # Calculate baseline
    counts = list(minute_counts.values())
    baseline = calculate_baseline(counts)
    
    # Detect anomalies
    for minute, count in minute_counts.items():
        if baseline["std_dev"] > 0:
            z_score = calculate_z_score(count, baseline["mean"], baseline["std_dev"])
            if abs(z_score) > Z_SCORE_THRESHOLD:
                severity = get_anomaly_severity(z_score)
                anomalies.append({
                    "timestamp": minute,
                    "type": "request_spike",
                    "value": count,
                    "baseline_mean": baseline["mean"],
                    "baseline_std": baseline["std_dev"],
                    "z_score": z_score,
                    "severity": severity,
                    "detail": f"Request spike detected: {count} requests (baseline: {baseline['mean']:.1f} ± {baseline['std_dev']:.1f})",
                    "evidence": f"Z-score: {z_score:.2f}, {severity} severity"
                })
    
    return anomalies


def detect_ip_request_anomalies(log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect anomalies in per-IP request patterns.
    
    Parameters
    ----------
    log_entries : list[dict]
        List of log entries
    
    Returns
    -------
    list[dict]
        List of detected IP anomalies
    """
    anomalies = []
    
    # Group requests by IP
    ip_counts = defaultdict(int)
    for entry in log_entries:
        ip = entry.get("ip")
        if ip:
            ip_counts[ip] += 1
    
    if len(ip_counts) < MIN_DATA_POINTS:
        return anomalies
    
    # Calculate baseline
    counts = list(ip_counts.values())
    baseline = calculate_baseline(counts)
    
    # Detect anomalies
    for ip, count in ip_counts.items():
        if baseline["std_dev"] > 0:
            z_score = calculate_z_score(count, baseline["mean"], baseline["std_dev"])
            if abs(z_score) > Z_SCORE_THRESHOLD:
                severity = get_anomaly_severity(z_score)
                anomalies.append({
                    "ip": ip,
                    "type": "ip_request_anomaly",
                    "value": count,
                    "baseline_mean": baseline["mean"],
                    "baseline_std": baseline["std_dev"],
                    "z_score": z_score,
                    "severity": severity,
                    "detail": f"IP {ip} has anomalous request count: {count} (baseline: {baseline['mean']:.1f} ± {baseline['std_dev']:.1f})",
                    "evidence": f"Z-score: {z_score:.2f}, {severity} severity"
                })
    
    return anomalies


def detect_status_code_anomalies(log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect anomalies in HTTP status code patterns.
    
    Parameters
    ----------
    log_entries : list[dict]
        List of log entries
    
    Returns
    -------
    list[dict]
        List of detected status code anomalies
    """
    anomalies = []
    
    # Group by status code
    status_counts = defaultdict(int)
    for entry in log_entries:
        status = entry.get("status")
        if status:
            status_counts[status] += 1
    
    if len(status_counts) < MIN_DATA_POINTS:
        return anomalies
    
    # Calculate baseline
    counts = list(status_counts.values())
    baseline = calculate_baseline(counts)
    
    # Detect anomalies
    for status, count in status_counts.items():
        if baseline["std_dev"] > 0:
            z_score = calculate_z_score(count, baseline["mean"], baseline["std_dev"])
            if abs(z_score) > Z_SCORE_THRESHOLD:
                severity = get_anomaly_severity(z_score)
                anomalies.append({
                    "status_code": status,
                    "type": "status_code_anomaly",
                    "value": count,
                    "baseline_mean": baseline["mean"],
                    "baseline_std": baseline["std_dev"],
                    "z_score": z_score,
                    "severity": severity,
                    "detail": f"Status code {status} has anomalous count: {count} (baseline: {baseline['mean']:.1f} ± {baseline['std_dev']:.1f})",
                    "evidence": f"Z-score: {z_score:.2f}, {severity} severity"
                })
    
    return anomalies


def detect_time_pattern_anomalies(log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect anomalies in time-based access patterns.
    
    Parameters
    ----------
    log_entries : list[dict]
        List of log entries
    
    Returns
    -------
    list[dict]
        List of detected time pattern anomalies
    """
    anomalies = []
    
    # Group by hour
    hour_counts = defaultdict(int)
    for entry in log_entries:
        try:
            timestamp = entry.get("time", "")
            if timestamp:
                dt = datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S")
                hour = dt.hour
                hour_counts[hour] += 1
        except (ValueError, KeyError):
            continue
    
    if len(hour_counts) < MIN_DATA_POINTS:
        return anomalies
    
    # Calculate baseline
    counts = list(hour_counts.values())
    baseline = calculate_baseline(counts)
    
    # Detect anomalies
    for hour, count in hour_counts.items():
        if baseline["std_dev"] > 0:
            z_score = calculate_z_score(count, baseline["mean"], baseline["std_dev"])
            if abs(z_score) > Z_SCORE_THRESHOLD:
                severity = get_anomaly_severity(z_score)
                anomalies.append({
                    "hour": hour,
                    "type": "time_pattern_anomaly",
                    "value": count,
                    "baseline_mean": baseline["mean"],
                    "baseline_std": baseline["std_dev"],
                    "z_score": z_score,
                    "severity": severity,
                    "detail": f"Unusual activity at hour {hour}: {count} requests (baseline: {baseline['mean']:.1f} ± {baseline['std_dev']:.1f})",
                    "evidence": f"Z-score: {z_score:.2f}, {severity} severity"
                })
    
    return anomalies


# ─────────────────────────────────────────────
# Comprehensive Anomaly Detection
# ─────────────────────────────────────────────

def detect_all_anomalies(log_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Run all anomaly detection methods on log entries.
    
    Parameters
    ----------
    log_entries : list[dict]
        List of log entries
    
    Returns
    -------
    dict
        Dictionary with all detected anomalies by type
    """
    results = {
        "request_spikes": detect_request_spikes(log_entries),
        "ip_anomalies": detect_ip_request_anomalies(log_entries),
        "status_code_anomalies": detect_status_code_anomalies(log_entries),
        "time_pattern_anomalies": detect_time_pattern_anomalies(log_entries),
    }
    
    # Calculate total anomalies
    results["total_anomalies"] = sum(len(anomalies) for anomalies in results.values())
    
    return results


def get_anomaly_summary(anomalies: Dict[str, Any]) -> str:
    """
    Get a summary of detected anomalies.
    
    Parameters
    ----------
    anomalies : dict
        Anomaly detection results
    
    Returns
    -------
    str
        Formatted summary
    """
    summary = []
    summary.append("Anomaly Detection Summary")
    summary.append("=" * 50)
    summary.append(f"Total anomalies detected: {anomalies.get('total_anomalies', 0)}")
    summary.append("")
    
    for anomaly_type, anomaly_list in anomalies.items():
        if anomaly_type != "total_anomalies" and anomaly_list:
            summary.append(f"{anomaly_type.replace('_', ' ').title()}: {len(anomaly_list)}")
    
    return "\n".join(summary)


# ─────────────────────────────────────────────
# Integration Functions
# ─────────────────────────────────────────────

def convert_anomalies_to_findings(anomalies: Dict[str, Any]) -> List:
    """
    Convert anomaly detection results to Finding objects.
    
    Parameters
    ----------
    anomalies : dict
        Anomaly detection results
    
    Returns
    -------
    list[Finding]
        List of Finding objects
    """
    from report import Finding
    
    findings = []
    
    for anomaly_type, anomaly_list in anomalies.items():
        if anomaly_type == "total_anomalies":
            continue
            
        for anomaly in anomaly_list:
            findings.append(Finding(
                category="Anomaly Detection",
                severity=anomaly.get("severity", "MEDIUM"),
                detail=anomaly.get("detail", "Unknown anomaly detected"),
                evidence=anomaly.get("evidence", "")
            ))
    
    return findings


# ─────────────────────────────────────────────
# Standalone Entry Point
# ─────────────────────────────────────────────

def main():
    """Test anomaly detection module."""
    from report import fix_encoding
    fix_encoding()
    
    print("Anomaly Detection Test")
    print("=" * 50)
    
    # Create test data
    test_data = []
    base_time = datetime.now()
    
    # Normal traffic (10 requests per minute for 10 minutes)
    for i in range(100):
        test_data.append({
            "ip": f"192.168.1.{i % 10}",
            "time": (base_time + timedelta(minutes=i//10)).strftime("%d/%b/%Y:%H:%M:%S"),
            "status": 200
        })
    
    # Add spike (50 requests in one minute)
    for i in range(50):
        test_data.append({
            "ip": f"10.0.0.{i % 5}",
            "time": (base_time + timedelta(minutes=11)).strftime("%d/%b/%Y:%H:%M:%S"),
            "status": 200
        })
    
    print(f"Test data: {len(test_data)} log entries")
    print()
    
    # Run anomaly detection
    anomalies = detect_all_anomalies(test_data)
    
    print(get_anomaly_summary(anomalies))
    print()
    
    # Show individual anomalies
    for anomaly_type, anomaly_list in anomalies.items():
        if anomaly_type != "total_anomalies" and anomaly_list:
            print(f"\n{anomaly_type.replace('_', ' ').title()}:")
            for anomaly in anomaly_list[:3]:  # Show first 3
                print(f"  - {anomaly['detail']}")
                print(f"    {anomaly['evidence']}")


if __name__ == "__main__":
    main()

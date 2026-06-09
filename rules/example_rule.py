#!/usr/bin/env python3
"""
Example Custom Rule
====================
This is an example custom rule for SIEM-Lite.
Custom rules allow you to add your own detection logic.

Required function:
    detect(entries: List[Dict]) -> List[Dict]

Returns:
    List of findings with keys: category, severity, detail, evidence
"""

from typing import List, Dict, Any


def detect(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect suspicious patterns in log entries.
    
    This example rule detects:
    - Requests to admin endpoints from non-internal IPs
    - Multiple failed login attempts from the same IP
    
    Parameters
    ----------
    entries : list[dict]
        List of log entries with keys: ip, path, status, method, etc.
    
    Returns
    -------
    list[dict]
        List of findings with keys: category, severity, detail, evidence
    """
    findings = []
    
    # Track failed logins by IP
    failed_logins = {}
    
    # Internal IP ranges (adjust as needed)
    internal_ips = {
        "192.168.", "10.", "172.16.", "172.17.", "172.18.", 
        "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
        "172.29.", "172.30.", "172.31.", "127."
    }
    
    def is_internal_ip(ip: str) -> bool:
        """Check if IP is internal."""
        return any(ip.startswith(prefix) for prefix in internal_ips)
    
    for entry in entries:
        ip = entry.get("ip", "")
        path = entry.get("path", "").lower()
        status = entry.get("status", 0)
        method = entry.get("method", "")
        
        # Rule 1: Admin endpoint access from external IP
        if any(admin in path for admin in ["/admin", "/wp-admin", "/administrator", "/dashboard"]):
            if not is_internal_ip(ip):
                findings.append({
                    "category": "Custom Rule: External Admin Access",
                    "severity": "HIGH",
                    "detail": f"External IP {ip} accessed admin endpoint: {path}",
                    "evidence": f"Method: {method}, Status: {status}, IP: {ip}"
                })
        
        # Rule 2: Track failed logins
        if status in [401, 403] and any(auth in path for auth in ["/login", "/auth", "/signin"]):
            if ip not in failed_logins:
                failed_logins[ip] = 0
            failed_logins[ip] += 1
    
    # Check for multiple failed logins
    for ip, count in failed_logins.items():
        if count >= 5:
            findings.append({
                "category": "Custom Rule: Multiple Failed Logins",
                "severity": "HIGH",
                "detail": f"IP {ip} has {count} failed login attempts",
                "evidence": f"Threshold: 5, Actual: {count}"
            })
    
    return findings

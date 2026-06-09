#!/usr/bin/env python3
"""
Threat Intelligence Module
==========================
Provides threat intelligence integration with:
  - AbuseIPDB API for IP reputation checking
  - Local blacklist management
  - Known malicious IP detection
  - Integration with log analysis and scanning

Usage:
    from threat_intel import check_ip_reputation, add_to_blacklist
    
    reputation = check_ip_reputation("8.8.8.8")
    add_to_blacklist("192.168.1.100", "Manual block")
"""

import json
import requests
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from pathlib import Path

from core.report import Colors, print_ok, print_warn, print_error, print_info
from core.database import get_connection, init_database


# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

# AbuseIPDB configuration
ABUSEIPDB_API_KEY = ""  # Set your API key here or in config file
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"

# Local blacklist file
BLACKLIST_FILE = Path("data/blacklist.json")

# Cache duration for IP reputation checks (hours)
CACHE_DURATION_HOURS = 24


# ─────────────────────────────────────────────
# Local Blacklist Management
# ─────────────────────────────────────────────

def load_blacklist() -> Dict[str, Any]:
    """Load the local blacklist from file."""
    if BLACKLIST_FILE.exists():
        try:
            with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print_error(f"Error loading blacklist: {e}")
            return {"ips": {}, "last_updated": None}
    return {"ips": {}, "last_updated": None}


def save_blacklist(blacklist: Dict[str, Any]):
    """Save the local blacklist to file."""
    try:
        with open(BLACKLIST_FILE, 'w', encoding='utf-8') as f:
            json.dump(blacklist, f, indent=2)
        return True
    except Exception as e:
        print_error(f"Error saving blacklist: {e}")
        return False


def add_to_blacklist(ip: str, reason: str, source: str = "manual") -> bool:
    """
    Add an IP to the local blacklist.
    
    Parameters
    ----------
    ip : str
        IP address to blacklist
    reason : str
        Reason for blacklisting
    source : str
        Source of the blacklist entry (manual, abuseipdb, etc.)
    
    Returns
    -------
    bool
        True if successful
    """
    blacklist = load_blacklist()
    
    blacklist["ips"][ip] = {
        "reason": reason,
        "source": source,
        "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "confidence": "high" if source == "abuseipdb" else "medium"
    }
    blacklist["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    return save_blacklist(blacklist)


def remove_from_blacklist(ip: str) -> bool:
    """
    Remove an IP from the local blacklist.
    
    Parameters
    ----------
    ip : str
        IP address to remove
    
    Returns
    -------
    bool
        True if successful
    """
    blacklist = load_blacklist()
    
    if ip in blacklist["ips"]:
        del blacklist["ips"][ip]
        blacklist["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return save_blacklist(blacklist)
    
    return False


def is_blacklisted(ip: str) -> Optional[Dict[str, Any]]:
    """
    Check if an IP is in the local blacklist.
    
    Parameters
    ----------
    ip : str
        IP address to check
    
    Returns
    -------
    dict or None
        Blacklist entry if found, None otherwise
    """
    blacklist = load_blacklist()
    return blacklist["ips"].get(ip)


def get_blacklist() -> List[Dict[str, Any]]:
    """
    Get all blacklisted IPs with their metadata.
    
    Returns
    -------
    list[dict]
        List of blacklisted IPs with metadata
    """
    blacklist = load_blacklist()
    return [
        {
            "ip": ip,
            **metadata
        }
        for ip, metadata in blacklist["ips"].items()
    ]


# ─────────────────────────────────────────────
# AbuseIPDB Integration
# ─────────────────────────────────────────────

def check_abuseipdb(ip: str, api_key: str = None) -> Optional[Dict[str, Any]]:
    """
    Check IP reputation using AbuseIPDB API.
    
    Parameters
    ----------
    ip : str
        IP address to check
    api_key : str, optional
        AbuseIPDB API key (uses default if not provided)
    
    Returns
    -------
    dict or None
        AbuseIPDB response data or None if error
    """
    key = api_key or ABUSEIPDB_API_KEY
    
    if not key:
        print_warn("No AbuseIPDB API key configured")
        return None
    
    try:
        headers = {
            "Key": key,
            "Accept": "application/json"
        }
        
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        
        response = requests.get(
            ABUSEIPDB_API_URL,
            headers=headers,
            params=params,
            timeout=10
        )
        
        if response.status_code == 200:
            return response.json().get("data")
        elif response.status_code == 401:
            print_error("Invalid AbuseIPDB API key")
            return None
        else:
            print_error(f"AbuseIPDB API error: {response.status_code}")
            return None
            
    except requests.RequestException as e:
        print_error(f"AbuseIPDB request error: {e}")
        return None


def check_ip_reputation(ip: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Check IP reputation using multiple sources.
    
    Parameters
    ----------
    ip : str
        IP address to check
    use_cache : bool
        Whether to use cached results
    
    Returns
    -------
    dict
        Reputation information from all sources
    """
    result = {
        "ip": ip,
        "blacklisted": False,
        "abuseipdb": None,
        "confidence_score": 0,
        "sources": []
    }
    
    # Check local blacklist first
    blacklist_entry = is_blacklisted(ip)
    if blacklist_entry:
        result["blacklisted"] = True
        result["confidence_score"] += 50
        result["sources"].append("local_blacklist")
        result["blacklist_entry"] = blacklist_entry
    
    # Check AbuseIPDB if API key is available
    if ABUSEIPDB_API_KEY:
        abuseipdb_data = check_abuseipdb(ip)
        if abuseipdb_data:
            result["abuseipdb"] = abuseipdb_data
            result["sources"].append("abuseipdb")
            
            # Calculate confidence score based on AbuseIPDB data
            abuse_confidence = abuseipdb_data.get("abuseConfidenceScore", 0)
            result["confidence_score"] += abuse_confidence
            
            # Auto-add to blacklist if high confidence
            if abuse_confidence >= 75:
                add_to_blacklist(
                    ip,
                    f"Auto-blocked: AbuseIPDB confidence {abuse_confidence}%",
                    "abuseipdb"
                )
                result["blacklisted"] = True
    
    return result


# ─────────────────────────────────────────────
# Database Integration
# ─────────────────────────────────────────────

def init_threat_intel_db():
    """Initialize threat intelligence database tables."""
    conn = get_connection()
    try:
        # Create threat intel table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                reputation_score INTEGER DEFAULT 0,
                is_blacklisted BOOLEAN DEFAULT 0,
                abuseipdb_data TEXT,
                last_checked DATETIME DEFAULT CURRENT_TIMESTAMP,
                source TEXT
            )
        """)
        
        # Create index for faster lookups
        conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_intel_ip ON threat_intel(ip)")
        
        conn.commit()
        return True
    except Exception as e:
        print_error(f"Error initializing threat intel DB: {e}")
        return False
    finally:
        conn.close()


def update_threat_intel_db(ip: str, reputation_data: Dict[str, Any]):
    """
    Update threat intelligence database with IP reputation data.
    
    Parameters
    ----------
    ip : str
        IP address
    reputation_data : dict
        Reputation data from check_ip_reputation
    """
    conn = get_connection()
    try:
        # Check if IP already exists
        cursor = conn.execute("SELECT id FROM threat_intel WHERE ip = ?", (ip,))
        existing = cursor.fetchone()
        
        abuseipdb_json = json.dumps(reputation_data.get("abuseipdb")) if reputation_data.get("abuseipdb") else None
        
        if existing:
            # Update existing record
            conn.execute("""
                UPDATE threat_intel
                SET reputation_score = ?, is_blacklisted = ?, abuseipdb_data = ?, last_checked = CURRENT_TIMESTAMP
                WHERE ip = ?
            """, (
                reputation_data.get("confidence_score", 0),
                reputation_data.get("blacklisted", False),
                abuseipdb_json,
                ip
            ))
        else:
            # Insert new record
            conn.execute("""
                INSERT INTO threat_intel (ip, reputation_score, is_blacklisted, abuseipdb_data, source)
                VALUES (?, ?, ?, ?, ?)
            """, (
                ip,
                reputation_data.get("confidence_score", 0),
                reputation_data.get("blacklisted", False),
                abuseipdb_json,
                ",".join(reputation_data.get("sources", []))
            ))
        
        conn.commit()
    except Exception as e:
        print_error(f"Error updating threat intel DB: {e}")
    finally:
        conn.close()


def get_threat_intel_from_db(ip: str) -> Optional[Dict[str, Any]]:
    """
    Get threat intelligence data from database.
    
    Parameters
    ----------
    ip : str
        IP address
    
    Returns
    -------
    dict or None
        Threat intelligence data or None if not found
    """
    conn = get_connection()
    try:
        cursor = conn.execute("""
            SELECT ip, reputation_score, is_blacklisted, abuseipdb_data, last_checked, source
            FROM threat_intel
            WHERE ip = ?
        """, (ip,))
        
        row = cursor.fetchone()
        if row:
            return {
                "ip": row["ip"],
                "reputation_score": row["reputation_score"],
                "is_blacklisted": row["is_blacklisted"],
                "abuseipdb_data": json.loads(row["abuseipdb_data"]) if row["abuseipdb_data"] else None,
                "last_checked": row["last_checked"],
                "source": row["source"]
            }
        return None
    except Exception as e:
        print_error(f"Error getting threat intel from DB: {e}")
        return None
    finally:
        conn.close()


# ─────────────────────────────────────────────
# Integration Functions
# ─────────────────────────────────────────────

def analyze_ips_threat_intel(ips: List[str], auto_block: bool = True) -> List[Dict[str, Any]]:
    """
    Analyze multiple IPs for threat intelligence.
    
    Parameters
    ----------
    ips : list[str]
        List of IP addresses to analyze
    auto_block : bool
        Whether to automatically add high-confidence IPs to blacklist
    
    Returns
    -------
    list[dict]
        List of threat intelligence results
    """
    init_threat_intel_db()
    
    results = []
    for ip in set(ips):  # Deduplicate IPs
        reputation = check_ip_reputation(ip)
        
        # Update database
        update_threat_intel_db(ip, reputation)
        
        results.append(reputation)
        
        # Alert if blacklisted
        if reputation.get("blacklisted"):
            print_warn(f"Blacklisted IP detected: {ip} (confidence: {reputation.get('confidence_score', 0)})")
    
    return results


def configure_abuseipdb(api_key: str):
    """
    Configure AbuseIPDB API key.
    
    Parameters
    ----------
    api_key : str
        AbuseIPDB API key
    """
    global ABUSEIPDB_API_KEY
    ABUSEIPDB_API_KEY = api_key
    print_ok("AbuseIPDB API key configured")


# ─────────────────────────────────────────────
# Standalone Entry Point
# ─────────────────────────────────────────────

def main():
    """Test threat intelligence module."""
    from report import fix_encoding
    fix_encoding()
    
    if len(sys.argv) < 2:
        print(f"{Colors.RED}Usage: python threat_intel.py <ip_address>{Colors.RESET}")
        print(f"{Colors.DIM}Example: python threat_intel.py 8.8.8.8{Colors.RESET}")
        sys.exit(1)
    
    ip = sys.argv[1]
    
    print_info(f"Checking threat intelligence for: {ip}")
    
    # Check local blacklist
    blacklist_entry = is_blacklisted(ip)
    if blacklist_entry:
        print_warn(f"IP found in local blacklist:")
        print(f"  Reason: {blacklist_entry['reason']}")
        print(f"  Source: {blacklist_entry['source']}")
        print(f"  Added: {blacklist_entry['added_at']}")
    else:
        print_ok("IP not in local blacklist")
    
    # Check AbuseIPDB if API key is configured
    if ABUSEIPDB_API_KEY:
        print_info("Checking AbuseIPDB...")
        abuseipdb_data = check_abuseipdb(ip)
        if abuseipdb_data:
            print_ok("AbuseIPDB data retrieved:")
            print(f"  Abuse Confidence Score: {abuseipdb_data.get('abuseConfidenceScore', 0)}")
            print(f"  Total Reports: {abuseipdb_data.get('totalReports', 0)}")
            print(f"  Last Report: {abuseipdb_data.get('lastReportedAt', 'N/A')}")
        else:
            print_warn("No AbuseIPDB data available")
    else:
        print_info("AbuseIPDB API key not configured")
        print_info("Set API key with: configure_abuseipdb('your_api_key')")
    
    # Full reputation check
    print_info("\nFull reputation check:")
    reputation = check_ip_reputation(ip)
    print(f"  Confidence Score: {reputation.get('confidence_score', 0)}")
    print(f"  Blacklisted: {reputation.get('blacklisted', False)}")
    print(f"  Sources: {', '.join(reputation.get('sources', []))}")


if __name__ == "__main__":
    import sys
    main()

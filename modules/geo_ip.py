#!/usr/bin/env python3
"""
Geo-IP Tracking Module
======================
Provides IP geolocation and impossible travel detection using the MaxMind GeoIP2 database.

Features:
  - IP to Country/City mapping
  - Impossible travel detection (same IP in different locations within short time)
  - Suspicious region flagging
  - Integration with alerting system

Usage:
    from geoip import get_ip_location, detect_impossible_travel
    
    location = get_ip_location("8.8.8.8")
    alerts = detect_impossible_travel(log_entries)
"""

import sys
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from collections import defaultdict

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

from core.report import Colors, print_ok, print_warn, print_error, print_info
from core.database import get_logs_by_ip, store_alert, init_database
from core.alerting import send_alert


# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

# MaxMind GeoIP2 database path (will be downloaded if not present)
GEOIP_DB_PATH = "data/GeoLite2-City.mmdb"

# Impossible travel thresholds
IMPOSSIBLE_TRAVEL_DISTANCE_KM = 1000  # Distance threshold for impossible travel
IMPOSSIBLE_TRAVEL_TIME_MINUTES = 30   # Time threshold for impossible travel

# Suspicious regions (can be customized)
SUSPICIOUS_COUNTRIES = [
    "CN",  # China
    "RU",  # Russia
    "KP",  # North Korea
    "IR",  # Iran
]

# Cache for IP locations to avoid repeated lookups
_ip_location_cache = {}


# ─────────────────────────────────────────────
# GeoIP Database Management
# ─────────────────────────────────────────────

def get_geoip_reader():
    """Get a GeoIP2 database reader."""
    if not GEOIP_AVAILABLE:
        return None
    
    try:
        reader = geoip2.database.Reader(GEOIP_DB_PATH)
        return reader
    except Exception as e:
        print_error(f"Failed to open GeoIP database: {e}")
        print_info(f"Download GeoLite2-City.mmdb from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
        return None


def init_geoip():
    """Initialize GeoIP database (download if needed)."""
    if not GEOIP_AVAILABLE:
        print_warn("geoip2 library not available. Install with: pip install geoip2")
        return False
    
    import os
    if not os.path.exists(GEOIP_DB_PATH):
        print_warn(f"GeoIP database not found at {GEOIP_DB_PATH}")
        print_info("Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
        print_info("Place the file in the current directory as GeoLite2-City.mmdb")
        return False
    
    reader = get_geoip_reader()
    if reader:
        print_ok("GeoIP database initialized successfully")
        reader.close()
        return True
    
    return False


# ─────────────────────────────────────────────
# IP Geolocation
# ─────────────────────────────────────────────

def get_ip_location(ip: str) -> Optional[Dict[str, Any]]:
    """
    Get geolocation information for an IP address.
    
    Parameters
    ----------
    ip : str
        IP address to lookup
    
    Returns
    -------
    dict or None
        Dictionary with country, city, latitude, longitude, etc.
    """
    if ip in _ip_location_cache:
        return _ip_location_cache[ip]
    
    reader = get_geoip_reader()
    if not reader:
        return None
    
    try:
        response = reader.city(ip)
        
        location = {
            "ip": ip,
            "country_code": response.country.iso_code if response.country.iso_code else "Unknown",
            "country_name": response.country.name if response.country.name else "Unknown",
            "city": response.city.name if response.city.name else "Unknown",
            "latitude": response.location.latitude if response.location.latitude else 0.0,
            "longitude": response.location.longitude if response.location.longitude else 0.0,
            "is_suspicious": response.country.iso_code in SUSPICIOUS_COUNTRIES if response.country.iso_code else False,
        }
        
        _ip_location_cache[ip] = location
        reader.close()
        return location
        
    except geoip2.errors.AddressNotFoundError:
        # IP not in database
        _ip_location_cache[ip] = None
        return None
    except Exception as e:
        print_error(f"GeoIP lookup error for {ip}: {e}")
        return None


def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate distance between two coordinates using Haversine formula.
    
    Parameters
    ----------
    lat1, lon1 : float
        Latitude and longitude of first point
    lat2, lon2 : float
        Latitude and longitude of second point
    
    Returns
    -------
    float
        Distance in kilometers
    """
    from math import radians, cos, sin, asin, sqrt
    
    # Convert to radians
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    
    # Haversine formula
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    
    # Radius of Earth in kilometers
    r = 6371
    return c * r


# ─────────────────────────────────────────────
# Impossible Travel Detection
# ─────────────────────────────────────────────

def detect_impossible_travel(
    ip_locations: Dict[str, Dict[str, Any]],
    time_window_hours: int = 24
) -> List[Dict[str, Any]]:
    """
    Detect impossible travel patterns (same IP in different locations within short time).
    
    Parameters
    ----------
    ip_locations : dict
        Dictionary mapping IP to location data with timestamps
    time_window_hours : int
        Time window to analyze (default: 24 hours)
    
    Returns
    -------
    list[dict]
        List of impossible travel alerts
    """
    alerts = []
    
    # Group by IP
    ip_data = defaultdict(list)
    for ip, data in ip_locations.items():
        if data and "timestamp" in data:
            ip_data[ip].append(data)
    
    # Check each IP for impossible travel
    for ip, entries in ip_data.items():
        if len(entries) < 2:
            continue
        
        # Sort by timestamp
        entries.sort(key=lambda x: x.get("timestamp", ""))
        
        # Check consecutive entries
        for i in range(len(entries) - 1):
            entry1 = entries[i]
            entry2 = entries[i + 1]
            
            # Calculate time difference
            try:
                time1 = datetime.strptime(entry1["timestamp"], "%Y-%m-%d %H:%M:%S")
                time2 = datetime.strptime(entry2["timestamp"], "%Y-%m-%d %H:%M:%S")
                time_diff = (time2 - time1).total_seconds() / 60  # minutes
            except (ValueError, KeyError):
                continue
            
            # Skip if time difference is too large (not impossible travel)
            if time_diff > IMPOSSIBLE_TRAVEL_TIME_MINUTES:
                continue
            
            # Calculate distance
            distance = calculate_distance(
                entry1.get("latitude", 0),
                entry1.get("longitude", 0),
                entry2.get("latitude", 0),
                entry2.get("longitude", 0)
            )
            
            # Check if distance is impossible
            if distance > IMPOSSIBLE_TRAVEL_DISTANCE_KM:
                alert = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "category": "Impossible Travel",
                    "severity": "HIGH",
                    "detail": f"Impossible travel detected for IP {ip}",
                    "evidence": (
                        f"Location 1: {entry1.get('city', 'Unknown')}, {entry1.get('country_name', 'Unknown')} "
                        f"at {entry1.get('timestamp', 'Unknown')}\n"
                        f"Location 2: {entry2.get('city', 'Unknown')}, {entry2.get('country_name', 'Unknown')} "
                        f"at {entry2.get('timestamp', 'Unknown')}\n"
                        f"Distance: {distance:.1f} km in {time_diff:.1f} minutes "
                        f"(requires > {IMPOSSIBLE_TRAVEL_DISTANCE_KM} km in {IMPOSSIBLE_TRAVEL_TIME_MINUTES} min)"
                    ),
                    "related_ip": ip,
                }
                alerts.append(alert)
    
    return alerts


def detect_suspicious_regions(ip: str) -> Optional[Dict[str, Any]]:
    """
    Check if an IP is from a suspicious region.
    
    Parameters
    ----------
    ip : str
        IP address to check
    
    Returns
    -------
    dict or None
        Alert if IP is from suspicious region
    """
    location = get_ip_location(ip)
    
    if not location:
        return None
    
    if location.get("is_suspicious"):
        alert = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "category": "Suspicious Region",
            "severity": "MEDIUM",
            "detail": f"Traffic from suspicious country: {location.get('country_name', 'Unknown')}",
            "evidence": f"IP {ip} is from {location.get('country_name', 'Unknown')} ({location.get('country_code', 'Unknown')})",
            "related_ip": ip,
        }
        return alert
    
    return None


# ─────────────────────────────────────────────
# Integration with Log Analysis
# ─────────────────────────────────────────────

def analyze_log_geoip(log_entries: List[Dict[str, Any]], store_to_db: bool = True) -> List[Dict[str, Any]]:
    """
    Analyze log entries for GeoIP threats.
    
    Parameters
    ----------
    log_entries : list[dict]
        List of log entries with IP addresses
    store_to_db : bool
        Whether to store alerts to database
    
    Returns
    -------
    list[dict]
        List of GeoIP-related alerts
    """
    if not GEOIP_AVAILABLE:
        print_warn("GeoIP not available, skipping GeoIP analysis")
        return []
    
    alerts = []
    ip_locations = {}
    
    # Get location for each unique IP
    unique_ips = set(entry.get("ip") for entry in log_entries if entry.get("ip"))
    
    print_info(f"Analyzing GeoIP for {len(unique_ips)} unique IPs...")
    
    for ip in unique_ips:
        location = get_ip_location(ip)
        if location:
            # Add timestamp from first log entry for this IP
            first_entry = next((e for e in log_entries if e.get("ip") == ip), None)
            if first_entry:
                location["timestamp"] = first_entry.get("time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            ip_locations[ip] = location
            
            # Check for suspicious regions
            suspicious_alert = detect_suspicious_regions(ip)
            if suspicious_alert:
                alerts.append(suspicious_alert)
    
    # Detect impossible travel
    if len(ip_locations) > 1:
        print_info("Checking for impossible travel patterns...")
        travel_alerts = detect_impossible_travel(ip_locations)
        alerts.extend(travel_alerts)
    
    # Store alerts
    if store_to_db and alerts:
        init_database()
        for alert in alerts:
            store_alert(
                category=alert["category"],
                severity=alert["severity"],
                detail=alert["detail"],
                evidence=alert["evidence"],
                source="geoip",
                related_ip=alert.get("related_ip")
            )
        
        # Send notifications for high-severity alerts
        for alert in alerts:
            if alert["severity"] in ["HIGH", "CRITICAL"]:
                send_alert(alert, channels=["file", "json"])
    
    print_ok(f"GeoIP analysis complete: {len(alerts)} alerts generated")
    return alerts


def enrich_log_with_geoip(log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enrich log entries with GeoIP information.
    
    Parameters
    ----------
    log_entries : list[dict]
        List of log entries
    
    Returns
    -------
    list[dict]
        Log entries enriched with GeoIP data
    """
    if not GEOIP_AVAILABLE:
        return log_entries
    
    enriched_entries = []
    unique_ips = set(entry.get("ip") for entry in log_entries if entry.get("ip"))
    
    # Cache locations
    ip_locations = {}
    for ip in unique_ips:
        location = get_ip_location(ip)
        if location:
            ip_locations[ip] = location
    
    # Enrich entries
    for entry in log_entries:
        ip = entry.get("ip")
        if ip and ip in ip_locations:
            enriched_entry = entry.copy()
            enriched_entry["geoip"] = ip_locations[ip]
            enriched_entries.append(enriched_entry)
        else:
            enriched_entries.append(entry)
    
    return enriched_entries


# ─────────────────────────────────────────────
# Utility Functions
# ─────────────────────────────────────────────

def get_ip_summary(ip: str) -> Dict[str, Any]:
    """
    Get a summary of information for an IP address.
    
    Parameters
    ----------
    ip : str
        IP address
    
    Returns
    -------
    dict
        Summary including location, recent logs, etc.
    """
    location = get_ip_location(ip)
    logs = get_logs_by_ip(ip, limit=10)
    
    return {
        "ip": ip,
        "location": location,
        "recent_logs_count": len(logs),
        "is_suspicious": location.get("is_suspicious", False) if location else False,
    }


def clear_geoip_cache():
    """Clear the IP location cache."""
    global _ip_location_cache
    _ip_location_cache.clear()


# ─────────────────────────────────────────────
# Standalone Entry Point
# ─────────────────────────────────────────────

def main():
    from core.report import fix_encoding
    fix_encoding()

    if len(sys.argv) < 2:
        print(f"{Colors.RED}Usage: python geoip.py <ip_address>{Colors.RESET}")
        print(f"{Colors.DIM}Example: python geoip.py 8.8.8.8{Colors.RESET}")
        sys.exit(1)
    
    ip = sys.argv[1]
    
    if not init_geoip():
        sys.exit(1)
    
    print_info(f"Looking up IP: {ip}")
    location = get_ip_location(ip)
    
    if location:
        print_ok(f"Location found:")
        print(f"  Country: {location.get('country_name', 'Unknown')} ({location.get('country_code', 'Unknown')})")
        print(f"  City: {location.get('city', 'Unknown')}")
        print(f"  Coordinates: {location.get('latitude', 0):.4f}, {location.get('longitude', 0):.4f}")
        print(f"  Suspicious: {location.get('is_suspicious', False)}")
    else:
        print_warn("Location not found for this IP")


if __name__ == "__main__":
    main()

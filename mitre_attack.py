#!/usr/bin/env python3
"""
MITRE ATT&CK Mapping Module
===========================
Maps SIEM-Lite detections to MITRE ATT&CK techniques and tactics.
Provides industry-standard threat intelligence context.

Features:
  - Detection category to MITRE technique mapping
  - Tactic and technique information
  - Integration with findings and alerts
  - MITRE reference URLs

Usage:
    from mitre_attack import get_mitre_mapping, enrich_with_mitre
    
    mapping = get_mitre_mapping("SQL Injection")
    enriched_finding = enrich_with_mitre(finding)
"""

from typing import Optional, Dict, Any, List

# ─────────────────────────────────────────────
# MITRE ATT&CK Mappings
# ─────────────────────────────────────────────

# Mapping of SIEM-Lite detection categories to MITRE ATT&CK techniques
MITRE_MAPPINGS = {
    # Initial Access
    "Brute Force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries may attempt to brute force credentials.",
        "url": "https://attack.mitre.org/techniques/T1110/"
    },
    
    # Credential Access
    "Brute Force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries may use brute force to access credentials.",
        "url": "https://attack.mitre.org/techniques/T1110/"
    },
    
    # Execution
    "Web Shell": {
        "technique_id": "T1505.003",
        "technique_name": "Web Shell",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "description": "Adversaries may web shell to execute commands.",
        "url": "https://attack.mitre.org/techniques/T1505/003/"
    },
    
    # Defense Evasion
    "Web Shell": {
        "technique_id": "T1505.003",
        "technique_name": "Web Shell",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "description": "Adversaries may use web shells to evade defenses.",
        "url": "https://attack.mitre.org/techniques/T1505/003/"
    },
    
    # Persistence
    "Web Shell": {
        "technique_id": "T1505.003",
        "technique_name": "Web Shell",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "description": "Adversaries may use web shells for persistence.",
        "url": "https://attack.mitre.org/techniques/T1505/003/"
    },
    
    # Discovery
    "404 Scanning": {
        "technique_id": "T1595.002",
        "technique_name": "Vulnerability Scanning",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "description": "Adversaries may scan for vulnerabilities.",
        "url": "https://attack.mitre.org/techniques/T1595/002/"
    },
    
    # Reconnaissance
    "404 Scanning": {
        "technique_id": "T1595.002",
        "technique_name": "Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "tactic_id": "TA0043",
        "description": "Adversaries may scan for vulnerabilities during reconnaissance.",
        "url": "https://attack.mitre.org/techniques/T1595/002/"
    },
    
    # Initial Access
    "SQL Injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries may exploit public-facing applications.",
        "url": "https://attack.mitre.org/techniques/T1190/"
    },
    
    # Execution
    "SQL Injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "description": "Adversaries may execute code via SQL injection.",
        "url": "https://attack.mitre.org/techniques/T1190/"
    },
    
    # Initial Access
    "XSS": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries may exploit XSS for initial access.",
        "url": "https://attack.mitre.org/techniques/T1190/"
    },
    
    # Execution
    "XSS": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "description": "Adversaries may exploit XSS for client execution.",
        "url": "https://attack.mitre.org/techniques/T1203/"
    },
    
    # Discovery
    "Malicious URI": {
        "technique_id": "T1595.001",
        "technique_name": "Vulnerability Scanning",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "description": "Adversaries may scan for vulnerabilities via malicious URIs.",
        "url": "https://attack.mitre.org/techniques/T1595/001/"
    },
    
    # Initial Access
    "Malicious URI": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries may exploit via malicious URIs.",
        "url": "https://attack.mitre.org/techniques/T1190/"
    },
    
    # Discovery
    "Port Scan": {
        "technique_id": "T1595.002",
        "technique_name": "Vulnerability Scanning",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "description": "Adversaries may scan ports to discover services.",
        "url": "https://attack.mitre.org/techniques/T1595/002/"
    },
    
    # Reconnaissance
    "Port Scan": {
        "technique_id": "T1595.002",
        "technique_name": "Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "tactic_id": "TA0043",
        "description": "Adversaries may scan ports during reconnaissance.",
        "url": "https://attack.mitre.org/techniques/T1595/002/"
    },
    
    # Discovery
    "Suspicious Frequency": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "description": "Adversaries may enumerate files and directories.",
        "url": "https://attack.mitre.org/techniques/T1083/"
    },
    
    # Defense Evasion
    "Security Headers": {
        "technique_id": "T1562.007",
        "technique_name": "Disable or Modify Security Headers",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "description": "Adversaries may disable security headers.",
        "url": "https://attack.mitre.org/techniques/T1562/007/"
    },
    
    # Initial Access
    "Impossible Travel": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries may use valid accounts from different locations.",
        "url": "https://attack.mitre.org/techniques/T1078/"
    },
    
    # Defense Evasion
    "Impossible Travel": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "description": "Adversaries may use valid accounts to evade detection.",
        "url": "https://attack.mitre.org/techniques/T1078/"
    },
    
    # Resource Development
    "Suspicious Region": {
        "technique_id": "T1583",
        "technique_name": "Acquire Infrastructure",
        "tactic": "Resource Development",
        "tactic_id": "TA0042",
        "description": "Adversaries may acquire infrastructure in suspicious regions.",
        "url": "https://attack.mitre.org/techniques/T1583/"
    },
    
    # Initial Access
    "Correlation": {
        "technique_id": "T1110",
        "technique_name": "Multi-Stage Attack",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Correlated attacks indicate multi-stage intrusion.",
        "url": "https://attack.mitre.org/tactics/TA0001/"
    },
}


# ─────────────────────────────────────────────
# MITRE Mapping Functions
# ─────────────────────────────────────────────

def get_mitre_mapping(category: str) -> Optional[Dict[str, Any]]:
    """
    Get MITRE ATT&CK mapping for a detection category.
    
    Parameters
    ----------
    category : str
        Detection category (e.g., "SQL Injection", "Brute Force")
    
    Returns
    -------
    dict or None
        MITRE mapping information or None if not found
    """
    return MITRE_MAPPINGS.get(category)


def get_all_mitre_mappings() -> Dict[str, Any]:
    """
    Get all MITRE ATT&CK mappings.
    
    Returns
    -------
    dict
        All MITRE mappings
    """
    return MITRE_MAPPINGS.copy()


def get_techniques_by_tactic(tactic: str) -> List[Dict[str, Any]]:
    """
    Get all techniques for a specific tactic.
    
    Parameters
    ----------
    tactic : str
        Tactic name (e.g., "Initial Access", "Discovery")
    
    Returns
    -------
    list[dict]
        List of technique mappings for the tactic
    """
    techniques = []
    for category, mapping in MITRE_MAPPINGS.items():
        if mapping.get("tactic") == tactic:
            techniques.append({
                "category": category,
                **mapping
            })
    return techniques


def get_tactics_summary() -> Dict[str, List[str]]:
    """
    Get a summary of tactics and their associated techniques.
    
    Returns
    -------
    dict
        Dictionary mapping tactic names to technique IDs
    """
    tactics = {}
    for category, mapping in MITRE_MAPPINGS.items():
        tactic = mapping.get("tactic", "Unknown")
        technique_id = mapping.get("technique_id", "Unknown")
        
        if tactic not in tactics:
            tactics[tactic] = []
        
        if technique_id not in tactics[tactic]:
            tactics[tactic].append(technique_id)
    
    return tactics


# ─────────────────────────────────────────────
# Finding Enrichment
# ─────────────────────────────────────────────

def enrich_with_mitre(finding) -> Dict[str, Any]:
    """
    Enrich a Finding with MITRE ATT&CK information.
    
    Parameters
    ----------
    finding : Finding
        Finding namedtuple to enrich
    
    Returns
    -------
    dict
        Enriched finding with MITRE information
    """
    mitre_info = get_mitre_mapping(finding.category)
    
    enriched = {
        "category": finding.category,
        "severity": finding.severity,
        "detail": finding.detail,
        "evidence": finding.evidence,
        "mitre_technique_id": mitre_info.get("technique_id") if mitre_info else None,
        "mitre_technique_name": mitre_info.get("technique_name") if mitre_info else None,
        "mitre_tactic": mitre_info.get("tactic") if mitre_info else None,
        "mitre_tactic_id": mitre_info.get("tactic_id") if mitre_info else None,
        "mitre_url": mitre_info.get("url") if mitre_info else None,
    }
    
    return enriched


def enrich_alert_with_mitre(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich an alert dictionary with MITRE ATT&CK information.
    
    Parameters
    ----------
    alert : dict
        Alert dictionary to enrich
    
    Returns
    -------
    dict
        Enriched alert with MITRE information
    """
    category = alert.get("category", "")
    mitre_info = get_mitre_mapping(category)
    
    if mitre_info:
        alert["mitre_technique_id"] = mitre_info.get("technique_id")
        alert["mitre_technique_name"] = mitre_info.get("technique_name")
        alert["mitre_tactic"] = mitre_info.get("tactic")
        alert["mitre_tactic_id"] = mitre_info.get("tactic_id")
        alert["mitre_url"] = mitre_info.get("url")
    
    return alert


# ─────────────────────────────────────────────
# MITRE Statistics
# ─────────────────────────────────────────────

def get_mitre_statistics(findings: List) -> Dict[str, Any]:
    """
    Get MITRE ATT&CK statistics from findings.
    
    Parameters
    ----------
    findings : list
        List of Finding objects or alert dictionaries
    
    Returns
    -------
    dict
        MITRE statistics including tactic and technique counts
    """
    tactic_counts = {}
    technique_counts = {}
    
    for finding in findings:
        # Handle both Finding objects and dictionaries
        if hasattr(finding, 'category'):
            category = finding.category
        else:
            category = finding.get("category", "")
        
        mitre_info = get_mitre_mapping(category)
        if mitre_info:
            tactic = mitre_info.get("tactic", "Unknown")
            technique_id = mitre_info.get("technique_id", "Unknown")
            
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
            technique_counts[technique_id] = technique_counts.get(technique_id, 0) + 1
    
    return {
        "tactic_counts": tactic_counts,
        "technique_counts": technique_counts,
        "total_mapped": sum(tactic_counts.values()),
    }


# ─────────────────────────────────────────────
# MITRE Reference Generator
# ─────────────────────────────────────────────

def generate_mitre_report(findings: List) -> str:
    """
    Generate a MITRE ATT&CK reference report from findings.
    
    Parameters
    ----------
    findings : list
        List of Finding objects or alert dictionaries
    
    Returns
    -------
    str
        Formatted MITRE report
    """
    stats = get_mitre_statistics(findings)
    
    report = []
    report.append("MITRE ATT&CK Analysis Report")
    report.append("=" * 50)
    report.append(f"Total Mapped Findings: {stats['total_mapped']}")
    report.append("")
    
    if stats["tactic_counts"]:
        report.append("Tactics Distribution:")
        for tactic, count in sorted(stats["tactic_counts"].items()):
            report.append(f"  - {tactic}: {count}")
        report.append("")
    
    if stats["technique_counts"]:
        report.append("Techniques Distribution:")
        for technique, count in sorted(stats["technique_counts"].items()):
            report.append(f"  - {technique}: {count}")
        report.append("")
    
    report.append("MITRE ATT&CK Reference:")
    report.append("https://attack.mitre.org/")
    
    return "\n".join(report)


# ─────────────────────────────────────────────
# Standalone Entry Point
# ─────────────────────────────────────────────

def main():
    """Test MITRE ATT&CK mapping."""
    print("MITRE ATT&CK Mapping Test")
    print("=" * 50)
    
    # Test mappings
    test_categories = [
        "SQL Injection",
        "Brute Force",
        "Web Shell",
        "XSS",
        "404 Scanning",
        "Malicious URI",
        "Port Scan",
        "Impossible Travel",
    ]
    
    for category in test_categories:
        mapping = get_mitre_mapping(category)
        if mapping:
            print(f"\n{category}:")
            print(f"  Technique: {mapping['technique_id']} - {mapping['technique_name']}")
            print(f"  Tactic: {mapping['tactic_id']} - {mapping['tactic']}")
            print(f"  URL: {mapping['url']}")
        else:
            print(f"\n{category}: No mapping found")
    
    # Test tactics summary
    print("\n\nTactics Summary:")
    print("=" * 50)
    tactics = get_tactics_summary()
    for tactic, techniques in sorted(tactics.items()):
        print(f"{tactic}: {', '.join(techniques)}")


if __name__ == "__main__":
    main()

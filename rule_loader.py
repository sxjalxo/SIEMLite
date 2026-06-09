#!/usr/bin/env python3
"""
Rule Loader Module
==================
Plugin-based rule system for extensible custom detection rules.
Loads and executes custom rules from the rules/ directory.

Features:
  - Dynamic rule loading from rules/ directory
  - Standardized rule interface
  - Error handling and validation
  - Integration with log analysis

Usage:
    from rule_loader import load_rules, run_custom_rules
    
    rules = load_rules()
    findings = run_custom_rules(log_entries, rules)
"""

import os
import sys
import importlib.util
import inspect
from pathlib import Path
from typing import List, Dict, Any, Callable

from report import Colors, print_ok, print_warn, print_error, print_info


# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

RULES_DIR = Path("rules")

# Required function name in rule files
REQUIRED_FUNCTION = "detect"

# Expected function signature: detect(entries: List[Dict]) -> List[Dict]


# ─────────────────────────────────────────────
# Rule Loading
# ─────────────────────────────────────────────

def load_rules() -> Dict[str, Callable]:
    """
    Load all custom rules from the rules/ directory.
    
    Returns
    -------
    dict
        Dictionary mapping rule names to detect functions
    """
    rules = {}
    
    if not RULES_DIR.exists():
        print_warn(f"Rules directory not found: {RULES_DIR}")
        print_info("Create custom rules in the rules/ directory")
        return rules
    
    # Find all Python files in rules directory
    rule_files = list(RULES_DIR.glob("*.py"))
    
    if not rule_files:
        print_info(f"No custom rules found in {RULES_DIR}")
        return rules
    
    print_info(f"Loading {len(rule_files)} custom rule(s) from {RULES_DIR}...")
    
    for rule_file in rule_files:
        # Skip __init__.py and files starting with underscore
        if rule_file.name.startswith("_"):
            continue
        
        rule_name = rule_file.stem
        
        try:
            # Load the module
            spec = importlib.util.spec_from_file_location(rule_name, rule_file)
            if spec is None or spec.loader is None:
                print_error(f"Could not load spec for rule: {rule_name}")
                continue
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Check for required function
            if not hasattr(module, REQUIRED_FUNCTION):
                print_warn(f"Rule {rule_name} missing required function: {REQUIRED_FUNCTION}")
                continue
            
            # Validate function signature
            detect_func = getattr(module, REQUIRED_FUNCTION)
            if not callable(detect_func):
                print_error(f"Rule {rule_name}: {REQUIRED_FUNCTION} is not callable")
                continue
            
            # Store the rule
            rules[rule_name] = detect_func
            print_ok(f"Loaded rule: {rule_name}")
            
        except Exception as e:
            print_error(f"Error loading rule {rule_name}: {e}")
    
    return rules


def validate_rule(detect_func: Callable) -> bool:
    """
    Validate that a rule function has the correct signature.
    
    Parameters
    ----------
    detect_func : callable
        The detect function to validate
    
    Returns
    -------
    bool
        True if valid
    """
    try:
        sig = inspect.signature(detect_func)
        params = list(sig.parameters.keys())
        
        # Should have at least one parameter (entries)
        if len(params) < 1:
            return False
        
        # First parameter should be entries
        if params[0] != "entries":
            return False
        
        return True
        
    except Exception:
        return False


# ─────────────────────────────────────────────
# Rule Execution
# ─────────────────────────────────────────────

def run_custom_rules(log_entries: List[Dict[str, Any]], rules: Dict[str, Callable] = None) -> List[Dict[str, Any]]:
    """
    Run all custom rules against log entries.
    
    Parameters
    ----------
    log_entries : list[dict]
        List of log entries to analyze
    rules : dict, optional
        Dictionary of rules (if None, will load from rules/)
    
    Returns
    -------
    list[dict]
        List of findings from all custom rules
    """
    if rules is None:
        rules = load_rules()
    
    all_findings = []
    
    for rule_name, detect_func in rules.items():
        try:
            print_info(f"Running custom rule: {rule_name}")
            
            # Execute the rule
            findings = detect_func(log_entries)
            
            # Validate findings format
            if findings:
                # Add rule name to findings
                for finding in findings:
                    if isinstance(finding, dict):
                        finding["rule_name"] = rule_name
                    elif hasattr(finding, "_asdict"):
                        # Handle namedtuples
                        finding_dict = finding._asdict()
                        finding_dict["rule_name"] = rule_name
                        all_findings.append(finding_dict)
                    else:
                        # Convert to dict if possible
                        all_findings.append({
                            "rule_name": rule_name,
                            "category": "Custom Rule",
                            "severity": "MEDIUM",
                            "detail": str(finding),
                            "evidence": f"From rule: {rule_name}"
                        })
                else:
                    all_findings.extend(findings)
            
            if findings:
                print_ok(f"Rule {rule_name} found {len(findings)} issue(s)")
            else:
                print_ok(f"Rule {rule_name} found no issues")
                
        except Exception as e:
            print_error(f"Error executing rule {rule_name}: {e}")
    
    return all_findings


def convert_custom_findings_to_standard(findings: List[Dict[str, Any]]) -> List:
    """
    Convert custom rule findings to standard Finding objects.
    
    Parameters
    ----------
    findings : list[dict]
        List of findings from custom rules
    
    Returns
    -------
    list[Finding]
        List of Finding objects
    """
    from report import Finding
    
    standard_findings = []
    
    for finding in findings:
        # Extract fields with fallbacks
        category = finding.get("category", "Custom Rule")
        severity = finding.get("severity", "MEDIUM")
        detail = finding.get("detail", "Custom rule detection")
        evidence = finding.get("evidence", "")
        
        # Create Finding object
        standard_findings.append(Finding(
            category=category,
            severity=severity,
            detail=detail,
            evidence=evidence
        ))
    
    return standard_findings


# ─────────────────────────────────────────────
# Rule Management
# ─────────────────────────────────────────────

def list_rules() -> List[str]:
    """
    List all available custom rules.
    
    Returns
    -------
    list[str]
        List of rule names
    """
    rules = load_rules()
    return list(rules.keys())


def get_rule_info(rule_name: str) -> Dict[str, Any]:
    """
    Get information about a specific rule.
    
    Parameters
    ----------
    rule_name : str
        Name of the rule
    
    Returns
    -------
    dict
        Rule information
    """
    rules = load_rules()
    
    if rule_name not in rules:
        return {"error": "Rule not found"}
    
    detect_func = rules[rule_name]
    
    return {
        "name": rule_name,
        "function": detect_func.__name__,
        "docstring": detect_func.__doc__,
        "module": detect_func.__module__,
    }


# ─────────────────────────────────────────────
# Standalone Entry Point
# ─────────────────────────────────────────────

def main():
    """Test rule loader."""
    from report import fix_encoding
    fix_encoding()
    
    print("Custom Rule System Test")
    print("=" * 50)
    
    # Load rules
    rules = load_rules()
    
    if not rules:
        print_info("No custom rules found")
        print_info("Create rule files in the rules/ directory")
        print_info("Each rule file must have a 'detect(entries)' function")
        return
    
    print(f"\nLoaded {len(rules)} custom rule(s):")
    for rule_name in rules.keys():
        print(f"  - {rule_name}")
    
    # Get rule info
    print("\nRule Information:")
    for rule_name in rules.keys():
        info = get_rule_info(rule_name)
        print(f"\n{rule_name}:")
        print(f"  Module: {info.get('module', 'Unknown')}")
        if info.get('docstring'):
            print(f"  Description: {info['docstring']}")


if __name__ == "__main__":
    main()

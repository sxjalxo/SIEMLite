#!/usr/bin/env python3
"""
Dashboard — Flask Web Server + REST API
=========================================
Serves the SIEM-Lite dashboard and provides JSON APIs for:
  - Alerts (with severity/type filtering)
  - Aggregate stats
  - Timeline data
  - Raw events

Design Decision:
    Polling-based dashboard updates (5 sec) for simplicity and reliability
    over real-time WebSocket streaming. No extra dependencies needed.
"""

import os
import json
import threading
from datetime import datetime
from collections import Counter, defaultdict

from flask import Flask, render_template, jsonify, request

from log_ingestor import ingest, LogEvent
from detection_engine import run_detection, Alert

# ─────────────────────────────────────────────
# App Setup
# ─────────────────────────────────────────────

app = Flask(__name__, template_folder="templates")

# Global state (thread-safe via GIL for reads; lock for writes)
_lock = threading.Lock()
_state = {
    "events": [],
    "alerts": [],
    "ingestion_stats": [],
    "last_updated": None,
}


def get_state():
    """Return a snapshot of the current state."""
    return _state


def run_pipeline(log_path):
    """Run the full ingestion + detection pipeline and store results."""
    events, stats = ingest(log_path)

    from detection_engine import run_detection
    alerts = run_detection(events)

    with _lock:
        _state["events"] = events
        _state["alerts"] = alerts
        _state["ingestion_stats"] = stats
        _state["last_updated"] = datetime.now().isoformat()

    return events, alerts, stats


# ─────────────────────────────────────────────
# Routes — Pages
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


# ─────────────────────────────────────────────
# Routes — API
# ─────────────────────────────────────────────

@app.route("/api/alerts")
def api_alerts():
    """Get all alerts with optional filtering."""
    state = get_state()
    alerts = state["alerts"]

    # Filters
    severity = request.args.get("severity")
    rule = request.args.get("rule")

    result = []
    for a in alerts:
        if severity and a.severity != severity.upper():
            continue
        if rule and a.rule_name != rule:
            continue
        result.append(a.to_dict())

    return jsonify({"alerts": result, "total": len(result)})


@app.route("/api/stats")
def api_stats():
    """Get aggregate statistics."""
    state = get_state()
    events = state["events"]
    alerts = state["alerts"]

    # Severity counts
    severity_counts = Counter(a.severity for a in alerts)

    # Attack type counts
    attack_counts = Counter(a.rule_name for a in alerts)

    # Source type counts
    source_counts = Counter(e.source_type for e in events)

    # Top attacker IPs
    ip_alert_counts = Counter()
    for a in alerts:
        for ip in a.source_ips:
            ip_alert_counts[ip] += 1

    top_attackers = [
        {"ip": ip, "alert_count": count}
        for ip, count in ip_alert_counts.most_common(10)
    ]

    # Action distribution
    action_counts = Counter(e.action for e in events)

    return jsonify({
        "total_events": len(events),
        "total_alerts": len(alerts),
        "severity_counts": dict(severity_counts),
        "attack_counts": dict(attack_counts),
        "source_counts": dict(source_counts),
        "action_counts": dict(action_counts),
        "top_attackers": top_attackers,
        "last_updated": state["last_updated"],
        "ingestion_stats": state["ingestion_stats"],
    })


@app.route("/api/timeline")
def api_timeline():
    """Get time-bucketed event data for timeline visualization."""
    state = get_state()
    events = state["events"]
    alerts = state["alerts"]

    if not events:
        return jsonify({"buckets": [], "alert_buckets": []})

    # Bucket events by minute
    event_buckets = defaultdict(lambda: {"total": 0, "login_fail": 0, "login_ok": 0, "request": 0, "other": 0})
    for e in events:
        key = e.timestamp.strftime("%H:%M")
        event_buckets[key]["total"] += 1
        if e.action == "LOGIN_FAIL":
            event_buckets[key]["login_fail"] += 1
        elif e.action == "LOGIN_OK":
            event_buckets[key]["login_ok"] += 1
        elif e.action == "REQUEST":
            event_buckets[key]["request"] += 1
        else:
            event_buckets[key]["other"] += 1

    # Bucket alerts by minute
    alert_buckets = defaultdict(lambda: {"total": 0, "critical": 0, "high": 0, "medium": 0})
    for a in alerts:
        if a.timestamp:
            try:
                ts = datetime.fromisoformat(a.timestamp)
                key = ts.strftime("%H:%M")
                alert_buckets[key]["total"] += 1
                alert_buckets[key][a.severity.lower()] = alert_buckets[key].get(a.severity.lower(), 0) + 1
            except (ValueError, AttributeError):
                pass

    # Sort by time
    sorted_event_buckets = [
        {"time": k, **v} for k, v in sorted(event_buckets.items())
    ]
    sorted_alert_buckets = [
        {"time": k, **v} for k, v in sorted(alert_buckets.items())
    ]

    return jsonify({
        "buckets": sorted_event_buckets,
        "alert_buckets": sorted_alert_buckets,
    })


@app.route("/api/events")
def api_events():
    """Get raw events with pagination."""
    state = get_state()
    events = state["events"]

    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    source = request.args.get("source")
    action = request.args.get("action")

    filtered = events
    if source:
        filtered = [e for e in filtered if e.source_type == source]
    if action:
        filtered = [e for e in filtered if e.action == action]

    start = (page - 1) * per_page
    end = start + per_page
    page_events = filtered[start:end]

    return jsonify({
        "events": [e.to_dict() for e in page_events],
        "total": len(filtered),
        "page": page,
        "per_page": per_page,
    })


@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    """Trigger log ingestion from a file path."""
    data = request.get_json(force=True)
    path = data.get("path", "")

    if not path or not os.path.exists(path):
        return jsonify({"error": f"Path not found: {path}"}), 400

    events, alerts, stats = run_pipeline(path)

    return jsonify({
        "status": "ok",
        "events_ingested": len(events),
        "alerts_generated": len(alerts),
        "files_processed": len(stats),
    })


# ─────────────────────────────────────────────
# Launch
# ─────────────────────────────────────────────

def launch_dashboard(log_path=None, port=5000, debug=False):
    """
    Launch the dashboard web server.

    Parameters
    ----------
    log_path : str or None
        Path to log file or directory to ingest on startup.
    port : int
        Port to run on.
    debug : bool
        Flask debug mode.
    """
    if log_path:
        run_pipeline(log_path)

    print(f"\n  \033[96m\033[1m{'=' * 50}")
    print(f"   SIEM-Lite Dashboard")
    print(f"   http://localhost:{port}")
    print(f"  {'=' * 50}\033[0m\n")

    app.run(host="0.0.0.0", port=port, debug=debug)


if __name__ == "__main__":
    import sys
    from report import fix_encoding
    fix_encoding()

    log_path = sys.argv[1] if len(sys.argv) > 1 else None
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    launch_dashboard(log_path=log_path, port=port)

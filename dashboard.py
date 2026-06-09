#!/usr/bin/env python3
"""
Dashboard — CLI Security Metrics Display
==========================================
Interactive CLI dashboard using rich library to display:
  - Alert timeline and statistics
  - Top attacking IPs
  - Status code distribution
  - Recent alerts
  - Scan history

Usage:
    python dashboard.py
    python dashboard.py --refresh 5  # Auto-refresh every 5 seconds
"""

import sys
import time
from datetime import datetime, timedelta
from collections import Counter

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.progress import Progress, BarColumn
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from report import Colors, print_ok, print_info, print_warn, print_error, fix_encoding
from database import (
    get_alerts, get_alert_stats, get_top_ips, get_status_distribution,
    get_alert_timeline, get_scans, get_log_stats, init_database
)


# ─────────────────────────────────────────────
# Dashboard Renderer
# ─────────────────────────────────────────────

class CLIDashboard:
    """Interactive CLI dashboard for SIEM-Lite metrics."""
    
    def __init__(self, refresh_interval: int = None):
        self.console = Console() if RICH_AVAILABLE else None
        self.refresh_interval = refresh_interval
        self.last_update = None
    
    def render(self):
        """Render the full dashboard."""
        if not RICH_AVAILABLE:
            self.render_fallback()
            return
        
        # Fetch data from database
        alert_stats = get_alert_stats()
        top_ips = get_top_ips(limit=10)
        status_dist = get_status_distribution()
        recent_alerts = get_alerts(limit=10)
        recent_scans = get_scans(limit=5)
        log_stats = get_log_stats()
        alert_timeline = get_alert_timeline(hours=24)
        
        # Create layout
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        
        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="right")
        )
        
        layout["left"].split_column(
            Layout(name="stats"),
            Layout(name="ips"),
            Layout(name="status")
        )
        
        layout["right"].split_column(
            Layout(name="alerts"),
            Layout(name="timeline"),
            Layout(name="scans")
        )
        
        # Header
        header = Panel(
            Text("SIEM-Lite Security Dashboard", style="bold cyan"),
            box=box.ROUNDED,
            style="blue"
        )
        layout["header"].update(header)
        
        # Stats panel
        layout["stats"].update(self.create_stats_panel(alert_stats, log_stats))
        
        # Top IPs panel
        layout["ips"].update(self.create_ips_panel(top_ips))
        
        # Status distribution panel
        layout["status"].update(self.create_status_panel(status_dist))
        
        # Recent alerts panel
        layout["alerts"].update(self.create_alerts_panel(recent_alerts))
        
        # Timeline panel
        layout["timeline"].update(self.create_timeline_panel(alert_timeline))
        
        # Recent scans panel
        layout["scans"].update(self.create_scans_panel(recent_scans))
        
        # Footer
        footer_text = f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        if self.refresh_interval:
            footer_text += f" | Auto-refresh: {self.refresh_interval}s"
        footer = Panel(Text(footer_text, style="dim"), box=box.ROUNDED)
        layout["footer"].update(footer)
        
        return layout
    
    def create_stats_panel(self, alert_stats: dict, log_stats: dict) -> Panel:
        """Create statistics panel."""
        table = Table(title="Security Statistics", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Alerts", str(alert_stats.get("total", 0)))
        table.add_row("Critical", str(alert_stats.get("critical", 0)), style="red")
        table.add_row("High", str(alert_stats.get("high", 0)), style="red")
        table.add_row("Medium", str(alert_stats.get("medium", 0)), style="yellow")
        table.add_row("Low", str(alert_stats.get("low", 0)), style="cyan")
        table.add_row("Resolved", str(alert_stats.get("resolved", 0)), style="green")
        table.add_row("", "")
        table.add_row("Total Log Entries", str(log_stats.get("total_entries", 0)))
        table.add_row("Unique IPs", str(log_stats.get("unique_ips", 0)))
        
        return Panel(table, box=box.ROUNDED)
    
    def create_ips_panel(self, top_ips: list) -> Panel:
        """Create top IPs panel."""
        table = Table(title="Top Attacking IPs", box=box.ROUNDED)
        table.add_column("IP Address", style="cyan")
        table.add_column("Request Count", style="green")
        
        for ip_data in top_ips[:10]:
            table.add_row(ip_data["ip"], str(ip_data["request_count"]))
        
        if not top_ips:
            table.add_row("No data available", "-")
        
        return Panel(table, box=box.ROUNDED)
    
    def create_status_panel(self, status_dist: dict) -> Panel:
        """Create status code distribution panel."""
        table = Table(title="HTTP Status Distribution", box=box.ROUNDED)
        table.add_column("Status", style="cyan")
        table.add_column("Count", style="green")
        table.add_column("Bar", style="blue")
        
        max_count = max(status_dist.values()) if status_dist else 1
        
        for status, count in sorted(status_dist.items(), key=lambda x: int(x[0])):
            bar_length = int((count / max_count) * 20)
            bar = "█" * bar_length
            table.add_row(str(status), str(count), bar)
        
        if not status_dist:
            table.add_row("No data available", "-", "-")
        
        return Panel(table, box=box.ROUNDED)
    
    def create_alerts_panel(self, alerts: list) -> Panel:
        """Create recent alerts panel."""
        table = Table(title="Recent Alerts", box=box.ROUNDED)
        table.add_column("Severity", style="cyan", width=10)
        table.add_column("Category", style="green", width=20)
        table.add_column("Detail", style="white")
        
        for alert in alerts[:10]:
            severity = alert.get("severity", "INFO")
            severity_style = {
                "CRITICAL": "red bold",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "cyan",
                "INFO": "dim"
            }.get(severity, "white")
            
            detail = alert.get("detail", "")[:50]
            if len(alert.get("detail", "")) > 50:
                detail += "..."
            
            table.add_row(
                Text(severity, style=severity_style),
                alert.get("category", "Unknown"),
                detail
            )
        
        if not alerts:
            table.add_row("-", "No recent alerts", "-")
        
        return Panel(table, box=box.ROUNDED)
    
    def create_timeline_panel(self, timeline: list) -> Panel:
        """Create alert timeline panel."""
        table = Table(title="Alert Timeline (24h)", box=box.ROUNDED)
        table.add_column("Time", style="cyan", width=8)
        table.add_column("Severity", style="green", width=10)
        table.add_column("Count", style="white")
        
        # Group by hour
        hourly_counts = {}
        for entry in timeline:
            hour = entry.get("hour", "")[:5]  # HH:MM format
            severity = entry.get("severity", "INFO")
            key = f"{hour}|{severity}"
            hourly_counts[key] = hourly_counts.get(key, 0) + entry.get("count", 0)
        
        # Show last 10 entries
        for entry in timeline[-10:]:
            hour = entry.get("hour", "")[:5]
            severity = entry.get("severity", "INFO")
            count = entry.get("count", 0)
            
            severity_style = {
                "CRITICAL": "red bold",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "cyan",
                "INFO": "dim"
            }.get(severity, "white")
            
            table.add_row(
                hour,
                Text(severity, style=severity_style),
                str(count)
            )
        
        if not timeline:
            table.add_row("-", "No timeline data", "-")
        
        return Panel(table, box=box.ROUNDED)
    
    def create_scans_panel(self, scans: list) -> Panel:
        """Create recent scans panel."""
        table = Table(title="Recent Scans", box=box.ROUNDED)
        table.add_column("Target", style="cyan")
        table.add_column("Findings", style="green")
        table.add_column("Critical", style="red")
        
        for scan in scans[:5]:
            table.add_row(
                scan.get("target_url", "Unknown")[:30],
                str(scan.get("total_findings", 0)),
                str(scan.get("critical_count", 0))
            )
        
        if not scans:
            table.add_row("No recent scans", "-", "-")
        
        return Panel(table, box=box.ROUNDED)
    
    def render_fallback(self):
        """Fallback rendering without rich library."""
        print(f"\n{Colors.CYAN}{'=' * 60}")
        print(f"SIEM-Lite Security Dashboard")
        print(f"{'=' * 60}{Colors.RESET}\n")
        
        alert_stats = get_alert_stats()
        log_stats = get_log_stats()
        
        print(f"{Colors.BOLD}Security Statistics:{Colors.RESET}")
        print(f"  Total Alerts: {alert_stats.get('total', 0)}")
        print(f"  Critical: {Colors.RED}{alert_stats.get('critical', 0)}{Colors.RESET}")
        print(f"  High: {Colors.RED}{alert_stats.get('high', 0)}{Colors.RESET}")
        print(f"  Medium: {Colors.YELLOW}{alert_stats.get('medium', 0)}{Colors.RESET}")
        print(f"  Low: {Colors.CYAN}{alert_stats.get('low', 0)}{Colors.RESET}")
        print(f"  Resolved: {Colors.GREEN}{alert_stats.get('resolved', 0)}{Colors.RESET}")
        print()
        print(f"  Total Log Entries: {log_stats.get('total_entries', 0)}")
        print(f"  Unique IPs: {log_stats.get('unique_ips', 0)}")
        print()
        
        top_ips = get_top_ips(limit=5)
        print(f"{Colors.BOLD}Top Attacking IPs:{Colors.RESET}")
        for ip_data in top_ips:
            print(f"  {ip_data['ip']}: {ip_data['request_count']} requests")
        print()
        
        recent_alerts = get_alerts(limit=5)
        print(f"{Colors.BOLD}Recent Alerts:{Colors.RESET}")
        for alert in recent_alerts:
            severity = alert.get('severity', 'INFO')
            severity_color = {
                'CRITICAL': Colors.RED,
                'HIGH': Colors.RED,
                'MEDIUM': Colors.YELLOW,
                'LOW': Colors.CYAN,
                'INFO': Colors.DIM
            }.get(severity, Colors.RESET)
            print(f"  {severity_color}[{severity}]{Colors.RESET} {alert.get('category', 'Unknown')}: {alert.get('detail', '')[:60]}")
        print()
        
        print(f"{Colors.DIM}Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 60}{Colors.RESET}\n")
    
    def run_live(self):
        """Run the dashboard with auto-refresh."""
        if not RICH_AVAILABLE:
            print_error("rich library not available. Install with: pip install rich")
            print_info("Running in fallback mode (single refresh)...")
            self.render_fallback()
            return
        
        with Live(self.render(), refresh_per_second=10, screen=True) as live:
            try:
                while True:
                    live.update(self.render())
                    if self.refresh_interval:
                        time.sleep(self.refresh_interval)
                    else:
                        # Single refresh mode
                        input("\nPress Enter to refresh, Ctrl+C to exit...")
            except KeyboardInterrupt:
                print_info("\nDashboard stopped.")


# ─────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────

def main():
    fix_encoding()
    
    # Initialize database
    init_database()
    
    # Parse arguments
    refresh_interval = None
    if len(sys.argv) > 1:
        try:
            refresh_interval = int(sys.argv[1])
        except ValueError:
            print_warn("Invalid refresh interval. Usage: python dashboard.py [refresh_seconds]")
    
    # Run dashboard
    dashboard = CLIDashboard(refresh_interval=refresh_interval)
    
    if refresh_interval:
        print_ok(f"Starting dashboard with {refresh_interval}s auto-refresh...")
        print_info("Press Ctrl+C to stop.")
    else:
        print_ok("Starting dashboard (single refresh mode)...")
        print_info("Press Enter to refresh, Ctrl+C to exit.")
    
    dashboard.run_live()


if __name__ == "__main__":
    main()

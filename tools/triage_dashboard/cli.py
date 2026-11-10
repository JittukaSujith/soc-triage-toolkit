"""Command-line launcher for the alert triage dashboard."""
from __future__ import annotations

import argparse
from typing import List, Optional

from soc_common.formatting import badge, color_enabled, format_table, heading
from soc_common.validation import cli_guard
from tools.alert_prioritizer.core import load_alerts, load_assets, score_alerts


@cli_guard
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m tools.triage_dashboard", description="Open the alert triage dashboard (GUI).")
    p.add_argument("--alerts", default="sample_data/alerts.json", help="alerts JSON (default: sample_data/alerts.json)")
    p.add_argument("--assets", default="sample_data/assets.json", help="assets JSON (default: sample_data/assets.json)")
    p.add_argument("--check", action="store_true", help="no window: just print the ranked list (useful over SSH or to test your setup)")
    args = p.parse_args(argv)
    if args.check:
        scored = score_alerts(load_alerts(args.alerts), load_assets(args.assets))
        use_color = color_enabled(False)
        print(heading("TRIAGE DASHBOARD (headless check)"))
        print(format_table(["#", "score", "priority", "id", "title"], [[i + 1, s.score, badge(s.severity, use_color), s.alert.id, s.alert.title] for i, s in enumerate(scored)], max_width=50))
        return 0
    from .gui import run

    run(args.alerts, args.assets)
    return 0

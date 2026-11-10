"""Command-line layer for the alert prioritizer."""
from __future__ import annotations

import argparse
from typing import List, Optional

from soc_common.formatting import badge, color_enabled, format_table, heading
from soc_common.io_utils import write_csv, write_json
from soc_common.validation import ToolError, cli_guard

from .core import load_alerts, load_assets, score_alerts


@cli_guard
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m tools.alert_prioritizer", description="Rank alerts by severity, asset value, repetition and context.")
    p.add_argument("alerts", help="alerts JSON file")
    p.add_argument("--assets", help="JSON mapping asset name to criticality 1-5")
    p.add_argument("--top", type=int, default=0, help="only show the top N alerts")
    p.add_argument("--explain", action="store_true", help="show the score breakdown for each alert")
    p.add_argument("--output", help="save ranked alerts (.json or .csv)")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)

    alerts = load_alerts(args.alerts)
    if not alerts:
        raise ToolError("no alerts found in %s" % args.alerts)
    scored = score_alerts(alerts, load_assets(args.assets) if args.assets else {})
    shown = scored[: args.top] if args.top > 0 else scored
    use_color = color_enabled(args.no_color)
    print(heading("ALERT PRIORITIZER"))
    print("Alerts: %d (showing %d)\n" % (len(scored), len(shown)))
    print(format_table(["#", "score", "priority", "id", "title", "asset"],
                       [[i + 1, s.score, badge(s.severity, use_color), s.alert.id, s.alert.title, s.alert.asset or "-"] for i, s in enumerate(shown)], max_width=46))
    if args.explain:
        print("\nScore breakdown:")
        for i, s in enumerate(shown, start=1):
            print("\n %d. %s - %s (score %d)" % (i, s.alert.id, s.alert.title, s.score))
            for r in s.reasons:
                print("      %s" % r)
    if args.output:
        rows = [s.to_dict() for s in shown]
        if args.output.lower().endswith(".csv"):
            write_csv(args.output, rows, ["id", "priority_score", "priority", "title", "category", "asset", "user", "src_ip", "source", "timestamp", "reasons"])
        else:
            write_json(args.output, rows)
        print("\nSaved ranked alerts to %s" % args.output)
    return 0

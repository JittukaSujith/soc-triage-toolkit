"""Command-line layer for the suspicious login analyzer."""
from __future__ import annotations

import argparse
from typing import List, Optional

from soc_common.formatting import badge, color_enabled, format_table, heading
from soc_common.io_utils import write_csv
from soc_common.validation import cli_guard

from .core import Settings, analyze_logins, load_logins


@cli_guard
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m tools.login_analyzer", description="Flag impossible travel, off-hours and new country/device logins.")
    p.add_argument("csv", help="login CSV with columns: timestamp,user,ip,country,city,lat,lon,tz_offset,device,result")
    p.add_argument("--max-speed", type=float, default=900.0, help="km/h above which travel is impossible (default 900)")
    p.add_argument("--work-start", type=int, default=7, help="work day starts at this local hour (default 7)")
    p.add_argument("--work-end", type=int, default=19, help="work day ends at this local hour (default 19)")
    p.add_argument("--flag-weekends", action="store_true", help="also flag weekend logins")
    p.add_argument("--output", help="save findings as CSV")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)

    records = load_logins(args.csv)
    findings = analyze_logins(records, Settings(args.max_speed, 100.0, args.work_start, args.work_end, args.flag_weekends))
    use_color = color_enabled(args.no_color)
    print(heading("SUSPICIOUS LOGIN ANALYZER"))
    print("Logins read: %d | flagged: %d\n" % (len(records), len(findings)))
    if not findings:
        print("No suspicious logins found.")
        return 0
    rows = [[badge(f.severity, use_color), f.score, f.record.timestamp.strftime("%m-%d %H:%M"), f.record.user, f.record.country, f.record.device, ",".join(f.signals)] for f in findings]
    print(format_table(["severity", "score", "time (UTC)", "user", "country", "device", "signals"], rows))
    print("\nWhy:")
    for f in findings:
        print(" - [%s] %s at %s: %s" % (f.severity.name, f.record.user, f.record.timestamp.strftime("%Y-%m-%d %H:%M"), " ".join(f.reasons)))
    if args.output:
        write_csv(args.output, (f.to_dict() for f in findings), ["severity", "score", "timestamp", "user", "ip", "country", "city", "device", "signals", "reasons"])
        print("\nSaved %d findings to %s" % (len(findings), args.output))
    return 0

"""Command-line layer for the brute-force / password-spray detector."""
from __future__ import annotations

import argparse
from typing import List, Optional

from soc_common.formatting import badge, color_enabled, format_table, heading
from soc_common.io_utils import write_csv
from soc_common.validation import ToolError, bounded_int, cli_guard
from tools.log_parser.core import load_events

from .core import Thresholds, detect

FIELDS = ["severity", "kind", "key", "failures", "distinct_users", "distinct_ips", "first_seen", "last_seen", "success_after", "reasons"]


@cli_guard
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m tools.bruteforce_detector", description="Find brute-force and password-spray activity.")
    p.add_argument("files", nargs="+", help="raw log files or normalised .jsonl event files")
    p.add_argument("--ip-failures", type=int, default=5, help="failures from one IP that count as brute force (default 5)")
    p.add_argument("--user-failures", type=int, default=5, help="failures against one user that count as targeted (default 5)")
    p.add_argument("--spray-users", type=int, default=5, help="distinct users from one IP that count as a spray (default 5)")
    p.add_argument("--window-minutes", type=int, default=10, help="sliding window size (default 10)")
    p.add_argument("--year", type=int, help="year for syslog timestamps (default: current year)")
    p.add_argument("--output", help="save findings as CSV")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)

    th = Thresholds(
        ip_failures=bounded_int(args.ip_failures, "--ip-failures", 2, 10000),
        user_failures=bounded_int(args.user_failures, "--user-failures", 2, 10000),
        spray_users=bounded_int(args.spray_users, "--spray-users", 2, 10000),
        window_minutes=bounded_int(args.window_minutes, "--window-minutes", 1, 1440),
    )
    events = load_events(args.files, args.year)
    if not events:
        raise ToolError("no events found in the input files")
    findings = detect(events, th)
    use_color = color_enabled(args.no_color)

    print(heading("BRUTE-FORCE / PASSWORD-SPRAY DETECTOR"))
    print("Events analysed: %d | window: %d min | thresholds: ip>=%d, user>=%d, spray users>=%d\n" % (
        len(events), th.window_minutes, th.ip_failures, th.user_failures, th.spray_users))
    if not findings:
        print("No suspicious login activity found.")
        return 0
    rows = [[badge(f.severity, use_color), f.kind, f.key, f.failures, f.distinct_users, f.distinct_ips, "YES" if f.success_after else "no"] for f in findings]
    print(format_table(["severity", "type", "source (IP/user)", "fails", "users", "IPs", "login after?"], rows))
    print("\nWhy:")
    for f in findings:
        print(" - [%s] %s %s: %s" % (f.severity.name, f.kind, f.key, " ".join(f.reasons)))
    if args.output:
        write_csv(args.output, (dict(f.to_dict()) for f in findings), FIELDS)
        print("\nSaved %d findings to %s" % (len(findings), args.output))
    return 0

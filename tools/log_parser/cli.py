"""Command-line layer for the log parser (thin: all logic lives in core.py)."""
from __future__ import annotations

import argparse
from typing import List, Optional

from soc_common.formatting import format_table, heading
from soc_common.io_utils import write_csv, write_events_jsonl
from soc_common.validation import ToolError, bounded_int, cli_guard

from .core import FORMATS, parse_files

CSV_FIELDS = ["timestamp", "source", "host", "user", "src_ip", "dst_ip", "action", "outcome", "message"]


@cli_guard
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m tools.log_parser", description="Normalise auth, web and firewall logs into one format.")
    p.add_argument("files", nargs="+", help="one or more log files")
    p.add_argument("--format", default="auto", choices=("auto",) + FORMATS, help="log family (default: auto-detect per line)")
    p.add_argument("--year", type=int, help="year for syslog timestamps (default: current year)")
    p.add_argument("--output", help="write normalised events here (.jsonl or .csv)")
    p.add_argument("--show", type=int, default=5, help="print the first N events (default 5)")
    args = p.parse_args(argv)
    if args.year is not None:
        bounded_int(args.year, "--year", 1970, 2100)

    result = parse_files(args.files, args.format, args.year)
    print(heading("LOG PARSER"))
    print("Lines read : %d  (parsed %d, skipped %d, comments/blank %d)" % (
        result.total_lines, len(result.events), result.skipped, result.comments))
    print("By source  : " + (", ".join("%s=%d" % kv for kv in sorted(result.by_source.items())) or "none"))
    if not result.events:
        raise ToolError("no events could be parsed - check --format or the file contents")
    if args.show > 0:
        rows = [[e.timestamp.strftime("%Y-%m-%d %H:%M:%S"), e.source, e.src_ip, e.user, e.action, e.outcome] for e in result.events[: args.show]]
        print("\n" + format_table(["time (UTC)", "source", "src_ip", "user", "action", "outcome"], rows))
    if args.output:
        if args.output.lower().endswith(".csv"):
            write_csv(args.output, (e.to_dict() for e in result.events), CSV_FIELDS)
        else:
            write_events_jsonl(args.output, result.events)
        print("\nSaved %d events to %s" % (len(result.events), args.output))
    return 0

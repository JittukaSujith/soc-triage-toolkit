"""Command-line layer for the incident timeline builder."""
from __future__ import annotations

import argparse
from typing import List, Optional

from soc_common.formatting import heading
from soc_common.io_utils import write_csv
from soc_common.schema import parse_timestamp
from soc_common.validation import ToolError, cli_guard
from tools.log_parser.core import load_events

from .core import build_timeline, filter_events, render_markdown, render_text


@cli_guard
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m tools.timeline_builder", description="Merge several logs into one sorted incident timeline.")
    p.add_argument("files", nargs="+", help="raw logs and/or normalised .jsonl event files")
    p.add_argument("--ip", action="append", default=[], help="only events involving this IP (repeatable)")
    p.add_argument("--user", action="append", default=[], help="only events for this user (repeatable)")
    p.add_argument("--start", help="ignore events before this ISO time, e.g. 2026-10-28T02:00:00Z")
    p.add_argument("--end", help="ignore events after this ISO time")
    p.add_argument("--year", type=int, help="year for syslog timestamps")
    p.add_argument("--output", help="save the timeline (.md or .csv)")
    p.add_argument("--limit", type=int, default=0, help="print only the first N entries")
    args = p.parse_args(argv)

    try:
        start = parse_timestamp(args.start) if args.start else None
        end = parse_timestamp(args.end) if args.end else None
    except ValueError as exc:
        raise ToolError(str(exc))
    events = filter_events(load_events(args.files, args.year), set(args.ip) or None, set(args.user) or None, start, end)
    if not events:
        raise ToolError("no events matched your filters")
    entries = build_timeline(events)
    shown = entries[: args.limit] if args.limit > 0 else entries
    print(heading("INCIDENT TIMELINE"))
    print("%d events, %s -> %s UTC | key moments marked with <--\n" % (len(entries), entries[0].event.timestamp.strftime("%Y-%m-%d %H:%M:%S"), entries[-1].event.timestamp.strftime("%H:%M:%S")))
    print(render_text(shown))
    if args.output:
        if args.output.lower().endswith(".csv"):
            write_csv(args.output, (t.to_dict() for t in entries), ["timestamp", "source", "host", "src_ip", "dst_ip", "user", "outcome", "message", "marker"])
        else:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(render_markdown(entries))
        print("\nSaved %d entries to %s" % (len(entries), args.output))
    return 0

"""Command-line layer for the IOC extractor."""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from soc_common.formatting import format_table, heading
from soc_common.validation import ToolError, cli_guard

from .core import extract_iocs, read_sources, to_csv, to_json, to_rows, total_count


@cli_guard
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m tools.ioc_extractor", description="Extract, de-duplicate and defang IOCs from text or files.")
    p.add_argument("files", nargs="*", help="text-like files (logs, .eml, reports)")
    p.add_argument("--text", help="extract from this text instead of files")
    p.add_argument("--types", help="comma-separated subset: ip,domain,url,email,md5,sha1,sha256,cve")
    p.add_argument("--defang", action="store_true", help="defang output (hxxp://evil[.]com)")
    p.add_argument("--exclude-private", action="store_true", help="skip private/loopback IPs")
    p.add_argument("--format", choices=("table", "json", "csv"), default="table")
    p.add_argument("--output", help="write the result to this file instead of the screen")
    args = p.parse_args(argv)

    if args.text:
        text = args.text
    elif args.files:
        text = read_sources(args.files)
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        raise ToolError("give one or more files, --text, or pipe text into the tool")
    types = [t.strip().lower() for t in args.types.split(",")] if args.types else None
    iocs = extract_iocs(text, args.exclude_private, types)

    if args.format == "json":
        body = to_json(iocs, args.defang)
    elif args.format == "csv":
        body = to_csv(iocs, args.defang)
    else:
        rows = [[r["type"], r["value"]] for r in to_rows(iocs, args.defang)]
        body = heading("IOC EXTRACTOR") + "\nFound %d unique indicators%s\n\n" % (total_count(iocs), " (defanged)" if args.defang else "")
        body += format_table(["type", "value"], rows, max_width=70) if rows else "No indicators found."
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(body if body.endswith("\n") else body + "\n")
        print("Saved %d indicators to %s" % (total_count(iocs), args.output))
    else:
        print(body)
    return 0

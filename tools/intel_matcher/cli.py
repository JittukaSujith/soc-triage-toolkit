"""Command-line layer for the offline threat-intel matcher."""
from __future__ import annotations

import argparse
from typing import List, Optional

from soc_common.formatting import badge, color_enabled, format_table, heading
from soc_common.io_utils import write_csv
from soc_common.validation import ToolError, bounded_int, cli_guard
from tools.ioc_extractor.core import extract_iocs, read_sources, total_count

from .core import load_blocklist, match_iocs, online_domain_lookup


@cli_guard
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m tools.intel_matcher", description="Match IOCs against a local blocklist (offline by default).")
    p.add_argument("files", nargs="*", help="files to extract IOCs from (logs, .eml, reports)")
    p.add_argument("--ioc", action="append", default=[], help="a single indicator to check (repeatable)")
    p.add_argument("--blocklist", required=True, help="local blocklist CSV or text file")
    p.add_argument("--output", help="save matches as CSV")
    p.add_argument("--online", action="store_true", help="ONLINE: look up domain registration dates via rdap.org (sends domains to a third party)")
    p.add_argument("--online-limit", type=int, default=5, help="max domains to look up online (default 5)")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)
    if not args.files and not args.ioc:
        raise ToolError("give at least one file or --ioc value")

    text = ((read_sources(args.files) + "\n") if args.files else "") + "\n".join(args.ioc)
    iocs = extract_iocs(text)
    blocklist = load_blocklist(args.blocklist)
    matches = match_iocs(iocs, blocklist)
    use_color = color_enabled(args.no_color)

    print(heading("OFFLINE THREAT-INTEL MATCHER"))
    print("IOCs extracted: %d | blocklist entries: %d | matches: %d  (mode: OFFLINE)\n" % (total_count(iocs), len(blocklist), len(matches)))
    if matches:
        print(format_table(["severity", "ioc", "type", "matched by", "how", "source", "conf"],
                           [[badge(m.severity, use_color), m.ioc, m.ioc_type, m.indicator, m.kind, m.source, m.confidence] for m in matches], max_width=40))
    else:
        print("No IOCs matched the blocklist. (That does not prove they are safe - only that YOUR list does not know them.)")

    if args.online:
        limit = bounded_int(args.online_limit, "--online-limit", 1, 50)
        print("\n*** ONLINE MODE: sending up to %d domain name(s) to rdap.org and the domain registry ***" % limit)
        for dom in iocs.get("domain", [])[:limit]:
            r = online_domain_lookup(dom)
            print(" - %s: %s" % (dom, r["detail"]))
    if args.output and matches:
        write_csv(args.output, (m.to_dict() for m in matches), ["severity", "ioc", "type", "matched_indicator", "match_kind", "source", "confidence", "note"])
        print("\nSaved %d matches to %s" % (len(matches), args.output))
    return 0

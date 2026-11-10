"""Command-line layer for the triage report generator."""
from __future__ import annotations

import argparse
from typing import List, Optional

from soc_common.io_utils import read_json
from soc_common.validation import ToolError, cli_guard

from .core import build_html, build_markdown, validate_case


@cli_guard
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m tools.report_generator", description="Turn a case JSON file into a Markdown/HTML triage report.")
    p.add_argument("case", help="case JSON file (see sample_data/case_example.json)")
    p.add_argument("--markdown", help="write a Markdown report here")
    p.add_argument("--html", help="write an HTML report here")
    args = p.parse_args(argv)
    case = validate_case(read_json(args.case))
    if not args.markdown and not args.html:
        print(build_markdown(case))
        return 0
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(build_markdown(case))
        print("Wrote Markdown report: %s" % args.markdown)
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(build_html(case))
        print("Wrote HTML report: %s" % args.html)
    return 0

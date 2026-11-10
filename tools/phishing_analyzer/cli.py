"""Command-line layer for the phishing email analyzer."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Optional

from soc_common.formatting import badge, color_enabled, format_table, heading
from soc_common.io_utils import write_json
from soc_common.validation import ToolError, cli_guard

from .core import EmailAnalysis, analyze_file


def render(a: EmailAnalysis, use_color: bool) -> str:
    lines = [heading("EMAIL: %s" % (Path(a.path).name or "(input)"))]
    lines.append("From     : %s <%s>" % (a.from_name, a.from_addr))
    if a.reply_to:
        lines.append("Reply-To : %s" % a.reply_to)
    lines.append("Return   : %s" % (a.return_path or "-"))
    lines.append("Subject  : %s" % a.subject)
    lines.append("Auth     : SPF=%s  DKIM=%s  DMARC=%s" % (a.spf.upper(), a.dkim.upper(), a.dmarc.upper()))
    lines.append("Score    : %d/100  %s" % (a.score, badge(a.severity, use_color)))
    if a.hops:
        lines.append("\nReceived chain (oldest first):")
        lines.append(format_table(["#", "from", "by", "ip", "time"], [[i + 1, h.from_host, h.by_host, h.ip, h.timestamp] for i, h in enumerate(a.hops)]))
    if a.links:
        lines.append("\nLinks:")
        lines.append(format_table(["url", "shown text", "flags"], [[l.href, l.text, ",".join(l.flags) or "-"] for l in a.links], max_width=44))
    if a.attachments:
        lines.append("\nAttachments:")
        lines.append(format_table(["file", "type", "bytes", "sha256 (first 16)", "flags"], [[x.filename, x.content_type, x.size, x.sha256[:16], ",".join(x.flags) or "-"] for x in a.attachments]))
    lines.append("\nWhy this score:")
    lines.extend(["  +%-3d %s" % (p, r) for p, r in a.findings] or ["  no suspicious signals found"])
    return "\n".join(lines) + "\n"


@cli_guard
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m tools.phishing_analyzer", description="Score .eml files for phishing risk.")
    p.add_argument("emails", nargs="+", help=".eml files (or folders containing .eml files)")
    p.add_argument("--json", dest="json_out", help="save full analysis as JSON")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)

    files: List[str] = []
    for item in args.emails:
        path = Path(item).expanduser()
        files.extend(sorted(str(f) for f in path.glob("*.eml")) if path.is_dir() else [item])
    if not files:
        raise ToolError("no .eml files found")
    use_color = color_enabled(args.no_color)
    results = [analyze_file(f) for f in files]
    for r in results:
        print(render(r, use_color))
    if len(results) > 1:
        print(heading("SUMMARY"))
        print(format_table(["file", "score", "severity"], [[Path(r.path).name, r.score, badge(r.severity, use_color)] for r in sorted(results, key=lambda r: -r.score)]))
    if args.json_out:
        write_json(args.json_out, [r.to_dict() for r in results])
        print("\nSaved analysis to %s" % args.json_out)
    return 0

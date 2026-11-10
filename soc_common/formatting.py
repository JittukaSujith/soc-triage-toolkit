"""Terminal output helpers: tables, colour and severity badges (ASCII only)."""
from __future__ import annotations

import os
import sys
from typing import List, Sequence

from .severity import Severity

_COLORS = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"


def color_enabled(no_color: bool = False) -> bool:
    """Colour only on a real terminal, and never if NO_COLOR is set."""
    return not no_color and "NO_COLOR" not in os.environ and sys.stdout.isatty()


def badge(severity: Severity, use_color: bool = False) -> str:
    text = severity.name
    return "%s%s%s" % (_COLORS[severity], text, _RESET) if use_color else text


def truncate(text: str, width: int) -> str:
    text = str(text)
    return text if len(text) <= width else text[: max(width - 3, 1)] + "..."


def format_table(headers: Sequence[str], rows: Sequence[Sequence[object]], max_width: int = 48) -> str:
    """Render a plain ASCII table (rows are lists of values)."""
    cells = [[truncate(c, max_width) for c in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in cells:
        for i, c in enumerate(row):
            widths[i] = max(widths[i], len(c))
    line = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    out: List[str] = [line, "| " + " | ".join(h.ljust(w) for h, w in zip(headers, widths)) + " |", line]
    for row in cells:
        out.append("| " + " | ".join(c.ljust(w) for c, w in zip(row, widths)) + " |")
    out.append(line)
    return "\n".join(out)


def heading(title: str, width: int = 72) -> str:
    return "%s\n %s\n%s" % ("=" * width, title, "=" * width)

"""Reading and writing the file formats the tools exchange (JSON, JSONL, CSV)."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from .schema import LogEvent
from .validation import ToolError, read_text_file, require_file


def read_json(path) -> Any:
    text = read_text_file(path)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ToolError("%s is not valid JSON (line %d: %s)" % (path, exc.lineno, exc.msg))


def write_json(path, data: Any) -> None:
    p = Path(str(path)).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def read_csv_rows(path) -> List[Dict[str, str]]:
    """Read a CSV into dicts. Blank lines and lines starting with '#' are ignored,
    which lets sample files carry a 'FAKE DATA' notice at the top."""
    text = read_text_file(path)
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    return [dict(row) for row in csv.DictReader(lines)]


def write_csv(path, rows: Iterable[Dict[str, Any]], fieldnames: Sequence[str]) -> None:
    p = Path(str(path)).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_events_jsonl(path, events: Iterable[LogEvent]) -> int:
    p = Path(str(path)).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with p.open("w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev.to_dict(), ensure_ascii=False) + "\n")
            count += 1
    return count


def read_events_jsonl(path) -> List[LogEvent]:
    """Load normalised events from a JSONL file (one JSON object per line)."""
    require_file(path)
    events: List[LogEvent] = []
    for number, line in enumerate(read_text_file(path).splitlines(), start=1):
        if not line.strip():
            continue
        try:
            events.append(LogEvent.from_dict(json.loads(line)))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ToolError("%s line %d: %s" % (path, number, exc))
    return events

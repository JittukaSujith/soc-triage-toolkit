"""Analyst decisions for the triage dashboard - pure logic, no GUI imports (so it is easy to test)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Iterable, List

from soc_common.io_utils import read_json, write_csv, write_json
from soc_common.validation import ToolError

DECISIONS = ("True positive", "False positive", "Needs escalation")


class DecisionStore:
    """Remembers the analyst's decision and note for each alert id."""

    def __init__(self) -> None:
        self._items: Dict[str, Dict[str, str]] = {}

    def set(self, alert_id: str, decision: str, note: str = "") -> None:
        if decision not in DECISIONS:
            raise ValueError("decision must be one of: %s" % ", ".join(DECISIONS))
        self._items[alert_id] = {"decision": decision, "note": note.strip(), "decided_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}

    def set_note(self, alert_id: str, note: str) -> None:
        if alert_id in self._items:
            self._items[alert_id]["note"] = note.strip()

    def get(self, alert_id: str) -> Dict[str, str]:
        return self._items.get(alert_id, {"decision": "", "note": "", "decided_at": ""})

    def clear(self, alert_id: str) -> None:
        self._items.pop(alert_id, None)

    def pending(self, alert_ids: Iterable[str]) -> List[str]:
        return [a for a in alert_ids if a not in self._items]

    def counts(self) -> Dict[str, int]:
        out = {d: 0 for d in DECISIONS}
        for item in self._items.values():
            out[item["decision"]] += 1
        return out

    def rows(self, scored) -> List[Dict[str, object]]:
        """Export rows for a ranked list of ScoredAlert objects."""
        rows = []
        for rank, s in enumerate(scored, start=1):
            d = self.get(s.alert.id)
            rows.append({"rank": rank, "id": s.alert.id, "title": s.alert.title, "priority_score": s.score, "priority": s.severity.name,
                         "asset": s.alert.asset, "decision": d["decision"], "note": d["note"], "decided_at": d["decided_at"]})
        return rows

    def load(self, path) -> int:
        """Resume a previous session from an exported JSON file."""
        data = read_json(path)
        if not isinstance(data, list):
            raise ToolError("%s is not an exported decisions file" % path)
        loaded = 0
        for row in data:
            if row.get("decision") in DECISIONS and row.get("id"):
                self._items[str(row["id"])] = {"decision": row["decision"], "note": row.get("note", ""), "decided_at": row.get("decided_at", "")}
                loaded += 1
        return loaded


def export_decisions(path: str, scored, store: DecisionStore) -> int:
    rows = store.rows(scored)
    if str(path).lower().endswith(".csv"):
        write_csv(path, rows, ["rank", "id", "title", "priority_score", "priority", "asset", "decision", "note", "decided_at"])
    else:
        write_json(path, rows)
    return len(rows)

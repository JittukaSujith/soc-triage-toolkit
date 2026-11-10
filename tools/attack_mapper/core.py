"""MITRE ATT&CK mapper - core logic.

MITRE ATT&CK is a public catalogue of attacker behaviour. Each *technique* has an ID
(T1110 = Brute Force) and belongs to one or more *tactics* (the attacker's goal, such as
Credential Access). Mapping detections to technique IDs gives everyone a shared vocabulary:
"T1110.003" means the same thing to every SOC, and it shows which stage of an attack you saw.

This tool uses a SMALL local JSON file, so it works offline and you can read and extend it.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple

from soc_common.io_utils import read_json
from soc_common.validation import ToolError

DEFAULT_MAPPING = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mapping.json")


@dataclass
class TechniqueMatch:
    behaviour: str
    technique_id: str
    name: str
    tactics: List[str]
    description: str
    why: str

    @property
    def url(self) -> str:
        # Sub-techniques use a slash in the URL: T1110.003 -> /techniques/T1110/003/
        return "https://attack.mitre.org/techniques/%s/" % self.technique_id.replace(".", "/")

    def to_dict(self) -> Dict:
        return {"behaviour": self.behaviour, "technique_id": self.technique_id, "name": self.name,
                "tactics": ", ".join(self.tactics), "why": self.why, "url": self.url}


def load_mapping(path: str = DEFAULT_MAPPING) -> Dict:
    data = read_json(path)
    if not isinstance(data, dict) or "behaviours" not in data:
        raise ToolError("%s must contain a 'behaviours' object" % path)
    for key, entry in data["behaviours"].items():
        for needed in ("technique_id", "name", "tactics", "description", "why"):
            if needed not in entry:
                raise ToolError("mapping entry %r is missing %r" % (key, needed))
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", entry["technique_id"]):
            raise ToolError("mapping entry %r has an invalid technique id %r" % (key, entry["technique_id"]))
    data.setdefault("aliases", {})
    return data


def normalise(name: str, mapping: Dict) -> str:
    key = re.sub(r"[\s\-]+", "_", str(name).strip().lower())
    return mapping["aliases"].get(key, key)


def map_behaviours(behaviours: Iterable[str], mapping: Dict) -> Tuple[List[TechniqueMatch], List[str]]:
    """Return (matches, unknown behaviours). Duplicate technique IDs are merged."""
    matches: Dict[str, TechniqueMatch] = {}
    unknown: List[str] = []
    for raw in behaviours:
        key = normalise(raw, mapping)
        entry = mapping["behaviours"].get(key)
        if not entry:
            if raw not in unknown:
                unknown.append(raw)
            continue
        m = TechniqueMatch(key, entry["technique_id"], entry["name"], list(entry["tactics"]), entry["description"], entry["why"])
        matches.setdefault(m.technique_id, m)
    return sorted(matches.values(), key=lambda m: m.technique_id), unknown


def behaviours_from_alerts(alerts: List[Dict]) -> List[str]:
    """Collect behaviour names from alert categories and tags."""
    found: List[str] = []
    for a in alerts:
        for value in [a.get("category", "")] + list(a.get("tags", [])):
            if value and value not in found:
                found.append(value)
    return found

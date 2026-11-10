"""Command-line layer for the ATT&CK mapper."""
from __future__ import annotations

import argparse
from typing import List, Optional

from soc_common.formatting import format_table, heading
from soc_common.io_utils import read_json, write_json
from soc_common.validation import ToolError, cli_guard

from .core import DEFAULT_MAPPING, behaviours_from_alerts, load_mapping, map_behaviours


@cli_guard
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m tools.attack_mapper", description="Map behaviours to MITRE ATT&CK technique IDs.")
    p.add_argument("--behaviour", action="append", default=[], help="a behaviour name such as password_spray (repeatable)")
    p.add_argument("--alerts", help="alerts JSON file: categories and tags are mapped")
    p.add_argument("--mapping", default=DEFAULT_MAPPING, help="mapping file (default: the bundled one)")
    p.add_argument("--list", action="store_true", help="list every behaviour this mapping knows")
    p.add_argument("--output", help="save the mapping result as JSON")
    args = p.parse_args(argv)

    mapping = load_mapping(args.mapping)
    print(heading("MITRE ATT&CK MAPPER"))
    if args.list:
        print(format_table(["behaviour", "technique", "name"], [[k, v["technique_id"], v["name"]] for k, v in sorted(mapping["behaviours"].items())], max_width=60))
        return 0
    behaviours = list(args.behaviour)
    if args.alerts:
        data = read_json(args.alerts)
        items = data.get("alerts") if isinstance(data, dict) else data
        if not isinstance(items, list):
            raise ToolError("%s must be a JSON list of alerts" % args.alerts)
        behaviours += behaviours_from_alerts(items)
    if not behaviours:
        raise ToolError("give --behaviour, --alerts or --list")
    matches, unknown = map_behaviours(behaviours, mapping)
    print("Mapped %d technique(s) from %d behaviour name(s)\n" % (len(matches), len(behaviours)))
    if matches:
        print(format_table(["technique", "name", "tactic(s)", "from behaviour"], [[m.technique_id, m.name, ", ".join(m.tactics), m.behaviour] for m in matches], max_width=52))
        print("\nWhy each one:")
        for m in matches:
            print(" - %s %s: %s\n   %s" % (m.technique_id, m.name, m.why, m.url))
    if unknown:
        print("\nNot in the mapping (add them to mapping.json if relevant): %s" % ", ".join(unknown))
    if args.output:
        write_json(args.output, [m.to_dict() for m in matches])
        print("\nSaved to %s" % args.output)
    return 0

"""Incident timeline builder - core logic.

During an investigation the question is "what happened, in what order?". Evidence is
scattered across logs, each with its own format. Merging everything into ONE sorted
timeline is what turns scattered log lines into a story: scan -> brute force -> login ->
download -> beaconing. Filtering by the attacker's IP or the victim account keeps it readable.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional, Set

from soc_common.schema import LogEvent, iso


@dataclass
class TimelineEntry:
    event: LogEvent
    marker: str = ""          # analyst-friendly note on key moments

    def to_dict(self) -> dict:
        e = self.event
        return {"timestamp": iso(e.timestamp), "source": e.source, "host": e.host, "src_ip": e.src_ip, "dst_ip": e.dst_ip,
                "user": e.user, "outcome": e.outcome, "message": e.message, "marker": self.marker}


def filter_events(events: Iterable[LogEvent], ips: Optional[Set[str]] = None, users: Optional[Set[str]] = None,
                  start: Optional[datetime] = None, end: Optional[datetime] = None, sources: Optional[Set[str]] = None) -> List[LogEvent]:
    """Keep events matching ALL given filters. An IP filter matches source OR destination."""
    out = []
    for e in events:
        if ips and e.src_ip not in ips and e.dst_ip not in ips:
            continue
        if users and e.user not in users:
            continue
        if start and e.timestamp < start:
            continue
        if end and e.timestamp > end:
            continue
        if sources and e.source not in sources:
            continue
        out.append(e)
    return out


def build_timeline(events: Iterable[LogEvent]) -> List[TimelineEntry]:
    """Sort events, drop exact duplicates, and mark the moments an analyst should look at first."""
    seen = set()
    ordered: List[LogEvent] = []
    for e in sorted(events, key=lambda ev: ev.timestamp):
        key = (e.timestamp, e.source, e.raw or e.message)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(e)

    entries: List[TimelineEntry] = []
    first_failure_by_ip = {}
    failures_by_ip = {}
    compromise_marked = set()
    outbound_marked = set()
    for e in ordered:
        marker = ""
        if e.action in ("ssh_login", "web_login") and e.src_ip:
            if e.outcome == "failure":
                failures_by_ip[e.src_ip] = failures_by_ip.get(e.src_ip, 0) + 1
                if e.src_ip not in first_failure_by_ip:
                    first_failure_by_ip[e.src_ip] = e.timestamp
                    marker = "FIRST FAILED LOGIN from %s" % e.src_ip
            elif e.outcome == "success" and failures_by_ip.get(e.src_ip, 0) >= 3 and e.src_ip not in compromise_marked:
                compromise_marked.add(e.src_ip)
                marker = "POSSIBLE COMPROMISE: success after %d failures from %s" % (failures_by_ip[e.src_ip], e.src_ip)
        if e.action == "sudo" and any(w in e.message for w in ("curl ", "wget ", "useradd", "adduser")):
            marker = "SUSPICIOUS PRIVILEGED COMMAND"
        if e.source == "firewall" and e.extra.get("direction") == "OUT" and e.outcome == "allow" and e.dst_ip not in outbound_marked \
                and e.extra.get("dport") not in (80, 443, 53):
            outbound_marked.add(e.dst_ip)
            marker = "FIRST OUTBOUND CONNECTION on unusual port to %s" % e.dst_ip
        entries.append(TimelineEntry(e, marker))
    return entries


def render_text(entries: List[TimelineEntry]) -> str:
    lines = []
    for t in entries:
        e = t.event
        lines.append("%s  %-8s %-8s %s%s" % (e.timestamp.strftime("%Y-%m-%d %H:%M:%S"), e.source, e.outcome, e.message,
                                             ("    <-- %s" % t.marker) if t.marker else ""))
    return "\n".join(lines)


def render_markdown(entries: List[TimelineEntry], title: str = "Incident timeline") -> str:
    lines = ["# %s" % title, "", "| Time (UTC) | Source | Outcome | Event | Note |", "|---|---|---|---|---|"]
    for t in entries:
        e = t.event
        msg = e.message.replace("|", "\\|")
        lines.append("| %s | %s | %s | %s | %s |" % (e.timestamp.strftime("%Y-%m-%d %H:%M:%S"), e.source, e.outcome, msg, ("**%s**" % t.marker) if t.marker else ""))
    return "\n".join(lines) + "\n"

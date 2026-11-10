"""Log parser and normalizer - core logic (pure functions, no I/O side effects).

Why normalise? An SSH login failure, a web 401 and a firewall DENY are all
"someone was refused" - but they are written three different ways. Turning them
into one LogEvent schema lets every other tool (detectors, timelines, reports)
work on any log source without caring about the original format.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from soc_common.schema import LogEvent
from soc_common.validation import ToolError, read_text_file

FORMATS = ("auth", "web", "firewall")

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
FAILED_RE = re.compile(r"Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
ACCEPTED_RE = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
SUDO_RE = re.compile(r"^(?P<user>\S+)\s*:\s*.*?COMMAND=(?P<cmd>.*)$")

WEB_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)(?: (?P<proto>[^"]*))?" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)
# Login pages: repeated failures here are a classic web brute-force signal.
LOGIN_PATH_RE = re.compile(r"/(wp-login\.php|login|signin|admin/login|xmlrpc\.php)", re.IGNORECASE)

KV_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')
ISO_START_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")


@dataclass
class ParseResult:
    events: List[LogEvent] = field(default_factory=list)
    total_lines: int = 0
    skipped: int = 0            # lines in an unrecognised shape
    comments: int = 0           # blank lines and '#' comments
    by_source: Dict[str, int] = field(default_factory=dict)


def parse_auth_line(line: str, year: int) -> Optional[LogEvent]:
    """Parse a syslog-style auth line (sshd and sudo). Syslog has no year, so we pass one in."""
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime("%d %s %s %s" % (year, m["mon"], m["day"], m["time"]), "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    host, proc, msg = m["host"], m["proc"], m["msg"]
    base = dict(timestamp=ts, source="auth", host=host, raw=line)
    f = FAILED_RE.search(msg)
    if f:
        # Failed logins are the raw material for brute-force detection.
        return LogEvent(message="SSH login failed for %s from %s" % (f["user"], f["ip"]), user=f["user"], src_ip=f["ip"],
                        action="ssh_login", outcome="failure",
                        extra={"method": f["method"], "invalid_user": bool(f["invalid"]), "port": int(f["port"])}, **base)
    a = ACCEPTED_RE.search(msg)
    if a:
        return LogEvent(message="SSH login succeeded for %s from %s" % (a["user"], a["ip"]), user=a["user"], src_ip=a["ip"],
                        action="ssh_login", outcome="success", extra={"method": a["method"], "port": int(a["port"])}, **base)
    i = INVALID_RE.search(msg)
    if i:
        # sshd logs "Invalid user" AND "Failed password" for the same attempt. We keep both as
        # evidence but give this one its own action so detectors do not count the attempt twice.
        return LogEvent(message="SSH attempt for non-existent user %s from %s" % (i["user"], i["ip"]), user=i["user"],
                        src_ip=i["ip"], action="ssh_invalid_user", outcome="failure", **base)
    if proc == "sudo":
        s = SUDO_RE.match(msg)
        if s:
            return LogEvent(message="sudo by %s: %s" % (s["user"], s["cmd"].strip()), user=s["user"], action="sudo",
                            outcome="success", extra={"command": s["cmd"].strip()}, **base)
    return None


def parse_web_line(line: str) -> Optional[LogEvent]:
    """Parse an Apache/Nginx 'combined' access-log line."""
    m = WEB_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except ValueError:
        return None
    status = int(m["status"])
    method, path = m["method"], m["path"]
    outcome = "failure" if status in (401, 403) else "error" if status >= 400 else "success"
    action = "web_login" if method == "POST" and LOGIN_PATH_RE.search(path) else "http_request"
    user = "" if m["user"] == "-" else m["user"]
    return LogEvent(timestamp=ts, source="web", host="", user=user, src_ip=m["ip"], action=action, outcome=outcome,
                    message="%s %s -> %d" % (method, path, status), raw=line,
                    extra={"method": method, "path": path, "status": status,
                           "bytes": 0 if m["bytes"] == "-" else int(m["bytes"]), "user_agent": m["ua"] or ""})


def parse_firewall_line(line: str) -> Optional[LogEvent]:
    """Parse a key=value firewall line: '<ISO time> action=DENY src=... dst=... dport=...'."""
    if not ISO_START_RE.match(line):
        return None
    ts_text, _, rest = line.partition(" ")
    fields = {k: v.strip('"') for k, v in KV_RE.findall(rest)}
    if "src" not in fields or "action" not in fields:
        return None
    try:
        ts = datetime.strptime(ts_text, "%Y-%m-%dT%H:%M:%S%z" if ts_text[-1] != "Z" else "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    ts = ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)
    verdict = fields["action"].upper()
    outcome = "allow" if verdict in ("ALLOW", "ACCEPT", "PERMIT") else "deny" if verdict in ("DENY", "DROP", "REJECT") else "unknown"
    dport = fields.get("dport", "")
    return LogEvent(timestamp=ts, source="firewall", host=fields.get("host", ""), src_ip=fields["src"], dst_ip=fields.get("dst", ""),
                    action="firewall_connection", outcome=outcome, raw=line,
                    message="%s %s %s -> %s:%s" % (verdict, fields.get("proto", ""), fields["src"], fields.get("dst", "?"), dport),
                    extra={"proto": fields.get("proto", ""), "direction": fields.get("dir", ""), "dport": int(dport) if dport.isdigit() else None,
                           "sport": int(fields["sport"]) if fields.get("sport", "").isdigit() else None})


def detect_format(line: str) -> Optional[str]:
    """Guess which log family a single line belongs to."""
    if ISO_START_RE.match(line) and "action=" in line:
        return "firewall"
    if WEB_RE.match(line):
        return "web"
    if SYSLOG_RE.match(line):
        return "auth"
    return None


def parse_lines(lines: List[str], fmt: str = "auto", year: Optional[int] = None) -> ParseResult:
    """Normalise a list of raw lines. fmt is 'auto' or one of FORMATS."""
    if fmt != "auto" and fmt not in FORMATS:
        raise ToolError("unknown format %r (choose auto, %s)" % (fmt, ", ".join(FORMATS)))
    year = year or datetime.now(timezone.utc).year
    result = ParseResult()
    counts: Counter = Counter()
    for raw in lines:
        result.total_lines += 1
        line = raw.strip()
        if not line or line.startswith("#"):
            result.comments += 1
            continue
        kind = fmt if fmt != "auto" else detect_format(line)
        event = None
        if kind == "auth":
            event = parse_auth_line(line, year)
        elif kind == "web":
            event = parse_web_line(line)
        elif kind == "firewall":
            event = parse_firewall_line(line)
        if event is None:
            result.skipped += 1
            continue
        result.events.append(event)
        counts[event.source] += 1
    result.by_source = dict(counts)
    result.events.sort(key=lambda e: e.timestamp)
    return result


def parse_file(path, fmt: str = "auto", year: Optional[int] = None) -> ParseResult:
    """Read and normalise one log file."""
    return parse_lines(read_text_file(path).splitlines(), fmt, year)


def parse_files(paths, fmt: str = "auto", year: Optional[int] = None) -> ParseResult:
    """Normalise several files into one combined, time-sorted result."""
    combined = ParseResult()
    counts: Counter = Counter()
    for path in paths:
        part = parse_file(path, fmt, year)
        combined.events.extend(part.events)
        combined.total_lines += part.total_lines
        combined.skipped += part.skipped
        combined.comments += part.comments
        counts.update(part.by_source)
    combined.by_source = dict(counts)
    combined.events.sort(key=lambda e: e.timestamp)
    return combined


def load_events(paths, year: Optional[int] = None) -> List[LogEvent]:
    """Convenience loader used by other tools: .jsonl files are read as already-normalised
    events, anything else is parsed as a raw log (format auto-detected)."""
    from soc_common.io_utils import read_events_jsonl

    events: List[LogEvent] = []
    raw_paths = []
    for path in paths:
        if str(path).lower().endswith(".jsonl"):
            events.extend(read_events_jsonl(path))
        else:
            raw_paths.append(path)
    if raw_paths:
        events.extend(parse_files(raw_paths, "auto", year).events)
    events.sort(key=lambda e: e.timestamp)
    return events

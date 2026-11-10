"""Alert prioritizer - core logic.

A SOC can receive thousands of alerts a day. Reading them in arrival order means
the dangerous one may wait behind fifty noisy ones. Prioritising ranks them by
*likely impact*, combining four things an experienced analyst weighs in their head:

  1. Severity   - how bad is this kind of event if it is real?
  2. Asset value - a web server or domain controller matters more than a printer.
  3. Repetition - the same alert again and again is more likely to be real.
  4. Context    - known-bad IP, privileged account, successful login after failures...

Every point is recorded with a reason, so the score can be explained (and argued with).
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List

from soc_common.io_utils import read_json
from soc_common.ioc_patterns import is_private_ip
from soc_common.severity import Severity
from soc_common.validation import ToolError

SEVERITY_POINTS = {Severity.INFO: 5, Severity.LOW: 15, Severity.MEDIUM: 30, Severity.HIGH: 45, Severity.CRITICAL: 60}
ASSET_POINTS = {1: 0, 2: 5, 3: 10, 4: 15, 5: 20}      # asset criticality 1 (low) .. 5 (crown jewels)
DEFAULT_CRITICALITY = 2                               # unknown assets are assumed low-ish, and we say so
REPEAT_POINTS_EACH, REPEAT_POINTS_MAX = 5, 15
TAG_POINTS = {
    "known_bad_ip": (15, "involves an IP on a threat-intel blocklist"),
    "successful_login_after_failures": (15, "a login succeeded after repeated failures (possible compromise)"),
    "privileged_account": (10, "involves a privileged account"),
    "impossible_travel": (10, "user appears in two distant places too quickly"),
    "malware_detected": (10, "malware was detected"),
    "internet_facing": (5, "asset is exposed to the internet"),
    "after_hours": (5, "happened outside normal working hours"),
}
EXTERNAL_SOURCE_POINTS = 3


@dataclass
class Alert:
    id: str
    title: str
    severity: Severity = Severity.MEDIUM
    category: str = ""
    asset: str = ""
    user: str = ""
    src_ip: str = ""
    source: str = ""
    description: str = ""
    timestamp: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {"id": self.id, "title": self.title, "severity": self.severity.name, "category": self.category, "asset": self.asset,
                "user": self.user, "src_ip": self.src_ip, "source": self.source, "description": self.description,
                "timestamp": self.timestamp, "tags": list(self.tags)}


@dataclass
class ScoredAlert:
    alert: Alert
    score: int
    severity: Severity
    reasons: List[str]

    def to_dict(self) -> Dict:
        d = self.alert.to_dict()
        d.update({"priority_score": self.score, "priority": self.severity.name, "reasons": "; ".join(self.reasons)})
        return d


def alerts_from_dicts(items: List[Dict]) -> List[Alert]:
    alerts = []
    seen = set()
    for n, item in enumerate(items, start=1):
        if not isinstance(item, dict) or not item.get("id") or not item.get("title"):
            raise ToolError("alert #%d needs at least an 'id' and a 'title'" % n)
        if str(item["id"]) in seen:
            raise ToolError("duplicate alert id %r" % item["id"])
        seen.add(str(item["id"]))
        try:
            sev = Severity.parse(item.get("severity", "medium"))
        except ValueError as exc:
            raise ToolError("alert %s: %s" % (item["id"], exc))
        alerts.append(Alert(str(item["id"]), str(item["title"]), sev, str(item.get("category", "")), str(item.get("asset", "")),
                            str(item.get("user", "")), str(item.get("src_ip", "")), str(item.get("source", "")),
                            str(item.get("description", "")), str(item.get("timestamp", "")), [str(t) for t in item.get("tags", [])]))
    return alerts


def load_alerts(path) -> List[Alert]:
    data = read_json(path)
    items = data.get("alerts") if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ToolError("%s must be a JSON list of alerts (or an object with an 'alerts' list)" % path)
    return alerts_from_dicts(items)


def load_assets(path) -> Dict[str, int]:
    data = read_json(path)
    assets = data.get("assets") if isinstance(data, dict) and "assets" in data else data
    if not isinstance(assets, dict):
        raise ToolError("%s must map asset names to criticality numbers 1-5" % path)
    out = {}
    for name, level in assets.items():
        if not isinstance(level, int) or not 1 <= level <= 5:
            raise ToolError("asset %r: criticality must be a whole number from 1 to 5, got %r" % (name, level))
        out[name] = level
    return out


def score_alerts(alerts: List[Alert], assets: Dict[str, int] = None) -> List[ScoredAlert]:
    """Score every alert 0-100 and return them ranked, highest first."""
    assets = assets or {}
    groups = Counter((a.category, a.asset or a.src_ip) for a in alerts)
    scored: List[ScoredAlert] = []
    for a in alerts:
        reasons = []
        score = SEVERITY_POINTS[a.severity]
        reasons.append("+%d base points for %s severity" % (score, a.severity.name))
        level = assets.get(a.asset, DEFAULT_CRITICALITY)
        pts = ASSET_POINTS[level]
        known = "criticality %d" % level if a.asset in assets else "criticality unknown, assuming %d" % level
        if pts:
            reasons.append("+%d for asset '%s' (%s)" % (pts, a.asset or "n/a", known))
        score += pts
        repeats = groups[(a.category, a.asset or a.src_ip)] - 1
        if repeats > 0:
            rp = min(REPEAT_POINTS_MAX, repeats * REPEAT_POINTS_EACH)
            score += rp
            reasons.append("+%d because %d other alert(s) share category '%s' and the same target" % (rp, repeats, a.category))
        for tag in a.tags:
            if tag in TAG_POINTS:
                tp, why = TAG_POINTS[tag]
                score += tp
                reasons.append("+%d %s" % (tp, why))
        if a.src_ip and not is_private_ip(a.src_ip):
            score += EXTERNAL_SOURCE_POINTS
            reasons.append("+%d source IP is outside the private network" % EXTERNAL_SOURCE_POINTS)
        score = min(100, score)
        scored.append(ScoredAlert(a, score, Severity.from_score(score), reasons))
    scored.sort(key=lambda s: (-s.score, s.alert.timestamp, s.alert.id))
    return scored

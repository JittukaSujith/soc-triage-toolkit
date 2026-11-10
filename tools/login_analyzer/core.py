"""Suspicious login analyzer - core logic.

Stolen passwords still log in "successfully", so detection has to look at
*context*, not just success/failure. Four classic context signals:

* Impossible travel - the same user logs in from two places further apart than
  anyone could travel in the time between logins (New York then Moscow 20 minutes
  later). Usually means two different people hold the credentials.
* New country    - first login from a country this user has never used.
* New device     - first login from a device this user has never used.
* Off-hours      - a login at a time the person normally does not work.

Each signal alone is weak (people travel, buy phones, work late). Together they
are strong, so we add weighted points and convert the total to a severity.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

from soc_common.io_utils import read_csv_rows
from soc_common.schema import iso, parse_timestamp
from soc_common.severity import Severity
from soc_common.validation import ToolError

REQUIRED_COLUMNS = ("timestamp", "user", "ip", "country", "device", "result")

WEIGHTS = {"impossible_travel": 60, "new_country": 40, "new_device": 20, "off_hours": 20, "weekend": 10}


@dataclass(frozen=True)
class Settings:
    max_speed_kmh: float = 900.0      # roughly the speed of a commercial flight
    min_distance_km: float = 100.0    # ignore tiny hops (GeoIP is imprecise at city level)
    work_start_hour: int = 7          # work hours in the user's LOCAL time
    work_end_hour: int = 19
    flag_weekends: bool = False


@dataclass
class LoginRecord:
    timestamp: datetime
    user: str
    ip: str
    country: str
    city: str
    lat: Optional[float]
    lon: Optional[float]
    device: str
    result: str
    tz_offset: float = 0.0   # hours from UTC for the user's location (from the CSV, default 0)


@dataclass
class LoginFinding:
    record: LoginRecord
    signals: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    score: int = 0
    severity: Severity = Severity.INFO

    def to_dict(self) -> Dict:
        r = self.record
        return {"timestamp": iso(r.timestamp), "user": r.user, "ip": r.ip, "country": r.country, "city": r.city,
                "device": r.device, "severity": self.severity.name, "score": self.score,
                "signals": ",".join(self.signals), "reasons": "; ".join(self.reasons)}


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points on Earth, in kilometres."""
    r = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi, dlmb = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def _float(value: str) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def load_logins(path) -> List[LoginRecord]:
    rows = read_csv_rows(path)
    if not rows:
        raise ToolError("%s has no login rows" % path)
    missing = [c for c in REQUIRED_COLUMNS if c not in rows[0]]
    if missing:
        raise ToolError("%s is missing required column(s): %s" % (path, ", ".join(missing)))
    records = []
    for n, row in enumerate(rows, start=2):
        try:
            ts = parse_timestamp(row["timestamp"])
        except ValueError as exc:
            raise ToolError("%s row %d: %s" % (path, n, exc))
        records.append(LoginRecord(ts, row["user"].strip(), row["ip"].strip(), row["country"].strip(), row.get("city", "").strip(),
                                   _float(row.get("lat", "")), _float(row.get("lon", "")), row["device"].strip(),
                                   row["result"].strip().lower(), _float(row.get("tz_offset", "")) or 0.0))
    records.sort(key=lambda r: r.timestamp)
    return records


def analyze_logins(records: List[LoginRecord], settings: Settings = Settings()) -> List[LoginFinding]:
    """Return one LoginFinding per *successful* login that triggered at least one signal."""
    findings: List[LoginFinding] = []
    last_login: Dict[str, LoginRecord] = {}
    countries: Dict[str, Set[str]] = defaultdict(set)
    devices: Dict[str, Set[str]] = defaultdict(set)

    for rec in records:
        if rec.result != "success":
            continue                        # failures belong to the brute-force detector
        finding = LoginFinding(rec)
        first_for_user = rec.user not in last_login

        prev = last_login.get(rec.user)
        if prev and None not in (prev.lat, prev.lon, rec.lat, rec.lon):
            km = haversine_km(prev.lat, prev.lon, rec.lat, rec.lon)
            hours = max((rec.timestamp - prev.timestamp).total_seconds() / 3600.0, 1.0 / 3600)
            speed = km / hours
            if km >= settings.min_distance_km and speed > settings.max_speed_kmh:
                finding.signals.append("impossible_travel")
                finding.reasons.append("%s (%s) to %s (%s): %.0f km in %.0f min = %.0f km/h, faster than any flight." % (
                    prev.city or prev.country, prev.country, rec.city or rec.country, rec.country, km, hours * 60, speed))

        if not first_for_user:              # the first login only builds the baseline
            if rec.country not in countries[rec.user]:
                finding.signals.append("new_country")
                finding.reasons.append("First login from %s - known countries: %s." % (rec.country, ", ".join(sorted(countries[rec.user]))))
            if rec.device not in devices[rec.user]:
                finding.signals.append("new_device")
                finding.reasons.append("First time this user used device '%s'." % rec.device)

        # Work hours are judged in the user's LOCAL time: 22:00 UTC is mid-morning in Sydney.
        local = rec.timestamp + timedelta(hours=rec.tz_offset)
        if not (settings.work_start_hour <= local.hour < settings.work_end_hour):
            finding.signals.append("off_hours")
            finding.reasons.append("Login at %02d:%02d local time (UTC%+g), outside %02d:00-%02d:00." % (
                local.hour, local.minute, rec.tz_offset, settings.work_start_hour, settings.work_end_hour))
        if settings.flag_weekends and local.weekday() >= 5:
            finding.signals.append("weekend")
            finding.reasons.append("Login on a weekend.")

        countries[rec.user].add(rec.country)
        devices[rec.user].add(rec.device)
        last_login[rec.user] = rec

        if finding.signals:
            finding.score = min(100, sum(WEIGHTS[s] for s in finding.signals))
            finding.severity = Severity.from_score(finding.score)
            findings.append(finding)

    findings.sort(key=lambda f: (-f.score, f.record.timestamp))
    return findings

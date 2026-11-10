"""Brute-force and password-spray detector - core logic.

Three attacker styles, three different fingerprints:

* Brute force   - one IP hammers one or a few accounts. Fingerprint: MANY failures
                  from ONE IP in a short time.
* Password spray - one IP tries a few common passwords against MANY accounts.
                  Attackers do this to stay under per-account lockout limits.
                  Fingerprint: many DISTINCT USERS from one IP, only 1-3 tries each.
* Targeted account (distributed / credential stuffing) - many IPs, one account.
                  Fingerprint: one USER failing from many DIFFERENT IPs. Per-IP
                  rules miss this, so we also group by user.

The most important question for an analyst is "did they get in?", so every finding
also checks for a successful login from the same source afterwards.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

from soc_common.schema import LogEvent, iso
from soc_common.severity import Severity

LOGIN_ACTIONS = ("ssh_login", "web_login")


@dataclass(frozen=True)
class Thresholds:
    ip_failures: int = 5              # failures from one IP inside the window = brute force
    user_failures: int = 5            # failures against one user inside the window = targeted
    user_min_ips: int = 2             # ...coming from at least this many different IPs
    spray_users: int = 5              # distinct users from one IP inside the window = spray
    spray_max_per_user: int = 3       # a spray tries each account only a few times
    window_minutes: int = 10


@dataclass
class Finding:
    kind: str                         # ip_bruteforce | password_spray | user_targeted
    key: str                          # the IP (or the username for user_targeted)
    failures: int
    distinct_users: int
    distinct_ips: int
    first_seen: datetime
    last_seen: datetime
    success_after: bool
    severity: Severity
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {"kind": self.kind, "key": self.key, "failures": self.failures, "distinct_users": self.distinct_users,
                "distinct_ips": self.distinct_ips, "first_seen": iso(self.first_seen), "last_seen": iso(self.last_seen),
                "success_after": self.success_after, "severity": self.severity.name, "reasons": "; ".join(self.reasons)}


def is_login(ev: LogEvent) -> bool:
    return ev.action in LOGIN_ACTIONS


def densest_window(events: List[LogEvent], window: timedelta) -> List[LogEvent]:
    """Sliding window: return the time-sorted slice with the most events inside `window`.

    Counting total failures is misleading (5 failures in a week is normal, 5 in 30
    seconds is a bot), so we look for the densest burst instead.
    """
    best: Tuple[int, int] = (0, 0)
    lo = 0
    for hi in range(len(events)):
        while events[hi].timestamp - events[lo].timestamp > window:
            lo += 1
        if hi - lo + 1 > best[1] - best[0]:
            best = (lo, hi + 1)
    return events[best[0]:best[1]]


def detect(events: List[LogEvent], th: Thresholds = Thresholds()) -> List[Finding]:
    window = timedelta(minutes=th.window_minutes)
    ordered = sorted(events, key=lambda e: e.timestamp)
    failures = [e for e in ordered if is_login(e) and e.outcome == "failure" and e.src_ip]
    successes = [e for e in ordered if is_login(e) and e.outcome == "success" and e.src_ip]
    findings: List[Finding] = []

    # ---- per-IP view: brute force and password spray
    by_ip: Dict[str, List[LogEvent]] = defaultdict(list)
    for e in failures:
        by_ip[e.src_ip].append(e)
    for ip, evs in by_ip.items():
        burst = densest_window(evs, window)
        users = Counter(e.user for e in burst)
        is_spray = len(users) >= th.spray_users and max(users.values()) <= th.spray_max_per_user
        if not is_spray and len(burst) < th.ip_failures:
            continue
        last = burst[-1].timestamp
        won = [s for s in successes if s.src_ip == ip and s.timestamp > last]
        reasons: List[str] = []
        if is_spray:
            kind, sev = "password_spray", Severity.HIGH
            reasons.append("%d different accounts tried from one IP, at most %d attempts each. Attackers spray a few common "
                           "passwords across many accounts to stay under per-account lockout limits." % (len(users), max(users.values())))
        else:
            kind = "ip_bruteforce"
            sev = Severity.HIGH if len(burst) >= th.ip_failures * 3 else Severity.MEDIUM
            reasons.append("%d failed logins from one IP within %d minutes (threshold %d)." % (len(burst), th.window_minutes, th.ip_failures))
        if won:
            sev = Severity.CRITICAL
            reasons.append("A successful login for '%s' from the same IP followed at %s. The attacker may now have a valid account." % (
                won[0].user or "(web session)", iso(won[0].timestamp)))
        invalid = sum(1 for e in burst if e.extra.get("invalid_user"))
        if invalid:
            reasons.append("%d attempts used usernames that do not exist - a sign of guessing from a wordlist." % invalid)
        findings.append(Finding(kind, ip, len(burst), len(users), 1, burst[0].timestamp, last, bool(won), sev, reasons))

    # ---- per-user view: one account attacked from many IPs
    by_user: Dict[str, List[LogEvent]] = defaultdict(list)
    for e in failures:
        if e.user:
            by_user[e.user].append(e)
    for user, evs in by_user.items():
        burst = densest_window(evs, window)
        ips = {e.src_ip for e in burst}
        if len(burst) < th.user_failures or len(ips) < th.user_min_ips:
            continue
        last = burst[-1].timestamp
        won = [s for s in successes if s.user == user and s.src_ip in ips and s.timestamp > last]
        sev = Severity.CRITICAL if won else Severity.MEDIUM
        reasons = ["Account '%s' failed %d times from %d different IPs within %d minutes. Spreading attempts across IPs "
                   "evades per-IP blocking (distributed attack or credential stuffing)." % (user, len(burst), len(ips), th.window_minutes)]
        if won:
            reasons.append("One of the attacking IPs then logged in successfully as '%s'." % user)
        findings.append(Finding("user_targeted", user, len(burst), 1, len(ips), burst[0].timestamp, last, bool(won), sev, reasons))

    findings.sort(key=lambda f: (-int(f.severity), -f.failures, f.key))
    return findings

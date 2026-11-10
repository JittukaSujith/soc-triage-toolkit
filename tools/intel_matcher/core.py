"""Offline threat-intel matcher - core logic.

"Threat intelligence" is knowledge that something is already known to be bad.
This tool compares your IOCs against a LOCAL blocklist that you maintain, so it
works with no internet and never sends your data anywhere.

An optional, clearly labelled online mode can look up domain registration dates
through the public RDAP protocol. Newly registered domains are a common phishing
signal, but this mode DOES send the domain name to a third party, so it is off by default.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlsplit

from soc_common.io_utils import read_csv_rows
from soc_common.ioc_patterns import classify_ioc, refang
from soc_common.severity import Severity
from soc_common.validation import ToolError, read_text_file

# Special-use top-level domains never exist in the public DNS, so online lookups are pointless.
RESERVED_TLDS = {"example", "invalid", "test", "localhost", "local", "internal"}


@dataclass
class Indicator:
    value: str
    type: str
    source: str = "local"
    confidence: int = 50
    note: str = ""


@dataclass
class Match:
    ioc: str
    ioc_type: str
    indicator: str
    source: str
    confidence: int
    note: str
    kind: str                       # exact | cidr | subdomain | url-host | email-domain

    @property
    def severity(self) -> Severity:
        c = self.confidence
        return Severity.CRITICAL if c >= 90 else Severity.HIGH if c >= 70 else Severity.MEDIUM if c >= 50 else Severity.LOW

    def to_dict(self) -> Dict:
        return {"ioc": self.ioc, "type": self.ioc_type, "matched_indicator": self.indicator, "match_kind": self.kind,
                "source": self.source, "confidence": self.confidence, "severity": self.severity.name, "note": self.note}


def load_blocklist(path) -> List[Indicator]:
    """Load a blocklist: a CSV with an 'indicator' column, or a plain text file with one indicator per line."""
    text = read_text_file(path)
    first = next((ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")), "")
    items: List[Indicator] = []
    if "indicator" in first.lower():
        for n, row in enumerate(read_csv_rows(path), start=2):
            value = refang((row.get("indicator") or "").strip()).lower() if (row.get("type") or "") not in ("sha256", "sha1", "md5") else (row.get("indicator") or "").strip().lower()
            if not value:
                continue
            kind = (row.get("type") or "").strip().lower() or classify_ioc(value)
            if not kind:
                raise ToolError("%s row %d: cannot tell what kind of indicator %r is" % (path, n, value))
            try:
                conf = int(row.get("confidence") or 50)
            except ValueError:
                raise ToolError("%s row %d: confidence must be a number 0-100" % (path, n))
            items.append(Indicator(value, kind, (row.get("source") or "local").strip(), max(0, min(100, conf)), (row.get("note") or "").strip()))
    else:
        for ln in text.splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                value = refang(ln).lower()
                kind = classify_ioc(value)
                if kind:
                    items.append(Indicator(value, kind))
    if not items:
        raise ToolError("%s contains no usable indicators" % path)
    return items


def _network(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _domain_hit(domain: str, indicator: str) -> bool:
    return domain == indicator or domain.endswith("." + indicator)


def match_iocs(iocs: Dict[str, List[str]], blocklist: List[Indicator]) -> List[Match]:
    """Compare extracted IOCs with the blocklist. Returns matches, most severe first."""
    out: Dict[tuple, Match] = {}

    def add(ioc, kind_t, ind: Indicator, how):
        out.setdefault((ioc, ind.value), Match(ioc, kind_t, ind.value, ind.source, ind.confidence, ind.note, how))

    ip_inds = [(i, _network(i.value)) for i in blocklist if i.type == "ip"]
    dom_inds = [i for i in blocklist if i.type == "domain"]

    def check_ip(ip: str, label: str, kind_t: str, how_prefix: str = ""):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return
        for ind, net in ip_inds:
            if net is not None and net.version == addr.version and addr in net:
                add(label, kind_t, ind, how_prefix + ("exact" if net.num_addresses == 1 else "cidr"))

    for ip in iocs.get("ip", []):
        check_ip(ip, ip, "ip")
    for dom in iocs.get("domain", []):
        for ind in dom_inds:
            if _domain_hit(dom, ind.value):
                add(dom, "domain", ind, "exact" if dom == ind.value else "subdomain")
    for url in iocs.get("url", []):
        for ind in blocklist:
            if ind.type == "url" and url.lower().rstrip("/") == ind.value.rstrip("/"):
                add(url, "url", ind, "exact")
        host = _host(url)
        for ind in dom_inds:
            if host and _domain_hit(host, ind.value):
                add(url, "url", ind, "url-host")
        check_ip(host, url, "url", "url-host ")
    for email in iocs.get("email", []):
        for ind in blocklist:
            if ind.type == "email" and email == ind.value:
                add(email, "email", ind, "exact")
        domain = email.rsplit("@", 1)[-1]
        for ind in dom_inds:
            if _domain_hit(domain, ind.value):
                add(email, "email", ind, "email-domain")
    for kind in ("md5", "sha1", "sha256", "cve"):
        for value in iocs.get(kind, []):
            for ind in blocklist:
                if ind.type == kind and ind.value == value.lower():
                    add(value, kind, ind, "exact")
    return sorted(out.values(), key=lambda m: (-m.confidence, m.ioc))


# ------------------------------------------------------------------ optional online mode (RDAP)
def parse_rdap_registration(data: Dict) -> Optional[datetime]:
    """Find the 'registration' event date in an RDAP domain response (pure function, testable offline)."""
    for event in data.get("events", []) or []:
        if str(event.get("eventAction", "")).lower() == "registration":
            raw = str(event.get("eventDate", ""))
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
            except ValueError:
                return None
    return None


def domain_age_note(age_days: int) -> str:
    if age_days < 30:
        return "registered only %d days ago - newly registered domains are a common phishing signal" % age_days
    if age_days < 180:
        return "registered %d days ago (fairly new)" % age_days
    return "registered %d days ago (established)" % age_days


def is_reserved_domain(domain: str) -> bool:
    return domain.rsplit(".", 1)[-1].lower() in RESERVED_TLDS


def online_domain_lookup(domain: str, timeout: int = 6) -> Dict:
    """ONLINE: ask the public rdap.org service (which redirects to the right registry) when a domain was registered.

    The domain name is sent to rdap.org and the registry. Network libraries are imported here,
    not at the top of the file, so the rest of the tool and the tests never need the internet.
    """
    if is_reserved_domain(domain):
        return {"domain": domain, "status": "skipped", "detail": "reserved/special-use TLD, not in public DNS"}
    import json
    import urllib.error
    import urllib.request
    from urllib.parse import quote

    req = urllib.request.Request("https://rdap.org/domain/" + quote(domain), headers={"Accept": "application/rdap+json", "User-Agent": "soc-triage-toolkit/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URL
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        return {"domain": domain, "status": "error", "detail": "RDAP returned HTTP %d (domain may not exist)" % exc.code}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"domain": domain, "status": "error", "detail": "lookup failed: %s" % exc}
    registered = parse_rdap_registration(data)
    if not registered:
        return {"domain": domain, "status": "unknown", "detail": "no registration date in RDAP response"}
    age = (datetime.now(timezone.utc) - registered).days
    return {"domain": domain, "status": "ok", "registered": registered.strftime("%Y-%m-%d"), "age_days": age, "detail": domain_age_note(age)}

"""Indicator-of-Compromise (IOC) patterns, defanging and classification.

An IOC is a piece of evidence that points at malicious activity: an IP that
attacked you, a phishing domain, a malware file hash. Analysts *defang* IOCs
(hxxp://evil[.]com) before sharing them so nobody clicks one by accident, and
*refang* them again before searching logs.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional

IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d|\.\d)")
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`\)\]\}]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,24}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)
MD5_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])")
SHA1_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])")
SHA256_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# "report.pdf" or "setup.exe" look like domains to a regex. We drop names whose
# last label is a common *file* extension. (Real TLDs such as .py, .sh and .md
# are NOT excluded, so they can still be extracted.)
FILE_EXTENSIONS = frozenset(
    "exe dll pdf doc docx xls xlsx ppt pptx txt csv json log jpg jpeg png gif bmp svg html htm php js css "
    "xml yml yaml ini cfg bat ps1 vbs msi iso rar tar gz tgz bak tmp eml zip".split()
)

# Authentication-Results headers contain tokens like "header.from" and "smtp.mailfrom" that look like domains.
PSEUDO_DOMAIN_RE = re.compile(r"^(header|smtp|policy|body)\.[a-z\-]{1,12}$", re.IGNORECASE)

IOC_TYPES = ("ip", "domain", "url", "email", "md5", "sha1", "sha256", "cve")


def refang(text: str) -> str:
    """Undo common defanging so patterns can match (hxxp -> http, [.] -> .)."""
    out = text
    for fake, real in (("[://]", "://"), ("[:]", ":"), ("[.]", "."), ("(.)", "."), ("{.}", "."),
                       ("[dot]", "."), ("(dot)", "."), ("[@]", "@"), ("[at]", "@"), ("(at)", "@")):
        out = re.sub(re.escape(fake), real, out, flags=re.IGNORECASE)
    out = re.sub(r"\bhxxp(s?)://", r"http\1://", out, flags=re.IGNORECASE)
    out = re.sub(r"\bfxp://", "ftp://", out, flags=re.IGNORECASE)
    return out


def defang(value: str, ioc_type: str = "") -> str:
    """Make an IOC safe to paste into chat or tickets (hxxp://evil[.]com)."""
    out = value
    if ioc_type in ("url", "") and re.match(r"(?i)^(https?|ftp)://", out):
        out = re.sub(r"(?i)^http", "hxxp", out, count=1)
        out = re.sub(r"(?i)^ftp", "fxp", out, count=1)
    if ioc_type in ("ip", "domain", "url", "email", ""):
        out = out.replace(".", "[.]")
    if ioc_type in ("email", ""):
        out = out.replace("@", "[at]")
    return out


def is_valid_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_private_ip(value: str) -> bool:
    """True for private, loopback and link-local addresses (not routable on the internet).

    Note: documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
    are used in this repo's fake data and are treated as *public* on purpose.
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    documentation = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    if any(ip in net for net in documentation if net.version == ip.version):
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def looks_like_file_name(domain: str) -> bool:
    """True for names that are really files (report.pdf) or header tokens (header.from), not domains."""
    return domain.rsplit(".", 1)[-1].lower() in FILE_EXTENSIONS or bool(PSEUDO_DOMAIN_RE.match(domain))


def classify_ioc(value: str) -> Optional[str]:
    """Guess the IOC type of a single indicator string, or None if unknown."""
    v = refang(value.strip())
    if not v:
        return None
    if re.fullmatch(r"(?i)(?:https?|ftp)://\S+", v):
        return "url"
    if is_valid_ipv4(v):
        return "ip"
    if "/" in v:
        try:
            ipaddress.ip_network(v, strict=False)
            return "ip"  # CIDR range, treated as an IP-type indicator
        except ValueError:
            pass
    if re.fullmatch(r"[A-Fa-f0-9]{64}", v):
        return "sha256"
    if re.fullmatch(r"[A-Fa-f0-9]{40}", v):
        return "sha1"
    if re.fullmatch(r"[A-Fa-f0-9]{32}", v):
        return "md5"
    if CVE_RE.fullmatch(v):
        return "cve"
    if EMAIL_RE.fullmatch(v):
        return "email"
    if DOMAIN_RE.fullmatch(v) and not looks_like_file_name(v):
        return "domain"
    return None

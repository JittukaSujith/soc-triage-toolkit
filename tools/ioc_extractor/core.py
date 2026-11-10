"""IOC extractor - core logic.

Incident reports, phishing emails and chat threads are full of indicators. The
extractor pulls them out, normalises them (lower-case domains, upper-case CVEs),
de-duplicates them, and can defang them so they are safe to paste into tickets.
"""
from __future__ import annotations

import csv
import io
import json
from typing import Dict, Iterable, List, Optional

from soc_common.ioc_patterns import (CVE_RE, DOMAIN_RE, EMAIL_RE, IOC_TYPES, IPV4_RE, MD5_RE, SHA1_RE, SHA256_RE, URL_RE,
                                     defang, is_private_ip, is_valid_ipv4, looks_like_file_name, refang)
from soc_common.validation import ToolError, read_text_file

TRAILING = ".,;:!?'\""


def extract_iocs(text: str, exclude_private: bool = False, types: Optional[Iterable[str]] = None) -> Dict[str, List[str]]:
    """Return {ioc_type: sorted unique values}. Defanged input (hxxp, [.]) is understood."""
    wanted = set(types) if types else set(IOC_TYPES)
    unknown = wanted - set(IOC_TYPES)
    if unknown:
        raise ToolError("unknown IOC type(s): %s (choose from %s)" % (", ".join(sorted(unknown)), ", ".join(IOC_TYPES)))
    t = refang(text)
    found: Dict[str, set] = {k: set() for k in IOC_TYPES}

    for url in URL_RE.findall(t):
        found["url"].add(url.rstrip(TRAILING))
    for email in EMAIL_RE.findall(t):
        found["email"].add(email.lower())
    for ip in IPV4_RE.findall(t):
        if is_valid_ipv4(ip) and not (exclude_private and is_private_ip(ip)):
            found["ip"].add(ip)
    for pattern, kind in ((SHA256_RE, "sha256"), (SHA1_RE, "sha1"), (MD5_RE, "md5")):
        for h in pattern.findall(t):
            found[kind].add(h.lower())
    for cve in CVE_RE.findall(t):
        found["cve"].add(cve.upper())
    for dom in DOMAIN_RE.findall(t):
        dom = dom.lower()
        if not looks_like_file_name(dom):
            found["domain"].add(dom)
    return {k: sorted(found[k]) for k in IOC_TYPES if k in wanted and found[k]}


def total_count(iocs: Dict[str, List[str]]) -> int:
    return sum(len(v) for v in iocs.values())


def to_rows(iocs: Dict[str, List[str]], defang_output: bool = False) -> List[Dict[str, str]]:
    rows = []
    for kind in IOC_TYPES:
        for value in iocs.get(kind, []):
            rows.append({"type": kind, "value": defang(value, kind) if defang_output else value})
    return rows


def to_json(iocs: Dict[str, List[str]], defang_output: bool = False) -> str:
    data = {k: [defang(v, k) if defang_output else v for v in vs] for k, vs in iocs.items()}
    return json.dumps(data, indent=2)


def to_csv(iocs: Dict[str, List[str]], defang_output: bool = False) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["type", "value"], lineterminator="\n")
    writer.writeheader()
    writer.writerows(to_rows(iocs, defang_output))
    return buf.getvalue()


def eml_to_text(path: str) -> str:
    """Turn an .eml into searchable text: all headers plus the DECODED text/HTML bodies.

    Raw .eml files often use quoted-printable encoding, which breaks long URLs across lines
    ("...100.=\\n77/verify"). Decoding first means URLs and domains are extracted whole.
    """
    from email import policy
    from email.parser import BytesParser

    from soc_common.validation import require_file

    msg = BytesParser(policy=policy.default).parsebytes(require_file(path).read_bytes())
    parts = ["%s: %s" % (k, v) for k, v in msg.items()]
    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html") and part.get_content_disposition() != "attachment":
            try:
                parts.append(part.get_content())
            except (LookupError, UnicodeDecodeError):
                continue
    return "\n".join(parts)


def read_sources(paths: List[str]) -> str:
    """Read and join text from files. .eml files are decoded; everything else is read as text."""
    return "\n".join(eml_to_text(p) if str(p).lower().endswith(".eml") else read_text_file(p) for p in paths)

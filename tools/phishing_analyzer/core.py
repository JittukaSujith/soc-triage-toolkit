"""Phishing email analyzer - core logic.

Phishing works by faking *trust*. Almost every trick leaves a trace in the headers
or the content, and an analyst can check them without opening the message:

* SPF / DKIM / DMARC - did the receiving server verify the sender?
    SPF   (Sender Policy Framework): is the sending server allowed to send for the domain?
    DKIM  (DomainKeys Identified Mail): does the cryptographic signature check out?
    DMARC (Domain-based Message Authentication, Reporting and Conformance): do SPF/DKIM
          line up with the visible From address, and what should receivers do if not?
* Reply-To mismatch  - You see "From: your CEO", but replies silently go to the attacker.
* Return-Path mismatch - the real bounce address often exposes the true sending system.
* Display-name spoofing - "PayPal Support <random@evil.example>": people read the name, not the address.
* Look-alike domains  - paypa1.com, rnicrosoft.com.
* Links    - the text says paypal.com but the link goes somewhere else; raw IP links; shorteners.
* Attachments - double extensions (invoice.pdf.exe), macro documents, executables.
* Urgency  - "act within 24 hours" is there to stop you thinking.

The result is a 0-100 risk score where EVERY point has a human-readable reason.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from soc_common.domains import BRANDS, lookalike_brand, registered_domain
from soc_common.ioc_patterns import URL_RE
from soc_common.severity import Severity
from soc_common.validation import ToolError, require_file

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"}
FREEMAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com", "proton.me", "protonmail.com", "icloud.com"}
RISKY_EXT = {"exe", "scr", "bat", "cmd", "com", "js", "jse", "vbs", "vbe", "ps1", "jar", "msi", "lnk", "hta", "wsf"}
MACRO_EXT = {"docm", "xlsm", "pptm"}
ARCHIVE_EXT = {"zip", "rar", "7z", "iso", "img"}
DOCUMENT_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png"}
URGENT_PATTERNS = [
    r"\burgent(ly)?\b", r"\bimmediate(ly)?\b", r"\baction required\b", r"\bfinal (notice|warning|reminder)\b",
    r"\baccount (has been )?(suspended|locked|limited|disabled|compromised)\b", r"\bverify (your|now)\b",
    r"\bwithin \d+ hours?\b", r"\bexpires? (today|soon)\b", r"\bpayment (failed|declined|overdue)\b",
    r"\bunusual (sign-?in|activity)\b", r"\bpassword (expires?|reset)\b", r"\b(wire|gift cards?)\b", r"\bquick (favou?r|task)\b",
]


@dataclass
class ReceivedHop:
    raw: str
    from_host: str = ""
    by_host: str = ""
    ip: str = ""
    timestamp: str = ""


@dataclass
class LinkInfo:
    href: str
    text: str = ""
    host: str = ""
    flags: List[str] = field(default_factory=list)


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size: int
    sha256: str
    flags: List[str] = field(default_factory=list)


@dataclass
class EmailAnalysis:
    path: str = ""
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    message_id: str = ""
    date: str = ""
    spf: str = "missing"
    dkim: str = "missing"
    dmarc: str = "missing"
    hops: List[ReceivedHop] = field(default_factory=list)
    links: List[LinkInfo] = field(default_factory=list)
    attachments: List[AttachmentInfo] = field(default_factory=list)
    score: int = 0
    severity: Severity = Severity.INFO
    findings: List[Tuple[int, str]] = field(default_factory=list)   # (points, reason)

    @property
    def from_domain(self) -> str:
        return self.from_addr.rsplit("@", 1)[1] if "@" in self.from_addr else ""

    def to_dict(self) -> Dict:
        return {
            "path": self.path, "subject": self.subject, "from_name": self.from_name, "from_addr": self.from_addr,
            "reply_to": self.reply_to, "return_path": self.return_path, "message_id": self.message_id, "date": self.date,
            "spf": self.spf, "dkim": self.dkim, "dmarc": self.dmarc,
            "received_chain": [h.__dict__ for h in self.hops],
            "links": [l.__dict__ for l in self.links],
            "attachments": [a.__dict__ for a in self.attachments],
            "score": self.score, "severity": self.severity.name,
            "findings": [{"points": p, "reason": r} for p, r in self.findings],
        }


# ------------------------------------------------------------------ header parsing
def _addr(value) -> Tuple[str, str]:
    name, addr = parseaddr(str(value or ""))
    return name.strip(), addr.strip().lower()


def parse_auth_results(msg) -> Dict[str, str]:
    """Pull spf/dkim/dmarc verdicts from Authentication-Results (added by the RECEIVING server)."""
    blob = " ".join(str(h) for h in (msg.get_all("Authentication-Results") or []))
    out = {}
    for mech in ("spf", "dkim", "dmarc"):
        vals = [v.lower() for v in re.findall(r"\b%s=([a-z]+)" % mech, blob, re.IGNORECASE)]
        out[mech] = "missing" if not vals else ("pass" if "pass" in vals else vals[0])
    if out["spf"] == "missing" and msg.get("Received-SPF"):
        out["spf"] = str(msg["Received-SPF"]).split()[0].lower()
    return out


def parse_received(msg) -> List[ReceivedHop]:
    """Parse the Received chain into hops, oldest first.

    Each mail server adds a Received header on top, so the LAST header is the first hop.
    The first hop's IP is the best clue to where the message really came from.
    """
    hops: List[ReceivedHop] = []
    for raw in reversed(msg.get_all("Received") or []):
        text = " ".join(str(raw).split())
        frm = re.search(r"\bfrom\s+(\S+)", text)
        by = re.search(r"\bby\s+(\S+)", text)
        ip = ""
        for candidate in re.findall(r"\[([0-9a-fA-F:.]+)\]", text):
            try:
                ipaddress.ip_address(candidate)
                ip = candidate
                break
            except ValueError:
                continue
        stamp = ""
        if ";" in text:
            try:
                stamp = parsedate_to_datetime(text.rsplit(";", 1)[1].strip()).strftime("%Y-%m-%d %H:%M:%S %z")
            except (TypeError, ValueError):
                stamp = text.rsplit(";", 1)[1].strip()
        hops.append(ReceivedHop(text, frm.group(1) if frm else "", by.group(1) if by else "", ip, stamp))
    return hops


# ------------------------------------------------------------------ links and attachments
class _AnchorParser(HTMLParser):
    """Collect (href, visible text) for every <a> tag."""

    def __init__(self) -> None:
        super().__init__()
        self.anchors: List[Tuple[str, str]] = []
        self._href: Optional[str] = None
        self._text: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.anchors.append((self._href, " ".join("".join(self._text).split())))
            self._href = None


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def assess_link(href: str, text: str = "") -> LinkInfo:
    info = LinkInfo(href=href, text=text, host=_host(href))
    host = info.host
    if not host:
        return info
    try:
        ipaddress.ip_address(host)
        info.flags.append("ip_host")           # legitimate sites almost never link to a bare IP
    except ValueError:
        pass
    if "xn--" in host:
        info.flags.append("punycode")          # may disguise look-alike characters
    if registered_domain(host) in SHORTENERS:
        info.flags.append("shortener")         # hides the real destination
    if "@" in urlsplit(href).netloc:
        info.flags.append("userinfo_trick")    # https://paypal.com@evil.example/ really goes to evil.example
    shown = re.search(r"(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})", text.lower())
    if shown and registered_domain(shown.group(1)) != registered_domain(host):
        info.flags.append("anchor_mismatch")   # the text promises one site, the link goes to another
    if lookalike_brand(host):
        info.flags.append("lookalike_domain")
    return info


def assess_attachment(filename: str, content_type: str, payload: bytes) -> AttachmentInfo:
    name = filename or "(unnamed)"
    parts = name.lower().split(".")
    ext = parts[-1] if len(parts) > 1 else ""
    flags: List[str] = []
    if ext in RISKY_EXT:
        flags.append("executable")
    if len(parts) > 2 and parts[-2] in DOCUMENT_EXT and ext in RISKY_EXT:
        flags.append("double_extension")       # invoice.pdf.exe: Windows may hide the last part
    if ext in MACRO_EXT:
        flags.append("macro_document")         # macros are a common malware delivery route
    if ext in ARCHIVE_EXT:
        flags.append("archive")
    return AttachmentInfo(name, content_type, len(payload), hashlib.sha256(payload).hexdigest(), flags)


def extract_links(msg) -> List[LinkInfo]:
    seen: Dict[str, LinkInfo] = {}
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeDecodeError):
            continue
        if ctype == "text/html":
            parser = _AnchorParser()
            parser.feed(content)
            for href, text in parser.anchors:
                if href.lower().startswith(("http://", "https://")) and href not in seen:
                    seen[href] = assess_link(href, text)
        else:
            for url in URL_RE.findall(content):
                url = url.rstrip(".,;:!?")
                if url not in seen:
                    seen[url] = assess_link(url)
    return list(seen.values())


def extract_attachments(msg) -> List[AttachmentInfo]:
    out = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment" or part.get_filename():
            payload = part.get_payload(decode=True) or b""
            out.append(assess_attachment(part.get_filename() or "", part.get_content_type(), payload))
    return out


# ------------------------------------------------------------------ scoring
def score_email(a: EmailAnalysis) -> EmailAnalysis:
    """Add up weighted signals. Each reason is stored with its points."""
    f: List[Tuple[int, str]] = []
    add = lambda pts, why: f.append((pts, why))  # noqa: E731

    for mech, bad, weak in (("spf", 25, 15), ("dkim", 20, 8), ("dmarc", 25, 8)):
        res = getattr(a, mech)
        if res == "fail":
            add(bad, "%s check FAILED - the receiving server could not verify the sender." % mech.upper())
        elif res == "softfail":
            add(weak if mech == "spf" else bad, "%s softfail - sender is probably not authorised." % mech.upper())
        elif res in ("missing", "none", "neutral", "temperror", "permerror"):
            add(weak if mech != "spf" else 10, "%s result is '%s' - no proof of who sent this." % (mech.upper(), res))

    from_dom, reg_from = a.from_domain, registered_domain(a.from_domain) if a.from_domain else ""
    if not from_dom:
        add(30, "No parseable From address.")

    reply_dom = _addr(a.reply_to)[1].rsplit("@", 1)[-1] if "@" in _addr(a.reply_to)[1] else ""
    if reply_dom and registered_domain(reply_dom) != reg_from:
        add(20, "Reply-To (%s) differs from From (%s): replies would go to someone other than the apparent sender." % (reply_dom, from_dom))
        if reply_dom in FREEMAIL and from_dom not in FREEMAIL:
            add(5, "Replies are redirected to a free mailbox provider.")
        look = lookalike_brand(reply_dom)
        if look:
            add(15, "Reply-To domain is a look-alike: %s." % look[1])

    rp_dom = _addr(a.return_path)[1].rsplit("@", 1)[-1] if "@" in _addr(a.return_path)[1] else ""
    if rp_dom and reg_from and registered_domain(rp_dom) != reg_from:
        add(10, "Return-Path domain (%s) differs from From domain (often benign for bulk senders, suspicious here)." % rp_dom)

    shown = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", a.from_name)
    if shown and registered_domain(shown.group(1)) != reg_from:
        add(25, "Display name shows an address (%s) that is not the real sender." % shown.group(0))
    lowered = a.from_name.lower()
    for brand, legit in BRANDS.items():
        if re.search(r"\b%s\b" % re.escape(brand), lowered) and reg_from not in legit:
            add(25, "Display name claims to be '%s' but the mail comes from %s." % (brand, from_dom or "an unknown domain"))
            break

    look = lookalike_brand(from_dom)
    if look:
        add(30, "Sender domain %s: %s." % (from_dom, look[1]))
    if "xn--" in from_dom:
        add(15, "Sender domain uses punycode (possible look-alike characters).")

    hits = [m.group(0).lower() for pat in URGENT_PATTERNS for m in [re.search(pat, a.subject, re.IGNORECASE)] if m]
    if hits:
        add(10 if len(hits) == 1 else 18, "Pressure language in the subject: %s." % ", ".join("'%s'" % h for h in hits))

    messages = {
        "ip_host": (20, "link points to a raw IP address"), "punycode": (15, "link domain uses punycode"),
        "shortener": (10, "link uses a URL shortener that hides the destination"),
        "userinfo_trick": (25, "link uses the user@host trick to disguise the real host"),
        "anchor_mismatch": (25, "link text shows one site but the link goes to another"),
        "lookalike_domain": (20, "link goes to a look-alike domain"),
    }
    reported = set()
    for link in a.links:
        for flag in link.flags:
            if flag in messages and flag not in reported:
                reported.add(flag)
                pts, why = messages[flag]
                add(pts, "Link: %s (e.g. %s)." % (why, link.href))

    att_msg = {"double_extension": (35, "has a double extension designed to hide an executable"),
               "executable": (30, "is an executable file type"), "macro_document": (20, "is a macro-enabled Office document"),
               "archive": (10, "is an archive, which can hide its contents from scanners")}
    for att in a.attachments:
        flagged = [fl for fl in ("double_extension", "executable", "macro_document", "archive") if fl in att.flags]
        for fl in flagged[:1] if "double_extension" in flagged else flagged:
            pts, why = att_msg[fl]
            add(pts, "Attachment '%s' %s." % (att.filename, why))

    if not a.hops:
        add(10, "No Received headers - the delivery path cannot be traced.")

    a.findings = sorted(f, key=lambda x: -x[0])
    a.score = min(100, sum(p for p, _ in f))
    a.severity = Severity.from_score(a.score)
    return a


def analyze_bytes(data: bytes, path: str = "") -> EmailAnalysis:
    try:
        msg = BytesParser(policy=policy.default).parsebytes(data)
    except Exception as exc:  # the email module can raise many error types on corrupt input
        raise ToolError("could not parse email%s: %s" % (" %s" % path if path else "", exc))
    name, addr = _addr(msg.get("From"))
    auth = parse_auth_results(msg)
    analysis = EmailAnalysis(
        path=path, subject=str(msg.get("Subject", "") or ""), from_name=name, from_addr=addr,
        reply_to=str(msg.get("Reply-To", "") or ""), return_path=str(msg.get("Return-Path", "") or ""),
        message_id=str(msg.get("Message-ID", "") or ""), date=str(msg.get("Date", "") or ""),
        spf=auth["spf"], dkim=auth["dkim"], dmarc=auth["dmarc"],
        hops=parse_received(msg), links=extract_links(msg), attachments=extract_attachments(msg),
    )
    if not analysis.from_addr and not analysis.subject and not analysis.hops:
        raise ToolError("%s does not look like an email (no From, Subject or Received headers)" % (path or "input"))
    return score_email(analysis)


def analyze_file(path) -> EmailAnalysis:
    p = require_file(path)
    return analyze_bytes(p.read_bytes(), str(p))


def analysis_iocs(a: EmailAnalysis) -> Dict[str, List[str]]:
    """IOCs worth hunting for elsewhere: origin IP, sender/reply domains, link hosts/URLs, attachment hashes."""
    ips = [h.ip for h in a.hops[:1] if h.ip]
    domains = [d for d in (a.from_domain, _addr(a.reply_to)[1].rsplit("@", 1)[-1] if "@" in _addr(a.reply_to)[1] else "") if d]
    domains += [l.host for l in a.links if l.host and not l.flags.count("ip_host")]
    ips += [l.host for l in a.links if "ip_host" in l.flags]
    return {"ip": sorted(set(ips)), "domain": sorted(set(domains)), "url": sorted({l.href for l in a.links}),
            "sha256": sorted({x.sha256 for x in a.attachments})}

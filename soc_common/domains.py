"""Domain helpers: registered domain, edit distance and look-alike detection.

Attackers register domains that *look* like trusted brands (paypa1.com,
rnicrosoft.com). People read a domain quickly and see what they expect, so
look-alikes are a staple of phishing.
"""
from __future__ import annotations

from typing import Dict, Optional, Set, Tuple

# A few multi-part endings so "example.co.uk" is treated correctly.
# (A full Public Suffix List is better; see the limitations in the README.)
MULTI_PART_SUFFIXES = {"co.uk", "org.uk", "com.au", "co.jp", "com.br", "co.in", "co.nz", "com.mx"}

# Small, FICTIONAL-SAFE demo list of well-known brands and domains they really use.
BRANDS: Dict[str, Set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "outlook.com", "live.com", "office.com"},
    "google": {"google.com", "gmail.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazonses.com"},
    "apple": {"apple.com", "icloud.com"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "github": {"github.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
}

_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})


def registered_domain(domain: str) -> str:
    labels = domain.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def levenshtein(a: str, b: str) -> int:
    """Number of single-character edits needed to turn a into b."""
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def lookalike_brand(domain: str, brands: Optional[Dict[str, Set[str]]] = None) -> Optional[Tuple[str, str]]:
    """Return (brand, reason) if the domain imitates a brand without belonging to it."""
    brands = brands or BRANDS
    if not domain:
        return None
    reg = registered_domain(domain)
    if any(reg in legit for legit in brands.values()):
        return None  # a genuine brand domain
    sld = reg.split(".")[0]
    norm1 = sld.translate(_HOMOGLYPHS)
    norm2 = norm1.replace("rn", "m").replace("vv", "w")
    labels = domain.lower().split(".")
    subdomains = labels[: len(labels) - len(reg.split("."))]
    for brand in brands:
        if sld == brand:
            return brand, "uses the '%s' name on an unrelated domain/TLD" % brand
        if brand in (norm1, norm2, sld.replace("rn", "m")):
            return brand, "character-substitution look-alike of '%s' (%s)" % (brand, sld)
        if len(brand) >= 5 and levenshtein(sld, brand) <= (2 if len(brand) >= 8 else 1):
            return brand, "typo of '%s' (%s)" % (brand, sld)
        if len(brand) >= 5 and (brand in sld or brand in norm2):
            return brand, "'%s' embedded in unrelated domain '%s'" % (brand, reg)
        if brand in subdomains:
            return brand, "'%s' used as a subdomain of unrelated domain '%s'" % (brand, reg)
    return None

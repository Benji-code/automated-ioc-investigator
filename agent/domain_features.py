"""Offline domain and IP features (task 2.3). No network lookups.

- Registered domain via tldextract's bundled public-suffix snapshot (it is
  told never to fetch a fresh list).
- Shared-infrastructure checks: published CDN/anycast ranges and a list of
  shared ASNs (knowledge.py).
- Provider lists: dynamic DNS, free hosting, tunnelling services.
- Lexical features of the leftmost label. DGA-like is a weak signal only.

Campus popularity and first-seen come from ClickHouse (db.py) and are merged
in by tools.domain_features.
"""
from __future__ import annotations

import ipaddress
import math
from collections import Counter
from functools import lru_cache

from . import knowledge

ECH_PLACEHOLDER = "cloudflare-ech.com"

# DGA-like thresholds (weak signal): a long random-looking label (high
# entropy AND few vowels: long English compounds like "valleywidelocksmiths"
# have high entropy too, but plenty of vowels), or a label that is mostly digits.
DGA_MIN_LENGTH = 12
DGA_MIN_ENTROPY = 3.5
DGA_MAX_VOWEL_RATIO = 0.25
DGA_DIGIT_MIN_LENGTH = 8
DGA_MIN_DIGIT_RATIO = 0.4


@lru_cache(maxsize=1)
def _extractor():
    import tldextract

    # suffix_list_urls=() and cache_dir=None: use the snapshot bundled with
    # the package, never the internet.
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def clean_name(name: str | None) -> str:
    return (name or "").strip().lower().rstrip(".")


def registered_domain(name: str | None) -> str:
    """'a.b.example.com.au' -> 'example.com.au'. Returns the input for IPs
    and names without a known suffix."""
    name = clean_name(name)
    if not name:
        return ""
    parts = _extractor()(name)
    if parts.domain and parts.suffix:
        return f"{parts.domain}.{parts.suffix}"
    return name


def is_ech_placeholder(name: str | None) -> bool:
    """cloudflare-ech.com in the SNI means Encrypted Client Hello hid the real name."""
    return registered_domain(name) == ECH_PLACEHOLDER


def ip_range_match(ip: str | None) -> dict | None:
    """The SHARED_IP_RANGES entry containing this IP, or None."""
    try:
        address = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    for key, entry in knowledge.SHARED_IP_RANGES.items():
        for cidr in entry["cidrs"]:
            if address in ipaddress.ip_network(cidr):
                return {"key": key, **entry, "cidr": cidr}
    return None


def asn_kind(asn) -> dict | None:
    """{'asn', 'org', 'kind'} for a shared-infrastructure ASN, else None."""
    number = str(asn or "").strip().upper().removeprefix("AS")
    entry = knowledge.SHARED_ASNS.get(number)
    if not entry:
        return None
    return {"asn": number, **entry}


def _in_list(domain: str, providers) -> bool:
    return any(domain == p or domain.endswith("." + p) for p in providers)


def provider_category(name: str | None) -> str | None:
    """'dynamic_dns', 'free_hosting', 'tunnel' or None."""
    name = clean_name(name)
    if not name:
        return None
    if _in_list(name, knowledge.DYNAMIC_DNS_DOMAINS):
        return "dynamic_dns"
    if _in_list(name, knowledge.FREE_HOSTING_DOMAINS):
        return "free_hosting"
    if knowledge.match_service(domain=name):
        return "tunnel"
    return None


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def lexical(name: str | None) -> dict:
    """Length, digit ratio and entropy of the leftmost meaningful label
    ('www.' is skipped). dga_like is True only above clear thresholds."""
    labels = [part for part in clean_name(name).split(".") if part]
    if labels and labels[0] == "www":
        labels = labels[1:]
    label = labels[0] if labels else ""
    digits = sum(ch.isdigit() for ch in label)
    ratio = round(digits / len(label), 2) if label else 0.0
    entropy = round(_entropy(label), 2)
    letters = [ch for ch in label if ch.isalpha()]
    vowel_ratio = sum(ch in "aeiouy" for ch in letters) / len(letters) if letters else 0.0
    long_random = (len(label) >= DGA_MIN_LENGTH and entropy >= DGA_MIN_ENTROPY
                   and vowel_ratio < DGA_MAX_VOWEL_RATIO)
    mostly_digits = len(label) >= DGA_DIGIT_MIN_LENGTH and ratio >= DGA_MIN_DIGIT_RATIO
    return {"label": label, "length": len(label), "digit_ratio": ratio, "entropy": entropy,
            "dga_like": bool(long_random or mostly_digits)}


def features(name: str) -> dict:
    """All offline features for one name."""
    return {
        "name": clean_name(name),
        "registered_domain": registered_domain(name),
        "ech_placeholder": is_ech_placeholder(name),
        "provider_category": provider_category(name),
        **{f"lexical_{k}": v for k, v in lexical(name).items()},
    }

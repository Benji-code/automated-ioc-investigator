"""Plain-word forms of the code's labels: verdicts, threat types, host types,
contact patterns, app classes and behaviour categories.

The prompt lists them so the report is written in plain words, the
self-check flags code labels left in the text, and plain_labels() swaps
only these exact labels as a last safety net when a report is shown (HTML,
Markdown, PDF). Nothing else in the report text is rewritten.
"""
from __future__ import annotations

import re

from . import beacon, behaviour, knowledge

VERDICTS = {
    "LIKELY_THREAT": "likely threat",
    "SUSPICIOUS": "suspicious",
    "LIKELY_FALSE_POSITIVE": "likely false positive",
    "INSUFFICIENT_DATA": "insufficient data",
}

THREAT_TYPES = {
    "botnet_cc": "botnet command-and-control",
    "c2": "command-and-control",
    "payload_delivery": "malware distribution",
    "phishing": "phishing",
    "exploit": "exploitation",
    "threat_actor": "threat-actor infrastructure",
    "cc_skimming": "card skimming",
    "unknown": "unknown threat type",
}

CONTACT_PATTERNS = {
    "periodic_checkin": "periodic check-ins",
    "held_open": "held-open connection",
    "human_interactive": "human-driven",
    "bulk_transfer": "bulk transfer",
    "one_off": "one-off contact",
    "irregular": "irregular contact",
    "insufficient_data": "no per-minute contact data",
    # large-flow patterns (analysis.classify_flows)
    "held_open_plus_sessions": "held-open connection plus large sessions",
    "sessions": "large sessions",
    "no_flows": "no large flows",
}

APP_CLASSES = {
    "benign": "ordinary app",
    "vendor": "named vendor app",
    "remote_access": "remote access",
    "privacy_vpn": "privacy VPN",
    "infrastructure": "cloud or CDN infrastructure",
}


def _short(name: str) -> str:
    """'end host (workstation, laptop or personal device)' -> 'end host'."""
    return re.sub(r"\s*\(.*\)\s*$", "", name).strip()


HOST_TYPES = {key: _short(profile["name"]) for key, profile in knowledge.HOST_TYPE_PROFILES.items()}
BEHAVIOURS = {key: label[0].lower() + label[1:] if not label[:2].isupper() else label
              for key, label in behaviour.CATEGORIES.items()}
# Known services by their own names ("cloudflare_tunnel" -> "Cloudflare Tunnel").
SERVICES = {key: _short(profile["name"]) for key, profile in knowledge.SERVICE_PROFILES.items()}

GROUPS = {
    "Verdicts": VERDICTS,
    "Threat types": THREAT_TYPES,
    "Host types": HOST_TYPES,
    "Contact patterns": CONTACT_PATTERNS,
    "App classes": APP_CLASSES,
    "Behaviour": BEHAVIOURS,
    "Known services": SERVICES,
}

# Only labels that cannot be plain English already (an underscore, or all
# capitals) are swapped: "phishing" or "benign" are words in their own right.
PLAIN: dict[str, str] = {}
for _group in GROUPS.values():
    for _key, _plain in _group.items():
        if "_" in _key:
            PLAIN.setdefault(_key, _plain)

_assert_patterns = set(beacon.PATTERNS) - set(CONTACT_PATTERNS)
assert not _assert_patterns, f"beacon patterns without a plain form: {_assert_patterns}"

# Not part of a domain, path or address: no word character, "-", "/" or "@"
# next to it, and no "." joining it to another word (a full stop is fine).
_BEFORE = r"(?<![\w\-/@])(?<!\w\.)"
_AFTER = r"(?![\w\-/@]|\.\w)"
LABEL_RE = re.compile(_BEFORE + "(" + "|".join(re.escape(k) for k in sorted(PLAIN, key=len, reverse=True))
                      + ")" + _AFTER)
CHART_MARKER_RE = re.compile(r"\[\[[^\]]*\]\]")


def plain_labels(text: str | None) -> str:
    """Known code labels in `text` swapped for their plain forms (capitalised
    at the start of a sentence). Chart and flow markers are left alone."""
    if not text:
        return text or ""
    parts = []
    last = 0
    for marker in CHART_MARKER_RE.finditer(text):
        parts.append(_swap(text[last:marker.start()], text[:last]))
        parts.append(marker.group(0))
        last = marker.end()
    parts.append(_swap(text[last:], text[:last]))
    return "".join(parts)


def _swap(text: str, before: str) -> str:
    def replace(match: re.Match) -> str:
        plain = PLAIN[match.group(1)]
        preceding = (before + text[:match.start()]).rstrip(" *_\"'(")
        if not preceding or preceding[-1] in ".!?:\n#-":
            plain = plain[0].upper() + plain[1:]
        return plain
    return LABEL_RE.sub(replace, text)


def prompt_list() -> str:
    """Every label group with its plain forms, for the system prompt."""
    lines = []
    for title, group in GROUPS.items():
        pairs = "; ".join(f"{key} = {plain}" for key, plain in group.items())
        lines.append(f"- {title}: {pairs}.")
    return "\n".join(lines)


CODE_TOKEN_RE = re.compile(_BEFORE + r"(?:[a-z][a-z0-9]*(?:_[a-z0-9]+)+|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)" + _AFTER)
QUOTED_RE = re.compile(r"`[^`\n]*`|\"[^\"\n]*\"|“[^”\n]*”")


def code_tokens(text: str, allowed: set[str] | frozenset[str] = frozenset()) -> list[str]:
    """snake_case and ALL_CAPS_WITH_UNDERSCORE words in prose, outside quotes,
    backticks, chart markers and domains, and not in `allowed` (table names,
    the indicator)."""
    text = QUOTED_RE.sub(" ", CHART_MARKER_RE.sub(" ", text or ""))
    found = []
    for match in CODE_TOKEN_RE.finditer(text):
        token = match.group(0)
        if token not in allowed and token.lower() not in allowed and token not in found:
            found.append(token)
    return found


# --- host type, with its uncertainty -----------------------------------------------------------

CONFIDENT_HOST_TYPE = 0.5


def host_type_name(label: str | None) -> str:
    """'website_server' -> 'web server' (the label itself if it has no profile)."""
    return HOST_TYPES.get(label or "", (label or "unknown type").replace("_", " "))


def host_type_uncertain(kind: dict | None) -> bool:
    """True when the classified type should not be stated as fact: no type,
    confidence under 0.5, or the rule-based reading names another type."""
    kind = kind or {}
    if not kind.get("label"):
        return True
    rule = kind.get("rule_label")
    return float(kind.get("confidence") or 0) < CONFIDENT_HOST_TYPE or bool(rule and rule != kind["label"])


def host_type_text(kind: dict | None) -> str:
    """'web server' when confident, else 'host type unclear: best guess web
    proxy (38%), rules suggest NAT gateway'."""
    kind = kind or {}
    if not kind.get("label"):
        return "host type unclear"
    name = host_type_name(kind["label"])
    if not host_type_uncertain(kind):
        return name
    text = f"host type unclear: best guess {name} ({float(kind.get('confidence') or 0):.0%})"
    rule = kind.get("rule_label")
    if rule and rule != kind["label"]:
        text += f", rules suggest {host_type_name(rule)}"
    return text

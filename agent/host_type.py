"""What kind of host this is, and whether it behaves like one.

assess_host() classifies the case's host from its own traffic over the days
before the match (host_classification: the trained forest if one has been
built, else the transparent rules) and compares its key features with what is
typical for that type: measured per-type profiles if built, else rough priors
from the knowledge base. The model reads the result in the case file and
judges what any unusual behaviour means.

Also the checks on the model's HOST_ROLE reading (moved here from the old
code-written narrative).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import lru_cache

from host_classification import classify, features, profiles

from . import config, knowledge
from .analysis import fmt_bytes, fmt_duration


def _window(identity: dict, days: int) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    last = identity.get("evidence_last_seen")
    try:
        anchor = datetime.fromisoformat(str(last).replace("Z", "+00:00")) if last else now
    except ValueError:
        anchor = now
    anchor = anchor if anchor.tzinfo else anchor.replace(tzinfo=timezone.utc)
    end = min(anchor + timedelta(days=1), now)
    return end - timedelta(days=days), end


@lru_cache(maxsize=1)
def _model(path: str, mtime: float):
    return classify.load(config.HOST_MODEL_PATH)


@lru_cache(maxsize=1)
def _profiles(path: str, mtime: float):
    return profiles.load(config.HOST_PROFILES_PATH)


def _cached(loader, path):
    return loader(str(path), path.stat().st_mtime) if path.exists() else None


def fmt_feature(value, unit: str) -> str:
    value = float(value or 0)
    if unit == "bytes":
        return fmt_bytes(value)
    if unit == "share":
        return f"{value:.0%}"
    if unit == "seconds":
        return fmt_duration(value)
    if unit == "ratio":
        return f"{value:.2f}"
    return f"{value:,.0f}"


def assess_host(host: str, identity: dict, hostname: str | None, days: int | None = None) -> dict:
    """The host's type, how sure that is, and how it compares with its type."""
    days = days or config.HOST_TYPE_WINDOW_DAYS
    start, end = _window(identity, days)
    period = f"{start:%Y-%m-%d %H:%M} to {end:%Y-%m-%d %H:%M} UTC"
    frame = features.extract([host], start, end, hostnames={host: hostname or ""})
    row = frame.iloc[0].to_dict()
    if not (row.get("load_rows") or row.get("long_flows")):
        return {"period": period, "label": None, "note": "no traffic from this host in the window"}

    rule_label, rule_confidence, rule_reason = classify.rule_classify(row)
    bundle = _cached(_model, config.HOST_MODEL_PATH)
    if bundle:
        scored = classify.predict(bundle, frame).iloc[0]
        label, confidence = scored["model_label"], float(scored["model_score"])
        method = f"random forest trained on {bundle.get('seeds', '?')} weakly labelled seed hosts"
        alternatives = scored["model_probabilities"]
    else:
        label, confidence = rule_label, rule_confidence
        method = "rules (no trained model yet: python -m host_classification build)"
        alternatives = {}
    profile = knowledge.host_type_profile(label)
    comparison = profiles.compare(row, label, _cached(_profiles, config.HOST_PROFILES_PATH), profile["priors"])
    values = {column: fmt_feature(row.get(column), unit)
              for column, (_, unit) in profiles.KEY_FEATURES.items() if column in row}
    return {
        "period": period,
        "label": label,
        "name": profile["name"],
        "confidence": round(confidence, 2),
        "method": method,
        "alternatives": alternatives,
        "rule_label": rule_label,
        "rule_reason": rule_reason,
        "hostname_hint": row.get("dns_hint_label") or "",
        "top_ports": list(row.get("client_top_ports") or [])[:6],
        "values": values,
        "comparison": comparison,
        "profile": {k: profile[k] for k in ("typical", "abnormal", "compromise", "ioc_reading")},
    }


def is_server_like(ev: dict) -> bool:
    return ((ev.get("host_type") or {}).get("label") or "") in knowledge.SERVER_HOST_TYPES


# --- checks on the model's HOST_ROLE --------------------------------------------------------

PART_TIME_WORDS = ("laptop", "phone", "mobile", "tablet", "personal device", "handheld")


def role_contradicts_uptime(role: str, uptime: dict, server_like: bool = False) -> bool:
    """A part-time device for a host that is busy around the clock, or a
    server for one that neither looks always-on nor was classified as a
    server (background traffic at night is not evidence of a server)."""
    text = role.lower()
    if uptime.get("always_on") is True:
        return any(word in text for word in PART_TIME_WORDS)
    return "server" in text and not server_like


# Role words and the evidence each needs: (words, activity hints, app categories).
ROLE_EVIDENCE = (
    (("gaming", "game"), ("gaming",), ("Gameplay", "Gaming Download")),
    (("develop",), ("software development",), ()),
    (("media", "stream"), ("self-hosted media", "streaming or social media"), ("Video", "Music", "Live Video")),
    (("home lab", "homelab", "self-host"), ("home lab or self-hosted services",), ()),
    # Who uses it: a student's (personal) device needs signs of personal use or study.
    (("student", "personal"), knowledge.USER_EVIDENCE["student"],
     ("Video", "Music", "Live Video", "Gameplay", "Gaming Download", "Social Media")),
    (("staff",), knowledge.USER_EVIDENCE["staff"], ()),
)
# Roles no evidence in this data can support.
UNSUPPORTED_ROLE_WORDS = ("research", "experiment", "iot", "camera", "printer", "smart tv", "kiosk")


def role_unsupported(role: str, ev: dict) -> bool:
    """True if the role names something the evidence does not show: each role
    word needs matching activity hints or app categories, or the role must name
    a site the host used (the hint lists are short)."""
    text = role.lower()
    if any(site in text for site in host_sites(ev)):
        return any(w in text for w in UNSUPPORTED_ROLE_WORDS)
    other = ev.get("other_traffic", {}) or {}
    hints = set((other.get("activity_hints") or {}).keys())
    categories = {c["category"] for c in (ev.get("host_apps") or {}).get("categories", [])}
    for words, needed_hints, needed_categories in ROLE_EVIDENCE:
        if any(w in text for w in words) and not (hints & set(needed_hints) or categories & set(needed_categories)):
            return True
    return any(w in text for w in UNSUPPORTED_ROLE_WORDS)


# Where-is-it words: the data never says which network a host is on, so a role
# may only use one if the host's own name contains it.
LOCATION_WORDS = ("residential", "residence", "dorm", "college", "office", "lab",
                  "library", "campus", "wifi", "wireless", "guest")


def role_guesses_location(role: str, hostname: str | None) -> bool:
    text = role.lower()
    name = (hostname or "").lower()
    return any(word in text and word not in name for word in LOCATION_WORDS)


USER_TYPES = ("student", "staff", "unclear")


def user_type(text: str) -> str:
    """The LIKELY_USER reading's first word: student, staff or unclear."""
    first = (text or "").strip().lower().split(" ", 1)[0].strip(".,:;-*")
    return first if first in USER_TYPES else ""


def usage_kinds(ev: dict) -> set[str]:
    other = ev.get("other_traffic") or {}
    profile = {c["category"] for c in (other.get("activity_profile") or {}).get("categories") or []}
    return profile | set((other.get("activity_hints") or {}).keys())


def host_sites(ev: dict) -> set[str]:
    """Root domains the host itself used, from its traffic summary."""
    other = ev.get("other_traffic") or {}
    profile = other.get("activity_profile") or {}
    sites = {site["domain"] for c in profile.get("categories") or [] for site in c["sites"]}
    sites |= {site["domain"] for site in profile.get("unlisted") or []}
    sites |= set(other.get("domains_by_active_minutes") or [])
    sites |= {d["root_domain"] for d in other.get("top_destinations_by_bytes") or []}
    return {s.lower() for s in sites if s and not s.startswith("(")}


def user_problem(text: str, ev: dict) -> bool:
    """True if a student or staff reading has nothing behind it: neither a
    listed kind of use (knowledge.USER_EVIDENCE) nor a site the host used named
    in the reason (the lists are short; the model judges other sites by name).
    "unclear" always stands."""
    kind = user_type(text)
    if not kind:
        return True
    if kind == "unclear":
        return False
    if usage_kinds(ev) & set(knowledge.USER_EVIDENCE[kind]):
        return False
    lowered = text.lower()
    return not any(site in lowered for site in host_sites(ev))


def role_problem(role: str, ev: dict) -> bool:
    """True if the HOST_ROLE reading is not backed by the evidence."""
    uptime = (ev.get("other_traffic") or {}).get("uptime") or {}
    hostname = (ev.get("host") or {}).get("hostname")
    return (role_contradicts_uptime(role, uptime, is_server_like(ev)) or role_guesses_location(role, hostname)
            or role_unsupported(role, ev))

"""Deterministic evidence signals and the baseline verdict (task 2, 1.4).

Each signal reads the gathered evidence and says which way it points:
  supports_threat  the host looks like a victim of this threat
  against_threat   the evidence has a benign explanation
  neutral          nothing either way, or no data

Threat-side signals also carry a strength. "strong" is direct evidence
(a bad name, regular check-ins, the abuse pattern of a known service, peers
flagged for the same family); "weak" is circumstantial (a rare or new domain,
a platform hint, a port that fits). ThreatFox confidence is deliberately not
a signal: it rates the indicator, not this host.

The model sees the signals and the baseline, and may disagree only by naming
the signal it overrides and why (assess.py enforces that).
"""
from __future__ import annotations

from . import config, domain_features as dfeat

SUPPORTS = "supports_threat"
AGAINST = "against_threat"
NEUTRAL = "neutral"

WEB_PORTS = {80, 443}
DOWNLOAD_MIN_BYTES = 500_000     # payload_delivery: a download of at least this size ...
DOWNLOAD_MIN_RATIO = 5.0         # ... and this many times more down than up
TINY_TRANSFER_BYTES = 50_000     # payload_delivery: less than this in total is a page load, not a payload
ONE_OFF_MAX_MINUTES = 10         # this few active minutes on one day is a one-off contact

VERDICTS = ("LIKELY_THREAT", "SUSPICIOUS", "LIKELY_FALSE_POSITIVE", "INSUFFICIENT_DATA")


def _signal(name: str, value: str, direction: str, reason: str, strength: str | None = None) -> dict:
    return {"name": name, "value": value, "direction": direction,
            "strength": strength if direction == SUPPORTS else None, "reason": reason}


# --- helpers over the evidence -------------------------------------------------

def _ports(flows: dict) -> list[tuple[int, str]]:
    ports = {(p["port"], p["protocol"]) for p in flows.get("ports", [])}
    ports |= {(p["port"], p["protocol"]) for p in flows.get("activity", {}).get("ports", [])}
    return sorted(ports)


def _visible_names(names: dict) -> list[dict]:
    return [n for n in names.get("names", []) if not n["ech_hidden"] and n["name"] != "(no name)"]


def _service_fits(expected: dict) -> bool | None:
    """True if a service matched and every port fits its own client; False
    if some port does not fit; None if no service matched or no ports."""
    fit = expected.get("service_port_fit") or []
    if not expected.get("service") or not fit:
        return None
    return all(f["fits"] for f in fit)


def _active_days(flows: dict) -> set[str]:
    days = set(flows.get("activity", {}).get("active_dates", []))
    for period in flows.get("active_periods", []):
        days.add(period["start"][:10])
        days.add(period["end"][:10])
    return days


def _total_bytes(flows: dict) -> tuple[int, int]:
    """(up, down) from long_flow_summary if present, else subscriber_activity_1m.
    The tables overlap, so they are never added together."""
    ports = flows.get("ports", [])
    if ports:
        return sum(p["up_bytes"] for p in ports), sum(p["down_bytes"] for p in ports)
    activity = flows.get("activity", {})
    return int(activity.get("up_bytes", 0) or 0), int(activity.get("down_bytes", 0) or 0)


# --- the signals -----------------------------------------------------------------

def shared_infrastructure(ev: dict) -> dict:
    against: list[str] = []
    for info in ev.get("asn", []):
        shared_range = info.get("shared_range")
        shared_asn = info.get("shared_asn")
        if shared_range:
            against.append(f"{info['server_ip']} is in {shared_range['name']} ({shared_range['cidr']})")
        elif shared_asn and shared_asn["kind"] in ("cdn", "cloud"):
            against.append(f"{info['server_ip']} is AS{shared_asn['asn']} {shared_asn['org']} ({shared_asn['kind']})")
    peer_hosts = max((p["distinct_host_count"] for p in ev.get("peers", []) if "error" not in p), default=0)
    if peer_hosts >= config.SHARED_PEER_HOSTS:
        against.append(f"{peer_hosts} campus hosts contacted it (long_flow_summary)")
    domains = 0
    for pdns in ev.get("passive_dns", []):
        if "error" in pdns:
            continue
        domains = max(domains, pdns["distinct_root_domains"])
        if (pdns.get("campus_hosts") or 0) >= config.SHARED_PEER_HOSTS:
            against.append(f"{pdns['campus_hosts']} campus hosts used it recently (subscriber_activity_1m)")
    if domains >= config.SHARED_PASSIVE_DNS_DOMAINS:
        against.append(f"{domains} unrelated root domains resolve to it")
    service = ev.get("expected", {}).get("service")
    if service:
        against.append(f"known public service {service['profile']['name']}")
    if against:
        return _signal("shared_infrastructure", "yes", AGAINST,
                       "Shared by many unrelated users: " + "; ".join(against) + ".")

    known_pdns = [p for p in ev.get("passive_dns", []) if "error" not in p and p["distinct_root_domains"]]
    hosting = any((i.get("shared_asn") or {}).get("kind") == "hosting" for i in ev.get("asn", []))
    if known_pdns and domains <= 1 and not hosting:
        return _signal("shared_infrastructure", "no", SUPPORTS,
                       "Only one domain seen on this IP and it is not a known shared ASN: looks dedicated.", "weak")
    return _signal("shared_infrastructure", "unknown", NEUTRAL,
                   "Not enough to say whether the IP is shared (hosting ASN or no passive DNS).")


def _bad_name_reasons(ev: dict) -> tuple[list[str], list[str]]:
    """(strong, weak) reasons from the domain features of the names the host used."""
    strong: list[str] = []
    weak: list[str] = []
    for f in ev.get("domain_features", []):
        domain = f["registered_domain"]
        others = f.get("other_campus_hosts")
        rare = others is not None and others <= config.RARE_DOMAIN_MAX_OTHER_HOSTS
        if f.get("flagged_in_feed"):
            strong.append(f"{domain} is itself an indicator in the feed")
        if f.get("provider_category") == "dynamic_dns":
            strong.append(f"{domain} is a dynamic-DNS provider")
        if rare and f.get("lexical_dga_like"):
            strong.append(f"{domain} is rare on campus and DGA-like")
        elif rare and f.get("new_on_campus"):
            # "New" is only the first visit within retention; for a domain one
            # person visits that is just when they visited, so it stays weak.
            weak.append(f"{domain} is rare and new on campus")
        elif rare:
            weak.append(f"{domain} is rare on campus (no other host used it, {f.get('campus_period', '')})")
        elif f.get("lexical_dga_like"):
            weak.append(f"{domain} looks DGA-like")
        elif f.get("new_on_campus"):
            weak.append(f"{domain} is new on campus")
        if f.get("provider_category") == "free_hosting":
            weak.append(f"{domain} is on free hosting")
    return strong, weak


def sni_matches_indicator(ev: dict) -> dict:
    identity = ev["identity"]
    names = _visible_names(ev.get("names", {}))
    listed = ", ".join(n["name"] for n in names[:5])
    if identity.get("indicator_type") == "domain":
        indicator = dfeat.registered_domain(identity["indicator"])
        matched = [n["name"] for n in names if n["registered_domain"] == indicator]
        if not matched:
            return _signal("sni_matches_indicator", "no name seen", NEUTRAL,
                           "No SNI/DNS name for the indicator in the host's traffic to this IP.")
        if _service_fits(ev.get("expected", {})):
            return _signal("sni_matches_indicator", matched[0], NEUTRAL,
                           "The host used the indicator's name, but only as the known service's own client.")
        return _signal("sni_matches_indicator", matched[0], SUPPORTS,
                       f"The host's traffic names the flagged domain ({matched[0]}).", "strong")

    strong, weak = _bad_name_reasons(ev)
    if strong:
        return _signal("sni_matches_indicator", listed, SUPPORTS, "; ".join(strong) + ".", "strong")
    if weak:
        return _signal("sni_matches_indicator", listed, SUPPORTS, "; ".join(weak) + ".", "weak")
    if names:
        return _signal("sni_matches_indicator", listed, AGAINST,
                       "The names the host used on this IP are ordinary sites, none flagged, dynamic-DNS or rare.")
    hidden = ev.get("names", {}).get("ech_hidden_minutes", 0)
    reason = ("The SNI was hidden by Encrypted Client Hello." if hidden
              else "No SNI or DNS name was recorded for this traffic.")
    return _signal("sni_matches_indicator", "hidden" if hidden else "none", NEUTRAL, reason)


def protocol_fit(ev: dict) -> dict:
    malware = ev.get("expected", {}).get("malware_profile", {})
    ports = _ports(ev.get("flows", {}))
    if not ports:
        return _signal("protocol_fit", "no ports", NEUTRAL, "No traffic to compare.")
    port_text = ", ".join(f"{p}/{proto}" for p, proto in ports)
    if _service_fits(ev.get("expected", {})):
        return _signal("protocol_fit", port_text, NEUTRAL, "Ports are explained by the known service's own client.")
    if malware.get("transport") != "custom_tcp":
        return _signal("protocol_fit", port_text, NEUTRAL, "No protocol profile to compare for this family.")
    non_web_tcp = [p for p, proto in ports if proto == "tcp" and p not in WEB_PORTS]
    if non_web_tcp:
        return _signal("protocol_fit", port_text, SUPPORTS,
                       f"{malware.get('family')} uses its own protocol over TCP; TCP to non-web port(s) "
                       f"{', '.join(map(str, non_web_tcp))} fits that.", "weak")
    quic = [p for p, proto in ports if proto == "udp" and p == 443]
    has_sni = bool(_visible_names(ev.get("names", {}))) or ev.get("names", {}).get("ech_hidden_minutes", 0) > 0
    if quic or has_sni:
        what = "UDP/443 is QUIC (browser/app HTTPS)" if quic else "TLS to a named website is normal HTTPS"
        return _signal("protocol_fit", port_text, AGAINST,
                       f"{what}; {malware.get('family')} uses its own protocol over plain TCP.")
    return _signal("protocol_fit", port_text, NEUTRAL, "Web port without a visible name: could be either.")


def traffic_shape_fit(ev: dict) -> dict:
    flows = ev.get("flows", {})
    threat_type = (ev["identity"].get("threat_type") or "").lower()
    classification = flows.get("classification", {})
    up, down = _total_bytes(flows)
    minutes = flows.get("activity", {}).get("active_minutes", 0)
    if threat_type in ("botnet_cc", "c2"):
        if classification.get("beacon_like"):
            return _signal("traffic_shape_fit", classification["pattern"], SUPPORTS,
                           "Repeated short check-ins at a regular interval: the botnet_cc shape.", "strong")
        if _service_fits(ev.get("expected", {})):
            return _signal("traffic_shape_fit", classification.get("pattern", "?"), NEUTRAL,
                           "Shape is the known service's normal client traffic.")
        if flows.get("long_flow_count", 0) <= 3 and minutes <= ONE_OFF_MAX_MINUTES:
            return _signal("traffic_shape_fit", f"{flows.get('long_flow_count', 0)} long flow(s), {minutes} active min",
                           AGAINST, "A few short sessions, not repeated check-ins or a persistent C2 connection.")
        return _signal("traffic_shape_fit", classification.get("pattern", "?"), NEUTRAL,
                       "Shape neither matches nor rules out the botnet_cc profile.")
    if threat_type == "payload_delivery":
        if down >= DOWNLOAD_MIN_BYTES and down >= DOWNLOAD_MIN_RATIO * max(up, 1):
            return _signal("traffic_shape_fit", f"down {down} B / up {up} B", SUPPORTS,
                           "A download-heavy transfer big enough to be a payload.", "weak")
        if up + down < TINY_TRANSFER_BYTES:
            return _signal("traffic_shape_fit", f"{up + down} B total", AGAINST,
                           "A tiny transfer, typical of a page or asset load, not a payload.")
    return _signal("traffic_shape_fit", classification.get("pattern", "?"), NEUTRAL, "No clear fit either way.")


def recurrence(ev: dict) -> dict:
    flows = ev.get("flows", {})
    classification = flows.get("classification", {})
    days = _active_days(flows)
    if classification.get("beacon_like") and len(days) >= 2:
        return _signal("recurrence", f"{len(days)} day(s), regular", SUPPORTS,
                       "Regular periodic contact across several days.", "weak")
    if classification.get("held_open"):
        return _signal("recurrence", f"{len(days)} day(s), held open", NEUTRAL,
                       "A held-open connection: presence across days is not a beacon.")
    if len(days) <= 1:
        return _signal("recurrence", f"{len(days)} day(s)", AGAINST, "A one-off contact on a single day.")
    return _signal("recurrence", f"{len(days)} day(s), irregular", AGAINST,
                   "Irregular contact on several days, like human use rather than a timer.")


def platform_fit(ev: dict) -> dict:
    target = ev.get("expected", {}).get("malware_profile", {}).get("platform")
    hints = ev.get("other_traffic", {}).get("platform_hints") or {}
    if not target:
        return _signal("platform_fit", "n/a", NEUTRAL, "No target platform on file for this family.")
    if not hints:
        return _signal("platform_fit", "no hints", NEUTRAL, "No operating-system hints in the host's other traffic.")
    seen = ", ".join(f"{k}: {', '.join(v[:2])}" for k, v in hints.items())
    if target in hints:
        return _signal("platform_fit", seen, SUPPORTS,
                       f"The host shows {target} signs, which the family targets.", "weak")
    return _signal("platform_fit", seen, AGAINST,
                   f"The host shows only {', '.join(hints)} signs; the family targets {target}.")


def campus_spread(ev: dict) -> dict:
    peers = [p for p in ev.get("peers", []) if "error" not in p]
    same_family = 0
    other_family = 0
    for p in peers:
        for host in p.get("hosts", []):
            for flag in host.get("also_flagged", []):
                if flag["same_malware_family"]:
                    same_family += 1
                else:
                    other_family += 1
    if same_family:
        return _signal("campus_spread", f"{same_family} peer flag(s), same family", SUPPORTS,
                       "Other hosts on this IP are independently flagged for the same malware family.", "strong")
    hosts = max((p["distinct_host_count"] for p in peers), default=0)
    if hosts >= config.SHARED_PEER_HOSTS:
        return _signal("campus_spread", f"{hosts} hosts", AGAINST,
                       "Many campus hosts use this IP and none are independently flagged for this family.")
    if other_family:
        return _signal("campus_spread", f"{other_family} peer flag(s), other families", SUPPORTS,
                       "Some peers are flagged by unrelated indicators.", "weak")
    return _signal("campus_spread", f"{hosts} host(s)", NEUTRAL, "Few campus hosts and none independently flagged.")


def known_service(ev: dict) -> dict:
    expected = ev.get("expected", {})
    service = expected.get("service")
    fits = _service_fits(expected)
    if not service:
        return _signal("known_service", "none", NEUTRAL, "No known service profile matched.")
    name = service["profile"]["name"]
    if fits:
        return _signal("known_service", name, AGAINST,
                       f"Only {name}'s own client ports are used: the host runs the client itself.")
    if fits is False:
        return _signal("known_service", name, SUPPORTS,
                       f"Ports other than {name}'s client ports are used: the abuse pattern (e.g. a tunnel's "
                       "public port).", "strong")
    return _signal("known_service", name, NEUTRAL, f"{name} matched but no ports were observed.")


SIGNAL_FUNCTIONS = (shared_infrastructure, sni_matches_indicator, protocol_fit, traffic_shape_fit,
                    recurrence, platform_fit, campus_spread, known_service)
SIGNAL_NAMES = tuple(f.__name__ for f in SIGNAL_FUNCTIONS)


def compute_signals(ev: dict) -> list[dict]:
    return [fn(ev) for fn in SIGNAL_FUNCTIONS]


def has_evidence(ev: dict) -> bool:
    """Traffic between the host and the flagged IP, live or from the feed."""
    flows = ev.get("flows", {})
    return bool(flows.get("has_traffic")) and "error" not in flows


def baseline_verdict(signals: list[dict], evidence_found: bool) -> dict:
    """The documented rules, in order. The first that applies wins.

    1. No traffic (live or feed)                          -> INSUFFICIENT_DATA
    2. 2+ strong threat signals, or 1 strong + 2 weak     -> LIKELY_THREAT
    3. 1 strong threat signal                             -> SUSPICIOUS
    4. Shared infrastructure or a known service's normal
       client, at most 2 weak threat signals              -> LIKELY_FALSE_POSITIVE
       (a rare small site plus a Windows host is normal
       browsing on a CDN, not a reason to escalate)
    5. 2+ weak threat signals                             -> SUSPICIOUS
    6. Some signal against, none for                      -> LIKELY_FALSE_POSITIVE (low confidence)
    7. Nothing either way                                 -> SUSPICIOUS (low confidence): can't be cleared
    """
    strong = [s["name"] for s in signals if s["direction"] == SUPPORTS and s["strength"] == "strong"]
    weak = [s["name"] for s in signals if s["direction"] == SUPPORTS and s["strength"] == "weak"]
    against = [s["name"] for s in signals if s["direction"] == AGAINST]
    benign_anchor = [n for n in against if n in ("shared_infrastructure", "known_service")]

    if not evidence_found:
        return _verdict("INSUFFICIENT_DATA", "high", 1, "No traffic to the flagged IP, live or in the feed.")
    if len(strong) >= 2 or (strong and len(weak) >= 2):
        return _verdict("LIKELY_THREAT", "medium", 2, f"Threat signals: {', '.join(strong + weak)}.")
    if strong:
        return _verdict("SUSPICIOUS", "medium", 3, f"One strong threat signal: {strong[0]}.")
    if benign_anchor and len(weak) <= 2:
        confidence = _false_positive_confidence(signals, against)
        return _verdict("LIKELY_FALSE_POSITIVE", confidence, 4,
                        f"{' and '.join(benign_anchor)} against threat; no strong threat signal"
                        + (f" (weak only: {', '.join(weak)})." if weak else "."))
    if len(weak) >= 2:
        return _verdict("SUSPICIOUS", "low", 5, f"Several weak threat signals: {', '.join(weak)}.")
    if against and not weak:
        return _verdict("LIKELY_FALSE_POSITIVE", "low", 6, f"Only signals against threat: {', '.join(against)}.")
    return _verdict("SUSPICIOUS", "low", 7, "Nothing clearly for or against: cannot be cleared on this evidence.")


def _false_positive_confidence(signals: list[dict], against: list[str]) -> str:
    """High only when the benign explanation is positively identified: a
    shared address, the host used a NAMED site there that is not flagged,
    dynamic DNS or DGA-like (a small or rare site still counts: rarity alone
    is a weak signal), and at least three signals against a threat. A known
    service's client stays medium: its use may be benign, but what it
    exposes is unknown. A hidden (ECH) or missing name stays medium."""
    sni = next((s for s in signals if s["name"] == "sni_matches_indicator"), {})
    named_site = sni.get("direction") == AGAINST or (sni.get("direction") == SUPPORTS and sni.get("strength") == "weak")
    if ("shared_infrastructure" in against and named_site and "known_service" not in against
            and len(against) >= 3):
        return "high"
    return "medium"


def _verdict(verdict: str, confidence: str, rule: int, reason: str) -> dict:
    return {"verdict": verdict, "confidence": confidence, "rule": rule, "reason": reason}

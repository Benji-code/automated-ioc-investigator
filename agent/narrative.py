"""The report's three paragraphs, written in code from the evidence:

  summary              who, what, when, what the match would normally mean,
                       what the flow data shows, the verdict, the baseline
                       check, and any risk that remains
  behaviour analysis   the workflow steps in order: which name the host used
                       on the flagged IP, the flows, the comparison with a
                       real victim, the host's other traffic, other hosts
  conclusion           verdict and confidence, remaining risk, limits of
                       the data, next steps

Written in code so every number is from the evidence and the risk wording is
never dropped. The wording is generic: it comes from the behaviour category
and the knowledge base's profiles, not from any one service or indicator.
"""
from __future__ import annotations

from datetime import date, datetime

from . import config, correlation, knowledge, signals
from .analysis import fmt_bytes, fmt_duration

MAX_NAMES = 3
MAX_PERIODS = 4

VERDICT_PHRASE = {
    "LIKELY_FALSE_POSITIVE": "a likely false positive",
    "SUSPICIOUS": "suspicious, needing a manual review",
    "LIKELY_THREAT": "a likely real infection",
    "INSUFFICIENT_DATA": "impossible to judge from the available data",
}


# --- small formatting helpers ----------------------------------------------------

def _day(value) -> date | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")[:19].replace("T", " ")).date()
    except ValueError:
        return None


def _fmt_day(d: date, year: bool = True) -> str:
    return f"{d.day} {d:%b}" + (f" {d.year}" if year else "")


def _span(start, end) -> str:
    """'on 5 Aug 2026', 'from 18 Jul to 19 Sep 2026'."""
    a, b = _day(start), _day(end)
    if not a or not b:
        return "at an unknown time"
    if a == b:
        return f"on {_fmt_day(a)}"
    return f"from {_fmt_day(a, year=a.year != b.year)} to {_fmt_day(b)}"


def _short_span(start, end) -> str:
    """'18 Jul to 9 Aug', '5 Aug' (no year, for lists of periods)."""
    a, b = _day(start), _day(end)
    if not a or not b:
        return "?"
    if a == b:
        return _fmt_day(a, year=False)
    return f"{_fmt_day(a, year=False)} to {_fmt_day(b, year=False)}"


def _join(items: list[str]) -> str:
    items = [i for i in items if i]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _a(phrase: str) -> str:
    """'a Windows RAT', 'an unknown_loader'."""
    return ("an " if phrase[:1].lower() in "aeiou" else "a ") + phrase


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _sentence(text: str) -> str:
    text = text.strip()
    return text if not text or text.endswith((".", "!", "?")) else text + "."


def _lower_first(text: str) -> str:
    """Lower-case the first letter for use mid-sentence, but leave acronyms
    and codes ("STEP 7b", "QUIC") alone."""
    if not text or (len(text) > 1 and text[1].isupper()):
        return text
    return text[:1].lower() + text[1:]


def _ports_text(ports: list[tuple[int, str]]) -> str:
    return _join([f"{p}/{proto.upper()}" for p, proto in ports])


def _service_short(service: dict) -> str:
    return service["profile"]["name"].split(" (")[0]


# --- facts pulled from the evidence -------------------------------------------------

def _family(ev: dict) -> str:
    family = ev.get("expected", {}).get("malware_profile", {}).get("family", "")
    if not family or family.startswith("unknown"):
        return ev["identity"].get("malware") or "the listed malware"
    return family


def _threat(ev: dict) -> dict:
    return ev.get("expected", {}).get("threat_type_profile", {}) or knowledge.DEFAULT_THREAT_TYPE_PROFILE


def _first_ip(ev: dict) -> dict:
    return (ev.get("asn") or [{}])[0]


def _ip_detail(info: dict) -> str:
    parts = []
    if info.get("asn"):
        parts.append(f"AS{info['asn']} {info.get('asn_org', '')}".strip())
    shared = info.get("shared_range")
    if shared:
        parts.append(f"part of {shared['name'].split(' (')[0]}")
    return ", ".join(parts)


def _host_phrase(ev: dict) -> str:
    host = ev.get("host") or {}
    ip = ev["identity"]["affected_asset"]
    return f"{config.HOST_LABEL} {ip}" + (f" ({host['hostname']})" if host.get("hostname") else "")


def _indicator_phrase(ev: dict) -> str:
    identity = ev["identity"]
    info = _first_ip(ev)
    detail = _ip_detail(info)
    ip = info.get("server_ip")
    if identity.get("indicator_type") == "domain":
        extra = [ip] if ip else []
        if detail:
            extra.append(detail)
        more = len(ev.get("server_ips", {}).get("ips", [])) - 1
        if more > 0:
            extra.append(f"and {_plural(more, 'other IP')}")
        return identity["indicator"] + (f" ({', '.join(extra)})" if extra else "")
    port = ev.get("server_ips", {}).get("indicator_port")
    return f"{ip} on port {port}" + (f" ({detail})" if detail else "") if ip else identity["indicator"]


def _ioc_ref(ev: dict) -> str:
    metadata = ev["identity"].get("ioc_metadata") or {}
    ioc_id = metadata.get("threatfox_ioc_id") or metadata.get("ioc_id")
    return f" (ThreatFox IOC {ioc_id})" if ioc_id else ""


def _period(ev: dict) -> tuple:
    flows = ev.get("flows", {})
    periods = flows.get("active_periods") or []
    if periods:
        return periods[0]["start"], periods[-1]["end"]
    activity = flows.get("activity", {})
    if activity.get("first_minute"):
        return activity["first_minute"], activity["last_minute"]
    return ev["identity"].get("evidence_first_seen"), ev["identity"].get("evidence_last_seen")


def _visible_names(ev: dict) -> list[str]:
    """Names the host used, dropping a parent domain when a fuller name
    under it is also listed (cdn.example.com covers example.com)."""
    names = [n["name"] for n in ev.get("names", {}).get("names", [])
             if not n["ech_hidden"] and n["name"] != "(no name)"]
    return [n for n in names if not any(other != n and other.endswith("." + n) for other in names)]


def _names_source(ev: dict) -> str:
    source = ev.get("names", {}).get("source")
    if source == "feed":
        return "from the IOC feed's own records, as the live per-minute data has expired"
    if source == "long_flows":
        return "from long_flow_summary, flows over 1 MB, as the per-minute data has expired"
    if source == "long_flows+feed":
        return "from long_flow_summary and the IOC feed's own records, as the per-minute data has expired"
    return "SNI/DNS in subscriber_activity_1m"


def _provider(ev: dict) -> str:
    info = _first_ip(ev)
    if info.get("shared_range"):
        return info["shared_range"]["name"].split(" (")[0]
    if info.get("shared_asn"):
        return info["shared_asn"]["org"]
    return info.get("asn_org") or "cloud"


def _other_services(ev: dict) -> list[dict]:
    """Tunnel/remote-access services in the host's other traffic, besides the matched one."""
    matched = (ev.get("expected", {}).get("service") or {}).get("key")
    other = ev.get("other_traffic", {})
    if "error" in other:
        return []
    return [s for s in other.get("service_matches", []) if s["service"] != matched]


def _service_volume(ev: dict, key: str) -> str:
    profile = knowledge.SERVICE_PROFILES.get(key, {"name": key})
    name = profile["name"].split(" (")[0]
    flows = [f for f in ev.get("other_traffic", {}).get("long_lived_flows", []) if f.get("service") == key]
    if not flows:
        return name
    count = sum(f["flows"] for f in flows)
    up = sum(f["up_bytes"] for f in flows)
    down = sum(f["down_bytes"] for f in flows)
    ports = _join(sorted({f"{f['port']}/{f['protocol'].upper()}" for f in flows}))
    return f"{name} ({_plural(count, 'long-lived flow')} on {ports}, {fmt_bytes(up)} out versus {fmt_bytes(down)} in)"


def _signal(ev: dict, name: str) -> dict:
    return next((s for s in ev.get("signals", []) if s["name"] == name), {})


# --- summary ---------------------------------------------------------------------------

def _finding(ev: dict, category: str) -> str:
    """One sentence: what the flow data shows, by behaviour category."""
    expected = ev.get("expected", {})
    service = expected.get("service")
    flows = ev.get("flows", {})
    activity = flows.get("activity", {})
    ports = signals._ports(flows)
    if category in ("tunnel_client", "remote_access_client"):
        roles = sorted({knowledge.expected_service_port(service["key"], p, proto)["role"].split(" (")[0]
                        for p, proto in ports if knowledge.expected_service_port(service["key"], p, proto)})
        return (f"The flow data instead shows the host running its own {_service_short(service)} client: all "
                f"of its traffic to the IP used the client's own {_join(roles)} port ({_ports_text(ports)}), "
                "which is how the service normally works, not how a victim of C2 hidden behind it would connect.")
    if category == "tunnel_public_port":
        other = [(f["port"], f["protocol"]) for f in expected.get("service_port_fit", []) if not f["fits"]]
        return (f"The flow data shows connections to {_service_short(service)} on {_ports_text(other)}, which are "
                "not the client's own ports: that is how something hosted behind the service, such as a C2 "
                "server behind a tunnel, would be reached.")
    if category in ("beaconing", "periodic_explained"):
        f = (ev.get("contact") or {}).get("features", {})
        text = (f"The per-minute data shows {f.get('bursts', 'many')} small contacts at a regular interval of about "
                f"{fmt_duration((f.get('median_gap_min') or 0) * 60)}, day and night")
        if category == "beaconing":
            return text + ", the pattern of an infected host checking in, with no app or service to explain it."
        reason = _signal(ev, "contact_pattern").get("explained_by", "a recognised app")
        return text + f", explained by {reason}."
    if category == "persistent_connection":
        return (f"The flow data shows long-lived connections on {_ports_text(ports)}, which is not a service the "
                "knowledge base recognises.")
    up, down = signals._total_bytes(flows)
    if category == "download":
        return f"The flow data shows a download of {fmt_bytes(down)} from the site ({fmt_bytes(up)} sent)."
    if category == "web_visit_flagged":
        name = (_visible_names(ev) or [ev["identity"]["indicator"]])[0]
        minutes = activity.get("active_minutes") or 0
        return (f"The flow data shows a brief web visit to {name}: {_plural(minutes, 'active minute')} over "
                f"{_ports_text(ports)}, {fmt_bytes(up)} sent and {fmt_bytes(down)} received.")
    if category == "web_shared":
        names = _visible_names(ev)[:MAX_NAMES]
        if names:
            site = f"the host visited {_join(names)} there"
        elif ev.get("names", {}).get("ech_hidden_minutes"):
            site = "the name of the site it visited was hidden by Encrypted Client Hello"
        else:
            site = "no site name was recorded"
        return (f"The flow data shows ordinary web traffic ({_ports_text(ports)}) to {shared_address_phrase(ev)}, "
                f"and {site}.")
    if category == "web":
        return f"The flow data shows web traffic ({_ports_text(ports)}) to the IP."
    if category == "no_traffic":
        return ("No traffic between the host and the IP was found in the live flow data or in the feed's own "
                "records, so the match cannot be checked.")
    return f"The flow data shows traffic on {_ports_text(ports) or 'unknown ports'}."


def risk_note(ev: dict, category: str) -> str:
    """The risk that remains even when the traffic is not malware."""
    service = ev.get("expected", {}).get("service")
    if category == "tunnel_client":
        return (f"Even if the use is benign, the {_service_short(service)} tunnel lets outside parties reach a "
                "service on this host past the campus firewall, and the flow data cannot show what that service "
                "is or who uses it.")
    if category == "remote_access_client":
        return (f"Even if the use is benign, {_service_short(service)} gives remote access into the campus network "
                "from outside, and the flow data cannot show who uses it.")
    if category == "tunnel_public_port":
        return "What the host reached behind the tunnel is unknown from flow data."
    if category == "persistent_connection":
        return ("What the connection carries, and whether it gives outside access to the host, is unknown from "
                "flow data.")
    if category in ("web_visit_flagged", "download"):
        return "Flow data cannot show whether anything from the site was run on the host."
    return ""


def _baseline_clause(result: dict) -> str:
    baseline = result.get("baseline_verdict")
    model = result.get("model_verdict")
    final = result.get("VERDICT")
    if final == "INSUFFICIENT_DATA" or not baseline:
        return ""
    if model and model != baseline:
        return (f", from the rule-based checks; the agent's independent review, which did not see that result, "
                f"judged it {VERDICT_PHRASE.get(model, model)} instead, so this needs a human check")
    return ", from the rule-based checks, and the agent's independent review, which did not see that result, agrees"


def disagreement_note(result: dict) -> str:
    """When the blind review disagrees, its reasoning goes in the report for
    the human who has to settle it (unless it quotes invented numbers)."""
    model = result.get("model_verdict")
    if not model or model == result.get("baseline_verdict") or result.get("VERDICT") == "INSUFFICIENT_DATA":
        return ""
    judgement = (result.get("KEY_JUDGEMENT") or "").strip()
    if not judgement or result.get("unverified_numbers"):
        return f"The agent's independent review judged this {VERDICT_PHRASE.get(model, model)}."
    return f"The agent's independent review judged this {VERDICT_PHRASE.get(model, model)}: {_sentence(judgement)}"


UPLOAD_NOTABLE_BYTES = 1_000_000  # more than this sent, and more sent than received, counts as uploading


def substantial_contact(ev: dict) -> str | None:
    """Why the host's own traffic to the flagged IP is more than a single
    browsing visit: repeated contact, non-web traffic or uploads. None for
    one short visit, which a linked domain alone does not make suspicious."""
    flows = ev.get("flows", {}) or {}
    if "error" in flows:
        return None
    f = (ev.get("contact") or {}).get("features", {}) or {}
    days = len(signals._active_days(flows))
    if (f.get("bursts") or 0) >= 3 or days >= 2:
        return f"repeated contact ({_plural(f.get('bursts') or 0, 'burst')} over {_plural(max(days, 1), 'day')})"
    non_web = sorted({p for p, _ in signals._ports(flows) if p not in (80, 443)})
    if non_web:
        return f"non-web traffic (port {_join([str(p) for p in non_web])})"
    up, down = signals._total_bytes(flows)
    if (flows.get("notable") or {}).get("upload_heavy_total") or (up >= UPLOAD_NOTABLE_BYTES and up > down):
        return f"uploads ({fmt_bytes(up)} sent, {fmt_bytes(down)} received)"
    return None


def correlation_sentence(ev: dict) -> str:
    """A neutral note for a case whose site is also behind other flagged
    addresses. The link is not evidence against the host; only substantial
    contact from this host makes it worth a review."""
    links = ev.get("correlation")
    if not links:
        return ""
    d = links["domains"][0]
    others = [i for i in d["indicators"] if i != ev["identity"]["indicator"]]
    provider = correlation.shared_provider(d["indicators"])
    normal = (f", which is normal for {provider}: it gives each site more than one address" if provider else "")
    text = (f"Its site, {d['domain']}, is also behind {_join(others)} in this feed{normal}; the indicator was "
            "probably reported against the domain (see the linked-domain note at the top of report.html)")
    reason = substantial_contact(ev)
    if reason:
        text += f". This host's own contact with it is more than one visit ({reason}), so it is marked for review"
    return _sentence(text)


def finding_sentence(result: dict) -> str:
    """Summary line for a finding the agent raised that the rule-based checks
    do not cover (already checked against the evidence in assess.py)."""
    finding = result.get("additional_finding")
    if not finding:
        return ""
    first = finding.split(". ")[0].rstrip(".")
    return (f"The agent's review raised a point the rule-based checks do not cover: {_lower_first(first)}; the case "
            "is marked for review.")


def finding_paragraph(result: dict) -> str:
    finding = result.get("additional_finding")
    if not finding:
        return ""
    return f"Agent's finding (not covered by the rule-based checks): {_sentence(finding)}"


def also_matched_sentence(ev: dict) -> str:
    also = ev.get("also_matched") or []
    if not also:
        return ""
    return (f"The same visit also matched {_join(also)}, another flagged address of the same site; this report "
            "covers both.")


def summary(result: dict, ev: dict, category: str) -> str:
    threat = _threat(ev)
    start, end = _period(ev)
    span = _span(start, end)
    if ev.get("flows", {}).get("retention_cut") and span.startswith("from "):
        span = "from at least " + span.removeprefix("from ")  # earlier flows have aged out of the table
    parts = [
        f"{span[0].upper()}{span[1:]}, {_host_phrase(ev)} contacted "
        f"{_indicator_phrase(ev)}, which ThreatFox lists as {_a(_family(ev))} {threat['ioc_role']}{_ioc_ref(ev)}.",
        f"A match like this would usually mean {threat['match_means']}.",
        _finding(ev, category),
        f"We assess this as {VERDICT_PHRASE.get(result['VERDICT'], result['VERDICT'])} "
        f"({result.get('CONFIDENCE') or 'low'} confidence){_baseline_clause(result)}.",
        risk_note(ev, category),
        correlation_sentence(ev),
        also_matched_sentence(ev),
        finding_sentence(result),
    ]
    return " ".join(_sentence(p) for p in parts if p)


# --- behaviour analysis ---------------------------------------------------------------------

def _names_sentence(ev: dict) -> str:
    identity = ev["identity"]
    ip = _first_ip(ev).get("server_ip") or "the flagged IP"
    names = _visible_names(ev)[:MAX_NAMES]
    source = _names_source(ev)
    if identity.get("indicator_type") == "domain" and names:
        return f"The host reached {ip} as {_join(names)} ({source})."
    if names:
        return f"On {ip}, the host's traffic named {_join(names)} ({source})."
    if ev.get("names", {}).get("ech_hidden_minutes"):
        return (f"The host's traffic to {ip} had its site name hidden by Encrypted Client Hello, so which site it "
                f"used there is unknown ({source}).")
    return f"No site name was recorded for the host's traffic to {ip}."


def _flow_sentences(ev: dict) -> list[str]:
    flows = ev.get("flows", {})
    c = flows.get("classification", {})
    activity = flows.get("activity", {})
    ports = signals._ports(flows)
    out = []
    held = c.get("held_open")
    if held:
        s = (f"It held {_plural(held['count'], 'long-lived connection')} on {_ports_text(ports)} lasting "
             f"{fmt_duration(held['min_duration_sec'])} to {fmt_duration(held['max_duration_sec'])}, at about "
             f"{held['median_packets_per_sec_down']:.1f} packets/s down and {held['median_packets_per_sec_up']:.1f} up "
             f"({held['median_bytes_per_packet_down']:.0f} and {held['median_bytes_per_packet_up']:.0f} bytes per "
             "packet), a steady keepalive rather than a beacon")
        if held["quick_reconnects"] >= 2:
            s += (f", and it reconnected within about {held['median_quick_reconnect_sec']:.0f} s of each drop, "
                  "which suggests something relaunches it automatically")
        out.append(s + ".")
    if not held and flows.get("long_flow_count"):
        up = sum(p["up_bytes"] for p in flows.get("ports", []))
        down = sum(p["down_bytes"] for p in flows.get("ports", []))
        flow_ports = sorted({(p["port"], p["protocol"]) for p in flows.get("ports", [])})
        out.append(f"It made {_plural(flows['long_flow_count'], 'flow')} over 1 MB on {_ports_text(flow_ports)}, sending "
                   f"{fmt_bytes(up)} and receiving {fmt_bytes(down)} in total.")
    heavy = flows.get("notable", {}).get("upload_heavy_total")
    if heavy and (held or flows.get("long_flow_count")):
        if heavy["count"] == 1:
            lasting = f"one upload-heavy session of {fmt_duration(heavy['max_duration_sec'])}"
        else:
            lasting = (f"{heavy['count']} upload-heavy sessions of {fmt_duration(heavy['min_duration_sec'])} to "
                       f"{fmt_duration(heavy['max_duration_sec'])}")
        out.append(f"There {'was' if heavy['count'] == 1 else 'were'} also {lasting}, sending "
                   f"{fmt_bytes(heavy['up_bytes'])} out versus {fmt_bytes(heavy['down_bytes'])} in "
                   "(shorter sessions may be missing).")
    if not flows.get("long_flow_count") and activity.get("active_minutes"):
        quic = any(p == 443 and proto == "udp" for p, proto in ports)
        out.append(f"The traffic was {_plural(activity['active_minutes'], 'active minute')} on {_ports_text(ports)}"
                   + (" (UDP/443 is QUIC, which browsers and apps use for HTTPS)" if quic else "")
                   + f", {fmt_bytes(activity.get('up_bytes', 0))} sent and "
                   f"{fmt_bytes(activity.get('down_bytes', 0))} received.")
    periods = _day_periods(flows.get("active_periods") or [])
    if len(periods) > 1 or (periods and periods[0][0] != periods[0][1]):
        spans = [_short_span(a, b) for a, b in periods[:MAX_PERIODS]]
        more = len(periods) - MAX_PERIODS
        out.append(f"Activity ran {_join(spans + ([_plural(more, 'more period')] if more > 0 else []))}.")
    identity = ev["identity"]
    if identity.get("n_events", 0) > 3:
        out.append(f"The {identity['n_events']} feed alerts are per-minute records of this activity "
                   f"{_span(identity.get('evidence_first_seen'), identity.get('evidence_last_seen'))}, not separate "
                   "incidents.")
    return out


def _observed(ev: dict) -> str:
    """What the traffic actually looked like, in plain words, for the
    comparison with a real victim."""
    flows = ev.get("flows", {})
    c = flows.get("classification", {})
    ports = signals._ports(flows)
    service = ev.get("expected", {}).get("service")
    if service and signals._service_fits(ev.get("expected", {})):
        return (f"every connection went to the {_service_short(service)} client's own port ({_ports_text(ports)}) and "
                "none to any other port on the IP, so the host was running the client, not reaching something "
                "hosted behind it")
    if any(p == 443 and proto == "udp" for p, proto in ports):
        kind = "QUIC web traffic"
    elif ports and all(p in (80, 443) for p, _ in ports):
        kind = "web traffic" + (" to a named website" if _visible_names(ev) else "")
    else:
        kind = f"traffic on {_ports_text(ports) or 'unknown ports'}"
    pattern = (ev.get("contact") or {}).get("pattern")
    if pattern == "periodic_checkin":
        shape = "sent as repeated small check-ins at a regular interval"
    elif c.get("held_open") or pattern == "held_open":
        shape = "held open for hours or days"
    elif flows.get("long_flow_count", 0) > 3:
        shape = f"in {flows['long_flow_count']} separate sessions"
    elif ((ev.get("contact") or {}).get("features") or {}).get("bursts") == 1:
        shape = "in a single short session"
    else:
        shape = "in a few sessions"
    days = len(signals._active_days(flows))
    when = "on a single day" if days <= 1 else f"on {days} different days"
    return f"{kind} {shape} {when}"


def _day_periods(periods: list[dict]) -> list[tuple[date, date]]:
    """Active periods merged to whole days: periods less than a day apart
    read as one span in a report."""
    merged: list[list[date]] = []
    for p in periods:
        start, end = _day(p["start"]), _day(p["end"])
        if not start or not end:
            continue
        if merged and (start - merged[-1][1]).days <= 1:
            merged[-1][1] = max(merged[-1][1], end)
            continue
        merged.append([start, end])
    return [(a, b) for a, b in merged]


def _comparison_sentences(ev: dict) -> list[str]:
    expected = ev.get("expected", {})
    malware = expected.get("malware_profile", {})
    victim = malware.get("victim_traffic") or _threat(ev).get("victim_traffic")
    article = _a(_family(ev))
    out = [f"{article[0].upper()}{article[1:]} victim would {victim}."]
    service = expected.get("service")
    if service:
        out.append(service["profile"]["c2_victim_would_show"].split(". ")[0].replace(" NOT ", " not ").rstrip(".") + ".")
    directions = [_signal(ev, n).get("direction") for n in ("known_service", "protocol_fit", "traffic_shape_fit",
                                                             "recurrence")]
    against = directions.count(signals.AGAINST)
    supports = directions.count(signals.SUPPORTS)
    if against and not supports:
        verdict = "which does not fit that"
    elif supports and not against:
        verdict = "which fits that"
    elif supports and against:
        verdict = "which fits it in part"
    else:
        verdict = "which neither fits nor rules it out"
    out.append(f"Here, the traffic was {_observed(ev)}, {verdict}." if not service or not signals._service_fits(expected)
               else f"Here, {_observed(ev)}.")
    out.append(_threatfox_dates_sentence(ev))
    return [s for s in out if s]


def _threatfox_dates_sentence(ev: dict) -> str:
    """If ThreatFox's last-seen date falls outside the host's activity, the
    host is unlikely to be the server behind the IOC."""
    metadata = ev["identity"].get("ioc_metadata") or {}
    last = _day(metadata.get("threatfox_last_seen"))
    periods = ev.get("flows", {}).get("active_periods") or []
    if not last or not periods:
        return ""
    active = any(_day(p["start"]) <= last <= _day(p["end"]) for p in periods)
    if active:
        return f"ThreatFox last saw the indicator on {_fmt_day(last)}, while the host was connected to it."
    return (f"ThreatFox last saw the indicator on {_fmt_day(last)}, when the host had no active connection to it, "
            "so the host is unlikely to be the server behind the IOC.")


PART_TIME_WORDS = ("laptop", "phone", "mobile", "tablet", "personal device", "handheld")


def role_contradicts_uptime(role: str, uptime: dict) -> bool:
    """A part-time device for a host that is busy around the clock, or a
    server for one without that evidence (background traffic at night is
    not evidence of a server)."""
    text = role.lower()
    if uptime.get("always_on") is True:
        return any(word in text for word in PART_TIME_WORDS)
    return "server" in text


# Role words and the evidence each needs: (words, activity hints, app categories).
ROLE_EVIDENCE = (
    (("gaming", "game"), ("gaming",), ("Gameplay", "Gaming Download")),
    (("develop",), ("software development",), ()),
    (("media", "stream"), ("self-hosted media", "streaming or social media"), ("Video", "Music", "Live Video")),
    (("home lab", "homelab", "self-host"), ("home lab or self-hosted services",), ()),
)
# Roles no evidence in this data can support.
UNSUPPORTED_ROLE_WORDS = ("research", "experiment", "iot", "camera", "printer", "smart tv", "kiosk")


def role_unsupported(role: str, ev: dict) -> bool:
    """True if the model's role names something the evidence does not show:
    each role word needs matching activity hints or app categories, so the
    agent only states a role the data supports."""
    text = role.lower()
    other = ev.get("other_traffic", {}) or {}
    hints = set((other.get("activity_hints") or {}).keys())
    categories = {c["category"] for c in (ev.get("host_apps") or {}).get("categories", [])}
    for words, needed_hints, needed_categories in ROLE_EVIDENCE:
        if any(w in text for w in words) and not (hints & set(needed_hints) or categories & set(needed_categories)):
            return True
    return any(w in text for w in UNSUPPORTED_ROLE_WORDS)


# Where-is-it words: the data never says which network a host is on, so the
# agent may only use one if the host's own name contains it.
LOCATION_WORDS = ("residential", "residence", "dorm", "college", "student", "staff", "office", "lab",
                  "library", "campus", "wifi", "wireless", "guest")


def role_guesses_location(role: str, hostname: str | None) -> bool:
    """True if the role names a network or location type not in the host name."""
    text = role.lower()
    name = (hostname or "").lower()
    return any(word in text and word not in name for word in LOCATION_WORDS)


def _uptime_sentence(ev: dict) -> str:
    """Night vs daytime volume (subscriber_ip_load_enriched_1h). Every host
    has some traffic every hour, so only volume says anything."""
    uptime = ev.get("other_traffic", {}).get("uptime") or {}
    ratio = uptime.get("night_day_ratio")
    if ratio is None:
        return ""
    night = f"{fmt_bytes(uptime['night_bytes_per_hour'])} an hour at night against {fmt_bytes(uptime['day_bytes_per_hour'])} by day"
    if uptime.get("always_on") is True:
        shared = len((ev.get("host_apps") or {}).get("user_agent_platforms") or {}) > 1
        what = "an always-on machine such as a server" + (", or several devices sharing this address" if shared else "")
        return f"The host stays busy around the clock ({night}), which points to {what}."
    if uptime.get("always_on") is False:
        return f"The host goes almost silent at night ({night}), like a personal device used in waking hours."
    if ratio >= 0.5:
        return (f"The host sends only a trickle at any hour ({night}): background traffic, which any connected "
                "device has, so it says nothing about what the machine is.")
    return (f"The host is always connected but much quieter at night ({night}): background traffic, which any "
            "connected device has, so it says nothing about what the machine is.")


def _agent_reading(result: dict, ev: dict) -> str:
    """The model's one-sentence reading of what the host is, labelled as such.
    Dropped if it quotes numbers not in the evidence or contradicts the
    uptime evidence."""
    role = (result.get("HOST_ROLE") or "").strip()
    uptime = ev.get("other_traffic", {}).get("uptime") or {}
    hostname = (ev.get("host") or {}).get("hostname")
    if (not role or result.get("unverified_numbers") or role_contradicts_uptime(role, uptime)
            or role_guesses_location(role, hostname) or role_unsupported(role, ev)):
        return ""
    first = role.split(". ")[0].rstrip(".")
    return f"The agent's reading of the host name and traffic, unconfirmed: {_lower_first(first)}."


def _other_traffic_sentence(ev: dict, result: dict) -> str:
    other = ev.get("other_traffic", {})
    reading = _agent_reading(result, ev)
    if "error" in other or (not other.get("top_destinations_by_bytes") and not other.get("long_lived_flows")):
        return _join_sentences("The host's other traffic is outside the retention window.", reading)
    services = [_service_volume(ev, s["service"]) for s in _other_services(ev)]
    hints = other.get("activity_hints") or {}
    hint_domains = [d for domains in list(hints.values())[:3] for d in domains[:2]]
    roles = list(hints)[:2]
    if services and len(services) + bool(ev.get("expected", {}).get("service")) >= 2:
        roles.append("exposing services through several tunnels")
    listed = _join(services + hint_domains[:5])
    if listed and roles:
        text = f"Its other traffic includes {listed}, which suggests it is used for {_join(roles)}."
    elif listed:
        text = f"Its other traffic includes {listed}."
    else:
        top = other.get("domains_by_active_minutes", [])[:4]
        text = f"Its other traffic ({_join(top) or 'little'}) gives no clear picture of what the host is used for."
    return _join_sentences(text, _uptime_sentence(ev), reading or "What the host is used for is unconfirmed.")


def _join_sentences(*parts: str) -> str:
    return " ".join(_sentence(p) for p in parts if p)


def sites_seen(ev: dict) -> list[str]:
    """Root domains actually seen on the flagged IP campus-wide (names_on_ip)."""
    pdns = next((p for p in ev.get("names_on_ip", []) if "error" not in p), None)
    return [d["root_domain"] for d in (pdns or {}).get("domains", [])]


def shared_address_phrase(ev: dict) -> str:
    """'a shared Cloudflare address that serves many unrelated sites (7 seen on
    it on campus)' only when more than one site was actually seen; otherwise
    say what was seen, so the report never claims more than the data shows."""
    sites = sites_seen(ev)
    provider = _provider(ev)
    if len(sites) > 1:
        return (f"a shared {provider} address that serves many unrelated sites "
                f"({len(sites)} seen on it on campus, including {_join(sites[:3])})")
    if len(sites) == 1:
        return f"a {provider} address, where only {sites[0]} was seen on campus"
    return f"a {provider} address (a provider whose addresses normally front many sites; none was named on it on campus)"


def _shared_reason(ev: dict) -> str:
    """Why the address counts as shared, in the words of what triggered it."""
    pdns = next((p for p in ev.get("names_on_ip", []) if "error" not in p), None)
    if pdns and pdns["distinct_root_domains"] >= config.SHARED_PASSIVE_DNS_DOMAINS:
        return "so the address is shared by many unrelated sites"
    service = ev.get("expected", {}).get("service")
    if service:
        return f"but it is the public {_service_short(service)} server, which many people use"
    info = _first_ip(ev)
    if info.get("shared_range") or info.get("shared_asn"):
        if len(sites_seen(ev)) > 1:
            return f"but it is a {_provider(ev)} address, which serves many unrelated sites"
        return f"but it is a {_provider(ev)} address, a provider whose addresses normally front many sites"
    return "so the address is shared infrastructure"


def _peers_sentence(ev: dict) -> str:
    ip = _first_ip(ev).get("server_ip") or "the flagged IP"
    peers = [p for p in ev.get("peers", []) if "error" not in p]
    parts = []
    if peers:
        p = peers[0]
        others = p["other_host_count"]
        # HOST_LABEL already ends in "host" ("Example University host", "internal host").
        text = (f"{_plural(others, 'other ' + config.HOST_LABEL)} connected to {ip}" if others
                else f"No other {config.HOST_LABEL} had long-lived connections to {ip}")
        text += f" in the last {p['lookback_days']} days"
        if p["peer_hosts_also_flagged"]:
            text += f", {p['peer_hosts_also_flagged']} of them flagged by other indicators"
        parts.append(text)
    pdns = next((p for p in ev.get("names_on_ip", []) if "error" not in p), None)
    if pdns and pdns["distinct_root_domains"]:
        when = "recently" if pdns["period_is_current"] else "around the match"
        if pdns["distinct_root_domains"] == 1:
            parts.append(f"campus-wide, only {pdns['domains'][0]['root_domain']} was seen on it {when}")
        else:
            examples = _join([d["root_domain"] for d in pdns["domains"][:3]])
            parts.append(f"campus-wide, {pdns['distinct_root_domains']} different sites were seen on it {when} "
                         f"(including {examples})")
    if not parts:
        return ""
    shared = _signal(ev, "shared_infrastructure").get("direction")
    tail = {signals.AGAINST: ", " + _shared_reason(ev),
            signals.SUPPORTS: ", so the address looks dedicated to one site"}.get(shared, "")
    return _sentence("; ".join(parts) + tail)


def contact_paragraph(ev: dict) -> str:
    """Short 'Contact pattern' paragraph from the per-minute data (beacon.py)."""
    contact = ev.get("contact") or {}
    if not contact or "error" in contact:
        return ""
    f = contact.get("features", {})
    table = contact.get("source", "")
    if contact.get("pattern") == "insufficient_data":
        return ("Contact pattern: no per-minute contact with the flagged IP was found in "
                f"{table or 'the per-minute tables'} for the window, so no beacon check is possible "
                "(long_flow_summary only holds flows over 1 MB and cannot show one).")
    where = ("the IOC feed's own per-minute records, as the live per-minute data has expired" if table == "IOC feed"
             else f"{table}, {contact.get('resolution_min', 1)}-minute resolution")
    parts = [f"Contact pattern ({where}): "
             f"{contact['description'].lower()}. There {'was' if f['bursts'] == 1 else 'were'} "
             f"{_plural(f['bursts'], 'burst')} of contact {_span(f['first'], f['last'])}"]
    if f.get("median_gap_min"):
        parts[0] += f", typically {fmt_duration(f['median_gap_min'] * 60)} apart"
    parts[0] += f", with {f['night_share']:.0%} of the contact between midnight and 6 am local time."
    signal = _signal(ev, "contact_pattern")
    if signal.get("explained_by"):
        parts.append(f"It is explained by {signal['explained_by']}.")
    elif signal.get("direction") == signals.SUPPORTS:
        parts.append("Nothing explains it: no recognised app or session, not a popular destination, and not a known "
                     "service's normal client.")
    return " ".join(parts)


def apps_line(ev: dict) -> str:
    app = ev.get("app_context") or {}
    host_apps = ev.get("host_apps") or {}
    if "error" in app and "error" in host_apps:
        return ""
    seen: list[str] = []
    for a in app.get("host_apps", []):
        if a["class"] in ("benign", "vendor", "remote_access") and a["application"] not in seen:
            seen.append(a["application"])
    labels = _join(seen)
    parts = [f"SuperNetFlow labels this traffic as {labels}" if labels
             else "SuperNetFlow has no app label for this traffic"]
    if app.get("host_sessions"):
        top = app["host_sessions"][0]
        parts.append(f"it was part of recognised {top['type']} sessions ({top['provider']})")
    agents = host_apps.get("user_agent_platforms") or {}
    if len(agents) == 1:
        parts.append(f"the host's user agents point to {next(iter(agents))}")
    elif agents:
        parts.append(f"the host's user agents are mixed, mostly {max(agents, key=agents.get)} (several devices "
                     "may share this address)")
    if host_apps.get("remote_access_apps"):
        parts.append(f"it also uses remote-access apps ({_join(host_apps['remote_access_apps'][:3])})")
    if host_apps.get("privacy_vpn_apps"):
        parts.append(f"it uses VPNs or privacy relays ({_join(host_apps['privacy_vpn_apps'][:3])})")
    return "Apps and platform: " + "; ".join(parts) + " (app_subscriber_server_enriched_5m, ux_sessions, subscriber_activity_1m)."


def dns_line(ev: dict) -> str:
    """DNS behaviour, from dns_tuple. Only unusual resolvers or a high
    unanswered share are notable: most hosts seen there only use the big
    public resolvers."""
    dns = ev.get("dns") or {}
    if "error" in dns:
        return ""
    caveat = ("On this deployment dns_tuple has no NXDOMAIN, SERVFAIL or REFUSED counts (unlike the public docs; its "
              "rcode is always -1), so a domain-generation pattern cannot be checked.")
    if not dns.get("present"):
        return ("DNS behaviour: no direct external DNS from this host was seen; it uses the campus resolvers, whose "
                f"traffic the sensor does not capture (dns_tuple). {caveat}")
    if not dns.get("rare_resolvers") and not dns.get("unanswered_high"):
        public = sorted({r["public_resolver"] for r in dns.get("resolvers", []) if r["public_resolver"]})
        common = f", as {dns['campus_public_only_share']:.0%} of hosts seen there do" if dns.get(
            "campus_public_only_share") is not None else ""
        return (f"DNS behaviour: nothing unusual; the little DNS it sends outside campus goes to public resolvers "
                f"({_join(public) or 'common ones'}){common} (dns_tuple). {caveat}")
    parts = []
    details = dns.get("rare_resolver_details") or [{"server_ip": ip} for ip in dns.get("rare_resolvers", [])]
    if details:
        ips = _join([d["server_ip"] for d in details[:2]])
        owner = next((f"AS{d['asn']} {d['asn_org']}" for d in details if d.get("asn")), "")
        kind = next((d["authoritative"] for d in details if d.get("authoritative")), None)
        text = f"it sends DNS to {ips}" + (f" ({owner})" if owner else "") + ", which few campus hosts ask"
        if kind:
            text += (f"; these are {kind}, not resolvers, and a normal client asks a resolver, so the host may run "
                     "its own recursive resolver")
        parts.append(text)
    if dns.get("unanswered_high"):
        median = dns.get("campus_median_unanswered_ratio")
        parts.append(f"{dns['unanswered_ratio']:.0%} of its DNS queries went unanswered"
                     + (f" (campus median {median:.0%})" if median is not None else ""))
        if dns["unanswered_ratio"] >= 0.95:
            parts.append("with nothing answered, the sensor may be seeing only one direction of this traffic")
    return f"DNS behaviour: {'; '.join(parts)} (dns_tuple), a weak hint on its own. {caveat}"


def analysis(result: dict, ev: dict, category: str) -> str:
    if category == "no_traffic":
        checked = "; ".join(ev.get("flows", {}).get("checked", [])) or "the flow tables and the feed's records"
        return _sentence(f"Checked: {checked}") + " " + _peers_sentence(ev)
    parts = [_names_sentence(ev), *_flow_sentences(ev), *_comparison_sentences(ev),
             _other_traffic_sentence(ev, result), _peers_sentence(ev)]
    extra = [finding_paragraph(result), contact_paragraph(ev), apps_line(ev), dns_line(ev)]
    return "\n\n".join([" ".join(p for p in parts if p)] + [e for e in extra if e])


# --- conclusion ---------------------------------------------------------------------

def _supporting_reasons(ev: dict) -> list[str]:
    return [_lower_first(s["reason"]).rstrip(".") for s in ev.get("signals", [])
            if s["direction"] == signals.SUPPORTS]


def _verdict_statement(result: dict, ev: dict, category: str) -> str:
    verdict = result["VERDICT"]
    family = _family(ev)
    service = ev.get("expected", {}).get("service")
    if verdict == "LIKELY_FALSE_POSITIVE":
        if category in ("tunnel_client", "remote_access_client"):
            why = f"the host shows no sign of infection and runs its own {_service_short(service)} client"
        elif category == "web_shared":
            if len(sites_seen(ev)) > 1:
                why = "the host was browsing a shared address used by many unrelated sites, and nothing points to infection"
            else:
                why = (f"the host was browsing through a {_provider(ev)} address (a provider that fronts many sites), "
                       "and nothing points to infection")
        else:
            why = "the traffic does not fit how an infected host behaves"
        return f"The IOC match appears to be a false positive for {family}: {why}."
    if verdict == "SUSPICIOUS":
        reasons = _supporting_reasons(ev)[:2]
        why = "; ".join(reasons) if reasons else "the evidence neither clears nor confirms it"
        return f"The match is suspicious and needs a manual review: {why}."
    if verdict == "LIKELY_THREAT":
        return f"The match is likely a real {family} infection: {'; '.join(_supporting_reasons(ev)[:3])}."
    return "The match cannot be assessed, because no traffic between the host and the indicator was found."


def _confidence_statement(result: dict, ev: dict, category: str) -> str:
    confidence = result.get("CONFIDENCE") or "low"
    service = ev.get("expected", {}).get("service")
    if result["VERDICT"] == "LIKELY_FALSE_POSITIVE" and category in ("tunnel_client", "remote_access_client"):
        return (f"We have high confidence that the host ran a {_service_short(service)} client, and {confidence} "
                "confidence that its use is benign.")
    if result["VERDICT"] == "INSUFFICIENT_DATA":
        return ""
    return f"Confidence in this verdict is {confidence}."


def _limits(ev: dict, category: str) -> str:
    limits = ["flow records cannot show what was in the traffic"]
    if category in ("tunnel_client", "tunnel_public_port"):
        limits.append("visitors reaching the host through the tunnel are hidden behind the tunnel server's address")
    if ev.get("flows", {}).get("sources", {}).get("subscriber_activity_1m") == "feed":
        limits.append("the per-minute data for this period has expired, so only the matched minutes remain")
    if ev.get("names", {}).get("ech_hidden_minutes") and not _visible_names(ev):
        limits.append("the site name was hidden by Encrypted Client Hello")
    if not ev.get("flows", {}).get("long_flow_count"):
        limits.append("long_flow_summary only holds flows over 1 MB, so small or short connections are not in it")
    cut = ev.get("flows", {}).get("retention_cut")
    if cut:
        limits.append(f"long_flow_summary only keeps flows that ended on or after {_fmt_day(_day(cut))}, and this "
                      "host's activity reaches that date, so earlier activity is missing")
    return "The data has limits: " + "; ".join(limits) + "."


def next_steps(result: dict, ev: dict, category: str) -> list[str]:
    host = ev["identity"]["affected_asset"]
    service = ev.get("expected", {}).get("service")
    verdict = result["VERDICT"]
    names = _visible_names(ev)
    steps: list[str] = []
    if verdict == "LIKELY_THREAT" or category == "beaconing":
        steps += ["escalate to incident response", f"isolate or closely monitor {host}",
                  "check the host with endpoint tools"]
    if category in ("tunnel_client", "remote_access_client"):
        steps += [f"contact the owner of {host} to identify the device and the services it exposes",
                  f"check this use against the policy for {config.NETWORK_LABEL}"]
        ports = [f"{p['port']}/{p['protocol'].upper()}" for p in service["profile"]["ports"] if p["distinctive"]]
        if ports:
            steps.append(f"consider a campus-wide alert on outbound traffic to {_join(ports)} "
                         f"({_service_short(service)})")
    elif category == "tunnel_public_port":
        steps += [f"find out what {host} reached behind {_service_short(service)}",
                  "check the host with endpoint tools"]
    elif category == "persistent_connection":
        steps += [f"identify the service on the connection with the owner of {host}",
                  "watch for further connections to the flagged IP"]
    elif category in ("web_visit_flagged", "download"):
        steps += [f"check {host} for anything downloaded or run from the site", "consider blocking the domain"]
    elif category == "no_traffic":
        steps += ["re-run the check while the traffic is still within the per-minute retention (about 15 days)",
                  "look for the indicator in other logs (DNS, proxy, endpoint)"]
    elif verdict == "LIKELY_FALSE_POSITIVE" and category == "web_shared":
        steps += [f"close this alert for {host}",
                  f"treat ip:port indicators on shared {_provider(ev)} addresses as low value unless the site name "
                  "the host used is itself suspicious"]
    elif verdict == "LIKELY_FALSE_POSITIVE":
        steps.append(f"close this alert for {host}")
    if verdict == "SUSPICIOUS" and names:
        steps.append(f"check what {_join(names[:2])} is and why this host used it")
    others = _other_services(ev)
    if others:
        listed = _join([knowledge.SERVICE_PROFILES.get(s["service"], {"name": s["service"]})["name"].split(" (")[0]
                        for s in others])
        steps.append(f"review the other tunnels or remote-access tools the host runs ({listed})")
    if result.get("additional_finding"):
        steps.insert(0, "check the agent's finding against the evidence")
    # One action per card: a case marked for review is reviewed, not closed.
    if result.get("needs_review"):
        steps = [s for s in steps if not s.startswith(("close this alert", "treat ip:port"))]
        steps.insert(0, "review this case before acting on it (the reasons it was marked are listed below)")
    return list(dict.fromkeys(steps))


def conclusion(result: dict, ev: dict, category: str) -> str:
    parts = [_verdict_statement(result, ev, category), _confidence_statement(result, ev, category),
             disagreement_note(result)]
    risk = risk_note(ev, category)
    if risk:
        parts.append(risk)
    others = _other_services(ev)
    if others and category not in ("tunnel_client", "remote_access_client"):
        parts.append("The host also runs other tunnels or remote-access tools, which expose it in a similar way.")
    parts.append(_limits(ev, category))
    steps = next_steps(result, ev, category)
    if steps:
        parts.append(f"The next steps are to {_join(steps)}.")
    return " ".join(_sentence(p) for p in parts if p)


def write(result: dict, ev: dict) -> dict:
    category = ev.get("behaviour", {}).get("key", "other")
    return {
        "summary": summary(result, ev, category),
        "analysis": analysis(result, ev, category),
        "conclusion": conclusion(result, ev, category),
    }

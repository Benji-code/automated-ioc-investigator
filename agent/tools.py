"""The per-question tools, one per workflow step, plus the one tool the model
can call itself.

A weak local model (qwen2.5:7b) reliably skips optional tools: given a
choice, it called one lookup and stopped. So every check that must always run
is called deterministically from assess.py, and the results go into the case
file before the model sees it:
  identify_server_ips  step 3  which IP(s) the indicator maps to
  expected_behaviour   step 4  threat, malware and service profiles
  indicator_flows      step 5  flows between the host and the flagged IP(s),
                               falling back to the feed's own evidence
  indicator_names      step 5  names (SNI/DNS) the host used on the flagged IP
  names_on_ip       step 8  names on the flagged IP, campus-wide
  domain_features      step 4  offline features, campus popularity, first seen
  host_other_traffic   step 7  the host's traffic to everything else
  indicator_peers      step 8  other internal hosts contacting the flagged IP

Open-ended follow-ups are left to the model: timeline_around, host_baseline,
compare_sessions and run_sql. All are bound to the case's host in code, so
the model cannot point them at another host. run_sql's safety lives in
db.run_sql, not the prompt.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import date, datetime, timedelta, timezone

import pandas as pd

from . import analysis, beacon, config, db, domain_features as dfeat, evidence, knowledge
from .evidence import CaseWindow

MAX_PEER_IPS = 3  # peer lookups per case, for indicators that map to several IPs
MAX_FEATURE_DOMAINS = 10
MAX_LISTED_NAMES = 15
MAX_BASELINE_DAYS = 14

def _spec(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": properties, "required": required},
    }}


TOOL_SPECS = [
    _spec(
        "timeline_around",
        "Everything this case's host did in a window around one time: destinations, names, bytes. "
        "Use it to tell a human browsing burst (many sites at once) from a lone automated connection. "
        "Only works within subscriber_activity_1m retention (about 15 days).",
        {"time": {"type": "string", "description": "UTC time, 'YYYY-MM-DD HH:MM'"},
         "minutes": {"type": "integer", "description": "minutes either side, at most 90 (default 10)"}},
        ["time"],
    ),
    _spec(
        "host_baseline",
        "This host's normal day: volume, number of destinations and active hours per day. Use it to "
        "judge whether the matched traffic stands out from the host's usual activity.",
        {"days": {"type": "integer", "description": "days back from now, at most 14 (default 5)"}},
        [],
    ),
    _spec(
        "compare_sessions",
        "Compare the host's traffic with the flagged IP on two dates (flows, ports, bytes, names). "
        "Use it when one day might tell a different story from another.",
        {"date_a": {"type": "string", "description": "YYYY-MM-DD"},
         "date_b": {"type": "string", "description": "YYYY-MM-DD"}},
        ["date_a", "date_b"],
    ),
    {
        "type": "function",
        "function": {
            "name": "run_sql",
            "description": (
                "Run a read-only SQL query against ClickHouse for anything the case file "
                "doesn't already cover - e.g. one specific flow, one hour, or one destination "
                "in the host's other traffic. The schema card in the system prompt describes "
                "the two tables. Must be a SELECT, must reference one of those tables, and "
                "must filter on this case's client_ip and a time column; otherwise it is "
                "rejected with an error explaining why. Keep subscriber_activity_1m queries "
                "to 5 days or less. Results are capped at 50 rows."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "sql": {"type": "string", "description": "a single read-only SELECT statement"},
                },
                "required": ["sql"],
            },
        },
    },
]


def execute(name: str, arguments: dict, *, client_ip: str, server_ips: list[str] | None = None) -> dict:
    """Run a model-callable tool, always for this case's host. A failure
    becomes a normal result the model can reason about, not a crash."""
    try:
        if name == "run_sql":
            sql = str(arguments.get("sql", "")).strip()
            if not sql:
                return {"error": "a 'sql' argument is required"}
            return {"sql": sql, "result": db.run_sql(sql, client_ip, server_ips or [])}
        if name == "timeline_around":
            return timeline_around(client_ip, str(arguments.get("time", "")), arguments.get("minutes"))
        if name == "host_baseline":
            return host_baseline(client_ip, arguments.get("days"))
        if name == "compare_sessions":
            return compare_sessions(client_ip, server_ips or [], str(arguments.get("date_a", "")),
                                    str(arguments.get("date_b", "")))
        return {"error": f"unknown tool '{name}'"}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{name} failed: {exc}"}


def describe_call(call: dict) -> str:
    """One-line label for a logged tool call (report appendix)."""
    args = call.get("arguments", {})
    if call.get("tool") == "run_sql":
        return "run_sql"
    return f"{call.get('tool')}({', '.join(f'{k}={v}' for k, v in args.items())})"


# --- step 1: who is the host? ----------------------------------------------------

def _reverse_dns(ip: str) -> str | None:
    """PTR name for the host, or None (no record, timeout or turned off)."""
    if not config.REVERSE_DNS:
        return None
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(socket.gethostbyaddr, ip)
        try:
            return future.result(timeout=config.REVERSE_DNS_TIMEOUT_SEC)[0]
        except (FutureTimeout, OSError):
            return None


def host_identity(ip: str) -> dict:
    """The host's name from reverse DNS: a fact. What the name suggests
    (a lab machine, a residence) is left to the model's HOST_ROLE, and the
    report labels it as the agent's unconfirmed reading. The subscriber_id
    is SuperNetFlow's key for the host (used to keep queries fast)."""
    return {"ip": ip, "hostname": _reverse_dns(ip), "subscriber_ids": list(db.subscriber_ids(ip))}


# --- step 3 --------------------------------------------------------------------

def identify_server_ips(identity: dict, case_rows: list[dict], window: CaseWindow) -> dict:
    """Every IP the indicator maps to: parsed from an ip:port indicator, or
    for a domain, every IP in the feed's evidence plus any IP the host reached
    under that name in live DNS/SNI data."""
    indicator = identity["indicator"]
    parsed = evidence.parse_ip_port(indicator)
    if parsed:
        ip, port = parsed
        return {
            "indicator_port": port,
            "ips": [{"server_ip": ip, "found_via": ["indicator is ip:port"], "names": [], "asn_org": []}],
        }

    found: dict[str, dict] = {}
    for entry in evidence.feed_server_ips(case_rows):
        found[entry["server_ip"]] = {
            "server_ip": entry["server_ip"],
            "found_via": ["feed evidence (subscriber_activity_1m)"],
            "names": entry["names"],
            "asn_org": entry["asn_org"],
        }

    result = {"indicator_port": None, "ips": []}
    try:
        live = db.fetch_domain_ips(identity["affected_asset"], indicator,
                                   window.activity_start, window.activity_end)
    except Exception as exc:  # noqa: BLE001 - keep the feed's IPs even if the live lookup fails
        result["live_lookup_error"] = str(exc)
        live = pd.DataFrame()
    for row in live.itertuples(index=False):
        entry = found.setdefault(str(row.server_ip), {
            "server_ip": str(row.server_ip), "found_via": [], "names": [], "asn_org": [],
        })
        live_note = "live DNS/SNI match (subscriber_activity_1m)"
        if live_note not in entry["found_via"]:
            entry["found_via"].append(live_note)
        for name in (row.dns_name, row.sni_name):
            if name and name not in entry["names"]:
                entry["names"].append(name)
    result["ips"] = list(found.values())
    return result


# --- step 4 --------------------------------------------------------------------

def _candidate_names(identity: dict, server_ips: dict) -> list[str]:
    names = []
    if identity.get("indicator_type") == "domain":
        names.append(identity["indicator"])
    for entry in server_ips.get("ips", []):
        names.extend(entry.get("names", []))
    return names


def _observed_ports(flows_result: dict) -> list[tuple[int, str]]:
    ports = {(p["port"], p["protocol"]) for p in flows_result.get("ports", [])}
    ports |= {(p["port"], p["protocol"]) for p in flows_result.get("activity", {}).get("ports", [])}
    return sorted(ports)


def expected_behaviour(identity: dict, server_ips: dict, flows_result: dict) -> dict:
    """Threat type and malware profiles, plus the known-service profile for
    the flagged domain or the ports seen, and whether each observed port is
    one the service's own client normally uses."""
    profile = knowledge.get_profile(identity.get("malware"), identity.get("threat_type"))
    ports = _observed_ports(flows_result)

    service = None
    for name in _candidate_names(identity, server_ips):
        service = knowledge.match_service(domain=name)
        if service:
            break
    if not service:
        for port, protocol in ports:
            service = knowledge.match_service(port=port, protocol=protocol)
            if service:
                break

    port_fit = []
    if service:
        for port, protocol in ports:
            entry = knowledge.expected_service_port(service["key"], port, protocol)
            if entry:
                port_fit.append({"port": port, "protocol": protocol, "fits": True,
                                 "note": f"{service['key']} client {entry['role']} port"})
            else:
                port_fit.append({"port": port, "protocol": protocol, "fits": False,
                                 "note": "not a port the service's own client uses"})
    return {**profile, "service": service, "service_port_fit": port_fit,
            "service_port_verdict": _service_port_verdict(service, port_fit)}


def _service_port_verdict(service: dict | None, port_fit: list[dict]) -> str | None:
    """One plain sentence comparing the observed ports with the service's own
    client ports: the deciding check for C2 hidden behind a shared service."""
    if not service or not port_fit:
        return None
    name = service["profile"]["name"]
    other_ports = [f"{f['port']}/{f['protocol']}" for f in port_fit if not f["fits"]]
    if not other_ports:
        return (f"Every observed port is one the {name} client itself uses. This is what the host "
                f"running its own {service['key']} client looks like. A victim of C2 hidden behind "
                f"{service['key']} would connect to other ports on the same IP, and none were seen.")
    return (f"Port(s) {', '.join(other_ports)} are not {name} client ports. Connections there could be "
            f"to something hosted behind {service['key']} (for example C2 behind a tunnel's public port).")


# --- step 5 --------------------------------------------------------------------

def build_indicator_flows(flows: pd.DataFrame, activity: pd.DataFrame, window: CaseWindow,
                          sources: dict | None = None) -> dict:
    """Analyse already-fetched flow data (split out so tests can skip the
    database). sources says per table whether rows are 'live' (queried now),
    'feed' (from the IOC feed, not re-queried) or 'none'."""
    port_rows = analysis.port_breakdown(flows)
    activity_summary = analysis.summarise_indicator_activity(activity)
    ports_seen = sorted({f"{p['port']}/{p['protocol']}" for p in port_rows}
                        | {f"{p['port']}/{p['protocol']}" for p in activity_summary["ports"]})
    return {
        "window": window.describe(),
        "has_traffic": not flows.empty or not activity.empty,
        "long_flow_count": int(len(flows)),
        "ports_seen": ports_seen,
        "ports": port_rows,
        "classification": analysis.classify_flows(flows),
        "notable": analysis.notable_flows(flows),
        "active_periods": analysis.active_periods(flows),
        "activity": activity_summary,
        "upload_heavy_over_exfil_threshold": analysis.exfil_sized_flows(flows),
        "sources": sources or {"long_flow_summary": "live" if not flows.empty else "none",
                               "subscriber_activity_1m": "live" if not activity.empty else "none"},
    }


def indicator_flows(host: str, server_ips: list[str], window: CaseWindow, case_rows: list[dict] | None = None,
                    own_name: str | None = None) -> dict:
    """Ports, names, timing and traffic shape between the host and the
    flagged IP(s), over the wide window (fixes A, B, C, E). When a live table
    has nothing (usually retention), the feed's own rows for that table are
    used instead and labelled as such (task 2, 1.2)."""
    if not server_ips:
        return {"error": "no server IP identified for this indicator - cannot query flows"}
    flows = db.fetch_indicator_long_flows(host, server_ips, window.flow_start, window.flow_end)
    activity = db.fetch_indicator_activity(host, server_ips, window.activity_start, window.activity_end, own_name)
    result = build_with_fallback(flows, activity, window, case_rows or [])
    result["retention_cut"] = retention_cut(window, result)
    return result


RETENTION_EDGE_DAYS = 3  # evidence this close to the table's oldest data may have been cut off


def retention_cut(window: CaseWindow, flows_result: dict, earliest: datetime | None = None) -> str | None:
    """The date long_flow_summary's data now starts, if that cuts into this
    case: the window reaches back before it and the host's earliest flow
    sits at that edge. With no flows there is nothing at the edge, so no
    claim is made. Raising the lookback cannot recover this; the flows are
    gone from the table."""
    if earliest is None:
        try:
            earliest = db.fetch_long_flow_retention_start()
        except Exception:  # noqa: BLE001 - a missing note is not worth failing the case
            return None
    if earliest is None:
        return None
    earliest = earliest.replace(tzinfo=timezone.utc) if earliest.tzinfo is None else earliest
    if window.flow_start >= earliest:
        return None
    periods = flows_result.get("active_periods") or []
    if not periods:
        return None
    first = datetime.fromisoformat(periods[0]["start"]).replace(tzinfo=timezone.utc)
    if (first - earliest).days > RETENTION_EDGE_DAYS:
        return None
    return f"{earliest:%Y-%m-%d}"


def build_with_fallback(flows: pd.DataFrame, activity: pd.DataFrame, window: CaseWindow,
                        case_rows: list[dict]) -> dict:
    """Swap in the feed's rows for any table the live query found empty."""
    sources = {"long_flow_summary": "live", "subscriber_activity_1m": "live"}
    if flows.empty:
        flows = evidence.feed_long_flows(case_rows)
        sources["long_flow_summary"] = "feed" if not flows.empty else "none"
    if activity.empty:
        activity = evidence.feed_activity(case_rows)
        sources["subscriber_activity_1m"] = "feed" if not activity.empty else "none"
    result = build_indicator_flows(flows, activity, window, sources)
    result["checked"] = _checked_notes(window, sources)
    return result


def _checked_notes(window: CaseWindow, sources: dict) -> list[str]:
    """What was looked at, for the INSUFFICIENT_DATA explanation."""
    described = window.describe()
    notes = [f"long_flow_summary queried live over {described['long_flow_summary']}: "
             + ("rows found" if sources["long_flow_summary"] == "live" else "no rows")]
    if window.activity_start is None:
        notes.append("subscriber_activity_1m: match is outside its retention (about 15 days), not queried")
    else:
        notes.append(f"subscriber_activity_1m queried live over {described['subscriber_activity_1m']}: "
                     + ("rows found" if sources["subscriber_activity_1m"] == "live" else "no rows"))
    feed_used = [t for t, source in sources.items() if source == "feed"]
    notes.append("IOC feed evidence: " + (f"used for {', '.join(feed_used)}" if feed_used else "no usable rows"))
    return notes


# --- step 5: names the host actually used on the flagged IP (task 2, 2.1) ------------------

def _name_key(sni: str, dns: str, root: str) -> str:
    """The best single name for a row: SNI unless hidden by ECH, then DNS, then root domain."""
    if sni and not dfeat.is_ech_placeholder(sni):
        return sni
    return dns or root or ""


def summarise_names(frame: pd.DataFrame, source: str) -> dict:
    """Per-name minutes and bytes from (sni, dns, root_domain, port, protocol) rows."""
    if frame.empty:
        return {"source": "none", "names": [], "ech_hidden_minutes": 0, "registered_domains": []}
    frame = frame.fillna({"sni": "", "dns": "", "root_domain": ""})
    if "near_match_minutes" not in frame:
        frame = frame.assign(near_match_minutes=0)
    ech = frame["sni"].map(dfeat.is_ech_placeholder)
    ech_minutes = int(frame.loc[ech, "minutes"].sum())
    frame = frame.assign(
        name=[_name_key(a, b, c) for a, b, c in zip(frame["sni"], frame["dns"], frame["root_domain"])],
        port=[f"{int(p)}/{knowledge.protocol_name(t)}" for p, t in zip(frame["server_port"], frame["transport_protocol"])],
        ech=ech,
    )
    names = []
    for name, group in frame.groupby("name"):
        names.append({
            "name": name or "(no name)",
            "registered_domain": dfeat.registered_domain(name) if name else "",
            "ech_hidden": bool(group["ech"].all()),
            "ports": sorted(set(group["port"])),
            "minutes": int(group["minutes"].sum()),
            "near_match_minutes": int(group["near_match_minutes"].sum()),
            "up_bytes": int(group["up_bytes"].sum()),
            "down_bytes": int(group["down_bytes"].sum()),
        })
    names.sort(key=lambda n: -n["minutes"])
    registered = [n["registered_domain"] for n in names
                  if n["registered_domain"] and not n["ech_hidden"] and n["name"] != "(no name)"]
    return {"source": source, "names": names[:MAX_LISTED_NAMES], "ech_hidden_minutes": ech_minutes,
            "registered_domains": list(dict.fromkeys(registered))}


def indicator_names(host: str, server_ips: list[str], window: CaseWindow, case_rows: list[dict],
                    own_name: str | None = None) -> dict:
    """The names the host used on the flagged IP(s): SNI, DNS and root domain
    from subscriber_activity_1m, with minutes near each feed match. Falls
    back to the names in the feed's own rows."""
    if not server_ips:
        return {"source": "none", "names": [], "ech_hidden_minutes": 0, "registered_domains": []}
    windows = evidence.match_windows(case_rows, config.NAMES_WINDOW_MINUTES)
    live = db.fetch_indicator_names(host, server_ips, window.activity_start, window.activity_end, windows, own_name)
    if not live.empty:
        return summarise_names(live, "live")
    try:
        flow_names = db.fetch_indicator_flow_names(host, server_ips, window.flow_start, window.flow_end)
    except Exception:  # noqa: BLE001 - fall through to the feed's names
        flow_names = pd.DataFrame()
    flow_names = flow_names[(flow_names["sni_name"] != "") | (flow_names["dns_name"] != "")] if not flow_names.empty else flow_names
    # Per-minute data has expired: combine both remaining sources, since each
    # can hold names the other lacks (flow attributes can be only an ECH
    # placeholder while the feed kept the real SNI).
    frames = []
    if not flow_names.empty:
        frames.append(pd.DataFrame({"sni": flow_names["sni_name"], "dns": flow_names["dns_name"],
                                    "root_domain": [dfeat.registered_domain(a or b) for a, b in
                                                    zip(flow_names["sni_name"], flow_names["dns_name"])],
                                    "server_port": 0, "transport_protocol": 6, "minutes": flow_names["flows"],
                                    "near_match_minutes": 0, "up_bytes": flow_names["up_bytes"],
                                    "down_bytes": flow_names["down_bytes"]}))
    feed = evidence.feed_activity(case_rows)
    if not feed.empty:
        frames.append(feed.assign(near_match_minutes=feed["minutes"]))
    if not frames:
        return summarise_names(pd.DataFrame(), "none")
    source = "feed" if len(frames) == 1 and flow_names.empty else ("long_flows" if len(frames) == 1 else "long_flows+feed")
    return summarise_names(pd.concat(frames, ignore_index=True), source)


# --- step 8: what else lives on the flagged IP (task 2, 2.2) ------------------------------

def _campus_period(window: CaseWindow, now: datetime | None = None,
                   match_end: datetime | None = None) -> tuple[datetime, datetime, bool]:
    """One chunk of at most CAMPUS_LOOKUP_DAYS for campus-wide lookups:
    ending a day after the last match if that is within retention, else the
    most recent days. The flag is True when the period is 'now', not the
    match time."""
    now = now or datetime.now(timezone.utc)
    span = timedelta(days=config.CAMPUS_LOOKUP_DAYS)
    if window.activity_start is not None and match_end and match_end >= window.activity_start:
        end = min(match_end + timedelta(days=1), now)
        return max(end - span, window.activity_start), end, False
    return now - span, now, True


def _match_end(identity: dict | None) -> datetime | None:
    value = (identity or {}).get("evidence_last_seen")
    return datetime.fromisoformat(value) if value else None


def summarise_names_on_ip(frame: pd.DataFrame, host_count: int | None) -> dict:
    """Distinct root domains on the IP and how many campus hosts used each."""
    domains: dict[str, dict] = {}
    ech_hosts = 0
    for row in frame.fillna("").itertuples(index=False):
        if dfeat.is_ech_placeholder(row.sni) and not row.dns:
            ech_hosts = max(ech_hosts, int(row.hosts))
            continue
        root = row.root_domain or dfeat.registered_domain(row.dns or row.sni)
        if not root:
            continue
        entry = domains.setdefault(root, {"root_domain": root, "hosts": 0, "names": []})
        entry["hosts"] = max(entry["hosts"], int(row.hosts))  # a lower bound: hosts can repeat across names
        for name in (row.sni, row.dns):
            if name and not dfeat.is_ech_placeholder(name) and name not in entry["names"] and len(entry["names"]) < 3:
                entry["names"].append(name)
    listed = sorted(domains.values(), key=lambda d: -d["hosts"])
    return {"distinct_root_domains": len(listed), "campus_hosts": host_count,
            "ech_hidden_hosts": ech_hosts, "domains": listed[:MAX_LISTED_NAMES]}


def names_on_ip(server_ip: str, window: CaseWindow, identity: dict | None = None) -> dict:
    """Campus-wide: names seen on the flagged IP and how many hosts used each.
    subscriber_activity_1m has no index on server_ip, so it is queried one
    day at a time (db.CAMPUS_CHUNK_DAYS); long_flow_summary's attributes.sni
    adds names for flows over 1 MB. Host counts are per-day maxima (a lower
    bound)."""
    start, end, is_current = _campus_period(window, match_end=_match_end(identity))
    frames = []
    host_count = 0
    for day_start, day_end in db.time_chunks(start, end, db.CAMPUS_CHUNK_DAYS):
        day = db.fetch_names_on_ip(server_ip, day_start, day_end)
        if not day.empty:
            frames.append(day)
        host_count = max(host_count, db.fetch_ip_host_count(server_ip, day_start, day_end))
    frame = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(
        columns=["root_domain", "sni", "dns", "hosts", "minutes"])
    long_flows = db.fetch_names_on_ip_long_flows(server_ip, start, end)
    if not long_flows.empty:
        extra = pd.DataFrame({"root_domain": [dfeat.registered_domain(n) for n in long_flows["sni_name"]],
                              "sni": long_flows["sni_name"], "dns": "", "hosts": long_flows["hosts"], "minutes": 0})
        frame = pd.concat([frame, extra], ignore_index=True)
    period = f"{start:%Y-%m-%d %H:%M} to {end:%Y-%m-%d %H:%M} UTC"
    return {"server_ip": server_ip, "period": period, "period_is_current": is_current,
            "sources": "subscriber_activity_1m (per day) and long_flow_summary attributes.sni",
            **summarise_names_on_ip(frame, host_count)}


def ip_asn(server_ip: str, flows_result: dict, server_ips: dict) -> dict:
    """ASN for the flagged IP: from the flow rows if present, else canopus.asn.
    Also says whether the IP is in a known shared range."""
    asn = ""
    org = ""
    for server in flows_result.get("activity", {}).get("servers", []):
        if server["server_ip"] == server_ip and server.get("asn"):
            asn = server["asn"][0]
            org = (server.get("asn_org") or [""])[0]
    for entry in server_ips.get("ips", []):
        if entry["server_ip"] == server_ip and not org and entry.get("asn_org"):
            org = entry["asn_org"][0]
    source = "flow rows" if asn else ""
    if not asn:
        try:
            looked_up = db.fetch_asn(server_ip)
        except Exception:  # noqa: BLE001 - the ASN is a nice-to-have
            looked_up = None
        if looked_up:
            asn, org, source = looked_up["asn"], looked_up["asn_org"], f"canopus.asn ({looked_up['cidr']})"
    country = ""
    for server in flows_result.get("activity", {}).get("servers", []):
        if server["server_ip"] == server_ip and server.get("country"):
            country = server["country"][0]
    if not country:
        try:
            geo = db.fetch_geo(server_ip)
        except Exception:  # noqa: BLE001 - country is a nice-to-have
            geo = None
        if geo:
            country = geo["country"]
    return {"server_ip": server_ip, "asn": asn, "asn_org": org, "source": source, "country": country,
            "shared_asn": dfeat.asn_kind(asn), "shared_range": dfeat.ip_range_match(server_ip)}


# --- step 4: domain features (task 2, 2.3) ----------------------------------------------

def domain_features(names: list[str], window: CaseWindow, feed_indicators: set[str], client_ip: str = "",
                    identity: dict | None = None) -> list[dict]:
    """Offline features plus campus popularity and first seen on campus
    (within retention) for each registered domain. Popularity counts OTHER
    hosts, over the match period if it is within retention, else the most
    recent CAMPUS_LOOKUP_DAYS (labelled as current)."""
    registered = []
    for name in names:
        domain = dfeat.registered_domain(name)
        if domain and not dfeat.is_ech_placeholder(domain) and domain not in registered:
            registered.append(domain)
    registered = registered[:MAX_FEATURE_DOMAINS]
    if not registered:
        return []

    now = datetime.now(timezone.utc)
    popularity: dict[str, int] = {}
    first_seen: dict[str, str] = {}
    lookup_error = None
    start, end, is_current = _campus_period(window, now, _match_end(identity))
    try:
        frame = db.fetch_domain_popularity(registered, start, end, client_ip)
        popularity = {str(r.root_domain): int(r.other_hosts) for r in frame.itertuples(index=False)}
        frame = db.fetch_domain_first_seen(registered, now - timedelta(days=config.ACTIVITY_RETENTION_DAYS), now)
        first_seen = {str(r.root_domain): analysis.fmt_time(r.first_time) for r in frame.itertuples(index=False)}
    except Exception as exc:  # noqa: BLE001 - offline features still help without these
        lookup_error = str(exc)

    retention_start = now - timedelta(days=config.ACTIVITY_RETENTION_DAYS)
    results = []
    for domain in registered:
        entry = dfeat.features(domain)
        entry["other_campus_hosts"] = None if lookup_error else popularity.get(domain, 0)
        entry["campus_period"] = f"{start:%Y-%m-%d} to {end:%Y-%m-%d}"
        entry["campus_period_is_current"] = is_current
        entry["campus_first_seen"] = first_seen.get(domain)
        entry["new_on_campus"] = _is_new(first_seen.get(domain), retention_start)
        entry["flagged_in_feed"] = domain in feed_indicators or any(
            dfeat.registered_domain(i) == domain for i in feed_indicators)
        if lookup_error:
            entry["lookup_error"] = lookup_error[:200]
        results.append(entry)
    return results


def linked_domain_checks(domains: list[str], identities: list[dict]) -> dict[str, dict]:
    """Campus checks for domains linked across cases (correlation.py): how
    many campus hosts used each, around the latest linked match if it is
    within retention (else the most recent days), and when it was first seen
    on campus within retention."""
    if not domains:
        return {}
    latest = max(identities, key=lambda i: i.get("evidence_last_seen") or "")
    window = evidence.case_window(latest)
    now = datetime.now(timezone.utc)
    start, end, is_current = _campus_period(window, now, _match_end(latest))
    hosts = db.fetch_domain_popularity(domains, start, end)
    first = db.fetch_domain_first_seen(domains, now - timedelta(days=config.ACTIVITY_RETENTION_DAYS), now)
    host_counts = {str(r.root_domain): int(r.hosts) for r in hosts.itertuples(index=False)} if not hosts.empty else {}
    first_seen = ({str(r.root_domain): analysis.fmt_time(r.first_time) for r in first.itertuples(index=False)}
                  if not first.empty else {})
    period = f"{start:%Y-%m-%d} to {end:%Y-%m-%d}"
    return {d: {"campus_hosts": host_counts.get(d, 0), "campus_period": period, "campus_period_is_current": is_current,
                "campus_first_seen": first_seen.get(d)} for d in domains}


def _is_new(first_seen: str | None, retention_start: datetime) -> bool | None:
    """True if the domain first appeared more than 2 days into retention
    (it was not already there at the start)."""
    if not first_seen:
        return None
    first = datetime.fromisoformat(first_seen).replace(tzinfo=timezone.utc)
    return first > retention_start + timedelta(days=2)


# --- model-callable follow-ups (task 2, part 3) ----------------------------------------

def _parse_when(text: str) -> datetime:
    return datetime.fromisoformat(text.strip().replace("T", " ").replace("Z", "")).replace(tzinfo=timezone.utc)


def timeline_around(client_ip: str, when: str, minutes) -> dict:
    """What the host did in ±minutes around one time."""
    minutes = min(int(minutes or 10), db.MAX_TIMELINE_MINUTES // 2)
    centre = _parse_when(when)
    start, end = centre - timedelta(minutes=minutes), centre + timedelta(minutes=minutes)
    frame = db.fetch_host_timeline(client_ip, start, end)
    frame = frame[frame["server_ip"].astype(str) != ""] if not frame.empty else frame
    rows = [
        f"{r.root_domain or '(no domain)'} sni={r.sni or '-'} {r.server_ip}:{int(r.server_port)}/"
        f"{knowledge.protocol_name(r.transport_protocol)} {int(r.minutes)} min, up {analysis.fmt_bytes(r.up_bytes)}, "
        f"down {analysis.fmt_bytes(r.down_bytes)}, {analysis.fmt_time(r.first_time)} to {analysis.fmt_time(r.last_time)}"
        for r in frame.itertuples(index=False)
    ]
    return {"window": f"{start:%Y-%m-%d %H:%M} to {end:%Y-%m-%d %H:%M} UTC",
            "distinct_destinations": int(frame["server_ip"].nunique()) if not frame.empty else 0,
            "distinct_root_domains": int(frame["root_domain"].nunique()) if not frame.empty else 0,
            "destinations_by_bytes": rows or ["(no activity in this window - outside retention or idle)"]}


def host_baseline(client_ip: str, days) -> dict:
    """The host's normal daily volume, destination count and active hours."""
    days = min(int(days or 5), MAX_BASELINE_DAYS)
    now = datetime.now(timezone.utc)
    frame = db.fetch_host_baseline(client_ip, now - timedelta(days=days), now)
    if frame.empty:
        return {"days": days, "per_day": ["(no activity in retention)"]}
    per_day = frame.groupby("day", as_index=False).agg(
        server_ips=("server_ips", "max"), root_domains=("root_domains", "max"), minutes=("minutes", "sum"),
        up_bytes=("up_bytes", "sum"), down_bytes=("down_bytes", "sum"),
        hours=("hours", lambda hs: sorted({int(h) for arr in hs for h in arr})))
    lines = [
        f"{r.day}: {r.server_ips} server IPs, {r.root_domains} root domains, {r.minutes} active minutes, "
        f"up {analysis.fmt_bytes(r.up_bytes)}, down {analysis.fmt_bytes(r.down_bytes)}, "
        f"active UTC hours {r.hours[0]}-{r.hours[-1]} ({len(r.hours)} of 24)"
        for r in per_day.itertuples(index=False)
    ]
    return {"days": days,
            "median_daily_up": analysis.fmt_bytes(per_day["up_bytes"].median()),
            "median_daily_down": analysis.fmt_bytes(per_day["down_bytes"].median()),
            "median_daily_server_ips": float(per_day["server_ips"].median()),
            "per_day": lines}


def _day_summary(client_ip: str, server_ips: list[str], day: date) -> dict:
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    flows = db.fetch_indicator_long_flows(client_ip, server_ips, start, end)
    activity = pd.DataFrame()
    if start >= datetime.now(timezone.utc) - timedelta(days=config.ACTIVITY_RETENTION_DAYS):
        activity = db.fetch_indicator_activity(client_ip, server_ips, start, end)
    act = analysis.summarise_indicator_activity(activity)
    return {
        "date": str(day),
        "long_flows": int(len(flows)),
        "ports": [f"{p['port']}/{p['protocol']}: {p['flows']} flow(s), up {analysis.fmt_bytes(p['up_bytes'])}, "
                  f"down {analysis.fmt_bytes(p['down_bytes'])}" for p in analysis.port_breakdown(flows)],
        "pattern": analysis.classify_flows(flows)["pattern"],
        "active_minutes": act["active_minutes"],
        "names": [n for s in act["servers"] for n in s["names"]][:10],
    }


def compare_sessions(client_ip: str, server_ips: list[str], date_a: str, date_b: str) -> dict:
    """The host's traffic with the flagged IP on two dates, side by side."""
    if not server_ips:
        return {"error": "no flagged IP for this case"}
    days = [date.fromisoformat(d.strip()[:10]) for d in (date_a, date_b)]
    return {"a": _day_summary(client_ip, server_ips, days[0]), "b": _day_summary(client_ip, server_ips, days[1])}


# --- task 3: contact pattern (per-minute), apps, DNS, load ------------------------------

def _minutes(start: datetime, end: datetime) -> float:
    return (end - start).total_seconds() / 60


def beacon_analysis(host: str, server_ips: list[str], port: int | None, window: CaseWindow,
                    case_rows: list[dict] | None = None) -> dict:
    """Contact pattern with the flagged IP from per-minute data
    (subscriber_activity_1m). For matches past its 15-day retention: the
    5-minute table (no port, coarser, and it drops '_unknown' traffic, so it
    only sees labelled apps), then the IOC feed's own matched minutes. Never
    from long_flow_summary."""
    if not server_ips:
        return beacon.analyse(pd.DataFrame(), 1, 1, "none")
    now = datetime.now(timezone.utc)
    if window.activity_start is not None:
        end = min(window.activity_end, now)
        frame = db.fetch_contact_series_1m(host, server_ips, port, window.activity_start, end)
        if not frame.empty:
            result = beacon.analyse(frame, 1, _minutes(window.activity_start, end), "subscriber_activity_1m")
            result["window"] = f"{window.activity_start:%Y-%m-%d} to {end:%Y-%m-%d}"
            return result
    end = min(window.flow_end, now)
    frame = db.fetch_contact_series_5m(host, server_ips, window.flow_start, end)
    if not frame.empty:
        result = beacon.analyse(frame, 5, _minutes(window.flow_start, end), "app_subscriber_server_enriched_5m")
        result["window"] = f"{window.flow_start:%Y-%m-%d} to {end:%Y-%m-%d}"
        result["note"] = ("past subscriber_activity_1m's 15-day retention, so the 5-minute table was used; it only "
                          "holds traffic SuperNetFlow labelled as an app")
        return result
    feed = evidence.feed_minutes(case_rows or [], server_ips)
    result = beacon.analyse(feed, 1, max(len(feed), 1), "IOC feed")
    result["note"] = ("per-minute data has expired and the 5-minute table has no labelled traffic to the IP, so "
                      "this uses only the feed's own matched minutes, not re-queried: it cannot show a pattern "
                      "outside those minutes")
    return result


def _explained_label(frame: pd.DataFrame) -> tuple[str | None, str | None]:
    """(explanation, remote-access app) from app labels on the host's traffic
    to the flagged IP, most-used first."""
    remote = None
    for row in frame.sort_values("minutes", ascending=False).itertuples(index=False):
        kind = knowledge.app_class(row.application, row.application_category, config.ORG_NAME)
        if kind == "remote_access" and not remote:
            remote = f"{row.application} ({row.application_category})"
        if kind in ("benign", "vendor", "privacy_vpn"):
            return f"SuperNetFlow classifies it as {row.application} ({row.application_category})", remote
    return None, remote


def app_context_for_indicator(host: str, server_ips: list[str], window: CaseWindow, identity: dict) -> dict:
    """Does SuperNetFlow tie the flagged IP to a known app, for this host or
    campus-wide, and was it part of a recognised app session?"""
    if not server_ips:
        return {"explained_by": None}
    now = datetime.now(timezone.utc)
    end = min(window.flow_end, now)
    host_apps = db.fetch_indicator_apps(host, server_ips, window.flow_start, end)
    if not host_apps.empty:  # chunks repeat labels: re-aggregate
        host_apps = host_apps.groupby(["application", "application_category"], as_index=False)[["buckets", "minutes"]].sum()
    host_sessions = db.fetch_ux_sessions(host, server_ips, window.flow_start, end)
    match_end = _match_end(identity) or end
    campus_start, campus_end = match_end - timedelta(days=7), min(match_end + timedelta(days=1), now)
    campus_apps = db.fetch_server_apps_campus(server_ips, campus_start, campus_end)
    campus_sessions = db.fetch_ux_sessions(None, server_ips, campus_start, campus_end)

    explained, remote = (None, None)
    if not host_apps.empty:
        explained, remote = _explained_label(host_apps)
    if not host_sessions.empty:
        top = host_sessions.iloc[0]
        explained = (f"part of {int(host_sessions['sessions'].sum())} recognised {top['type']} session(s) "
                     f"({top['provider']})")
    return {
        "host_apps": [{"application": r.application, "category": r.application_category, "minutes": int(r.minutes),
                       "class": knowledge.app_class(r.application, r.application_category, config.ORG_NAME)}
                      for r in host_apps.sort_values("minutes", ascending=False).head(5).itertuples(index=False)]
        if not host_apps.empty else [],
        "host_sessions": _session_rows(host_sessions),
        "campus_apps": [{"application": r.application, "category": r.application_category,
                         "peak_hosts": int(r.peak_hosts)} for r in campus_apps.head(5).itertuples(index=False)]
        if not campus_apps.empty else [],
        "campus_sessions": _session_rows(campus_sessions),
        "explained_by": explained,
        "remote_access_app": remote,
        "sources": "app_subscriber_server_enriched_5m, ux_sessions, app_server_enriched_1h",
    }


def _session_rows(frame: pd.DataFrame) -> list[dict]:
    if frame.empty:
        return []
    return [{"type": r.type, "provider": r.provider, "sessions": int(r.sessions), "hosts": int(r.hosts)}
            for r in frame.head(5).itertuples(index=False)]


def host_applications(host: str, window: CaseWindow) -> dict:
    """What apps the host uses (subscriber_activity_1m) and which platform its
    user agents point to (subscriber_activity_1m and long_flow_summary)."""
    now = datetime.now(timezone.utc)
    activity_end = min(window.activity_end, now) if window.activity_end else None
    apps = db.fetch_host_applications(host, window.activity_start, activity_end)
    if not apps.empty:  # chunks repeat labels: re-aggregate
        apps = apps.groupby(["application_category", "application"], as_index=False)[["minutes", "up_bytes", "down_bytes"]].sum()
    agents = db.fetch_host_user_agents(host, window.activity_start, activity_end, window.flow_start,
                                       min(window.flow_end, now))
    categories = []
    remote = []
    relays = []
    if not apps.empty:
        by_category = apps.groupby("application_category")["minutes"].sum().sort_values(ascending=False)
        for category, minutes in by_category.head(6).items():
            top = apps[apps["application_category"] == category].sort_values("minutes", ascending=False)
            categories.append({"category": category, "minutes": int(minutes),
                               "apps": [a for a in top["application"].head(3) if a not in ("_unknown", "Web Browsing")]})
        for row in apps.itertuples(index=False):
            kind = knowledge.app_class(row.application, row.application_category)
            if kind == "remote_access":
                remote.append(row.application)
            elif kind == "privacy_vpn":
                relays.append(row.application)
    platforms: dict[str, int] = {}
    for row in agents.itertuples(index=False):
        platform = analysis.platform_from_user_agent(row.agent)
        if platform:
            platforms[platform] = platforms.get(platform, 0) + int(row.minutes)
    return {"categories": categories, "remote_access_apps": sorted(set(remote)),
            "privacy_vpn_apps": sorted(set(relays)),
            "user_agent_platforms": dict(sorted(platforms.items(), key=lambda kv: -kv[1])),
            "user_agents_seen": int(len(agents)),
            "sources": "subscriber_activity_1m (apps, user_agent), long_flow_summary (attributes.http_user_agent)"}


RARE_RESOLVER_MAX_CLIENTS = 2      # a DNS server this few campus hosts use is unusual
UNANSWERED_RATIO_MULTIPLE = 3.0    # host's unanswered share this many times the campus median ...
UNANSWERED_RATIO_MIN = 0.2         # ... and at least this high counts as unusual


def host_dns_behaviour(host: str, identity: dict) -> dict:
    """External resolvers the host asks directly (dns_tuple), how common each
    is on campus, and the host's unanswered share against the campus median.
    dns_tuple has no names and no response codes here, so no NXDOMAIN rate."""
    now = datetime.now(timezone.utc)
    match_end = _match_end(identity) or now
    end = min(match_end + timedelta(days=1), now)
    start = end - timedelta(days=14)
    frame = db.fetch_host_dns(host, start, end)
    period = f"{start:%Y-%m-%d} to {end:%Y-%m-%d}"
    if frame.empty:
        return {"present": False, "period": period,
                "note": "no direct external DNS seen (the host uses the campus resolvers, which the sensor does not see)"}
    baseline_start = end - timedelta(days=1)
    clients, campus_median = db.fetch_dns_campus_baseline(list(frame["server_ip"]), baseline_start, end)
    client_counts = dict(zip(clients["server_ip"], clients["clients"])) if not clients.empty else {}
    resolvers = []
    for row in frame.itertuples(index=False):
        public = row.server_ip in knowledge.PUBLIC_RESOLVERS
        count = int(client_counts.get(row.server_ip, 0))
        entry = {"server_ip": row.server_ip, "answered": int(row.answered), "unanswered": int(row.unanswered),
                 "campus_clients": count, "public_resolver": knowledge.PUBLIC_RESOLVERS.get(row.server_ip),
                 "rare": (not public) and count <= RARE_RESOLVER_MAX_CLIENTS,
                 "authoritative": knowledge.authoritative_dns(row.server_ip)}
        if entry["rare"]:  # name who runs an unusual DNS server rather than just "a server few hosts use"
            try:
                asn = db.fetch_asn(row.server_ip)
            except Exception:  # noqa: BLE001 - the ASN only improves the wording
                asn = None
            entry["asn"] = asn["asn"] if asn else ""
            entry["asn_org"] = asn["asn_org"] if asn else ""
        resolvers.append(entry)
    try:
        public_share = db.fetch_dns_public_only_share(list(knowledge.PUBLIC_RESOLVERS), baseline_start, end)
    except Exception:  # noqa: BLE001 - only used for wording
        public_share = None
    answered = int(frame["answered"].sum())
    unanswered = int(frame["unanswered"].sum())
    ratio = unanswered / max(answered + unanswered, 1)
    high = (campus_median is not None and ratio >= UNANSWERED_RATIO_MIN
            and ratio >= UNANSWERED_RATIO_MULTIPLE * max(campus_median, 0.01))
    return {"present": True, "period": period, "resolvers": resolvers[:8],
            "unanswered_ratio": round(ratio, 3), "campus_median_unanswered_ratio":
                round(campus_median, 3) if campus_median is not None else None,
            "unanswered_high": bool(high),
            "rare_resolvers": [r["server_ip"] for r in resolvers if r["rare"]],
            "rare_resolver_details": [r for r in resolvers if r["rare"]],
            "campus_public_only_share": round(public_share, 2) if public_share is not None else None,
            "sources": "dns_tuple (no names or response codes here)"}


def host_load_baseline(host: str, identity: dict) -> dict:
    """The host's hourly load over two weeks up to the match
    (subscriber_ip_load_enriched_1h, which keeps long history): night vs
    daytime volume, normal daily volume, and whether the match hours stand out.
    Active minutes are not used: every host is 'active' 60 minutes of every
    hour from background traffic alone, so only volume tells hosts apart."""
    now = datetime.now(timezone.utc)
    match_end = _match_end(identity) or now
    end = min(match_end + timedelta(days=1), now)
    start = end - timedelta(days=14)
    frame = db.fetch_host_load_1h(host, start, end)
    result = {"period": f"{start:%Y-%m-%d} to {end:%Y-%m-%d}", "sources": "subscriber_ip_load_enriched_1h"}
    if frame.empty:
        return result
    stamps = pd.to_datetime(frame["time"])
    stamps = stamps.dt.tz_localize("UTC") if stamps.dt.tz is None else stamps
    local_hour = stamps.dt.tz_convert(config.LOCAL_TIMEZONE).dt.hour
    frame = frame.assign(day=stamps.dt.date, total=frame["up_bytes"] + frame["down_bytes"])
    night = frame.loc[local_hour < NIGHT_END_HOUR, "total"]
    day = frame.loc[(local_hour >= DAY_START_HOUR) & (local_hour < DAY_END_HOUR), "total"]
    if not night.empty and not day.empty:
        result["night_bytes_per_hour"] = int(night.median())
        result["day_bytes_per_hour"] = int(day.median())
        result["night_day_ratio"] = round(float(night.median()) / max(float(day.median()), 1.0), 2)
    daily = frame.groupby("day")[["up_bytes", "down_bytes"]].sum()
    result["median_daily_up"] = int(daily["up_bytes"].median())
    result["median_daily_down"] = int(daily["down_bytes"].median())
    first = _match_start(identity)
    if first:
        in_match = frame[(pd.to_datetime(frame["time"], utc=True) >= first.replace(minute=0, second=0, microsecond=0))
                         & (pd.to_datetime(frame["time"], utc=True) <= match_end)]
        typical = float(frame["total"].median())
        if not in_match.empty and typical > 0:
            result["match_hours_vs_typical"] = round(float(in_match["total"].median()) / typical, 2)
    return result


def _match_start(identity: dict | None) -> datetime | None:
    value = (identity or {}).get("evidence_first_seen")
    return datetime.fromisoformat(value) if value else None


# --- step 7 --------------------------------------------------------------------

def host_other_traffic(host: str, window: CaseWindow, exclude_ips: list[str] | None = None,
                       own_name: str | None = None, indicator_longest_sec: float | None = None,
                       load: dict | None = None) -> dict:
    """The host's top destinations, long-lived flows to other IPs, any
    destinations matching a known service profile, and uptime evidence."""
    exclude_ips = exclude_ips or []
    activity = db.fetch_host_activity(host, exclude_ips, window.activity_start, window.activity_end, own_name)
    long_flows = db.fetch_host_long_lived_flows(host, exclude_ips, window.flow_start, window.flow_end)
    longest = indicator_longest_sec
    if "max_duration_sec" in long_flows and not long_flows.empty:
        longest = max(longest or 0.0, float(long_flows["max_duration_sec"].max()))
    return {"window": window.describe(), **analysis.summarise_other_traffic(activity, long_flows),
            "uptime": host_uptime(longest, load)}


# Local hours for the night/day comparison.
NIGHT_END_HOUR = 6        # night = 00:00-06:00 local
DAY_START_HOUR = 9        # day = 09:00-21:00 local
DAY_END_HOUR = 21
# Night volume as a share of daytime volume. Measured on real hosts: a
# self-hosted server ran at 0.76, ordinary machines with background traffic
# at 0.20-0.36, a personal device that sleeps at 0.00.
BUSY_AT_NIGHT_RATIO = 0.5    # at or above: busy around the clock (server-like) ...
BUSY_NIGHT_MIN_BYTES = 50_000_000  # ... but only with real volume at night (50 MB an hour): an idle
                                   # host's trickle can be just as steady night and day
QUIET_AT_NIGHT_RATIO = 0.1   # at or below: used in waking hours only


def host_uptime(longest_connection_sec: float | None, load: dict | None) -> dict:
    """Is the host busy around the clock? Based on night vs daytime VOLUME
    (subscriber_ip_load_enriched_1h), because every connected host shows some
    traffic every hour. always_on: True = busy around the clock (server-like),
    False = used in waking hours, None = connected all the time but much
    quieter at night (background traffic, which says nothing about its role)."""
    load = load or {}
    ratio = load.get("night_day_ratio")
    always_on = None
    night = load.get("night_bytes_per_hour") or 0
    if ratio is not None and ratio >= BUSY_AT_NIGHT_RATIO and night >= BUSY_NIGHT_MIN_BYTES:
        always_on = True
    elif ratio is not None and ratio <= QUIET_AT_NIGHT_RATIO:
        always_on = False
    return {"longest_connection_sec": longest_connection_sec, "night_day_ratio": ratio,
            "night_bytes_per_hour": load.get("night_bytes_per_hour"),
            "day_bytes_per_hour": load.get("day_bytes_per_hour"), "always_on": always_on}


# --- step 8 --------------------------------------------------------------------

def indicator_peers(server_ip: str, port: int | None, identity: dict,
                    asset_index: dict[str, list[dict]]) -> dict:
    """Internal hosts contacting the flagged IP, each cross-checked against the
    whole feed: peers that are also flagged by other IOCs point to a
    multi-host compromise rather than shared infrastructure."""
    frame = db.fetch_peers(server_ip, port)
    this_asset = identity["affected_asset"]
    this_malware = identity.get("malware")
    hosts = []
    flagged_count = 0
    for row in frame.itertuples(index=False):
        host = {
            "host": str(row.client_ip),
            "is_this_case": str(row.client_ip) == this_asset,
            "flows": int(row.flows),
            "first_seen": analysis.fmt_time(row.first_seen),
            "last_seen": analysis.fmt_time(row.last_seen),
            "up_bytes": int(row.up_bytes),
            "down_bytes": int(row.down_bytes),
            "ports": sorted(int(p) for p in row.ports),
        }
        # Only OTHER indicators count: a peer flagged for this same indicator
        # is the same trigger, not independent evidence.
        other_matches = []
        if not host["is_this_case"]:
            other_matches = [m for m in asset_index.get(host["host"], []) if m["indicator"] != identity["indicator"]]
        if other_matches:
            flagged_count += 1
            host["also_flagged"] = [
                {"indicator": m["indicator"], "malware": m["malware"],
                 "same_malware_family": m["malware"] == this_malware}
                for m in other_matches[:5]
            ]
        hosts.append(host)
    return {
        "server_ip": server_ip,
        "server_port": port,
        "lookback_days": config.PEER_LOOKBACK_DAYS,
        "distinct_host_count": len(hosts),
        "other_host_count": sum(1 for h in hosts if not h["is_this_case"]),
        "peer_hosts_also_flagged": flagged_count,
        "hosts": hosts,
    }


def shared_infrastructure(server_ips: dict, flows_result: dict, expected: dict, peers: list[dict]) -> dict:
    """Fix F: combine the knowledge base, ASN organisation and peer count."""
    asn_orgs = []
    for entry in server_ips.get("ips", []):
        asn_orgs.extend(entry.get("asn_org", []))
    for server in flows_result.get("activity", {}).get("servers", []):
        asn_orgs.extend(server.get("asn_org", []))
    asn_orgs = list(dict.fromkeys(asn_orgs))

    valid_peers = [p for p in peers if "error" not in p]
    peer_count = max((p["distinct_host_count"] for p in valid_peers), default=None)
    flagged = sum(p["peer_hosts_also_flagged"] for p in valid_peers)
    result = analysis.shared_infrastructure(asn_orgs, expected.get("service"), peer_count, flagged)
    return {"asn_organisations": asn_orgs, **result}

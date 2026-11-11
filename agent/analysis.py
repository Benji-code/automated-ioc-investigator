"""Pure analysis of flow data: no database, no LLM.

long_flow_summary only stores flows over 1 MB, so the flow analysis here is
about large sessions (held open, upload-heavy, bulk). Contact cadence and
beacons are analysed on per-minute data in beacon.py.

db.py fetches pandas DataFrames, tools.py passes them here, and the results
go into the case file. Keeping these functions free of I/O lets the tests run
them on fake data.

Expected DataFrame columns:
  long flows (public.long_flow_summary): start, finish, duration_sec,
      server_ip, server_port, client_port, protocol, up_bytes, down_bytes,
      up_packets, down_packets, classifier, type
  indicator activity (subscriber_activity_1m, aggregated per day): day,
      server_ip, server_port, transport_protocol, sni, dns, root_domain,
      asn, asn_org, country, minutes, up_bytes, down_bytes, up_packets,
      down_packets, first_time, last_time
  other activity (subscriber_activity_1m, aggregated): root_domain,
      server_ip, server_port, transport_protocol, minutes, up_bytes, down_bytes
  other long flows (long_flow_summary, aggregated): server_ip, server_port,
      protocol, flows, total_duration_sec, up_bytes, down_bytes,
      first_start, last_finish
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from . import config, knowledge

HELD_OPEN_MIN_SEC = 3600        # a flow lasting an hour or more is "held open"
QUICK_RECONNECT_SEC = 60        # a gap this short between held-open flows is a reconnect
STEADY_RATE_CV = 0.25           # packet-rate spread across held-open flows below this = steady
UPLOAD_HEAVY_RATIO = 2.0        # up bytes at least twice down bytes
UPLOAD_HEAVY_MIN_BYTES = 100_000
ACTIVE_PERIOD_GAP_SEC = 3600    # flows less than an hour apart belong to one active period
MAX_LISTED_FLOWS = 5
MAX_LISTED_HELD_OPEN = 6
MAX_LISTED_DESTINATIONS = 10
MAX_LISTED_DOMAIN_NAMES = 20


# --- formatting ---------------------------------------------------------------

def fmt_bytes(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1000:
            return f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} TB"


def fmt_duration(seconds) -> str:
    seconds = abs(float(seconds or 0))
    if seconds < 120:
        return f"{seconds:.0f} s"
    minutes = seconds / 60
    if minutes < 120:
        return f"{minutes:.1f} min"
    hours = minutes / 60
    if hours < 48:
        return f"{hours:.1f} hours"
    return f"{hours / 24:.1f} days"


def fmt_time(value) -> str:
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return ""
    return pd.Timestamp(value).strftime("%Y-%m-%d %H:%M:%S")


def _clean(values) -> list[str]:
    """Non-empty, de-duplicated, order-preserved strings."""
    seen: dict[str, None] = {}
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text and text.lower() != "nan" and text not in seen:
            seen[text] = None
    return list(seen)


# --- per-flow helpers -----------------------------------------------------------

def flow_record(row) -> dict:
    """One long_flow_summary row as a plain dict, with the ratio and rates."""
    up = int(row.up_bytes or 0)
    down = int(row.down_bytes or 0)
    up_packets = int(row.up_packets or 0)
    down_packets = int(row.down_packets or 0)
    duration = float(row.duration_sec or 0)
    return {
        "start": fmt_time(row.start),
        "finish": fmt_time(row.finish),
        "duration_sec": round(duration, 1),
        "server_ip": str(row.server_ip),
        "server_port": int(row.server_port),
        "client_port": int(row.client_port),
        "protocol": knowledge.protocol_name(row.protocol),
        "up_bytes": up,
        "down_bytes": down,
        "up_packets": up_packets,
        "down_packets": down_packets,
        "up_down_ratio": round(up / max(down, 1), 2),
        "packets_per_sec_down": round(down_packets / duration, 2) if duration > 0 else None,
        "packets_per_sec_up": round(up_packets / duration, 2) if duration > 0 else None,
        "bytes_per_packet_down": round(down / down_packets, 1) if down_packets else None,
        "bytes_per_packet_up": round(up / up_packets, 1) if up_packets else None,
        "classifier": getattr(row, "classifier", None),
        "type": getattr(row, "type", None),
    }


def _regularity_score(gaps: np.ndarray) -> float:
    """100 = perfectly evenly spaced, 0 = wildly irregular (median gap vs MAD jitter)."""
    median = float(np.median(gaps))
    if median <= 0:
        return 0.0
    mad = float(np.median(np.abs(gaps - median)))
    return round(100.0 * (1.0 - min(mad / median, 1.0)), 1)


def _spread(values: pd.Series) -> float:
    """Coefficient of variation (0 = identical values)."""
    mean = float(values.mean())
    if mean <= 0:
        return 0.0
    return float(values.std(ddof=0) / mean)


# --- fix A: per-port breakdown ----------------------------------------------

def port_breakdown(flows: pd.DataFrame) -> list[dict]:
    """Flows, bytes, packets and total duration per server port (long_flow_summary)."""
    if flows.empty:
        return []
    rows = []
    with_proto = flows.assign(proto=flows["protocol"].map(knowledge.protocol_name))
    for (port, proto), group in with_proto.groupby(["server_port", "proto"]):
        rows.append({
            "port": int(port),
            "protocol": proto,
            "flows": int(len(group)),
            "up_bytes": int(group["up_bytes"].sum()),
            "down_bytes": int(group["down_bytes"].sum()),
            "up_packets": int(group["up_packets"].sum()),
            "down_packets": int(group["down_packets"].sum()),
            "total_duration_sec": round(float(group["duration_sec"].sum()), 1),
            "first_start": fmt_time(group["start"].min()),
            "last_finish": fmt_time(group["finish"].max()),
            "server_ips": _clean(group["server_ip"]),
        })
    rows.sort(key=lambda r: -(r["up_bytes"] + r["down_bytes"]))
    return rows


def activity_port_breakdown(activity: pd.DataFrame) -> list[dict]:
    """Active minutes, bytes and packets per server port (subscriber_activity_1m)."""
    if activity.empty:
        return []
    rows = []
    with_proto = activity.assign(proto=activity["transport_protocol"].map(knowledge.protocol_name))
    for (port, proto), group in with_proto.groupby(["server_port", "proto"]):
        rows.append({
            "port": int(port),
            "protocol": proto,
            "active_minutes": int(group["minutes"].sum()),
            "up_bytes": int(group["up_bytes"].sum()),
            "down_bytes": int(group["down_bytes"].sum()),
            "up_packets": int(group["up_packets"].sum()),
            "down_packets": int(group["down_packets"].sum()),
            "first_minute": fmt_time(group["first_time"].min()),
            "last_minute": fmt_time(group["last_time"].max()),
        })
    rows.sort(key=lambda r: -r["active_minutes"])
    return rows


# --- fix B: held-open connection vs repeated check-ins --------------------------

def _reconnect_gaps(held: pd.DataFrame) -> list[float]:
    """Seconds between one held-open flow's finish and the next one's start, per port."""
    gaps: list[float] = []
    for _, group in held.sort_values("start").groupby("server_port"):
        finishes = list(group["finish"])
        starts = list(group["start"])
        for previous_finish, next_start in zip(finishes[:-1], starts[1:]):
            gap = (pd.Timestamp(next_start) - pd.Timestamp(previous_finish)).total_seconds()
            if gap >= 0:
                gaps.append(round(gap, 1))
    return gaps


def _held_open_summary(held: pd.DataFrame) -> dict:
    held = held.sort_values("start")
    duration = held["duration_sec"].astype(float)
    rate_down = held["down_packets"] / duration
    rate_up = held["up_packets"] / duration
    bpp_down = held["down_bytes"] / held["down_packets"].clip(lower=1)
    bpp_up = held["up_bytes"] / held["up_packets"].clip(lower=1)
    gaps = _reconnect_gaps(held)
    quick = [g for g in gaps if g <= QUICK_RECONNECT_SEC]
    steady = _spread(rate_down) <= STEADY_RATE_CV and _spread(rate_up) <= STEADY_RATE_CV
    return {
        "count": int(len(held)),
        "min_duration_sec": round(float(duration.min()), 1),
        "max_duration_sec": round(float(duration.max()), 1),
        "total_duration_sec": round(float(duration.sum()), 1),
        "median_packets_per_sec_down": round(float(rate_down.median()), 2),
        "median_packets_per_sec_up": round(float(rate_up.median()), 2),
        "median_bytes_per_packet_down": round(float(bpp_down.median()), 1),
        "median_bytes_per_packet_up": round(float(bpp_up.median()), 1),
        "packet_rate_steady": bool(steady),
        "reconnect_gaps_sec": gaps,
        "quick_reconnects": len(quick),
        "median_quick_reconnect_sec": round(float(np.median(quick)), 1) if quick else None,
        "longest_gap_sec": max(gaps) if gaps else None,
        "flows": [flow_record(r) for r in held.head(MAX_LISTED_HELD_OPEN).itertuples(index=False)],
    }


def _pattern(n_held: int, n_other: int) -> tuple[str, str]:
    if n_held and n_other:
        return ("held_open_plus_sessions",
                f"Held-open connection ({n_held} long-lived flow(s) over 1 MB) plus {n_other} shorter large "
                "session(s).")
    if n_held:
        return ("held_open", f"Held-open connection ({n_held} long-lived flow(s) over 1 MB).")
    return ("sessions", f"{n_other} large session(s) over 1 MB.")


def classify_flows(flows: pd.DataFrame) -> dict:
    """Describe the LARGE flows only: held-open connections and other
    sessions over 1 MB. long_flow_summary does not store flows under 1 MB,
    so it cannot show check-ins or beacons, and no cadence is scored here:
    that is beacon.py's job, on per-minute data."""
    if flows.empty:
        return {"pattern": "no_flows", "description": "No flows over 1 MB in long_flow_summary."}
    durations = flows["duration_sec"].astype(float)
    held = flows[durations >= HELD_OPEN_MIN_SEC]
    other = flows[durations < HELD_OPEN_MIN_SEC]
    pattern, description = _pattern(len(held), len(other))
    return {
        "pattern": pattern,
        "description": description,
        "held_open": _held_open_summary(held) if not held.empty else None,
        "other_flows": {"count": int(len(other))},
    }


def active_periods(flows: pd.DataFrame, max_gap_sec: float = ACTIVE_PERIOD_GAP_SEC) -> list[dict]:
    """Merge flows into periods of activity (flows less than max_gap_sec apart)."""
    if flows.empty:
        return []
    periods: list[dict] = []
    for row in flows.sort_values("start").itertuples(index=False):
        start = pd.Timestamp(row.start)
        finish = pd.Timestamp(row.finish)
        if periods and (start - periods[-1]["_end"]).total_seconds() <= max_gap_sec:
            periods[-1]["_end"] = max(periods[-1]["_end"], finish)
            periods[-1]["flows"] += 1
            continue
        periods.append({"_start": start, "_end": finish, "flows": 1})
    return [
        {
            "start": fmt_time(p["_start"]),
            "end": fmt_time(p["_end"]),
            "duration_sec": round((p["_end"] - p["_start"]).total_seconds(), 1),
            "flows": p["flows"],
        }
        for p in periods
    ]


# --- fix C: notable flows -----------------------------------------------------

def notable_flows(flows: pd.DataFrame, limit: int = MAX_LISTED_FLOWS) -> dict:
    """The largest flows by total bytes AND the most upload-heavy flows, so
    upload-heavy sessions are never hidden behind big downloads."""
    if flows.empty:
        return {"largest_by_total_bytes": [], "most_upload_heavy": [], "upload_heavy_total": None}
    ranked = flows.assign(
        total_bytes=flows["up_bytes"] + flows["down_bytes"],
        ratio=flows["up_bytes"] / flows["down_bytes"].clip(lower=1),
    )
    largest = ranked.sort_values("total_bytes", ascending=False).head(limit)
    is_heavy = (ranked["ratio"] >= UPLOAD_HEAVY_RATIO) & (ranked["up_bytes"] >= UPLOAD_HEAVY_MIN_BYTES)
    heavy = ranked[is_heavy].sort_values("ratio", ascending=False)

    heavy_total = None
    if not heavy.empty:
        heavy_total = {
            "count": int(len(heavy)),
            "up_bytes": int(heavy["up_bytes"].sum()),
            "down_bytes": int(heavy["down_bytes"].sum()),
            "min_duration_sec": round(float(heavy["duration_sec"].min()), 1),
            "max_duration_sec": round(float(heavy["duration_sec"].max()), 1),
        }
    return {
        "largest_by_total_bytes": [flow_record(r) for r in largest.itertuples(index=False)],
        "most_upload_heavy": [flow_record(r) for r in heavy.head(limit).itertuples(index=False)],
        "upload_heavy_total": heavy_total,
    }


def exfil_sized_flows(flows: pd.DataFrame) -> dict:
    """Flows upload-heavy enough to support an 'exfiltration' claim:
    up/down ratio above EXFIL_MIN_RATIO and more than EXFIL_MIN_UP_BYTES up."""
    if flows.empty:
        return {"count": 0, "up_bytes": 0}
    ratio = flows["up_bytes"] / flows["down_bytes"].clip(lower=1)
    heavy = flows[(ratio > config.EXFIL_MIN_RATIO) & (flows["up_bytes"] > config.EXFIL_MIN_UP_BYTES)]
    return {"count": int(len(heavy)), "up_bytes": int(heavy["up_bytes"].sum())}


def activity_hints(root_domains) -> dict[str, list[str]]:
    """What the host seems to be used for, from its root domains (a hint only)."""
    hints: dict[str, list[str]] = {}
    for domain in _clean(root_domains):
        domain = domain.lower()
        for label, markers in knowledge.HOST_ACTIVITY_HINTS.items():
            if any(domain == m or domain.endswith("." + m) for m in markers):
                hints.setdefault(label, []).append(domain)
    return dict(sorted(hints.items(), key=lambda kv: -len(kv[1])))


# User-agent markers per platform, most specific first (an iPhone agent
# also says "like Mac OS X", Android agents also say "Linux").
USER_AGENT_PLATFORMS = (
    ("ios", ("iphone", "ipad", "ios/")),
    ("android", ("android", "okhttp", "dalvik")),
    ("windows", ("windows", "win64", "microsoft-delivery-optimization", "microsoft bits", "microsoft-cryptoapi",
                 "msie", "officeclicktorun", "winhttp")),
    ("macos", ("macintosh", "mac os x", "darwin")),
    ("linux", ("linux", "ubuntu", "debian", "fedora", "apt-http", "x11")),
)


def platform_from_user_agent(agent: str | None) -> str | None:
    """'windows', 'macos', 'linux', 'android', 'ios' or None for an HTTP user agent."""
    text = (agent or "").lower()
    for platform, markers in USER_AGENT_PLATFORMS:
        if any(m in text for m in markers):
            return platform
    return None


def platform_hints(root_domains) -> dict[str, list[str]]:
    """Operating-system hints from the host's root domains (weak signal)."""
    hints: dict[str, list[str]] = {}
    for domain in _clean(root_domains):
        domain = domain.lower()
        for platform, markers in knowledge.PLATFORM_HINT_DOMAINS.items():
            if any(domain == m or domain.endswith("." + m) for m in markers):
                hints.setdefault(platform, []).append(domain)
    return hints


# --- subscriber_activity_1m summaries ------------------------------------------

def summarise_indicator_activity(activity: pd.DataFrame) -> dict:
    """Which IPs, names, ASNs and ports the host used with the flagged IP(s)."""
    if activity.empty:
        return {"active_minutes": 0, "servers": [], "ports": [], "active_dates": []}
    servers = []
    for ip, group in activity.groupby("server_ip"):
        servers.append({
            "server_ip": str(ip),
            "names": _clean(list(group["dns"]) + list(group["sni"]) + list(group["root_domain"])),
            "asn": _clean(group["asn"]),
            "asn_org": _clean(group["asn_org"]),
            "country": _clean(group["country"]),
            "active_minutes": int(group["minutes"].sum()),
        })
    servers.sort(key=lambda s: -s["active_minutes"])
    return {
        "active_minutes": int(activity["minutes"].sum()),
        "up_bytes": int(activity["up_bytes"].sum()),
        "down_bytes": int(activity["down_bytes"].sum()),
        "first_minute": fmt_time(activity["first_time"].min()),
        "last_minute": fmt_time(activity["last_time"].max()),
        "servers": servers,
        "ports": activity_port_breakdown(activity),
        "active_dates": sorted({str(pd.Timestamp(d).date()) for d in activity["day"]}),
    }


def _service_for(domain: str | None, port, protocol: str | None) -> dict | None:
    match = knowledge.match_service(domain=domain, port=port, protocol=protocol)
    if not match:
        return None
    return {"service": match["key"], "matched_on": match["matched_on"]}


MAX_PROFILE_SITES = 4
MAX_UNLISTED_SITES = 15
NOT_A_SITE = ("(no domain)", "cloudflare-ech.com")  # no name, or the ECH placeholder


def activity_label(domain: str) -> str | None:
    """The kind of use a root domain shows (knowledge.HOST_ACTIVITY_HINTS), if any."""
    domain = domain.lower()
    for label, markers in knowledge.HOST_ACTIVITY_HINTS.items():
        if any(domain == m or domain.endswith("." + m) for m in markers):
            return label
    return None


def activity_profile(activity: pd.DataFrame) -> dict:
    """What the host spends its traffic on: per kind of use (adult content,
    gaming, ...), its bytes, share of all the host's traffic, active minutes
    and busiest sites. A reading of the traffic, never proof of who uses it."""
    if activity is None or activity.empty:
        return {"total_bytes": 0, "categories": []}
    frame = activity.assign(total=activity["up_bytes"] + activity["down_bytes"])
    total = int(frame["total"].sum())
    per_domain = frame.groupby("root_domain").agg(bytes=("total", "sum"), minutes=("minutes", "sum"))
    categories: dict[str, dict] = {}
    unlisted: list[dict] = []
    for domain, row in per_domain.sort_values("bytes", ascending=False).iterrows():
        if not domain or domain in NOT_A_SITE:
            continue
        label = activity_label(str(domain))
        if not label:
            # Skip IP fragments SuperNetFlow stores as a domain ("116.9"), and
            # sites on the other lists (ad networks, OS services).
            if str(domain).replace(".", "").isdigit() or knowledge.destination_kind(str(domain)):
                continue
            if len(unlisted) < MAX_UNLISTED_SITES:
                unlisted.append({"domain": str(domain), "bytes": int(row["bytes"]),
                                 "share": round(int(row["bytes"]) / total, 3) if total else 0.0})
            continue
        entry = categories.setdefault(label, {"category": label, "bytes": 0, "minutes": 0, "sites": []})
        entry["bytes"] += int(row["bytes"])
        entry["minutes"] += int(row["minutes"])
        if len(entry["sites"]) < MAX_PROFILE_SITES:
            entry["sites"].append({"domain": str(domain), "bytes": int(row["bytes"])})
    rows = sorted(categories.values(), key=lambda c: -c["bytes"])
    for entry in rows:
        entry["share"] = round(entry["bytes"] / total, 3) if total else 0.0
    # The lists are short: the busiest other sites go to the model to judge by name.
    return {"total_bytes": total, "categories": rows, "unlisted": unlisted}


def summarise_other_traffic(activity: pd.DataFrame, long_flows: pd.DataFrame) -> dict:
    """Host's traffic to everything except the flagged IP(s): top destinations,
    long-lived flows elsewhere, and destinations matching a known service."""
    result: dict = {
        "top_destinations_by_bytes": [],
        "domains_by_active_minutes": [],
        "distinct_root_domains": 0,
        "long_lived_flows": [],
        "service_matches": [],
        "platform_hints": {},
        "activity_hints": {},
        "activity_profile": {"total_bytes": 0, "categories": []},
    }
    services: dict[str, dict] = {}

    def add_service(match: dict | None, table: str, up: int, down: int) -> None:
        # Bytes are kept per table: the two tables overlap, so adding them would double count.
        if not match:
            return
        entry = services.setdefault(match["service"], {
            "service": match["service"], "matched_on": set(), "bytes_by_table": {},
        })
        entry["matched_on"].add(match["matched_on"])
        totals = entry["bytes_by_table"].setdefault(table, {"up_bytes": 0, "down_bytes": 0})
        totals["up_bytes"] += up
        totals["down_bytes"] += down

    ip_to_domain: dict[str, str] = {}
    if not activity.empty:
        activity = activity.assign(
            root_domain=activity["root_domain"].fillna("").replace("", "(no domain)"),
            proto=activity["transport_protocol"].map(knowledge.protocol_name),
        )
        by_destination = (
            activity.groupby(["root_domain", "server_port", "proto"])
            .agg(active_minutes=("minutes", "sum"), server_ips=("server_ip", "nunique"),
                 up_bytes=("up_bytes", "sum"), down_bytes=("down_bytes", "sum"))
            .reset_index()
        )
        by_destination["total"] = by_destination["up_bytes"] + by_destination["down_bytes"]
        for row in by_destination.sort_values("total", ascending=False).head(MAX_LISTED_DESTINATIONS).itertuples():
            result["top_destinations_by_bytes"].append({
                "root_domain": row.root_domain, "port": int(row.server_port), "protocol": row.proto,
                "active_minutes": int(row.active_minutes), "server_ips": int(row.server_ips),
                "up_bytes": int(row.up_bytes), "down_bytes": int(row.down_bytes),
            })
        for row in by_destination.itertuples():
            domain = None if row.root_domain == "(no domain)" else row.root_domain
            add_service(_service_for(domain, row.server_port, row.proto), "subscriber_activity_1m",
                        int(row.up_bytes), int(row.down_bytes))

        minutes_by_domain = activity.groupby("root_domain")["minutes"].sum().sort_values(ascending=False)
        result["domains_by_active_minutes"] = [
            d for d in minutes_by_domain.index if d != "(no domain)"
        ][:MAX_LISTED_DOMAIN_NAMES]
        result["distinct_root_domains"] = sum(1 for d in minutes_by_domain.index if d != "(no domain)")
        result["platform_hints"] = platform_hints(d for d in minutes_by_domain.index if d != "(no domain)")
        result["activity_hints"] = activity_hints(d for d in minutes_by_domain.index if d != "(no domain)")
        result["activity_profile"] = activity_profile(activity)

        busiest = activity.assign(total=activity["up_bytes"] + activity["down_bytes"]).sort_values("total")
        ip_to_domain = dict(zip(busiest["server_ip"].astype(str), busiest["root_domain"]))

    if not long_flows.empty:
        ranked = long_flows.assign(total=long_flows["up_bytes"] + long_flows["down_bytes"])
        for row in ranked.sort_values("total", ascending=False).itertuples():
            protocol = knowledge.protocol_name(row.protocol)
            domain = ip_to_domain.get(str(row.server_ip))
            lookup_domain = None if domain in (None, "(no domain)") else domain
            match = _service_for(lookup_domain, row.server_port, protocol)
            add_service(match, "long_flow_summary", int(row.up_bytes), int(row.down_bytes))
            if len(result["long_lived_flows"]) >= MAX_LISTED_DESTINATIONS:
                continue
            result["long_lived_flows"].append({
                "server_ip": str(row.server_ip),
                "root_domain": domain or "(unknown)",
                "port": int(row.server_port),
                "protocol": protocol,
                "flows": int(row.flows),
                "total_duration_sec": round(float(row.total_duration_sec), 1),
                "up_bytes": int(row.up_bytes),
                "down_bytes": int(row.down_bytes),
                "first_start": fmt_time(row.first_start),
                "last_finish": fmt_time(row.last_finish),
                "service": match["service"] if match else None,
            })

    result["service_matches"] = [
        {**entry, "matched_on": sorted(entry["matched_on"])}
        for entry in services.values()
    ]
    return result


# --- fix F: shared infrastructure ---------------------------------------------

def shared_infrastructure(asn_orgs: list[str], service_match: dict | None,
                          peer_count: int | None, peers_flagged: int = 0) -> dict:
    """Signals that the flagged IP is shared by many unrelated users. Peer
    count alone misses niche services with one campus user, so the
    knowledge base and ASN organisation are checked too."""
    signals: list[str] = []
    likely_shared = False

    if service_match:
        likely_shared = True
        name = service_match["profile"]["name"]
        signals.append(f"Known public service: {name} (matched on {service_match['matched_on']}).")

    for org in asn_orgs:
        kind = knowledge.classify_asn(org)
        if kind == "shared_frontend":
            likely_shared = True
            signals.append(f"ASN organisation '{org}' is a CDN/front-end: one IP serves many unrelated sites.")
        elif kind == "cloud_vps":
            signals.append(
                f"ASN organisation '{org}' is a cloud/VPS provider: the IP may be one customer's server "
                "or a public service used by many."
            )

    if peer_count is not None and peer_count >= config.SHARED_PEER_HOSTS:
        likely_shared = True
        signals.append(f"{peer_count} distinct {config.HOST_LABEL}s contacted this IP.")
    elif peer_count is not None:
        signals.append(
            f"Only {peer_count} {config.HOST_LABEL}(s) contacted this IP. A niche shared service can still look like this."
        )

    if peers_flagged:
        signals.append(
            f"{peers_flagged} peer host(s) are also flagged by other IOCs in the feed. This points to a "
            "multi-host compromise and outweighs the shared-infrastructure signals."
        )
    return {"likely_shared": likely_shared and not peers_flagged, "signals": signals}

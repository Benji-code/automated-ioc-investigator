"""Render one case's evidence as the plain-text case file the model reads.

Sections follow the workflow steps. Every fact names the table it came from,
so the model (and a reviewer reading the saved case file) can trace it.
"""
from __future__ import annotations

from . import beacon, charts, config, evidence, labels, schema, timeline
from .analysis import fmt_bytes, fmt_duration

LFS = "long_flow_summary"
LFS_SCOPE = "long_flow_summary, flows over 1 MB only: smaller or shorter contacts are not counted"
SA = "subscriber_activity_1m"
FEED_LABEL = "from the IOC feed, not re-queried"


def source_label(table: str, sources: dict) -> str:
    """'long_flow_summary' or 'long_flow_summary, from the IOC feed, not re-queried'."""
    if sources.get(table) == "feed":
        return f"{table}, {FEED_LABEL}"
    return table


def _error_line(section: dict) -> str | None:
    if "error" in section:
        return f"  Could not query ClickHouse: {section['error']}"
    return None


def _connection(f: dict, inbound: bool) -> str:
    """Which side each port is on: inbound, the remote's temporary port and
    the host's service port; otherwise the remote's service port."""
    if inbound:
        return (f"{f['server_ip']} from its temporary port {f['server_port']}/{f['protocol']} "
                f"to host port {f['client_port']}")
    return (f"{f['server_ip']}:{f['server_port']}/{f['protocol']} (remote service port) "
            f"from host temporary port {f['client_port']}")


def _flow_line(f: dict, inbound: bool = False) -> str:
    line = (
        f"    - {f['start']} -> {f['finish']} ({fmt_duration(f['duration_sec'])}), "
        f"{_connection(f, inbound)}, "
        f"up {fmt_bytes(f['up_bytes'])} ({f['up_packets']} pkts), "
        f"down {fmt_bytes(f['down_bytes'])} ({f['down_packets']} pkts), up/down ratio {f['up_down_ratio']}"
    )
    if f.get("packets_per_sec_down") is not None:
        line += (
            f", {f['packets_per_sec_down']} pkt/s down / {f['packets_per_sec_up']} pkt/s up, "
            f"{f['bytes_per_packet_down']} / {f['bytes_per_packet_up']} bytes per packet down/up"
        )
    return line


# --- steps 1-4 -------------------------------------------------------------------

def _host_line(host: dict | None) -> str:
    host = host or {}
    if "error" in host:
        return "  (host name lookup failed)"
    ids = ", ".join(host.get("subscriber_ids") or []) or "unknown"
    return (f"  Host name (reverse DNS): {host.get('hostname') or 'none (no PTR record)'}; subscriber_id: {ids} "
            "(add subscriber_id = '...' to run_sql queries on subscriber_activity_1m and the 5-minute table, "
            "or they scan every row in the window)")


def _intel_lines(identity: dict) -> list[str]:
    """The source's confidence, event, tags and references."""
    confidence = evidence.confidence_text(identity)
    if identity.get("intel_confidence") is None:
        confidence += " (MISP events often carry none; it would rate the indicator, not this host, anyway)"
    lines = [f"Source confidence: {confidence}"]
    if identity.get("intel_event_id"):
        lines.append(f"Source event ID: {identity['intel_event_id']}")
    if identity.get("intel_source_first_seen") or identity.get("intel_source_last_seen"):
        lines.append(f"Source's own first/last seen for the indicator: {identity.get('intel_source_first_seen') or '?'}"
                     f" / {identity.get('intel_source_last_seen') or '?'}")
    tags = identity.get("intel_tags") or []
    if tags:
        lines.append(f"Source tags: {', '.join(str(t) for t in tags[:15])}")
    refs = identity.get("intel_references") or []
    if refs:
        lines.append(f"Source references: {', '.join(str(r) for r in refs[:5])}")
    urls = identity.get("intel_listed_urls") or []
    if urls:
        lines.append(f"URL(s) the source listed: {', '.join(urls)}")
    service = identity.get("intel_known_service")
    if service:
        lines.append(
            f"KNOWN SERVICE: {identity['indicator']} belongs to {service}, a large link-sharing, file-sharing or "
            "site-hosting service. The source listed one URL on it, not the whole service. Flow records show "
            "only the host name (TLS SNI or DNS), never the URL path, so a domain match CANNOT prove that the "
            f"listed URL was visited: it only shows the host used {service} at that time.")
    metadata = identity.get("ioc_metadata")
    if metadata:
        lines.append("Source entry details (entered by hand in data/ioc_metadata.json):")
        lines += [f"  {k}: {v}" for k, v in metadata.items()]
    else:
        lines.append("Source entry dates, reporter and ID: not available (the feed does not carry them; "
                     "they can be added by hand in data/ioc_metadata.json).")
    return lines


def _ioc_section(identity: dict, host: dict | None = None) -> str:
    intel = "\n".join(_intel_lines(identity))
    return f"""[STEP 1] IOC MATCH
Indicator: {identity['indicator']} (type={identity['indicator_type']})
Affected {config.HOST_LABEL}: {identity['affected_asset']}
{_host_line(host)}
Feed match records for this pair: {identity['n_events']} (one per matching per-minute row, not separate incidents)
Evidence first/last seen (UTC): {identity['evidence_first_seen']} / {identity['evidence_last_seen']}{_local_pair(identity['evidence_first_seen'], identity['evidence_last_seen'])}
  (these are the matched flow's own times, NOT the source's dates for the indicator)

[STEP 2] IOC CONTEXT (the indicator's source, via the feed)
Indicator source: {evidence.source_name(identity)}
Malware family: {identity['malware']}
Threat type: {identity['threat_type']}
{intel}"""


def _usage_section(other: dict) -> str:
    """What the host is used for, by kind of use, with volumes and the main sites."""
    header = "[STEP 1b] WHAT THE HOST IS USED FOR (its own traffic, sites grouped by kind of use from a local list)"
    if "error" in other:
        return f"{header}\n{_error_line(other)}"
    profile = other.get("activity_profile") or {}
    window = (other.get("window") or {}).get("subscriber_activity_1m", "")
    if not profile.get("total_bytes"):
        return f"{header}\n  No per-minute traffic for the host in {window or 'the window'}."
    lines = [header, f"  ({SA}, {window}; all its traffic: {fmt_bytes(profile['total_bytes'])}. A reading of the "
                     "traffic, not proof of who uses the machine.)"]
    for c in profile.get("categories") or []:
        sites = ", ".join(f"{site['domain']} {fmt_bytes(site['bytes'])}" for site in c["sites"])
        share = f"{c['share']:.0%}" if c["share"] >= 0.01 else "under 1%"
        lines.append(f"    - {c['category']}: {fmt_bytes(c['bytes'])} ({share} of all its traffic), "
                     f"{c['minutes']} active minute(s); main sites: {sites}")
    if not profile.get("categories"):
        lines.append("    (none of its sites is on the local lists of kinds of use)")
    unlisted = profile.get("unlisted") or []
    if unlisted:
        sites = ", ".join(f"{site['domain']} {fmt_bytes(site['bytes'])}" for site in unlisted)
        lines.append(f"  Busiest sites NOT on the lists (the lists are short; judge what these are from their "
                     f"names): {sites}")
    return "\n".join(lines)


def _asn_line(info: dict) -> str:
    parts = [f"ASN {info['asn'] or '?'} {info['asn_org'] or ''}".strip()]
    if info.get("source"):
        parts[0] += f" (via {info['source']})"
    if info.get("shared_range"):
        r = info["shared_range"]
        parts.append(f"in {r['name']} {r['cidr']}: {r['notes']}")
    elif info.get("shared_asn"):
        a = info["shared_asn"]
        parts.append(f"shared-infrastructure ASN ({a['org']}, {a['kind']})")
    return f"    {info['server_ip']}: " + "; ".join(parts)


def _ips_section(server_ips: dict, flows: dict, asn_info: list[dict] | None = None) -> str:
    if "error" in server_ips:
        return f"[STEP 3] FLAGGED IP(S)\n{_error_line(server_ips)}"
    lines = ["[STEP 3] FLAGGED IP(S)"]
    if not server_ips.get("ips"):
        lines.append("  No IP found for this indicator in the feed or in live DNS/SNI data.")
    if server_ips.get("live_lookup_error"):
        lines.append(f"  (live DNS/SNI lookup failed: {server_ips['live_lookup_error'][:200]})")
    live = {s["server_ip"]: s for s in flows.get("activity", {}).get("servers", [])}
    for entry in server_ips.get("ips", []):
        ip = entry["server_ip"]
        server = live.get(ip, {})
        names = server.get("names") or entry.get("names") or ["(none)"]
        asn_org = server.get("asn_org") or entry.get("asn_org") or ["(unknown)"]
        asn = server.get("asn") or []
        country = server.get("country") or []
        lines.append(
            f"  - {ip}: found via {', '.join(entry['found_via'])}; names seen: {', '.join(names)}; "
            f"ASN {', '.join(asn) or '?'} {', '.join(asn_org)}; country {', '.join(country) or '?'}"
        )
    if asn_info:
        lines.append("  ASN and shared-infrastructure check:")
        lines.extend(_asn_line(info) for info in asn_info)
    return "\n".join(lines)


def _service_block(service: dict | None, port_fit: list[dict], port_verdict: str | None) -> str:
    if not service:
        return "Known service profile: none matched (domain and ports checked against the knowledge base)."
    p = service["profile"]
    fit_lines = "\n".join(
        f"    - {f['port']}/{f['protocol']}: {'FITS' if f['fits'] else 'DOES NOT FIT'} ({f['note']})"
        for f in port_fit
    ) or "    (no ports observed)"
    return f"""Known service profile: {p['name']} (matched on {service['matched_on']})
  What it does: {p['what_it_does']}
  Normal client traffic: {p['normal_client_traffic']}
  How it is abused: {p['abuse']}
  What a victim of C2 behind it would show: {p['c2_victim_would_show']}
  Observed ports vs this service's client ports:
{fit_lines}
  Port check: {port_verdict or "n/a"}"""


def _expected_section(identity: dict, expected: dict) -> str:
    malware = expected.get("malware_profile", {})
    threat = expected.get("threat_type_profile", {})
    if expected.get("briefing"):
        refs = ", ".join(expected["briefing"].get("references") or []) or "none given"
        return f"""[STEP 4] EXPECTED BEHAVIOUR (analyst-supplied threat description, not the local knowledge base)
Threat: {malware.get('family')}
  {malware.get('notes')}
  What an affected host's traffic looks like: {threat.get('victim_traffic')}
  Expected traffic shape: {threat.get('expected_traffic_shape')}
  Expected recurrence: {threat.get('expected_recurrence')}
  Common false-positive pattern: {threat.get('false_positive_pattern')}
  References in the description: {refs}
{_service_block(expected.get('service'), expected.get('service_port_fit', []), expected.get('service_port_verdict'))}"""
    return f"""[STEP 4] EXPECTED BEHAVIOUR (local knowledge base)
Malware family: {malware.get('family')}
  {malware.get('notes')}
Threat type {identity['threat_type']}:
{_threat_type_lines(threat)}
{_service_block(expected.get('service'), expected.get('service_port_fit', []), expected.get('service_port_verdict'))}"""


THREAT_TYPE_LINES = (
    ("affected_means", "What \"affected\" means here"),
    ("match_means", "A real match means"),
    ("victim_traffic", "What an affected host's traffic looks like"),
    ("expected_traffic_shape", "Expected traffic shape"),
    ("expected_recurrence", "Expected recurrence"),
    ("false_positive_pattern", "Common false-positive pattern"),
    ("consequence", "What is at stake"),
    ("next_steps", "Next steps if real"),
)


def _threat_type_lines(threat: dict) -> str:
    """The threat-type profile's fields that are filled in. match_means and
    victim_traffic only for profiles that say what "affected" means, so
    malware profiles read as before."""
    keys = [k for k, _ in THREAT_TYPE_LINES]
    if not threat.get("affected_means"):
        keys = [k for k in keys if k not in ("match_means", "victim_traffic")]
    return "\n".join(f"  {label}: {threat[key]}" for key, label in THREAT_TYPE_LINES
                     if key in keys and threat.get(key))


# --- step 5 --------------------------------------------------------------------

def _side(inbound: bool) -> str:
    return "remote temporary port " if inbound else "remote service port "


def _port_lines(ports: list[dict], inbound: bool = False) -> str:
    return "\n".join(
        f"    - {_side(inbound)}{p['port']}/{p['protocol']}: {p['flows']} flow(s), up {fmt_bytes(p['up_bytes'])} "
        f"({p['up_packets']} pkts), down {fmt_bytes(p['down_bytes'])} ({p['down_packets']} pkts), "
        f"total duration {fmt_duration(p['total_duration_sec'])}, {p['first_start']} to {p['last_finish']}"
        for p in ports
    ) or "    (no long flows)"


def _activity_port_lines(ports: list[dict], inbound: bool = False) -> str:
    return "\n".join(
        f"    - {_side(inbound)}{p['port']}/{p['protocol']}: {p['active_minutes']} active minute(s), "
        f"up {fmt_bytes(p['up_bytes'])} ({p['up_packets']} pkts), "
        f"down {fmt_bytes(p['down_bytes'])} ({p['down_packets']} pkts), {p['first_minute']} to {p['last_minute']}"
        for p in ports
    ) or "    (no per-minute rows in the retention window)"


def _classification_lines(c: dict, inbound: bool = False) -> str:
    lines = [f"  Large-flow pattern ({LFS}, flows over 1 MB only): {c['pattern']} - {c['description']}",
             "  (Check-ins and beacons are judged in CONTACT PATTERN below, from per-minute data, not here.)"]
    held = c.get("held_open")
    if held:
        steady = "steady" if held["packet_rate_steady"] else "NOT steady"
        quick = held["quick_reconnects"]
        reconnect = (f"{quick} quick reconnect(s) (median {held['median_quick_reconnect_sec']} s between one "
                     f"flow's finish and the next flow's start)" if quick else "no quick reconnects")
        longest = fmt_duration(held["longest_gap_sec"]) if held["longest_gap_sec"] is not None else "n/a"
        lines.append(
            f"  Held-open flows (1 hour or longer): {held['count']}, lasting "
            f"{fmt_duration(held['min_duration_sec'])} to {fmt_duration(held['max_duration_sec'])}; "
            f"median {held['median_packets_per_sec_down']} pkt/s down and {held['median_packets_per_sec_up']} "
            f"pkt/s up ({steady} across flows); median {held['median_bytes_per_packet_down']} bytes/packet "
            f"down and {held['median_bytes_per_packet_up']} up (keepalive fingerprint); {reconnect}; "
            f"longest gap between held-open flows {longest}."
        )
        lines.append("  Held-open flows:")
        lines.extend(_flow_line(f, inbound) for f in held["flows"])
    other = c.get("other_flows") or {}
    if other.get("count"):
        lines.append(f"  Other flows over 1 MB (under an hour): {other['count']}.")
    return "\n".join(lines)


def _flow_key(f: dict) -> tuple:
    return f["start"], f["client_port"]


def _notable_lines(notable: dict, already_listed: set[tuple], inbound: bool = False) -> str:
    largest = notable["largest_by_total_bytes"]
    new = [f for f in largest if _flow_key(f) not in already_listed]
    repeated = len(largest) - len(new)
    note = f" ({repeated} of the top {len(largest)} are the held-open flows listed above)" if repeated else ""
    lines = [f"  Largest flows by total bytes{note}:"]
    lines.extend(_flow_line(f, inbound) for f in new)
    heavy_total = notable.get("upload_heavy_total")
    if heavy_total:
        lines.append(
            f"  Upload-heavy flows (up at least 2x down): {heavy_total['count']}, lasting "
            f"{fmt_duration(heavy_total['min_duration_sec'])} to {fmt_duration(heavy_total['max_duration_sec'])}, "
            f"{fmt_bytes(heavy_total['up_bytes'])} up vs {fmt_bytes(heavy_total['down_bytes'])} down in total. Most upload-heavy:"
        )
        lines.extend(_flow_line(f, inbound) for f in notable["most_upload_heavy"])
    else:
        lines.append("  Upload-heavy flows (up at least 2x down): none.")
    return "\n".join(lines)


def _held_open_keys(classification: dict) -> set[tuple]:
    held = classification.get("held_open") or {}
    return {_flow_key(f) for f in held.get("flows", [])}


def _direction_line(flows: dict) -> str:
    direction = flows.get("direction") or {}
    if not direction.get("inbound_likely"):
        return ""
    return (f"\nDirection (inferred): INBOUND. {direction['reason'][0].upper()}{direction['reason'][1:]}. In these "
            "records \"up\" is what the host sent back and \"server port\" is the remote side's temporary port. The "
            "campus name on those rows is this host's own service name (what the remote side asked for), not a name "
            "of the flagged address.")


def port_sides_line(direction: dict) -> str:
    """Which side each port belongs to, stated once at the top of the flows."""
    ports = direction.get("ports") or []
    if not ports:
        return "Port sides: no ports recorded."
    listed = ", ".join(map(str, ports[:6])) + (f" and {len(ports) - 6} more" if len(ports) > 6 else "")
    if direction.get("inbound_likely"):
        host = direction.get("host_ports") or []
        served = (f"The host's service port(s): {', '.join(host)}." if host else
                  "The host's service port is not recorded (per-minute rows hold only the remote side's port).")
        return (f"Port sides: {served} Ports like {listed} are the remote side's temporary ports, not services "
                "on the host.")
    return (f"Port sides: {listed} {'is' if len(ports) == 1 else 'are'} the remote side's service port(s), on the "
            "flagged address; the host's own ports are temporary client ports.")


def _flows_section(flows: dict) -> str:
    header = ("[STEP 5] FLOWS BETWEEN HOST AND FLAGGED IP(S)\n"
              "  (long_flow_summary: only flows over 1 MB, so small or short connections are not in it; "
              "subscriber_activity_1m: per minute, about 15 days kept)")
    error = _error_line(flows)
    if error:
        return f"{header}\n{error}"
    window = flows["window"]
    checked = "\n".join(f"    - {c}" for c in flows.get("checked", []))
    if not flows["has_traffic"]:
        return (f"{header}\nWindow: {LFS} {window['long_flow_summary']}; {SA} {window['subscriber_activity_1m']}\n"
                f"  What was checked:\n{checked}\n"
                "  No traffic found live or in the feed's own evidence. The verdict is INSUFFICIENT_DATA. "
                "Do not describe any traffic as observed.")
    sources = flows.get("sources", {})
    lfs = source_label(LFS, sources)
    sa = source_label(SA, sources)
    exfil = flows.get("upload_heavy_over_exfil_threshold", {"count": 0})
    exfil_line = (f"  Flows over the exfiltration threshold (up/down > {config.EXFIL_MIN_RATIO:g} and > "
                  f"{config.EXFIL_MIN_UP_BYTES / 1e6:g} MB up): {exfil['count']}"
                  + (f", {fmt_bytes(exfil['up_bytes'])} up in total" if exfil["count"] else
                     ". Do not call this traffic exfiltration."))
    activity = flows["activity"]
    periods = "\n".join(
        f"    - {p['start']} to {p['end']} UTC{_local_pair(p['start'], p['end'], sep=' to ')} "
        f"({fmt_duration(p['duration_sec'])}, {p['flows']} flow(s))"
        for p in flows["active_periods"]
    ) or "    (none)"
    dates = ", ".join(activity.get("active_dates", [])) or "(none in retention window)"
    inbound = bool((flows.get("direction") or {}).get("inbound_likely"))
    return f"""{header}
{port_sides_line(flows.get("direction") or {})}
Window: {LFS} {window['long_flow_summary']}; {SA} {window['subscriber_activity_1m']}
  What was checked:
{checked}
Ports seen (both tables): {', '.join(flows['ports_seen']) or '(none)'}{_direction_line(flows)}
Per-port breakdown ({lfs}, flows over 1 MB only, {flows['long_flow_count']} flow(s)):
{_port_lines(flows['ports'], inbound)}
Per-port activity ({sa}):
{_activity_port_lines(activity.get('ports', []), inbound)}
{_classification_lines(flows['classification'], inbound)}
{_notable_lines(flows['notable'], _held_open_keys(flows['classification']), inbound)}
{exfil_line}{_retention_line(flows)}
  Active periods ({lfs}, flows over 1 MB only, less than 1 hour apart merged):
{periods}
  Dates with per-minute activity ({sa}): {dates}"""


def _names_section(names: dict) -> str:
    header = "[STEP 5b] NAMES THE HOST ACTUALLY USED ON THE FLAGGED IP(S)"
    if "error" in names:
        return f"{header}\n{_error_line(names)}"
    source = {"live": f"{SA}, queried live", "feed": f"{SA}, {FEED_LABEL}",
              "long_flows": "long_flow_summary attributes.sni, flows over 1 MB only",
              "long_flows+feed": f"long_flow_summary attributes.sni (flows over 1 MB) and {SA} {FEED_LABEL}"
              }.get(names["source"])
    if not source:
        return f"{header}\n  No SNI or DNS names recorded for this host on the flagged IP."
    lines = [f"{header} ({source}; minutes within ±{config.NAMES_WINDOW_MINUTES} min of a feed match in brackets)"]
    for n in names["names"]:
        label = "SNI hidden by Encrypted Client Hello" if n["ech_hidden"] else n["name"]
        lines.append(f"    - {label} [{n['registered_domain'] or '-'}] on {', '.join(n['ports'])}: "
                     f"{n['minutes']} min ({n['near_match_minutes']} near a match), "
                     f"up {fmt_bytes(n['up_bytes'])}, down {fmt_bytes(n['down_bytes'])}")
    if names.get("ech_hidden_minutes"):
        lines.append(f"  {names['ech_hidden_minutes']} minute(s) had the SNI hidden by Encrypted Client Hello "
                     "(cloudflare-ech.com is a placeholder, not a destination).")
    return "\n".join(lines)


def _features_section(features: list[dict]) -> str:
    header = (f"[STEP 4b] DOMAIN FEATURES (offline lists; how many OTHER campus hosts used each domain, "
              f"over up to {config.CAMPUS_LOOKUP_DAYS} days; first seen on campus within retention; {SA})")
    if not features:
        return f"{header}\n  (no domain names to check)"
    lines = [header]
    for f in features:
        flags = []
        if f.get("flagged_in_feed"):
            flags.append("ALSO AN INDICATOR IN THE FEED")
        if f.get("provider_category"):
            flags.append(f["provider_category"].replace("_", " "))
        if f.get("lexical_dga_like"):
            flags.append("DGA-like")
        if f.get("new_on_campus"):
            flags.append("new on campus")
        hosts = f.get("other_campus_hosts")
        when = f.get("campus_period", "?") + (" (current data, not the match time)" if f.get("campus_period_is_current") else "")
        lines.append(
            f"    - {f['registered_domain']}: other campus hosts {hosts if hosts is not None else '?'} over {when}, "
            f"first seen on campus "
            f"{f.get('campus_first_seen') or 'not within retention'}; label '{f['lexical_label']}' length "
            f"{f['lexical_length']}, digits {f['lexical_digit_ratio']}, entropy {f['lexical_entropy']}"
            + (f"; {'; '.join(flags)}" if flags else "")
        )
    return "\n".join(lines)


def _local_pair(first, last, sep: str = " / ") -> str:
    """" [<city> time: a / b]", e.g. [Sydney time: ...] (the zone's city) when a local time zone is set,
    else empty. Not "[local: ...]": the model copied "local" as a zone name."""
    a, b = config.to_local(first), config.to_local(last)
    if not a:
        return ""
    return f" [{config.LOCAL_CITY} time: {a}{sep}{b}]"


# --- steps 7-8 -----------------------------------------------------------------

def _bytes_by_table(by_table: dict) -> str:
    return "; ".join(
        f"{table}: up {fmt_bytes(t['up_bytes'])}, down {fmt_bytes(t['down_bytes'])}"
        for table, t in sorted(by_table.items())
    )


def _other_traffic_section(other: dict) -> str:
    header = ("[STEP 7] HOST'S TRAFFIC TO OTHER IPS\n"
              "  (subscriber_activity_1m: per minute, about 15 days kept; long_flow_summary: flows over 1 MB only)")
    error = _error_line(other)
    if error:
        return f"{header}\n{error}"
    top = "\n".join(
        f"    - {d['root_domain']} {d['port']}/{d['protocol']}: up {fmt_bytes(d['up_bytes'])}, "
        f"down {fmt_bytes(d['down_bytes'])}, {d['active_minutes']} active minute(s), {d['server_ips']} IP(s)"
        for d in other["top_destinations_by_bytes"]
    ) or "    (no per-minute rows in the retention window)"
    long_lived = "\n".join(
        f"    - {f['server_ip']} ({f['root_domain']}) {f['port']}/{f['protocol']}: {f['flows']} flow(s), "
        f"summed duration {fmt_duration(f['total_duration_sec'])}, up {fmt_bytes(f['up_bytes'])}, "
        f"down {fmt_bytes(f['down_bytes'])}, {f['first_start']} to {f['last_finish']}"
        + (f" [service: {f['service']}]" if f["service"] else "")
        for f in other["long_lived_flows"]
    ) or "    (none)"
    services = "\n".join(
        f"    - {s['service']}: matched on {', '.join(s['matched_on'])}; " + _bytes_by_table(s["bytes_by_table"])
        for s in other["service_matches"]
    ) or "    (none)"
    domains = ", ".join(other["domains_by_active_minutes"]) or "(none)"
    window = other["window"]
    return f"""{header}
Window: {LFS} {window['long_flow_summary']}; {SA} {window['subscriber_activity_1m']}
  Destinations matching a known service profile (tunnels, remote access):
{services}
  Top destinations by bytes ({SA}):
{top}
  Long-lived flows (1 hour or longer) to other IPs ({LFS}, flows over 1 MB only):
{long_lived}
  Root domains contacted, busiest first ({SA}, {other['distinct_root_domains']} distinct): {domains}
  Activity types from ALL its root domains (not only the busiest listed above): {_activity_text(other.get('activity_hints') or {})}
  Operating-system hints from those domains: {_platform_text(other.get('platform_hints') or {})}
  {uptime_text(other.get('uptime') or {})} (subscriber_ip_load_enriched_1h)"""


def uptime_text(uptime: dict) -> str:
    """Uptime evidence for the host's role, from night vs daytime volume."""
    parts = []
    if uptime.get("longest_connection_sec"):
        parts.append(f"longest single connection held open {fmt_duration(uptime['longest_connection_sec'])}")
    if uptime.get("night_day_ratio") is not None:
        parts.append(f"night (00-06 local) volume {fmt_bytes(uptime['night_bytes_per_hour'])}/hour vs daytime "
                     f"{fmt_bytes(uptime['day_bytes_per_hour'])}/hour ({uptime['night_day_ratio']:.0%})")
    if uptime.get("night_day_ratio") is None:
        verdict = "no hourly load data"
    else:
        verdict = {True: "busy around the clock (server-like)",
                   False: "used in waking hours only (a personal device that sleeps at night)",
                   None: "only background traffic at night (or a trickle at every hour), which says nothing "
                         "about what the machine is"}[uptime.get("always_on")]
    return f"Uptime: {'; '.join(parts) or 'no data'} -> {verdict}. Every host shows some traffic every hour, so only volume counts."


def _retention_line(flows: dict) -> str:
    cut = flows.get("retention_cut")
    if not cut:
        return ""
    return (f"\n  NOTE: long_flow_summary now only holds flows that finished on or after {cut}, and this host's "
            "activity reaches that edge, so earlier activity may be missing.")


def _activity_text(hints: dict) -> str:
    if not hints:
        return "(none)"
    return "; ".join(f"{label}: {', '.join(domains[:4])}" for label, domains in hints.items())


def _platform_text(hints: dict) -> str:
    if not hints:
        return "(none)"
    return "; ".join(f"{platform}: {', '.join(domains[:3])}" for platform, domains in hints.items())


def _peer_host_line(h: dict) -> str:
    tag = " (this case's host)" if h["is_this_case"] else ""
    line = (f"    - {h['host']}{tag}: {h['flows']} flow(s) on port(s) {', '.join(map(str, h['ports']))}, "
            f"{h['first_seen']} to {h['last_seen']}, up {fmt_bytes(h['up_bytes'])}, down {fmt_bytes(h['down_bytes'])}")
    for flag in h.get("also_flagged", []):
        same = " [SAME malware family]" if flag["same_malware_family"] else ""
        line += f"\n      *** also flagged in the feed: {flag['malware']} via {flag['indicator']}{same} ***"
    return line


def _peers_section(peers: list[dict], shared: dict) -> str:
    lines = [f"[STEP 8] OTHER {config.HOST_LABEL.upper()}S CONTACTING THE FLAGGED IP(S)"]
    if not peers:
        lines.append("  (no IP to look up)")
    for p in peers:
        if "error" in p:
            lines.append(f"  {p.get('server_ip', '?')}: could not query ClickHouse: {p['error']}")
            continue
        port = f" port {p['server_port']}" if p["server_port"] else " (any port)"
        lines.append(
            f"  {p['server_ip']}{port}, last {p['lookback_days']} days ({LFS_SCOPE}): {p['distinct_host_count']} "
            f"distinct {config.HOST_LABEL}(s), {p['other_host_count']} besides this one; "
            f"{p['peer_hosts_also_flagged']} also flagged by other IOCs in the feed."
        )
        lines.extend(_peer_host_line(h) for h in p["hosts"][:10])
    lines.append(
        "  Shared infrastructure (knowledge base, ASN and peer count, not peer count alone) - likely shared: "
        + ("yes" if shared.get("likely_shared") else "no")
    )
    lines.extend(f"    - {s}" for s in shared.get("signals", []))
    return "\n".join(lines)


def _names_on_ip_section(names_on_ip: list[dict]) -> str:
    header = (f"[STEP 8b] OTHER NAMES ON THE FLAGGED IP, CAMPUS-WIDE\n"
              f"  ({SA} queried one day at a time, plus long_flow_summary attributes.sni)")
    if not names_on_ip:
        return f"{header}\n  (no IP to look up)"
    lines = [header]
    for p in names_on_ip:
        if "error" in p:
            lines.append(f"  {p.get('server_ip', '?')}: could not query ClickHouse: {p['error']}")
            continue
        when = " (current data, not the match time: the match is outside retention)" if p["period_is_current"] else ""
        lines.append(f"  {p['server_ip']} over {p['period']}{when}: {p['distinct_root_domains']} distinct root "
                     f"domain(s), {p['campus_hosts']} campus host(s) in total"
                     + (f", {p['ech_hidden_hosts']} with the SNI hidden by ECH" if p["ech_hidden_hosts"] else ""))
        for d in p["domains"]:
            lines.append(f"    - {d['root_domain']}: {d['hosts']} host(s) ({', '.join(d['names']) or '-'})")
        if not p["domains"]:
            lines.append("    (no named traffic on this IP in the period)")
    return "\n".join(lines)


def _contact_section(contact: dict) -> str:
    header = "[STEP 5c] CONTACT PATTERN WITH THE FLAGGED IP (beacon check)"
    if "error" in contact:
        return f"{header}\n{_error_line(contact)}"
    table = contact.get("source", "none")
    names = {"subscriber_activity_1m": "canopus.subscriber_activity_1m",
             "app_subscriber_server_enriched_5m": "canopus_dbt.app_subscriber_server_enriched_5m"}
    note = schema.source_note(names[table]) if table in names else f"(from the {table})"
    f = contact.get("features", {})
    lines = [header, f"  {note}".rstrip(), f"  Pattern: {contact['pattern']} - {contact['description']}"]
    if contact.get("note"):
        lines.append(f"  Note: {contact['note']}")
    if f.get("active_minutes"):
        lines.append(
            f"  Window {contact.get('window', '?')}, {contact['resolution_min']}-minute resolution: "
            f"{f['active_minutes']} active minute(s) in {f['bursts']} burst(s) from {f['first']} to {f['last']}; "
            f"duty cycle {f['duty_cycle']:.0%} of that span; median burst {f['median_burst_min']:.0f} min, "
            f"longest run {f['longest_run_min']} min")
        lines.append(
            f"  Gaps between bursts: median {f['median_gap_min'] if f['median_gap_min'] is not None else '-'} min, "
            f"regularity {f['gap_regularity'] if f['gap_regularity'] is not None else '-'}/100; bytes per burst: "
            f"median {fmt_bytes(f['median_burst_up_bytes'])} up / {fmt_bytes(f['median_burst_down_bytes'])} down, "
            f"consistency {f['volume_consistency'] if f['volume_consistency'] is not None else '-'}/100")
        flows = f"; flows active per minute: median {f['flows_per_minute']:.1f}" if f.get("flows_per_minute") is not None else ""
        lines.append(f"  Time of day ({config.LOCAL_TIMEZONE}): {f['hour_spread']} of 24 hours, night (00-06) share "
                     f"{f['night_share']:.0%}{flows}")
        lines.append(f"  Burst starts (first {len(f['burst_starts'])}): {', '.join(f['burst_starts'])}")
        lines += _contact_size_lines(contact)
    return "\n".join(lines)


MAX_SIZED_CONTACTS = 12


def _session_lines(contact: dict, n_contacts: int) -> list[str]:
    """The contacts grouped into sessions, with each session's size, and the
    way to count them in the report ("4 contacts in 2 sessions")."""
    sessions = beacon.contact_sessions(contact, timeline.EPISODE_GAP_MIN)
    lines = [f"  Count: {n_contacts} contact(s) in {len(sessions)} session(s) (contacts under "
             f"{timeline.EPISODE_GAP_MIN} min apart are one session). Count them this way in the report, e.g. "
             f"\"{n_contacts} contacts in {len(sessions)} sessions\"; never call them \"twice\" or \"N times\" "
             "unless that is the number of contacts."]
    for i, session in enumerate(sessions[:MAX_SIZED_CONTACTS], 1):
        span = session["start"][:16] + (f" to {session['end'][11:16]}" if session["end"] != session["start"] else "")
        local = config.to_local(session["start"])
        split = (f" ({fmt_bytes(session['up'])} up / {fmt_bytes(session['down'])} down)"
                 if session["up"] is not None else "")
        lines.append(f"    Session {i}: {span} UTC{f' [{local}]' if local else ''}: {session['contacts']} "
                     f"contact(s), {fmt_bytes(session['total'])}{split}")
    return lines


def _contact_size_lines(contact: dict) -> list[str]:
    """Each contact's size and the totals, in time order, so per-contact
    statements can be checked against them."""
    sizes = beacon.contact_sizes(contact)
    if not sizes:
        return []
    days = sorted({s["start"][:10] for s in sizes})
    span = (f" The contacts fall on {len(days)} different days ({days[0]} to {days[-1]}): give the full date "
            "with every time in the report." if len(days) > 1 else "")
    lines = [f"  Each contact (time order; UTC, then {config.LOCAL_CITY} time; size up / down):{span}"]
    for i, s in enumerate(sizes[:MAX_SIZED_CONTACTS], 1):
        local = config.to_local(s["start"])
        split = f" ({fmt_bytes(s['up'])} up / {fmt_bytes(s['down'])} down)" if s["up"] is not None else ""
        lines.append(f"    {i}. {s['start'][:16]} UTC{f' [{local}]' if local else ''}: {fmt_bytes(s['total'])}{split}")
    if len(sizes) > MAX_SIZED_CONTACTS:
        lines.append(f"    ... and {len(sizes) - MAX_SIZED_CONTACTS} more")
    lines += _session_lines(contact, len(sizes))
    totals = beacon.contact_totals(contact)
    split = (f" ({fmt_bytes(totals['up'])} up / {fmt_bytes(totals['down'])} down)"
             if totals["up"] is not None else "")
    largest = max(s["total"] for s in sizes)
    smallest = min(s["total"] for s in sizes)
    lines.append(f"  All {len(sizes)} contact(s) together: {fmt_bytes(totals['total'])}{split}; largest "
                 f"{fmt_bytes(largest)}, smallest {fmt_bytes(smallest)}.")
    return lines


def remote_address(row: dict) -> str:
    """"203.0.113.5:443/tcp (+2 more IPs)", or a note when no IP was recorded."""
    if not row["server_ip"]:
        return "(server IP not recorded)"
    extra = row.get("ip_count", 1) - 1
    return f"{row['server_ip']}:{row['port']}/{row['protocol']}" + (f" (+{extra} more IPs)" if extra > 0 else "")


def _timeline_row(row: dict, inbound: bool = False) -> str:
    when = row["start"][11:16] + (f"-{row['end'][11:16]}" if row["end"] != row["start"] else "")
    address = remote_address(row)
    if row.get("flagged") and row.get("server_ip"):
        address += " (remote temporary port)" if inbound else " (remote service port)"
    return (f"    {row['id']} {when} ({row['minutes']} active min) {address}  {row['remote']}; "
            f"up {fmt_bytes(row['up_bytes'])}, down {fmt_bytes(row['down_bytes'])}, {row['flows']} flow(s)")


def _timeline_section(timeline: dict | None, inbound: bool = False) -> str:
    header = "[STEP 5e] FLOW TIMELINE AROUND THE CONTACT (what else the host was doing at the same moments)"
    timeline = timeline or {}
    if "error" in timeline:
        return f"{header}\n{_error_line(timeline)}"
    if not timeline.get("episodes"):
        return f"{header}\n  (no contact times to look around)"
    before, after = timeline.get("pad_before", 5), timeline.get("pad_after", 2)
    lines = [header,
             f"  ({SA}: the host's traffic from {before} min before to {after} min after each contact episode, one "
             "row per site (all its names, IPs and ports) and one row per flagged address (every name seen on it), "
             "earliest first. Listed first: sites already in use before the contact and sites of a known kind "
             "(adult content, ad network, ...); the rest are named at the end of the episode. Rows labelled Web "
             f"Browsing have no server IP. {timeline.get('episode_count', 0)} contact episode(s) in all; the first, "
             "the largest and the last are shown.)",
             "  Read the order: what was open just before the contact usually explains it. Cite rows in the report "
             "as [[flow F3]] and give every row a short note in FLOW_NOTES."]
    for ep in timeline["episodes"]:
        local = _local_pair(ep["start"], ep["end"], sep=" to ")
        lines.append(f"  Episode {ep['n']}: contact {ep['start']} to {ep['end']} UTC{local}, {ep['bursts']} burst(s); "
                     f"window {ep['window'][0]} to {ep['window'][1]} UTC")
        if ep.get("expired"):
            lines.append("    (per-minute data no longer covers this time: about 15 days are kept)")
            continue
        lines.append(f"    {ep.get('sites', 0)} site(s) in the window, {ep.get('flagged', 0)} of them flagged "
                     f"address(es); {ep['shown']} listed:")
        lines.extend(_timeline_row(r, inbound) for r in timeline["rows"] if r["episode"] == ep["n"])
        if ep.get("other_count"):
            more = ep["other_count"] - len(ep["other_sites"])
            lines.append(f"    Other sites in the window, not listed ({ep['other_count']}, largest first): "
                         + ", ".join(ep["other_sites"]) + (f" and {more} more" if more > 0 else ""))
    return "\n".join(lines)


def _apps_section(app_context: dict, host_apps: dict) -> str:
    header = "[STEP 5d] APPS AND PLATFORM"
    lines = [header, "  (from app_subscriber_server_enriched_5m, ux_sessions, app_server_enriched_1h and "
             "subscriber_activity_1m; SuperNetFlow's own app labels, '_unknown' when it has none)"]
    if "error" in app_context:
        lines.append(_error_line(app_context))
    else:
        host = ", ".join(f"{a['application']} ({a['category']}, {a['class']})" for a in app_context.get("host_apps", []))
        lines.append(f"  Labels on this host's traffic to the flagged IP: {host or 'none'}")
        sessions = ", ".join(f"{x['sessions']} {x['type']} ({x['provider']})" for x in app_context.get("host_sessions", []))
        lines.append(f"  Recognised app sessions on this IP for this host: {sessions or 'none'}")
        campus = ", ".join(f"{a['application']} ({a['category']}, up to {a['peak_hosts']} hosts/hour)"
                           for a in app_context.get("campus_apps", []))
        lines.append(f"  Campus-wide labels for the IP: {campus or 'none'}")
        lines.append(f"  Explained by: {app_context.get('explained_by') or 'nothing'}"
                     + (f"; remote-access app: {app_context['remote_access_app']}" if app_context.get("remote_access_app") else ""))
    if "error" in host_apps:
        lines.append(_error_line(host_apps))
    else:
        cats = "; ".join(f"{c['category']} {c['minutes']} min" + (f" ({', '.join(c['apps'])})" if c["apps"] else "")
                         for c in host_apps.get("categories", []))
        lines.append(f"  The host's apps overall (subscriber_activity_1m): {cats or 'none in retention'}")
        if host_apps.get("remote_access_apps"):
            lines.append(f"  Remote-access apps on the host: {', '.join(host_apps['remote_access_apps'])}")
        if host_apps.get("privacy_vpn_apps"):
            lines.append(f"  VPNs or privacy relays on the host: {', '.join(host_apps['privacy_vpn_apps'])}")
        agents = host_apps.get("user_agent_platforms") or {}
        lines.append("  Platform from user agents: " + (", ".join(f"{k} ({v} min)" for k, v in agents.items())
                                                         if agents else "none sent"))
    return "\n".join(lines)


def _dns_section(dns: dict) -> str:
    header = "[STEP 7b] DNS BEHAVIOUR"
    lines = [header, "  (from dns_tuple: resolver statistics only, NOT domain names; response codes are not recorded "
             "here, so there is no NXDOMAIN rate)"]
    if "error" in dns:
        return "\n".join(lines + [_error_line(dns)])
    if not dns.get("present"):
        return "\n".join(lines + [f"  {dns.get('note', 'no data')} ({dns.get('period', '')})."])
    for r in dns.get("resolvers", []):
        tags = []
        if r["public_resolver"]:
            tags.append(f"public resolver: {r['public_resolver']}")
        if r.get("rare"):
            tags.append("RARE on campus")
        if r.get("asn"):
            tags.append(f"AS{r['asn']} {r.get('asn_org', '')}".strip())
        if r.get("authoritative"):
            tags.append(f"{r['authoritative']}, NOT a resolver")
        lines.append(f"    - {r['server_ip']}: {r['answered']} answered, {r['unanswered']} unanswered, "
                     f"{r['campus_clients']} campus client(s) in a day" + (f" [{'; '.join(tags)}]" if tags else ""))
    median = dns["campus_median_unanswered_ratio"]
    lines.append(f"  Unanswered share {dns['unanswered_ratio']:.0%} vs campus median "
                 f"{f'{median:.0%}' if median is not None else '?'}"
                 + (" -> HIGH" if dns.get("unanswered_high") else ""))
    return "\n".join(lines)


def _load_section(load: dict) -> str:
    if "error" in load or "median_daily_up" not in load:
        return ""
    stands = load.get("match_hours_vs_typical")
    return (f"  Host load ({load['period']}, subscriber_ip_load_enriched_1h): median day "
            f"{fmt_bytes(load['median_daily_up'])} up / {fmt_bytes(load['median_daily_down'])} down"
            + (f"; hours around the match carried {stands}x a typical hour" if stands is not None else ""))


def signals_table(signals: list[dict]) -> str:
    rows = [f"  {'signal':<22} {'direction':<16} {'strength':<8} value / reason"]
    for s in signals:
        rows.append(f"  {s['name']:<22} {s['direction']:<16} {s['strength'] or '-':<8} "
                    f"{s['value']} - {s['reason']}")
    return "\n".join(rows)


def _signals_section(ev: dict) -> str:
    baseline = ev["baseline"]
    return f"""EVIDENCE SIGNALS (computed in code from the sections above)
{signals_table(ev['signals'])}

BEHAVIOUR CATEGORY (code): {ev.get('behaviour', {}).get('label', '?')}
BASELINE VERDICT (fixed rules): {baseline['verdict']} (confidence {baseline['confidence']}, rule {baseline['rule']}): {baseline['reason']}
(For reviewers: this section is the rules' result and is NOT shown to the model, which reviews the evidence above blind.)"""


def _correlation_section(links: dict | None) -> str:
    """Domains this case shares with other flagged indicators in the feed."""
    if not links:
        return ""
    lines = ["[CROSS-CASE] NAMES SHARED WITH OTHER FLAGGED INDICATORS IN THIS FEED",
             "  (from the feed's own records: the same domain behind two or more different flagged IPs means the "
             "domain, not the IP, may be the real indicator)"]
    for d in links["domains"]:
        campus = ""
        if "campus_hosts" in d:
            when = " (current data)" if d.get("campus_period_is_current") else ""
            campus = (f"; {d['campus_hosts']} campus host(s) used it over {d['campus_period']}{when}, first seen on "
                      f"campus {d.get('campus_first_seen') or 'not within retention'}")
        lines.append(f"    - {d['domain']}: behind {', '.join(d['indicators'])}; {len(d['hosts'])} host(s) in "
                     f"{d['case_count']} case(s){campus}")
    for r in links["related_cases"]:
        same = " - the SAME visit by this host, matched through another flagged IP" if r["same_visit"] else ""
        lines.append(f"    related case: {r['indicator']} and {r['host']} (via {r['domain']}){same}")
    return "\n".join(lines) + "\n\n"


def _other_matches_section(other_matches: list[dict]) -> str:
    body = "\n".join(
        f"  - {m['indicator']} ({m['malware']}, {m['threat_type']})" for m in other_matches[:10]
    ) or "  (none)"
    return f"THIS HOST'S OTHER IOC MATCHES (from the feed):\n{body}"


def _host_type_section(result: dict | None) -> str:
    title = "[STEP 7b] HOST TYPE AND ITS TYPICAL BEHAVIOUR (host classification)"
    if not result:
        return f"{title}: not run\n\n"
    if "error" in result:
        return f"{title}: could not be worked out ({result['error'][:200]})\n\n"
    if not result.get("label"):
        return f"{title} ({result.get('period', '')}): {result.get('note', 'no classification')}\n\n"
    from .host_type import fmt_feature

    lines = [f"{title}, from the host's own traffic {result['period']}:"]
    if labels.host_type_uncertain(result):
        lines.append(f"  {labels.host_type_text(result).capitalize()}. Do not state a host type as fact: describe "
                     "what the traffic shows (volumes, hours, kinds of use, remote addresses) and give the best "
                     "guess only as a guess.")
    lines.append(f"  Classified as: {result['name']} [{result['label']}], confidence {result['confidence']:.2f}, "
                 f"by {result['method']}")
    others = {k: v for k, v in (result.get("alternatives") or {}).items() if k != result["label"]}
    if others:
        lines.append("  Other possible types: " + ", ".join(f"{k} {v:.2f}" for k, v in others.items()))
    lines.append(f"  Rule-based reading: {result['rule_label']} ({result['rule_reason']})")
    if result.get("hostname_hint"):
        lines.append(f"  Host-name hint (weak): {result['hostname_hint']}")
    ports = result.get("top_ports") or []
    lines.append(f"  Most used remote ports in its large flows: {', '.join(map(str, ports)) or 'none'}")
    comparison = result.get("comparison") or {}
    lines.append(f"  Compared with typical hosts of this type ({comparison.get('source', 'no profile')}):")
    for row in comparison.get("rows", []):
        span = f"{fmt_feature(row['typical_low'], row['unit'])} to {fmt_feature(row['typical_high'], row['unit'])}"
        where = f", {row['percentile']}th percentile" if row.get("percentile") is not None else ""
        flag = "" if row["position"] == "typical" else f"  <-- {row['position'].upper()}"
        lines.append(f"    - {row['description']}: {fmt_feature(row['value'], row['unit'])} "
                     f"(typical {span}{where}){flag}")
    unusual = comparison.get("unusual") or []
    lines.append("  Unusual for this type: " + ("; ".join(r["description"] for r in unusual) if unusual
                                                else "nothing outside the typical range"))
    profile = result.get("profile") or {}
    lines.append("  Typical for this type: " + "; ".join(profile.get("typical") or []))
    if profile.get("abnormal"):
        lines.append("  Would be abnormal for this type: " + "; ".join(profile["abnormal"]))
    if profile.get("compromise"):
        lines.append(f"  What compromise of this type looks like: {profile['compromise']}")
    if profile.get("ioc_reading"):
        lines.append(f"  Reading an IOC match from this type: {profile['ioc_reading']}")
    return "\n".join(lines) + "\n\n"


def _charts_section(options: list[dict]) -> str:
    if not options:
        return "READY-MADE CHARTS: none (too little data); use add_chart for your own.\n\n"
    lines = "\n".join(f"  - {charts.describe(c)}" for c in options)
    return ("READY-MADE CHARTS (built from the evidence above; place 1-3 in the report, each on its own line, "
            f"e.g. [[chart {options[0]['id']}]], then say in your own words what it shows; do not copy these "
            f"descriptions into the report):\n{lines}\n\n")


def _public_intel_section(found: dict | None) -> str:
    header = ("[STEP 4b] PUBLIC THREAT INTEL (looked up online for this case: about the threat in general, "
              "not evidence about this host)")
    found = found or {}
    if not found.get("enabled", True):
        return f"{header}\n  Not looked up (WEB_CONTEXT=0)."
    lines = [header]
    family = found.get("malpedia")
    if family:
        aliases = f" (also known as {', '.join(family['aliases'])})" if family.get("aliases") else ""
        lines.append(f"  Malpedia, {family['name']}{aliases}: \"{family['description']}\" ({family['url']})")
    else:
        lines.append("  Malpedia: no entry for this malware family (or no family given).")
    for listing in found.get("threatfox") or []:
        lines.append(f"  ThreatFox lists {listing.get('ioc')} as {listing.get('malware_printable') or listing.get('malware')}"
                     f", {listing.get('threat_type')}, confidence {listing.get('confidence_level')}, first seen "
                     f"{listing.get('first_seen')}, last seen {listing.get('last_seen') or 'not given'}, reported by "
                     f"{listing.get('reporter') or 'unknown'}" + (f"; reference {listing['reference']}"
                                                                 if listing.get("reference") else ""))
    if not found.get("threatfox") and "ThreatFox" not in " ".join(found.get("errors") or []):
        lines.append("  ThreatFox: no listing of this exact indicator.")
    web = found.get("web")
    if web and web.get("summary"):
        lines.append("  WEB CONTEXT (external, unverified; cite the source URL). Flow data outranks it: if they "
                     "conflict, follow the flow data and say so. It never decides the verdict on its own.")
        lines += [f"    {line}" for line in web["summary"].splitlines()]
        lines += [f"    Source: {source['url']}" for source in web.get("sources") or []]
    lines += [f"  (lookup failed: {error})" for error in found.get("errors") or []]
    return "\n".join(lines)


DATA_LIMITATIONS = [
    "Flow data only: no payloads, so the content of any session is unknown.",
    "long_flow_summary only holds flows over a size/duration threshold; short flows are missing.",
    "subscriber_activity_1m keeps about 15 days; older per-minute detail is gone.",
    "Visitors reaching the host through a tunnel appear as the tunnel server's IP, so they are hidden.",
    "Threat context comes from a local knowledge base and the public sources cited (Malpedia, ThreatFox and, "
    "when listed, a web search); nothing else was looked up online.",
]


def build_case_file(ev: dict, blind: bool = False) -> str:
    """ev is the evidence dict from assess.gather_evidence. blind=True leaves
    out the rules' conclusions (signal table, behaviour category, baseline
    verdict): that is the version the model reviews, so its verdict is an
    independent check rather than agreement with an answer it was shown.
    Reviewers get the full version."""
    limitations = "\n".join(f"  - {item}" for item in DATA_LIMITATIONS)
    conclusions = "" if blind else _signals_section(ev) + "\n\n"
    return f"""CASE FILE
The evidence below was gathered automatically just now (steps 1-5, 7 and 8 of the workflow).
The source's confidence rates the indicator, not this host.

{_ioc_section(ev['identity'], ev.get('host'))}

{_usage_section(ev.get('other_traffic') or {})}

{_ips_section(ev['server_ips'], ev['flows'], ev.get('asn'))}

{_expected_section(ev['identity'], ev['expected'])}

{_public_intel_section(ev.get('web_context'))}

{_features_section(ev.get('domain_features', []))}

{_flows_section(ev['flows'])}

{_names_section(ev.get('names', {"source": "none", "names": []}))}

{_contact_section(ev.get('contact') or {"pattern": "insufficient_data", "description": "not run", "features": {}})}

{_timeline_section(ev.get('timeline'), bool(((ev.get('flows') or {}).get('direction') or {}).get('inbound_likely')))}

{_apps_section(ev.get('app_context') or {}, ev.get('host_apps') or {})}

{_other_traffic_section(ev['other_traffic'])}
{_load_section(ev.get('load') or {})}

{_host_type_section(ev.get('host_type'))}
{_dns_section(ev.get('dns') or {"present": False})}

{_peers_section(ev['peers'], ev['shared'])}

{_names_on_ip_section(ev.get('names_on_ip', []))}

{_correlation_section(ev.get('correlation'))}{_other_matches_section(ev['other_matches'])}

DATA LIMITATIONS (always true for this data):
{limitations}

{_charts_section(ev.get('chart_options') or [])}{conclusions}Investigate anything this leaves open with the tools, \
then reply in the format from the instructions: the header fields, then the report in its four parts.
"""

"""Render one case's evidence as the plain-text case file the model reads.

Sections follow the workflow steps. Every fact names the table it came from,
so the model (and a reviewer reading the saved case file) can trace it.
"""
from __future__ import annotations

from . import config, schema
from .analysis import fmt_bytes, fmt_duration

LFS = "long_flow_summary"
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


def _flow_line(f: dict) -> str:
    line = (
        f"    - {f['start']} -> {f['finish']} ({fmt_duration(f['duration_sec'])}), "
        f"{f['server_ip']}:{f['server_port']}/{f['protocol']} from client port {f['client_port']}, "
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


def _ioc_section(identity: dict, host: dict | None = None) -> str:
    metadata = identity.get("ioc_metadata")
    if metadata:
        intel = "\n".join(f"  {k}: {v}" for k, v in metadata.items())
        intel = "ThreatFox entry details (entered by hand in data/ioc_metadata.json):\n" + intel
    else:
        intel = ("ThreatFox entry dates, reporter and ID: not available (the feed does not carry them; "
                 "they can be added by hand in data/ioc_metadata.json).")
    return f"""[STEP 1] IOC MATCH
Indicator: {identity['indicator']} (type={identity['indicator_type']})
Affected {config.HOST_LABEL}: {identity['affected_asset']}
{_host_line(host)}
Feed match records for this pair: {identity['n_events']} (one per matching per-minute row, not separate incidents)
Evidence first/last seen (UTC): {identity['evidence_first_seen']} / {identity['evidence_last_seen']}{_local_pair(identity['evidence_first_seen'], identity['evidence_last_seen'])}
  (these are the matched flow's own times, NOT ThreatFox's dates for the indicator)

[STEP 2] IOC CONTEXT (ThreatFox, via the feed)
Malware family: {identity['malware']}
Threat type: {identity['threat_type']}
ThreatFox confidence: {identity['threatfox_confidence']}/100
{intel}"""


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
    return f"""[STEP 4] EXPECTED BEHAVIOUR (local knowledge base)
Malware family: {malware.get('family')}
  {malware.get('notes')}
Threat type {identity['threat_type']}:
  Expected traffic shape: {threat.get('expected_traffic_shape')}
  Expected recurrence: {threat.get('expected_recurrence')}
  Common false-positive pattern: {threat.get('false_positive_pattern')}
{_service_block(expected.get('service'), expected.get('service_port_fit', []), expected.get('service_port_verdict'))}"""


# --- step 5 --------------------------------------------------------------------

def _port_lines(ports: list[dict]) -> str:
    return "\n".join(
        f"    - {p['port']}/{p['protocol']}: {p['flows']} flow(s), up {fmt_bytes(p['up_bytes'])} "
        f"({p['up_packets']} pkts), down {fmt_bytes(p['down_bytes'])} ({p['down_packets']} pkts), "
        f"total duration {fmt_duration(p['total_duration_sec'])}, {p['first_start']} to {p['last_finish']}"
        for p in ports
    ) or "    (no long flows)"


def _activity_port_lines(ports: list[dict]) -> str:
    return "\n".join(
        f"    - {p['port']}/{p['protocol']}: {p['active_minutes']} active minute(s), "
        f"up {fmt_bytes(p['up_bytes'])} ({p['up_packets']} pkts), "
        f"down {fmt_bytes(p['down_bytes'])} ({p['down_packets']} pkts), {p['first_minute']} to {p['last_minute']}"
        for p in ports
    ) or "    (no per-minute rows in the retention window)"


def _classification_lines(c: dict) -> str:
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
        lines.extend(_flow_line(f) for f in held["flows"])
    other = c.get("other_flows") or {}
    if other.get("count"):
        lines.append(f"  Other flows over 1 MB (under an hour): {other['count']}.")
    return "\n".join(lines)


def _flow_key(f: dict) -> tuple:
    return f["start"], f["client_port"]


def _notable_lines(notable: dict, already_listed: set[tuple]) -> str:
    largest = notable["largest_by_total_bytes"]
    new = [f for f in largest if _flow_key(f) not in already_listed]
    repeated = len(largest) - len(new)
    note = f" ({repeated} of the top {len(largest)} are the held-open flows listed above)" if repeated else ""
    lines = [f"  Largest flows by total bytes{note}:"]
    lines.extend(_flow_line(f) for f in new)
    heavy_total = notable.get("upload_heavy_total")
    if heavy_total:
        lines.append(
            f"  Upload-heavy flows (up at least 2x down): {heavy_total['count']}, lasting "
            f"{fmt_duration(heavy_total['min_duration_sec'])} to {fmt_duration(heavy_total['max_duration_sec'])}, "
            f"{fmt_bytes(heavy_total['up_bytes'])} up vs {fmt_bytes(heavy_total['down_bytes'])} down in total. Most upload-heavy:"
        )
        lines.extend(_flow_line(f) for f in notable["most_upload_heavy"])
    else:
        lines.append("  Upload-heavy flows (up at least 2x down): none.")
    return "\n".join(lines)


def _held_open_keys(classification: dict) -> set[tuple]:
    held = classification.get("held_open") or {}
    return {_flow_key(f) for f in held.get("flows", [])}


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
    return f"""{header}
Window: {LFS} {window['long_flow_summary']}; {SA} {window['subscriber_activity_1m']}
  What was checked:
{checked}
Ports seen (both tables): {', '.join(flows['ports_seen']) or '(none)'}
Per-port breakdown ({lfs}, {flows['long_flow_count']} flow(s)):
{_port_lines(flows['ports'])}
Per-port activity ({sa}):
{_activity_port_lines(activity.get('ports', []))}
{_classification_lines(flows['classification'])}
{_notable_lines(flows['notable'], _held_open_keys(flows['classification']))}
{exfil_line}{_retention_line(flows)}
  Active periods ({lfs}, flows less than 1 hour apart merged):
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
    """" [local: a / b]" when a local time zone is set, else empty."""
    a, b = config.to_local(first), config.to_local(last)
    if not a:
        return ""
    return f" [local: {a}{sep}{b}]"


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
  Long-lived flows (1 hour or longer) to other IPs ({LFS}):
{long_lived}
  Root domains contacted, busiest first ({SA}, {other['distinct_root_domains']} distinct): {domains}
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
                   None: "connected all the time with little traffic at night: background traffic, which says "
                         "nothing about what the machine is"}[uptime.get("always_on")]
    return f"Uptime: {'; '.join(parts) or 'no data'} -> {verdict}. Every host shows some traffic every hour, so only volume counts."


def _retention_line(flows: dict) -> str:
    cut = flows.get("retention_cut")
    if not cut:
        return ""
    return (f"\n  NOTE: long_flow_summary now only holds flows that finished on or after {cut}, and this host's "
            "activity reaches that edge, so earlier activity may be missing.")


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
            f"  {p['server_ip']}{port}, last {p['lookback_days']} days ({LFS}): {p['distinct_host_count']} "
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
        kind = f"public: {r['public_resolver']}" if r["public_resolver"] else ("RARE on campus" if r["rare"] else "")
        lines.append(f"    - {r['server_ip']}: {r['answered']} answered, {r['unanswered']} unanswered, "
                     f"{r['campus_clients']} campus client(s) in a day" + (f" [{kind}]" if kind else ""))
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
Give this verdict unless the evidence above contradicts a signal. If so, name that signal in BASELINE_OVERRIDE."""


def _other_matches_section(other_matches: list[dict]) -> str:
    body = "\n".join(
        f"  - {m['indicator']} ({m['malware']}, {m['threat_type']})" for m in other_matches[:10]
    ) or "  (none)"
    return f"THIS HOST'S OTHER IOC MATCHES (from the feed):\n{body}"


DATA_LIMITATIONS = [
    "Flow data only: no payloads, so the content of any session is unknown.",
    "long_flow_summary only holds flows over a size/duration threshold; short flows are missing.",
    "subscriber_activity_1m keeps about 15 days; older per-minute detail is gone.",
    "Visitors reaching the host through a tunnel appear as the tunnel server's IP, so they are hidden.",
    "No internet research: service and malware context comes from the local knowledge base only.",
]


def build_case_file(ev: dict) -> str:
    """ev is the evidence dict from assess.gather_evidence."""
    limitations = "\n".join(f"  - {item}" for item in DATA_LIMITATIONS)
    return f"""CASE FILE
Steps 1-5, 7 and 8 were gathered automatically just now. Your job: steps 6 and 9.
ThreatFox confidence rates the indicator, not this host.

{_ioc_section(ev['identity'], ev.get('host'))}

{_ips_section(ev['server_ips'], ev['flows'], ev.get('asn'))}

{_expected_section(ev['identity'], ev['expected'])}

{_features_section(ev.get('domain_features', []))}

{_flows_section(ev['flows'])}

{_names_section(ev.get('names', {"source": "none", "names": []}))}

{_contact_section(ev.get('contact') or {"pattern": "insufficient_data", "description": "not run", "features": {}})}

{_apps_section(ev.get('app_context') or {}, ev.get('host_apps') or {})}

{_other_traffic_section(ev['other_traffic'])}
{_load_section(ev.get('load') or {})}

{_dns_section(ev.get('dns') or {"present": False})}

{_peers_section(ev['peers'], ev['shared'])}

{_names_on_ip_section(ev.get('names_on_ip', []))}

{_other_matches_section(ev['other_matches'])}

DATA LIMITATIONS (always true for this data):
{limitations}

{_signals_section(ev)}

If something above doesn't answer what you need, use a follow-up tool. \
Otherwise, answer now using the evidence above.
"""

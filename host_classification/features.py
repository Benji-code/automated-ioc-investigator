"""Per-host behaviour features for host classification.

One feature set, used twice:
  - campus-wide (`extract_population`): every active host in CAMPUS_CIDR over
    a period, to train the classifier and build per-type profiles;
  - one host (`extract`): the case's host over the days before the match, so
    it is compared like with like.

Feature groups (all from SuperNetFlow tables checked against the deployment):
  load_*     subscriber_ip_load_enriched_1h: volume, burstiness, uptime
  client_*   long_flow_summary: the host's large flows: peers, server ports,
             protocols, port groups (web, remote, mail, ...), upload share
  app_*      app_subscriber_enriched_1h: how many apps and categories the
             host uses (this table drops unlabelled traffic)
  dns_*      reverse-DNS name patterns (weak hints)

SuperNetFlow records every flow from the campus host's side: the campus host
is always client_ip and the remote party server_ip, whoever connected to
whom (checked: no campus host appears as server_ip, in long_flow_summary or
app_server_enriched_1h). So a server shows up through what it does, not a
direction field: it sends more than it receives, to many peers, around the
clock.

long_flow_summary only holds flows over 1 MB, so the flow features describe
larger sessions; quiet hosts can have none. Per-minute and 5-minute tables are
not used here: they are sorted by subscriber_id, and a campus-wide scan of
them over a week hits the 200M-row read limit.

Refined from the original feature_extraction.py and script.py. script.py's
"connected in every hour of the day" check was dropped: on this deployment
every host shows background traffic in every hour (all 21 active seed hosts
scored the same), so it separates nothing; night-vs-day volume is used instead.
"""
from __future__ import annotations

import json
import logging
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Iterable, Sequence

import pandas as pd

from agent import config, db

LOAD_TABLE = "canopus_dbt.subscriber_ip_load_enriched_1h"
FLOW_TABLE = "public.long_flow_summary"
APP_TABLE = "canopus_dbt.app_subscriber_enriched_1h"
BATCH_SIZE = 500

# Feature groups, not rules: the share of a host's flows on each.
PORT_GROUPS: dict[str, list[int]] = {
    "web_http": [80, 8000, 8008, 8080, 8888],
    "web_https": [443, 8443],
    "dns": [53],
    "mail": [25, 465, 587, 110, 995, 143, 993],
    "remote": [22, 23, 3389, 5900, 5901, 5902, 5985, 5986],
    "file_storage": [20, 21, 69, 111, 139, 445, 873, 2049],
    "vpn": [500, 4500, 1194, 1701, 1723],
    "ntp": [123],
    "database": [1433, 1521, 3306, 5432, 6379, 9200, 27017],
}

HOSTNAME_PATTERNS: dict[str, str] = {
    "dns_has_www": r"(^|[.-])www\d*([.-]|$)",
    "dns_has_web": r"(^|[.-])(web|http|https|site|cms)([.-]|$)",
    "dns_has_proxy": r"(^|[.-])(proxy|cache|squid)([.-]|$)",
    "dns_has_mail": r"(^|[.-])(mail|smtp|imap|pop|mx|exchange|owa)([.-]|$)",
    "dns_has_dns": r"(^|[.-])(dns|bind|resolver)([.-]|$)",
    "dns_has_ns": r"(^|[.-])ns\d*([.-]|$)",
    "dns_has_vpn": r"(^|[.-])(vpn|openvpn|ipsec|wireguard|remoteaccess)([.-]|$)",
    "dns_has_file": r"(^|[.-])(file|files|ftp|sftp|nfs|smb|share|storage|nas|fs)([.-]|$)",
    "dns_has_remote": r"(^|[.-])(ssh|login|compute|hpc|rdp|vnc|remote|terminal|jumphost|bastion)([.-]|$)",
    "dns_has_gateway": r"(^|[.-])(gw|gateway|nat|pat|router|firewall|fw|lb|loadbalancer)([.-]|$)",
    "dns_has_database": r"(^|[.-])(db|database|sql|mysql|postgres|oracle|mongo|redis)([.-]|$)",
}

NIGHT_HOURS = (0, 6)    # local time, as in tools.host_uptime
DAY_HOURS = (9, 21)


# --- helpers ----------------------------------------------------------------------------

def _ips(ips: Sequence[str]) -> str:
    return ", ".join(f"'{db._escape(ip)}'" for ip in ips)


def _when(start: datetime, end: datetime, column: str) -> str:
    return (f"{column} >= toDateTime('{start:%Y-%m-%d %H:%M:%S}', 'UTC') "
            f"AND {column} < toDateTime('{end:%Y-%m-%d %H:%M:%S}', 'UTC')")


def _batches(items: Sequence[str], size: int = BATCH_SIZE) -> Iterable[list[str]]:
    for i in range(0, len(items), size):
        yield list(items[i: i + size])


def ratio(num, den) -> float:
    try:
        num, den = float(num or 0), float(den or 0)
    except (TypeError, ValueError):
        return 0.0
    return num / den if den else 0.0


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    if hasattr(value, "tolist"):
        return list(value.tolist())
    return [value]


def _query(sql_for_filter, ips: Sequence[str], campus: bool = False, one_host_filter=None) -> pd.DataFrame:
    """Run a feature query for these hosts. sql_for_filter takes the WHERE
    clause that picks the hosts. Campus mode: ONE query over the campus range,
    kept to `ips` afterwards (batches of `client_ip IN (...)` reread the whole
    period on tables not sorted by client_ip, so 20 batches meant 20 scans).
    Otherwise: batches of addresses, or one_host_filter for a single host."""
    if campus:
        frame = db.query(sql_for_filter(f"isIPAddressInRange(client_ip, '{db._escape(campus_cidr())}')"))
        if frame.empty:
            return pd.DataFrame({"ip": []})
        frame["ip"] = frame["ip"].astype(str)
        return frame[frame["ip"].isin(set(ips))].reset_index(drop=True)
    frames = []
    for batch in _batches(ips):
        where = one_host_filter(batch[0]) if one_host_filter and len(batch) == 1 else f"client_ip IN ({_ips(batch)})"
        frames.append(db.query(sql_for_filter(where)))
    frames = [f for f in frames if not f.empty]
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame({"ip": []})


# --- campus population -------------------------------------------------------------------

def campus_cidr() -> str:
    if not config.CAMPUS_CIDR:
        raise SystemExit("Set CAMPUS_CIDR in .env (the campus address range, e.g. 192.0.2.0/24) to select "
                         "campus hosts for host classification.")
    return config.CAMPUS_CIDR


def select_active_ips(start: datetime, end: datetime, max_ips: int = 10000) -> list[str]:
    """Campus hosts with traffic in the period, busiest first."""
    limit = f"LIMIT {int(max_ips)}" if max_ips > 0 else ""
    frame = db.query(f"""
    SELECT client_ip AS ip, sum(active_minutes) AS minutes,
           sum(metrics_sum__up_volume__bytes + metrics_sum__down_volume__bytes) AS volume
    FROM {LOAD_TABLE}
    WHERE isIPAddressInRange(client_ip, '{db._escape(campus_cidr())}') AND {_when(start, end, 'time')}
    GROUP BY ip ORDER BY minutes DESC, volume DESC {limit}
    """)
    return frame["ip"].astype(str).tolist() if not frame.empty else []


# --- feature groups ----------------------------------------------------------------------

def load_features(ips: Sequence[str], start: datetime, end: datetime, campus: bool = False) -> pd.DataFrame:
    """Volume, burstiness and uptime from the hourly load table."""
    zone = db._escape(config.LOCAL_TIMEZONE)
    total = "toFloat64(metrics_sum__up_volume__bytes + metrics_sum__down_volume__bytes)"
    local_hour = f"toHour(toTimezone(time, '{zone}'))"
    frame = _query(lambda where: f"""
    SELECT client_ip AS ip,
           count() AS load_rows,
           uniqExact(toStartOfHour(time)) AS load_observed_hours,
           sum(active_minutes) AS load_active_minutes,
           sum(toFloat64(metrics_sum__up_volume__bytes)) AS load_up_bytes,
           sum(toFloat64(metrics_sum__down_volume__bytes)) AS load_down_bytes,
           avg({total}) AS load_hourly_bytes_mean,
           stddevPop({total}) AS load_hourly_bytes_std,
           quantileTDigest(0.5)({total}) AS load_hourly_bytes_p50,
           quantileTDigest(0.95)({total}) AS load_hourly_bytes_p95,
           max({total}) AS load_hourly_bytes_max,
           medianIf({total}, {local_hour} >= {NIGHT_HOURS[0]} AND {local_hour} < {NIGHT_HOURS[1]}) AS load_night_bytes_p50,
           medianIf({total}, {local_hour} >= {DAY_HOURS[0]} AND {local_hour} < {DAY_HOURS[1]}) AS load_day_bytes_p50
    FROM {LOAD_TABLE}
    WHERE {where} AND {_when(start, end, 'time')}
    GROUP BY ip
    """, ips, campus)
    if frame.empty:
        return pd.DataFrame({"ip": list(ips)})
    expected_hours = max((end - start).total_seconds() / 3600, 1)
    total_bytes = frame["load_up_bytes"] + frame["load_down_bytes"]
    frame["load_total_bytes"] = total_bytes
    frame["load_daily_bytes"] = total_bytes / max(expected_hours / 24, 1)
    frame["load_hours_share"] = frame["load_observed_hours"] / expected_hours
    frame["load_up_byte_ratio"] = [ratio(u, t) for u, t in zip(frame["load_up_bytes"], total_bytes)]
    frame["load_bytes_per_active_minute"] = [ratio(t, m) for t, m in zip(total_bytes, frame["load_active_minutes"])]
    frame["load_hourly_bytes_cv"] = [ratio(s, m) for s, m in
                                     zip(frame["load_hourly_bytes_std"], frame["load_hourly_bytes_mean"])]
    frame["load_peak_to_mean"] = [ratio(x, m) for x, m in
                                  zip(frame["load_hourly_bytes_max"], frame["load_hourly_bytes_mean"])]
    frame["load_night_day_ratio"] = [ratio(n, d) for n, d in
                                     zip(frame["load_night_bytes_p50"], frame["load_day_bytes_p50"])]
    return frame


def flow_features(ips: Sequence[str], start: datetime, end: datetime, campus: bool = False) -> pd.DataFrame:
    """The host's large flows (over 1 MB): peers, ports, protocols, upload share."""
    group_counts = ",\n           ".join(
        f"countIf(server_port IN ({', '.join(map(str, ports))})) AS {name}_flows"
        for name, ports in PORT_GROUPS.items())
    frame = _query(lambda where: f"""
    SELECT client_ip AS ip,
           count() AS flows,
           sum(toFloat64(up_bytes)) AS up_total,
           sum(toFloat64(down_bytes)) AS down_total,
           countIf(protocol = 6) AS tcp_flows,
           countIf(protocol = 17) AS udp_flows,
           countIf(up_bytes > down_bytes) AS upload_heavy_flows,
           uniqExact(server_ip) AS unique_peers,
           uniqExact(server_port) AS unique_ports,
           topK(10)(server_port) AS top_ports,
           countIf(server_port >= 49152) AS ephemeral_port_flows,
           avg(toFloat64(duration_sec)) AS avg_duration_sec,
           quantileTDigest(0.95)(toFloat64(duration_sec)) AS p95_duration_sec,
           {group_counts}
    FROM {FLOW_TABLE}
    WHERE {where} AND {_when(start, end, 'start')}
    GROUP BY ip
    """, ips, campus)
    out = pd.DataFrame({"ip": list(ips)})
    if frame.empty:
        return out
    # Aggregates are aliased *_total: ClickHouse substitutes an alias that
    # matches a column name into the rest of the query (see db.TOTALS_TO_BYTES).
    frame = frame.rename(columns={"up_total": "up_bytes", "down_total": "down_bytes"})
    frame["top_ports"] = frame["top_ports"].apply(lambda v: [int(p) for p in _as_list(v)])
    flows = frame["flows"]
    frame["bytes"] = frame["up_bytes"] + frame["down_bytes"]
    frame["bytes_per_flow"] = [ratio(b, f) for b, f in zip(frame["bytes"], flows)]
    frame["up_byte_ratio"] = [ratio(u, b) for u, b in zip(frame["up_bytes"], frame["bytes"])]
    for base in ["tcp_flows", "udp_flows", "upload_heavy_flows", "ephemeral_port_flows"] + \
            [f"{g}_flows" for g in PORT_GROUPS]:
        frame[f"{base}_ratio"] = [ratio(c, f) for c, f in zip(frame[base], flows)]
    frame["unique_peers_per_1000_flows"] = [1000 * ratio(c, f) for c, f in zip(frame["unique_peers"], flows)]
    out = out.merge(frame.rename(columns={c: f"client_{c}" for c in frame.columns if c != "ip"}), on="ip", how="left")
    for col in out.columns:
        if col == "client_top_ports":
            out[col] = out[col].apply(_as_list)
        elif col != "ip":
            out[col] = pd.to_numeric(out[col], errors="coerce").fillna(0)
    return out


def app_features(ips: Sequence[str], start: datetime, end: datetime, campus: bool = False) -> pd.DataFrame:
    """How many apps and categories the host uses. A single host adds its
    subscriber_id (db._host): this table is sorted by it."""
    frame = _query(lambda where: f"""
    SELECT client_ip AS ip,
           uniqExact(application) AS app_unique_apps,
           uniqExact(application_category) AS app_unique_categories,
           sum(active_minutes) AS app_minutes,
           topK(8)(application) AS app_top_apps
    FROM {APP_TABLE}
    WHERE {where} AND {_when(start, end, 'time')}
    GROUP BY ip
    """, ips, campus, one_host_filter=db._host)
    if frame.empty:
        return pd.DataFrame({"ip": list(ips)})
    frame["app_top_apps"] = frame["app_top_apps"].apply(lambda v: [str(a) for a in _as_list(v)])
    return frame


def hostname_features(hostname: str | None) -> dict:
    name = (hostname or "").lower().rstrip(".")
    features = {"dns_hostname": name, "dns_has_ptr": int(bool(name))}
    for key, pattern in HOSTNAME_PATTERNS.items():
        features[key] = int(bool(name and re.search(pattern, name)))
    features["dns_hint_label"] = hostname_hint(features)
    return features


def hostname_hint(features: dict) -> str:
    """A weak hint from the name alone, never a label by itself."""
    name = features.get("dns_hostname") or ""
    if not name:
        return ""
    for key, hint in (("dns_has_proxy", "web_proxy"), ("dns_has_mail", "mail_server"),
                      ("dns_has_vpn", "vpn_server"), ("dns_has_file", "file_storage_server"),
                      ("dns_has_remote", "remote_computing_server"), ("dns_has_gateway", "NAT_gateway"),
                      ("dns_has_ns", "dns_server"), ("dns_has_dns", "dns_server"),
                      ("dns_has_www", "website_server"), ("dns_has_web", "website_server"),
                      ("dns_has_database", "non_typical_tcp_server")):
        if features.get(key):
            return hint
    return ""


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def reverse_dns_features(ips: Sequence[str], workers: int = 32) -> pd.DataFrame:
    socket.setdefaulttimeout(config.REVERSE_DNS_TIMEOUT_SEC)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        names = list(pool.map(_reverse_dns, ips))
    return pd.DataFrame([{"ip": ip, **hostname_features(name)} for ip, name in zip(ips, names)])


# --- putting it together -------------------------------------------------------------------

LIST_COLUMNS = ("client_top_ports", "app_top_apps")


def _timed(label: str, fn, *args, **kwargs):
    began = time.monotonic()
    result = fn(*args, **kwargs)
    logging.info("  %s: %.0f s", label, time.monotonic() - began)
    return result


def extract(ips: Sequence[str], start: datetime, end: datetime, hostnames: dict[str, str] | None = None,
            reverse_dns: bool = False, campus: bool = False) -> pd.DataFrame:
    """The feature matrix for these hosts over [start, end): one row per IP.
    Host names come from `hostnames` if given, else reverse DNS if asked.
    campus=True reads each table once over CAMPUS_CIDR (for the whole
    population) instead of per host."""
    ips = [str(ip) for ip in ips]
    frame = pd.DataFrame({"ip": ips})
    for label, feature_fn in (("load", load_features), ("large flows", flow_features), ("apps", app_features)):
        part = _timed(label, feature_fn, ips, start, end, campus=campus) if campus else \
            feature_fn(ips, start, end)
        if len(part.columns) > 1:
            frame = frame.merge(part, on="ip", how="left")
    if hostnames is not None:
        names = pd.DataFrame([{"ip": ip, **hostname_features(hostnames.get(ip))} for ip in ips])
        frame = frame.merge(names, on="ip", how="left")
    elif reverse_dns:
        frame = frame.merge(_timed(f"reverse DNS ({len(ips)} lookups)", reverse_dns_features, ips),
                            on="ip", how="left")
    for col in frame.columns:
        if col in LIST_COLUMNS:
            frame[col] = frame[col].apply(_as_list)
        elif col not in ("ip", "dns_hostname", "dns_hint_label"):
            frame[col] = pd.to_numeric(frame[col], errors="coerce").fillna(0)
    frame.attrs["period"] = f"{start:%Y-%m-%d %H:%M} to {end:%Y-%m-%d %H:%M} UTC"
    return frame


def extract_population(start: datetime, end: datetime, max_ips: int = 10000,
                       reverse_dns: bool = True) -> pd.DataFrame:
    """Features for every active campus host (busiest first, up to max_ips):
    one query per table over the campus range."""
    ips = _timed("selecting hosts", select_active_ips, start, end, max_ips)
    logging.info("Selected %d campus hosts; reading features%s", len(ips),
                 "" if reverse_dns else " (no reverse DNS)")
    return extract(ips, start, end, reverse_dns=reverse_dns, campus=True)


def to_csv(frame: pd.DataFrame, path) -> None:
    """Lists become JSON text so the CSV reads back cleanly."""
    out = frame.copy()
    for col in LIST_COLUMNS:
        if col in out:
            out[col] = out[col].apply(lambda v: json.dumps([x.item() if hasattr(x, "item") else x for x in v]))
    out.to_csv(path, index=False)


def read_csv(path) -> pd.DataFrame:
    frame = pd.read_csv(path)
    frame["ip"] = frame["ip"].astype(str)
    for col in LIST_COLUMNS:
        if col in frame:
            frame[col] = frame[col].apply(lambda v: json.loads(v) if isinstance(v, str) and v else [])
    for col in ("dns_hostname", "dns_hint_label"):
        if col in frame:
            frame[col] = frame[col].fillna("")
    return frame

"""Find campus contacts with a list of indicators and write match records.

The records have the same format as the IOC-match feed assess.py already
reads: one record per (indicator, campus host, minute) with the matched
per-minute rows, long flows attached, an `intel` block and a match_id. So a
MISP pull or a manual entry goes through the rest of the pipeline unchanged.

  normalise_indicator()  'https://x.example/a' -> ('x.example', 'domain'), '1.2.3.4|443' -> ip:port, ...
  merge_indicators()     one entry per indicator, tags and references combined
  screen_services()      drop bare link-sharing/hosting service domains (share.google, ...)
  match()                indicators -> match records (queries ClickHouse)
  write_jsonl()          records -> a .jsonl feed

ClickHouse limits: a query may read at most 200M rows, and subscriber_activity_1m
is sorted by subscriber_id, so a campus-wide search reads every row in its
time range. Each query covers at most MATCH_CHUNK_DAYS (never more than 5),
and indicators go in IN (...) lists in batches, one query per window and
batch rather than one per indicator.
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

from . import config, db, evidence, knowledge

# Exactly the columns of the feed's evidence rows.
ACTIVITY_COLUMNS = [
    "time", "client_ip", "server_ip", "server_port", "ip_protocol", "transport_protocol", "sni", "dns",
    "root_domain", "down_volume__bytes", "up_volume__bytes", "down_volume__packets", "up_volume__packets",
    "flow_count", "server_metadata__asn", "server_metadata__asn_organization", "server_metadata__geo_country",
    "server_metadata__geo_city", "subscriber_metadata__operator", "subscriber_metadata__country",
    "subscriber_metadata__device", "network_metadata__country", "network_metadata__operator",
]
FLOW_COLUMNS = [
    "start", "finish", "duration_sec", "flow_id", "client_ip", "server_ip", "client_port", "server_port",
    "protocol", "down_bytes", "up_bytes", "down_packets", "up_packets", "classifier", "type",
]
NAME_FIELDS = ("sni", "dns", "root_domain")
# Indicators per IN (...) list, by size: a name list appears three times
# (sni, dns, root_domain) and ClickHouse's default max_query_size is 256 KB.
BATCH_CHARS = 60_000
MAX_ROWS_PER_QUERY = 100_000


# --- indicators --------------------------------------------------------------------

def _host_of_url(value: str) -> str:
    text = value if "://" in value else f"http://{value}"
    return (urlsplit(text).hostname or "").strip(".").lower()


def normalise_indicator(value: str, kind: str | None = None) -> tuple[str, str] | None:
    """(indicator, indicator_type) as the pipeline uses them: 'ip', 'ip:port'
    or 'domain'. kind is a MISP type (ip-dst, ip-dst|port, domain, hostname,
    url) or None to guess. A URL is reduced to its host name. None for
    values SuperNetFlow cannot match (IPv6, empty, malformed)."""
    value = (value or "").strip()
    if not value:
        return None
    if kind == "url" or "://" in value or "/" in value:
        value = _host_of_url(value)
    if kind == "ip-dst|port" or "|" in value:
        ip, _, port = value.partition("|")
        value = f"{ip.strip()}:{port.strip()}"
    parsed = evidence.parse_ip_port(value)
    if parsed and parsed[1] is not None and evidence.is_ip(parsed[0]):
        return f"{parsed[0]}:{parsed[1]}", "ip:port"
    if evidence.is_ip(value):
        return value, "ip"
    name = value.lower().rstrip(".")
    if ":" in name or "." not in name or " " in name:
        return None
    return name, "domain"


def listed_url(value: str, kind: str | None = None) -> str | None:
    """The value if it is a URL naming a page (a path or query beyond "/"),
    else None: a URL with no path names the whole site."""
    value = (value or "").strip()
    if not (kind == "url" or "://" in value or "/" in value):
        return None
    parts = urlsplit(value if "://" in value else f"http://{value}")
    return value if parts.path.strip("/") or parts.query else None


def merge_indicators(items: list[dict]) -> list[dict]:
    """One entry per indicator. The intel with the highest confidence wins;
    tags and references from every entry are kept (MISP often lists the same
    value in several events)."""
    merged: dict[str, dict] = {}
    for item in items:
        current = merged.get(item["indicator"])
        if current is None:
            merged[item["indicator"]] = {**item, "intel": dict(item["intel"]),
                                         "listed_urls": list(item.get("listed_urls") or [])}
            continue
        current["listed_urls"] = list(dict.fromkeys(current["listed_urls"] + list(item.get("listed_urls") or [])))
        best = current["intel"]
        if (item["intel"].get("confidence") or 0) > (best.get("confidence") or 0):
            best = {**item["intel"], "tags": best.get("tags"), "references": best.get("references")}
        for field in ("tags", "references"):
            best[field] = list(dict.fromkeys((best.get(field) or []) + (item["intel"].get(field) or [])))
        current["intel"] = best
    return list(merged.values())


MAX_LISTED_URLS = 5


def screen_services(items: list[dict]) -> tuple[list[dict], list[str]]:
    """(indicators to match, indicators skipped as known services). A domain
    on agent/data/service_domains.txt (share.google, bit.ly, docs.google.com
    ...) is one URL on a big shared service, not the service: a bare domain
    is skipped, and a URL is kept but matched only where the flow names its
    exact host (SNI or DNS), with a note that the URL itself cannot be seen."""
    kept, skipped = [], []
    for item in items:
        service = knowledge.service_domain(item["indicator"]) if item["indicator_type"] == "domain" else None
        urls = list(item.get("listed_urls") or [])
        if service and not urls:
            skipped.append(item["indicator"])
            continue
        intel = dict(item["intel"])
        if urls:
            intel["listed_urls"] = urls[:MAX_LISTED_URLS]
        if service:
            intel["known_service"] = service
        kept.append({**item, "intel": intel, "exact_host_only": bool(service)})
    return kept, sorted(skipped)


# --- queries --------------------------------------------------------------------

def _batches(values: list[str], max_chars: int = BATCH_CHARS) -> list[list[str]]:
    """Consecutive pieces whose quoted values total at most max_chars."""
    batches, current, size = [], [], 0
    for value in values:
        cost = len(value) + 4  # quotes, comma, space
        if current and size + cost > max_chars:
            batches.append(current)
            current, size = [], 0
        current.append(value)
        size += cost
    if current:
        batches.append(current)
    return batches


def _in(column: str, values: list[str]) -> str | None:
    return f"{column} IN ({db._ip_list(values)})" if values else None


def activity_sql(ips: list[str], names: list[str], start: datetime, end: datetime) -> str:
    """Campus-wide per-minute rows to any of the IPs or names in one window."""
    conditions = [c for c in (_in("server_ip", ips), *(_in(f, names) for f in NAME_FIELDS)) if c]
    return f"""
    SELECT {', '.join(ACTIVITY_COLUMNS)}
    FROM {db.SUBSCRIBER_ACTIVITY_TABLE}
    WHERE {db._time_filter("time", start, end)} AND ({' OR '.join(conditions)})
    ORDER BY time
    LIMIT {MAX_ROWS_PER_QUERY}
    """


def flows_sql(ips: list[str], names: list[str], start: datetime, end: datetime) -> str:
    """Campus-wide long flows (over 1 MB) to any of the IPs or names in one window."""
    conditions = [c for c in (_in("server_ip", ips), _in("attributes.sni", names)) if c]
    return f"""
    SELECT {', '.join(FLOW_COLUMNS)}, attributes.sni AS flow_sni
    FROM {db.LONG_FLOW_TABLE}
    WHERE {db._time_filter("start", start, end)} AND ({' OR '.join(conditions)})
    ORDER BY start
    LIMIT {MAX_ROWS_PER_QUERY}
    """


def _run(sql_for, ips: list[str], names: list[str], windows: list[tuple[datetime, datetime]],
         label: str) -> pd.DataFrame:
    frames = []
    for start, end in windows:
        for ip_batch, name_batch in _paired_batches(ips, names):
            frame = db.query(sql_for(ip_batch, name_batch, start, end))
            if len(frame) >= MAX_ROWS_PER_QUERY:
                print(f"  warning: {label} {start:%Y-%m-%d} hit {MAX_ROWS_PER_QUERY} rows; later rows are cut off")
            if not frame.empty:
                frames.append(frame)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def _paired_batches(ips: list[str], names: list[str]) -> list[tuple[list[str], list[str]]]:
    """IP and name batches, run separately so neither list grows past BATCH_CHARS."""
    pairs = [(batch, []) for batch in _batches(ips)]
    pairs += [([], batch) for batch in _batches(names)]
    return pairs


def windows(days: int, now: datetime | None = None, chunk_days: int | None = None) -> list[tuple[datetime, datetime]]:
    """The last `days` days, ending at the current minute, in chunks of at most MATCH_CHUNK_DAYS (max 5)."""
    end = (now or datetime.now(timezone.utc)).replace(second=0, microsecond=0, tzinfo=None)
    start = end - timedelta(days=days)
    return db.time_chunks(start, end, min(chunk_days or config.MATCH_CHUNK_DAYS, 5))


# --- rows -> match records --------------------------------------------------------------

def _plain(value):
    """A DataFrame cell as JSON: times as 'YYYY-MM-DD HH:MM:SS', numpy as Python."""
    if isinstance(value, (pd.Timestamp, datetime)):
        return _utc(value).strftime("%Y-%m-%d %H:%M:%S")
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    if hasattr(value, "item"):
        return value.item()
    return value


def _utc(value) -> pd.Timestamp:
    """A time as a naive UTC Timestamp (ClickHouse may return aware ones)."""
    moment = pd.Timestamp(value)
    return moment.tz_convert("UTC").tz_localize(None) if moment.tzinfo else moment


def _iso(value) -> str:
    return _utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


class Index:
    """Which indicators a row's server IP, port or names match."""

    def __init__(self, indicators: list[dict]):
        self.by_ip: dict[str, list[tuple[dict, int | None]]] = defaultdict(list)
        self.by_name: dict[str, list[dict]] = defaultdict(list)
        self.by_exact_host: dict[str, list[dict]] = defaultdict(list)  # SNI or DNS only, never root_domain
        for item in indicators:
            if item["indicator_type"] == "domain":
                target = self.by_exact_host if item.get("exact_host_only") else self.by_name
                target[item["indicator"]].append(item)
                continue
            parsed = evidence.parse_ip_port(item["indicator"])
            ip, port = parsed if parsed else (item["indicator"], None)
            self.by_ip[ip].append((item, port))

    @property
    def ips(self) -> list[str]:
        return sorted(self.by_ip)

    @property
    def names(self) -> list[str]:
        return sorted(set(self.by_name) | set(self.by_exact_host))

    def matches(self, server_ip, port, names, exact_names=None) -> list[dict]:
        """Indicators matching a row. `names` are every name column; an
        exact-host-only indicator matches only `exact_names` (SNI and DNS)."""
        found = [item for item, want in self.by_ip.get(str(server_ip or ""), [])
                 if want is None or (port is not None and int(port) == want)]
        for name in names:
            found += self.by_name.get(str(name or "").lower().rstrip("."), [])
        for name in names if exact_names is None else exact_names:
            found += self.by_exact_host.get(str(name or "").lower().rstrip("."), [])
        return list({id(i): i for i in found}.values())


def _match_id(indicator: str, host: str, time_text: str) -> str:
    return "m_" + hashlib.sha1(f"{indicator}|{host}|{time_text}".encode()).hexdigest()[:16]


def _record(item: dict, host: str, first: str, last: str, created_at: str) -> dict:
    return {
        "indicator_type": item["indicator_type"],
        "indicator": item["indicator"],
        config.FEED_ASSET_FIELD: host,
        "intel": {**item["intel"], "first_seen_utc": first, "last_seen_utc": last},
        "evidence": {"subscriber_activity": [], "long_flow_summary": [], "dns_tuple": []},
        "match_id": _match_id(item["indicator"], host, first),
        "created_at": created_at,
    }


def build_records(index: Index, activity: pd.DataFrame, flows: pd.DataFrame,
                  created_at: str | None = None) -> list[dict]:
    """One record per (indicator, host, minute) with that minute's rows. A
    long flow joins the host's record nearest its start, or makes its own
    record if the host has no per-minute match (e.g. outside retention)."""
    created_at = created_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    records: dict[tuple[str, str, str], dict] = {}
    for row in activity.to_dict("records") if not activity.empty else []:
        for item in index.matches(row.get("server_ip"), row.get("server_port"),
                                  [row.get(f) for f in NAME_FIELDS], [row.get("sni"), row.get("dns")]):
            minute = _iso(row["time"])
            key = (item["indicator"], str(row["client_ip"]), minute)
            record = records.setdefault(key, _record(item, key[1], minute, minute, created_at))
            record["evidence"]["subscriber_activity"].append({c: _plain(row.get(c)) for c in ACTIVITY_COLUMNS})
    for row in flows.to_dict("records") if not flows.empty else []:
        for item in index.matches(row.get("server_ip"), row.get("server_port"), [row.get("flow_sni")]):
            _attach_flow(records, item, row, created_at)
    return sorted(records.values(), key=lambda r: (r["indicator"], r[config.FEED_ASSET_FIELD],
                                                   r["intel"]["first_seen_utc"]))


def _attach_flow(records: dict, item: dict, row: dict, created_at: str) -> None:
    host = str(row["client_ip"])
    flow = {c: _plain(row.get(c)) for c in FLOW_COLUMNS}
    start = _utc(row["start"])
    own = [k for k in records if k[0] == item["indicator"] and k[1] == host]
    if own:
        nearest = min(own, key=lambda k: abs(_utc(k[2]) - start))
        records[nearest]["evidence"]["long_flow_summary"].append(flow)
        return
    key = (item["indicator"], host, _iso(start))
    record = records.setdefault(key, _record(item, host, _iso(start), _iso(row["finish"]), created_at))
    record["evidence"]["long_flow_summary"].append(flow)


def match(indicators: list[dict], days: int, now: datetime | None = None, stats: dict | None = None) -> list[dict]:
    """Match records for every campus contact with the indicators in the last
    `days` days. Each indicator is {"indicator", "indicator_type", "intel"}
    (and "listed_urls" for URLs). Per-minute data only exists for about 15
    days; long flows go back further. `stats`, if given, gets the indicators
    skipped as known services."""
    indicators, skipped = screen_services(indicators)
    if stats is not None:
        stats["skipped_known_service"] = skipped
    if skipped:
        print(f"  {len(skipped)} indicator(s) skipped as known services (a bare link-sharing or hosting domain): "
              + ", ".join(skipped[:10]) + (" ..." if len(skipped) > 10 else ""))
    index = Index(indicators)
    if not index.ips and not index.names:
        return []
    all_windows = windows(days, now)
    retention = (now or datetime.now(timezone.utc)).replace(tzinfo=None) - timedelta(
        days=config.ACTIVITY_RETENTION_DAYS)
    recent = [(a, b) for a, b in all_windows if b > retention]
    activity = _run(activity_sql, index.ips, index.names, recent, "per-minute search")
    flows = _run(flows_sql, index.ips, index.names, all_windows, "long-flow search")
    return build_records(index, activity, flows)


def write_jsonl(records: list[dict], path: Path, stats: dict | None = None) -> None:
    """The records, one per line. With `stats`, also <path>.summary.json,
    which assess.py and the dashboard show in their run summaries."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, default=str) + "\n")
    if stats is not None:
        summary_path(path).write_text(json.dumps(stats, indent=1), encoding="utf-8")


def summary_path(feed: Path) -> Path:
    return feed.with_name(feed.name + ".summary.json")


def read_summary(feed: Path) -> dict:
    """The feed build's summary ({} if there is none)."""
    try:
        return json.loads(summary_path(Path(feed)).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}

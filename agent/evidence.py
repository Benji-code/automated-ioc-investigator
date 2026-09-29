"""Load the IOC-match feed and group it into cases.

The feed is event-based: the same (indicator, host) pair appears once per
matching per-minute row, so one held-open connection can produce thousands
of matches. Grouping first means the model judges the host's whole
relationship with the indicator, not one arbitrary row.

The feed is only the trigger list plus ThreatFox context. The behavioural
evidence comes from live ClickHouse queries (tools.py). This module pulls
just enough from the feed (which IPs, roughly when) to seed those queries.

Note on dates: the feed's threatfox.first_seen_utc / last_seen_utc are the
matched flow's start and finish, NOT the dates on the ThreatFox entry. They
are exposed here as evidence_first_seen / evidence_last_seen. Real ThreatFox
dates can be added by hand in data/ioc_metadata.json (see load_ioc_metadata).
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import config


JSON_LINES_SUFFIXES = (".jsonl", ".ndjson")


def _parse_json_lines(text: str, path: Path) -> list[dict]:
    """One JSON object per line; blank lines are skipped."""
    records = []
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}, line {number}: not valid JSON ({exc.msg})") from None
        if not isinstance(record, dict):
            raise SystemExit(f"{path}, line {number}: expected one JSON object per line")
        records.append(record)
    return records


def read_records(path: Path) -> list[dict]:
    """Match records from a JSON list, a single JSON object, or JSON Lines
    (.jsonl/.ndjson, or a .json file that holds one object per line)."""
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in JSON_LINES_SUFFIXES:
        return _parse_json_lines(text, path)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return _parse_json_lines(text, path)
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    raise SystemExit(f"{path} does not contain match records (a JSON list, or one JSON object per line)")


def load_matches(path: Path) -> list[dict]:
    matches = read_records(path)
    field = config.FEED_ASSET_FIELD
    for m in matches:
        if field != "affected_asset" and field in m:
            m["affected_asset"] = m.pop(field)
    return matches


def load_ioc_metadata(path: Path = config.IOC_METADATA_PATH) -> dict[str, dict]:
    """Optional hand-filled ThreatFox fields per indicator, e.g.
    {"bore.pub": {"threatfox_first_seen": "...", "threatfox_last_seen": "...",
                  "reporter": "...", "is_compromised": false, "ioc_id": 123}}.
    Returns {} when the file is absent."""
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise SystemExit(f"{path} must contain a JSON object keyed by indicator")
    return data


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    value = value.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def group_matches(matches: list[dict]) -> dict[tuple[str, str], list[dict]]:
    """Step 1: one entry per (indicator, affected_asset) pair."""
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for m in matches:
        key = (m.get("indicator", "?"), m.get("affected_asset", "?"))
        groups[key].append(m)
    return groups


def asset_ioc_index(matches: list[dict]) -> dict[str, list[dict]]:
    """For every host in the feed, which indicators it matched. Used to check
    whether peer hosts are independently flagged too: many hosts sharing a
    server is usually benign, but many hosts all flagged (especially for the
    same malware family) points to a multi-host compromise."""
    index: dict[str, list[dict]] = defaultdict(list)
    seen: set[tuple[str, str]] = set()
    for m in matches:
        asset = m.get("affected_asset")
        indicator = m.get("indicator")
        if not asset or not indicator or (asset, indicator) in seen:
            continue
        seen.add((asset, indicator))
        threatfox = m.get("threatfox", {})
        index[asset].append({
            "indicator": indicator,
            "malware": threatfox.get("malware"),
            "threat_type": threatfox.get("threat_type"),
        })
    return index


def _activity_rows(case_rows: list[dict]) -> list[dict]:
    return [a for r in case_rows for a in r.get("evidence", {}).get("subscriber_activity", [])]


def feed_server_ips(case_rows: list[dict]) -> list[dict]:
    """Every server IP the feed's own evidence recorded for this case, with
    the port and names it was seen with (step 3)."""
    by_ip: dict[str, dict] = {}
    for a in _activity_rows(case_rows):
        ip = a.get("server_ip")
        if not ip:
            continue
        entry = by_ip.setdefault(ip, {"server_ip": ip, "ports": set(), "names": set(), "asn_org": set()})
        if a.get("server_port") is not None:
            entry["ports"].add(int(a["server_port"]))
        for field in ("dns", "sni", "root_domain"):
            if a.get(field):
                entry["names"].add(a[field])
        if a.get("server_metadata__asn_organization"):
            entry["asn_org"].add(a["server_metadata__asn_organization"])
    return [
        {**e, "ports": sorted(e["ports"]), "names": sorted(e["names"]), "asn_org": sorted(e["asn_org"])}
        for e in by_ip.values()
    ]


def parse_ip_port(indicator: str) -> tuple[str, int | None] | None:
    """(ip, port) for an 'ip:port' indicator, else None."""
    if indicator.count(":") != 1:
        return None
    ip, _, port = indicator.partition(":")
    if not ip.replace(".", "").isdigit():
        return None
    return ip, int(port) if port.isdigit() else None


def case_identity(key: tuple[str, str], rows: list[dict], ioc_metadata: dict[str, dict] | None = None) -> dict:
    """Step 2: the IOC context for one case."""
    indicator, asset = key
    threatfox = rows[0].get("threatfox", {})

    first_times = [_parse_time(r.get("threatfox", {}).get("first_seen_utc")) for r in rows]
    last_times = [_parse_time(r.get("threatfox", {}).get("last_seen_utc")) for r in rows]
    first_times = [t for t in first_times if t]
    last_times = [t for t in last_times if t]
    evidence_first = min(first_times) if first_times else None
    evidence_last = max(last_times) if last_times else None

    return {
        "indicator_type": rows[0].get("indicator_type"),
        "indicator": indicator,
        "affected_asset": asset,
        "malware": threatfox.get("malware"),
        "threat_type": threatfox.get("threat_type"),
        "threatfox_confidence": threatfox.get("confidence"),
        "evidence_first_seen": evidence_first.isoformat() if evidence_first else None,
        "evidence_last_seen": evidence_last.isoformat() if evidence_last else None,
        "ioc_metadata": (ioc_metadata or {}).get(indicator),
        "match_ids": [r.get("match_id") for r in rows],
        "n_events": len(rows),
    }


@dataclass(frozen=True)
class CaseWindow:
    """Query windows for one case (all UTC). long_flow_summary is queried over
    the wide flow window; subscriber_activity_1m only over the part of it
    that is still within retention (activity_start is None if none is)."""
    flow_start: datetime
    flow_end: datetime
    activity_start: datetime | None
    activity_end: datetime | None

    def describe(self) -> dict:
        def fmt(t: datetime | None) -> str | None:
            return t.strftime("%Y-%m-%d %H:%M") if t else None
        return {
            "long_flow_summary": f"{fmt(self.flow_start)} to {fmt(self.flow_end)} UTC",
            "subscriber_activity_1m": (
                f"{fmt(self.activity_start)} to {fmt(self.activity_end)} UTC"
                if self.activity_start else "outside retention (no per-minute data)"
            ),
        }


def _midnight(t: datetime) -> datetime:
    return t.replace(hour=0, minute=0, second=0, microsecond=0)


def case_window(identity: dict, now: datetime | None = None) -> CaseWindow:
    """Step 5 window: FLOW_LOOKBACK_DAYS before the first matched evidence to
    FLOW_LOOKAHEAD_DAYS after the last, capped at now."""
    now = now or datetime.now(timezone.utc)
    first = _parse_time_iso(identity.get("evidence_first_seen")) or now
    last = _parse_time_iso(identity.get("evidence_last_seen")) or now

    flow_start = _midnight(first - timedelta(days=config.FLOW_LOOKBACK_DAYS))
    flow_end = min(_midnight(last) + timedelta(days=config.FLOW_LOOKAHEAD_DAYS + 1), now)

    retention_start = _midnight(now - timedelta(days=config.ACTIVITY_RETENTION_DAYS))
    activity_start = max(flow_start, retention_start)
    if activity_start >= flow_end:
        return CaseWindow(flow_start, flow_end, None, None)
    return CaseWindow(flow_start, flow_end, activity_start, flow_end)


def _parse_time_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


# --- task 2, 1.2: the feed's own evidence as a fallback ------------------------------

FLOW_COLUMNS = ["start", "finish", "duration_sec", "server_ip", "server_port", "client_port", "protocol",
                "up_bytes", "down_bytes", "up_packets", "down_packets", "classifier", "type"]


def feed_long_flows(case_rows: list[dict]):
    """The feed's long_flow_summary rows for this case as a flows DataFrame
    (same columns as db.fetch_indicator_long_flows), de-duplicated by flow."""
    import pandas as pd

    seen: set = set()
    rows = []
    for r in case_rows:
        for f in r.get("evidence", {}).get("long_flow_summary", []):
            key = f.get("flow_id") or (f.get("start"), f.get("client_port"), f.get("server_ip"))
            if key in seen:
                continue
            seen.add(key)
            rows.append({c: f.get(c) for c in FLOW_COLUMNS})
    frame = pd.DataFrame(rows, columns=FLOW_COLUMNS)
    if frame.empty:
        return frame
    frame["start"] = pd.to_datetime(frame["start"])
    frame["finish"] = pd.to_datetime(frame["finish"])
    for column in ("up_bytes", "down_bytes", "up_packets", "down_packets", "server_port", "client_port", "protocol"):
        frame[column] = pd.to_numeric(frame[column], errors="coerce").fillna(0).astype("int64")
    frame["duration_sec"] = pd.to_numeric(frame["duration_sec"], errors="coerce").fillna(0.0)
    return frame


def feed_activity(case_rows: list[dict]):
    """The feed's subscriber_activity rows aggregated per day, with the same
    columns as db.fetch_indicator_activity. Duplicate minutes are dropped."""
    import pandas as pd

    seen: set = set()
    rows = []
    for a in _activity_rows(case_rows):
        key = (a.get("time"), a.get("server_ip"), a.get("server_port"), a.get("sni"), a.get("dns"))
        if key in seen or not a.get("server_ip"):
            continue
        seen.add(key)
        time = pd.Timestamp(a.get("time"))
        rows.append({
            "day": time.date(), "server_ip": a.get("server_ip"), "server_port": int(a.get("server_port") or 0),
            "transport_protocol": int(a.get("transport_protocol") or 0),
            "sni": a.get("sni") or "", "dns": a.get("dns") or "", "root_domain": a.get("root_domain") or "",
            "asn": a.get("server_metadata__asn") or "", "asn_org": a.get("server_metadata__asn_organization") or "",
            "country": a.get("server_metadata__geo_country") or "",
            "minutes": 1,
            "up_bytes": int(a.get("up_volume__bytes") or 0), "down_bytes": int(a.get("down_volume__bytes") or 0),
            "up_packets": int(a.get("up_volume__packets") or 0),
            "down_packets": int(a.get("down_volume__packets") or 0),
            "first_time": time, "last_time": time,
        })
    frame = pd.DataFrame(rows)
    if frame.empty:
        return frame
    keys = ["day", "server_ip", "server_port", "transport_protocol", "sni", "dns", "root_domain",
            "asn", "asn_org", "country"]
    return frame.groupby(keys, as_index=False).agg(
        minutes=("minutes", "sum"), up_bytes=("up_bytes", "sum"), down_bytes=("down_bytes", "sum"),
        up_packets=("up_packets", "sum"), down_packets=("down_packets", "sum"),
        first_time=("first_time", "min"), last_time=("last_time", "max"),
    )


def feed_minutes(case_rows: list[dict], server_ips: list[str]):
    """The feed's matched minutes to the flagged IP(s) as a per-minute
    contact series (beacon.py's columns). Only the matched minutes: not
    evidence of anything outside them."""
    import pandas as pd

    rows = {}
    for a in _activity_rows(case_rows):
        if a.get("server_ip") not in server_ips or not a.get("time"):
            continue
        rows[a["time"]] = {"time": pd.Timestamp(a["time"]), "flows": int(a.get("flow_count") or 1),
                           "up_bytes": int(a.get("up_volume__bytes") or 0),
                           "down_bytes": int(a.get("down_volume__bytes") or 0),
                           "up_pkts": int(a.get("up_volume__packets") or 0),
                           "down_pkts": int(a.get("down_volume__packets") or 0)}
    frame = pd.DataFrame(list(rows.values()))
    return frame.sort_values("time") if not frame.empty else frame


def match_windows(case_rows: list[dict], minutes: int) -> list[tuple[datetime, datetime]]:
    """±minutes around each feed match, merged where they overlap."""
    times = sorted({t for t in (_parse_time(r.get("threatfox", {}).get("first_seen_utc")) for r in case_rows) if t})
    pad = timedelta(minutes=minutes)
    windows: list[list[datetime]] = []
    for t in times:
        if windows and t - pad <= windows[-1][1]:
            windows[-1][1] = t + pad
            continue
        windows.append([t - pad, t + pad])
    return [(a, b) for a, b in windows]

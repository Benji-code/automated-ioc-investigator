"""Step 5e: the flow timeline around the flagged contact.

What the host was doing in the minutes around each contact: every site it
used from PAD_BEFORE minutes before to PAD_AFTER minutes after
(subscriber_activity_1m), one row per site (all its names, IPs and ports)
and one row per flagged address (every name seen on it). A lone flow cannot
show context; the timeline can, e.g. an adult site opened two minutes before
a burst of flagged ad domains and click redirects is most likely pop-up ads
the page loaded, not something the user chose. So the lead-in (sites already
in use before the contact) and sites of a known kind (adult content, ad
networks, ...) are listed first; sites that do not fit are named on one line.

Rows are numbered F1, F2, ... in time order. The case file lists them, the
report cites them as [[flow F3]], and the report's flow table shows them with
the model's note on what each connection likely is (FLOW_NOTES).

  episodes()          contact bursts -> episodes (bursts close together)
  pick_episodes()     the first, the largest and the last episode
  build_rows()        one window's query rows -> the rows to show
  contact_timeline()  the step: query each window, number the rows
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd

from . import analysis, config, db, knowledge

EPISODE_GAP_MIN = 10       # contact bursts closer than this are one episode
MAX_EPISODES = 3           # the first, the largest and the last
PAD_BEFORE = 5             # minutes shown before an episode: the page or app that led to it
PAD_AFTER = 2              # minutes shown after it
MAX_WINDOW_MINUTES = 20    # a long (held-open) episode: only its start is shown
MAX_SITE_ROWS = 25         # per episode, besides the flagged addresses
MAX_OTHER_NAMES = 40       # sites not listed are named on one line, up to this many
MAX_FLAGGED_NAMES = 8
ECH_NAME = "name hidden by Encrypted Client Hello"


def _time(value) -> datetime:
    moment = pd.Timestamp(value).to_pydatetime()
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def episodes(spans: list[list]) -> list[dict]:
    """[[start, end, bytes], ...] bursts -> episodes, merging bursts that start
    within EPISODE_GAP_MIN of the previous one's end."""
    out: list[dict] = []
    for start, end, size in sorted(spans, key=lambda s: str(s[0])):
        start, end = _time(start), _time(end)
        if out and start - out[-1]["end"] <= timedelta(minutes=EPISODE_GAP_MIN):
            out[-1]["end"] = max(out[-1]["end"], end)
            out[-1]["bursts"] += 1
            out[-1]["bytes"] += int(size or 0)
            continue
        out.append({"start": start, "end": end, "bursts": 1, "bytes": int(size or 0)})
    return out


def pick_episodes(all_episodes: list[dict]) -> list[dict]:
    """At most MAX_EPISODES, in time order: the first, the largest, the last."""
    if len(all_episodes) <= MAX_EPISODES:
        return all_episodes
    largest = max(range(len(all_episodes)), key=lambda i: all_episodes[i]["bytes"])
    chosen = sorted({0, largest, len(all_episodes) - 1})
    return [all_episodes[i] for i in chosen]


def window(episode: dict) -> tuple[datetime, datetime]:
    start = episode["start"] - timedelta(minutes=PAD_BEFORE)
    end = episode["end"] + timedelta(minutes=1 + PAD_AFTER)
    return start, min(end, start + timedelta(minutes=MAX_WINDOW_MINUTES))


def _text(value) -> str:
    if value is None or (not isinstance(value, str) and pd.isna(value)):
        return ""
    return str(value).strip()


def _squash(text: str) -> str:
    return "".join(ch for ch in text.lower() if ch.isalnum())


def _echoes(app: str, name: str) -> bool:
    """SuperNetFlow often labels an unknown site with its own name (Advertoix
    for advertoix.com), or ECH traffic as Cloudflare-Ech: no new fact."""
    return _squash(app) in _squash(name) or (name == ECH_NAME and "ech" in app.lower())


def describe_remote(row: dict) -> str:
    """Facts about the remote end, for the flow table: name, kind, owner, app."""
    parts = [row["name"] or "no name recorded"]
    seen_as = [n for n in row.get("names") or [] if n != row["name"]]
    if seen_as:
        parts.append("seen as " + ", ".join(seen_as))
    if row["kind"]:
        parts.append(row["kind"])
    if row["asn_org"]:
        parts.append(row["asn_org"])
    if row["app"] and not _echoes(row["app"], row["name"]):
        parts.append(f"labelled {row['app']}")
    if row["flagged"]:
        parts.append("FLAGGED address")
    return "; ".join(parts)


def _record(r, flagged_ips: set[str]) -> dict:
    """One query row: a destination, port and app label in the window."""
    name = _text(r.sni) or _text(r.dns) or _text(r.root_domain)
    if name == "cloudflare-ech.com":
        name = ECH_NAME
    root = _text(r.root_domain)
    app = _text(r.application)
    return {
        "start": analysis.fmt_time(r.first_time), "end": analysis.fmt_time(r.last_time),
        "minutes": int(r.minutes), "flows": int(r.flows or 0),
        "server_ip": _text(r.server_ip), "port": int(r.server_port or 0),
        "protocol": knowledge.protocol_name(r.transport_protocol),
        "name": name, "root_domain": "" if root == "cloudflare-ech.com" else root,
        "asn_org": _text(r.asn_org), "app": "" if app in ("", "_unknown") else app,
        "flagged": _text(r.server_ip) in flagged_ips,
        "up_bytes": int(r.up_bytes or 0), "down_bytes": int(r.down_bytes or 0),
    }


def _size(row: dict) -> int:
    return row["up_bytes"] + row["down_bytes"]


def _site_key(rec: dict) -> str:
    """A flagged address is one row; otherwise one row per site (root domain),
    or per IP when the name is hidden or missing."""
    if rec["flagged"]:
        return f"flagged {rec['server_ip']}"
    if rec["root_domain"]:
        return rec["root_domain"]
    return f"{rec['name']} {rec['server_ip']}".strip() or "(unnamed)"


def _distinct(values) -> list:
    return list(dict.fromkeys(v for v in values if v))


def _span_minutes(start: str, end: str) -> int:
    return int((_time(end) - _time(start)).total_seconds() // 60) + 1


def _site_row(records: list[dict]) -> dict:
    records = sorted(records, key=_size, reverse=True)
    main = records[0]
    start, end = min(r["start"] for r in records), max(r["end"] for r in records)
    row = {**main, "start": start, "end": end,
           "minutes": min(sum(r["minutes"] for r in records), _span_minutes(start, end)),
           "flows": sum(r["flows"] for r in records),
           "ip_count": len(_distinct(r["server_ip"] for r in records)),
           "up_bytes": sum(r["up_bytes"] for r in records), "down_bytes": sum(r["down_bytes"] for r in records)}
    if main["flagged"]:
        roots = _distinct(r["root_domain"] or r["name"] for r in records)
        more = f" and {len(roots) - MAX_FLAGGED_NAMES} more" if len(roots) > MAX_FLAGGED_NAMES else ""
        row["name"] = f"{len(roots)} name(s) on the flagged address: {', '.join(roots[:MAX_FLAGGED_NAMES])}{more}"
        row["names"] = []
    else:
        row["name"] = main["root_domain"] or main["name"]
        row["names"] = _distinct(r["name"] for r in records)[:3]
    row["kind"] = knowledge.destination_kind(main["root_domain"] or main["name"])
    row["remote"] = describe_remote(row)
    return row


def _context_kind(row: dict) -> bool:
    """A kind of use or an ad network: context worth listing (OS services are not)."""
    return bool(row["kind"]) and not row["kind"].endswith(" services")


def build_rows(frame: pd.DataFrame, flagged_ips: list[str], contact_start: datetime) -> tuple[list[dict], dict]:
    """(rows to show, counts in the window). Every flagged address is listed.
    Of the other sites, the lead-in (already in use before the contact) and
    sites of a known kind come first, then the ones closest in time to the
    contact, larger first; the rest are only named."""
    counts = {"sites": 0, "flagged": 0, "other_sites": [], "other_count": 0}
    if frame is None or frame.empty:
        return [], counts
    frame = frame[(frame["up_bytes"] + frame["down_bytes"]) > 0]
    groups: dict[str, list[dict]] = {}
    for r in frame.itertuples(index=False):
        rec = _record(r, set(flagged_ips))
        groups.setdefault(_site_key(rec), []).append(rec)
    sites = [_site_row(records) for records in groups.values()]
    flagged = [row for row in sites if row["flagged"]]
    others = [row for row in sites if not row["flagged"]]

    def priority(row: dict) -> tuple:
        start = _time(row["start"])
        context = start < contact_start or _context_kind(row)
        return (not context, abs((start - contact_start).total_seconds()), -_size(row))

    others.sort(key=priority)
    listed, rest = others[:MAX_SITE_ROWS], sorted(others[MAX_SITE_ROWS:], key=_size, reverse=True)
    shown = sorted(flagged + listed, key=lambda row: (row["start"], -_size(row)))
    counts.update(sites=len(sites), flagged=len(flagged), other_count=len(rest),
                  other_sites=_distinct(row["name"] for row in rest)[:MAX_OTHER_NAMES])
    return shown, counts


def _fallback_spans(identity: dict) -> list[list]:
    """No per-minute contact series: the feed's own matched times, as one burst."""
    first, last = identity.get("evidence_first_seen"), identity.get("evidence_last_seen")
    return [[first, last or first, 0]] if first else []


def contact_timeline(host: str, server_ips: list[str], contact: dict, identity: dict,
                     own_name: str | None = None, now: datetime | None = None) -> dict:
    """The host's traffic around up to MAX_EPISODES contact episodes, rows
    numbered F1, F2, ... across episodes."""
    now = now or datetime.now(timezone.utc)
    spans = ((contact or {}).get("features") or {}).get("burst_spans") or _fallback_spans(identity)
    all_episodes = episodes(spans)
    retention_start = now - timedelta(days=config.ACTIVITY_RETENTION_DAYS - 1)
    result = {"source": "subscriber_activity_1m", "episode_count": len(all_episodes), "episodes": [], "rows": [],
              "pad_before": PAD_BEFORE, "pad_after": PAD_AFTER}
    for episode in pick_episodes(all_episodes):
        start, end = window(episode)
        entry = {"n": len(result["episodes"]) + 1, "start": analysis.fmt_time(episode["start"]),
                 "end": analysis.fmt_time(episode["end"]), "bursts": episode["bursts"],
                 "window": [analysis.fmt_time(start), analysis.fmt_time(end)], "sites": 0, "flagged": 0,
                 "shown": 0, "other_sites": [], "other_count": 0}
        if end <= retention_start:
            entry["expired"] = True
            result["episodes"].append(entry)
            continue
        frame = db.fetch_host_window_flows(host, start, end, own_name)
        rows, counts = build_rows(frame, server_ips, episode["start"])
        for row in rows:
            row["id"] = f"F{len(result['rows']) + 1}"
            row["episode"] = entry["n"]
            result["rows"].append(row)
        entry.update(counts, shown=len(rows))
        result["episodes"].append(entry)
    return result


def row_ids(timeline: dict | None) -> list[str]:
    return [row["id"] for row in (timeline or {}).get("rows") or []]

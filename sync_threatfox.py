"""Copy recent ThreatFox IOCs into the local MISP, keeping ThreatFox's labels.

    python sync_threatfox.py --days 1
    python sync_threatfox.py --days 7 --dry-run     # fetch and count, write nothing

ThreatFox's bulk exports return 502 and MISP's built-in ThreatFox feeds need
the Auth-Key, but the API works and keeps the labels. Each run asks the API
for the last N days (at most 7) and adds every new network IOC to one MISP
event per day ("ThreatFox IOCs 2026-11-10"), with to_ids set, its first-seen
time and three tags that misp_feed.py reads back:

    threatfox:malware="win.nanocore"  threatfox:threat-type="botnet_cc"  threatfox:confidence="75"

so ThreatFox matches keep the malware and threat-type labels knowledge.py
relies on. IOCs already in MISP (searched by value) are skipped. File hashes
are skipped: flow data cannot match them.

Needs ABUSECH_AUTH_KEY and a MISP key with write access (MISP_KEY) in .env.
Neither key is ever printed or put in a URL.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone

import requests

from agent import config, misp_feed

MAX_DAYS = 7  # the API's limit for get_iocs
TYPE_MAP = {"ip:port": "ip-dst|port", "domain": "domain", "url": "url"}
SEARCH_BATCH = 500
ADD_BATCH = 500
REQUEST_TIMEOUT_SEC = 60


# --- ThreatFox API ---------------------------------------------------------------------

def fetch_iocs(days: int, post=requests.post) -> list[dict]:
    """IOCs ThreatFox saw in the last `days` days (1-7)."""
    if not config.ABUSECH_AUTH_KEY:
        raise SystemExit("ABUSECH_AUTH_KEY is not set. Add it to .env (see .env.example).")
    days = max(1, min(int(days), MAX_DAYS))
    try:
        response = post(config.THREATFOX_API_URL, json={"query": "get_iocs", "days": days},
                        headers={"Auth-Key": config.ABUSECH_AUTH_KEY}, timeout=REQUEST_TIMEOUT_SEC)
    except requests.RequestException as exc:
        raise RuntimeError(f"ThreatFox API unreachable ({type(exc).__name__})") from None
    if response.status_code != 200:
        raise RuntimeError(f"ThreatFox API returned HTTP {response.status_code}")
    data = response.json()
    status = data.get("query_status")
    if status == "no_result":
        return []
    if status != "ok":
        raise RuntimeError(f"ThreatFox API query failed: {status}")
    return data.get("data") or []


def _first_seen(value: str | None) -> datetime | None:
    """'2026-11-09 10:00:00 UTC' -> an aware datetime."""
    if not value:
        return None
    try:
        return datetime.strptime(value.replace(" UTC", "").strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def to_attribute(ioc: dict) -> dict | None:
    """One ThreatFox IOC as a MISP attribute (plain dict), or None for a hash."""
    misp_type = TYPE_MAP.get(ioc.get("ioc_type") or "")
    value = str(ioc.get("ioc") or "").strip()
    if not misp_type or not value:
        return None
    if misp_type == "ip-dst|port":
        value = value.replace(":", "|", 1)
    tags = [f'threatfox:malware="{ioc.get("malware") or "unknown"}"',
            f'threatfox:threat-type="{ioc.get("threat_type") or "unknown"}"']
    if ioc.get("confidence_level") is not None:
        tags.append(f'threatfox:confidence="{int(ioc["confidence_level"])}"')
    return {"type": misp_type, "value": value, "first_seen": _first_seen(ioc.get("first_seen")), "tags": tags,
            "comment": f"ThreatFox IOC {ioc.get('id', '')}: {ioc.get('malware_printable') or ''}".strip(),
            "reference": ioc.get("reference") or None}


# --- MISP ----------------------------------------------------------------------------

def search_terms(values: list[str]) -> list[str]:
    """What to search MISP for: a composite ip|port value is found by its IP
    (MISP matches each half of a composite attribute on its own, so the full
    "ip|port" string never matches)."""
    return sorted({value.split("|", 1)[0] for value in values})


def existing_values(misp, values: list[str]) -> set[str]:
    """The values already in MISP (any event), compared in full."""
    found: set[str] = set()
    terms = search_terms(values)
    for i in range(0, len(terms), SEARCH_BATCH):
        batch = terms[i:i + SEARCH_BATCH]
        result = misp.search(controller="attributes", value=batch, pythonify=True)
        if isinstance(result, dict):
            raise RuntimeError(f"MISP search failed: {result.get('errors')}")
        found |= {str(misp_feed._get(a, "value")) for a in result or []}
    return found & set(values)


def event_for(misp, title: str) -> str:
    """The ID of the event with this title, created if there is none."""
    from pymisp import MISPEvent

    found = misp.search(controller="events", eventinfo=title, metadata=True, pythonify=True)
    for event in found or []:
        if misp_feed._get(event, "info") == title:
            return str(misp_feed._get(event, "id"))
    event = MISPEvent()
    event.info = title
    event.distribution = 0  # this organisation only
    event.add_tag("source:threatfox-api")
    created = misp.add_event(event, pythonify=True)
    if isinstance(created, dict) and created.get("errors"):
        raise RuntimeError(f"MISP did not create the event: {created['errors']}")
    return str(misp_feed._get(created, "id"))


def _misp_attribute(item: dict):
    from pymisp import MISPAttribute

    attribute = MISPAttribute()
    attribute.from_dict(type=item["type"], value=item["value"], to_ids=item["type"] != "link",
                        comment=item.get("comment") or "")
    if item.get("first_seen"):
        attribute.first_seen = item["first_seen"]
    for tag in item.get("tags") or []:
        attribute.add_tag(tag)
    return attribute


def new_attributes(iocs: list[dict], already: set[str]) -> list[dict]:
    """Attributes to add: network IOCs not yet in MISP, plus their reference
    links, each value once."""
    items, seen = [], set(already)
    for ioc in iocs:
        item = to_attribute(ioc)
        if not item or item["value"] in seen:
            continue
        seen.add(item["value"])
        items.append(item)
        if item["reference"] and item["reference"].startswith(("http://", "https://")) \
                and item["reference"] not in seen:
            seen.add(item["reference"])
            items.append({"type": "link", "value": item["reference"], "tags": [], "comment": "ThreatFox reference"})
    return items


def sync(days: int, misp=None, post=requests.post, dry_run: bool = False, today: str | None = None) -> dict:
    """Fetch, skip what MISP has, add the rest to today's event. Returns counts."""
    iocs = fetch_iocs(days, post)
    candidates = [a for a in (to_attribute(i) for i in iocs) if a]
    counts = {"fetched": len(iocs), "network": len(candidates), "added": 0, "event_id": None}
    if dry_run or not candidates:
        return counts
    misp = misp or misp_feed.client()
    values = sorted({c["value"] for c in candidates} | {c["reference"] for c in candidates if c["reference"]})
    items = new_attributes(iocs, existing_values(misp, values))
    if not items:
        return counts
    today = today or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    event_id = event_for(misp, f"ThreatFox IOCs {today}")
    for i in range(0, len(items), ADD_BATCH):
        result = misp.add_attribute(event_id, [_misp_attribute(item) for item in items[i:i + ADD_BATCH]])
        if isinstance(result, dict) and result.get("errors"):
            print(f"  MISP refused some attributes: {str(result['errors'])[:300]}")
    counts.update(added=len(items), event_id=event_id)
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Copy recent ThreatFox IOCs into the local MISP.")
    parser.add_argument("--days", type=int, default=1, help=f"days of IOCs to fetch (1-{MAX_DAYS})")
    parser.add_argument("--dry-run", action="store_true", help="fetch and count only; write nothing to MISP")
    args = parser.parse_args()
    counts = sync(args.days, dry_run=args.dry_run)
    print(f"ThreatFox: {counts['fetched']} IOC(s), {counts['network']} matchable on flow data.")
    if args.dry_run:
        print("Dry run: nothing written to MISP.")
    elif counts["event_id"]:
        print(f"Added {counts['added']} attribute(s) (IOCs and reference links) to MISP event {counts['event_id']}.")
    else:
        print("Nothing new to add.")


if __name__ == "__main__":
    main()

"""A snapshot of the latest public threat intel for the dashboard's Threat board.

    fetch_snapshot()   newest ThreatFox malware families (API) and newest MISP events (local MISP)
    save() / load()    intel.json next to the demo bundle

Public data only: family names, threat types and counts from ThreatFox, and
the titles, dates and sizes of MISP events from public feeds. No indicator
values, nothing from campus traffic. Events entered by hand (source:manual,
"Manual entry: ...") or marked TLP amber/red are left out.

The snapshot is taken when the bundle is built (python -m demo.anonymise) or
on request in live mode, so demo mode itself makes no network calls.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

MAX_FAMILIES = 12
MAX_EVENTS = 12
NOT_PUBLIC_TAGS = ("source:manual", "tlp:amber", "tlp:amber+strict", "tlp:red")


def threatfox_families(iocs: list[dict]) -> list[dict]:
    """ThreatFox IOCs grouped by malware family, the most recently seen first."""
    families: dict[str, dict] = {}
    for ioc in iocs:
        name = ioc.get("malware_printable") or ioc.get("malware") or "unknown"
        entry = families.setdefault(name, {"family": name, "malware": ioc.get("malware"), "iocs": 0,
                                           "threat_types": [], "last_seen": ""})
        entry["iocs"] += 1
        threat = ioc.get("threat_type")
        if threat and threat not in entry["threat_types"]:
            entry["threat_types"].append(threat)
        entry["last_seen"] = max(entry["last_seen"], str(ioc.get("first_seen") or "").replace(" UTC", ""))
    return sorted(families.values(), key=lambda f: f["last_seen"], reverse=True)[:MAX_FAMILIES]


def _tags(event: dict) -> list[str]:
    return [str((t.get("Tag") or t).get("name") or "") for t in event.get("EventTag") or event.get("Tag") or []]


def is_public(event: dict) -> bool:
    if str(event.get("info") or "").lower().startswith("manual entry"):
        return False
    return not any(tag.lower() in NOT_PUBLIC_TAGS for tag in _tags(event))


def misp_events(events: list[dict]) -> list[dict]:
    """The newest public MISP events: date, title, size and the organisation that published them."""
    out = []
    for event in events:
        if not is_public(event):
            continue
        out.append({"date": str(event.get("date") or ""), "info": str(event.get("info") or ""),
                    "attributes": int(event.get("attribute_count") or 0),
                    "org": str((event.get("Orgc") or {}).get("name") or "")})
    return sorted(out, key=lambda e: e["date"], reverse=True)[:MAX_EVENTS]


def fetch_snapshot(misp=None, post=None) -> dict:
    """Both lists; a source that fails is reported as an error, not raised."""
    import requests

    import sync_threatfox
    from agent import misp_feed

    snapshot = {"taken_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                "threatfox": [], "misp_events": [], "errors": []}
    try:
        snapshot["threatfox"] = threatfox_families(sync_threatfox.fetch_iocs(1, post or requests.post))
    except (Exception, SystemExit) as exc:  # noqa: BLE001 - the board works without it
        snapshot["errors"].append(f"ThreatFox: {exc}")
    try:
        misp = misp or misp_feed.client()
        events = misp.search_index(sort="date", desc=True, limit=MAX_EVENTS * 3, pythonify=False)
        if isinstance(events, dict):
            raise RuntimeError(str(events.get("errors")))
        snapshot["misp_events"] = misp_events(events)
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        snapshot["errors"].append(f"MISP: {exc}")
    return snapshot


def save(snapshot: dict, folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "intel.json"
    path.write_text(json.dumps(snapshot, indent=1), encoding="utf-8")
    return path


def load(folder: Path) -> dict | None:
    path = folder / "intel.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

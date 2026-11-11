"""Public threat intel looked up online for one case.

Deterministic lookups in curated public sources, not free web search (accuracy
first): the model does not browse. Two sources:
  - Malpedia: the malware family's description, aliases and its page.
  - ThreatFox (API, ABUSECH_AUTH_KEY): the indicator's own listing, its
    reporter, dates, confidence and reference.
Only public names are sent: the malware family and the indicator itself,
never a campus address or host name. What comes back is quoted in the case
file as data about the threat in general, not evidence about the host, and
cited in the report's sources. Results are cached for a week in
data/web_cache.json. WEB_CONTEXT=0 turns the lookups off.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

import requests

from . import config

MALPEDIA_API = "https://malpedia.caad.fkie.fraunhofer.de/api/get/family/{}"
MALPEDIA_PAGE = "https://malpedia.caad.fkie.fraunhofer.de/details/{}"
THREATFOX_PAGE = "https://threatfox.abuse.ch/ioc/{}/"
MALPEDIA_KEY_RE = re.compile(r"^[a-z0-9]+\.[a-z0-9_]+$")  # e.g. win.nanocore, js.clearfake
MAX_DESCRIPTION_CHARS = 900
MAX_LISTINGS = 3
TIMEOUT_SEC = 20
CACHE_DAYS = 7
CACHE_PATH = config.PROJECT_ROOT / "data" / "web_cache.json"


# --- HTTP (replaced in tests) ------------------------------------------------------------

def http_get(url: str) -> dict:
    response = requests.get(url, timeout=TIMEOUT_SEC)
    response.raise_for_status()
    return response.json()


def http_post_threatfox(body: dict) -> dict:
    response = requests.post(config.THREATFOX_API_URL, json=body, headers={"Auth-Key": config.ABUSECH_AUTH_KEY},
                             timeout=TIMEOUT_SEC)
    if response.status_code != 200:
        raise RuntimeError(f"ThreatFox API returned HTTP {response.status_code}")  # never the key
    return response.json()


# --- cache -----------------------------------------------------------------------------------

def _load_cache() -> dict:
    try:
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _cached(key: str, fetch):
    """fetch() once a week per key; a failed fetch is not cached."""
    cache = _load_cache()
    entry = cache.get(key)
    now = datetime.now(timezone.utc)
    if entry and now - datetime.fromisoformat(entry["at"]) < timedelta(days=CACHE_DAYS):
        return entry["value"]
    value = fetch()
    cache[key] = {"at": now.isoformat(), "value": value}
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CACHE_PATH.write_text(json.dumps(cache, indent=1), encoding="utf-8")
    except OSError:
        pass
    return value


# --- lookups -------------------------------------------------------------------------------

def malpedia_family(key: str | None) -> dict | None:
    """Malpedia's entry for a family key such as win.nanocore, or None."""
    key = (key or "").strip().lower()
    if not MALPEDIA_KEY_RE.match(key):
        return None

    def fetch():
        data = http_get(MALPEDIA_API.format(key))
        description = " ".join(str(data.get("description") or "").split())
        if len(description) > MAX_DESCRIPTION_CHARS:
            description = description[:MAX_DESCRIPTION_CHARS].rsplit(" ", 1)[0] + " ..."
        return {"key": key, "name": data.get("common_name") or key, "aliases": (data.get("alt_names") or [])[:6],
                "description": description, "url": MALPEDIA_PAGE.format(key)}
    return _cached(f"malpedia:{key}", fetch)


def threatfox_listings(indicator: str) -> list[dict]:
    """ThreatFox's own listings of this exact indicator (none if not listed)."""
    if not config.ABUSECH_AUTH_KEY or not indicator:
        return []

    def fetch():
        data = http_post_threatfox({"query": "search_ioc", "search_term": indicator, "exact_match": True})
        rows = data.get("data") if isinstance(data.get("data"), list) else []
        keep = ("id", "ioc", "threat_type", "malware", "malware_printable", "confidence_level", "first_seen",
                "last_seen", "reporter", "reference")
        return [{k: row.get(k) for k in keep} for row in rows[:MAX_LISTINGS]]
    return _cached(f"threatfox:{indicator}", fetch)


def lookup(identity: dict) -> dict:
    """Public intel for the case's malware family and indicator. A source
    that fails is reported, never raised; with WEB_CONTEXT=0 nothing is fetched."""
    result = {"enabled": config.WEB_CONTEXT, "malpedia": None, "threatfox": [], "sources": [], "errors": []}
    if not config.WEB_CONTEXT:
        return result
    try:
        result["malpedia"] = malpedia_family(identity.get("malware"))
    except Exception as exc:  # noqa: BLE001 - the case goes on without it
        result["errors"].append(f"Malpedia: {type(exc).__name__}")
    try:
        result["threatfox"] = threatfox_listings(identity.get("indicator") or "")
    except Exception as exc:  # noqa: BLE001
        result["errors"].append(f"ThreatFox: {str(exc)[:80]}")
    if result["malpedia"]:
        result["sources"].append({"name": f"Malpedia: {result['malpedia']['name']}", "url": result["malpedia"]["url"]})
    for listing in result["threatfox"]:
        if listing.get("id"):
            result["sources"].append({"name": f"ThreatFox listing {listing['id']}",
                                      "url": THREATFOX_PAGE.format(listing["id"])})
        if str(listing.get("reference") or "").startswith(("http://", "https://")):
            result["sources"].append({"name": "reference given on ThreatFox", "url": listing["reference"]})
    return result

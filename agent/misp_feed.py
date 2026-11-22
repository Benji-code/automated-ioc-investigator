"""Pull network indicators from a local MISP and describe them as `intel` blocks.

The local MISP (e.g. misp-docker) combines several public feeds. This module
only reads it (MISP_KEY is a read-only key): which IP, IP:port, domain,
hostname and URL attributes were added or changed in the last N days, with
their event, tags and dates. matcher.py then looks for campus contacts with
them, and build_feed.py writes the match records assess.py reads.

  client()            a PyMISP connection from .env (MISP_URL, MISP_KEY, MISP_VERIFY_SSL)
  refresh_feeds()     ask MISP to fetch every enabled feed now (optional)
  pull_indicators()   the attributes, as plain dicts
  to_intel()          one attribute's dict -> the feed's `intel` block
  push_event()        save manual indicators as a local MISP event (MISP_WRITE_KEY)
"""
from __future__ import annotations

import re
from datetime import date, datetime, timezone

from . import config, knowledge

ATTRIBUTE_TYPES = ["ip-dst", "ip-dst|port", "domain", "hostname", "url"]
LINK_TYPE = "link"
PAGE_SIZE = 5000          # attributes per search request (tens of thousands per week)
MAX_PAGES = 100
EVENTS_PER_LINK_QUERY = 200
MAX_REFERENCES = 10

# Threat types from tags and event titles, most specific first. Words are
# matched case-insensitively in a tag's value or the event info.
THREAT_TYPE_WORDS = [
    ("botnet_cc", ("botnet_cc", "botnet c2", "command and control", "command-and-control", "c2 server", "c&c",
                   "c2")),
    ("payload_delivery", ("payload_delivery", "payload delivery", "malware download", "dropper", "delivery",
                          "payload")),
    ("exploit", ("exploitation", "exploit")),
    ("phishing", ("phishing",)),
]

# MISP taxonomies that rate an indicator, mapped to 0-100.
CONFIDENCE_TAGS = {
    "misp:confidence-level": {"completely-confident": 100, "usually-confident": 75, "fairly-confident": 50,
                              "rarely-confident": 25, "unconfident": 0},
    "estimative-language:likelihood-probability": {"almost-certain": 95, "very-likely": 85, "likely": 70,
                                                   "roughly-even-chance": 50, "unlikely": 30,
                                                   "very-unlikely": 15, "almost-no-chance": 5},
    "estimative-language:confidence-in-analytic-judgment": {"high": 80, "moderate": 50, "low": 20},
}
TAG_RE = re.compile(r'^(?P<ns>[^=]+?)(?:="?(?P<value>[^"]*)"?)?$')


# --- connection ---------------------------------------------------------------------

def client(write: bool = False):
    """A PyMISP connection. The read key unless write=True."""
    import urllib3
    from pymisp import PyMISP  # imported lazily: only feed building needs it

    settings = config.misp_settings(write)
    if not settings["ssl"]:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # self-signed local instance
    return PyMISP(settings["url"], settings["key"], ssl=settings["ssl"], timeout=settings["timeout"])


def refresh_feeds(misp=None) -> dict:
    """Ask MISP to fetch every enabled feed now (feeds/fetchFromAllFeeds).
    MISP queues the fetch as a background job, so new attributes may take a
    few minutes to appear."""
    misp = misp or client()
    return misp.fetch_all_feeds()


# --- reading attributes -----------------------------------------------------------

def _get(obj, name: str, default=None):
    """A field from a PyMISP object or a plain dict."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _tag_names(attribute) -> list[str]:
    tags = _get(attribute, "tags") or _get(attribute, "Tag") or []
    names = [str(_get(t, "name") or "") for t in tags]
    return list(dict.fromkeys(n for n in names if n))


def _time_text(value) -> str | None:
    """A MISP time (datetime, date or epoch) as ISO UTC with Z."""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
        value = datetime.fromtimestamp(int(value), tz=timezone.utc)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, date):
        return f"{value.isoformat()}T00:00:00Z"
    return str(value)


def _attribute_dict(attribute) -> dict:
    event = _get(attribute, "Event") or {}
    return {
        "value": str(_get(attribute, "value") or "").strip(),
        "type": str(_get(attribute, "type") or ""),
        "event_id": str(_get(attribute, "event_id") or _get(event, "id") or "") or None,
        "event_info": str(_get(event, "info") or "") or None,
        "tags": _tag_names(attribute),
        "first_seen": _time_text(_get(attribute, "first_seen")),
        "last_seen": _time_text(_get(attribute, "last_seen") or _get(attribute, "timestamp")),
        "references": [],
    }


def _search_pages(misp, days: int) -> list:
    """Every matching attribute, PAGE_SIZE at a time.

    attribute_timestamp, not last: `last` filters on the event's publish
    time, and feed fetches republish events, so months-old indicators slip
    through. For fixed-event feeds attribute_timestamp effectively means
    "currently on the list". Warninglists are applied afterwards
    (drop_warninglisted): MISP applies them after the page limit, so a page
    came back short and paging stopped early, losing every later feed."""
    found = []
    for page in range(1, MAX_PAGES + 1):
        batch = misp.search(controller="attributes", type_attribute=ATTRIBUTE_TYPES, to_ids=True,
                            attribute_timestamp=f"{int(days)}d", include_event_tags=True,
                            include_context=True, limit=PAGE_SIZE, page=page, pythonify=True)
        if isinstance(batch, dict) and batch.get("errors"):
            raise RuntimeError(f"MISP search failed: {batch['errors']}")
        found += list(batch or [])
        if len(batch or []) < PAGE_SIZE:
            break
    return found


def pull_indicators(days: int | None = None, misp=None) -> list[dict]:
    """Network attributes marked for detection (to_ids) whose attribute
    timestamp is within the last `days` days, excluding values on MISP's
    warninglists (CDNs, top sites, ...). Plain dicts: value, type, event_id,
    event_info, tags, first_seen, last_seen, references."""
    misp = misp or client()
    days = days or config.MISP_LOOKBACK_DAYS
    pulled = [_attribute_dict(a) for a in _search_pages(misp, days)]
    pulled = drop_warninglisted(misp, [p for p in pulled if p["value"]])
    links = event_links(misp, sorted({p["event_id"] for p in pulled if p["event_id"]}))
    for p in pulled:
        p["references"] = links.get(p["event_id"], [])
    return pulled


WARNINGLIST_BATCH = 1000


def _site_host(attribute: dict) -> str | None:
    """The host of a URL that names a whole site (no path or query), e.g.
    http://8.8.8.8/ -> 8.8.8.8: such a URL lists the host itself, so the host
    must pass the warninglists too. A URL to a page is checked as a URL."""
    from urllib.parse import urlsplit

    value = attribute["value"]
    if attribute.get("type") != "url" and "://" not in value:
        return None
    parts = urlsplit(value if "://" in value else f"http://{value}")
    if parts.path.strip("/") or parts.query:
        return None
    return (parts.hostname or "").strip(".").lower() or None


def drop_warninglisted(misp, pulled: list[dict]) -> list[dict]:
    """Attributes whose value (or, for a URL naming a whole site, its host)
    is on none of MISP's enabled warninglists (CDNs, top sites, public
    resolvers), checked in batches."""
    values = sorted({p["value"] for p in pulled} | {h for h in map(_site_host, pulled) if h})
    listed: set[str] = set()
    for i in range(0, len(values), WARNINGLIST_BATCH):
        hits = misp.values_in_warninglist(values[i:i + WARNINGLIST_BATCH])
        if isinstance(hits, dict) and not hits.get("errors"):
            listed |= set(hits)
    return [p for p in pulled if p["value"] not in listed and _site_host(p) not in listed]


def event_links(misp, event_ids: list[str]) -> dict[str, list[str]]:
    """{event id: link attribute URLs} for the given events."""
    links: dict[str, list[str]] = {}
    for i in range(0, len(event_ids), EVENTS_PER_LINK_QUERY):
        batch = event_ids[i:i + EVENTS_PER_LINK_QUERY]
        found = misp.search(controller="attributes", type_attribute=LINK_TYPE, eventid=batch, pythonify=True)
        if isinstance(found, dict):
            continue  # an error reply: references are optional
        for attribute in found or []:
            event_id = str(_get(attribute, "event_id") or "")
            url = str(_get(attribute, "value") or "").strip()
            if event_id and url.startswith(("http://", "https://")):
                links.setdefault(event_id, [])
                if url not in links[event_id] and len(links[event_id]) < MAX_REFERENCES:
                    links[event_id].append(url)
    return links


# --- feed names ---------------------------------------------------------------------

THREATFOX_FEED = "ThreatFox"
MANUAL_FEED = "Manual entry"
PHISHING_GROUP = "Phishing feeds"
THREATFOX_EVENT_PREFIX = "ThreatFox IOCs"  # the events sync_threatfox.py writes


def feed_name(info: str | None) -> str:
    """The feed a MISP event (or a stored intel.feed) stands for: the event's
    title minus a trailing " feed"; "ThreatFox" for the API sync's daily events."""
    name = " ".join(str(info or "").split())
    if not name:
        return "MISP"
    if name.lower().startswith(THREATFOX_EVENT_PREFIX.lower()) or name.lower() == "threatfox":
        return THREATFOX_FEED
    if name.lower() in ("analyst entry", "manual entry"):
        return MANUAL_FEED
    if name.lower().endswith(" feed"):
        name = name[:-len(" feed")].rstrip()
    return name


def feed_group(feed: str) -> str:
    """How the dashboard lists a feed: phishing feeds together, the rest by name."""
    return PHISHING_GROUP if "phish" in feed.lower() else feed


# --- attribute -> intel ------------------------------------------------------------

def _split_tag(tag: str) -> tuple[str, str]:
    """'misp-galaxy:malpedia="NanoCore"' -> ('misp-galaxy:malpedia', 'NanoCore')."""
    match = TAG_RE.match(tag.strip())
    if not match:
        return tag, ""
    return match.group("ns").strip(), (match.group("value") or "").strip()


def _threat_type_in(text: str) -> str | None:
    text = text.lower()
    for threat_type, words in THREAT_TYPE_WORDS:
        for word in words:
            if re.search(rf"(?<![\w]){re.escape(word)}(?![\w])", text):
                return threat_type
    return None


def _tag_value(tags: list[str], namespace: str) -> str | None:
    """The value of the first tag in this namespace, e.g. threatfox:malware."""
    for tag in tags:
        name, value = _split_tag(tag)
        if name == namespace and value:
            return value
    return None


def threat_type_from(tags: list[str], event_info: str | None) -> str:
    """ThreatFox's own label (sync_threatfox.py tags) first, then kill-chain
    and threat-type tags, then the event's title; a threat-actor galaxy alone
    gives 'threat_actor'; else 'unknown'."""
    labelled = _tag_value(tags, "threatfox:threat-type")
    if labelled:
        return labelled.lower()
    for tag in tags:
        namespace, value = _split_tag(tag)
        if namespace.startswith(("kill-chain", "threat-type", "threatfox", "malware_classification")) \
                or "threat" in namespace:
            found = _threat_type_in(value or namespace)
            if found:
                return found
    if "phish" in (event_info or "").lower():  # Phishtank, OpenPhish, PhishScore, Phishing.Database
        return "phishing"
    found = _threat_type_in(event_info or "")
    if found:
        return found
    if any(_split_tag(t)[0] == "misp-galaxy:threat-actor" for t in tags):
        return "threat_actor"
    return "unknown"


def malware_from(tags: list[str]) -> str | None:
    """ThreatFox's label (already a malpedia key such as 'win.nanocore'),
    else the malpedia galaxy's family as a knowledge-base key where one fits
    ('NanoCore' -> 'win.nanocore'), else as named."""
    labelled = _tag_value(tags, "threatfox:malware")
    if labelled:
        return knowledge.malware_key(labelled)
    for tag in tags:
        namespace, value = _split_tag(tag)
        if namespace == "misp-galaxy:malpedia" and value:
            return knowledge.malware_key(value)
    return None


def confidence_from(tags: list[str]) -> int | None:
    """0-100 from ThreatFox's label or a confidence taxonomy tag, or None
    (MISP often has none)."""
    labelled = _tag_value(tags, "threatfox:confidence")
    if labelled and labelled.isdigit():
        return max(0, min(100, int(labelled)))
    for tag in tags:
        namespace, value = _split_tag(tag)
        scale = CONFIDENCE_TAGS.get(namespace)
        if scale and value.lower() in scale:
            return scale[value.lower()]
    return None


def to_intel(attribute: dict) -> dict:
    """One pulled attribute as the feed's `intel` block. first_seen_utc and
    last_seen_utc are left for the matcher: in a match record they are the
    matched flow's times. The attribute's own dates go in source_first_seen
    and source_last_seen."""
    tags = attribute.get("tags") or []
    return {
        "source": "misp",
        "feed": feed_name(attribute.get("event_info")),
        "event_id": attribute.get("event_id"),
        "threat_type": threat_type_from(tags, attribute.get("event_info")),
        "malware": malware_from(tags),
        "confidence": confidence_from(tags),
        "tags": tags,
        "first_seen_utc": None,
        "last_seen_utc": None,
        "source_first_seen": attribute.get("first_seen"),
        "source_last_seen": attribute.get("last_seen"),
        "references": attribute.get("references") or [],
        "threat_ref": None,
    }


# --- writing (manual indicators) ---------------------------------------------------

MISP_TYPES = {"ip": "ip-dst", "ip:port": "ip-dst|port", "domain": "domain"}


def push_event(indicators: list[dict], title: str, misp=None) -> str:
    """Save manual indicators as one local MISP event (distribution: this
    organisation only). Needs MISP_WRITE_KEY. Returns the new event's ID."""
    from pymisp import MISPEvent

    misp = misp or client(write=True)
    event = MISPEvent()
    event.info = title
    event.distribution = 0
    event.add_tag("source:manual")
    for item in indicators:
        misp_type = MISP_TYPES.get(item["indicator_type"], "domain")
        value = item["indicator"].replace(":", "|") if misp_type == "ip-dst|port" else item["indicator"]
        event.add_attribute(misp_type, value, to_ids=True, comment="entered by an analyst")
    created = misp.add_event(event, pythonify=True)
    if isinstance(created, dict) and created.get("errors"):
        raise RuntimeError(f"MISP did not save the event: {created['errors']}")
    return str(_get(created, "id"))

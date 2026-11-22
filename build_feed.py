"""Build an IOC-match feed for assess.py, from MISP or from indicators entered by hand.

    python build_feed.py --source misp --days 7 --out data/misp_matches.jsonl
    python build_feed.py --source misp --days 7 --refresh          # fetch MISP's feeds first
    python build_feed.py --source manual --indicator 203.0.113.7 --indicator example.test \\
        --threat-file threat.txt --out data/manual_matches.jsonl
    python build_feed.py --source manual --indicator example.test --threat "text of an email about the threat"

MISP: the network attributes (IP, IP:port, domain, hostname, URL) added or
changed in the last N days, minus MISP's warninglists. Manual: the given
indicators, plus an optional threat description that one model call turns
into a briefing (saved under data/threat_briefings/, shown for you to
confirm; --yes skips that). Either way, agent/matcher.py finds the campus
hosts that contacted them and writes match records in the feed format, ready
for: python assess.py <out> [--pdf]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agent import briefing as briefings
from agent import config, matcher, misp_feed

HERE = Path(__file__).resolve().parent


# --- MISP -----------------------------------------------------------------------------

def misp_indicators(days: int, refresh: bool = False, misp=None, feeds: set[str] | None = None) -> list[dict]:
    """Indicators from MISP, one entry per indicator, with their intel. With
    `feeds`, only attributes from those feeds (names as misp_feed.feed_group
    gives them, e.g. "ThreatFox", "Phishing feeds", "Feodo IP Blocklist")."""
    misp = misp or misp_feed.client()
    if refresh:
        print("Asking MISP to fetch its feeds (it runs as a background job; new attributes may take a while).")
        misp_feed.refresh_feeds(misp)
    pulled = misp_feed.pull_indicators(days, misp)
    items, skipped = [], 0
    for attribute in pulled:
        normal = matcher.normalise_indicator(attribute["value"], attribute["type"])
        if not normal:
            skipped += 1
            continue
        url = matcher.listed_url(attribute["value"], attribute["type"])
        items.append({"indicator": normal[0], "indicator_type": normal[1], "intel": misp_feed.to_intel(attribute),
                      "listed_urls": [url] if url else []})
    if feeds is not None:
        items = [i for i in items if misp_feed.feed_group(i["intel"]["feed"]) in feeds]
    merged = matcher.merge_indicators(items)
    print(f"MISP: {len(pulled)} attribute(s) from the last {days} day(s) -> {len(merged)} indicator(s)"
          + (f"; {skipped} skipped (IPv6 or not matchable)" if skipped else "") + ".")
    return merged


# --- manual ---------------------------------------------------------------------------

def manual_intel(threat: dict | None, threat_type: str, event_id: str | None = None) -> dict:
    return {
        "source": "manual",
        "feed": misp_feed.MANUAL_FEED,
        "event_id": event_id,
        "threat_type": threat_type or "unknown",
        "malware": threat["name"] if threat else None,
        "confidence": None,
        "tags": [],
        "first_seen_utc": None,
        "last_seen_utc": None,
        "references": (threat or {}).get("references") or [],
        "threat_ref": threat["slug"] if threat else None,
    }


def manual_indicators(values: list[str]) -> list[dict]:
    """The given indicators, normalised. Exits on any value that cannot be matched."""
    items = []
    for value in values:
        normal = matcher.normalise_indicator(value)
        if not normal:
            raise SystemExit(f"Not an indicator SuperNetFlow can match: {value!r} (use an IPv4 address, "
                             "ip:port, a domain or a URL).")
        url = matcher.listed_url(value)
        items.append({"indicator": normal[0], "indicator_type": normal[1], "listed_urls": [url] if url else []})
    merged: dict[str, dict] = {}
    for item in items:
        if item["indicator"] in merged:
            merged[item["indicator"]]["listed_urls"] += item["listed_urls"]
        else:
            merged[item["indicator"]] = item
    return list(merged.values())


def confirm(threat: dict) -> bool:
    print("\n" + briefings.describe(threat) + "\n")
    if not sys.stdin.isatty():
        raise SystemExit("Not asking for confirmation without a terminal: check the briefing above and run "
                         "again with --yes.")
    return input("Use this briefing? [y/N] ").strip().lower() in ("y", "yes")


def make_briefing(description: str, yes: bool, chat=None) -> dict:
    """Description -> saved briefing, confirmed by the analyst unless yes=True."""
    print("Writing a threat briefing from the description (one model call)...")
    threat = briefings.generate(description, chat=chat)
    if not yes and not confirm(threat):
        raise SystemExit("Briefing not used. Edit the description and run again.")
    record = briefings.save(threat, description)
    if yes:
        print("\n" + briefings.describe(record) + "\n")
    print(f"Saved the briefing as data/threat_briefings/{record['slug']}.json")
    return record


def build_manual(values: list[str], description: str | None, days: int, yes: bool = True,
                 threat_type: str = "unknown", push: bool = False, chat=None,
                 stats: dict | None = None) -> tuple[list[dict], dict | None]:
    """(match records, briefing) for manual indicators. Used by the CLI and the dashboard."""
    items = manual_indicators(values)
    threat = make_briefing(description, yes, chat) if description and description.strip() else None
    event_id = None
    if push:
        title = f"Manual entry: {threat['name'] if threat else ', '.join(i['indicator'] for i in items)}"
        event_id = misp_feed.push_event(items, title)
        print(f"Saved the indicators to MISP as event {event_id}.")
    intel = manual_intel(threat, threat_type, event_id)
    indicators = [{**item, "intel": dict(intel)} for item in items]
    config.clickhouse_settings()
    return matcher.match(indicators, days, stats=stats), threat


def pull_feeds(feeds: set[str], days: int, stats: dict | None = None) -> list[dict]:
    """Match records for the chosen feeds. ThreatFox in the choice means a
    fresh API pull into MISP first (at most 7 days); without it, the API is
    not called and ThreatFox's events are left out."""
    if misp_feed.THREATFOX_FEED in feeds:
        import sync_threatfox

        counts = sync_threatfox.sync(min(days, sync_threatfox.MAX_DAYS))
        print(f"ThreatFox: {counts['fetched']} IOC(s) fetched, {counts['added']} new attribute(s) added to MISP.")
    return matcher.match(misp_indicators(days, feeds=feeds), days, stats=stats)


def _feed_list(text: str | None) -> set[str] | None:
    return {name.strip() for name in text.split(",") if name.strip()} if text else None


# --- CLI ------------------------------------------------------------------------------

def _description(args) -> str | None:
    if args.threat_file:
        return Path(args.threat_file).read_text(encoding="utf-8")
    return args.threat


def summarise(records: list[dict], out: Path, stats: dict | None = None) -> None:
    pairs = {(r["indicator"], r[config.FEED_ASSET_FIELD]) for r in records}
    print(f"{len(records)} match record(s), {len(pairs)} indicator+host case(s), written to {out}")
    skipped = (stats or {}).get("skipped_known_service") or []
    if skipped:
        print(f"Skipped as known services: {len(skipped)} ({', '.join(skipped[:10])}"
              + (" ..." if len(skipped) > 10 else "") + ")")
    if not records:
        print("No campus host contacted these indicators in the window: assess.py has nothing to investigate.")
    else:
        print(f"Next: python assess.py {out} [--pdf] [--limit N]")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build an IOC-match feed from MISP or manual indicators.")
    parser.add_argument("--source", choices=("misp", "manual"), required=True)
    parser.add_argument("--days", type=int, default=config.MISP_LOOKBACK_DAYS,
                        help="MISP attributes added in, and campus traffic searched over, the last N days")
    parser.add_argument("--out", type=Path, default=None, help="output .jsonl (default data/<source>_matches.jsonl)")
    parser.add_argument("--refresh", action="store_true", help="MISP: fetch every enabled feed before pulling")
    parser.add_argument("--feeds", help='MISP: only these feeds, comma-separated, e.g. "ThreatFox,Phishing feeds,'
                                        'Feodo IP Blocklist" (event titles without " feed"; phishing feeds as a group)')
    parser.add_argument("--sync-threatfox", action="store_true",
                        help="MISP: pull ThreatFox's API into MISP first (sync_threatfox.py)")
    parser.add_argument("--indicator", action="append", default=[], help="manual: an IP, ip:port, domain or URL "
                        "(repeat for several)")
    parser.add_argument("--threat", help="manual: the threat description as text")
    parser.add_argument("--threat-file", help="manual: a file holding the threat description")
    parser.add_argument("--threat-type", default="unknown",
                        help="manual: threat type, e.g. botnet_cc, payload_delivery, exploit (default unknown)")
    parser.add_argument("--yes", action="store_true", help="manual: use the briefing without asking")
    parser.add_argument("--push-misp", action="store_true",
                        help="manual: also save the indicators as a local MISP event (needs MISP_WRITE_KEY)")
    args = parser.parse_args()
    out = args.out or HERE / "data" / f"{args.source}_matches.jsonl"
    stats: dict = {}

    if args.source == "misp":
        config.clickhouse_settings()  # fail now, before the MISP pull, if .env is missing
        if args.sync_threatfox:
            import sync_threatfox

            sync_threatfox.sync(min(args.days, sync_threatfox.MAX_DAYS))
        records = matcher.match(misp_indicators(args.days, args.refresh, feeds=_feed_list(args.feeds)), args.days,
                                stats=stats)
    else:
        if not args.indicator:
            raise SystemExit("--source manual needs at least one --indicator.")
        if args.threat and args.threat_file:
            raise SystemExit("Give the threat description once: --threat or --threat-file.")
        records, _ = build_manual(args.indicator, _description(args), args.days, args.yes, args.threat_type,
                                  args.push_misp, stats=stats)
    matcher.write_jsonl(records, out, stats)
    summarise(records, out, stats)


if __name__ == "__main__":
    main()

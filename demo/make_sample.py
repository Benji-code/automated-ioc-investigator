"""Build demo/sample/results.json: two illustrative cases on fake data, for the
dashboard on a fresh clone (before a real, anonymised bundle is built).

    python -m demo.make_sample        # also compiles their PDFs if tectonic or latexmk is installed

Every address is from the documentation ranges and every name ends in
.example or .test. The report text is sample content written for the demo,
in the format the model returns; real reports are always the model's own.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pandas as pd

import assess
from agent import charts, knowledge
from demo import anonymise

SAMPLE_NETS = "192.0.2.0/24,198.51.100.0/24"
SAMPLE_DOMAINS = ["campus.test"]

POPUP_REPORT = """VERDICT: LIKELY_FALSE_POSITIVE
CONFIDENCE: medium
HOST_ROLE: Probably a personal laptop in student housing: busy in the evening, quiet overnight.
LIKELY_USER: student - streaming and adult video sites (videohub.example) carry most of its traffic
HEADLINE: A pop-up ad loaded by an open adult video page, not a malware download.
FLOW_NOTES:
F1: video page on the adult site, already open
F2: pop-up ad network loaded by that page
F3: flagged domain, same minute as the pop-up
REPORT:
## Executive summary
At 10:41 UTC (21:41 AEDT) on 13 September the student laptop 192.0.2.44 fetched 38 KB from \
update-check.example, a domain listed for ClearFake fake-update pages. An adult video site was already open \
and an ad network loaded in the same minute ([[flow F1-F3]]), so this was most likely a pop-up ad. The host \
sent 4 KB and received 38 KB, far below a payload. The evidence reaches the contact grade only. Close the \
alert after the checks below.

## Background
### The host
The host looks like a personal laptop: its traffic is mostly streaming and adult video \
(videohub.example), and it is quiet overnight, which points to a student's own device.
### The threat
ClearFake injects a fake browser-update prompt into compromised sites; a user who accepts it downloads a \
loader.
### What an affected host looks like
A page visit, then a download of a few megabytes from the update domain, then new outbound connections.

## Analysis
### When and how
The single contact was at 10:41 UTC (21:41 AEDT) ([[flow F3]]). The video page had been open since \
10:37 UTC ([[flow F1]]) and the ad network appeared at 10:41 UTC ([[flow F2]]).
### Against an affected host
The host received 38 KB from the flagged domain: a page or script, not a payload, and nothing followed. As \
[[chart contact]] shows, there was no further contact.

## Conclusion and next steps
Likely false positive, medium confidence: the sequence fits a pop-up ad and no download followed.
1. Close the alert.
2. Alert on any repeat contact from 192.0.2.44 to update-check.example.
"""

CDN_REPORT = """VERDICT: LIKELY_FALSE_POSITIVE
CONFIDENCE: high
HOST_ROLE: A shared NAT gateway: busy around the clock with many unrelated sites.
LIKELY_USER: unclear - many devices share the address
HEADLINE: Ordinary video streaming through a shared CDN address that a C2 report also named.
FLOW_NOTES:
F1: video streaming over QUIC on the shared CDN address
REPORT:
## Executive summary
At 08:12 UTC (18:12 AEST) on 14 September the gateway 198.51.100.23 reached 203.0.113.80 on UDP port 443, \
an address a feed lists for NanoCore command and control. The name used was a video service \
(streamvideo.example) and the traffic was QUIC, which NanoCore never uses. The host sent 40 KB and received \
900 KB. The evidence reaches the contact grade only. Close the alert.

## Background
### The host
A NAT gateway: one address that many devices share, busy day and night.
### The threat
NanoCore is a Windows remote-access trojan that holds a TCP connection to its operator's server.
### What an affected host looks like
One long TCP connection to an unusual port, small steady traffic, with uploads when data is stolen.

## Analysis
### What the contact was
The flagged address is a shared CDN front end used by 180 campus hosts, and this host used it for \
streamvideo.example over QUIC ([[flow F1]]). As [[chart sites_on_ip]] shows, the address serves many \
unrelated sites.

## Conclusion and next steps
Likely false positive, high confidence: the flagged address is shared and the traffic was streaming.
1. Close the alert.
2. Ask the feed to drop shared CDN addresses.
"""


def _row(n: int, flagged: bool, start: str, name: str, remote: str, up: int, down: int, ip: str, port: int,
         protocol: str = "tcp") -> dict:
    end = (datetime.fromisoformat(start) + timedelta(minutes=1)).isoformat()
    return {"id": f"F{n}", "episode": 1, "flagged": flagged, "start": start, "end": end, "minutes": 2,
            "server_ip": ip, "port": port, "protocol": protocol, "ip_count": 1, "up_bytes": up, "down_bytes": down,
            "flows": 1, "name": name, "remote": remote}


def _contact_chart(start: datetime, minutes: int, host: str, first: str) -> dict:
    frame = pd.DataFrame({"time": [start + timedelta(minutes=m) for m in range(minutes)],
                          "up_bytes": [4000 if m == 4 else 0 for m in range(minutes)],
                          "down_bytes": [38000 if m == 4 else 0 for m in range(minutes)]})
    chart, _ = charts.build_chart({
        "id": "contact", "kind": "line", "x": "time", "y": ["up_bytes", "down_bytes"],
        "labels": ["upload", "download"], "unit": "bytes", "sql": "", "source": "subscriber_activity_1m",
        "title": "Traffic between the host and the flagged address, per minute",
        "markers": [{"start": first, "end": first, "label": "flagged contact"}],
        "caption": "Every minute of contact with the flagged address."}, frame, host)
    return chart


def _sites_chart(host: str) -> dict:
    frame = pd.DataFrame({"site": ["streamvideo.example", "news.example", "shop.example", "games.example"],
                          "hosts": [180, 95, 40, 12]})
    chart, _ = charts.build_chart({
        "id": "sites_on_ip", "kind": "bar", "x": "site", "y": ["hosts"], "unit": "count", "sql": "",
        "source": "subscriber_activity_1m", "title": "Sites on 203.0.113.80, by campus hosts that used them",
        "caption": "Every site seen on the flagged address; the site this host used is highlighted."},
        frame, host, highlight=["streamvideo.example"])
    return chart


def _evidence(identity: dict, hostname: str, host_kind: str, rows: list[dict], chart: dict) -> dict:
    return {
        "identity": identity, "host": {"ip": identity["affected_asset"], "hostname": hostname},
        "flows": {"has_traffic": True, "upload_heavy_over_exfil_threshold": {"count": 0}},
        "asn": [], "signals": [], "expected": {**knowledge.get_profile(identity["malware"], identity["threat_type"]),
                                               "service": None},
        "baseline": {"verdict": "LIKELY_FALSE_POSITIVE", "confidence": "medium", "rule": 4, "reason": "sample"},
        "host_type": {"label": host_kind, "name": host_kind, "confidence": 0.8, "comparison": {}},
        "timeline": {"rows": rows, "episodes": [{"n": 1, "start": rows[0]["start"], "end": rows[-1]["end"]}]},
        "chart_options": [chart], "behaviour": {"label": "ad or redirect"},
    }


def _identity(indicator: str, kind: str, host: str, malware: str, threat_type: str, first: str, source: str,
              confidence, feed: str) -> dict:
    return {"indicator": indicator, "indicator_type": kind, "affected_asset": host, "malware": malware,
            "threat_type": threat_type, "intel_source": source, "intel_feed": feed,
            "intel_event_id": None, "intel_confidence": confidence, "intel_tags": [], "intel_references": [],
            "threat_ref": None, "evidence_first_seen": first, "evidence_last_seen": first, "n_events": 1}


def build() -> list[dict]:
    popup = _identity("update-check.example", "domain", "192.0.2.44", "js.clearfake", "payload_delivery",
                      "2026-09-13T10:41:00+00:00", "misp", 100, "ThreatFox")
    popup_rows = [_row(1, False, "2026-09-13T10:37:00", "videohub.example", "videohub.example (adult content)",
                       90_000, 4_200_000, "203.0.113.20", 443),
                  _row(2, False, "2026-09-13T10:41:00", "exosrv.com", "exosrv.com (ad network)", 3_000, 20_000,
                       "203.0.113.31", 443),
                  _row(3, True, "2026-09-13T10:41:00", "update-check.example", "1 name(s) on the flagged address: "
                       "update-check.example", 4_000, 38_000, "203.0.113.45", 443)]
    popup_chart = _contact_chart(datetime(2026, 9, 13, 10, 37), 10, "192.0.2.44", popup["evidence_first_seen"])
    cdn = _identity("203.0.113.80:443", "ip:port", "198.51.100.23", "win.nanocore", "botnet_cc",
                    "2026-09-14T08:12:00+00:00", "misp", None, "Example C2 blocklist")
    cdn_rows = [_row(1, True, "2026-09-14T08:12:00", "streamvideo.example", "streamvideo.example (streaming)",
                     40_000, 900_000, "203.0.113.80", 443, "udp")]
    cdn_chart = _sites_chart("198.51.100.23")
    cases = [(popup, _evidence(popup, "res-laptop-17.campus.test", "end host", popup_rows, popup_chart),
              POPUP_REPORT),
             (cdn, _evidence(cdn, "gw-3.campus.test", "NAT gateway", cdn_rows, cdn_chart), CDN_REPORT)]
    results = []
    for identity, ev, reply in cases:
        result = assess.finish_result(identity, ev, "sample case file", reply, [], [])
        result.update(needs_review=False, consistency_flags=[], unverified_numbers=[], verdict_notes=[],
                      sample=True)
        results.append(result)
    return results


# Illustrative only: the shape of a real snapshot (demo/latest_intel.py), with
# well-known public family names and made-up feed titles and counts.
SAMPLE_INTEL = {
    "taken_at": "2026-09-15 00:00 UTC", "sample": True, "errors": [],
    "threatfox": [
        {"family": "ClearFake", "malware": "js.clearfake", "iocs": 14, "threat_types": ["payload_delivery"],
         "last_seen": "2026-09-14 23:10:00"},
        {"family": "NanoCore RAT", "malware": "win.nanocore", "iocs": 9, "threat_types": ["botnet_cc"],
         "last_seen": "2026-09-14 21:02:00"},
        {"family": "ClickFix", "malware": "js.iclickfix", "iocs": 5, "threat_types": ["payload_delivery"],
         "last_seen": "2026-09-14 18:45:00"},
    ],
    "misp_events": [
        {"date": "2026-09-14", "info": "Sample phishing URL feed", "attributes": 3127, "org": "Sample feed"},
        {"date": "2026-09-14", "info": "ThreatFox IOCs 2026-09-14", "attributes": 413, "org": "Sample org"},
        {"date": "2026-09-13", "info": "Example C2 blocklist feed", "attributes": 88, "org": "Sample feed"},
    ],
}


def main() -> None:
    anonymiser = anonymise.Anonymiser(SAMPLE_NETS, SAMPLE_DOMAINS,
                                      keep_domains=anonymise.indicator_names(build()) | {"exosrv.com"})
    results = anonymise.anonymise_results(build(), anonymiser)
    path = anonymise.write_bundle(results, anonymise.SAMPLE_DIR, pdf=True, intel=SAMPLE_INTEL)
    print(f"Wrote {len(results)} sample case(s) to {path}")


if __name__ == "__main__":
    main()

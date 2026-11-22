"""Investigate IOC matches on a campus network.

For each (indicator, internal host) pair in the feed, the must-run checks
(steps 1-5, 7, 8) run deterministically in Python against ClickHouse and the
local knowledge base, and Python computes evidence signals and a rule-based
baseline verdict. The model gets the evidence WITHOUT the rules' signals or
verdict, investigates further with its own queries, adds 1-3 charts, and
writes the report with its verdict (steps 6, 9, 10). Code checks the report
against the evidence; where it disagrees with the rule-based cross-check or
contradicts the evidence, the case goes to a human.

    python assess.py                                   # the default feed in data/
    python assess.py data/ioc_matches.jsonl --limit 5  # a feed given by name (JSON or JSON Lines)
    python assess.py data/sample/ioc_matches_sample.json --indicator bore.pub
    python assess.py data/misp_matches.jsonl --pdf --limit 2  # also LaTeX/PDF reports
"""
from __future__ import annotations

import argparse
import json
import math
import re
import time
from functools import partial
from pathlib import Path

from agent import (analysis, beacon, behaviour, casefile, charts, config, correlation, db, evidence, host_type,
                   knowledge, labels, latex, llm_client, matcher, mdrender, report, signals, timeline, tools, web_context)

HERE = Path(__file__).resolve().parent
# Local Ollama has no rate limit; OpenRouter's free tier does.
REQUEST_PAUSE_SEC = 0.0 if config.PROVIDER == "ollama" else 6.0


def _site_section() -> str:
    """Site context for the system prompt: local time zone and free-text notes."""
    lines = []
    if config.LOCAL_TIMEZONE != "UTC":
        lines.append(
            f"- Local time zone: {config.LOCAL_TIMEZONE}. All data timestamps are UTC; the case "
            f"file adds local times in [{config.LOCAL_CITY} time: ...] with their zone abbreviation. Use them (and the "
            "weekday) when judging "
            "time of day, e.g. overnight or weekend activity. Do not convert times yourself."
        )
    if config.SITE_CONTEXT:
        lines.append(f"- {config.SITE_CONTEXT}")
    if not lines:
        return ""
    return "\nSite context:\n" + "\n".join(lines) + "\n"


SITE_SECTION = _site_section()

TEAM_LABEL = f"the {config.ORG_NAME} security team" if config.ORG_NAME else "the security team"

SYSTEM_PROMPT = f"""You are a senior network security analyst investigating IOC (Indicator \
of Compromise) matches on {config.NETWORK_LABEL} (a university network). Each case is one \
{config.HOST_LABEL} that contacted an indicator listed by a threat-intelligence source (a MISP \
feed, ThreatFox, or an analyst's manual entry). You investigate the case \
and write the report {TEAM_LABEL} will act on.
{SITE_SECTION}
You get a CASE FILE with the evidence already gathered: the IOC context, the \
flagged IP(s) and their ASN, the expected behaviour from a local knowledge base \
(threat type, malware family, and any known service such as a tunnel), the flows \
between the host and the flagged IP, the names the host actually used on that IP, \
its per-minute contact pattern, app labels, the host's traffic to other IPs and its \
uptime, DNS behaviour, the names on the flagged IP campus-wide, and other \
{config.HOST_LABEL}s contacting it. Use only the case file and your tool results. \
Do not invent numbers, hostnames or events. You have no internet access.

How to read the evidence:
- CONTACT PATTERN comes from per-minute data (subscriber_activity_1m, or the \
5-minute table for older matches). "periodic_checkin" or "held_open" only \
counts against the host when nothing explains it; an "explained by" reason \
(a recognised app or session, a known service's client, a popular \
destination) means the pattern is normal for that app.
- long_flow_summary only holds flows over 1 MB. No rows there is NOT evidence \
of anything, and it cannot show beacons.
- APPS: SuperNetFlow's application labels and recognised sessions \
(ux_sessions) for this traffic. A remote-access app explains traffic but is \
itself an exposure. Platform comes from user agents where the host sent any.
- DNS: dns_tuple shows which external resolvers the host asks directly, with \
no domain names and no response codes, so there is no NXDOMAIN rate. An \
unusual resolver or a high unanswered share is only a weak hint.
- WHAT THE HOST IS USED FOR: the host's own traffic grouped by kind of use \
(adult content, gaming, streaming or social media, study help, work tools), \
with volumes, shares and the main sites, then the busiest sites that are on no \
list. The lists are short and miss many sites: judge what every site is from \
its name yourself (a name with porn, xxx, sex, cams, nsfw or tube in it, or a \
known adult brand, is adult content; likewise games, streaming, study or work \
sites), in this section, the busiest destinations and the FLOW TIMELINE. It is \
the main evidence of what the machine is and who uses it. On a university network, personal use such as \
pornography, games or streaming, or study-help sites, points to a student's \
own device; workplace tools with no personal use point to staff; neither \
points to an unclear user. Streaming or social media beside heavy work tools \
points neither way (everyone uses them): the user is then unclear unless \
adult content, games or study-help sites are there too. A host name in the \
university's managed-device domain only means a university-managed machine.
- FLOW TIMELINE: all of the host's traffic in the minutes around the contacts, \
rows F1, F2, ... in time order. It shows what the host was doing when the \
contact happened: the page or app that was open, and what came just before \
and after it. Rows in the same minute as the flagged contact are its context.
- EXPECTED BEHAVIOUR comes from the local knowledge base, or, when it says so, \
from a threat description an analyst supplied (for example about a new CVE). \
Use that description as the background on the threat and the yardstick for an \
affected host; it says nothing about whether this host is affected.
- When EXPECTED BEHAVIOUR says what "affected" means for the threat type (for \
phishing: a user visited the page, not an infected host), use that meaning in \
the Background, the verdict and the next steps, and do not bring in malware \
expectations (beacons, payload downloads, exfiltration) the profile does not \
list.
- PUBLIC THREAT INTEL is looked up online for this case: Malpedia's \
description of the malware family and the indicator's ThreatFox listing. Use \
it in The threat, naming the source ("Malpedia describes ..."); it describes \
the threat in general and says nothing about this host.
- WEB CONTEXT (inside PUBLIC THREAT INTEL, when present) is external and \
unverified: cite its source URL with any claim taken from it. Flow data \
outranks it: if they conflict, follow the flow data and say so. It never \
decides the verdict on its own.
- Evidence marked "from the IOC feed, not re-queried" is the feed's own copy \
of the matched rows: real, but only the matched minutes.
- The evidence first/last seen times are the matched flow's own times, not \
the source's dates for the indicator. Only reason about the source's dates if \
the case file gives them.
- DIRECTION: flow records always list the campus host as the client. When \
STEP 5 says the flagged address most likely connected TO the host (inbound), \
write it that way: the host was reached (for example a campus server being \
scanned or probed), it did not reach out, and "the host sent" means its \
replies. Judge it as exposure of that service, not as infection.
- If the case file shows no traffic between the host and the flagged IP, say \
so plainly and do not describe traffic that is not there; explain what was \
checked and what that means. Such a case is recorded as insufficient data \
whatever verdict you give.
- HOST TYPE says what kind of machine the host is (from its own traffic, with \
a confidence) and how it compares with typical hosts of that type. Use it: \
the same contact means different things from a workstation, a server or a NAT \
gateway, and behaviour that is unusual for the type is worth explaining. When HOST TYPE \
says the type is unclear (confidence under 0.5, or the rule-based reading \
names another type), do not state a type anywhere, the header fields \
included: describe what the traffic shows (volumes, hours, kinds of use, how \
many remote addresses) and give the best guess only as a guess. A NAT \
gateway or proxy carries many devices, so a match from one says some device \
behind it made the contact.

Investigating (all tools are bound to this case's host):
- timeline_around(time, minutes): what the host did around one time. Tells a \
browsing burst apart from a lone automated connection.
- host_baseline(days): the host's normal daily volume, destinations and hours.
- compare_sessions(date_a, date_b): the host's traffic with the flagged IP on two dates.
- run_sql(sql): anything else, read-only, 50 rows at most.
- add_chart(...): your own chart, if no ready-made one fits (see Charts).
Use them wherever the case file leaves a question open or a point in your report \
needs checking: what else the host did at the match time, whether the contact \
stands out from its normal day, how other campus hosts use the flagged IP, which \
ports and names were involved. A case that is already clear needs few queries.
Tables for run_sql and add_chart:
{db.SCHEMA_CARD}
Notes on this data:
{db.DOMAIN_NOTES}
Every query MUST filter on this case's client_ip (or a flagged server_ip) AND a \
time column within the table's span, or it is rejected with an error saying why. \
Bound time with literal UTC datetimes ('2026-09-15 00:00:00'). Read any error and \
fix the query.

Judging the case. An IOC match is a starting point, not proof: judge the \
behaviour, not the match.
- The source's confidence says how sure the reporter is that the INDICATOR is \
malicious. It says nothing about whether THIS HOST is infected. Never use it \
to move a verdict to SUSPICIOUS or LIKELY_THREAT. Many MISP indicators carry \
no confidence at all; that is not evidence either way.
- An ip:443 indicator on a CDN or shared cloud IP (Cloudflare, AWS) is weak on \
its own: one IP serves thousands of unrelated sites. What matters is which \
name the host actually used on it and whether that name is bad. UDP/443 is \
QUIC: browser or app HTTPS, not a custom C2 protocol.
- Only call traffic exfiltration if a flow is marked over the exfiltration \
threshold in the case file.
- Ports decide a lot on shared infrastructure. If a known service profile \
matched, the "Port check" line says whether the observed ports are the \
service's own client ports (the host runs the service's client itself, which \
is NOT what a C2 victim looks like) or other ports (e.g. a tunnel's public \
port, which is what a victim of C2 hidden behind the service would use).
- A held-open connection (one connection lasting hours or days at a steady \
packet rate) is NOT a beacon. A beacon is many small contacts at a regular \
interval. Daily presence alone proves nothing. Use the CONTACT PATTERN as \
computed; do not re-derive it.
- Many campus hosts on one IP, a CDN ASN or a known public service point to \
shared infrastructure. Peers ALSO flagged by other IOCs (marked ***) point to \
a multi-host compromise instead; peers flagged for the SAME indicator are the \
same trigger, not independent evidence.
- A tunnel that exposes a campus host to the internet bypasses the firewall \
even when its use is benign: a false positive for the malware can still be a \
risk worth following up.

Charts:
The case file ends with READY-MADE CHARTS, built from the evidence. Choose the \
1-3 that best support your analysis and place each on its own line where it \
belongs, as written there, e.g. [[chart host_load]]. Then say in your own words \
what the reader should see in it; never copy the chart's description line. If none of them shows what matters, make your own \
with the add_chart tool and place it as [[chart N]] with the number it returns. \
Never write SQL or chart instructions in the report itself.

Writing the report:
The readers are analysts in {TEAM_LABEL} deciding what to do with this alert. \
Write it the way a senior analyst briefs a colleague: in your own words, as \
connected reasoning about this particular case, not a form filled in. Explain \
what happened, what it means and how you know. Be specific: exact times (UTC, \
with the {config.LOCAL_CITY} time where time of day matters), names, ports, volumes and \
counts; how the contact compares with the host's own normal traffic and with \
other campus hosts; and what each fact means for the verdict. Prefer short \
paragraphs. Use a list only for things that are truly parallel, such as next \
steps, and a small table only to compare several values. Do not write \
"Label: value" lines, do not repeat a fact in several places, and leave out \
anything that does not bear on this case.

The report has exactly these four parts, as ## headings, in this order:

## Executive summary
Three to five sentences for a reader who reads nothing else: which host \
contacted what and when, what the host appears to be and who likely uses it \
(and the activity that shows it), what the traffic \
actually was, your verdict and the main reason, and the one thing to do now.

## Background
What a reader needs before the analysis, in three ### parts of a short \
paragraph or two each:
### The host
What the machine appears to be and how it is normally used, read from its own \
traffic: its classified type and how sure that is, its operating system, its \
uptime and usual volume. Then what it is used for: name the kinds of content \
and activity and the main sites, with their volumes and shares from WHAT THE \
HOST IS USED FOR (for example "adult video sites carried over half of its \
traffic, most of it to one site"). State it plainly and factually; it is evidence. \
From that activity, infer whether a student or a staff member most likely \
uses the machine, and say which activity points there: pornography, games, \
streaming and social media, or study-help sites point to a student's own \
device; workplace tools with no personal use point to staff. If nothing points \
either way, or the use is mixed (see WHAT THE HOST IS USED FOR above), say the \
user is unclear. Present it as an inference from the traffic, never as \
"typical of a student device", and never from volumes alone, and do not guess where the host is or which network it \
is on unless the host name plainly says so.
### The threat
What the indicator is and why it matters: the malware family and threat type, \
how it usually reaches a machine, what it does once there, and what harm it \
could do to the host's user and to the university.
### What an affected host looks like
The typical characteristics of an affected host in flow data, as EXPECTED \
BEHAVIOUR describes it for this threat type: which \
destinations, ports and protocols, how often and at what times of day, how \
much data each way, and what usually comes just before the contact (for \
example a web page visit before a fake-update download). This is the \
yardstick the Analysis measures this host against.

## Analysis
The investigation, as a breakdown of the evidence behind the verdict, with \
### subheadings for its strands, for example: when and how the contact \
happened; what the host was doing around it; how it compares with an affected \
host and with the host's normal behaviour; what decides it. Be investigative. \
Give the exact times of the contacts in time order (UTC, with {config.LOCAL_CITY} time), and use the FLOW \
TIMELINE to say what the host did in the minutes before and during it, and in \
what order, with times. Look for the sequence that explains the contact: an \
adult or streaming site already open in the minutes before a burst of flagged \
ad domains, ad networks and click redirects is most likely pop-up or redirect \
ads loaded by that site, while a contact with nothing around it looks \
automated. Name the sites, the times and the gap between them. \
Cite the timeline rows you rely on in the sentence as [[flow F3]] (or \
[[flow F3-F6]]); they link to the flow table. Weigh the benign explanation \
(shared infrastructure, a known service's normal client, an app label, a \
popular destination, an ad) against the malicious one, say which evidence \
decides it, and note anything that does not fit. Place your charts here.

## Conclusion and next steps
The verdict, how confident you are and why; any risk that remains even if this \
is not the flagged malware; what the evidence cannot show for this case; then \
numbered next steps specific to this host (who to contact, what to check, what \
to alert on), most important first.

Length: about 450 words for the four parts together, so the report fits on one \
page; the figures and the flow table carry the detail, and the text points to \
them.

Style:
- Times in UTC with the {config.LOCAL_CITY} time in brackets, written with the \
zone abbreviation the case file gives (for Sydney: AEDT in daylight saving, \
AEST otherwise), e.g. "04:34 UTC (15:34 AEDT)". Never write "local" as the zone.
- When the contacts fall on more than one day, give the full date with every \
time ("2 Nov 2026 01:16 UTC (12:16 AEDT)"), so no time can be read as the \
wrong day. List contacts in time order.
- Full IP addresses every time, never shorthand such as "3.11".
- Always say who sent what: "the host sent 2.1 MB and received 40 KB", never \
"far more than they got back".
- Grade the evidence and say which grade the case reaches: contact (the host \
only reached the indicator), delivery attempt (something came down from it), \
exploitation indicated (signs that what came down ran or worked), \
post-compromise (ongoing control, or data leaving the host).
- Say what the host is and what would be at stake if it were compromised.
- Compare the flagged contact with the host's normal traffic or with the \
indicator's other campus visitors, using figures from the case file or a \
query (e.g. "larger than 71% of visitors").
- Refer to figures and tables by number: name a chart inside a sentence with \
its marker ("as [[chart host_load]] shows" reads "as Figure 2 shows"), and cite \
flow rows as [[flow F3]] (they point to the flow table).

Plain words for the data's labels. The case file uses code labels; write \
their plain forms in the report and headline, never the labels themselves:
{labels.prompt_list()}

Rules for the report text:
- Every number must appear in the case file or a tool result (the ready-made \
charts' values count). Do not work out new figures such as percentages, sums or \
rates in your head: if you need one, query it.
- Only cite sources the case file or a tool result contains: the feed and \
its tags, the knowledge base, and Malpedia or ThreatFox where PUBLIC THREAT \
INTEL quotes them. Never cite VirusTotal, reputation lists, "known phishing \
patterns" or any other source you were not given.
- Flow records hold host names (TLS SNI, DNS), never the URL path: never say \
which URL or page was or was not visited; say the host reached the host name \
and that the records cannot show which page.
- State only what the evidence shows. An explanation the evidence does not \
test (a pop-up or redirect ad, a user's intent) is at most a possibility, \
named as one with the rows it rests on; a pop-up ad needs an ad-network or \
adult-site row beside the flagged contact, and a link-sharing or hosting \
service is not an ad. No yardsticks of your own ("typical of a student device").
- Count contacts as the case file does ("4 contacts in 2 sessions"), never \
"twice" for four contacts.
- Describe a figure only by what it shows (its title and bars or lines): do \
not name sites for a chart of kinds of use, for example.
- Counts from long_flow_summary (other campus hosts, large flows) cover only \
flows over 1 MB in the lookback window: say so whenever you use them, and \
never turn them into "ever" or "only N hosts" without that qualifier.
- Write as the security team's own analysis. Never mention an agent, a model, AI, \
a prompt, the case file or its step numbers, or yourself ("I", "my"). Name data \
by what it is, e.g. "per-minute flow records".
- No title: the page already shows the indicator and the host above the report.

Reply in exactly this format: the header lines, FLOW_NOTES, then REPORT: on its \
own line, then the four parts.

VERDICT: <LIKELY_THREAT | SUSPICIOUS | LIKELY_FALSE_POSITIVE>
CONFIDENCE: <low | medium | high>
HOST_ROLE: <one hedged sentence: what the machine probably is, based on its \
uptime and other traffic>
LIKELY_USER: <student | staff | unclear> - <the activity that points there, \
naming the kind of use and the main sites by domain>
HEADLINE: <one sentence for the case list: what happened and your assessment>
FLOW_NOTES:
F1: <a few words on what this connection most likely is>
F2: <...one line per FLOW TIMELINE row; rows with the same note may share a \
line, e.g. F4-F6: ...; "none" if there are no rows>
REPORT:
## Executive summary
...
## Background
### The host
...
### The threat
...
### What an affected host looks like
...
## Analysis
...
## Conclusion and next steps
...

FLOW_NOTES examples: "video page on the adult site", "pop-up ad loaded by \
that page", "flagged ad domain, same minute as the pop-up", "Windows update \
check", "background sync, unrelated".

VERDICT meanings: LIKELY_THREAT = evidence supports escalation; SUSPICIOUS = \
mixed or incomplete, needs a manual look; LIKELY_FALSE_POSITIVE = the traffic \
does not match the threat (shared infrastructure, a known service's normal \
client, or a shape that doesn't fit), even if some other risk remains.
"""

HEADER_FIELDS = ["VERDICT", "CONFIDENCE", "HOST_ROLE", "LIKELY_USER", "HEADLINE", "FLOW_NOTES"]
FIELDS = HEADER_FIELDS + ["REPORT"]
MULTI_LINE_FIELDS = ("FLOW_NOTES",)  # one note per line
VERDICTS = {"LIKELY_THREAT", "SUSPICIOUS", "LIKELY_FALSE_POSITIVE"}  # the model's choices
ONE_WORD_FIELDS = ("VERDICT", "CONFIDENCE")
REPORT_MARKER_RE = re.compile(r"(?i)^REPORT\s*:?(.*)$")
MIN_REPORT_CHARS = 300  # shorter than this is not a report


def _clean(line: str) -> str:
    return line.strip().lstrip("*# ").replace("**", "")


def _clean_report(text: str) -> str:
    """Drop a code fence around the whole report and a leading title line."""
    text = text.strip()
    fenced = re.match(r"^```[a-zA-Z]*\n(.*)\n```$", text, re.S)
    if fenced:
        text = fenced.group(1).strip()
    lines = text.split("\n")
    if lines and re.match(r"^#\s", lines[0]):
        text = "\n".join(lines[1:]).strip()
    return text


def parse_reply(text: str) -> dict:
    """Header fields, then the report after a REPORT: line. Lenient: missing
    fields come back empty; without a REPORT: line, everything after the last
    header field is the report."""
    parsed = {field: "" for field in FIELDS}
    lines = (text or "").splitlines()
    marker = next((i for i, line in enumerate(lines) if REPORT_MARKER_RE.match(_clean(line))), None)
    header_end = marker
    if marker is None:
        header_lines = [i for i, line in enumerate(lines)
                        if any(_clean(line).startswith(f + ":") for f in HEADER_FIELDS)]
        header_end = header_lines[-1] + 1 if header_lines else 0
    current = None
    for line in lines[:header_end]:
        stripped = _clean(line)
        field = next((f for f in HEADER_FIELDS if stripped.startswith(f + ":")), None)
        if field:
            current = field
            parsed[field] = stripped.split(":", 1)[1].strip()
        elif current and current not in ONE_WORD_FIELDS and stripped:
            joiner = "\n" if current in MULTI_LINE_FIELDS else " "
            parsed[current] = (parsed[current] + joiner + stripped).strip()
    if marker is not None:
        first = REPORT_MARKER_RE.match(_clean(lines[marker])).group(1).strip()
        parsed["REPORT"] = _clean_report("\n".join([first] + lines[marker + 1:]))
    else:
        parsed["REPORT"] = _clean_report("\n".join(lines[header_end:]))
    parsed["REPORT"], trailing = _split_trailing_notes(parsed["REPORT"])
    if trailing and not parsed["FLOW_NOTES"]:
        parsed["FLOW_NOTES"] = trailing
    parsed["flow_notes"] = parse_flow_notes(parsed["FLOW_NOTES"])
    # One-word fields: take the known value, ignoring any stray text after it.
    verdict = parsed["VERDICT"].upper().replace(" ", "_")
    given = next((v for v in sorted(VERDICTS, key=len, reverse=True) if v in verdict), None)
    parsed["verdict_given"] = given is not None
    parsed["VERDICT"] = given or "SUSPICIOUS"
    confidence = re.search(r"(?i)\b(low|medium|high)\b", parsed["CONFIDENCE"])
    parsed["CONFIDENCE"] = confidence.group(1).lower() if confidence else "low"
    parsed["SECTIONS"] = split_sections(parsed["REPORT"])
    return parsed


TRAILING_NOTES_RE = re.compile(r"(?im)^\W*FLOW_NOTES\s*:?\**\s*(.*)$")


def _split_trailing_notes(report_text: str) -> tuple[str, str]:
    """FLOW_NOTES written after the report instead of before it: (report, notes)."""
    match = TRAILING_NOTES_RE.search(report_text)
    if not match:
        return report_text, ""
    notes = (match.group(1) + "\n" + report_text[match.end():]).strip()
    return report_text[:match.start()].rstrip(), notes


FLOW_NOTE_RE = re.compile(r"^\W*(F\d+(?:\s*(?:,|&|-|–|—|\bto\b|\band\b)\s*F?\d+)*)\s*[:=]\s*(.+)$", re.I)
FLOW_RANGE_RE = re.compile(r"F?(\d+)(?:\s*(?:-|–|—|\bto\b)\s*F?(\d+))?", re.I)
MAX_NOTE_RANGE = 100


def parse_flow_notes(text: str) -> dict[str, str]:
    """FLOW_NOTES lines ("F3: pop-up ad", "F4-F6: video page") -> {"F3": note, ...}."""
    notes: dict[str, str] = {}
    for line in (text or "").splitlines():
        match = FLOW_NOTE_RE.match(line.replace("**", "").strip())
        if not match:
            continue
        note = match.group(2).strip().strip("*").strip()
        for first, last in FLOW_RANGE_RE.findall(match.group(1)):
            a, b = int(first), int(last or first)
            if a <= b <= a + MAX_NOTE_RANGE:
                notes.update({f"F{n}": note for n in range(a, b + 1)})
    return notes


SECTION_TITLES = mdrender.SECTION_TITLES
split_sections = mdrender.split_sections


def main_text(parsed: dict) -> str:
    """The report without its Background part, which describes the threat in
    general terms (e.g. "NanoCore sends stolen data back") rather than this host."""
    sections = parsed.get("SECTIONS") or split_sections(parsed.get("REPORT", ""))
    return "\n".join(sections.get(k, "") for k in ("summary", "analysis", "conclusion"))


def report_usable(parsed: dict) -> bool:
    return parsed.get("verdict_given", False) and len(parsed.get("REPORT", "")) >= MIN_REPORT_CHARS


# --- evidence gathering (steps 2-5, 7, 8) -------------------------------------------

def _safe(label: str, fn, *args) -> dict:
    """Run one tool; a failed query becomes {"error": ...} in the case file
    instead of taking the whole case down."""
    try:
        return fn(*args)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{label} failed: {exc}"}


def gather_evidence(identity: dict, case_rows: list[dict], asset_index: dict[str, list[dict]]) -> dict:
    host = identity["affected_asset"]
    window = evidence.case_window(identity)

    host_info = _safe("host_identity", tools.host_identity, host)
    own_name = host_info.get("hostname")
    server_ips = _safe("identify_server_ips", tools.identify_server_ips, identity, case_rows, window)
    ip_list = [entry["server_ip"] for entry in server_ips.get("ips", [])]
    flows = _safe("indicator_flows", tools.indicator_flows, host, ip_list, window, case_rows, own_name)
    if "error" not in flows:
        flows["direction"] = tools.connection_direction(flows, case_rows, own_name)
    names = _safe("indicator_names", tools.indicator_names, host, ip_list, window, case_rows, own_name)
    expected = tools.expected_behaviour(identity, server_ips, flows)
    public_intel = _safe("web_context", web_context.lookup, identity)
    held = (flows.get("classification") or {}).get("held_open") or {}
    load = _safe("host_load_baseline", tools.host_load_baseline, host, identity)
    other_traffic = _safe("host_other_traffic", tools.host_other_traffic, host, window, ip_list, own_name,
                          held.get("max_duration_sec"), load)

    asn = [tools.ip_asn(ip, flows, server_ips) for ip in ip_list[: tools.MAX_PEER_IPS]]
    names_on_ip = []
    for ip in ip_list[: tools.MAX_PEER_IPS]:
        result = _safe("names_on_ip", tools.names_on_ip, ip, window, identity)
        result.setdefault("server_ip", ip)
        names_on_ip.append(result)

    feed_indicators = {m["indicator"] for ms in asset_index.values() for m in ms} - {identity["indicator"]}
    feature_names = [identity["indicator"]] if identity.get("indicator_type") == "domain" else []
    feature_names += names.get("registered_domains", [])
    features = _safe("domain_features", tools.domain_features, feature_names, window, feed_indicators, host, identity)
    features = features if isinstance(features, list) else []

    peers = []
    for ip in ip_list[: tools.MAX_PEER_IPS]:
        result = _safe("indicator_peers", tools.indicator_peers, ip, server_ips.get("indicator_port"),
                       identity, asset_index)
        result.setdefault("server_ip", ip)
        peers.append(result)

    port = server_ips.get("indicator_port")
    contact = _safe("beacon_analysis", tools.beacon_analysis, host, ip_list, port, window, case_rows)
    flow_timeline = _safe("contact_timeline", timeline.contact_timeline, host, ip_list, contact, identity, own_name)
    app_context = _safe("app_context_for_indicator", tools.app_context_for_indicator, host, ip_list, window, identity)
    host_apps = _safe("host_applications", tools.host_applications, host, window)
    dns = _safe("host_dns_behaviour", tools.host_dns_behaviour, host, identity)
    shared = tools.shared_infrastructure(server_ips, flows, expected, peers)
    host_kind = _safe("host_type", host_type.assess_host, host, identity, own_name)
    other_matches = [m for m in asset_index.get(host, []) if m["indicator"] != identity["indicator"]]
    ev = {
        "identity": identity,
        "host": host_info,
        "window": window.describe(),
        "server_ips": server_ips,
        "flows": flows,
        "names": names,
        "asn": asn,
        "names_on_ip": names_on_ip,
        "domain_features": features,
        "contact": contact,
        "timeline": flow_timeline,
        "app_context": app_context,
        "host_apps": host_apps,
        "dns": dns,
        "load": load,
        "expected": expected,
        "web_context": public_intel,
        "other_traffic": other_traffic,
        "host_type": host_kind,
        "peers": peers,
        "shared": shared,
        "other_matches": other_matches,
    }
    ev["signals"] = signals.compute_signals(ev)
    ev["baseline"] = signals.baseline_verdict(ev["signals"], signals.has_evidence(ev))
    ev["behaviour"] = behaviour.classify(ev)
    ev["chart_options"] = charts.prepared(ev)
    return ev


# --- guards on the model's reply ----------------------------------------------------

def _no_traffic(ev: dict) -> bool:
    flows = ev["flows"]
    return not flows.get("has_traffic") or "error" in flows


# --- verdict and the rule-based cross-check ------------------------------------------

SEVERITY = {"LIKELY_FALSE_POSITIVE": 0, "SUSPICIOUS": 1, "LIKELY_THREAT": 2}
VERDICT_LABEL = {"LIKELY_THREAT": "likely threat", "SUSPICIOUS": "suspicious",
                 "LIKELY_FALSE_POSITIVE": "likely false positive", "INSUFFICIENT_DATA": "insufficient data"}


def reconcile_verdict(parsed: dict, baseline: dict) -> dict:
    """The report and its verdict are the model's: it reads the evidence
    without the rules' result. The rule-based baseline is a cross-check, and a
    disagreement marks the case for a human. Two things are set in code: no
    traffic means INSUFFICIENT_DATA, and a reply with no verdict falls back to
    the baseline's."""
    parsed = dict(parsed)
    model_verdict = parsed["VERDICT"]
    parsed["model_verdict"] = model_verdict
    parsed["model_confidence"] = parsed["CONFIDENCE"]
    parsed["baseline_verdict"] = baseline["verdict"]
    parsed["report_source"] = "analysis" if report_usable(parsed) else "incomplete"
    notes: list[str] = []
    if parsed["report_source"] == "incomplete":
        notes.append("The written analysis is incomplete (a part is missing or it is very short): read it with "
                     "care and check the evidence.")
    if baseline["verdict"] == "INSUFFICIENT_DATA":
        parsed["VERDICT"], parsed["CONFIDENCE"] = "INSUFFICIENT_DATA", "high"
        return {**parsed, "verdict_notes": notes}
    if not parsed.get("verdict_given"):
        parsed["VERDICT"], parsed["CONFIDENCE"] = baseline["verdict"], baseline["confidence"]
        notes.append(f"The analysis gave no verdict, so the rule-based one is shown "
                     f"({baseline.get('reason', '').rstrip('.')}).")
        return {**parsed, "verdict_notes": notes}
    if model_verdict != baseline["verdict"]:
        notes.append(f"The rule-based cross-check gives {VERDICT_LABEL.get(baseline['verdict'])} "
                     f"({baseline.get('reason', '').rstrip('.')}), where this report concludes "
                     f"{VERDICT_LABEL.get(model_verdict)}. Weigh both before acting.")
        escalating = SEVERITY.get(model_verdict, 1) > SEVERITY.get(baseline["verdict"], 1)
        if escalating and _cites_source_confidence(parsed.get("REPORT", "") + " " + parsed.get("HEADLINE", "")):
            notes.append("The report mentions the source's confidence, which rates the indicator, not this host.")
    return {**parsed, "verdict_notes": notes}


SOURCE_WORDS_RE = re.compile(r"(?i)threatfox|\bmisp\b|\bfeed\b|reporter|listing|source'?s? confidence|"
                             r"(indicator'?s?|intel(ligence)?|threat[- ]intel(ligence)?) source")


def _cites_source_confidence(text: str) -> bool:
    """A sentence that leans on the indicator source's confidence rating."""
    return any(SOURCE_WORDS_RE.search(s) and re.search(r"(?i)confidence", s) for s in _sentences(text))


DOES_NOT_FIT_RE = re.compile(r"(?i)\b(does not|doesn't|do not|don't|not)\s+(match|fit|consistent|align)|inconsistent with|unlike")
EXFIL_RE = re.compile(r"(?i)exfiltrat|data theft|stolen data|data (was|being) sent out|sending data out")
NEGATION_RE = re.compile(r"(?i)\b(no|not|none|zero|without|lack of|absence of|never|nor|rather than|instead of|"
                         r"would|could|can|may|might|if|whether|unless|typical|typically|usually|expected|"
                         r"designed|known to|such as|"
                         # "inconsistent with exfiltration", "rules out data theft", "unlikely to be ..."
                         r"inconsistent|unlike|unlikely|rules? out|ruled out|ruling out|against|too small|"
                         r"doesn't|does not|isn't|is not|aren't|are not|cannot|can't)\b"
                         r"|\bthreshold\b")  # "over the exfiltration threshold: 0" quotes the case file
# The negation must sit right before "shared" ("not shared", "no shared
# infrastructure", "lack of shared"), not anywhere earlier in the sentence.
NOT_SHARED_RE = re.compile(
    r"(?i)\b(not|no|lack of|isn't|is not|without|absence of)\s+(a\s+|any\s+|on\s+|on a\s+)?(shared|cdn)\b"
    r"|\bdedicated (ip|server|host|infrastructure)\b")
SHARED_RE = re.compile(r"(?i)shared (infrastructure|service|ip|hosting|nature|address)|\bcdn\b|many unrelated")


def _sentences(text: str) -> list[str]:
    return [s for s in re.split(r"(?<=[.;!?])\s+|\n+", text) if s.strip()]


def _affirmed(pattern: re.Pattern, text: str) -> bool:
    """True if some sentence uses the pattern without negating or
    hypothesising it ("possible exfiltration", not "no exfiltration")."""
    return any(pattern.search(s) and not NEGATION_RE.search(s) for s in _sentences(text))


def _affirmed_mismatch(text: str) -> bool:
    return bool(DOES_NOT_FIT_RE.search(text))


def consistency_flags(parsed: dict, ev: dict) -> list[str]:
    """Contradictions between the report and the evidence. The headline is
    held to every check; the long report only to the ones a careful report
    would not trip by discussing the other explanation."""
    flags: list[str] = []
    model_verdict = parsed.get("model_verdict", parsed["VERDICT"])
    headline = parsed.get("HEADLINE", "")
    report_text = main_text(parsed)
    if model_verdict in ("SUSPICIOUS", "LIKELY_THREAT") and _affirmed_mismatch(headline):
        flags.append(f"The headline says the traffic does not match the threat, but the verdict is {model_verdict}.")

    exfil = ev.get("flows", {}).get("upload_heavy_over_exfil_threshold", {"count": 0})
    if _affirmed(EXFIL_RE, headline + "\n" + report_text) and not exfil.get("count"):
        flags.append(f"The report mentions exfiltration, but no flow is over the threshold "
                     f"(up/down > {config.EXFIL_MIN_RATIO:g} and > {config.EXFIL_MIN_UP_BYTES / 1e6:g} MB up).")

    shared = next((s for s in ev.get("signals", []) if s["name"] == "shared_infrastructure"), None)
    if shared:
        says_not_shared = bool(NOT_SHARED_RE.search(headline + "\n" + report_text))
        if shared["direction"] == signals.AGAINST and says_not_shared:
            flags.append("The report says the IP is not shared, but the shared-infrastructure check says it is: "
                         f"{shared['reason']}")
        if shared["direction"] == signals.SUPPORTS and _affirmed(SHARED_RE, headline) \
                and not NOT_SHARED_RE.search(headline):
            flags.append("The headline calls the IP shared infrastructure, but the shared-infrastructure check "
                         "says it looks dedicated.")
    words = self_references(parsed.get("REPORT", "") + "\n" + headline)
    if words:
        flags.append(f"The report text refers to itself or to how it was produced ({', '.join(words)}).")
    return flags


# Numbers are matched as whole tokens: an IP address, a date, a time, a size
# with its unit, or a plain number. "20" is not in the evidence just because
# "2026" or "203.0.113.20" is.
NUMBER_TOKEN_RE = re.compile(
    r"(?<![\d.:])(?:"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<port>\d+))?"
    r"|(?P<date>\d{4}-\d{2}-\d{2})"
    r"|(?P<time>\d{1,2}:\d{2}(?::\d{2})?)"
    r"|(?P<size>\d+(?:\.\d+)?)\s?(?P<unit>(?i:[kmgt]?b|bytes?))(?![\w])"
    r"|(?P<num>\d+(?:\.\d+)?)"
    r")(?!\d)")
UNIT_BYTES = {"b": 1, "byte": 1, "bytes": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12}  # as analysis.fmt_bytes
CHECKED_FIELDS = ("HOST_ROLE", "LIKELY_USER", "HEADLINE", "FLOW_NOTES", "REPORT")
BOUND_UNDER_RE = re.compile(r"(?i)\b(under|below|less than|smaller than|at most|no more than|up to|within)"
                            r"(\s+(about|around|roughly|approximately))?\s*~?\s*$")
BOUND_OVER_RE = re.compile(r"(?i)\b(over|above|more than|larger than|bigger than|at least|exceeding)"
                           r"(\s+(about|around|roughly|approximately))?\s*~?\s*$")
UP_WORDS_RE = re.compile(r"(?i)\b(up|upload(ed|s)?|sent|outbound)\b")
DOWN_WORDS_RE = re.compile(r"(?i)\b(down|download(ed|s)?|received|inbound)\b")


def _checkable(text: str) -> str:
    """Text whose numbers must be in the evidence: no chart markers, flow row
    ids (F3) or list numbering."""
    text = mdrender.CHART_ANYWHERE_RE.sub(" ", text)
    text = mdrender.FLOW_ID_RE.sub(" ", mdrender.replace_flow_refs(text))
    text = re.sub(r"(?m)^\s*\d+[.)]\s", " ", text)
    return re.sub(r"(?<=\d),(?=\d)", "", text)


# Product and service names with a number in them: the number is part of the name, not a figure.
KNOWN_NUMBERED_NAMES_RE = re.compile(r"(?i)\b(?:Microsoft|Office|M)\s?365\b|\bWindows\s(?:7|8|8\.1|10|11)\b"
                                     r"|\bWindows Server\s20\d\d\b|\bOffice\s20\d\d\b")
NAME_WITH_NUMBER_RE = re.compile(r"\b([A-Z][A-Za-z-]{2,})\s?(\d+)\b")


def _without_names(text: str, evidence_lower: str) -> str:
    """Numbers that belong to a name read as words: well-known product names
    ("Microsoft 365", "Windows 11") and any capitalised word + number the case
    file also holds, with or without the space ("Office 365" when it lists
    office365.com)."""
    text = KNOWN_NUMBERED_NAMES_RE.sub(" ", text)

    def name(m: re.Match) -> str:
        word, number = m.group(1).lower(), m.group(2)
        return " " if f"{word} {number}" in evidence_lower or f"{word}{number}" in evidence_lower else m.group(0)
    return NAME_WITH_NUMBER_RE.sub(name, text)


def _plain(number: str) -> str:
    """'07' -> '7', '1.50' -> '1.5', '3.0' -> '3'."""
    whole, _, fraction = number.partition(".")
    whole = whole.lstrip("0") or "0"
    fraction = fraction.rstrip("0")
    return f"{whole}.{fraction}" if fraction else whole


def _plain_time(text: str) -> str:
    hour, minute = text.split(":")[:2]
    return f"{int(hour)}:{minute}"


def _size_bytes(match: re.Match) -> float:
    return float(match["size"]) * UNIT_BYTES[match["unit"].lower()]


def _zone_offsets() -> list[int]:
    """The local zone's UTC offsets in minutes (standard and daylight time)."""
    from datetime import datetime
    from zoneinfo import ZoneInfo

    if config.LOCAL_TIMEZONE == "UTC":
        return []
    zone = ZoneInfo(config.LOCAL_TIMEZONE)
    year = datetime.now().year
    return sorted({int(datetime(year, month, 15, tzinfo=zone).utcoffset().total_seconds() // 60) for month in (1, 7)})


def _local_times(text: str) -> set[str]:
    """A UTC time of day as the local zone shows it, at each of its offsets."""
    hour, minute = map(int, text.split(":")[:2])
    out = set()
    for offset in _zone_offsets():
        total = (hour * 60 + minute + offset) % (24 * 60)
        out.add(f"{total // 60}:{total % 60:02d}")
    return out


def evidence_numbers(text: str) -> tuple[set[str], list[float]]:
    """(whole number tokens, byte values) in the evidence. A date also gives
    its year, month and day; a decimal its rounded forms (and a share its
    percentage); a size and any integer from 1000 up count as byte values."""
    numbers: set[str] = set()
    sizes: list[float] = []
    for m in NUMBER_TOKEN_RE.finditer(re.sub(r"(?<=\d),(?=\d)", "", text)):
        if m["ip"]:
            numbers.add(m["ip"])
            if m["port"]:
                numbers.add(_plain(m["port"]))
        elif m["date"]:
            year, month, day = m["date"].split("-")
            numbers.update({m["date"], year, _plain(month), _plain(day)})
        elif m["time"]:
            numbers.add(_plain_time(m["time"]))
            numbers.update(_local_times(m["time"]))  # "19:25 UTC (06:25 AEDT)" with only 19:25 in the evidence
        elif m["size"]:
            numbers.add(_plain(m["size"]))
            sizes.append(_size_bytes(m))
        else:
            value = float(m["num"])
            numbers.add(_plain(m["num"]))
            if "." in m["num"]:
                # rounded, or cut to a whole number either way: 251.5 min may be written 251 or 252
                numbers.update({_plain(str(round(value))), _plain(f"{value:.1f}"), str(math.floor(value)),
                                str(math.ceil(value))})
                if 0 < value <= 1:
                    numbers.update({_plain(str(round(value * 100))), _plain(f"{value * 100:.1f}")})
            elif value >= 1000:
                sizes.append(value)  # a raw byte count from a query result
    return numbers, sizes


def _decimals(number: str) -> int:
    return len(number.partition(".")[2])


def _close(value: float, decimals: int, candidate: float) -> bool:
    """value (as written, in its unit) is candidate rounded to the decimals
    written. No looser tolerance: 2% let "39.4 KB" match an unrelated 40,100
    bytes elsewhere in the evidence."""
    return abs(candidate - value) <= 0.5 * 10 ** -decimals + 1e-9


def size_in_evidence(match: re.Match, sizes: list[float]) -> bool:
    unit = UNIT_BYTES[match["unit"].lower()]
    value, decimals = float(match["size"]), _decimals(match["size"])
    return any(_close(value, decimals, b / unit) for b in sizes)


def _which_bytes(text_after: str, text_before: str) -> str:
    """'up', 'down' or 'total': what a size near these words measures."""
    for text in (text_after, text_before):
        if UP_WORDS_RE.search(text):
            return "up"
        if DOWN_WORDS_RE.search(text):
            return "down"
    return "total"


def bound_holds(match: re.Match, text: str, contacts: list[dict]) -> bool | None:
    """For "under X" / "over X" sizes: True or False against every contact's
    size, None if the size is not a bound or no contact sizes are known."""
    before = text[max(0, match.start() - 40):match.start()]
    under, over = BOUND_UNDER_RE.search(before), BOUND_OVER_RE.search(before)
    if not contacts or not (under or over):
        return None
    kind = _which_bytes(text[match.end():match.end() + 25], before)
    values = [c[kind] for c in contacts if c.get(kind) is not None] or [c["total"] for c in contacts]
    unit = UNIT_BYTES[match["unit"].lower()]
    limit = float(match["size"]) + 0.5 * 10 ** -_decimals(match["size"])
    if under:
        return max(values) / unit <= limit
    return min(values) / unit >= float(match["size"]) - 0.5 * 10 ** -_decimals(match["size"])


def _displayed(n: float) -> float:
    """A byte count as the case file shows it (analysis.fmt_bytes), back in bytes."""
    value, unit = analysis.fmt_bytes(n).split()
    return float(value) * UNIT_BYTES[unit.lower()]


def _percent_complements(text: str) -> set[str]:
    """100 minus every whole percentage in the evidence: a share sent of 7%
    means 93% received."""
    return {str(100 - int(v)) for v in re.findall(r"(?<![\d.])(\d{1,2})%", text)}


def contact_run_sums(contacts: list[dict]) -> list[float]:
    """Totals of every run of consecutive contacts (a session, or "the last
    three"), up, down and total, both exact and as the sum of the displayed
    values, so a correctly added figure is never taken for an invented one."""
    sums: list[float] = []
    for kind in ("total", "up", "down"):
        values = [c.get(kind) for c in contacts]
        if any(v is None for v in values):
            continue
        for i in range(len(values)):
            for j in range(i + 2, len(values) + 1):
                run = values[i:j]
                sums += [float(sum(run)), sum(_displayed(v) for v in run)]
    return sums


def unverified_numbers(parsed: dict, evidence_text: str, contacts: list[dict] | None = None) -> list[str]:
    """Numbers (2+ characters) the model wrote that are not in the case file
    or its tool results, matched as whole tokens. Sizes are compared with the
    evidence's byte values, allowing for rounding; a bound ("under 20 KB")
    also passes if it holds for every flagged contact. Shown as a warning."""
    numbers, sizes = evidence_numbers(evidence_text)
    numbers |= _percent_complements(evidence_text)  # "7% sent" -> "93% received"
    sizes = sizes + contact_run_sums(contacts or [])
    missing: list[str] = []
    evidence_lower = evidence_text.lower()
    for field in CHECKED_FIELDS:
        text = _without_names(_checkable(parsed.get(field, "")), evidence_lower)
        for m in NUMBER_TOKEN_RE.finditer(text):
            if m["ip"]:
                label, ok = m[0], m["ip"] in numbers and (not m["port"] or _plain(m["port"]) in numbers)
            elif m["date"]:
                label, ok = m["date"], m["date"] in numbers
            elif m["time"]:
                label, ok = m["time"], _plain_time(m["time"]) in numbers
            elif m["size"]:
                label = f"{m['size']} {m['unit']}"
                ok = size_in_evidence(m, sizes) or bool(bound_holds(m, text, contacts or []))
            else:
                label = m["num"]
                ok = len(label) < 2 or _plain(label) in numbers
            if not ok and label not in missing:
                missing.append(label)
    return missing


CONTACT_WORDS_RE = re.compile(r"(?i)\b(contacts?|flows?|connections?|visits?|bursts?|requests?|sessions?|"
                              r"episodes?)\b")
EACH_RE = re.compile(r"(?i)\b(each|every|all|apiece|individually|per (contact|flow|connection|visit|burst))\b")
TOTAL_SIZE_RE = re.compile(
    r"(?i)\b(?:a total of|total(?:l?ing|led|ed)?|in total|in all|altogether|combined|overall)\s+(?:of\s+)?"
    r"(?:about\s+|around\s+|roughly\s+|~\s*)?(?P<size>\d+(?:\.\d+)?)\s?(?P<unit>[kmgt]?b|bytes?)(?![\w])"
    r"|(?P<size2>\d+(?:\.\d+)?)\s?(?P<unit2>[kmgt]?b|bytes?)\s+(?:in total|in all|altogether|combined|overall)\b")
OTHER_TOTAL_RE = re.compile(r"(?i)\b(daily|per day|a day|per hour|baseline|median|host's (total|traffic)|"
                            r"all (its|of its) traffic|over 1 MB|long flows?|large flows?)\b")


def contact_claim_problems(parsed: dict, ev: dict) -> list[str]:
    """Per-contact sizes ("each contact was under 20 KB") and contact totals
    that disagree with the flagged contacts in the evidence."""
    contacts = beacon.contact_sizes(ev.get("contact"))
    if not contacts:
        return []
    totals = beacon.contact_totals(ev.get("contact"))
    largest = max(c["total"] for c in contacts)
    listed = ", ".join(analysis.fmt_bytes(c["total"]) for c in contacts[:6])
    problems: list[str] = []
    text = _checkable(parsed.get("HEADLINE", "") + "\n" + main_text(parsed))
    for sentence in _sentences(text):
        if not CONTACT_WORDS_RE.search(sentence):
            continue
        if EACH_RE.search(sentence):
            for m in NUMBER_TOKEN_RE.finditer(sentence):
                if m["size"] and bound_holds(m, sentence, contacts) is False:
                    problems.append(
                        f"The report says each contact was {sentence[max(0, m.start() - 12):m.end()].strip()}, "
                        f"but the flagged contacts were {listed} (largest {analysis.fmt_bytes(largest)}). "
                        "Quote the sizes from the case file's list of contacts.")
        if OTHER_TOTAL_RE.search(sentence):
            continue
        for m in TOTAL_SIZE_RE.finditer(sentence):
            size, unit = m["size"] or m["size2"], (m["unit"] or m["unit2"]).lower()
            # the whole, or any run of consecutive contacts (a session such as "Session 4 ... totalling 6.2 MB")
            known = [v for v in (totals["total"], totals["up"], totals["down"]) if v is not None]
            known += contact_run_sums(contacts)
            if not any(_close(float(size), _decimals(size), v / UNIT_BYTES[unit]) for v in known):
                split = (f" ({analysis.fmt_bytes(totals['up'])} up / {analysis.fmt_bytes(totals['down'])} down)"
                         if totals["up"] is not None else "")
                problems.append(f"The report gives a total of {size} {unit.upper() if unit != 'bytes' else unit}, "
                                f"but the {len(contacts)} flagged contact(s) total "
                                f"{analysis.fmt_bytes(totals['total'])}{split}.")
    return list(dict.fromkeys(problems))


# --- sources the report may cite ---------------------------------------------------------

# Sources the analysis cannot consult: cited only if the case file or a tool
# result holds the matched words.
OUTSIDE_SOURCES = (
    ("VirusTotal", r"virus\s?total"),
    ("AbuseIPDB", r"abuse\s?ipdb"),
    ("URLhaus", r"urlhaus"),
    ("Google Safe Browsing", r"safe\s?browsing"),
    ("Shodan", r"\bshodan\b"),
    ("Spamhaus", r"spamhaus"),
    ("Cisco Talos", r"\btalos\b"),
    ("WHOIS", r"\bwhois\b"),
    ("passive DNS", r"passive dns"),
    ("reputation lists", r"\breputation\b"),
    ("known patterns", r"\bknown (?:phishing |malware |attack |malicious |c2 |scam )?"
                       r"(?:patterns?|campaigns?|signatures?|tactics)\b"),
    ("threat reports", r"\bthreat (?:intelligence )?reports?\b|\bsecurity (?:researchers|vendors)\b"),
)
SOURCE_NEGATION_RE = re.compile(r"(?i)\b(no|not|without|never|cannot|can't|unable|none|nor)\b")


def _threatfox_given(ev: dict) -> bool:
    identity = ev.get("identity") or {}
    tags = [str(t).lower() for t in identity.get("intel_tags") or []]
    return (identity.get("intel_source") == "threatfox" or identity.get("intel_feed") == "ThreatFox"
            or any(t.startswith("threatfox:") for t in tags) or bool((ev.get("web_context") or {}).get("threatfox")))


URL_IN_TEXT_RE = re.compile(r"https?://[^\s)\]>\"']+")
NEXT_STEPS_START_RE = re.compile(r"(?im)\bnext steps?\b|^\s*(?:\d+[.)]|[-*])\s|(?<!\d)1[.)]\s")


def _before_next_steps(conclusion: str) -> str:
    """The conclusion up to its next steps: a step ("check the domain's
    reputation") is advice to the analyst, not a claim from a source."""
    match = NEXT_STEPS_START_RE.search(conclusion)
    return conclusion[:match.start()] if match else conclusion


def source_problems(parsed: dict, ev: dict, evidence_text: str) -> list[str]:
    """Claims resting on sources the case file does not hold (VirusTotal,
    reputation lists, "known phishing patterns", a ThreatFox listing that was
    never found). A sentence saying the source was not consulted is fine."""
    sections = parsed.get("SECTIONS") or split_sections(parsed.get("REPORT", ""))
    findings = "\n".join([parsed.get("HEADLINE", ""), sections.get("summary", ""), sections.get("background", ""),
                          sections.get("analysis", ""), _before_next_steps(sections.get("conclusion", ""))])
    text = mdrender.CHART_ANYWHERE_RE.sub(" ", findings)
    web = (ev.get("web_context") or {}).get("web") or {}
    web_text = (web.get("summary") or "").lower()
    web_urls = [s["url"] for s in web.get("sources") or []]
    known = evidence_text.lower()
    outside_web = known.replace(web_text, " ") if web_text else known
    given = {"ThreatFox": _threatfox_given(ev), "Malpedia": bool((ev.get("web_context") or {}).get("malpedia"))}
    found: list[str] = []
    for sentence in _sentences(text):
        for url in URL_IN_TEXT_RE.findall(sentence):
            if url.rstrip(".,;:").lower() not in known and "a URL the case file does not hold" not in found:
                found.append("a URL the case file does not hold")
        if SOURCE_NEGATION_RE.search(sentence):
            continue
        for name, pattern in OUTSIDE_SOURCES:
            match = re.search("(?i)" + pattern, sentence)
            if not match or name in found:
                continue
            claim = match.group(0).lower()
            if claim not in known:
                found.append(name)
            elif claim not in outside_web and not any(u in sentence for u in web_urls):
                found.append(f"{name} (from WEB CONTEXT, but without its source URL)")
        for name, present in given.items():
            if not present and re.search(rf"(?i)\b{name}\b", sentence) and name not in found:
                found.append(name)
    if not found:
        return []
    return [f"The report cites sources that are not in the case file or a tool result: {', '.join(found)}. "
            "Only cite what the case file shows (the feed and its tags, the knowledge base, PUBLIC THREAT INTEL), "
            "and cite a WEB CONTEXT claim with its source URL; "
            "remove those claims or say the source was not checked."]


# --- what a figure shows --------------------------------------------------------------------

FIGURE_WORDS_RE = re.compile(r"(?i)\b(chart|figure|graph|plot|bars?)\b")
NAME_RE = re.compile(r"(?i)(?<![\w@/-])((?:[a-z0-9-]+\.)+[a-z]{2,})(?![\w-])")


def _chart_text(chart: dict) -> str:
    """Everything a chart shows in words: title, caption, series and categories."""
    words = [chart.get("title") or "", chart.get("caption") or ""]
    for series in chart.get("series") or []:
        words.append(str(series.get("name") or ""))
        words += [str(point[0]) for point in series.get("points") or []]
    return " ".join(words).lower()


def figure_problems(parsed: dict, ev: dict, custom: list[dict] | None = None) -> list[str]:
    """Sentences that say a category chart shows sites it does not show (e.g.
    naming sites for a chart of traffic by kind of use). A sentence counts if
    it holds the chart's marker, or talks about "the chart" right after a
    marker on its own line."""
    charts_by_id = {str(c["id"]): c for c in (ev.get("chart_options") or []) + list(custom or [])}
    indicator = str((ev.get("identity") or {}).get("indicator") or "").lower()
    problems: list[str] = []
    current = None
    for sentence in _sentences(mdrender.replace_flow_refs(parsed.get("REPORT", ""))):
        refs = mdrender.chart_refs(sentence)
        if refs and not mdrender.CHART_ANYWHERE_RE.sub("", sentence).strip():
            current = refs[-1]  # a marker on its own line: the next sentences describe it
            continue
        targets = refs or ([current] if current and FIGURE_WORDS_RE.search(sentence) else [])
        if not refs and not FIGURE_WORDS_RE.search(sentence):
            current = None
        for ref in targets:
            chart = charts_by_id.get(str(ref))
            if not chart or chart.get("x_type") == "time":
                continue
            shown = _chart_text(chart)
            names = [n for n in NAME_RE.findall(mdrender.CHART_ANYWHERE_RE.sub(" ", sentence))
                     if n.lower() not in shown and n.lower() != indicator]
            if names:
                categories = [str(p[0]) for p in (chart.get("series") or [{}])[0].get("points", [])][:4]
                problems.append(f"A sentence about [[chart {ref}]] names {', '.join(dict.fromkeys(names))}, but "
                                f"that {chart.get('kind', '')} chart shows {chart.get('title', '').rstrip('.')} "
                                f"({', '.join(categories)}): describe only what it shows.")
    return list(dict.fromkeys(problems))


# --- claims from long_flow_summary counts ---------------------------------------------------

# The site's own name ("UNSW hosts"), from ORG_NAME; "campus" and "university" always count.
ORG_WORD = re.escape(config.ORG_NAME.lower()) if config.ORG_NAME else "campus"
EVER_RE = re.compile(r"(?i)\b(ever|never|at any time|all[- ]time)\b")
ONLY_HOSTS_RE = re.compile(rf"(?i)\b(?:only|just|no other|no more than)\s+(\d+|one|two|three|four|five|a few|a handful "
                           rf"of)?\s*(?:other\s+)?(?:campus\s+|university\s+|{ORG_WORD}\s+)?(?:hosts?|devices?|machines?)\b")
NUMBER_WORDS = {w: n for n, w in enumerate(
    "zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen "
    "seventeen eighteen nineteen twenty".split())}
NUMBER_WORDS.update({"thirty": 30, "forty": 40, "fifty": 50})
_COUNT = r"\d+|" + "|".join(sorted(NUMBER_WORDS, key=len, reverse=True))
N_HOSTS_RE = re.compile(rf"(?i)\b({_COUNT})\s+(?:other\s+|distinct\s+)?(?:campus\s+|university\s+|{ORG_WORD}\s+)?"
                        r"(?:hosts?|devices?|machines?)\b")
SCOPE_RE = re.compile(r"(?i)over 1\s?MB|1 MB|large(?:r)? flows|long(?:er)? flows|big flows|flows over")
HOST_FLOW_WORDS_RE = re.compile(r"(?i)\b(hosts?|devices?|machines?|flows?|contacts?|connections?|visited|contacted)\b")


def _large_flow_counts(ev: dict) -> set[str]:
    counts = set()
    for peer in ev.get("peers") or []:
        for key in ("distinct_host_count", "other_host_count"):
            if peer.get(key) is not None:
                counts.add(str(peer[key]))
    return counts


def scope_problems(parsed: dict, ev: dict) -> list[str]:
    """'ever' / 'only N hosts' claims read from long_flow_summary counts
    without saying those cover only flows over 1 MB."""
    counts = _large_flow_counts(ev)
    flagged: list[str] = []
    for sentence in _sentences(parsed.get("HEADLINE", "") + "\n" + main_text(parsed)):
        if SCOPE_RE.search(sentence):
            continue
        only = ONLY_HOSTS_RE.search(sentence)
        numbers = set(re.findall(r"\b\d+\b", sentence))
        from_large_flows = bool(numbers & counts) or "long_flow_summary" in sentence
        counted = next((m for m in N_HOSTS_RE.finditer(sentence)
                        if str(NUMBER_WORDS.get(m.group(1).lower(), m.group(1))) in counts), None)
        if only and from_large_flows:
            flagged.append(only.group(0).strip())
        elif counted:
            flagged.append(counted.group(0).strip())
        elif EVER_RE.search(sentence) and HOST_FLOW_WORDS_RE.search(sentence) and from_large_flows:
            flagged.append(EVER_RE.search(sentence).group(0))
    if not flagged:
        return []
    quoted = ", ".join(f'"{claim}"' for claim in dict.fromkeys(flagged))
    return [f"The report says {quoted} from long_flow_summary counts, which cover only flows over 1 MB (and "
            "only the lookback window): say so, or drop the claim."]


# --- counting contacts -------------------------------------------------------------------

COUNT_WORDS = {"once": 1, "twice": 2, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
               "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12}
# "once" as a count, not "close it once the owner confirms" or a rate ("once per session").
TIMES_RE = re.compile(r"(?i)(?<!\bport )(?<!\bports )(?<![\d.])\b(once(?!\s+(?:the|a|an|it|they|this|that|he|she|we|you|its|their|confirmed|done|per|"
                      r"each|every|in\s+each|daily|a\s+day)\b)"
                      r"|twice|(\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)"
                      r"\s+(?:separate\s+|brief\s+|short\s+|small\s+)?(times|contacts?|connections?|visits?|bursts?|"
                      r"sessions?|episodes?))\b")
OTHER_HOSTS_RE = re.compile(rf"(?i)\b(other|campus|university|{ORG_WORD})\s+hosts\b|\bhosts\b")


def contact_count_problems(parsed: dict, ev: dict) -> list[str]:
    """Counts of the host's contacts that disagree with the case file's count
    ("twice" for 4 contacts in 2 sessions): times, contacts, connections,
    visits and bursts must be the number of contacts; sessions and episodes
    the number of sessions."""
    contacts = beacon.contact_sizes(ev.get("contact"))
    if not contacts:
        return []
    sessions = beacon.contact_sessions(ev.get("contact"), timeline.EPISODE_GAP_MIN)
    n_sessions, session_sizes = len(sessions), {s["contacts"] for s in sessions}
    wrong = []
    for sentence in _sentences(parsed.get("HEADLINE", "") + "\n" + main_text(parsed)):
        if OTHER_HOSTS_RE.search(sentence):
            continue  # about other hosts' contacts
        for m in TIMES_RE.finditer(sentence):
            word = m.group(1).lower()
            if word in ("once", "twice"):
                n, unit = COUNT_WORDS[word], "times"
            else:
                number, unit = m.group(2).lower(), m.group(3).lower()
                n = int(number) if number.isdigit() else COUNT_WORDS[number]
            # all the contacts, or the contacts of one session ("Session 4 held 5 contacts")
            about_one_session = bool(re.search(r"(?i)\b(session|episode)\b", sentence)) and unit != "times"
            want = ({n_sessions} if unit.startswith(("session", "episode"))
                    else {len(contacts)} | (session_sizes if about_one_session else set()))
            if n not in want:
                wrong.append(m.group(0))
    if not wrong:
        return []
    return [f"The report counts the contacts as {', '.join(dict.fromkeys(wrong))}, but the case file has "
            f"{len(contacts)} contact(s) in {n_sessions} session(s): count them that way."]


# --- claims flow data cannot make ---------------------------------------------------------

URL_CLAIM_RE = re.compile(
    r"(?i)\b(?:the\s+)?(?:flagged|listed|specific|exact|phishing|malicious|reported)\s+(?:url|link|page|path)\b"
    r".{0,60}?\b(?:was|were|is|has been|had been)\s+(?:not\s+|never\s+)?(?:visited|opened|accessed|clicked|loaded|"
    r"requested|reached|viewed)"
    r"|\b(?:did\s+not|didn't|never|not)\s+(?:visit|open|access|click|load|request|view)\s+(?:the\s+)?"
    r"(?:flagged|listed|specific|exact|phishing|malicious|reported)\s+(?:url|link|page|path)"
    r"|\b(?:visited|opened|accessed|clicked|loaded|requested|viewed)\s+(?:the\s+)?"
    r"(?:flagged|listed|specific|exact|phishing|malicious|reported)\s+(?:url|link|page|path)")
CANNOT_TELL_RE = re.compile(r"(?i)\b(cannot|can't|can not|could not|unable to|no way to|does not|doesn't|do not|"
                            r"don't)\s+(tell|show|prove|confirm|see|say|know|determine|reveal|establish)|\bwhether\b"
                            # a definition or a hypothetical, not a claim: '"affected" means a user visited the page'
                            r"|\bmeans\b|\bwould\b|\bif\b")


def url_claim_problems(parsed: dict) -> list[str]:
    """"The flagged URL was (not) visited": flow records hold host names, never
    the URL path, so neither can be shown. Saying it cannot be told is fine."""
    text = parsed.get("HEADLINE", "") + "\n" + parsed.get("REPORT", "")
    claims = [s for s in _sentences(text) if URL_CLAIM_RE.search(s) and not CANNOT_TELL_RE.search(s)]
    if not claims:
        return []
    return [f"The report says which URL was or was not visited (\"{claims[0].strip()[:120]}\"). Flow records show "
            "host names only, never the URL path: say the host reached the host name, and that the records cannot "
            "show which page was opened."]


POPUP_RE = re.compile(r"(?i)\bpop-?ups?\b|\bredirect(?:ed|ion|s)?\b.{0,20}\bads?\b|\bmalvertis|\bad[- ]injected\b")
HEURISTIC_RE = re.compile(r"(?i)\btypical (?:of|for) (?:a |an )?(?:student|staff|personal|university|campus)\b"
                          r"|\btypical (?:of|for) (?:a |an )?[\w-]+(?: [\w-]+)? (?:device|host|machine|server|workstation)s?\b"
                          r"|\b(?:student|staff)[- ]like\b")
AD_KINDS = ("ad network", "adult content")


def _ad_context(ev: dict) -> bool:
    """A flagged row shares an episode with an ad-network or adult-site row:
    the only evidence a pop-up or redirect ad can rest on."""
    rows = (ev.get("timeline") or {}).get("rows") or []
    flagged = {r.get("episode") for r in rows if r.get("flagged")}
    return any(r.get("episode") in flagged and r.get("kind") in AD_KINDS for r in rows)


def speculation_problems(parsed: dict, ev: dict) -> list[str]:
    """Explanations stated beyond the evidence: a pop-up or redirect ad when
    the flagged name is a known service, or nothing ad-related shares its
    episode; and made-up yardsticks such as "typical of a student device"."""
    problems = []
    text = parsed.get("HEADLINE", "") + "\n" + main_text(parsed)
    indicator = str((ev.get("identity") or {}).get("indicator") or "")
    service = knowledge.service_domain(indicator)
    popup = [s for s in _sentences(text) if POPUP_RE.search(s) and not NEGATION_RE.search(s)]
    if popup and (service or not _ad_context(ev)):
        owner = indicator if indicator == service else f"{indicator} (on {service})"
        why = (f"{owner} is a link-sharing or hosting service, not an ad" if service
               else "no ad-network or adult-site row shares an episode with the flagged contact")
        problems.append(f"The report explains the contact as a pop-up or redirect ad (\"{popup[0].strip()[:100]}\"), "
                        f"but {why}. Leave it out, or give it only as an untested possibility.")
    heuristic = [m.group(0) for m in HEURISTIC_RE.finditer(text)
                 if not re.search(r"(?i)\bnot\s+$", text[max(0, m.start() - 6):m.start()])]  # "not typical for"
    if heuristic:
        problems.append(f"The report uses a yardstick the evidence does not hold (\"{heuristic[0]}\"): say what the "
                        "traffic shows instead.")
    return problems


OUTBOUND_VERB_RE = re.compile(
    r"(?i)\bfetch(?:ing|ed|es)?\b[^.;]{0,40}\bfor\s+(?:its\s+)?(?:clients|users)\b"
    r"|\b(?:the\s+)?(?:host|machine|server|device|it|proxy|workstation)\s+(?:that\s+|which\s+)?"
    r"(?:has\s+|had\s+|was\s+)?"
    r"(?:contacted|contacts|reached|reaches|connected\s+(?:out\s+)?to|connects\s+to|fetched|fetches|accessed|"
    r"visited|requested|called\s+out\s+to|sent\s+requests\s+to|initiated)\b")


TEMP_PORTS_ON_HOST_RE = re.compile(r"(?i)\b(?:temporary|ephemeral|high)\s+ports?\b(?:(?!\b(?:to|from)\b)[^.]){0,30}\bon (?:the|this) "
                                   r"(?:campus )?host\b|\bhost['’]s (?:temporary|ephemeral) ports?\b"
                                   r"|\b(?:to|into|in to) (?:the|this) (?:campus )?host on (?:\w+ ){0,2}(?:temporary|ephemeral|high) ports?\b")


def direction_problems(parsed: dict, ev: dict) -> list[str]:
    """When the case file infers the connections were INBOUND, sentences that
    say the host contacted or reached the flagged address get it backwards."""
    if not ((ev.get("flows") or {}).get("direction") or {}).get("inbound_likely"):
        return []
    text = parsed.get("HEADLINE", "") + "\n" + main_text(parsed)
    wrong = [s.strip()[:90] for s in _sentences(text) if OUTBOUND_VERB_RE.search(s) and not NEGATION_RE.search(s)]
    ports = (((ev.get("flows") or {}).get("direction") or {}).get("ports") or [])
    port_words = "|".join(str(p) for p in ports[:20])
    if port_words:
        served = re.compile(rf"(?i)\b(?:service|server|listening|exposed|open)\b(?:(?!\bfrom\b)[^.]){{0,40}}\bport\s+(?:{port_words})\b"
                            rf"|\b(?:host|its|this host's)\s+port\s+(?:{port_words})\b"
                            rf"|\bby the host on port\s+(?:{port_words})\b"
                            rf"|\b(?:local )?services?\b(?:(?!\bfrom\b)[^.]){{0,40}}\bports?\s+(?:{port_words})\b"
                            rf"|\bservices?\s+(?:listen|listens|answer|answers|run|runs)\s+on\s+(?:tcp\s+)?(?:ports?\s+)?"
                            rf"(?:{port_words})\b"
                            rf"|\b(?:host['’]s|its)\b[^.]{{0,30}}\b(?:listening|open)\s+ports\b[^.]{{0,80}}"
                            rf"\b(?:{port_words})\b")
        wrong += [s.strip()[:90] for s in _sentences(text) if served.search(s)]
    # The remote side's temporary ports placed on the host ("reached eight temporary ports on the host").
    wrong += [s.strip()[:90] for s in _sentences(text) if TEMP_PORTS_ON_HOST_RE.search(s) and not NEGATION_RE.search(s)]
    if not wrong:
        return []
    quoted = "; ".join(f'"{s}"' for s in wrong[:3])
    return [f"The case file infers the connections were INBOUND: the flagged address connected to this host, not the "
            f"other way round, and the port shown is the remote side's temporary port, not a service on the host. "
            f"Rewrite these sentences ({len(wrong)}): {quoted}. Say the address connected to the host (and which "
            "service on it was reached, by its name), and that \"sent\" means the host's replies."]


# "unclear" said of the type, not of the user ("the user is unclear" does not count).
TYPE_UNCLEAR_RE = re.compile(r"(?i)\b(?:type|kind|classification|classified|role)\b[^.]{0,60}\b(?:unclear|uncertain|"
                             r"not clear|undetermined|unsure)\b|\b(?:unclear|uncertain)\b[^.]{0,30}\b(?:type|kind|what)\b")
HEDGE_RE = re.compile(r"(?i)\b(likely|probably|possibly|perhaps|may|might|best guess|appears|seems|suggests?|"
                      r"could|unclear|uncertain|classified as|guess)\b")
UNCLEAR_WORDS_RE = re.compile(r"(?i)\b(unclear|uncertain|not clear|cannot tell|can't tell|undetermined|unsure)\b")


def host_type_problems(parsed: dict, ev: dict) -> list[str]:
    """When the host type is unclear, the host part of the Background must say
    so (and describe the traffic) rather than name a type."""
    kind = ev.get("host_type") or {}
    if not kind.get("label") or not labels.host_type_uncertain(kind):
        return []
    sections = parsed.get("SECTIONS") or split_sections(parsed.get("REPORT", ""))
    host_part = sections.get("background", "").split("### The threat")[0]
    problems = []
    if not TYPE_UNCLEAR_RE.search(host_part) and not TYPE_UNCLEAR_RE.search(sections.get("summary", "")):
        problems.append(f"The host's type is unclear ({labels.host_type_text(kind)}), but the Background does not say "
                        "so: write that the type is unclear and describe what the traffic shows instead of naming a "
                        "type.")
    full = set(labels.HOST_TYPES.values())
    short = {n.split()[-1] for n in full} - {"host", "service"}  # "a proxy", "a gateway", "a server"
    names = "|".join(re.escape(n) for n in sorted(full | short, key=len, reverse=True))
    asserted = re.compile(rf"(?i)\b(?:host|machine|device|it)\s+(?:is|acts\s+as|serves\s+as|works\s+as|"
                          rf"operates\s+as|functions\s+as)\s+(?:a|an|the)\s+(?:{names})\b")
    text = parsed.get("HEADLINE", "") + "\n" + "\n".join(sections.get(k, "") for k in ("summary", "analysis",
                                                                                           "conclusion"))
    stated = []
    for sentence in _sentences(text):
        for m in asserted.finditer(sentence):
            near = sentence[max(0, m.start() - 30):m.end()]  # a hedge on the claim, not on the verdict
            if not HEDGE_RE.search(near):
                stated.append(sentence.strip()[:90])
    if stated:
        problems.append(f"The type is unclear, but these sentences state it as fact: \"{stated[0]}\". Say what "
                        "the traffic shows, or give the type only as a best guess.")
    return problems


TABLE_NAMES = frozenset(name for table in db.ALLOWED_TABLES for name in (table, table.split(".")[-1]))


def code_label_problems(parsed: dict, ev: dict) -> list[str]:
    """snake_case or ALL_CAPS_WITH_UNDERSCORE words in the report or headline,
    other than quoted text, domains, table names and the indicator."""
    indicator = str((ev.get("identity") or {}).get("indicator") or "").lower()
    allowed = TABLE_NAMES | {indicator}
    text = parsed.get("HEADLINE", "") + "\n" + mdrender.replace_flow_refs(parsed.get("REPORT", ""))
    found = labels.code_tokens(text, allowed)
    if not found:
        return []
    shown = ", ".join(f"{t} ({labels.PLAIN[t]})" if t in labels.PLAIN else t for t in found[:8])
    return [f"The report uses code labels: {shown}. Write them in plain words (the plain form is in brackets "
            "where there is one), as a reader on the security team would say them."]


SELF_REFERENCE_PATTERNS = (
    re.compile(r"(?i)(?<!user )(?<!user-)\bagents?\b"),
    re.compile(r"(?i)\bLLMs?\b|\blanguage model\b|\bthe model\b|\bprompt\b|\bcase file\b"),
    re.compile(r"\bSTEP\s*\d+[a-z]?\b"),  # the case file's section labels
    # "AI" only as the author ("As an AI", "AI-generated"): "AI research" is a host's activity.
    re.compile(r"\b(?:[Aa]s an|I am an|I'm an|[Tt]his) AI\b|\bAI[- ](?:generated|written|produced)\b"
               r"|\bI\b|\bI'm\b|\bI've\b|\bI'd\b|\b[Mm]y\b"),
)


def self_references(text: str) -> list[str]:
    """Words that show the text talking about itself or how it was made."""
    found: list[str] = []
    for pattern in SELF_REFERENCE_PATTERNS:
        for match in pattern.finditer(text):
            word = match.group(0)
            if word.lower() not in (w.lower() for w in found):
                found.append(word)
    return found


# --- one case -----------------------------------------------------------------------

def assess_case(identity: dict, case_rows: list[dict], asset_index: dict[str, list[dict]],
                links: dict | None = None, link_checks: dict | None = None,
                also_matched: list[str] | None = None) -> dict:
    ev = gather_evidence(identity, case_rows, asset_index)
    attach_links(ev, links, link_checks)
    ev["also_matched"] = also_matched or []
    return assess_evidence(identity, ev)


def merge_same_visits(cases: list[tuple[dict, list[dict]]], links: dict) -> tuple[list, dict[tuple, list[str]]]:
    """Drop duplicate cases (one host, one linked site, two flagged IPs) and
    return (cases to assess, {primary case: [the other indicators]})."""
    duplicates = correlation.same_visits(cases, links)
    also: dict[tuple, list[str]] = {}
    for duplicate, primary in duplicates.items():
        also.setdefault(primary, []).append(duplicate[0])
    keep = [c for c in cases if (c[0]["indicator"], c[0]["affected_asset"]) not in duplicates]
    return keep, also


def attach_links(ev: dict, links: dict | None, link_checks: dict | None) -> None:
    """Cross-case links for this case: its own names shared with other
    flagged indicators. The link itself is a report-level note; the case is
    only marked for review if its own contact with the domain is substantial."""
    ev["correlation"] = None
    if not links or not links.get("domains"):
        return
    key = (ev["identity"]["indicator"], ev["identity"]["affected_asset"])
    # Only this case's OWN names count: a case whose site name was hidden
    # (e.g. by ECH) is not linked on a guess about which site it visited.
    ev["correlation"] = correlation.for_case(links, key, link_checks)


def cross_case_links(cases: list[tuple[dict, list[dict]]]) -> tuple[dict, dict]:
    """(correlation, domain checks) for the whole feed: domains seen behind
    two or more flagged indicators, and campus checks on each."""
    links = correlation.correlate(cases)
    domains = list(links["domains"])
    identities = [identity for identity, _ in cases
                  if (identity["indicator"], identity["affected_asset"]) in links["by_case"]]
    checks = _safe("linked_domain_checks", tools.linked_domain_checks, domains, identities) if domains else {}
    if "error" in checks:
        print(f"  (campus checks on linked domains failed: {checks['error'][:120]})")
        checks = {}
    return links, checks


def assess_evidence(identity: dict, ev: dict) -> dict:
    """Have the model investigate the gathered evidence and write the report
    (eval re-runs this to check that identical evidence gives an identical
    verdict). Every case, including one with no traffic, is written by the
    model."""
    llm_client.reset_usage()
    case_file = casefile.build_case_file(ev)           # full, for reviewers and the number check
    blind_file = casefile.build_case_file(ev, blind=True)  # what the model reads: evidence, no rules' result
    ip_list = [entry["server_ip"] for entry in ev["server_ips"].get("ips", [])]
    charts: list[dict] = []
    tool_executor = partial(tools.execute, client_ip=identity["affected_asset"], server_ips=ip_list, charts=charts)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": blind_file}]
    reply_text, tool_trace, conversation = llm_client.run_agent(
        messages=messages,
        tools=tools.TOOL_SPECS,
        tool_executor=tool_executor,
    )
    reply_text, more_calls, refinement = refine_reply(conversation, reply_text, ev, case_file, tool_trace,
                                                      tool_executor, charts)
    tool_trace = tool_trace + more_calls
    result = finish_result(identity, ev, case_file, reply_text, tool_trace, charts)
    result["refinement"] = refinement
    result["prompt_tokens"] = llm_client.max_prompt_tokens
    result["usage"] = llm_client.usage_snapshot()
    if config.PROVIDER == "ollama" and llm_client.max_prompt_tokens >= CONTEXT_WARN_SHARE * config.OLLAMA_NUM_CTX:
        result["consistency_flags"].append(
            f"The prompt reached {llm_client.max_prompt_tokens:,} of {config.OLLAMA_NUM_CTX:,} context tokens; "
            "Ollama drops the start of an overflowing prompt, so raise OLLAMA_NUM_CTX.")
        result["needs_review"] = True
    return result


CONTEXT_WARN_SHARE = 0.95


# --- self-check pass ---------------------------------------------------------------

REFINE_PROMPT = """Check your report before it is final. Go through each point and fix anything wrong:
1. Every number appears in the case file or a tool result; no figures worked out in your head.
2. VERDICT and CONFIDENCE follow from the assessment in the report.
3. The Analysis weighs the benign and the malicious explanation, says which evidence decided it, and \
reads as your own reasoning about this case, not a list of fields.
4. It names any risk that remains even if this is not malware (for example a tunnel or remote-access \
tool that exposes the host).
5. The host's role rests on its uptime and other traffic, is labelled as a reading of the evidence, and \
does not guess the host's location or network.
6. It does not rely on the source's confidence: that rates the indicator, not this host.
7. It places 1-3 charts, each on its own line ([[chart name]] from READY-MADE CHARTS, or [[chart N]] for \
one you made) next to the text that explains it.
8. It has the four parts in order (Executive summary, Background, Analysis, Conclusion and next steps), \
the next steps are specific to this host, and nothing mentions an agent, a model, yourself, the case \
file or step numbers.
9. The Background has its three ### parts: The host (what it is used for, naming the kinds of use and \
main sites with their volumes, and whether a student or staff member likely uses it), The threat (why \
it matters), and What an affected host looks like. LIKELY_USER says student, staff or unclear and why.
10. The Analysis gives the times of the contacts, says what the host was doing around them from the FLOW \
TIMELINE, and cites those rows as [[flow F3]]; FLOW_NOTES has a short note for every timeline row.
{problems}
You may use the tools again, for example to check a number or fix a chart. Then reply with the complete \
answer in the same format: the header lines, FLOW_NOTES, REPORT:, and the four parts. If it already holds up, \
repeat it unchanged."""

MAX_REPORT_WORDS = 750  # well over this does not fit the PDF's one-page body
EXPOSURE_WORDS_RE = re.compile(r"(?i)expos|firewall|tunnel|remote|inbound|reach")
NEXT_STEPS_RE = re.compile(r"(?i)next step|recommend|action")
SQL_IN_TEXT_RE = re.compile(r"(?is)\bselect\b.{1,300}\bfrom\b\s+[\w.]+")


def self_check_problems(parsed: dict, ev: dict, evidence_text: str, charts: list[dict] | None = None) -> list[str]:
    """Problems code can find in a reply without revealing the rules' verdict
    (the review must stay blind). `charts` are the model's own (add_chart)."""
    problems: list[str] = []
    full_text = parsed.get("REPORT", "")
    report_text = main_text(parsed)  # the Background describes the threat in general
    if not parsed.get("verdict_given"):
        problems.append("The VERDICT line is missing or not one of the three allowed values.")
    if len(full_text) < MIN_REPORT_CHARS:
        problems.append("The report is missing or far too short: write the full report after REPORT:.")
    sections = parsed.get("SECTIONS") or split_sections(full_text)
    missing = [SECTION_TITLES[k] for k in SECTION_TITLES if not sections.get(k)]
    if full_text and missing:
        problems.append(f"The report is missing these parts: {', '.join(missing)}. Use the four ## headings.")
    if SQL_IN_TEXT_RE.search(full_text):
        problems.append("The report contains SQL. Leave queries out of the text; place charts with [[chart name]].")
    numbers = unverified_numbers(parsed, evidence_text, beacon.contact_sizes(ev.get("contact")))
    if numbers:
        problems.append(f"These numbers are not in the case file or tool results: {', '.join(numbers)}. "
                        "Correct them, query them, or remove them.")
    problems += contact_claim_problems(parsed, ev)
    verdict = parsed.get("VERDICT")
    if verdict in ("SUSPICIOUS", "LIKELY_THREAT") and _affirmed_mismatch(parsed.get("HEADLINE", "")):
        problems.append(f"Your headline says the traffic does not match the threat, yet your verdict is {verdict}.")
    exfil = ev.get("flows", {}).get("upload_heavy_over_exfil_threshold", {"count": 0})
    if _affirmed(EXFIL_RE, report_text) and not exfil.get("count"):
        problems.append("The report mentions exfiltration, but no flow is over the exfiltration threshold.")
    shared = next((s for s in ev.get("signals", []) if s["name"] == "shared_infrastructure"), None)
    if (ev.get("shared") or {}).get("likely_shared") is not True and _affirmed(SHARED_RE, report_text) \
            and not NOT_SHARED_RE.search(report_text):
        problems.append("The report calls the flagged address shared infrastructure, but the case file's shared-"
                        "infrastructure check does not say it is shared: say what the ASN is, without calling it "
                        "shared.")
    if shared and shared["direction"] == signals.AGAINST and NOT_SHARED_RE.search(report_text):
        problems.append(f"The report says the IP is not shared, but the case file shows it is: {shared['reason']}")
    if verdict in ("SUSPICIOUS", "LIKELY_THREAT") and _cites_source_confidence(report_text):
        problems.append("The report brings up the source's confidence: make sure it is not part of the reasoning, "
                        "as it rates the indicator, not this host.")
    service = ev.get("expected", {}).get("service")
    remote = (ev.get("app_context") or {}).get("remote_access_app")
    if (service or remote) and not EXPOSURE_WORDS_RE.search(report_text):
        name = service["profile"]["name"] if service else remote
        problems.append(f"The case file shows {name}; say what risk remains from it even if it is not malware.")
    words = self_references(full_text + "\n" + parsed.get("HEADLINE", ""))
    if words:
        problems.append(f"The report refers to itself or how it was made ({', '.join(words)}). Rewrite those "
                        "parts as the security team's own analysis.")
    problems += code_label_problems(parsed, ev)
    problems += source_problems(parsed, ev, evidence_text)
    problems += contact_count_problems(parsed, ev)
    problems += time_format_problems(sections, ev)
    problems += time_of_day_problems(sections, ev)
    problems += direction_problems(parsed, ev)
    problems += url_claim_problems(parsed)
    problems += speculation_problems(parsed, ev)
    problems += host_type_problems(parsed, ev)
    problems += figure_problems(parsed, ev, charts)
    problems += scope_problems(parsed, ev)
    conclusion = sections.get("conclusion", "")
    if full_text and not (re.search(r"(?m)^\s*(\d+[.)]|[-*])\s", conclusion) or NEXT_STEPS_RE.search(conclusion)):
        problems.append("The Conclusion and next steps part has no next steps.")
    words = len(re.findall(r"\w+", mdrender.CHART_ANYWHERE_RE.sub("", full_text)))
    if words > MAX_REPORT_WORDS:
        problems.append(f"The report is {words} words; keep the four parts to about 450 words so they fit on one "
                        "page. Cut repetition and detail the figures and flow table already carry.")
    problems += _chart_problems(full_text, charts or [], ev.get("chart_options") or [])
    problems += _structure_problems(sections, full_text, has_traffic=not _no_traffic(ev))
    problems += flow_problems(parsed, ev)
    problems += usage_problems(parsed, ev)
    role = parsed.get("HOST_ROLE", "")
    if role and host_type.role_problem(role, ev):
        words = host_type.unsupported_role_words(role, ev)
        named = f" (the evidence does not show: {', '.join(words)})" if words else ""
        problems.append(f"Your HOST_ROLE is not supported by the evidence{named}: base it on the uptime and the app "
                        "and domain evidence, or say the role is unclear.")
    return problems


def _chart_problems(report_text: str, custom: list[dict], options: list[dict]) -> list[str]:
    available = [c["id"] for c in options] + [c["id"] for c in custom]
    placed = mdrender.chart_refs(report_text)
    problems = []
    if not placed:
        menu = (f"from READY-MADE CHARTS ({', '.join(c['id'] for c in options)}) " if options else "")
        problems.append(f"The report has no charts: place 1-3 {menu}on their own lines as [[chart name]], or make "
                        "your own with add_chart.")
    unknown = [n for n in placed if n not in available]
    if unknown:
        problems.append(f"[[chart {unknown[0]}]] is not a chart. Available: {', '.join(available) or 'none'}.")
    if len(set(placed)) > config.MAX_CHARTS:
        problems.append(f"Place at most {config.MAX_CHARTS} charts; only the first {config.MAX_CHARTS} are shown.")
    unplaced = [c["id"] for c in custom if c["id"] not in placed]
    if unplaced:
        problems.append(f"You made chart(s) {', '.join(unplaced)} but did not place them: place them with "
                        "[[chart N]] or leave them out on purpose.")
    return problems


CHART_COPY_RE = re.compile(r"\((?:line|bar)\):")
# "18:25 local", "(local time)", "18:25 (local)": "local" used as a time zone.
LOCAL_ZONE_RE = re.compile(r"(?i)\d{1,2}:\d{2}(?::\d{2})?\s*\(?\s*local\b|\blocal time\b|\(\s*local\s*\)")
TIME_RE = re.compile(r"\b\d{1,2}:\d{2}\b")
BACKGROUND_PARTS = 3


def _structure_problems(sections: dict, full_text: str, has_traffic: bool) -> list[str]:
    problems = []
    background = sections.get("background", "")
    if background and len(re.findall(r"(?m)^\s*###\s", background)) < BACKGROUND_PARTS:
        problems.append("The Background needs its three ### parts: The host (including what kind of device it "
                        "likely is, from its activity), The threat, and What an affected host looks like.")
    if LOCAL_ZONE_RE.search(full_text):
        problems.append('The report writes "local" as a time zone: write the zone the case file gives '
                        '(e.g. AEDT or AEST), e.g. "04:34 UTC (15:34 AEDT)".')
    if CHART_COPY_RE.search(full_text):
        problems.append("The report copies chart description lines from READY-MADE CHARTS: place only the "
                        "[[chart name]] marker and say in your own words what the chart shows.")
    if has_traffic and sections.get("analysis") and not TIME_RE.search(sections["analysis"]):
        problems.append(f"The Analysis gives no times: say when the contacts happened (UTC, with {config.LOCAL_CITY} time) and "
                        "what the host was doing then.")
    return problems


HHMM_RE = re.compile(r"\b\d{1,2}:\d{2}\b")
ZONE_ABBREV_RE = re.compile(r"\b(?!UTC\b)[A-Z]{2,4}T\b")  # AEDT, AEST, CEST ...
DATE_WORDS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
                           r"|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2}\b")


NIGHT_WORDS_RE = re.compile(r"(?i)\b(overnight|at night|night[- ]time|late at night|after midnight|small hours|"
                            r"early[- ]morning hours)\b")


def time_of_day_problems(sections: dict, ev: dict) -> list[str]:
    """"Overnight" or "at night" when no contact fell between 22:00 and 06:00 local time."""
    if config.LOCAL_TIMEZONE == "UTC":
        return []
    hours = []
    for c in beacon.contact_sizes(ev.get("contact")):
        local = config.to_local(c["start"])
        if local:
            hours.append(int(local[11:13]))
    text = "\n".join(sections.get(k, "") for k in ("summary", "analysis", "conclusion"))
    said = [s for s in _sentences(text) if NIGHT_WORDS_RE.search(s) and not NEGATION_RE.search(s)]
    if hours and said and not any(h >= 22 or h < 6 for h in hours):
        shown = ", ".join(f"{h:02d}h" for h in sorted(set(hours))[:6])
        return [f"The report places the contact at night (\"{said[0].strip()[:80]}\"), but every contact was in "
                f"the day, {config.LOCAL_CITY} time ({shown}): describe the time of day as it was."]
    return []


def time_format_problems(sections: dict, ev: dict) -> list[str]:
    """UTC times with no local time beside them, and times with no date when
    the contacts fall on more than one day."""
    if config.LOCAL_TIMEZONE == "UTC":
        return []
    days = {c["start"][:10] for c in beacon.contact_sizes(ev.get("contact"))}
    no_zone, no_date = [], []
    for key in ("summary", "analysis", "conclusion"):
        for sentence in _sentences(mdrender.replace_flow_refs(sections.get(key, ""))):
            if not HHMM_RE.search(sentence):
                continue
            if "UTC" in sentence and not ZONE_ABBREV_RE.search(sentence):
                no_zone.append(sentence.strip()[:80])
            if len(days) > 1 and not DATE_WORDS_RE.search(sentence):
                no_date.append(sentence.strip()[:80])
    problems = []
    if no_zone:
        quoted = "; ".join(f'"{s}"' for s in no_zone[:4])
        problems.append(f"Every UTC time needs the {config.LOCAL_CITY} time beside it, as the case file gives it "
                        f"(e.g. \"04:34 UTC (15:34 AEDT)\"). Missing in {len(no_zone)} sentence(s): {quoted}.")
    if no_date:
        quoted = "; ".join(f'"{s}"' for s in no_date[:4])
        problems.append(f"The contacts fall on {len(days)} days, so every time needs its date. Missing in "
                        f"{len(no_date)} sentence(s): {quoted}.")
    return problems


def usage_problems(parsed: dict, ev: dict) -> list[str]:
    """The report must say what the host is used for and who likely uses it."""
    problems = []
    user = parsed.get("LIKELY_USER", "")
    if not host_type.user_type(user):
        problems.append("LIKELY_USER is missing: give student, staff or unclear, then the activity that points "
                        "there (see WHAT THE HOST IS USED FOR).")
    elif host_type.user_problem(user, ev):
        problems.append(f"LIKELY_USER says {host_type.user_type(user)}, but WHAT THE HOST IS USED FOR shows no "
                        "activity of that kind: base it on that section or say unclear.")
    categories = (((ev.get("other_traffic") or {}).get("activity_profile") or {}).get("categories") or [])[:2]
    names = [c["category"] for c in categories] + [site["domain"] for c in categories for site in c["sites"]]
    background = (parsed.get("SECTIONS") or {}).get("background", "").lower()
    if names and background and not any(name.lower() in background for name in names):
        top = categories[0]
        problems.append(f"The host part of the Background does not say what the host is used for: name the kinds "
                        f"of use and main sites from WHAT THE HOST IS USED FOR (e.g. {top['category']}: "
                        f"{', '.join(site['domain'] for site in top['sites'][:2])}) and what they say about who "
                        "uses it.")
    return problems


PLAIN_ROW_RE = re.compile(r"\bF(\d{1,3})(?:\s*[-\u2013]\s*F?(\d{1,3}))?\b")


def plain_row_refs(report_text: str) -> list[str]:
    """Flow rows named in plain text ("F4-F6", "(F7)"), outside [[flow ...]] markers."""
    text = mdrender.FLOW_REF_RE.sub(" ", report_text)
    rows = []
    for m in PLAIN_ROW_RE.finditer(text):
        first = int(m.group(1))
        last = int(m.group(2)) if m.group(2) else first
        rows += [f"F{n}" for n in range(first, min(last, first + 50) + 1)]
    return rows


def flow_problems(parsed: dict, ev: dict) -> list[str]:
    """Flow timeline rows the report cites that do not exist, no citations at
    all, and rows with no note in FLOW_NOTES."""
    ids = timeline.row_ids(ev.get("timeline"))
    cited = mdrender.flow_refs(parsed.get("REPORT", ""))
    unknown = [i for i in dict.fromkeys(cited + plain_row_refs(parsed.get("REPORT", ""))) if i not in ids]
    problems = []
    if unknown:
        rows = f"rows {ids[0]}-{ids[-1]}" if ids else "no rows"
        problems.append(f"Rows {', '.join(unknown[:8])} are cited but are not in the FLOW TIMELINE ({rows}): cite "
                        "only rows that exist.")
    if not ids:
        return problems
    if not cited:
        problems.append("The Analysis cites no FLOW TIMELINE rows: say what the host was doing around the contact "
                        "and cite the rows as [[flow F3]].")
    notes = parsed.get("flow_notes") or {}
    missing = [i for i in ids if i not in notes]
    if missing:
        shown = ", ".join(missing[:15]) + (" and more" if len(missing) > 15 else "")
        problems.append(f"FLOW_NOTES has no note for {shown}: give every timeline row a few words on what the "
                        "connection most likely is.")
    return problems


DEFAULT_CHARTS = ("contact", "host_load", "sites_on_ip", "campus_hosts")


def select_charts(parsed: dict, custom: list[dict], options: list[dict]) -> list[dict]:
    """The charts the report shows, in the order it places them (at most
    MAX_CHARTS). If it places none, the most telling ready-made one is added
    at the end of the Analysis, so every written report has a chart."""
    available = {c["id"]: c for c in options + custom}
    sections = parsed["SECTIONS"]
    order = [key for key in ("summary", "analysis", "conclusion", "background")]
    placed = [n for key in order for n in mdrender.chart_refs(sections.get(key, ""))]
    chosen = [available[n] for n in dict.fromkeys(placed) if n in available][: config.MAX_CHARTS]
    if chosen or not options:
        return chosen
    candidates = [available[n] for n in DEFAULT_CHARTS if n in available]
    contact = available.get("contact")
    if contact and sum(len(s["points"]) for s in contact["series"]) < 6 and len(candidates) > 1:
        candidates.remove(contact)  # a minute or two of contact says little drawn as a chart
    default = candidates[0] if candidates else options[0]
    sections["analysis"] = (sections.get("analysis", "").rstrip() + f"\n\n[[chart {default['id']}]]").strip()
    return [default]


def refine_reply(conversation: list[dict], reply_text: str, ev: dict, case_file: str, tool_trace: list[dict],
                 tool_executor, charts: list[dict]) -> tuple[str, list[dict], dict]:
    """Give the model its report back with a checklist and any problems code
    found; it may use the tools again. Keep the corrected reply if it is a
    complete answer. Returns (final reply, tool calls made here, record)."""
    record = {"rounds": 0, "problems": [], "first_reply": reply_text, "changed": False}
    calls: list[dict] = []
    for _ in range(max(config.MODEL_REFINE_ROUNDS, 0)):
        evidence_text = case_file + json.dumps(tool_trace + calls, default=str)
        problems = self_check_problems(parse_reply(reply_text), ev, evidence_text, charts)
        if record["rounds"] and not problems:
            break  # the checklist round is done and code finds nothing more to fix
        listed = ("\nProblems found automatically in your answer:\n" + "\n".join(f"- {p}" for p in problems)
                  if problems else "")
        prompt = {"role": "user", "content": REFINE_PROMPT.format(problems=listed)}
        revised, more, revised_conversation = llm_client.run_agent(
            conversation + [prompt], tools=tools.TOOL_SPECS, tool_executor=tool_executor,
            max_rounds=config.REFINE_TOOL_ROUNDS, reset_prompt_count=False)
        record["rounds"] += 1
        record["problems"].extend(problems)
        calls += more
        if not report_usable(parse_reply(revised)):
            break  # incomplete rewrite: keep the previous answer
        record["changed"] = record["changed"] or _comparable(revised) != _comparable(reply_text)
        reply_text, conversation = revised, revised_conversation
    record["first_verdict"] = parse_reply(record["first_reply"])["VERDICT"]
    return reply_text, calls, record


def _comparable(reply: str) -> dict:
    return {k: v for k, v in parse_reply(reply).items() if k != "verdict_given"}


def finish_result(identity: dict, ev: dict, case_file: str, reply_text: str, tool_trace: list[dict],
                  charts: list[dict] | None = None) -> dict:
    """Parse the reply and apply every code check (split out for tests). The
    report is always the model's own text; code only checks it and sets the
    two verdicts it owns (no traffic, no verdict given)."""
    parsed = reconcile_verdict(parse_reply(reply_text), ev["baseline"])
    if _no_traffic(ev):
        parsed["VERDICT"], parsed["CONFIDENCE"] = "INSUFFICIENT_DATA", "high"
    if not parsed["REPORT"].strip() and reply_text.strip():
        parsed["REPORT"] = reply_text.strip()  # no recognisable format: show what was written
        parsed["SECTIONS"] = split_sections(parsed["REPORT"])
    evidence_text = case_file + json.dumps(tool_trace, default=str)
    numbers = unverified_numbers(parsed, evidence_text, beacon.contact_sizes(ev.get("contact")))
    flags = consistency_flags(parsed, ev) + contact_claim_problems(parsed, ev)
    remaining = self_check_problems(parsed, ev, evidence_text, charts) if parsed["REPORT"] else []
    ids = set(timeline.row_ids(ev.get("timeline")))
    unknown_rows = [i for i in dict.fromkeys(mdrender.flow_refs(parsed["REPORT"])) if i not in ids]
    if unknown_rows:
        flags.append(f"The report cites flow rows that are not in the timeline: {', '.join(unknown_rows)}.")
    if numbers:
        flags.append(f"Numbers not found in the evidence: {', '.join(numbers)}.")
    links = ev.get("correlation")
    substantial = signals.substantial_contact(ev) if links else None
    if substantial:
        domains = ", ".join(d["domain"] for d in links["domains"])
        parsed["verdict_notes"].append(
            f"{domains} is behind other flagged indicators in this feed, and this host's own contact with it is "
            f"more than one visit: {substantial}.")
        if parsed["CONFIDENCE"] == "high":
            parsed["CONFIDENCE"] = "medium"  # a possible real indicator with real contact: not a confident clear
    disagrees = (parsed["VERDICT"] != "INSUFFICIENT_DATA" and parsed.get("verdict_given")
                 and parsed["model_verdict"] != parsed["baseline_verdict"])
    review = (bool(flags) or bool(substantial) or bool(disagrees) or parsed["report_source"] != "analysis"
              or not parsed.get("verdict_given"))
    result = {
        **identity,
        "evidence": ev,
        "case_file": case_file,
        "tool_calls": tool_trace,
        "model_reply_raw": reply_text,
        **parsed,
        "charts": select_charts(parsed, charts or [], ev.get("chart_options") or []) if parsed["REPORT"] else [],
        "unverified_numbers": numbers,
        "consistency_flags": flags,
        "remaining_problems": remaining,  # self-check problems still in the final reply
        "needs_review": review,
    }
    if "behaviour" not in ev:  # evidence saved before behaviour categories existed
        ev["behaviour"] = behaviour.classify(ev)
    result["behaviour"] = ev["behaviour"]
    return result


def _error_result(identity: dict, exc: Exception) -> dict:
    result = {**identity, "evidence": None, "case_file": "", "tool_calls": [], "model_reply_raw": "", "charts": []}
    result.update({field: "" for field in FIELDS})
    result.update({"VERDICT": "ERROR", "HEADLINE": f"Assessment failed: {exc}", "unverified_numbers": [],
                   "consistency_flags": [], "needs_review": True, "report_source": "incomplete",
                   "SECTIONS": {"summary": f"Assessment failed: {exc}"}})
    return result


# --- batch run ----------------------------------------------------------------------

def load_cases(input_path: Path) -> tuple[list[tuple[dict, list[dict]]], dict[str, list[dict]], int]:
    """(cases, asset_index, raw match count): one (identity, rows) per
    (indicator, host), highest source confidence (none counts as 0) and most matches first."""
    matches = evidence.load_matches(input_path)
    ioc_metadata = evidence.load_ioc_metadata()
    groups = evidence.group_matches(matches)
    asset_index = evidence.asset_ioc_index(matches)
    cases = [(evidence.case_identity(key, rows, ioc_metadata), rows) for key, rows in groups.items()]
    cases.sort(key=lambda c: (-(c[0].get("intel_confidence") or 0), -c[0]["n_events"]))
    return cases, asset_index, len(matches)


DEFAULT_FEEDS = (HERE / "data" / "ioc_matches.jsonl", HERE / "data" / "ioc_matches.json")


def feed_path(positional: Path | None, option: Path | None) -> Path:
    """The feed to read: given by name (positional or --input), else the
    first default feed in data/ that exists."""
    if positional and option and positional != option:
        raise SystemExit(f"Two different feeds given: {positional} and --input {option}. Give one.")
    chosen = positional or option
    if chosen:
        return chosen
    return next((p for p in DEFAULT_FEEDS if p.exists()), DEFAULT_FEEDS[0])


USAGE_KEYS = ("calls", "prompt_tokens", "completion_tokens", "cached_tokens", "web_searches", "cost_usd")


def skipped_line(feed_summary: dict) -> str:
    """The run summary's line on indicators the feed build skipped ("" if none)."""
    skipped = feed_summary.get("skipped_known_service") or []
    if not skipped:
        return ""
    return (f"{len(skipped)} indicator(s) skipped as known services (bare link-sharing or hosting domains): "
            + ", ".join(skipped[:10]) + (" ..." if len(skipped) > 10 else ""))


def read_feed_summary(path: Path) -> dict:
    """The feed-build summary saved in an assessments.json ({} if none)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return (data.get("feed") or {}) if isinstance(data, dict) else {}


def read_results(path: Path) -> list[dict]:
    """The results in an assessments.json: {"usage", "results"}, or a plain
    list (files written before usage totals were added)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["results"] if isinstance(data, dict) else data


def usage_totals(results: list[dict]) -> dict:
    """Model calls, tokens and estimated cost over every result that has them."""
    totals = {key: 0 for key in USAGE_KEYS}
    for r in results:
        for key in USAGE_KEYS:
            totals[key] += (r.get("usage") or {}).get(key) or 0
    totals["cost_usd"] = round(totals["cost_usd"], 6)
    totals["cases"] = len(results)
    totals["model"] = f"{config.PROVIDER}:{config.model()}"
    return totals


def over_budget(spent: float) -> bool:
    return config.MAX_RUN_COST_USD is not None and spent >= config.MAX_RUN_COST_USD


def usage_line(used: dict, run_cost: float) -> str:
    line = (f"tokens: {used['prompt_tokens']:,} in ({used['cached_tokens']:,} cached), "
            f"{used['completion_tokens']:,} out, {used['calls']} call(s)")
    if used.get("web_searches"):
        line += f", {used['web_searches']} web search(es)"
    if used["cost_usd"] or run_cost:
        line += f"; cost ${used['cost_usd']:.4f}, run ${run_cost:.4f}"
    return line


def totals_line(totals: dict) -> str:
    """The run summary's usage line: model, tokens, searches and cost over all cases."""
    cost = f"${totals['cost_usd']:.4f}" if totals["cost_usd"] else "no cost"
    return (f"Usage over {totals['cases']} case(s) with {totals['model']}: {totals['prompt_tokens']:,} tokens in "
            f"({totals['cached_tokens']:,} cached), {totals['completion_tokens']:,} out, {totals['calls']} call(s), "
            f"{totals['web_searches']} web search(es), {cost}.")


def write_pdf(result: dict, cases_dir: Path, reports_dir: Path) -> Path | None:
    """The case's LaTeX report and chart PDFs, built in cases_dir and compiled
    (if a TeX engine is installed) to reports_dir/<indicator>-<host>.pdf. A
    failure here never fails the case."""
    try:
        pdf = latex.build_case_pdf(result, cases_dir, reports_dir)
    except Exception as exc:  # noqa: BLE001 - the HTML and Markdown reports are already written
        print(f"  warning: LaTeX report not written: {exc}")
        return None
    if pdf:
        print(f"  PDF: {pdf}")
    return pdf


def write_summary_pdf(results: list[dict], cases_dir: Path, reports_dir: Path) -> Path | None:
    tex, pdf = latex.build_summary_pdf(results, cases_dir, reports_dir)
    print(f"Wrote the batch summary to {pdf or tex}")
    return pdf


def main() -> None:
    parser = argparse.ArgumentParser(description="Investigate IOC matches with flow data and an LLM agent.")
    parser.add_argument("feed", type=Path, nargs="?", default=None,
                        help="IOC-match feed: a JSON list or JSON Lines (.jsonl). "
                             "Default: data/ioc_matches.jsonl, else data/ioc_matches.json")
    parser.add_argument("--input", type=Path, default=None, help="same as the positional feed argument")
    parser.add_argument("--output-dir", type=Path, default=HERE / "output")
    parser.add_argument("--limit", type=int, default=None, help="only assess the first N new cases")
    parser.add_argument("--indicator", type=str, default=None,
                        help="only assess cases for this exact indicator, e.g. 'bore.pub'")
    parser.add_argument("--pause", type=float, default=REQUEST_PAUSE_SEC,
                        help="seconds to wait between cases (for rate-limited providers)")
    parser.add_argument("--resume", action="store_true",
                        help="keep cases that already succeeded in the output and only assess the rest")
    parser.add_argument("--pdf", action="store_true",
                        help="also compile PDF reports into output/reports/ (<indicator>-<host>.pdf and "
                             "summary-<date>.pdf; LaTeX build files stay in output/cases/) "
                             "with latexmk or tectonic")
    args = parser.parse_args()
    args.input = feed_path(args.feed, args.input)

    if not args.input.exists():
        raise SystemExit(f"{args.input} not found")
    config.clickhouse_settings()  # fail now, with a clear message, if .env is missing

    cases, asset_index, match_count = load_cases(args.input)
    feed_summary = matcher.read_summary(args.input)
    total_cases = len(cases)
    links, link_checks = cross_case_links(cases)
    for domain, info in links["domains"].items():
        print(f"Linked domain: {domain} is behind {len(info['indicators'])} flagged indicators "
              f"({', '.join(info['indicators'])}); noted in the report.")
    cases, also_matched = merge_same_visits(cases, links)
    for primary, others in also_matched.items():
        print(f"Same visit: {primary[0]} and {', '.join(others)} for {primary[1]} are reported as one case.")
    if args.indicator:
        cases = [c for c in cases if c[0]["indicator"] == args.indicator]

    args.output_dir.mkdir(parents=True, exist_ok=True)
    cases_dir = args.output_dir / "cases"
    cases_dir.mkdir(exist_ok=True)
    reports_dir = args.output_dir / "reports"  # finished PDFs only
    assessments_path = args.output_dir / "assessments.json"
    report_path = args.output_dir / "report.html"

    results = []
    if args.resume and assessments_path.exists():
        previous = read_results(assessments_path)
        done_keys = set()
        for r in previous:
            if r.get("VERDICT") != "ERROR":
                results.append(r)
                done_keys.add((r["indicator"], r["affected_asset"]))
        cases = [c for c in cases if (c[0]["indicator"], c[0]["affected_asset"]) not in done_keys]
        print(f"--resume: keeping {len(results)} assessed case(s), {len(cases)} remaining.")

    if args.limit:
        cases = cases[: args.limit]

    print(f"{match_count} raw match(es) grouped into {total_cases} indicator+host case(s); "
          f"assessing {len(cases)}.")

    def flush() -> None:
        # Write after every case so an error or Ctrl-C keeps what already finished.
        saved = {"usage": usage_totals(results), "feed": feed_summary, "results": results}
        assessments_path.write_text(json.dumps(saved, indent=2, default=str), encoding="utf-8")
        report_path.write_text(report.render(results), encoding="utf-8")

    run_cost = 0.0
    for i, (identity, case_rows) in enumerate(cases):
        if over_budget(run_cost):
            print(f"\nEstimated spend ${run_cost:.2f} reached MAX_RUN_COST_USD (${config.MAX_RUN_COST_USD:.2f}). "
                  f"Stopping after {i} case(s); raise the limit and run again with --resume.")
            break
        print(f"\n[{i + 1}/{len(cases)}] {identity['indicator']} <-> {identity['affected_asset']}")
        llm_client.reset_usage()
        try:
            key = (identity["indicator"], identity["affected_asset"])
            result = assess_case(identity, case_rows, asset_index, links, link_checks, also_matched.get(key))
            tool_note = f", {len(result['tool_calls'])} tool call(s)" if result["tool_calls"] else ""
            review = " [REVIEW]" if result["needs_review"] else ""
            charts_note = f", {len(result['charts'])} chart(s)" if result.get("charts") else ""
            print(f"  verdict={result['VERDICT']} (rule-based cross-check: {result['baseline_verdict']}) "
                  f"confidence={result['CONFIDENCE']}{tool_note}{charts_note}{review}")
            report.write_case_files(result, cases_dir)
            if args.pdf:
                write_pdf(result, cases_dir, reports_dir)
        except llm_client.DailyQuotaExceeded as exc:
            print(f"\n{exc}\nStopping after {i} case(s). Run again with --resume once that is fixed.")
            break
        except Exception as exc:  # noqa: BLE001 - one bad case shouldn't stop the batch
            print(f"  FAILED: {exc}")
            result = _error_result(identity, exc)
        result["usage"] = llm_client.usage_snapshot()
        run_cost += result["usage"]["cost_usd"]
        print(f"  {usage_line(result['usage'], run_cost)}")
        results.append(result)
        flush()
        if i < len(cases) - 1:
            time.sleep(args.pause)

    flush()
    if args.pdf and results:
        write_summary_pdf(results, cases_dir, reports_dir)
    if skipped_line(feed_summary):
        print(skipped_line(feed_summary))
    print("\n" + totals_line(usage_totals(results)))
    print(f"Wrote {len(results)} assessment(s) to {assessments_path}")
    print(f"Wrote report to {report_path} and per-case Markdown to {cases_dir}/")


if __name__ == "__main__":
    main()

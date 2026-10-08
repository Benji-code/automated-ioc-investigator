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
"""
from __future__ import annotations

import argparse
import json
import re
import time
from functools import partial
from pathlib import Path

from agent import (behaviour, casefile, charts, config, correlation, db, evidence, host_type, llm_client,
                   mdrender, report, signals, tools)

HERE = Path(__file__).resolve().parent
# Local Ollama has no rate limit; OpenRouter's free tier does.
REQUEST_PAUSE_SEC = 0.0 if config.PROVIDER == "ollama" else 6.0


def _site_section() -> str:
    """Site context for the system prompt: local time zone and free-text notes."""
    lines = []
    if config.LOCAL_TIMEZONE != "UTC":
        lines.append(
            f"- Local time zone: {config.LOCAL_TIMEZONE}. All data timestamps are UTC; the case "
            "file adds local times in [local: ...]. Use the local times (and weekday) when judging "
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
{config.HOST_LABEL} that contacted an indicator listed on ThreatFox. You investigate the case \
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
- Evidence marked "from the IOC feed, not re-queried" is the feed's own copy \
of the matched rows: real, but only the matched minutes.
- The evidence first/last seen times are the matched flow's own times, not \
ThreatFox's dates. Only reason about ThreatFox dates if the case file gives them.
- If the case file shows no traffic between the host and the flagged IP, say \
so plainly and do not describe traffic that is not there; explain what was \
checked and what that means. Such a case is recorded as insufficient data \
whatever verdict you give.
- HOST TYPE says what kind of machine the host is (from its own traffic, with \
a confidence) and how it compares with typical hosts of that type. Use it: \
the same contact means different things from a workstation, a server or a NAT \
gateway, and behaviour that is unusual for the type is worth explaining. A \
low-confidence type is a hint, not a fact; say so if you rely on it. A NAT \
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
- ThreatFox confidence says how sure the reporter is that the INDICATOR is \
malicious. It says nothing about whether THIS HOST is infected. Never use it \
to move a verdict to SUSPICIOUS or LIKELY_THREAT.
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
belongs, as written there, e.g. [[chart host_load]]. Then say in the text what \
the reader should see in it. If none of them shows what matters, make your own \
with the add_chart tool and place it as [[chart N]] with the number it returns. \
Never write SQL or chart instructions in the report itself.

Writing the report:
The readers are analysts in {TEAM_LABEL} deciding what to do with this alert. \
Write it the way a senior analyst briefs a colleague: in your own words, as \
connected reasoning about this particular case, not a form filled in. Explain \
what happened, what it means and how you know. Be specific: exact times (UTC, \
with the local time where time of day matters), names, ports, volumes and \
counts; how the contact compares with the host's own normal traffic and with \
other campus hosts; and what each fact means for the verdict. Prefer short \
paragraphs. Use a list only for things that are truly parallel, such as next \
steps, and a small table only to compare several values. Do not write \
"Label: value" lines, do not repeat a fact in several places, and leave out \
anything that does not bear on this case.

The report has exactly these four parts, as ## headings, in this order:

## Executive summary
Three to five sentences for a reader who reads nothing else: which host \
contacted what and when, what the traffic actually was, your verdict and the \
main reason, and the one thing to do now.

## Analysis
The investigation itself: what the flow data shows and what your own queries \
added; how the host's behaviour compares with typical hosts of its type; the \
evidence for and against compromise, weighing the benign \
explanation (shared infrastructure, a known service's normal client, an app \
label, a popular destination) against the malicious one; which evidence \
decides it; and anything that does not fit. Place your charts here. Use ### \
subheadings only if the analysis covers several distinct strands.

## Conclusion and next steps
The verdict, how confident you are and why; any risk that remains even if this \
is not the flagged malware; what the evidence cannot show for this case; then \
numbered next steps specific to this host (who to contact, what to check, what \
to alert on), most important first.

## Background
Reference for a reader new to the case, shown folded away, so the three parts \
above must stand on their own. Cover what the host appears to be (its \
classified type and how sure that is, operating system, uptime and usual \
traffic, and what normal looks like for that type; a reading of the evidence, \
not a fact, and no guess at where it is or which network it is on unless the \
host name plainly says so); what the threat is (the malware family and threat \
type, how it usually arrives and what it does); what a compromised host would \
look like in flow data; and what the flagged address is (its owner, and \
whether it is shared).

Length: a simple case about 400-600 words in all; a complex one up to about 1,200.

Rules for the report text:
- Every number must appear in the case file or a tool result (the ready-made \
charts' values count). Do not work out new figures such as percentages, sums or \
rates in your head: if you need one, query it.
- Write as the security team's own analysis. Never mention an agent, a model, AI, \
a prompt, the case file or its step numbers, or yourself ("I", "my"). Name data \
by what it is, e.g. "per-minute flow records".
- No title: the page already shows the indicator and the host above the report.

Reply in exactly this format: four header lines, then REPORT: on its own line, \
then the four parts.

VERDICT: <LIKELY_THREAT | SUSPICIOUS | LIKELY_FALSE_POSITIVE>
CONFIDENCE: <low | medium | high>
HOST_ROLE: <one hedged sentence: what the machine probably is, based first on its \
uptime and other traffic>
HEADLINE: <one sentence for the case list: what happened and your assessment>
REPORT:
## Executive summary
...
## Analysis
...
## Conclusion and next steps
...
## Background
...

VERDICT meanings: LIKELY_THREAT = evidence supports escalation; SUSPICIOUS = \
mixed or incomplete, needs a manual look; LIKELY_FALSE_POSITIVE = the traffic \
does not match the threat (shared infrastructure, a known service's normal \
client, or a shape that doesn't fit), even if some other risk remains.
"""

HEADER_FIELDS = ["VERDICT", "CONFIDENCE", "HOST_ROLE", "HEADLINE"]
FIELDS = HEADER_FIELDS + ["REPORT"]
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
            parsed[current] = (parsed[current] + " " + stripped).strip()
    if marker is not None:
        first = REPORT_MARKER_RE.match(_clean(lines[marker])).group(1).strip()
        parsed["REPORT"] = _clean_report("\n".join([first] + lines[marker + 1:]))
    else:
        parsed["REPORT"] = _clean_report("\n".join(lines[header_end:]))
    # One-word fields: take the known value, ignoring any stray text after it.
    verdict = parsed["VERDICT"].upper().replace(" ", "_")
    given = next((v for v in sorted(VERDICTS, key=len, reverse=True) if v in verdict), None)
    parsed["verdict_given"] = given is not None
    parsed["VERDICT"] = given or "SUSPICIOUS"
    confidence = re.search(r"(?i)\b(low|medium|high)\b", parsed["CONFIDENCE"])
    parsed["CONFIDENCE"] = confidence.group(1).lower() if confidence else "low"
    parsed["SECTIONS"] = split_sections(parsed["REPORT"])
    return parsed


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
    names = _safe("indicator_names", tools.indicator_names, host, ip_list, window, case_rows, own_name)
    expected = tools.expected_behaviour(identity, server_ips, flows)
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
        "app_context": app_context,
        "host_apps": host_apps,
        "dns": dns,
        "load": load,
        "expected": expected,
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
        if escalating and _cites_threatfox_confidence(parsed.get("REPORT", "") + " " + parsed.get("HEADLINE", "")):
            notes.append("The report mentions ThreatFox confidence, which rates the indicator, not this host.")
    return {**parsed, "verdict_notes": notes}


def _cites_threatfox_confidence(text: str) -> bool:
    return any(re.search(r"(?i)threatfox", s) and re.search(r"(?i)confidence", s) for s in _sentences(text))


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
SHARED_RE = re.compile(r"(?i)shared (infrastructure|service|ip|hosting|nature)|\bcdn\b|many unrelated")


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


NUMBER_RE = re.compile(r"\d+(?:\.\d+)?")
CHECKED_FIELDS = ("HOST_ROLE", "HEADLINE", "REPORT")


def _checkable(text: str) -> str:
    """Text whose numbers must be in the evidence: no chart markers or list numbering."""
    text = mdrender.CHART_ANYWHERE_RE.sub(" ", text)
    text = re.sub(r"(?m)^\s*\d+[.)]\s", " ", text)
    return re.sub(r"(?<=\d),(?=\d)", "", text)


def unverified_numbers(parsed: dict, evidence_text: str) -> list[str]:
    """Numbers (2+ characters) the model wrote that appear nowhere in the case
    file or its tool results. Shown as a warning in the report."""
    source = re.sub(r"(?<=\d),(?=\d)", "", evidence_text)
    missing: list[str] = []
    for field in CHECKED_FIELDS:
        for number in NUMBER_RE.findall(_checkable(parsed.get(field, ""))):
            if len(number) < 2 or number in source or number in missing:
                continue
            missing.append(number)
    return missing


SELF_REFERENCE_PATTERNS = (
    re.compile(r"(?i)(?<!user )(?<!user-)\bagents?\b"),
    re.compile(r"(?i)\bLLMs?\b|\blanguage model\b|\bthe model\b|\bprompt\b|\bcase file\b"),
    re.compile(r"\bSTEP\s*\d+[a-z]?\b"),  # the case file's section labels
    re.compile(r"\bAI\b|\bI\b|\bI'm\b|\bI've\b|\bI'd\b|\b[Mm]y\b"),
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
6. It does not rely on ThreatFox confidence: that rates the indicator, not this host.
7. It places 1-3 charts, each on its own line ([[chart name]] from READY-MADE CHARTS, or [[chart N]] for \
one you made) next to the text that explains it.
8. It has the four parts in order (Executive summary, Analysis, Conclusion and next steps, Background), \
the next steps are specific to this host, and nothing mentions an agent, a model, yourself, the case \
file or step numbers.
{problems}
You may use the tools again, for example to check a number or fix a chart. Then reply with the complete \
answer in the same format: the four header lines, REPORT:, and the four parts. If it already holds up, \
repeat it unchanged."""

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
    numbers = unverified_numbers(parsed, evidence_text)
    if numbers:
        problems.append(f"These numbers are not in the case file or tool results: {', '.join(numbers)}. "
                        "Correct them, query them, or remove them.")
    verdict = parsed.get("VERDICT")
    if verdict in ("SUSPICIOUS", "LIKELY_THREAT") and _affirmed_mismatch(parsed.get("HEADLINE", "")):
        problems.append(f"Your headline says the traffic does not match the threat, yet your verdict is {verdict}.")
    exfil = ev.get("flows", {}).get("upload_heavy_over_exfil_threshold", {"count": 0})
    if _affirmed(EXFIL_RE, report_text) and not exfil.get("count"):
        problems.append("The report mentions exfiltration, but no flow is over the exfiltration threshold.")
    shared = next((s for s in ev.get("signals", []) if s["name"] == "shared_infrastructure"), None)
    if shared and shared["direction"] == signals.AGAINST and NOT_SHARED_RE.search(report_text):
        problems.append(f"The report says the IP is not shared, but the case file shows it is: {shared['reason']}")
    if verdict in ("SUSPICIOUS", "LIKELY_THREAT") and _cites_threatfox_confidence(report_text):
        problems.append("The report brings up ThreatFox confidence: make sure it is not part of the reasoning, "
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
    conclusion = sections.get("conclusion", "")
    if full_text and not (re.search(r"(?m)^\s*(\d+[.)]|[-*])\s", conclusion) or NEXT_STEPS_RE.search(conclusion)):
        problems.append("The Conclusion and next steps part has no next steps.")
    problems += _chart_problems(full_text, charts or [], ev.get("chart_options") or [])
    role = parsed.get("HOST_ROLE", "")
    if role and host_type.role_problem(role, ev):
        problems.append("Your HOST_ROLE is not supported by the evidence: base it on the uptime and the app and "
                        "domain evidence, or say the role is unclear.")
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
    numbers = unverified_numbers(parsed, evidence_text)
    flags = consistency_flags(parsed, ev)
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
    (indicator, host), highest ThreatFox confidence and most matches first."""
    matches = evidence.load_matches(input_path)
    ioc_metadata = evidence.load_ioc_metadata()
    groups = evidence.group_matches(matches)
    asset_index = evidence.asset_ioc_index(matches)
    cases = [(evidence.case_identity(key, rows, ioc_metadata), rows) for key, rows in groups.items()]
    cases.sort(key=lambda c: (-(c[0]["threatfox_confidence"] or 0), -c[0]["n_events"]))
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
    args = parser.parse_args()
    args.input = feed_path(args.feed, args.input)

    if not args.input.exists():
        raise SystemExit(f"{args.input} not found")
    config.clickhouse_settings()  # fail now, with a clear message, if .env is missing

    cases, asset_index, match_count = load_cases(args.input)
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
    assessments_path = args.output_dir / "assessments.json"
    report_path = args.output_dir / "report.html"

    results = []
    if args.resume and assessments_path.exists():
        previous = json.loads(assessments_path.read_text())
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
        assessments_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
        report_path.write_text(report.render(results), encoding="utf-8")

    for i, (identity, case_rows) in enumerate(cases):
        print(f"\n[{i + 1}/{len(cases)}] {identity['indicator']} <-> {identity['affected_asset']}")
        try:
            key = (identity["indicator"], identity["affected_asset"])
            result = assess_case(identity, case_rows, asset_index, links, link_checks, also_matched.get(key))
            tool_note = f", {len(result['tool_calls'])} tool call(s)" if result["tool_calls"] else ""
            review = " [REVIEW]" if result["needs_review"] else ""
            charts_note = f", {len(result['charts'])} chart(s)" if result.get("charts") else ""
            print(f"  verdict={result['VERDICT']} (rule-based cross-check: {result['baseline_verdict']}) "
                  f"confidence={result['CONFIDENCE']}{tool_note}{charts_note}{review}")
            report.write_case_files(result, cases_dir)
        except llm_client.DailyQuotaExceeded as exc:
            print(f"\n{exc}\nStopping after {i} case(s). Run again with --resume after the reset.")
            break
        except Exception as exc:  # noqa: BLE001 - one bad case shouldn't stop the batch
            print(f"  FAILED: {exc}")
            result = _error_result(identity, exc)
        results.append(result)
        flush()
        if i < len(cases) - 1:
            time.sleep(args.pause)

    flush()
    print(f"\nWrote {len(results)} assessment(s) to {assessments_path}")
    print(f"Wrote report to {report_path} and per-case Markdown to {cases_dir}/")


if __name__ == "__main__":
    main()

"""Triage IOC matches on a campus network.

For each (indicator, internal host) pair in the feed, the must-run checks
(steps 1-5, 7, 8) run deterministically in Python against ClickHouse and the
local knowledge base, and Python computes evidence signals and a baseline
verdict. The model then reads the case file, may call follow-up tools, and
gives a verdict (steps 6, 9); code checks the reply against the evidence and
the baseline. Python writes the reports (step 10).

    python assess.py --input data/sample/ioc_matches_sample.json
    python assess.py --input data/ioc_matches.json --indicator bore.pub
"""
from __future__ import annotations

import argparse
import json
import re
import time
from functools import partial
from pathlib import Path

from agent import behaviour, casefile, config, db, evidence, llm_client, narrative, report, signals, tools

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

SYSTEM_PROMPT = f"""You are a network security analyst triaging IOC (Indicator \
of Compromise) matches on {config.NETWORK_LABEL} (a university network). Each case is one \
{config.HOST_LABEL} \
that contacted an indicator listed on ThreatFox.
{SITE_SECTION}
You get a CASE FILE with steps 1-5, 7 and 8 of the workflow already done: the \
IOC context, the flagged IP(s), the expected behaviour from a local knowledge \
base (threat type, malware family, and any known service such as a tunnel), \
the flows between the host and the flagged IP, the names the host actually \
used on that IP, the other names on that IP campus-wide, domain features, the \
host's traffic to other IPs, and other {config.HOST_LABEL}s contacting the flagged IP. \
It ends with EVIDENCE SIGNALS computed in code and a BASELINE VERDICT from \
fixed rules. Use only the case file and tool results. Do not invent numbers, \
hostnames or events. You have no internet access.

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

Follow-up tools (all bound to this case's host; use them only if the case file \
leaves a real question open):
- timeline_around(time, minutes): what the host did around one time. Tells a \
browsing burst apart from a lone automated connection.
- host_baseline(days): the host's normal daily volume, destinations and hours.
- compare_sessions(date_a, date_b): the host's traffic with the flagged IP on two dates.
- run_sql(sql): anything else, read-only. Filter on this case's client_ip or a \
flagged server_ip and a time column; each table has a maximum span. Reference:
{db.SCHEMA_CARD}
Notes on this data:
{db.DOMAIN_NOTES}
Every run_sql query MUST filter on this case's client_ip (or a flagged \
server_ip) AND a time column within the table's span, or it is rejected with \
an error saying why. Read the error and fix the query.

An IOC match is a starting point, not proof. Judge the behaviour, not the \
match. Key points:
- ThreatFox confidence says how sure the reporter is that the INDICATOR is \
malicious. It says nothing about whether THIS HOST is infected. Never use it \
to move a verdict to SUSPICIOUS or LIKELY_THREAT.
- Start from the BASELINE VERDICT. You may disagree, but only by naming the \
signal you override in BASELINE_OVERRIDE and saying what evidence contradicts \
it. Otherwise give the baseline verdict. A verdict that differs from the \
baseline without a named override is replaced by the baseline.
- An ip:443 indicator on a CDN or shared cloud IP (Cloudflare, AWS) is weak on \
its own: one IP serves thousands of unrelated sites. What matters is which \
name the host actually used on it (the "names" section) and whether that name \
is bad. UDP/443 is QUIC: browser or app HTTPS, not a custom C2 protocol.
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
- The host's other traffic (step 7) shows what kind of machine it is, e.g. a \
home server running several tunnels, a gaming PC, a developer laptop.
- Many campus hosts on one IP, a CDN ASN or a known public service point to \
shared infrastructure. Peers ALSO flagged by other IOCs (marked ***) point to \
a multi-host compromise instead.
- The evidence first/last seen times are the matched flow's own times, not \
ThreatFox's dates. Only reason about ThreatFox dates if the case file gives them.
- A tunnel that exposes a campus host to the internet bypasses the firewall \
even when its use is benign: a false positive for the malware can still be a \
risk worth following up.
- If step 5 found no traffic, say so plainly. The verdict is then set to \
INSUFFICIENT_DATA in code, whatever you write.
- Evidence marked "from the IOC feed, not re-queried" is the feed's own copy \
of the matched rows: real, but only the matched minutes.

The report itself is written in code from the evidence. Your job is the \
judgement: the verdict, and a short reading of the case for the reviewer.

Reply using EXACTLY this template, one field per line, nothing before or after:

HOST_ROLE: <one sentence: what the machine is, based first on the "Uptime" line and \
the other traffic in step 7 (always on = server-like; part-time = laptop or phone), with \
the host name only as a weak hint; hedged, never stated as fact. Do not guess where the \
host is or which network it is on (e.g. residential, staff, lab) unless the host name \
plainly says so>
KEY_JUDGEMENT: <2-3 sentences: the deciding evidence for the verdict, and any \
risk that remains even if it is not malware>
BASELINE_OVERRIDE: <"none", or the one signal you override then " - " and the evidence, e.g. "protocol_fit - flows are TCP to port 1604">
VERDICT: <LIKELY_THREAT | SUSPICIOUS | LIKELY_FALSE_POSITIVE>
CONFIDENCE: <low | medium | high>

VERDICT meanings: LIKELY_THREAT = evidence supports escalation; SUSPICIOUS = \
mixed or incomplete, needs a manual look; LIKELY_FALSE_POSITIVE = the traffic \
does not match the threat (shared infrastructure, a known service's normal \
client, or a shape that doesn't fit), even if some other risk remains.
"""

FIELDS = ["HOST_ROLE", "KEY_JUDGEMENT", "BASELINE_OVERRIDE", "VERDICT", "CONFIDENCE"]
VERDICTS = {"LIKELY_THREAT", "SUSPICIOUS", "LIKELY_FALSE_POSITIVE"}  # the model's choices


def parse_reply(text: str) -> dict:
    """Parse the line-per-field template. Lenient: missing fields come back
    empty, since a small model sometimes drifts from the template."""
    parsed = {field: "" for field in FIELDS}
    current = None
    for line in text.splitlines():
        stripped = line.strip().lstrip("*# ").replace("**", "")
        matched_field = next((f for f in FIELDS if stripped.startswith(f + ":")), None)
        if matched_field:
            current = matched_field
            parsed[current] = stripped.split(":", 1)[1].strip()
        elif current:
            parsed[current] = (parsed[current] + " " + line.strip()).strip()
    parsed["VERDICT"] = parsed["VERDICT"].upper().replace(" ", "_") or "SUSPICIOUS"
    if parsed["VERDICT"] not in VERDICTS:
        parsed["VERDICT"] = "SUSPICIOUS"
    parsed["CONFIDENCE"] = parsed["CONFIDENCE"].lower() or "low"
    return parsed


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
        "peers": peers,
        "shared": shared,
        "other_matches": other_matches,
    }
    ev["signals"] = signals.compute_signals(ev)
    ev["baseline"] = signals.baseline_verdict(ev["signals"], signals.has_evidence(ev))
    ev["behaviour"] = behaviour.classify(ev)
    return ev


# --- guards on the model's reply ----------------------------------------------------

NO_TRAFFIC_NOTE = ("No traffic between the host and the flagged IP was found, live or in the IOC feed's "
                   "own records, so the flows cannot be assessed.")


def _guard_against_fabricated_traffic_detail(parsed: dict, ev: dict) -> dict:
    """When there is no traffic to the flagged IP, replace the model's text
    with fixed text and set INSUFFICIENT_DATA, whatever the model wrote.
    qwen2.5:7b repeatedly invented SNI/ASN/byte counts for empty cases even
    when told not to, so this is enforced in code."""
    flows = ev["flows"]
    if flows.get("has_traffic") and "error" not in flows:
        return parsed
    parsed = dict(parsed)
    parsed["KEY_JUDGEMENT"] = NO_TRAFFIC_NOTE
    parsed["HOST_ROLE"] = ""
    parsed["VERDICT"] = "INSUFFICIENT_DATA"
    parsed["CONFIDENCE"] = "high"
    return parsed


# --- verdict reconciliation and consistency checks (task 2, 1.4 and 1.5) --------------

SEVERITY = {"LIKELY_FALSE_POSITIVE": 0, "SUSPICIOUS": 1, "LIKELY_THREAT": 2}


def parse_override(text: str) -> tuple[str | None, str]:
    """(signal name, reason) from BASELINE_OVERRIDE, or (None, '') for none.
    The line must START with a signal name: a small model sometimes echoes
    the template ("signal_name - ...") or names signals while agreeing."""
    text = (text or "").strip().strip("`*").strip()
    if not text or text.lower().startswith(("none", "n/a", "no ")) or text.lower() == "no":
        return None, ""
    first = re.split(r"[\s:,-]+", text, maxsplit=1)[0].strip("`*")
    if first in signals.SIGNAL_NAMES:
        return first, text
    return None, text


def reconcile_verdict(parsed: dict, baseline: dict) -> dict:
    """Keep the model's verdict only if it matches the baseline, or it names
    the signal it overrides with a reason that is not ThreatFox confidence.
    Otherwise use the baseline. Any disagreement is marked for review."""
    parsed = dict(parsed)
    model_verdict = parsed["VERDICT"]
    parsed["model_verdict"] = model_verdict
    parsed["baseline_verdict"] = baseline["verdict"]
    parsed["override_signal"] = None
    notes: list[str] = []
    parsed["model_confidence"] = parsed["CONFIDENCE"]
    if baseline["verdict"] == "INSUFFICIENT_DATA" or model_verdict == baseline["verdict"]:
        # Same verdict: the confidence is the baseline's, which follows fixed
        # rules, so identical evidence always gets the same confidence.
        parsed["VERDICT"] = baseline["verdict"]
        parsed["CONFIDENCE"] = baseline["confidence"]
        return {**parsed, "verdict_notes": notes}

    signal, reason = parse_override(parsed.get("BASELINE_OVERRIDE", ""))
    leans_on_confidence = re.search(r"(?i)threatfox|confidence", reason or "")
    escalating = SEVERITY.get(model_verdict, 1) > SEVERITY.get(baseline["verdict"], 1)
    if signal and not (escalating and leans_on_confidence):
        parsed["override_signal"] = signal
        notes.append(f"Model overrode the baseline ({baseline['verdict']}) on {signal}: {reason}")
        return {**parsed, "verdict_notes": notes}

    parsed["VERDICT"] = baseline["verdict"]
    parsed["CONFIDENCE"] = baseline["confidence"]
    why = ("it rested on ThreatFox confidence, which rates the indicator, not the host"
           if signal and leans_on_confidence else "no signal was named in BASELINE_OVERRIDE")
    notes.append(f"Model said {model_verdict} but {why}; baseline {baseline['verdict']} kept.")
    return {**parsed, "verdict_notes": notes}


DOES_NOT_FIT_RE = re.compile(r"(?i)\b(does not|doesn't|do not|don't|not)\s+(match|fit|consistent|align)|inconsistent with|unlike")
EXFIL_RE = re.compile(r"(?i)exfiltrat|data theft|stolen data|data (was|being) sent out|sending data out")
NEGATION_RE = re.compile(r"(?i)\b(no|not|none|zero|without|lack of|absence of|never|nor|rather than|instead of)\b"
                         r"|\bthreshold\b")  # "over the exfiltration threshold: 0" quotes the case file
# The negation must sit right before "shared" ("not shared", "no shared
# infrastructure", "lack of shared"), not anywhere earlier in the sentence.
NOT_SHARED_RE = re.compile(
    r"(?i)\b(not|no|lack of|isn't|is not|without|absence of)\s+(a\s+|any\s+|on\s+|on a\s+)?(shared|cdn)\b"
    r"|\bdedicated (ip|server|host|infrastructure)\b")
SHARED_RE = re.compile(r"(?i)shared (infrastructure|service|ip|hosting|nature)|\bcdn\b|many unrelated")


def _sentences(text: str) -> list[str]:
    return [s for s in re.split(r"(?<=[.;!?])\s+", text) if s.strip()]


def _affirmed(pattern: re.Pattern, text: str) -> bool:
    """True if some sentence uses the pattern without negating it
    ("possible exfiltration", not "no exfiltration")."""
    return any(pattern.search(s) and not NEGATION_RE.search(s) for s in _sentences(text))
REPLY_TEXT_FIELDS = ("HOST_ROLE", "KEY_JUDGEMENT")


def _affirmed_mismatch(text: str) -> bool:
    return bool(DOES_NOT_FIT_RE.search(text))


def consistency_flags(parsed: dict, ev: dict) -> list[str]:
    """Contradictions between the reply and the evidence (task 2, 1.5)."""
    flags: list[str] = []
    verdict = parsed["VERDICT"]
    if (verdict in ("SUSPICIOUS", "LIKELY_THREAT") and not parsed.get("override_signal")
            and _affirmed_mismatch(parsed.get("KEY_JUDGEMENT", ""))):
        flags.append(f"The agent's judgement says the traffic does not match the threat, but the verdict is "
                     f"{verdict} with no overriding signal.")

    text = " ".join(parsed.get(f, "") for f in REPLY_TEXT_FIELDS)
    exfil = ev.get("flows", {}).get("upload_heavy_over_exfil_threshold", {"count": 0})
    if _affirmed(EXFIL_RE, text) and not exfil.get("count"):
        flags.append(f"The text mentions exfiltration, but no flow is over the threshold "
                     f"(up/down > {config.EXFIL_MIN_RATIO:g} and > {config.EXFIL_MIN_UP_BYTES / 1e6:g} MB up).")

    shared = next((s for s in ev.get("signals", []) if s["name"] == "shared_infrastructure"), None)
    if shared:
        says_not_shared = bool(NOT_SHARED_RE.search(text))
        says_shared = _affirmed(SHARED_RE, text) and not says_not_shared
        if shared["direction"] == signals.AGAINST and says_not_shared:
            flags.append("The text says the IP is not shared, but the shared_infrastructure signal says it is.")
        if shared["direction"] == signals.SUPPORTS and says_shared:
            flags.append("The text calls the IP shared infrastructure, but the shared_infrastructure signal says "
                         "it looks dedicated.")
    return flags


NUMBER_RE = re.compile(r"\d+(?:\.\d+)?")
CHECKED_FIELDS = ("HOST_ROLE", "KEY_JUDGEMENT")


def unverified_numbers(parsed: dict, evidence_text: str) -> list[str]:
    """Numbers (2+ characters) the model wrote that appear nowhere in the case
    file or run_sql results. Shown as a warning in the report."""
    source = re.sub(r"(?<=\d),(?=\d)", "", evidence_text)
    missing: list[str] = []
    for field in CHECKED_FIELDS:
        text = re.sub(r"(?<=\d),(?=\d)", "", parsed.get(field, ""))
        for number in NUMBER_RE.findall(text):
            if len(number) < 2 or number in source or number in missing:
                continue
            missing.append(number)
    return missing


# --- one case -----------------------------------------------------------------------

def assess_case(identity: dict, case_rows: list[dict], asset_index: dict[str, list[dict]]) -> dict:
    ev = gather_evidence(identity, case_rows, asset_index)
    return assess_evidence(identity, ev)


def assess_evidence(identity: dict, ev: dict) -> dict:
    """Run the model on already-gathered evidence (eval re-runs this to check
    that identical evidence gives an identical verdict)."""
    case_file = casefile.build_case_file(ev)
    ip_list = [entry["server_ip"] for entry in ev["server_ips"].get("ips", [])]
    tool_executor = partial(tools.execute, client_ip=identity["affected_asset"], server_ips=ip_list)
    reply_text, tool_trace = llm_client.run_agent(
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": case_file},
        ],
        tools=tools.TOOL_SPECS,
        tool_executor=tool_executor,
    )
    result = finish_result(identity, ev, case_file, reply_text, tool_trace)
    result["prompt_tokens"] = llm_client.max_prompt_tokens
    if config.PROVIDER == "ollama" and llm_client.max_prompt_tokens >= CONTEXT_WARN_SHARE * config.OLLAMA_NUM_CTX:
        result["consistency_flags"].append(
            f"The prompt reached {llm_client.max_prompt_tokens:,} of {config.OLLAMA_NUM_CTX:,} context tokens; "
            "Ollama drops the start of an overflowing prompt, so raise OLLAMA_NUM_CTX.")
        result["needs_review"] = True
    return result


CONTEXT_WARN_SHARE = 0.95


def finish_result(identity: dict, ev: dict, case_file: str, reply_text: str, tool_trace: list[dict]) -> dict:
    """Parse the reply and apply every code check (split out for tests)."""
    parsed = parse_reply(reply_text)
    parsed = reconcile_verdict(parsed, ev["baseline"])
    parsed = _guard_against_fabricated_traffic_detail(parsed, ev)
    evidence_text = case_file + json.dumps(tool_trace, default=str)
    numbers = unverified_numbers(parsed, evidence_text)
    flags = consistency_flags(parsed, ev)
    if numbers:
        flags.append(f"Numbers not found in the evidence: {', '.join(numbers)}.")
    review = bool(flags) or parsed["model_verdict"] != parsed["baseline_verdict"]
    result = {
        **identity,
        "evidence": ev,
        "case_file": case_file,
        "tool_calls": tool_trace,
        "model_reply_raw": reply_text,
        **parsed,
        "unverified_numbers": numbers,
        "consistency_flags": flags,
        "needs_review": review and parsed["VERDICT"] != "INSUFFICIENT_DATA",
    }
    if "behaviour" not in ev:  # evidence saved before behaviour categories existed
        ev["behaviour"] = behaviour.classify(ev)
    result["behaviour"] = ev["behaviour"]
    result["report"] = narrative.write(result, ev)
    return result


def _error_result(identity: dict, exc: Exception) -> dict:
    result = {**identity, "evidence": None, "case_file": "", "tool_calls": [], "model_reply_raw": ""}
    result.update({field: "" for field in FIELDS})
    result.update({"VERDICT": "ERROR", "KEY_JUDGEMENT": f"Assessment failed: {exc}", "unverified_numbers": [],
                   "consistency_flags": [], "needs_review": True,
                   "report": {"summary": f"Assessment failed: {exc}", "analysis": "", "conclusion": ""}})
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Triage IOC matches with flow data and a local LLM.")
    parser.add_argument("--input", type=Path, default=HERE / "data" / "ioc_matches.json")
    parser.add_argument("--output-dir", type=Path, default=HERE / "output")
    parser.add_argument("--limit", type=int, default=None, help="only assess the first N new cases")
    parser.add_argument("--indicator", type=str, default=None,
                        help="only assess cases for this exact indicator, e.g. 'bore.pub'")
    parser.add_argument("--pause", type=float, default=REQUEST_PAUSE_SEC,
                        help="seconds to wait between cases (for rate-limited providers)")
    parser.add_argument("--resume", action="store_true",
                        help="keep cases that already succeeded in the output and only assess the rest")
    args = parser.parse_args()

    if not args.input.exists():
        raise SystemExit(f"{args.input} not found")
    config.clickhouse_settings()  # fail now, with a clear message, if .env is missing

    cases, asset_index, match_count = load_cases(args.input)
    total_cases = len(cases)
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
            result = assess_case(identity, case_rows, asset_index)
            tool_note = f", {len(result['tool_calls'])} tool call(s)" if result["tool_calls"] else ""
            review = " [REVIEW]" if result["needs_review"] else ""
            print(f"  verdict={result['VERDICT']} (baseline {result['baseline_verdict']}, model "
                  f"{result['model_verdict']}) confidence={result['CONFIDENCE']}{tool_note}{review}")
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

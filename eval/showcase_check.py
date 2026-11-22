"""Automated part of the showcase quality standard, per case report.

    python eval/showcase_check.py output/assessments.json [--reports output/reports] [--json out.json]

For every result with a compiled PDF, reads the PDF text (pdftotext if
installed, else pypdf) beside the result and its case file, and runs the
checks code can decide. Items that need judgement (does the reasoning hold,
are the next steps concrete) are left for a human reading, and listed as
"manual". The numbers in the left column follow the standard's items 1-17.
Nothing here changes a report: it only reports.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import assess  # noqa: E402
from agent import beacon, config, host_type, labels, latex, mdrender  # noqa: E402

VERDICT_WORDS = {"LIKELY_THREAT": "likely threat", "SUSPICIOUS": "suspicious",
                 "LIKELY_FALSE_POSITIVE": "likely false positive", "INSUFFICIENT_DATA": "insufficient data"}
MALWARE_REASONING_RE = re.compile(r"(?i)\bbeacon|\bexfiltrat|\bcommand[- ]and[- ]control\b|\bC2\b|\bpayload")
CREDENTIAL_RE = re.compile(r"(?i)credential|password|log-?in details|sign-?in")
ARTEFACT_RE = re.compile(r"\?\?|\*\*|`|\[\[|\]\]|\\[a-z]+\{")
SHORT_IP_RE = re.compile(r"(?<![\d.])(?!0\.)\d{1,3}\.\d{1,3}(?![\d.])(?!\s*(?:KB|MB|GB|TB|B\b|%|s\b|min|hours?|days?|"
                         r"bytes|pkt|percent|x\b|times\b|/\s*100\b))"
                         r"(?!\s*(?:to|-|–)\s*\d[\d.]*\s*(?:KB|MB|GB|TB|B\b|%))")  # a range of sizes: "9.6 to 23.2 KB"
HHMM_RE = re.compile(r"\b\d{1,2}:\d{2}\b")
ZONE_RE = re.compile(r"\b(?!UTC\b)[A-Z]{2,4}T\b")  # a local zone abbreviation such as AEDT or CEST
DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\b"
                     r"|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2}\b")


def pdf_pages(path: Path) -> list[str]:
    """The PDF's text, one string per page."""
    if shutil.which("pdftotext"):
        out = subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True, text=True).stdout
        return out.split("\f")
    from pypdf import PdfReader
    return [page.extract_text() or "" for page in PdfReader(str(path)).pages]


def _flat(text: str) -> str:
    """Text with hyphenation and line breaks undone, for phrase checks."""
    return " ".join(re.sub(r"-\n\s*", "", text).split())


def check(result: dict, pdf: Path) -> dict:
    """{item number: [problems]} for one report; empty lists pass."""
    pages = pdf_pages(pdf)
    text = "\n".join(pages)
    flat = _flat(text)
    ev = result.get("evidence") or {}
    parsed = {k: result.get(k, "") for k in ("HEADLINE", "REPORT", "HOST_ROLE", "LIKELY_USER", "FLOW_NOTES")}
    parsed["verdict_given"] = result.get("verdict_given", True)
    parsed["SECTIONS"] = result.get("SECTIONS") or mdrender.split_sections(result.get("REPORT", ""))
    parsed["flow_notes"] = result.get("flow_notes") or {}
    evidence_text = result.get("case_file", "") + json.dumps(result.get("tool_calls") or [], default=str)
    contacts = beacon.contact_sizes(ev.get("contact"))
    out: dict[int, list[str]] = {i: [] for i in range(1, 18)}

    numbers = assess.unverified_numbers(parsed, evidence_text, contacts)
    if numbers:
        out[1].append(f"numbers not in the evidence: {', '.join(numbers)}")
    out[2] += assess.contact_claim_problems(parsed, ev) + assess.contact_count_problems(parsed, ev)
    out[3] += _verdict_problems(result)
    out[4] += assess.url_claim_problems(parsed) + assess.source_problems(parsed, ev, evidence_text)
    out[5] += assess.scope_problems(parsed, ev)
    out[6] += assess.speculation_problems(parsed, ev)
    user = result.get("LIKELY_USER") or ""
    if host_type.user_type(user) in ("student", "staff") and host_type.user_problem(user, ev):
        out[6].append(f"LIKELY_USER not supported by the evidence: {user[:80]}")
    out[7] += assess.host_type_problems(parsed, ev)
    out[8] += _phishing_problems(result)
    allowed = assess.TABLE_NAMES | {str(result.get("indicator", "")).lower()}
    tokens = labels.code_tokens(flat, allowed) + re.findall(r"(?<![\w])_[a-z]+\b", flat)  # e.g. _unknown
    if tokens:
        out[9].append(f"code labels in the PDF: {', '.join(tokens[:6])}")
    out[10] += _time_problems(result, parsed)
    out[11] += [f"shorthand IP-like number: {m}" for m in dict.fromkeys(SHORT_IP_RE.findall(assess.main_text(parsed)))]
    if "Campus host:" not in flat or re.search(r"\b(\w+) \1\b", flat.split("Executive summary")[0], re.I):
        out[12].append("title line lacks 'Campus host:' or doubles a word")
    out[13] += assess.figure_problems(parsed, ev, []) + _reference_problems(result, flat)
    out[14] += _one_page_problems(result, pages)
    artefacts = sorted(set(ARTEFACT_RE.findall(flat)))
    if artefacts:
        out[15].append(f"LaTeX/Markdown artefacts: {artefacts}")
    words = assess.self_references(result.get("REPORT", "") + "\n" + result.get("HEADLINE", ""))
    if words:
        out[16].append(f"self-references: {words}")
    if not re.search(r"(?m)^\s*(\d+[.)]|[-*])\s|(?<!\d)1[.)]\s.+(?<!\d)2[.)]\s", parsed["SECTIONS"].get("conclusion", "")):
        out[17].append("no list of next steps")
    # Problems that never reach the page are left out: the word count is a proxy for the one-page rule
    # (item 14 checks the page itself), and an unsupported HOST_ROLE is not printed (report._role hides it).
    options = {str(c["id"]) for c in ev.get("chart_options") or []}
    custom = [c for c in result.get("charts") or [] if str(c["id"]) not in options]
    fresh = assess.self_check_problems(parsed, ev, evidence_text, custom)  # with the current checks
    remaining = [p for p in fresh if not p.startswith(("The report is ", "Your HOST_ROLE is not supported",
                                                       "The report uses code labels",
                                                       "The Analysis cites no FLOW TIMELINE rows",
                                                       "The host part of the Background does not say"))]  # item 9 checks the page; citing rows is not required
    if remaining:
        out[17] += [f"left in the final reply: {p[:150]}" for p in remaining]
    parsed["VERDICT"] = parsed["model_verdict"] = result.get("model_verdict") or result.get("VERDICT")
    for flag in assess.consistency_flags(parsed, ev):  # recomputed with the current checks
        out[2].append(f"flag: {flag[:140]}")
    return out


def _verdict_problems(result: dict) -> list[str]:
    """The verdict and confidence named anywhere in the text must be the result's."""
    verdict, confidence = result.get("VERDICT"), result.get("CONFIDENCE")
    text = _flat(labels.plain_labels(result.get("REPORT", "") + " " + result.get("HEADLINE", ""))).lower()
    problems = []
    for key, words in VERDICT_WORDS.items():
        if key == verdict or key == "INSUFFICIENT_DATA":
            continue
        for m in re.finditer(rf"\b(?:verdict|assessment|conclusion)\b[^.]{{0,40}}\b{words}\b", text):
            problems.append(f"names another verdict: '{m.group(0)[:80]}'")
    named = re.compile(r"\b" + VERDICT_WORDS[verdict].replace("likely ", r"likely (?:an? )?") + r"\b")
    if verdict != "INSUFFICIENT_DATA" and not named.search(text):
        problems.append(f"the verdict '{VERDICT_WORDS[verdict]}' is not named in the text")
    for m in re.finditer(r"\b(low|medium|high)\s+confidence\b", text):
        if m.group(1) != confidence:
            problems.append(f"confidence '{m.group(0)}' differs from {confidence}")
    return problems


def _phishing_problems(result: dict) -> list[str]:
    if (result.get("threat_type") or "").lower() != "phishing":
        return []
    main = assess.main_text({"REPORT": result.get("REPORT", ""), "SECTIONS": result.get("SECTIONS")})
    problems = [f"malware reasoning in a phishing case: '{m.group(0)}'" for m in MALWARE_REASONING_RE.finditer(main)]
    if not CREDENTIAL_RE.search(result.get("REPORT", "")):
        problems.append("does not name the credential-theft risk")
    return list(dict.fromkeys(problems))


def _time_problems(result: dict, parsed: dict) -> list[str]:
    problems = []
    report = result.get("REPORT", "")
    if assess.LOCAL_ZONE_RE.search(report):
        problems.append("'local' used as a time zone")
    sizes = beacon.contact_sizes((result.get("evidence") or {}).get("contact"))
    days = {s["start"][:10] for s in sizes}
    main = assess.main_text(parsed)
    for sentence in assess._sentences(main):
        if HHMM_RE.search(sentence) and len(days) > 1 and not DATE_RE.search(sentence):
            problems.append(f"time without a date though contacts span {len(days)} days: '{sentence.strip()[:90]}'")
        if HHMM_RE.search(sentence) and "UTC" in sentence and not ZONE_RE.search(sentence):
            problems.append(f"UTC time without {config.LOCAL_CITY} time: '{sentence.strip()[:90]}'")
    return problems[:4]


def _reference_problems(result: dict, flat: str) -> list[str]:
    """Figures and tables the text refers to must exist; no empty figures."""
    n_figures = len(result.get("charts") or [])
    problems = [f"refers to Figure {n} of {n_figures}" for n in map(int, re.findall(r"Figures? (\d+)", flat))
                if n > n_figures or n < 1]
    for chart in result.get("charts") or []:
        points = sum(len(s.get("points") or []) for s in chart.get("series") or [])
        if points < 2:
            problems.append(f"near-empty figure: {chart.get('title', '')[:60]}")
    return problems


def _one_page_problems(result: dict, pages: list[str]) -> list[str]:
    """The body, from the title to the end of the conclusion, is on page 1."""
    conclusion = (result.get("SECTIONS") or {}).get("conclusion") or ""
    conclusion = mdrender.CHART_ANYWHERE_RE.sub("", mdrender.FLOW_REF_RE.sub("", labels.plain_labels(conclusion)))
    tail = re.sub(r"[^a-z]", "", conclusion.lower())[-40:]
    first = re.sub(r"[^a-z]", "", pages[0].lower()) if pages else ""
    if not tail or tail not in first:
        return ["the conclusion does not end on page 1"]
    return []


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("assessments", type=Path)
    parser.add_argument("--reports", type=Path, default=None, help="folder of compiled PDFs (default: <dir>/reports)")
    parser.add_argument("--json", type=Path, default=None, help="write the results here")
    args = parser.parse_args()
    reports = args.reports or args.assessments.parent / "reports"
    results = assess.read_results(args.assessments)
    summary = {}
    for result in results:
        if result.get("VERDICT") == "ERROR":
            continue
        pdf = reports / latex.report_name(result)
        name = pdf.stem
        if not pdf.exists():
            summary[name] = {"pdf": False}
            print(f"{name}: no PDF")
            continue
        found = check(result, pdf)
        failed = {k: v for k, v in found.items() if v}
        summary[name] = {"pdf": True, "verdict": result.get("VERDICT"), "failed": failed}
        print(f"{name}: {'PASS (automated items)' if not failed else 'FAIL ' + str(sorted(failed))}")
        for note in result.get("verdict_notes") or []:
            print(f"    note: {note[:200]}")
        for item, problems in sorted(failed.items()):
            for problem in problems[:3]:
                print(f"    {item:>2}. {problem[:200]}")
    if args.json:
        args.json.write_text(json.dumps(summary, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()

"""Step 10: write the reports.

- render_markdown(): one short report per case in three paragraphs (summary,
  behaviour analysis, conclusion and next steps), written in code by
  narrative.py from the evidence.
- write_case_files(): the report, plus the case file the model saw, saved
  next to it for anyone who wants to check the evidence.
- render(): one HTML page with a card per case, worst first. The paragraphs
  are shown; the agent's judgement, the case file and tool calls are folded
  away for reviewers.
"""
from __future__ import annotations

import html
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from . import config, tools

VERDICT_ORDER = {"LIKELY_THREAT": 0, "SUSPICIOUS": 1, "LIKELY_FALSE_POSITIVE": 2, "INSUFFICIENT_DATA": 3}
VERDICT_STYLE = {
    "LIKELY_THREAT": ("#b3261e", "#fce8e6", "Likely threat"),
    "SUSPICIOUS": ("#e37400", "#fff4e5", "Suspicious - review"),
    "LIKELY_FALSE_POSITIVE": ("#188038", "#e6f4ea", "Likely false positive"),
    "INSUFFICIENT_DATA": ("#5f6368", "#f1f3f4", "Insufficient data"),
}
SECTIONS = [("summary", "Summary"), ("analysis", "Behaviour analysis"),
            ("conclusion", "Conclusion and next steps")]


def case_filename(result: dict) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{result['indicator']}__{result['affected_asset']}")
    return f"{slug}.md"


def _label(verdict: str | None) -> str:
    return VERDICT_STYLE.get(verdict, (None, None, verdict or "?"))[2]


def _review_notes(result: dict) -> list[str]:
    return result.get("verdict_notes", []) + result.get("consistency_flags", [])


# --- Markdown -----------------------------------------------------------------------

def render_markdown(result: dict) -> str:
    title = f"# IOC triage: {result['indicator']} and {result['affected_asset']}"
    paragraphs = result.get("report") or {}
    category = (result.get("behaviour") or {}).get("label", "")
    meta = f"**Verdict:** {_label(result.get('VERDICT'))} ({result.get('CONFIDENCE') or '-'} confidence)"
    if category:
        meta += f" · **Behaviour:** {category}"
    out = [title, "", meta, ""]
    for key, heading in SECTIONS:
        text = paragraphs.get(key, "").strip()
        if text:
            out += [f"## {heading}", "", text, ""]
    if result.get("needs_review"):
        out += ["_Marked for human review: " + " ".join(_review_notes(result)) + "_", ""]
    out.append(f"_Automated first-pass triage, {datetime.now(UTC):%Y-%m-%d %H:%M} UTC. The evidence it is based "
               f"on is in {case_filename(result).removesuffix('.md')}.casefile.txt._")
    return "\n".join(out) + "\n"


def write_case_files(result: dict, cases_dir: Path) -> None:
    """The report and, next to it, the case file the model saw."""
    name = case_filename(result)
    (cases_dir / name).write_text(render_markdown(result), encoding="utf-8")
    (cases_dir / name.replace(".md", ".casefile.txt")).write_text(result.get("case_file", ""), encoding="utf-8")


# --- HTML ---------------------------------------------------------------------------

def _format_tool_call(call: dict) -> str:
    e = html.escape
    result = call.get("result", {})
    if call.get("tool") == "run_sql":
        head = str(result.get("sql", ""))
        body = result.get("result", result.get("error", ""))
    else:
        head = tools.describe_call(call)
        body = json.dumps(result, indent=1, default=str)
    return (f"<div class='tool-call'><pre class='tool-block'>{e(head)}</pre>"
            f"<pre class='tool-block'>{e(str(body)[:4000])}</pre></div>")


def _card(result: dict) -> str:
    e = html.escape
    verdict = result.get("VERDICT", "SUSPICIOUS")
    color, bg, label = VERDICT_STYLE.get(verdict, ("#5f6368", "#f1f3f4", verdict))
    paragraphs = result.get("report") or {}
    category = (result.get("behaviour") or {}).get("label", "")
    sections = "".join(
        f"<h4>{e(heading)}</h4><p>{e(paragraphs.get(key, ''))}</p>"
        for key, heading in SECTIONS if paragraphs.get(key)
    )
    review = "<span class='review'>Human review</span>" if result.get("needs_review") else ""
    notes = _review_notes(result)
    warning = ("<div class='warn'><strong>Why it needs review:</strong><ul>"
               + "".join(f"<li>{e(n)}</li>" for n in notes) + "</ul></div>") if notes else ""
    calls = result.get("tool_calls") or []
    calls_html = "".join(_format_tool_call(c) for c in calls) or "(none)"
    judgement = (f"<p><strong>Verdicts:</strong> baseline {e(_label(result.get('baseline_verdict')))}, model "
                 f"{e(_label(result.get('model_verdict')))}"
                 + (f" (overrides <code>{e(result['override_signal'])}</code>)" if result.get("override_signal") else "")
                 + f"</p><p><strong>Host role:</strong> {e(result.get('HOST_ROLE', ''))}</p>"
                 f"<p><strong>Judgement:</strong> {e(result.get('KEY_JUDGEMENT', ''))}</p>")
    return f"""
<div class="card">
  <div class="card-head">
    <span class="badge" style="color:{color}; background:{bg};">{e(label)}</span>
    <span class="category">{e(category)}</span>
    {review}
    <span class="confidence">{e(result.get('CONFIDENCE', ''))} confidence</span>
  </div>
  <h3>{e(result['indicator'])} <span class="arrow">&rarr;</span> {e(result['affected_asset'])}</h3>
  {warning}
  {sections}
  <p class="meta"><a href="cases/{e(case_filename(result))}">Markdown report</a></p>
  <details><summary>Agent's judgement</summary>{judgement}</details>
  <details><summary>Case file (evidence the agent saw)</summary>
    <pre class="tool-block">{e(result.get('case_file', ''))}</pre></details>
  <details><summary>Follow-up tool calls ({len(calls)})</summary>{calls_html}</details>
</div>"""


def render(results: list[dict]) -> str:
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    ordered = sorted(
        results,
        key=lambda r: (VERDICT_ORDER.get(r.get("VERDICT"), 1), not r.get("needs_review"),
                       -(r.get("threatfox_confidence") or 0)),
    )
    counts = {v: sum(1 for r in results if r.get("VERDICT") == v) for v in VERDICT_ORDER}
    review_count = sum(1 for r in results if r.get("needs_review"))
    cards_html = "\n".join(_card(r) for r in ordered) if ordered else "<p>No cases assessed.</p>"
    summary_cards = "".join(
        f'<div class="summary-card" style="border-color:{VERDICT_STYLE[v][0]}">'
        f'<strong>{counts[v]}</strong>{VERDICT_STYLE[v][2]}</div>'
        for v in VERDICT_ORDER
    ) + f'<div class="summary-card" style="border-color:#7b1fa2"><strong>{review_count}</strong>Marked for review</div>'
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IOC Triage Report</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; padding: 28px; color: #202124; background: #fafafa; }}
h1 {{ margin-bottom: 4px; }}
.generated {{ color: #5f6368; margin-top: 0; }}
.note {{ background: #f4f6f8; border-left: 4px solid #5f6368; padding: 10px 16px; margin: 16px 0 24px; font-size: 0.92rem; max-width: 900px; }}
.summary-row {{ display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; }}
.summary-card {{ border: 2px solid; border-radius: 8px; padding: 10px 18px; background: #fff; }}
.summary-card strong {{ display: block; font-size: 1.6rem; }}
.card {{ background: #fff; border: 1px solid #dadce0; border-radius: 10px; padding: 16px 20px; margin-bottom: 16px; max-width: 900px; }}
.card-head {{ display: flex; gap: 10px; align-items: center; margin-bottom: 6px; flex-wrap: wrap; }}
.badge, .review {{ font-weight: 600; padding: 3px 10px; border-radius: 12px; font-size: 0.82rem; }}
.review {{ color: #7b1fa2; background: #f3e5f5; }}
.category {{ color: #3c4043; font-size: 0.85rem; font-weight: 600; }}
.confidence {{ color: #5f6368; font-size: 0.82rem; margin-left: auto; }}
.card h3 {{ margin: 4px 0 6px; font-size: 1.05rem; font-family: ui-monospace, SFMono-Regular, monospace; word-break: break-all; }}
.card h4 {{ margin: 12px 0 4px; font-size: 0.92rem; }}
.card p {{ line-height: 1.5; margin: 0 0 6px; font-size: 0.92rem; }}
.arrow {{ color: #9aa0a6; }}
.meta {{ color: #5f6368; font-size: 0.85rem; }}
.warn {{ color: #b3261e; font-size: 0.85rem; background: #fce8e6; border-radius: 6px; padding: 6px 10px; margin: 8px 0; }}
.warn ul {{ margin: 4px 0 0; padding-left: 18px; }}
details {{ margin-top: 6px; }}
details summary {{ cursor: pointer; color: #1a73e8; font-size: 0.88rem; }}
.tool-call {{ background: #f4f6f8; border-radius: 6px; padding: 8px 10px; margin-bottom: 6px; }}
.tool-block {{ font-family: ui-monospace, SFMono-Regular, monospace; font-size: 0.76rem; white-space: pre-wrap;
               overflow-x: auto; background: #fff; border: 1px solid #dadce0; border-radius: 4px; padding: 6px 8px; margin: 4px 0 0; }}
</style>
</head>
<body>
<h1>IOC Triage Report</h1>
<p class="generated">Generated {generated}</p>
<div class="note">Automated first-pass triage. Each card is one (indicator, {config.HOST_LABEL}) pair. The flow checks run
automatically against SuperNetFlow, code works out the behaviour and a baseline verdict from fixed rules, and a local
LLM gives its own verdict. Where the two differ, or the model's reading contradicts the evidence, the case is marked
for human review. The data in this report is sensitive: do not share it outside the team.</div>
<div class="summary-row">{summary_cards}</div>
{cards_html}
</body>
</html>
"""

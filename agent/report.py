"""Step 10: write the reports.

Every report is the model's own writing, in three parts (executive summary,
analysis, conclusion and next steps) plus a folded-away background, with its
chosen charts collected at the end. Code adds only the facts box, the
rule-based cross-check and the reasons a case needs review.

- render_markdown(): one report per case, with its charts as SVG files.
- write_case_files(): the report, its charts, and the case file the model
  saw, for anyone who wants to check the evidence.
- render(): one HTML page: an overview with a case index, then one article
  per case, worst first. The queries run and the evidence are folded away
  under each case.
"""
from __future__ import annotations

import html
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from . import charts as chart_tools, config, correlation, host_type, mdrender, tools

VERDICT_ORDER = {"LIKELY_THREAT": 0, "SUSPICIOUS": 1, "LIKELY_FALSE_POSITIVE": 2, "INSUFFICIENT_DATA": 3}
VERDICT_STYLE = {  # css class, label
    "LIKELY_THREAT": ("threat", "Likely threat"),
    "SUSPICIOUS": ("suspicious", "Suspicious"),
    "LIKELY_FALSE_POSITIVE": ("benign", "Likely false positive"),
    "INSUFFICIENT_DATA": ("nodata", "Insufficient data"),
    "ERROR": ("nodata", "Assessment failed"),
}
SECTIONS = [(key, mdrender.SECTION_TITLES[key]) for key in ("summary", "analysis", "conclusion")]
TITLE = "IOC Investigation Report"


def case_filename(result: dict) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{result['indicator']}__{result['affected_asset']}")
    return f"{slug}.md"


def chart_filename(result: dict, chart_id) -> str:
    return case_filename(result).removesuffix(".md") + f".chart-{chart_id}.svg"


def _label(verdict: str | None) -> str:
    return VERDICT_STYLE.get(verdict, (None, verdict or "?"))[1]


def _review_notes(result: dict) -> list[str]:
    return result.get("verdict_notes", []) + result.get("consistency_flags", [])


def _written(result: dict) -> bool:
    return bool(result.get("REPORT") or any((result.get("SECTIONS") or {}).values()))


def _cross_check(result: dict) -> str:
    baseline = result.get("baseline_verdict")
    if (not baseline or baseline == "INSUFFICIENT_DATA" or result.get("VERDICT") in ("INSUFFICIENT_DATA", "ERROR")
            or not result.get("verdict_given")):
        return ""
    if baseline == result.get("VERDICT"):
        return "Rule-based cross-check agrees"
    return f"Rule-based cross-check: {_label(baseline)}"


def _role(result: dict) -> str:
    """The host-role reading, if it holds up against the evidence."""
    ev = result.get("evidence") or {}
    role = (result.get("HOST_ROLE") or "").strip()
    if not role or not _written(result) or result.get("unverified_numbers"):
        return ""
    if re.match(r"(?i)^\W*(unclear|unknown|not clear|cannot tell|n/?a|none)\b", role):
        return ""
    return "" if host_type.role_problem(role, ev) else role


def _parts(result: dict) -> dict[str, str]:
    """The report's four parts, as the model wrote them."""
    return result.get("SECTIONS") or mdrender.split_sections(result.get("REPORT") or "")


def _figure_numbers(result: dict) -> dict[str, tuple[dict, int]]:
    """Chart id -> (chart, figure number), numbered in the order shown."""
    return {str(c["id"]): (c, i + 1) for i, c in enumerate(result.get("charts") or [])}


def _figure_label(numbers: dict[str, tuple[dict, int]]):
    """For a chart named inside a sentence: "Figure 2", so the sentence still reads."""
    return lambda ref: f"Figure {numbers[ref][1]}" if ref in numbers else ""


# --- Markdown -----------------------------------------------------------------------

def render_markdown(result: dict) -> str:
    title = f"# {result['indicator']} → {result['affected_asset']}"
    category = (result.get("behaviour") or {}).get("label", "")
    meta = f"**Assessment:** {_label(result.get('VERDICT'))} ({result.get('CONFIDENCE') or '-'} confidence)"
    if category:
        meta += f" · **Behaviour:** {category}"
    check = _cross_check(result)
    if check:
        meta += f" · {check}"
    out = [title, "", meta, ""]
    if result.get("needs_review"):
        out += ["> **Marked for review.** " + " ".join(_review_notes(result)), ""]
    parts = _parts(result)
    numbers = _figure_numbers(result)
    for key, heading in SECTIONS + [("background", "Background")]:
        text = parts.get(key, "").strip()
        if not text:
            continue
        out += [f"## {heading}", ""]
        for line in mdrender.isolate_charts(text, _figure_label(numbers)).split("\n"):
            match = mdrender.CHART_RE.match(line)
            if match and match.group(1) in numbers:
                chart, number = numbers[match.group(1)]
                out.append(f"*(See Figure {number}: {chart['title']}, at the end of the report.)*")
            elif not match:
                out.append(line)
        out.append("")
    if numbers:
        out += ["## Figures", ""] + [_markdown_figure(result, chart, number) for chart, number in numbers.values()]
    out.append(f"_{config.ORG_NAME + ' ' if config.ORG_NAME else ''}IOC investigation, generated "
               f"{datetime.now(UTC):%Y-%m-%d %H:%M} UTC. The evidence it is based on is in "
               f"{case_filename(result).removesuffix('.md')}.casefile.txt._")
    return "\n".join(out) + "\n"


def _markdown_figure(result: dict, chart: dict, number: int) -> str:
    caption = f"*Figure {number}. {chart['title']}.*"
    if chart.get("caption"):
        caption += f" {chart['caption']}"
    return f"\n![{chart['title']}]({chart_filename(result, chart['id'])})\n\n{caption}\n"


def write_case_files(result: dict, cases_dir: Path) -> None:
    """The report, its charts, and next to it the case file the model saw."""
    name = case_filename(result)
    (cases_dir / name).write_text(render_markdown(result), encoding="utf-8")
    (cases_dir / name.replace(".md", ".casefile.txt")).write_text(result.get("case_file", ""), encoding="utf-8")
    for chart in result.get("charts") or []:
        (cases_dir / chart_filename(result, chart["id"])).write_text(chart_tools.render_svg(chart), encoding="utf-8")


# --- HTML pieces --------------------------------------------------------------------

e = html.escape


def _badge(verdict: str) -> str:
    css, label = VERDICT_STYLE.get(verdict, ("nodata", verdict))
    return f'<span class="badge {css}"><span class="dot" aria-hidden="true"></span>{e(label)}</span>'


def _format_tool_call(call: dict) -> str:
    result = call.get("result", {})
    if call.get("tool") == "run_sql":
        head = str(result.get("sql", ""))
        body = result.get("result", result.get("error", ""))
    elif call.get("tool") == "add_chart":
        head = f"{tools.describe_call(call)}\n\n{call.get('arguments', {}).get('sql', '')}"
        body = json.dumps(result, indent=1, default=str)
    else:
        head = tools.describe_call(call)
        body = json.dumps(result, indent=1, default=str)
    return (f"<div class='call'><div class='call-name'>{e(call.get('tool', ''))}</div>"
            f"<pre>{e(head)}</pre><pre class='call-result'>{e(str(body)[:4000])}</pre></div>")


def _chart_table(chart: dict) -> str:
    rows = chart.get("rows") or []
    head = "".join(f"<th>{e(c)}</th>" for c in chart.get("columns", []))
    body = "".join("<tr>" + "".join(f"<td>{e('' if v is None else str(v))}</td>" for v in row) + "</tr>"
                   for row in rows[:200])
    more = f"<p class='muted'>First 200 of {len(rows)} rows.</p>" if len(rows) > 200 else ""
    return f"<div class='table-wrap'><table class='data'><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>{more}"


def _figure(chart: dict, number: int, element_id: str = "") -> str:
    notes = " ".join(chart_tools.notes(chart))
    caption = e(chart.get("caption") or "")
    if notes:
        caption += f" <span class='muted'>{e(notes)}</span>"
    return f"""<figure class="figure"{f' id="{element_id}"' if element_id else ''}>
  <figcaption class="figure-title"><span class="figure-no">Figure {number}</span>{e(chart['title'])}</figcaption>
  {chart_tools.render_svg(chart)}
  {f'<p class="figure-caption">{caption}</p>' if caption else ''}
  <details class="figure-data"><summary>Data and source</summary>{_chart_table(chart)}<pre>{e(chart.get('sql') or 'Source: ' + (chart.get('source') or 'the evidence gathered for this case'))}</pre></details>
</figure>"""


def _report_parts(result: dict) -> tuple[str, str, str]:
    """(the three main parts, the background, the figures), as HTML. A chart
    the report places becomes a link; the figures themselves come at the end."""
    parts = _parts(result)
    numbers = _figure_numbers(result)
    anchor = _anchor(result)

    def reference(ref: str) -> str:
        if ref not in numbers:
            return ""
        chart, number = numbers[ref]
        return (f"<p class='fig-ref'><a href='#{anchor}-fig{number}' data-fig>See Figure {number}: "
                f"{e(chart['title'])}</a></p>")

    def label(ref: str) -> str:  # a chart named inside a sentence
        return f"[Figure {numbers[ref][1]}](#{anchor}-fig{numbers[ref][1]})" if ref in numbers else ""

    body = ""
    for key, heading in SECTIONS:
        if parts.get(key):
            css = "part lead" if key == "summary" else "part"
            body += (f"<section class='{css}'><h3>{e(heading)}</h3>"
                     f"{mdrender.to_html(parts[key], reference, heading_offset=1, label=label)}</section>")
    background = (mdrender.to_html(parts["background"], reference, heading_offset=1, label=label)
                  if parts.get("background") else "")
    figures = "".join(_figure(chart, number, f"{anchor}-fig{number}") for chart, number in numbers.values())
    return body, background, figures


def _when(value) -> str:
    if not value:
        return "?"
    text = str(value).replace("T", " ")[:16]
    local = config.to_local(value)
    return f"{text} UTC" + (f" ({local})" if local else "")


def _facts(result: dict) -> str:
    ev = result.get("evidence") or {}
    host = ev.get("host") or {}
    malware = " / ".join(x for x in (result.get("malware"), result.get("threat_type")) if x) or "?"
    ips = []
    for info in ev.get("asn") or []:
        org = (info.get("asn_org") or "").strip()
        ips.append(f"{info['server_ip']}" + (f" (AS{info['asn']} {org})" if info.get("asn") else ""))
    rows = [
        ("Internal host", f"{result['affected_asset']}" + (f" ({host['hostname']})" if host.get("hostname") else "")),
        ("Indicator", f"{result['indicator']} ({result.get('indicator_type') or '?'})"),
        ("ThreatFox listing", f"{malware}; reporter confidence {result.get('threatfox_confidence', '?')}%"),
        ("Matched evidence", f"{_when(result.get('evidence_first_seen'))} to {_when(result.get('evidence_last_seen'))}"
                             f" ({result.get('n_events', '?')} feed match(es))"),
    ]
    if ips:
        rows.append(("Flagged address", "; ".join(ips)))
    kind = ev.get("host_type") or {}
    if kind.get("label"):
        unusual = len((kind.get("comparison") or {}).get("unusual") or [])
        rows.append(("Host type (classified)", f"{kind['name']}, confidence {kind['confidence']:.2f}; "
                     + (f"{unusual} feature(s) unusual for the type" if unusual else "behaves like the type")))
    role = _role(result)
    if role:
        rows.append(("Likely role (analyst reading)", role))
    items = "".join(f"<div><dt>{e(k)}</dt><dd>{e(v)}</dd></div>" for k, v in rows)
    return f"<dl class='facts'>{items}</dl>"


def _related_html(result: dict) -> str:
    """Links to other cases whose host used the same linked domain. Same
    visits are merged into one case, so they are not listed here."""
    links = (result.get("evidence") or {}).get("correlation") or {}
    items = []
    for r in links.get("related_cases", []):
        if r["same_visit"]:
            continue
        items.append(f"<a href='#{_anchor({'indicator': r['indicator'], 'affected_asset': r['host']})}'>"
                     f"{e(r['indicator'])} &rarr; {e(r['host'])}</a> (via {e(r['domain'])})")
    return f"<p class='related'><strong>Other cases with this domain:</strong> {'; '.join(items)}</p>" if items else ""


def linked_domain_notes(results: list[dict]) -> list[str]:
    """One note per domain behind two or more flagged indicators in the feed:
    a report-level fact to check once, not evidence against any host."""
    notes: dict[str, str] = {}
    for result in results:
        links = (result.get("evidence") or {}).get("correlation") or {}
        for d in links.get("domains", []):
            if d["domain"] in notes:
                continue
            provider = correlation.shared_provider(d["indicators"])
            normal = f" (normal for {provider}, which gives each site more than one address)" if provider else ""
            campus = ""
            if "campus_hosts" in d:
                campus = (f" On campus, {d['campus_hosts']} host(s) used it"
                          + (f", first seen {d['campus_first_seen'][:10]}" if d.get("campus_first_seen") else "") + ".")
            notes[d["domain"]] = (
                f"{d['domain']} is behind {len(d['indicators'])} flagged addresses ({', '.join(d['indicators'])})"
                f"{normal}; the IOC was probably reported against this domain. Check it on ThreatFox: if it is not "
                f"listed, the cases that only browsed it are clean false positives.{campus}")
    return list(notes.values())


def _also_html(result: dict) -> str:
    """Other flagged addresses merged into this case (the same visit)."""
    also = (result.get("evidence") or {}).get("also_matched") or []
    return f"<p class='related'>Also matched {e(', '.join(also))} in the same visit.</p>" if also else ""


def _refinement_html(result: dict) -> str:
    r = result.get("refinement") or {}
    if not r.get("rounds"):
        return ""
    found = "".join(f"<li>{e(p)}</li>" for p in r.get("problems", [])) or "<li>none found by code</li>"
    change = "revised its report" if r.get("changed") else "kept its report"
    verdict = (f" (first verdict: {e(_label(r.get('first_verdict')))})"
               if r.get("first_verdict") and r.get("first_verdict") != result.get("model_verdict") else "")
    return (f"<details class='appendix'><summary>Agent self-check</summary><p>After a proofreading pass the agent "
            f"{change}{verdict}. Problems code found in the first draft:</p><ul>{found}</ul></details>")


def _hostname(result: dict) -> str:
    name = ((result.get("evidence") or {}).get("host") or {}).get("hostname")
    return f" <span class='muted'>({e(name)})</span>" if name else ""


def _anchor(result: dict) -> str:
    return "case-" + re.sub(r"[^A-Za-z0-9]+", "-", f"{result['indicator']}-{result['affected_asset']}").strip("-")


def _review_html(result: dict) -> str:
    notes = _review_notes(result)
    if not result.get("needs_review") or not notes:
        return ""
    items = "".join(f"<li>{e(n)}</li>" for n in notes)
    return f"<aside class='callout'><div class='callout-title'>Needs analyst review</div><ul>{items}</ul></aside>"


def _case(result: dict, number: int, total: int) -> str:
    verdict = result.get("VERDICT", "SUSPICIOUS")
    category = (result.get("behaviour") or {}).get("label", "")
    check = _cross_check(result)
    body, background, figures = _report_parts(result)
    background_html = (f"<details class='background'><summary>Background: the host, the threat and what "
                       f"compromise would look like</summary><div class='report'>{background}</div></details>"
                       if background else "")
    count = len(result.get("charts") or [])
    figures_html = (f"<details class='background figures'><summary>Figures ({count})</summary>{figures}</details>"
                    if figures else "")
    calls = result.get("tool_calls") or []
    calls_html = "".join(_format_tool_call(c) for c in calls) or "<p class='muted'>None.</p>"
    pills = [_badge(verdict), f"<span class='pill'>{e(result.get('CONFIDENCE') or '-')} confidence</span>"]
    if category:
        pills.append(f"<span class='pill'>{e(category)}</span>")
    if check:
        css = "pill ok" if "agrees" in check else "pill warn"
        pills.append(f"<span class='{css}'>{e(check)}</span>")
    if result.get("needs_review"):
        pills.append("<span class='pill review'>Needs review</span>")
    return f"""
<article class="case" id="{_anchor(result)}" data-verdict="{e(verdict)}" data-review="{'1' if result.get('needs_review') else '0'}">
  <header class="case-head">
    <div class="kicker">Case {number} of {total}</div>
    <h2 class="case-title mono">{e(result['indicator'])}</h2>
    <p class="case-sub">contacted by <span class="mono">{e(result['affected_asset'])}</span>{_hostname(result)}</p>
    <div class="pills">{''.join(pills)}</div>
  </header>
  {_facts(result)}
  {_also_html(result)}
  {_review_html(result)}
  <div class="report">{body}</div>
  {background_html}
  {figures_html}
  {_related_html(result)}
  <div class="appendices">
    <details class="appendix"><summary>Queries run during the investigation ({len(calls)})</summary>{calls_html}</details>
    <details class="appendix"><summary>Evidence gathered (case file)</summary><pre class="casefile">{e(result.get('case_file', ''))}</pre></details>
    {_refinement_html(result)}
  </div>
  <p class="case-foot"><a href="cases/{e(case_filename(result))}">Markdown version</a> · <a href="#top">Back to overview</a></p>
</article>"""


def _index_row(result: dict) -> str:
    verdict = result.get("VERDICT", "SUSPICIOUS")
    headline = (result.get("HEADLINE") or _parts(result).get("summary") or "").strip()
    if len(headline) > 220:
        headline = headline[:219].rsplit(" ", 1)[0] + "…"
    review = "<span class='pill review'>Review</span>" if result.get("needs_review") else ""
    category = (result.get("behaviour") or {}).get("label", "")
    return (f"<tr data-verdict='{e(verdict)}' data-review='{'1' if result.get('needs_review') else '0'}'>"
            f"<td>{_badge(verdict)}</td>"
            f"<td><a class='mono' href='#{_anchor(result)}'>{e(result['indicator'])}</a>"
            f"<div class='mono muted small'>{e(result['affected_asset'])}</div></td>"
            f"<td class='small'>{e(category)}</td><td class='small'>{e(headline)}</td><td>{review}</td></tr>")


def render(results: list[dict]) -> str:
    generated = datetime.now(UTC).strftime("%d %b %Y, %H:%M UTC")
    ordered = sorted(
        results,
        key=lambda r: (VERDICT_ORDER.get(r.get("VERDICT"), 1), not r.get("needs_review"),
                       (((r.get("evidence") or {}).get("correlation") or {}).get("domains") or [{"domain": "~"}])[0]["domain"],
                       -(r.get("threatfox_confidence") or 0)),
    )
    counts = {v: sum(1 for r in results if r.get("VERDICT") == v) for v in VERDICT_ORDER}
    review_count = sum(1 for r in results if r.get("needs_review"))
    tiles = [("Cases", len(results), "", "all")]
    tiles += [(VERDICT_STYLE[v][1], counts[v], VERDICT_STYLE[v][0], v) for v in VERDICT_ORDER]
    tiles.append(("Needs review", review_count, "review", "review"))
    tiles_html = "".join(
        f"<button class='tile {css}' data-filter='{key}' type='button'><span class='tile-value'>{n}</span>"
        f"<span class='tile-label'>{e(label)}</span></button>" for label, n, css, key in tiles)
    domain_notes = linked_domain_notes(results)
    linked_html = ("<section class='notice'><h3>Linked domains</h3><ul>"
                   + "".join(f"<li>{e(n)}</li>" for n in domain_notes) + "</ul></section>") if domain_notes else ""
    index_rows = "".join(_index_row(r) for r in ordered)
    cases_html = "\n".join(_case(r, i + 1, len(ordered)) for i, r in enumerate(ordered)) \
        or "<p class='muted'>No cases assessed.</p>"
    org = e(config.ORG_NAME) if config.ORG_NAME else ""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TITLE}{' - ' + org if org else ''}</title>
<style>{CSS}</style>
</head>
<body>
<header class="masthead" id="top">
  <div class="wrap masthead-inner">
    <div>
      <div class="eyebrow">{org + ' · ' if org else ''}Security operations</div>
      <h1>{TITLE}</h1>
      <p class="sub">ThreatFox indicator matches investigated against SuperNetFlow flow records · generated {generated}</p>
    </div>
    <div class="marking">Sensitive · internal use only</div>
  </div>
</header>
<main class="wrap">
  <section class="overview">
    <div class="tiles">{tiles_html}</div>
    <details class="about"><summary>How these cases were investigated</summary>
      <p>Each case is one {e(config.HOST_LABEL)}'s contact with a ThreatFox indicator (one case covers a visit that
      matched several flagged addresses of the same site). Fixed checks first gather the evidence from SuperNetFlow:
      the flows to the flagged address, the names the host used on it, its per-minute contact pattern, app labels, the
      host's other traffic and uptime, DNS behaviour and the other campus hosts on the address. An investigation agent
      then reviews that evidence, runs its own follow-up queries, chooses the charts, and writes the report and
      assessment. Every number in a report is checked against the evidence, and a rule-based assessment from the same
      evidence serves as a cross-check: where they disagree, or the report contradicts the evidence, the case is
      marked for analyst review. Flow records carry no payloads, so these are leads to verify, not proof.</p>
      <p>The data in this report includes internal IP addresses and per-host activity. Do not share it outside the
      team.</p>
    </details>
    {linked_html}
    <div class="index-head"><h2>Cases</h2><div class="filters" role="group" aria-label="Filter cases">
      <button type="button" data-filter="all" class="chip active">All</button>
      <button type="button" data-filter="review" class="chip">Needs review</button>
      <button type="button" data-filter="LIKELY_THREAT" class="chip">Likely threat</button>
      <button type="button" data-filter="SUSPICIOUS" class="chip">Suspicious</button>
      <button type="button" data-filter="LIKELY_FALSE_POSITIVE" class="chip">Likely false positive</button>
    </div></div>
    <div class="table-wrap index"><table>
      <thead><tr><th>Assessment</th><th>Indicator / host</th><th>Behaviour</th><th>Finding</th><th></th></tr></thead>
      <tbody>{index_rows}</tbody>
    </table></div>
  </section>
  {cases_html}
</main>
<footer class="wrap page-foot">{TITLE} · generated {generated}</footer>
<script>{SCRIPT}</script>
</body>
</html>
"""


SCRIPT = """
(function () {
  var buttons = document.querySelectorAll('[data-filter]');
  function apply(filter) {
    document.querySelectorAll('tr[data-verdict], article.case').forEach(function (el) {
      var show = filter === 'all' || (filter === 'review' ? el.dataset.review === '1' : el.dataset.verdict === filter);
      el.hidden = !show;
    });
    document.querySelectorAll('.chip').forEach(function (chip) {
      chip.classList.toggle('active', chip.dataset.filter === filter);
    });
  }
  buttons.forEach(function (b) { b.addEventListener('click', function () { apply(b.dataset.filter); }); });
  document.addEventListener('click', function (event) {
    var link = event.target.closest('a[data-fig]');
    var target = link && document.getElementById(link.getAttribute('href').slice(1));
    var section = target && target.closest('details');
    if (section) { section.open = true; }
  });
})();
"""

CSS = """
:root {
  --bg: #f4f5f7; --card: #ffffff; --ink: #14171c; --ink2: #3d4450; --muted: #6b7280; --line: #e3e6ea;
  --line-strong: #cfd4da; --accent: #1f4f8a; --accent-ink: #ffffff; --mast: #10213a; --mast-ink: #e8edf4;
  --mast-muted: #a9b6c7; --code-bg: #f6f7f9;
  --threat: #b42318; --threat-bg: #fdecea; --suspicious: #9a5b00; --suspicious-bg: #fff4e0;
  --benign: #17703a; --benign-bg: #e7f5ec; --nodata: #5b6270; --nodata-bg: #eef0f3;
  --review: #5a3a9a; --review-bg: #f1ecfb; --warn-bg: #fff8e6; --warn-line: #e8b44a;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #0e1116; --card: #161a21; --ink: #eef1f5; --ink2: #c6ccd6; --muted: #8b93a1; --line: #262c36;
    --line-strong: #343b47; --accent: #7fb0ec; --accent-ink: #0e1116; --mast: #0a1526; --mast-ink: #e8edf4;
    --mast-muted: #8fa0b6; --code-bg: #11151b;
    --threat: #ff8a7a; --threat-bg: #3a1714; --suspicious: #f3b54a; --suspicious-bg: #33240a;
    --benign: #6fd394; --benign-bg: #11301d; --nodata: #a6adba; --nodata-bg: #222833;
    --review: #c3a6ff; --review-bg: #271d3d; --warn-bg: #2b2310; --warn-line: #8a6a1f;
    color-scheme: dark;
  }
}
:root[data-theme="dark"] {
  --bg: #0e1116; --card: #161a21; --ink: #eef1f5; --ink2: #c6ccd6; --muted: #8b93a1; --line: #262c36;
  --line-strong: #343b47; --accent: #7fb0ec; --accent-ink: #0e1116; --mast: #0a1526; --mast-ink: #e8edf4;
  --mast-muted: #8fa0b6; --code-bg: #11151b;
  --threat: #ff8a7a; --threat-bg: #3a1714; --suspicious: #f3b54a; --suspicious-bg: #33240a;
  --benign: #6fd394; --benign-bg: #11301d; --nodata: #a6adba; --nodata-bg: #222833;
  --review: #c3a6ff; --review-bg: #271d3d; --warn-bg: #2b2310; --warn-line: #8a6a1f;
  color-scheme: dark;
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 15px/1.6 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.wrap { max-width: 1040px; margin: 0 auto; padding: 0 16px; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-wrap: anywhere; }
.muted { color: var(--muted); }
.small { font-size: 13px; }
h1, h2, h3, h4 { line-height: 1.25; }

.masthead { background: var(--mast); color: var(--mast-ink); padding: 28px 0 24px; }
.masthead-inner { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; }
.eyebrow { text-transform: uppercase; letter-spacing: .08em; font-size: 12px; color: var(--mast-muted); font-weight: 600; }
.masthead h1 { margin: 4px 0 6px; font-size: 28px; font-weight: 650; letter-spacing: -.01em; }
.masthead .sub { margin: 0; color: var(--mast-muted); font-size: 14px; }
.marking { border: 1px solid var(--mast-muted); color: var(--mast-ink); border-radius: 4px; padding: 4px 10px;
  font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: .06em; white-space: nowrap; }

.overview { margin: 24px 0 32px; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
.tile { all: unset; cursor: pointer; background: var(--card); border: 1px solid var(--line); border-radius: 10px;
  padding: 14px 16px; display: flex; flex-direction: column; gap: 2px; border-top: 3px solid var(--line-strong); }
.tile:hover { border-color: var(--line-strong); }
.tile:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.tile.threat { border-top-color: var(--threat); } .tile.suspicious { border-top-color: var(--suspicious); }
.tile.benign { border-top-color: var(--benign); } .tile.nodata { border-top-color: var(--nodata); }
.tile.review { border-top-color: var(--review); }
.tile-value { font-size: 28px; font-weight: 650; line-height: 1.1; }
.tile-label { color: var(--muted); font-size: 13px; }

.about, .notice { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 12px 16px;
  margin-top: 16px; font-size: 14px; color: var(--ink2); }
.about summary { cursor: pointer; font-weight: 600; color: var(--ink); }
.notice h3 { margin: 0 0 6px; font-size: 15px; color: var(--ink); }
.notice ul { margin: 0; padding-left: 20px; }

.index-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; margin: 28px 0 10px; }
.index-head h2 { margin: 0; font-size: 18px; }
.filters { display: flex; gap: 6px; flex-wrap: wrap; }
.chip { font: inherit; font-size: 13px; padding: 4px 12px; border-radius: 999px; border: 1px solid var(--line-strong);
  background: var(--card); color: var(--ink2); cursor: pointer; }
.chip.active { background: var(--accent); border-color: var(--accent); color: var(--accent-ink); }

.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); font-weight: 600; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.index { background: var(--card); border: 1px solid var(--line); border-radius: 10px; }
.index table { min-width: 680px; }
.index td:nth-child(2) { min-width: 200px; }
.index tr:last-child td { border-bottom: 0; }

.badge { display: inline-flex; align-items: center; gap: 6px; font-weight: 600; font-size: 12.5px; padding: 2px 10px;
  border-radius: 999px; white-space: nowrap; }
.badge .dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
.badge.threat { color: var(--threat); background: var(--threat-bg); }
.badge.suspicious { color: var(--suspicious); background: var(--suspicious-bg); }
.badge.benign { color: var(--benign); background: var(--benign-bg); }
.badge.nodata { color: var(--nodata); background: var(--nodata-bg); }
.pill { display: inline-block; font-size: 12.5px; padding: 2px 10px; border-radius: 999px; border: 1px solid var(--line-strong);
  color: var(--ink2); white-space: nowrap; }
.pill.review { color: var(--review); background: var(--review-bg); border-color: transparent; font-weight: 600; }
.pill.ok { color: var(--benign); border-color: transparent; background: var(--benign-bg); }
.pill.warn { color: var(--suspicious); border-color: transparent; background: var(--suspicious-bg); }

.case { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 24px 28px; margin: 0 0 24px; }
.kicker { font-size: 12px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); font-weight: 600; }
.case-title { margin: 6px 0 2px; font-size: 21px; font-weight: 600; }
.case-sub { margin: 0 0 12px; color: var(--ink2); font-size: 14px; }
.pills { display: flex; gap: 6px; flex-wrap: wrap; }
.facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 10px 24px; margin: 18px 0 0;
  padding: 14px 16px; background: var(--code-bg); border: 1px solid var(--line); border-radius: 8px; }
.facts dt { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; font-weight: 600; }
.facts dd { margin: 2px 0 0; font-size: 14px; word-break: break-word; }
.callout { margin: 16px 0 0; padding: 12px 16px; border-radius: 8px; background: var(--warn-bg);
  border-left: 4px solid var(--warn-line); font-size: 14px; }
.callout-title { font-weight: 650; margin-bottom: 4px; }
.callout ul { margin: 0; padding-left: 20px; }
.related { font-size: 14px; color: var(--ink2); }

.report { margin-top: 8px; }
.part { margin-top: 26px; padding-top: 18px; border-top: 1px solid var(--line); }
.part > h3 { font-size: 13px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 0 0 10px; }
.part.lead { border-top: 0; padding: 16px 20px; margin-top: 20px; background: var(--code-bg); border-radius: 8px;
  border-left: 4px solid var(--accent); }
.part.lead p { font-size: 15.5px; }
.part.lead > p:last-child { margin-bottom: 0; }
.background { margin-top: 22px; border: 1px solid var(--line); border-radius: 8px; padding: 10px 16px; }
.background > summary { cursor: pointer; font-weight: 600; color: var(--ink); }
.background[open] > summary { margin-bottom: 6px; }
.background + .background { margin-top: 10px; }
.fig-ref { font-size: 14px; margin: -4px 0 12px; }
.fig-ref a::before { content: "\\2193  "; }
.report p, .report ul, .report ol, .report blockquote { max-width: 78ch; }
.report h3 { font-size: 17px; margin: 22px 0 8px; }
.report h4 { font-size: 15.5px; margin: 18px 0 6px; }
.report h5 { font-size: 14px; margin: 14px 0 4px; }
.report p { margin: 0 0 12px; }
.report ul, .report ol { margin: 0 0 12px; padding-left: 22px; }
.report li { margin: 3px 0; }
.report code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px;
  background: var(--code-bg); border: 1px solid var(--line); padding: 0 4px; border-radius: 4px; word-break: break-all; }
.report pre { background: var(--code-bg); border: 1px solid var(--line); border-radius: 6px; padding: 10px 12px; overflow-x: auto; font-size: 13px; }
.report pre code { border: 0; padding: 0; background: none; }
.report blockquote { margin: 0 0 12px; padding: 4px 14px; border-left: 3px solid var(--line-strong); color: var(--ink2); }
.report table { margin: 0 0 14px; }
.report hr { border: 0; border-top: 1px solid var(--line); margin: 18px 0; }

.figure { margin: 18px 0 20px; padding: 14px 16px 10px; border: 1px solid var(--line); border-radius: 10px; max-width: none; }
.figure-title { font-weight: 600; font-size: 14px; margin-bottom: 8px; }
.figure-no { color: var(--muted); font-weight: 600; margin-right: 8px; }
.figure svg { display: block; height: auto; }
.figure-caption { font-size: 13.5px; color: var(--ink2); margin: 8px 0 4px; }
.figure-data summary, .appendix summary { cursor: pointer; color: var(--accent); font-size: 13.5px; }
.figure-data pre { font-size: 12px; white-space: pre-wrap; }
table.data { font-size: 12.5px; }
table.data td { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; padding: 4px 8px; }

.appendices { margin-top: 22px; border-top: 1px solid var(--line); padding-top: 12px; display: grid; gap: 6px; }
.appendix { font-size: 14px; }
.appendix[open] { padding-bottom: 8px; }
.appendix h4 { margin: 12px 0 4px; font-size: 14px; }
.appendix p { margin: 0 0 8px; }
.casefile, .call pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; white-space: pre-wrap;
  background: var(--code-bg); border: 1px solid var(--line); border-radius: 6px; padding: 8px 10px; overflow-x: auto; margin: 6px 0; }
.call { margin: 10px 0; }
.call-name { font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
.call-result { max-height: 320px; overflow: auto; }
.case-foot { margin: 16px 0 0; font-size: 13px; color: var(--muted); }
.page-foot { color: var(--muted); font-size: 13px; padding: 8px 16px 40px; }

@media (max-width: 640px) {
  .case { padding: 18px 16px; }
  .masthead h1 { font-size: 23px; }
}
@media print {
  body { background: #fff; }
  .filters, .tiles button:hover { display: none; }
  .case { break-before: page; border: 0; padding: 0; }
  .masthead { background: none; color: #000; }
}
"""

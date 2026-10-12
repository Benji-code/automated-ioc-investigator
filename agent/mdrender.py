"""Render the model's Markdown report as HTML for report.html.

A small renderer for the subset a report uses: headings, paragraphs,
bullet and numbered lists (one level of nesting), tables, block quotes,
code blocks, rules, **bold**, *italic*, `code` and http(s) links. All text
is HTML-escaped first, so nothing the model writes becomes markup. A line
holding only [[chart <id>]] is replaced by that chart (a ready-made chart's
name, or a number for the model's own). [[flow F3]] (or [[flow F3-F5]])
cites rows of the flow timeline and becomes links to the flow table.
"""
from __future__ import annotations

import html
import re
from typing import Callable

CHART_RE = re.compile(r"^\W{0,3}\[\[\s*chart[\s:]*([\w-]+)\s*\]\]\W{0,3}$", re.I)
CHART_ANYWHERE_RE = re.compile(r"\[\[\s*chart[\s:]*([\w-]+)\s*\]\]", re.I)
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
BULLET_RE = re.compile(r"^(\s*)[-*+]\s+(.*)$")
NUMBERED_RE = re.compile(r"^(\s*)\d+[.)]\s+(.*)$")
TABLE_SEP_RE = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")
RULE_RE = re.compile(r"^\s*([-*_])(\s*\1){2,}\s*$")
FLOW_REF_RE = re.compile(r"\[\[\s*flows?\s*:?\s*([^\]]*?)\s*\]\]", re.I)
FLOW_ID_RE = re.compile(r"\bF(\d+)\b", re.I)


def inline(text: str) -> str:
    """Escape, then apply inline marks."""
    out = html.escape(text, quote=False)
    codes: list[str] = []

    def keep_code(m: re.Match) -> str:
        codes.append(m.group(1))
        return f"\x00{len(codes) - 1}\x00"

    out = re.sub(r"`([^`]+)`", keep_code, out)
    out = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"__(.+?)__", r"<strong>\1</strong>", out)
    out = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<em>\1</em>", out)
    out = re.sub(r"(?<![\w_])_(?!\s)(.+?)(?<!\s)_(?![\w_])", r"<em>\1</em>", out)
    out = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)",
                 lambda m: f'<a href="{m.group(2)}" rel="noopener noreferrer">{m.group(1)}</a>', out)
    # In-page links (a figure named inside a sentence); data-fig opens the figures section.
    out = re.sub(r"\[([^\]]+)\]\((#[\w-]+)\)", lambda m: f'<a href="{m.group(2)}" data-fig>{m.group(1)}</a>', out)
    return re.sub(r"\x00(\d+)\x00", lambda m: f"<code>{codes[int(m.group(1))]}</code>", out)


def _cells(line: str) -> list[str]:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return [c.strip() for c in line.split("|")]


def _table(lines: list[str]) -> str:
    head = _cells(lines[0])
    rows = [_cells(line) for line in lines[2:]]
    numeric = [all(re.fullmatch(r"[\d.,%\s]+(\s?[KMGT]?B)?", r[i]) for r in rows if i < len(r) and r[i])
               and any(i < len(r) and r[i] for r in rows) for i in range(len(head))]

    def cell(tag: str, text: str, i: int) -> str:
        cls = ' class="num"' if i < len(numeric) and numeric[i] else ""
        return f"<{tag}{cls}>{inline(text)}</{tag}>"

    out = ["<div class=\"table-wrap\"><table><thead><tr>"]
    out += [cell("th", h, i) for i, h in enumerate(head)]
    out.append("</tr></thead><tbody>")
    for r in rows:
        out.append("<tr>" + "".join(cell("td", c, i) for i, c in enumerate(r)) + "</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def _list(lines: list[str]) -> str:
    """Bullet or numbered list; items indented deeper become a nested list."""
    out: list[str] = []
    stack: list[tuple[int, str]] = []  # (indent, tag)
    for line in lines:
        m = BULLET_RE.match(line) or NUMBERED_RE.match(line)
        if not m:  # continuation of the previous item
            if out:
                out[-1] = out[-1].removesuffix("</li>") + " " + inline(line.strip()) + "</li>"
            continue
        indent = len(m.group(1).expandtabs(4))
        tag = "ul" if BULLET_RE.match(line) else "ol"
        if not stack or indent > stack[-1][0]:
            if stack and out and out[-1].endswith("</li>"):
                out[-1] = out[-1].removesuffix("</li>")  # nest inside the previous item
            stack.append((indent, tag))
            out.append(f"<{tag}>")
        else:
            while len(stack) > 1 and indent < stack[-1][0]:
                out.append(f"</{stack.pop()[1]}></li>")
        out.append(f"<li>{inline(m.group(2))}</li>")
    while stack:
        out.append(f"</{stack.pop()[1]}>" + ("</li>" if stack else ""))
    return "".join(out)


def isolate_charts(text: str, label: Callable[[str], str] | None = None) -> str:
    """Put each [[chart ...]] on a line of its own, so one written inside a
    sentence still becomes a figure reference, placed after the end of that
    paragraph. With `label`, a reference inside a sentence is replaced by its
    label (e.g. "Figure 2") so the sentence still reads ("Figure 2 shows ...")."""
    out: list[str] = []
    pending: list[str] = []
    for line in text.replace("\r\n", "\n").split("\n"):
        if not line.strip() and pending:
            out += ["", *pending]
            pending = []
        refs = CHART_ANYWHERE_RE.findall(line)
        if refs and not CHART_RE.match(line):
            if label:
                line = CHART_ANYWHERE_RE.sub(lambda m: label(m.group(1)) or "the chart", line).rstrip()
            else:
                line = CHART_ANYWHERE_RE.sub("", line).rstrip()
                pending += [f"[[chart {ref}]]" for ref in refs]
        out.append(line)
    if pending:
        out += ["", *pending]
    return "\n".join(out)


def flow_refs(text: str) -> list[str]:
    """Flow rows the text cites, e.g. ["F3", "F5"] (the ends of a range)."""
    return [f"F{n}" for inner in FLOW_REF_RE.findall(text) for n in FLOW_ID_RE.findall(inner)]


def replace_flow_refs(text: str, link: Callable[[str], str] | None = None) -> str:
    """[[flow F3-F5]] -> "F3-F5", each id passed through `link` (e.g. to a
    Markdown link to the table row)."""
    def ids(match: re.Match) -> str:
        return FLOW_ID_RE.sub(lambda m: link(f"F{m.group(1)}") if link else f"F{m.group(1)}", match.group(1))
    return FLOW_REF_RE.sub(ids, text)


def to_html(text: str, chart_html: Callable[[str], str] | None = None, heading_offset: int = 1,
            label: Callable[[str], str] | None = None, flow_link: Callable[[str], str] | None = None) -> str:
    """Markdown to HTML. Headings are shifted down by heading_offset (a '#'
    in the report becomes <h2> with the default) and capped at <h5>. A chart
    on its own line goes through chart_html; one inside a sentence through
    label (see isolate_charts). Flow ids cited with [[flow F3]] go through
    flow_link."""
    lines = isolate_charts(replace_flow_refs(text, flow_link), label).split("\n")
    out: list[str] = []
    paragraph: list[str] = []
    i = 0

    def flush() -> None:
        if paragraph:
            out.append("<p>" + inline(" ".join(s.strip() for s in paragraph)) + "</p>")
            paragraph.clear()

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            flush()
            i += 1
            continue
        if stripped.startswith("```"):
            flush()
            body = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                body.append(lines[i])
                i += 1
            out.append("<pre><code>" + html.escape("\n".join(body), quote=False) + "</code></pre>")
            i += 1
            continue
        chart = CHART_RE.match(line)
        if chart:
            flush()
            if chart_html:
                out.append(chart_html(chart.group(1)))
            i += 1
            continue
        heading = HEADING_RE.match(stripped)
        if heading:
            flush()
            level = min(len(heading.group(1)) + heading_offset, 5)
            out.append(f"<h{level}>{inline(heading.group(2))}</h{level}>")
            i += 1
            continue
        if RULE_RE.match(stripped):
            flush()
            out.append("<hr>")
            i += 1
            continue
        if "|" in stripped and i + 1 < len(lines) and TABLE_SEP_RE.match(lines[i + 1]):
            flush()
            block = [line, lines[i + 1]]
            i += 2
            while i < len(lines) and "|" in lines[i] and lines[i].strip():
                block.append(lines[i])
                i += 1
            out.append(_table(block))
            continue
        if BULLET_RE.match(line) or NUMBERED_RE.match(line):
            flush()
            block = []
            while i < len(lines) and lines[i].strip() and (
                    BULLET_RE.match(lines[i]) or NUMBERED_RE.match(lines[i]) or lines[i].startswith(("  ", "\t"))):
                block.append(lines[i])
                i += 1
            out.append(_list(block))
            continue
        if stripped.startswith(">"):
            flush()
            quote = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                quote.append(lines[i].strip()[1:].strip())
                i += 1
            out.append("<blockquote>" + to_html("\n".join(quote), chart_html, heading_offset) + "</blockquote>")
            continue
        paragraph.append(line)
        i += 1
    flush()
    return "\n".join(out)


def chart_refs(text: str) -> list[str]:
    """Chart ids the text places, in order."""
    return CHART_ANYWHERE_RE.findall(text)


# --- the report's four parts ------------------------------------------------------------

SECTION_TITLES = {"summary": "Executive summary", "analysis": "Analysis",
                  "conclusion": "Conclusion and next steps", "background": "Background"}
SECTION_HEADING_RE = re.compile(
    r"(?i)^\s*(?:#{1,2}\s*|\*\*)?\s*(?:\d+[.)]\s*)?(executive summary|summary|analysis|"
    r"conclusions?(?:\s*(?:and|&)\s*(?:recommended\s+)?next steps)?|(?:recommended\s+)?next steps|background)"
    r"\s*:?\s*(?:\*\*)?\s*:?\s*$")


def split_sections(report_text: str) -> dict[str, str]:
    """The report's four parts by their headings. Text before the first
    heading counts as the executive summary; a separate "Next steps" heading
    joins the conclusion."""
    parts: dict[str, list[str]] = {key: [] for key in SECTION_TITLES}
    current = "summary"
    for line in report_text.split("\n"):
        heading = SECTION_HEADING_RE.match(line)
        if heading:
            name = heading.group(1).lower()
            current = ("summary" if "summary" in name else "background" if name == "background"
                       else "analysis" if name == "analysis" else "conclusion")
            continue
        parts[current].append(line)
    return {key: "\n".join(lines).strip() for key, lines in parts.items()}

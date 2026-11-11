"""LaTeX (PDF) reports, in the style of the hand-written CyberShield reports:
a one-page main body (the model's four parts, compactly set: the Background's
parts as run-in labels), then an appendix of figures and tables that the body
refers to by number, closing with one paragraph of sources and limits.

  render_latex(result)          one case -> .tex source
  render_latex_summary(results) a batch overview: verdict table, one paragraph per case
  write_case_tex(result, dir)   the .tex plus its chart PDFs
  compile_tex(path)             latexmk -pdf, or tectonic; None (and a warning) without either
  tex_escape(text)              every piece of model or feed text goes through this

The report text is the model's own Markdown, converted here; code only lays
it out and writes the facts and tables, as in the HTML report. A chart the
model placed with [[chart X]] becomes "Figure N" (a \\ref to the appendix);
a flow row cited as [[flow F3]] becomes "F3 (Table N)", N being the flow table.

LaTeX notes: no \\usepackage[T1]{fontenc}, because with Computer Modern it
breaks microtype's font expansion ("auto expansion only possible with
scalable fonts"). Text is kept to ASCII plus LaTeX commands so pdflatex
needs no extra fonts.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import unicodedata
from datetime import UTC, datetime
from pathlib import Path

from . import charts as chart_tools
from . import casefile, config, evidence, mdrender, report

# --- escaping -------------------------------------------------------------------------

TEX_SPECIALS = {
    "\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#", "_": r"\_", "{": r"\{",
    "}": r"\}", "~": r"\textasciitilde{}", "^": r"\textasciicircum{}", "<": r"\ensuremath{<}",
    ">": r"\ensuremath{>}", "|": r"\textbar{}",
}
UNICODE_TEXT = {
    "\u2013": "--", "\u2014": "---", "\u2018": "`", "\u2019": "'", "\u201c": "``", "\u201d": "''",
    "\u2026": r"\ldots{}", "\u00a0": "~", "\u2192": r"\ensuremath{\rightarrow}", "\u2190": r"\ensuremath{\leftarrow}",
    "\u2194": r"\ensuremath{\leftrightarrow}", "\u2265": r"\ensuremath{\geq}", "\u2264": r"\ensuremath{\leq}",
    "\u2248": r"\ensuremath{\approx}", "\u00d7": r"\ensuremath{\times}", "\u00b1": r"\ensuremath{\pm}",
    "\u00b0": r"\ensuremath{^\circ}", "\u2022": r"\textbullet{}", "\u00b7": r"\ensuremath{\cdot}",
    "\u00b5": r"\ensuremath{\mu}", "\u2212": "-", "\u2010": "-", "\u2011": "-", "\u00a7": r"\S{}",
    "\u20ac": "EUR", "\u00a3": r"\pounds{}", "\u2032": "'", "\u2033": "''", "\u2122": "(TM)",
}
BREAK_AFTER = set("./:-_|=?&@")


def _ascii(char: str) -> str:
    """A character pdflatex can set without extra fonts: accents dropped,
    anything else unknown becomes '?'."""
    plain = unicodedata.normalize("NFKD", char).encode("ascii", "ignore").decode()
    return plain if plain else "?"


def tex_escape(text) -> str:
    """Plain text -> LaTeX that prints it literally."""
    out = []
    for char in str(text if text is not None else ""):
        if char in TEX_SPECIALS:
            out.append(TEX_SPECIALS[char])
        elif char in UNICODE_TEXT:
            out.append(UNICODE_TEXT[char])
        elif char in "\x01\x02":
            out.append(char)  # internal markers, replaced after escaping
        elif ord(char) < 32:
            out.append(" ")
        elif ord(char) < 128:
            out.append(char)
        else:
            out.append(tex_escape(_ascii(char)) if _ascii(char) != "?" else "?")
    return "".join(out)


def tex_code(text) -> str:
    """\\texttt{} with break points after . / : - and similar, so long IPs,
    domains and URLs wrap inside table cells."""
    parts = []
    for char in str(text if text is not None else ""):
        parts.append(tex_escape(char))
        if char in BREAK_AFTER:
            parts.append(r"\allowbreak{}")
    return r"\texttt{" + "".join(parts) + "}"


# --- Markdown (the model's report) -> LaTeX ----------------------------------------------

FIG = "\x01"   # \x01<n>\x01 -> Figure~\ref{fig:n}
FLOW = "\x02"  # \x02F3-F5\x02 -> F3-F5 (Table~\ref{tab:flows})
URL_OK_RE = re.compile(r"^https?://[\w.\-/:?=&%#+~@!,;]+$")
INLINE_RE = re.compile(
    r"`(?P<code>[^`]+)`"
    r"|\[(?P<ltext>[^\]]+)\]\((?P<url>[^)\s]+)\)"
    r"|\*\*(?P<bold>.+?)\*\*|__(?P<bold2>.+?)__"
    r"|(?<![\w*])\*(?!\s)(?P<it>.+?)(?<!\s)\*(?![\w*])"
    r"|(?<![\w_])_(?!\s)(?P<it2>.+?)(?<!\s)_(?![\w_])")


def _href(url: str, text: str) -> str:
    if not URL_OK_RE.match(url):
        return text
    safe = url.replace("\\", "").replace("%", r"\%").replace("#", r"\#").replace("&", r"\&")
    return rf"\href{{{safe}}}{{{text}}}"


def inline(text: str) -> str:
    """Escape, then apply **bold**, *italic*, `code` and [links](https://...)."""
    out, pos = [], 0
    for m in INLINE_RE.finditer(text):
        out.append(tex_escape(text[pos:m.start()]))
        if m.group("code") is not None:
            out.append(tex_code(m.group("code")))
        elif m.group("url") is not None:
            out.append(_href(m.group("url"), inline(m.group("ltext"))))
        elif m.group("bold") is not None or m.group("bold2") is not None:
            out.append(r"\textbf{" + inline(m.group("bold") or m.group("bold2")) + "}")
        else:
            out.append(r"\emph{" + inline(m.group("it") or m.group("it2")) + "}")
        pos = m.end()
    out.append(tex_escape(text[pos:]))
    return "".join(out)


class Refs:
    """Figure numbers and the flow table, for one case."""

    def __init__(self, result: dict):
        self.figures = {str(c["id"]): i + 1 for i, c in enumerate(result.get("charts") or [])}
        self.has_flows = bool(report.flow_rows(result))

    def chart(self, ref: str) -> str:
        return f"{FIG}{self.figures[ref]}{FIG}" if ref in self.figures else ""

    def flows(self, match: re.Match) -> str:
        """[[flow F3-F6]] -> a marker for 'F3-F6'; [[flow F3, F5]] -> 'F3, F5'."""
        inner = match.group(1)
        ids = [f"F{n}" for n in mdrender.FLOW_ID_RE.findall(inner)]
        if not ids:
            return ""
        is_range = len(ids) == 2 and re.search(r"[-\u2013\u2014]|\bto\b", inner)
        return FLOW + ("-".join(ids) if is_range else ", ".join(ids)) + FLOW

    def figures_note(self, numbers: list[int]) -> str:
        """'See Figure 2' or 'See Figures 1, 2 and 3', for charts placed on their own lines."""
        refs = [rf"\ref{{fig:{n}}}" for n in dict.fromkeys(numbers)]
        if len(refs) == 1:
            return rf"\emph{{(See Figure~{refs[0]}.)}}"
        return r"\emph{(See Figures~" + ", ".join(refs[:-1]) + " and " + refs[-1] + ".)}"

    def resolve(self, tex: str) -> str:
        tex = re.sub(f"{FIG}(\\d+){FIG}", lambda m: rf"Figure~\ref{{fig:{m.group(1)}}}", tex)
        table = r", Table~\ref{tab:flows}" if self.has_flows else ""

        def ids(text: str) -> str:
            return text.replace("-", "--")
        # Inside the writer's own brackets: "(F3)" -> "(F3, Table 1)"; elsewhere add the brackets.
        tex = re.sub(f"\\(\\s*{FLOW}([F0-9, -]+){FLOW}", lambda m: f"({ids(m.group(1))}{table}", tex)
        return re.sub(f"{FLOW}([F0-9, -]+){FLOW}", lambda m: f"({ids(m.group(1))}{table})", tex)


def _table(lines: list[str]) -> str:
    head = mdrender._cells(lines[0])
    rows = [mdrender._cells(line) for line in lines[2:]]
    spec = "@{}" + "Y" * len(head) + "@{}"
    body = [" & ".join(r"\textbf{" + inline(h) + "}" for h in head) + r" \\ \midrule"]
    for row in rows:
        cells = (row + [""] * len(head))[:len(head)]
        body.append(" & ".join(inline(c) for c in cells) + r" \\")
    return ("{\\small\n\\begin{tabularx}{\\linewidth}{" + spec + "}\n\\toprule\n"
            + "\n".join(body) + "\n\\bottomrule\n\\end{tabularx}\n}\n")


def _list(lines: list[str]) -> str:
    """Bullet or numbered list; deeper-indented items nest."""
    out, stack = [], []  # stack of (indent, environment)
    for line in lines:
        m = mdrender.BULLET_RE.match(line) or mdrender.NUMBERED_RE.match(line)
        if not m:
            if out:
                out[-1] += " " + inline(line.strip())
            continue
        indent = len(m.group(1).expandtabs(4))
        env = "itemize" if mdrender.BULLET_RE.match(line) else "enumerate"
        while stack and indent < stack[-1][0]:
            out.append(f"\\end{{{stack.pop()[1]}}}")
        if not stack or indent > stack[-1][0]:
            if len(stack) < 3:
                stack.append((indent, env))
                out.append(f"\\begin{{{env}}}")
        out.append(r"\item " + inline(m.group(2)))
    while stack:
        out.append(f"\\end{{{stack.pop()[1]}}}")
    return "\n".join(out)


class _Writer:
    """Collects LaTeX for md_to_latex: paragraphs, a pending run-in label
    ("The host:") and charts placed on their own lines (merged into one note)."""

    def __init__(self, refs: Refs):
        self.refs, self.out, self.paragraph, self.label, self.charts = refs, [], [], "", []

    def flush(self) -> None:
        if self.paragraph:
            self.out.append(self.label + inline(" ".join(s.strip() for s in self.paragraph)) + "\n")
            self.paragraph.clear()
            self.label = ""

    def flush_charts(self) -> None:
        if self.charts:
            self.out.append(self.refs.figures_note(self.charts) + "\n")
            self.charts.clear()

    def block(self, tex: str) -> None:
        self.flush()
        self.flush_charts()
        if self.label:  # a run-in label with no paragraph after it
            self.out.append(self.label.rstrip() + "\n")
            self.label = ""
        self.out.append(tex)


def md_to_latex(text: str, refs: Refs, run_in: bool = False) -> str:
    """The subset of Markdown a report uses, as LaTeX body text. With run_in,
    ### headings become bold labels at the start of the next paragraph, as in
    a compact report ("The host: ...")."""
    text = mdrender.FLOW_REF_RE.sub(refs.flows, text)
    lines = mdrender.isolate_charts(text, refs.chart).split("\n")
    w = _Writer(refs)
    i = 0
    while i < len(lines):
        line, stripped = lines[i], lines[i].strip()
        heading = mdrender.HEADING_RE.match(stripped)
        chart = mdrender.CHART_RE.match(line)
        if not stripped:
            w.flush()
            i += 1
        elif chart:
            w.flush()
            number = refs.figures.get(chart.group(1))
            if number:
                w.charts.append(number)
            i += 1
        elif heading and run_in and len(heading.group(1)) >= 3:
            w.block("")
            w.label = r"\textbf{" + inline(heading.group(2).rstrip(":")) + r":} "
            i += 1
        elif heading:
            w.block((r"\subsection*{" if len(heading.group(1)) <= 3 else r"\paragraph{")
                    + inline(heading.group(2)) + "}")
            i += 1
        elif mdrender.RULE_RE.match(stripped):
            w.flush()
            i += 1
        elif stripped.startswith("```"):
            block, i = [], i + 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                block.append(lines[i])
                i += 1
            w.block(r"\begin{quote}\small" + r"\\".join(tex_code(b) for b in block if b.strip()) + r"\end{quote}")
            i += 1
        elif "|" in stripped and i + 1 < len(lines) and mdrender.TABLE_SEP_RE.match(lines[i + 1]):
            block, i = [line, lines[i + 1]], i + 2
            while i < len(lines) and "|" in lines[i] and lines[i].strip():
                block.append(lines[i])
                i += 1
            w.block(_table(block))
        elif mdrender.BULLET_RE.match(line) or mdrender.NUMBERED_RE.match(line):
            block = []
            while i < len(lines) and lines[i].strip() and (
                    mdrender.BULLET_RE.match(lines[i]) or mdrender.NUMBERED_RE.match(lines[i])
                    or lines[i].startswith(("  ", "\t"))):
                block.append(lines[i])
                i += 1
            w.block(_list(block))
        elif stripped.startswith(">"):
            quote = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                quote.append(lines[i].strip()[1:].strip())
                i += 1
            w.block(r"\begin{quote}" + inline(" ".join(quote)) + r"\end{quote}")
        else:
            w.flush_charts()
            w.paragraph.append(line)
            i += 1
    w.block("")
    return refs.resolve("\n".join(t for t in w.out if t))


# --- the document ----------------------------------------------------------------------

PREAMBLE = r"""\documentclass[10pt,a4paper]{article}
\usepackage[a4paper,left=1.6cm,right=1.6cm,top=1.1cm,bottom=1.0cm]{geometry}
\usepackage{microtype}
\usepackage{graphicx}
\usepackage{booktabs}
\usepackage{tabularx}
\usepackage{array}
\usepackage{longtable}
\usepackage[table]{xcolor}
\usepackage{caption}
\usepackage{float}
\usepackage{titlesec}
\usepackage{enumitem}
\usepackage[colorlinks=true,urlcolor=blue,linkcolor=blue]{hyperref}

\pagestyle{empty}
\setlength{\parindent}{0pt}
\setlength{\parskip}{2pt}
\titleformat*{\section}{\large\bfseries}
\titleformat*{\subsection}{\normalsize\bfseries}
\titlespacing*{\section}{0pt}{6pt}{2pt}
\titlespacing*{\subsection}{0pt}{4pt}{1pt}
\captionsetup{font=small,labelfont=bf,skip=3pt}
\setlist{nosep,leftmargin=1.4em}
\renewcommand{\arraystretch}{1.18}
\newcolumntype{Y}{>{\raggedright\arraybackslash}X}
\newcolumntype{R}[1]{>{\raggedright\arraybackslash}p{#1}}
\newcolumntype{N}[1]{>{\raggedleft\arraybackslash}p{#1}}
\definecolor{flagged}{HTML}{FFF1CC}
\definecolor{muted}{HTML}{555555}
"""


def stem(result: dict) -> str:
    """File name stem for the case's .tex and figures: letters, digits and dashes
    only (graphicx misreads extra dots in a file name)."""
    return re.sub(r"[^A-Za-z0-9]+", "-", f"{result['indicator']}--{result['affected_asset']}").strip("-")


def figure_file(result: dict, number: int) -> str:
    return f"{stem(result)}-fig{number}.pdf"


def _title(result: dict) -> str:
    """The title and one line of facts: host, assessment, source, date."""
    host = ((result.get("evidence") or {}).get("host") or {}).get("hostname")
    host_text = tex_code(result["affected_asset"]) + (f" ({tex_code(host)})" if host else "")
    assessment = (r"\textbf{" + tex_escape(report._label(result.get("VERDICT"))) + "}"
                  + tex_escape(f" ({result.get('CONFIDENCE') or '-'} confidence)"))
    facts = [f"Host {host_text}", assessment, tex_escape(f"Source: {evidence.source_name(result)}"),
             tex_escape(f"{datetime.now(UTC):%d %b %Y}")]
    review = (r"\\{\small\textbf{Marked for analyst review:} see Table~\ref{tab:facts}.}"
              if result.get("needs_review") else "")
    return ("{\\LARGE\\bfseries IOC investigation: " + tex_code(result["indicator"]) + "\\par}\n\\vspace{1pt}\n"
            "{\\small " + r" \textperiodcentered{} ".join(facts) + review + "\\par}\n")


def _body(result: dict, refs: Refs) -> str:
    parts = report._parts(result)
    out = []
    for key, heading in report.SECTIONS:
        text = (parts.get(key) or "").strip()
        if text:
            out.append(r"\section*{" + tex_escape(heading) + "}\n" + md_to_latex(text, refs, run_in=key == "background"))
    return "\n".join(out) or r"\emph{No written analysis.}"


def _figures(result: dict) -> str:
    out = []
    for number, chart in enumerate(result.get("charts") or [], start=1):
        extra = " ".join(filter(None, [chart.get("caption") or "", *chart_tools.notes(chart)]))
        if chart.get("source"):
            extra += f" Source: {chart['source']}."
        out.append("\\begin{figure}[H]\n\\centering\n"
                   f"\\includegraphics[width=\\textwidth]{{{figure_file(result, number)}}}\n"
                   f"\\caption{{{tex_escape(chart['title'])}. {tex_escape(extra.strip())}}}\n"
                   f"\\label{{fig:{number}}}\n\\end{{figure}}")
    return "\n".join(out)


def tex_break(text) -> str:
    """Plain text that may break after . / - (long domain names in table cells)."""
    out = []
    for char in str(text if text is not None else ""):
        out.append(tex_escape(char))
        if char in "./":
            out.append(r"\allowbreak{}")
    return "".join(out)


def short_remote(remote: str) -> str:
    """The flow table's remote description without its "seen as ..." name list."""
    return "; ".join(p for p in str(remote or "").split("; ") if not p.startswith("seen as "))


FLOW_SPEC = "@{}R{0.7cm}R{2.0cm}R{3.0cm}N{1.25cm}N{1.25cm}R{4.3cm}R{3.4cm}@{}"
FLOW_HEAD = ("\\#", "Time (UTC)", "Connection", "Up", "Down", "Remote", "Likely connection")


def _episode_line(ep: dict, n) -> str:
    start, end = str(ep.get("start") or "")[:16], str(ep.get("end") or "")[:16]
    when = start.replace("T", " ")
    if end and end != start:
        when += f" to {end[11:]}" if end[:10] == start[:10] else f" to {end.replace('T', ' ')}"
    return (r"\multicolumn{7}{@{}l}{\cellcolor{gray!10}\textbf{"
            + tex_escape(f"Contact episode {n}: {when} UTC") + r"}} \\")


def _flows_table(result: dict) -> str:
    rows = report.flow_rows(result)
    if not rows:
        return ""
    timeline = (result.get("evidence") or {}).get("timeline") or {}
    episodes = {ep["n"]: ep for ep in timeline.get("episodes", [])}
    head = " & ".join(r"\textbf{" + h + "}" for h in FLOW_HEAD) + r" \\"
    body, current = [], None
    for row in rows:
        if row["episode"] != current:
            current = row["episode"]
            body.append(_episode_line(episodes.get(current) or {}, current))
        colour = r"\rowcolor{flagged}" if row["flagged"] else ""
        cells = [row["id"], tex_escape(row["clock"]) + r"\newline{\color{muted}" + tex_escape(row["duration"]) + "}",
                 tex_code(row["to"]), r"\mbox{" + tex_escape(row["up"]) + "}",
                 r"\mbox{" + tex_escape(row["down"]) + "}", tex_break(short_remote(row["remote"])),
                 tex_escape(row["likely"]) or "--"]
        body.append(colour + " & ".join(cells) + r" \\")
    caption = ("Flows around the flagged contact: the host's traffic from a few minutes before to just after each "
               "contact (per-minute flow records), one row per site and one per flagged address (shaded). Likely "
               "connection is the analysis's reading of each row.")
    return ("{\\footnotesize\\setlength{\\tabcolsep}{4pt}\n\\begin{longtable}{" + FLOW_SPEC + "}\n"
            f"\\caption{{{tex_escape(caption)}}}\\label{{tab:flows}}\\\\\n\\toprule\n{head}\n\\midrule\n"
            "\\endfirsthead\n\\toprule\n" + head + "\n\\midrule\n\\endhead\n\\bottomrule\n\\endfoot\n"
            + "\n".join(body) + "\n\\end{longtable}\n}")


def _facts_table(result: dict) -> str:
    rows = [("Assessment", f"{report._label(result.get('VERDICT'))}, {result.get('CONFIDENCE') or '-'} confidence")]
    rows += report.fact_rows(result)
    check = report._cross_check(result)
    if check:
        rows.append(("Cross-check", check))
    if result.get("needs_review"):
        rows += [("Needs review", note) for note in report._review_notes(result)] or [("Needs review", "yes")]
    body = "\n".join(r"\textbf{" + tex_escape(k) + "} & " + tex_break(v) + r" \\" for k, v in rows)
    return ("\\begin{table}[H]\n\\small\n\\caption{Case facts.}\\label{tab:facts}\n"
            "\\begin{tabularx}{\\textwidth}{@{}R{3.6cm}Y@{}}\n\\toprule\n" + body
            + "\n\\bottomrule\n\\end{tabularx}\n\\end{table}")


def sources(result: dict) -> list[tuple[str, str | None]]:
    """(text, url) items for the Sources line: the indicator's source and its
    references, public threat intel looked up online, the threat description's
    references, and the data used."""
    items: list[tuple[str, str | None]] = []
    event = f", event {result['intel_event_id']}" if result.get("intel_event_id") else ""
    items.append((f"indicator source {evidence.source_name(result)}{event}", None))
    for url in result.get("intel_references") or []:
        items.append(("source reference", url))
    ev = result.get("evidence") or {}
    for found in (ev.get("web_context") or {}).get("sources") or []:
        items.append((found["name"], found["url"]))
    briefing = (ev.get("expected") or {}).get("briefing") or {}
    if briefing:
        items.append((f"analyst-supplied threat description ({briefing.get('name', '')})", None))
        for url in briefing.get("references") or []:
            items.append(("reference in the threat description", url))
    items.append(("SuperNetFlow per-minute activity (subscriber_activity_1m), long flows over 1 MB "
                  "(long_flow_summary) and hourly host load", None))
    return items


def _sources(result: dict) -> str:
    """The closing paragraph: sources (linked) and the data's limits."""
    parts = []
    for text, url in sources(result):
        parts.append(_href(url, tex_escape(text)) if url and URL_OK_RE.match(url) else tex_escape(text))
    calls = len(result.get("tool_calls") or [])
    limits = list(casefile.DATA_LIMITATIONS)
    if calls:
        limits.append(f"{calls} follow-up quer{'y' if calls == 1 else 'ies'} ran during the investigation.")
    return ("\\par\\medskip{\\small\\textbf{Sources:} " + "; ".join(parts) + ". \\textbf{Limits:} "
            + tex_escape(" ".join(limits)) + "\\par}")


def render_latex(result: dict) -> str:
    """One case as a LaTeX document: a one-page body, then the appendix."""
    refs = Refs(result)
    appendix = ["\\clearpage", "{\\Large\\bfseries Appendix\\par}", "\\vspace{4pt}"]
    figures = _figures(result)
    if figures:
        appendix.append(figures)
    flows = _flows_table(result)
    if flows:
        appendix += ["\\clearpage" if figures else "", flows]  # the long table starts on a page of its own
    appendix += [_facts_table(result), _sources(result)]
    return (PREAMBLE + "\\begin{document}\n\n" + _title(result) + "\n" + _body(result, refs) + "\n\n"
            + "\n\n".join(appendix) + "\n\n\\end{document}\n")


def render_latex_summary(results: list[dict]) -> str:
    """The batch: a verdict table, then one paragraph per case (the model's
    executive summary, or its headline)."""
    ordered = sorted(results, key=lambda r: (report.VERDICT_ORDER.get(r.get("VERDICT"), 1), not r.get("needs_review")))
    head = r"\textbf{\#} & \textbf{Indicator} & \textbf{Host} & \textbf{Assessment} & \textbf{Review} \\"
    rows = []
    for n, r in enumerate(ordered, start=1):
        rows.append(" & ".join([str(n), tex_code(r["indicator"]), tex_code(r["affected_asset"]),
                                tex_escape(f"{report._label(r.get('VERDICT'))} ({r.get('CONFIDENCE') or '-'})"),
                                "yes" if r.get("needs_review") else ""]) + r" \\")
    cases = []
    for n, r in enumerate(ordered, start=1):
        text = (report._parts(r).get("summary") or r.get("HEADLINE") or "").strip()
        text = mdrender.CHART_ANYWHERE_RE.sub("", mdrender.replace_flow_refs(text))
        cases.append(r"\subsection*{" + f"{n}. " + tex_code(r["indicator"]) + r" $\rightarrow$ "
                     + tex_code(r["affected_asset"]) + "}\n" + inline(" ".join(text.split())))
    org = f"{config.ORG_NAME} " if config.ORG_NAME else ""
    return (PREAMBLE + "\\begin{document}\n{\\LARGE\\bfseries " + tex_escape(f"{org}IOC investigation summary")
            + "\\par}\n\\vspace{1pt}\n{\\small "
            + tex_escape(f"{len(results)} case(s), generated {datetime.now(UTC):%d %b %Y %H:%M} UTC") + "\\par}\n"
            "\\begin{table}[H]\n\\small\n\\caption{Cases, most serious first.}\\label{tab:cases}\n"
            "\\begin{tabularx}{\\textwidth}{@{}R{0.5cm}YR{4.2cm}R{4.4cm}R{1.2cm}@{}}\n\\toprule\n" + head
            + "\n\\midrule\n" + "\n".join(rows) + "\n\\bottomrule\n\\end{tabularx}\n\\end{table}\n"
            + "\n\n".join(cases) + "\n\\end{document}\n")


# --- files and compiling ----------------------------------------------------------------

def write_case_tex(result: dict, folder: Path) -> Path:
    """The case's .tex and one PDF per chart, side by side in `folder`."""
    folder.mkdir(parents=True, exist_ok=True)
    for number, chart in enumerate(result.get("charts") or [], start=1):
        chart_tools.chart_pdf(chart, folder / figure_file(result, number))
    path = folder / f"{stem(result)}.tex"
    path.write_text(render_latex(result), encoding="utf-8")
    return path


def tex_engine() -> list[str] | None:
    """The command to compile with: latexmk -pdf, else tectonic, else None."""
    if shutil.which("latexmk"):
        return ["latexmk", "-pdf", "-interaction=nonstopmode", "-halt-on-error"]
    if shutil.which("tectonic"):
        return ["tectonic", "--chatter", "minimal"]
    return None


def compile_tex(path: Path, timeout: int = 240) -> Path | None:
    """Compile a .tex in its own folder. Returns the PDF, or None (with a
    printed warning) if there is no TeX engine or the compile fails. Never raises."""
    engine = tex_engine()
    if not engine:
        print(f"  warning: no TeX engine (latexmk or tectonic) found; wrote {path.name} only.")
        return None
    try:
        done = subprocess.run(engine + [path.name], cwd=path.parent, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"  warning: compiling {path.name} failed ({type(exc).__name__}).")
        return None
    pdf = path.with_suffix(".pdf")
    if done.returncode != 0 or not pdf.exists():
        tail = "\n    ".join((done.stdout + done.stderr).strip().splitlines()[-8:])
        print(f"  warning: compiling {path.name} failed:\n    {tail}")
        return None
    if engine[0] == "latexmk":
        subprocess.run(["latexmk", "-c", path.name], cwd=path.parent, capture_output=True)
    return pdf


def main() -> None:
    """Rebuild the PDFs for saved results (e.g. a run made before a TeX engine
    was installed) without running the model again:

        python -m agent.latex output/assessments.json     # -> output/cases/*.pdf, output/summary.pdf
    """
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Write and compile the LaTeX reports for saved results.")
    parser.add_argument("assessments", type=Path, help="an assessments.json written by assess.py")
    args = parser.parse_args()
    data = json.loads(args.assessments.read_text(encoding="utf-8"))
    results = [r for r in (data["results"] if isinstance(data, dict) else data) if r.get("VERDICT") != "ERROR"]
    cases = args.assessments.parent / "cases"
    made = [compile_tex(write_case_tex(r, cases)) for r in results]
    summary = args.assessments.parent / "summary.tex"
    summary.write_text(render_latex_summary(results), encoding="utf-8")
    compile_tex(summary)
    print(f"{sum(1 for m in made if m)} of {len(results)} case PDF(s) compiled in {cases}/")


if __name__ == "__main__":
    main()

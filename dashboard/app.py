"""Stand demo: a threat board of investigated cases, and how the pipeline works.

    streamlit run dashboard/app.py
    ANONYMISE=1 streamlit run dashboard/app.py    # anonymised: Host A, role labels, site kinds
    DEMO_ONLY=1 streamlit run dashboard/app.py    # the stand: anonymised, no Live mode, no Try it tab

Tabs: Threat board (counts, recent cases, the latest public threat intel),
How it works (the pipeline, replayed step by step) and Try it (indicators and
a threat description in; a report out). The sidebar's feed checklist filters
the board; in live mode it also picks the feeds a pull matches against.

Demo mode (the default) shows recorded cases and the intel snapshot saved with
them, and makes no network calls. Live mode needs ClickHouse and the model.
By default it shows real details: output/assessments.json and the PDFs that
assess.py --pdf wrote next to it. With ANONYMISE=1, and always with
DEMO_ONLY=1, everything goes through demo/anonymise.py first and it reads
demo/bundle/ (or the fake sample in demo/sample/).
"""
from __future__ import annotations

import html
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402
import streamlit.components.v1 as components  # noqa: E402

from agent import config, evidence, latex, mdrender, misp_feed, report  # noqa: E402
from demo import anonymise, latest_intel  # noqa: E402

OUTPUT_DIR = ROOT / "output"
LIVE_DIR = OUTPUT_DIR / "stand_live"
LIVE_BUNDLE = LIVE_DIR / "anonymised"      # what may be shown from a live run
STATIC_DIR = Path(__file__).resolve().parent / "static"  # served at app/static/ (server.enableStaticServing)
MAX_PDF_PAGES = 8
# (key, title, what happens, seconds in a replay)
STEPS = [
    ("feed", "Threat feed", "MISP, ThreatFox or an analyst's indicators and threat description", 1.0),
    ("match", "Match", "campus hosts that contacted an indicator, from flow records", 1.5),
    ("evidence", "Evidence", "the host's traffic, the flagged address, other campus hosts", 3.0),
    ("agent", "Agent", "the model investigates with its own queries and writes the report", 6.0),
    ("checks", "Checks", "code checks every number and claim against the evidence", 1.5),
    ("report", "Report", "HTML and PDF report for the security team", 1.0),
]
VERDICT_COLOURS = {"LIKELY_THREAT": "#c0392b", "SUSPICIOUS": "#d68910", "LIKELY_FALSE_POSITIVE": "#1e8449",
                   "INSUFFICIENT_DATA": "#7f8c8d"}
CSS = """<style>
.pipe{display:flex;flex-wrap:wrap;gap:6px;align-items:stretch;margin:8px 0 16px}
.step{flex:1 1 130px;border:2px solid #d5d8dc;border-radius:10px;padding:10px;background:#fbfcfc;color:#1c2833}
.step b{display:block;font-size:15px}.step span{font-size:12.5px;color:#566573}
.step.active{border-color:#2a78d6;background:#eaf2fc;box-shadow:0 0 0 3px #2a78d633}
.step.done{border-color:#1e8449;background:#eafaf1}
.arrow{align-self:center;color:#aab7b8;font-size:20px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;color:#fff;font-weight:600;font-size:13px}
.headline{font-size:15px;margin:4px 0 8px}
</style>"""


def anonymised() -> bool:
    """Anonymise what is shown: always at the stand (DEMO_ONLY), else only with ANONYMISE=1."""
    return config.ANONYMISE or config.DEMO_ONLY


# --- plain text from the model's Markdown ------------------------------------------------

MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")


def plain(text) -> str:
    """A headline or summary without Markdown marks: no backticks, ** or __,
    links reduced to their text, chart and flow markers dropped."""
    text = mdrender.replace_flow_refs(str(text or ""))
    text = mdrender.CHART_ANYWHERE_RE.sub("", text)
    text = MD_LINK_RE.sub(r"\1", text)
    text = text.replace("`", "").replace("**", "").replace("__", "")
    text = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"\1", text)  # *italic*
    return " ".join(text.lstrip("# ").split())


# --- reading cases ----------------------------------------------------------------------

def case_time(result: dict) -> datetime | None:
    value = result.get("evidence_first_seen") or result.get("evidence_last_seen")
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment.replace(tzinfo=None) if moment.tzinfo else moment


def source_of(result: dict) -> str:
    """MISP, ThreatFox or manual entry (results saved before the intel block were ThreatFox)."""
    source = result.get("intel_source") or ("threatfox" if "threatfox_confidence" in result else "")
    return evidence.SOURCE_NAMES.get(source, source or "unknown")


def feed_of(result: dict) -> str:
    """The case's feed as the checklist lists it: "ThreatFox", "Phishing feeds", a MISP feed's name, ..."""
    feed = result.get("intel_feed")
    if not feed:
        source = result.get("intel_source") or ("threatfox" if "threatfox_confidence" in result else "")
        feed = {"threatfox": misp_feed.THREATFOX_FEED, "manual": misp_feed.MANUAL_FEED}.get(source, "Unknown feed")
    return misp_feed.feed_group(misp_feed.feed_name(feed))


def newest_first(results: list[dict]) -> list[dict]:
    return sorted(results, key=lambda r: case_time(r) or datetime.min, reverse=True)


def case_table(results: list[dict]) -> pd.DataFrame:
    rows = []
    for r in results:
        when = case_time(r)
        rows.append({"When (UTC)": when.strftime("%Y-%m-%d %H:%M") if when else "",
                     "Verdict": report._label(r.get("VERDICT")), "Indicator": str(r.get("indicator") or ""),
                     "Host": str(r.get("affected_asset") or ""), "Threat type": r.get("threat_type") or "unknown",
                     "Malware": r.get("malware") or "", "Feed": feed_of(r), "Source": source_of(r),
                     "Review": "yes" if r.get("needs_review") else "", "Headline": plain(r.get("HEADLINE"))})
    return pd.DataFrame(rows)


def _read(path: Path) -> list[dict]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    results = data["results"] if isinstance(data, dict) else data
    return [r for r in results if r.get("VERDICT") != "ERROR"]


def load_cases(live: bool, anonymise_on: bool) -> tuple[list[dict], Path, Path]:
    """(results, the folder holding their PDFs, the folder with an intel snapshot).
    Anonymised: a live run's anonymised results, else the recorded bundle.
    Real (the default): assess.py's own output and the PDFs it compiled."""
    if anonymise_on:
        if live and (LIVE_BUNDLE / "results.json").exists():
            return _read(LIVE_BUNDLE / "results.json"), LIVE_BUNDLE / "pdf", LIVE_BUNDLE
        results, folder = anonymise.load_bundle()
        return results, folder / "pdf", folder
    source = LIVE_DIR if live else OUTPUT_DIR
    return _read(source / "assessments.json"), source / "cases", anonymise.load_bundle()[1]


def load_snapshot(live: bool, folder: Path) -> dict | None:
    """The newest intel snapshot: a live refresh, else the one saved with the bundle (public data either way)."""
    if live and (LIVE_DIR / "intel.json").exists():
        return latest_intel.load(LIVE_DIR)
    return latest_intel.load(folder) or latest_intel.load(anonymise.BUNDLE_DIR) or latest_intel.load(
        anonymise.SAMPLE_DIR)


# --- feeds -------------------------------------------------------------------------------

def snapshot_feeds(snapshot: dict | None) -> set[str]:
    if not snapshot:
        return set()
    feeds = {misp_feed.feed_group(misp_feed.feed_name(e["info"])) for e in snapshot.get("misp_events") or []}
    if snapshot.get("threatfox"):
        feeds.add(misp_feed.THREATFOX_FEED)
    return feeds


@st.cache_data(ttl=600, show_spinner=False)
def misp_feeds() -> list[str]:
    """Live mode: every feed the local MISP holds, by its events' titles."""
    events = misp_feed.client().search_index(sort="date", desc=True, limit=500, pythonify=False)
    if isinstance(events, dict):
        raise RuntimeError(str(events.get("errors")))
    return sorted({misp_feed.feed_group(misp_feed.feed_name(e.get("info"))) for e in events})


def feed_counts(results: list[dict], extra: set[str]) -> dict[str, int]:
    """{feed: cases}, ThreatFox and phishing first, manual entries last."""
    counts = {name: 0 for name in extra}
    for r in results:
        counts[feed_of(r)] = counts.get(feed_of(r), 0) + 1
    first = [misp_feed.THREATFOX_FEED, misp_feed.PHISHING_GROUP]

    def order(name: str):
        return (first.index(name) if name in first else 2 if name != misp_feed.MANUAL_FEED else 3, name.lower())
    return {name: counts[name] for name in sorted(counts, key=order)}


def feed_checklist(counts: dict[str, int], live: bool) -> set[str]:
    st.sidebar.markdown("**Feeds**")
    st.sidebar.caption("Which feeds to pull from (live) and show." if live else "Which feeds to show.")
    return {name for name, n in counts.items()
            if st.sidebar.checkbox(f"{name} ({n})", value=True, key=f"feed-{name}")}


def filter_intel(snapshot: dict | None, feeds: set[str]) -> dict | None:
    """The snapshot with only the chosen feeds' families and events."""
    if not snapshot:
        return snapshot
    events = [e for e in snapshot.get("misp_events") or []
              if misp_feed.feed_group(misp_feed.feed_name(e["info"])) in feeds]
    families = snapshot.get("threatfox") if misp_feed.THREATFOX_FEED in feeds else []
    return {**snapshot, "misp_events": events, "threatfox": families}


# --- pieces ---------------------------------------------------------------------------

def pipeline_html(active: str | None = None, done: set[str] | None = None) -> str:
    done = done or set()
    parts = []
    for i, (key, title, what, _) in enumerate(STEPS):
        css = "step active" if key == active else "step done" if key in done else "step"
        parts.append(f"<div class='{css}'><b>{i + 1}. {html.escape(title)}</b><span>{html.escape(what)}</span></div>")
    return CSS + "<div class='pipe'>" + "<div class='arrow'>&rarr;</div>".join(parts) + "</div>"


def badge(verdict: str) -> str:
    colour = VERDICT_COLOURS.get(verdict, "#7f8c8d")
    return f"<span class='badge' style='background:{colour}'>{html.escape(report._label(verdict))}</span>"


def replay(placeholder, log, result: dict, speed: float) -> None:
    """Step through the pipeline for one recorded case, with realistic timing."""
    done: set[str] = set()
    lines = []
    notes = {
        "feed": f"Indicator {result['indicator']} from {feed_of(result)} ({result.get('malware') or 'unknown family'})",
        "match": f"Contact found: {result['affected_asset']}",
        "evidence": "Flow records, host traffic, campus-wide checks gathered",
        "agent": f"Model's verdict: {report._label(result.get('model_verdict') or result.get('VERDICT'))}",
        "checks": "Numbers and claims checked" + (" - marked for review" if result.get("needs_review") else ""),
        "report": f"Report written: {report._label(result.get('VERDICT'))}, {result.get('CONFIDENCE')} confidence",
    }
    for key, title, _, seconds in STEPS:
        placeholder.markdown(pipeline_html(key, done), unsafe_allow_html=True)
        lines.append(f"{title}: ...")
        log.code("\n".join(lines))
        time.sleep(seconds / speed)
        lines[-1] = f"{title}: {notes[key]}"
        done.add(key)
    placeholder.markdown(pipeline_html(None, done), unsafe_allow_html=True)
    log.code("\n".join(lines))


# --- PDFs ------------------------------------------------------------------------------------

def served_name(pdf: Path, anonymise_on: bool) -> str:
    """The file's name under static/: real reports are kept apart (and removed
    whenever the app runs anonymised)."""
    prefix = "anon" if anonymise_on else "real"
    return f"{prefix}-{pdf.parent.parent.name}-{pdf.name}"


def serve_pdf(pdf: Path, anonymise_on: bool) -> str:
    """Copy the PDF into static/ and return its URL (opens in its own tab)."""
    STATIC_DIR.mkdir(exist_ok=True)
    target = STATIC_DIR / served_name(pdf, anonymise_on)
    if not target.exists() or target.stat().st_mtime < pdf.stat().st_mtime:
        shutil.copy2(pdf, target)
    return f"app/static/{target.name}"


def tidy_static(anonymise_on: bool) -> None:
    """Running anonymised, nothing real may stay servable."""
    if anonymise_on and STATIC_DIR.exists():
        for path in STATIC_DIR.glob("real-*"):
            path.unlink()


@st.cache_data(show_spinner=False, max_entries=20)
def pdf_pages(path: str, modified: float) -> list[bytes]:
    """The PDF's first pages as PNG images (pypdfium2), for browsers without a viewer."""
    import io

    import pypdfium2

    doc = pypdfium2.PdfDocument(path)
    pages = []
    for i in range(min(len(doc), MAX_PDF_PAGES)):
        image = doc[i].render(scale=1.6).to_pil()
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        pages.append(buffer.getvalue())
    doc.close()
    return pages


def pdf_viewer(pdf: Path) -> None:
    """st.pdf where this Streamlit has it (it needs the streamlit-pdf package), else page images."""
    if hasattr(st, "pdf") and importlib.util.find_spec("streamlit_pdf"):
        st.pdf(str(pdf), height=800)
        return
    if not importlib.util.find_spec("pypdfium2"):
        st.caption("Install pypdfium2 (requirements-demo.txt) to view the PDF here; use Open PDF meanwhile.")
        return
    pages = pdf_pages(str(pdf), pdf.stat().st_mtime)
    for page in pages:
        st.image(page, use_container_width=True)
    if len(pages) == MAX_PDF_PAGES:
        st.caption(f"First {MAX_PDF_PAGES} pages; open the PDF for the rest.")


def show_case(result: dict, pdf_dir: Path, anonymise_on: bool) -> None:
    """The report (with its charts and flow table), the PDF and the downloads."""
    st.html(f"{CSS}<div class='headline'>{badge(result.get('VERDICT', ''))} &nbsp; "
            f"<b>{html.escape(plain(result.get('HEADLINE')))}</b></div>")
    if result.get("sample"):
        st.caption("Illustrative sample case on fake data.")
    stem = latex.stem(result)
    pdf = pdf_dir / f"{stem}.pdf"
    cols = st.columns(4)
    if pdf.exists():
        cols[0].link_button("Open PDF", serve_pdf(pdf, anonymise_on))
        cols[1].download_button("Download PDF", pdf.read_bytes(), file_name=pdf.name, mime="application/pdf",
                                key=f"pdf-{pdf_dir}-{stem}")
    else:
        cols[0].caption("No PDF for this case (no TeX engine when it was built).")
    cols[2].download_button("Markdown", report.render_markdown(result), file_name=f"{stem}.md",
                            key=f"md-{pdf_dir}-{stem}")
    cols[3].download_button("LaTeX", latex.render_latex(result), file_name=f"{stem}.tex",
                            key=f"tex-{pdf_dir}-{stem}")
    report_tab, pdf_tab = st.tabs(["Report", "PDF"])
    with report_tab:
        components.html(report.render([result]), height=900, scrolling=True)
    with pdf_tab:
        if pdf.exists():
            pdf_viewer(pdf)
        else:
            st.caption("No PDF for this case.")


def pick_case(results: list[dict], indicators: list[str]) -> dict:
    """The recorded case for an entered indicator, else the newest one."""
    wanted = {i.strip().lower() for i in indicators if i.strip()}
    ordered = newest_first(results)
    return next((r for r in ordered if str(r["indicator"]).lower() in wanted), ordered[0])


# --- Threat board ----------------------------------------------------------------------------

def summary_counts(results: list[dict]) -> dict:
    """Cases in the week up to the newest case, verdict counts and the top threat types."""
    times = [t for t in (case_time(r) for r in results) if t]
    newest = max(times) if times else None
    week = [r for r in results if newest and case_time(r) and case_time(r) > newest - timedelta(days=7)]
    verdicts = {v: sum(1 for r in results if r.get("VERDICT") == v) for v in VERDICT_COLOURS}
    types = pd.Series([r.get("threat_type") or "unknown" for r in results], dtype=object).value_counts()
    return {"newest": newest, "week": len(week), "total": len(results), "verdicts": verdicts,
            "review": sum(1 for r in results if r.get("needs_review")), "top_types": list(types.head(3).items())}


def board_summary(results: list[dict]) -> None:
    counts = summary_counts(results)
    cols = st.columns(5)
    week_end = f"7 days to {counts['newest']:%d %b %Y}" if counts["newest"] else ""
    cols[0].metric("Cases this week", counts["week"], help=f"{week_end}; {counts['total']} in all")
    cols[1].metric("Likely threats", counts["verdicts"]["LIKELY_THREAT"])
    cols[2].metric("Suspicious", counts["verdicts"]["SUSPICIOUS"])
    cols[3].metric("False positives", counts["verdicts"]["LIKELY_FALSE_POSITIVE"])
    cols[4].metric("Need review", counts["review"])
    top = " · ".join(f"{name} ({n})" for name, n in counts["top_types"])
    st.caption(f"Top threat types: {top or 'none'}" + (f" · week = {week_end}" if week_end else ""))


def board_table(results: list[dict], pdf_dir: Path, anonymise_on: bool) -> None:
    ordered = newest_first(results)
    table = case_table(ordered)
    cols = st.columns(3)
    verdicts = cols[0].multiselect("Verdict", sorted(table["Verdict"].unique()), key="f-verdict")
    types = cols[1].multiselect("Threat type", sorted(table["Threat type"].unique()), key="f-type")
    sources = cols[2].multiselect("Source", sorted(table["Source"].unique()), key="f-source")
    keep = pd.Series(True, index=table.index)
    for column, chosen in (("Verdict", verdicts), ("Threat type", types), ("Source", sources)):
        if chosen:
            keep &= table[column].isin(chosen)
    shown = table[keep]
    st.caption(f"{len(shown)} of {len(table)} case(s), newest first. Click a row to open its report.")
    picked = st.dataframe(shown, hide_index=True, use_container_width=True, on_select="rerun",
                          selection_mode="single-row", key="board-table")
    rows = picked.selection.rows if picked else []
    if rows:
        show_case(ordered[shown.index[rows[0]]], pdf_dir, anonymise_on)


def intel_panel(snapshot: dict | None, live: bool, feeds: set[str]) -> None:
    st.subheader("Latest threat intel")
    if live and st.button("Refresh from ThreatFox and MISP"):
        latest_intel.save(latest_intel.fetch_snapshot(), LIVE_DIR)
        st.rerun()
    if not snapshot:
        st.caption("No snapshot in this bundle. Build one with: python -m demo.anonymise output/assessments.json")
        return
    snapshot = filter_intel(snapshot, feeds)
    note = " (illustrative sample)" if snapshot.get("sample") else ""
    st.caption(f"Public data only, taken {snapshot.get('taken_at', '?')}{note}; the feeds ticked in the sidebar.")
    families = snapshot.get("threatfox") or []
    if families:
        st.markdown("**Newest ThreatFox malware families**")
        st.dataframe(pd.DataFrame([{"Family": f["family"], "IOCs": f["iocs"],
                                    "Threat type": ", ".join(f["threat_types"]),
                                    "Last seen (UTC)": f["last_seen"][:16]} for f in families]),
                     hide_index=True, use_container_width=True)
    events = snapshot.get("misp_events") or []
    if events:
        st.markdown("**Newest MISP events**")
        st.dataframe(pd.DataFrame([{"Date": e["date"], "Feed": misp_feed.feed_name(e["info"]),
                                    "Attributes": e["attributes"], "Published by": e["org"]} for e in events]),
                     hide_index=True, use_container_width=True)
    if not families and not events:
        st.caption("Nothing from the ticked feeds in this snapshot.")
    for error in snapshot.get("errors") or []:
        st.caption(f"Not available: {error[:120]}")


def threat_board(results: list[dict], pdf_dir: Path, snapshot: dict | None, live: bool, feeds: set[str],
                 anonymise_on: bool) -> None:
    if live:
        live_pull(feeds, anonymise_on)
    if not results:
        st.info("No cases from the ticked feeds. Build a bundle with: python -m demo.anonymise output/assessments.json")
    else:
        board_summary(results)
    left, right = st.columns([3, 2])
    with left:
        st.subheader("Recent cases")
        if results:
            board_table(results, pdf_dir, anonymise_on)
    with right:
        intel_panel(snapshot, live, feeds)


# --- live mode -------------------------------------------------------------------------

class Progress:
    """The pipeline picture and a running log, for live runs."""

    def __init__(self, placeholder, log, anonymise_on: bool):
        self.placeholder, self.log, self.lines = placeholder, log, []
        self.hide = anonymise.Anonymiser() if anonymise_on else None  # the log can name campus hosts

    def say(self, text: str, step: str | None, done: set[str]) -> None:
        self.lines.append(self.hide.text(text) if self.hide else text)
        self.log.code("\n".join(self.lines[-30:]))
        self.placeholder.markdown(pipeline_html(step, done), unsafe_allow_html=True)


def run_assess(records: list[dict], limit: int, progress: Progress, anonymise_on: bool) -> list[dict]:
    """assess.py --pdf on the records; with anonymisation on, the results anonymised (with their PDFs)."""
    from agent import matcher

    feed = LIVE_DIR / "feed.jsonl"
    matcher.write_jsonl(records, feed)
    command = [sys.executable, str(ROOT / "assess.py"), str(feed), "--output-dir", str(LIVE_DIR),
               "--limit", str(limit), "--pdf"]
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    step = "evidence"
    for line in process.stdout:
        if "verdict=" in line:
            step = "checks"
        elif line.startswith("["):
            step = "agent"
        progress.say(line.rstrip(), step, {"feed", "match"})
    process.wait()
    results = _read(LIVE_DIR / "assessments.json")
    if anonymise_on:
        progress.say("Anonymising the results and their PDFs...", "report",
                     {"feed", "match", "evidence", "agent", "checks"})
        results = anonymise.anonymise_results(results)
        anonymise.write_bundle(results, LIVE_BUNDLE, pdf=True)
    progress.placeholder.markdown(pipeline_html(None, {s[0] for s in STEPS}), unsafe_allow_html=True)
    return results


def _check_live(anonymise_on: bool) -> None:
    if anonymise_on and not config.CAMPUS_CIDR:
        raise SystemExit("Live mode needs CAMPUS_CIDR in .env, so results can be anonymised before they are shown.")


def live_pull(feeds: set[str], anonymise_on: bool) -> None:
    """Pull the ticked feeds (ThreatFox's API only if it is ticked), match and investigate."""
    import build_feed

    with st.expander("Pull from the ticked feeds and investigate"):
        cols = st.columns(2)
        days = cols[0].number_input("Days of indicators and traffic", 1, 15, 7)
        limit = cols[1].number_input("Cases to investigate", 1, 20, 3)
        if not st.button("Pull and investigate"):
            return
        pulled = feeds - {misp_feed.MANUAL_FEED}
        if not pulled:
            st.warning("Tick at least one feed.")
            return
        progress = Progress(st.empty(), st.empty(), anonymise_on)
        try:
            _check_live(anonymise_on)
            note = "with" if misp_feed.THREATFOX_FEED in pulled else "without"
            progress.say(f"Pulling {', '.join(sorted(pulled))} ({note} a ThreatFox API pull)...", "feed", set())
            records = build_feed.pull_feeds(pulled, int(days))
            progress.say(f"{len(records)} match record(s) found.", "match", {"feed"})
            if records:
                run_assess(records, int(limit), progress, anonymise_on)
        except SystemExit as exc:
            st.error(str(exc))


def run_live(indicators: list[str], description: str, threat_type: str, progress: Progress,
             anonymise_on: bool) -> list[dict]:
    """Manual feed -> assess.py -> results. Needs ClickHouse and the model."""
    import build_feed

    _check_live(anonymise_on)
    progress.say("Writing the threat briefing and matching the indicators...", "feed", set())
    records, _ = build_feed.build_manual(indicators, description or None, days=7, yes=True, threat_type=threat_type)
    progress.say(f"{len(records)} match record(s) found.", "match", {"feed"})
    return run_assess(records, 3, progress, anonymise_on) if records else []


def try_it(results: list[dict], pdf_dir: Path, live: bool, speed: float, anonymise_on: bool) -> None:
    with st.form("try"):
        indicators = st.text_area("Indicators (one per line: IP, ip:port, domain or URL)", "update-check.example")
        description = st.text_area("Threat description (optional), e.g. an email about a new CVE", height=120)
        threat_type = st.selectbox("Threat type", ["unknown", "botnet_cc", "payload_delivery", "exploit", "phishing"])
        submitted = st.form_submit_button("Investigate")
    if not submitted:
        return
    values = [v for v in indicators.splitlines() if v.strip()]
    placeholder, log = st.empty(), st.empty()
    if live:
        try:
            found = run_live(values, description, threat_type, Progress(placeholder, log, anonymise_on), anonymise_on)
        except SystemExit as exc:
            st.error(str(exc))
            found = []
        live_pdfs = LIVE_BUNDLE / "pdf" if anonymise_on else LIVE_DIR / "cases"
        for r in found:
            show_case(r, live_pdfs, anonymise_on)
        if not found:
            st.info("No campus host contacted these indicators in the last 7 days.")
    elif results:
        st.info("Demo mode: replaying a recorded case (no network calls).")
        case = pick_case(results, values)
        replay(placeholder, log, case, speed)
        show_case(case, pdf_dir, anonymise_on)


# --- page ----------------------------------------------------------------------------------

def main() -> None:
    st.set_page_config(page_title="IOC investigation agent", layout="wide")
    st.title("IOC investigation agent")
    st.caption("Threat-intelligence matches on campus traffic, investigated by a language model and checked by code.")
    anonymise_on = anonymised()
    tidy_static(anonymise_on)
    live = False
    if not config.DEMO_ONLY:
        live = st.sidebar.toggle("Live mode", value=False,
                                 help="Needs the flow database and the model. Off: replays recorded cases.")
    if not anonymise_on:
        st.sidebar.warning("Real details: hosts, names and sites are not anonymised. For the stand, run with "
                           "DEMO_ONLY=1 (or ANONYMISE=1).")
    speed = st.sidebar.slider("Replay speed", 0.5, 4.0, 1.0, 0.5)
    all_results, pdf_dir, intel_dir = load_cases(live, anonymise_on)
    snapshot = load_snapshot(live, intel_dir)
    known = snapshot_feeds(snapshot)
    if live:
        try:
            known |= set(misp_feeds()) | {misp_feed.THREATFOX_FEED}
        except Exception as exc:  # noqa: BLE001 - the checklist still lists the feeds the cases came from
            st.sidebar.caption(f"Could not list MISP's feeds: {str(exc)[:100]}")
    feeds = feed_checklist(feed_counts(all_results, known), live)
    results = [r for r in all_results if feed_of(r) in feeds]
    st.sidebar.caption(f"{'LIVE' if live else 'Demo'} mode · {len(results)} of {len(all_results)} case(s) "
                       f"from {pdf_dir.parent.name}/" + ("" if anonymise_on else " · real details"))

    names = ["Threat board", "How it works"] + ([] if config.DEMO_ONLY else ["Try it"])
    tabs = st.tabs(names)
    with tabs[0]:
        threat_board(results, pdf_dir, snapshot, live, feeds, anonymise_on)
    with tabs[1]:
        st.markdown("Every alert from the threat feed becomes a case. Code gathers the evidence; the model "
                    "investigates it **without being shown the rule-based answer**, writes the report and picks its "
                    "charts; code then checks every number and claim before anything reaches an analyst.")
        placeholder, log = st.empty(), st.empty()
        placeholder.markdown(pipeline_html(), unsafe_allow_html=True)
        if results and st.button("Watch a case run"):
            replay(placeholder, log, newest_first(results)[0], speed)
    if not config.DEMO_ONLY:
        with tabs[2]:
            try_it(results, pdf_dir, live, speed, anonymise_on)


if __name__ == "__main__":
    main()

# Usage

Setup and day-to-day use. For what the pipeline does, see the
[README](../README.md) and [how-it-works.md](how-it-works.md).

## Setup

You'll need Python 3.11+, read access to a SuperNetFlow ClickHouse database,
a model (an OpenRouter key, or [Ollama](https://ollama.com) with a
tool-calling model), and for the threat feed a local MISP and an abuse.ch key.
PDF reports need [tectonic](https://tectonic-typesetting.github.io) or a TeX
distribution with `latexmk`; without one the reports are written as `.tex`
files only.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-demo.txt   # optional: the stand dashboard
cp .env.example .env                   # ClickHouse, MISP, abuse.ch, model and site settings
brew install tectonic                  # optional: PDF reports
```

Every setting is listed in `.env.example` with a placeholder.

## A full run

```bash
python sync_threatfox.py --days 1                         # ThreatFox's latest IOCs into MISP
python build_feed.py --source misp --days 7               # campus hosts that contacted them -> data/misp_matches.jsonl
python assess.py data/misp_matches.jsonl --limit 5 --pdf  # investigate and write the reports
python -m demo.anonymise output/assessments.json          # optional: the anonymised stand bundle
streamlit run dashboard/app.py                            # optional: the dashboard, http://localhost:8501
```

Results land in `output/`:

- `output/reports/`: the finished PDFs, one per case as
  `<indicator>-<host>.pdf` plus the batch `summary-<YYYY-MM-DD>.pdf`. A rerun
  of a case overwrites its PDF.
- `output/report.html`: every case in one page (worst first, filterable).
- `output/cases/`: build files: each case's Markdown report, case file
  (`.casefile.txt`), LaTeX source, chart PDFs and LaTeX logs.
- `output/assessments.json`: everything, including token use, cost and the
  indicators the feed build skipped as known services.

They contain internal IPs and per-host activity, so they're gitignored.

`assess.py` takes any feed of matches (JSON or JSON Lines):

```bash
python assess.py data/misp_matches.jsonl --indicator bore.pub  # one indicator
python assess.py data/misp_matches.jsonl --limit 5 --resume    # the next five, keeping earlier results
python assess.py data/sample/ioc_matches_sample.json           # fake sample feed
```

Without `--resume`, a run replaces `output/assessments.json`.

## Building a feed from MISP

Run a local MISP with [misp-docker](https://github.com/MISP/misp-docker),
enable the public feeds you want (Feeds → "Load default feed metadata"), and
create an auth key. Put `MISP_URL` and `MISP_KEY` in `.env`; the local
instance's self-signed certificate is accepted unless `MISP_VERIFY_SSL=1`.

ThreatFox's bulk exports fail and MISP's built-in ThreatFox feeds need a key,
so ThreatFox comes in through its API instead, keeping its malware and
threat-type labels (needs `ABUSECH_AUTH_KEY` and a MISP key with write access):

```bash
python sync_threatfox.py --days 1 --dry-run                               # count only, write nothing
python build_feed.py --source misp --refresh                              # ask MISP to fetch its feeds first
python build_feed.py --source misp --feeds "ThreatFox,Phishing feeds"     # only some feeds
```

`build_feed.py` takes the IP, IP:port, domain, hostname and URL attributes
whose attribute timestamp is in the last N days (URLs are reduced to their
host), skips values on MISP's warninglists, and searches campus traffic for
them in windows of at most 5 days. Big link-sharing and hosting services
(share.google, bit.ly, docs.google.com, github.io and others in
[agent/data/service_domains.txt](../agent/data/service_domains.txt)) are
handled apart: a feed lists one URL on them, not the whole service. A bare
domain on that list is skipped and counted ("skipped as known services" in
the run summary and on the dashboard). A URL on one is matched only where the
flow shows its exact host, and the case file says that a host-name match
cannot prove the URL itself was visited. Each match records its feed (the MISP
event's title, or "ThreatFox"). Records keep the old feed format with an
`intel` block in place of `threatfox` (see [schema.md](schema.md)); older
feeds still load.

## Manual indicators and a threat description

For a new threat that no feed lists yet, such as an email about a new CVE:

```bash
python build_feed.py --source manual --indicator 203.0.113.7 --indicator example.test \
    --threat-file threat.txt --out data/manual_matches.jsonl
python assess.py data/manual_matches.jsonl --pdf
```

One model call turns the description into a threat briefing (what an affected
host's traffic looks like, what a false positive looks like, CVEs, references),
saved in `data/threat_briefings/` and shown for you to confirm (`--yes` skips
that). The investigation then uses it in place of the built-in knowledge base,
labelled as an analyst-supplied description. `--push-misp` also saves the
indicators as a MISP event (needs `MISP_WRITE_KEY`).

## PDF reports

`--pdf` writes each case as LaTeX in `output/cases/` (with its charts as
vector PDFs) plus a batch overview, compiles them with `latexmk` or
`tectonic`, whichever is installed, and moves the finished PDFs to
`output/reports/`. The layout follows the hand-written CyberShield reports: a
one-page body, then an appendix with the figures, the flow table, the case
facts and a closing line of sources and limits, all referred to by number
from the body.

To compile reports from a run made without a TeX engine, without running the
model again:

```bash
python -m agent.latex output/assessments.json
```

## Dashboard and stand demo

```bash
streamlit run dashboard/app.py                     # real details, for the security team
ANONYMISE=1 streamlit run dashboard/app.py         # anonymised
DEMO_ONLY=1 streamlit run dashboard/app.py         # the event stand: anonymised, replay only
```

- **Threat board**: cases this week, likely threats against false positives,
  the top threat types, and a table of recent cases (newest first, filtered by
  verdict, threat type and source). Click a row for its report, charts and PDF.
  Beside it, the newest ThreatFox malware families and MISP events, from a
  snapshot of public data.
- **Feeds** (sidebar): ThreatFox, each MISP feed by name and the phishing
  feeds as one group, each with its case count. The ticks filter the board;
  in live mode they also choose which feeds a pull matches against.
- **How it works**: the pipeline, replayed step by step for a recorded case.
- **Try it**: indicators and a threat description in, a report out.

The dashboard listens on localhost only. By default it reads
`output/assessments.json` and the PDFs in `output/reports/` as they are. With
`ANONYMISE=1`, and always with `DEMO_ONLY=1`, it shows the anonymised bundle
instead, built by `python -m demo.anonymise output/assessments.json` into
`demo/bundle/`. Only campus data is replaced: campus addresses become Host A,
Host B; a case host's name becomes its role ("campus web server", or "campus
host" when its type is unclear); other campus names, and names served from
campus addresses, become "campus site A", "campus site B". Public third-party
domains stay as they are. Building the bundle needs `CAMPUS_CIDR` and
`CAMPUS_DOMAINS` in `.env`, and a TeX engine for its PDFs. Without a bundle, a
fake sample set in `demo/sample/` is shown.

Demo mode (the default) only replays recorded cases and makes no network
calls. Live mode (a sidebar toggle, hidden by `DEMO_ONLY=1`) runs the pipeline
and needs the database and the model.

## Model provider and cost

`LLM_PROVIDER` chooses the model:

- `openrouter`: a hosted model (`OPENROUTER_MODEL`, Claude Haiku in current
  use). Case files, which hold internal IPs and per-host activity, are sent
  off-network to OpenRouter and the model's provider; the supervisor has
  approved this. Each case records its tokens and cost, the run totals go into
  `assessments.json` and the run summary, and a batch stops cleanly once
  `MAX_RUN_COST_USD` (default 2.00) is reached. Running out of credit stops
  the batch rather than failing each case. With an `anthropic/*` model the
  system prompt and case file are marked for prompt caching (`PROMPT_CACHE=0`
  turns it off).
- `ollama`: a local model, so no flow data leaves the network. The agent asks
  for a 32k-token context (`OLLAMA_NUM_CTX`): Ollama's 4k default silently cuts
  off the start of the prompt.

Web context (Malpedia, ThreatFox and a web search of at most
`WEB_SEARCH_MAX` = 3 searches per indicator, cached in `data/web_context/`) is
on by default with OpenRouter and off with Ollama; `WEB_CONTEXT=0` or `1`
overrides it, and `WEB_SEARCH_MAX=0` keeps Malpedia and ThreatFox but skips
the search. Searches only ever contain public names (the indicator, malware
family, threat type and feed).

## Evaluation

`eval/run_eval.py` runs the agent on cases with an expected verdict and
compares the expected, rule-based and model verdicts side by side.
`eval/showcase_check.py` checks finished reports against the report-quality
standard.

```bash
python eval/run_eval.py                                        # quick sample
python eval/run_eval.py --all --repeat 2                       # everything, twice, to check consistency
python eval/run_eval.py --from-output output/assessments.json  # re-score a saved run, no model calls
python -m eval.showcase_check output/assessments.json          # report-quality check of a run's PDFs
```

## Project layout

```
assess.py               runs each case: evidence, model, checks, report
build_feed.py           builds a feed from MISP or manual indicators
sync_threatfox.py       copies ThreatFox IOCs into MISP with their labels
agent/
  misp_feed.py          reads indicators from MISP as intel blocks
  matcher.py            finds campus contacts and writes match records
  briefing.py           threat description -> briefing (one model call)
  web_context.py        outside context: Malpedia, ThreatFox and a web search
  latex.py              LaTeX/PDF reports (finished PDFs go to output/reports/)
  labels.py             plain words for code labels (verdicts, host types, patterns)
  tools.py, db.py       evidence queries and the model's guarded tools
  analysis.py           flow analysis: contact pattern, timelines, usage
  beacon.py, timeline.py
  signals.py            rule-based signals and the baseline verdict
  casefile.py           the evidence as the model reads it
  knowledge.py          malware, service and site profiles
  llm_client.py         OpenRouter / Ollama client with a tool loop
  charts.py, report.py  charts (SVG and PDF) and the HTML and Markdown reports
  mdrender.py           the model's Markdown, safely rendered as HTML
host_classification/    host-type classifier and per-type profiles
dashboard/              Streamlit dashboard (threat board, pipeline replay, try it)
demo/                   anonymiser, intel snapshot and a fake sample bundle
eval/                   verdict evaluation and the report-quality check
docs/                   design notes, usage and the data schema
```

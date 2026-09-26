# IOC Triage Agent

An LLM agent that triages IOC matches on a campus network. It reads a feed of
IOC matches (each one a [ThreatFox](https://threatfox.abuse.ch) indicator plus
the internal host that contacted it), analyses the host's flow records from
SuperNetFlow in ClickHouse, computes evidence signals and a rule-based
baseline verdict, and asks a local LLM for its own verdict. It writes an HTML
overview and one Markdown report per case.

The agent has no internet access. It works only from the feed, ClickHouse and
a local knowledge base of threat, malware and service profiles.

## Workflow

Each case follows the same ten steps. "Auto" steps are plain Python and always
run. "Agent" steps are the LLM reasoning over the evidence; it can also call
follow-up tools (below).

| # | Step | Who | Where |
|---|---|---|---|
| 1 | Group the feed by (indicator, host) | Auto | `evidence.group_matches` |
| 2 | Read the IOC context: type, malware, threat type, confidence | Auto | `evidence.case_identity` |
| 3 | Identify every flagged IP, its ASN and whether it is shared infrastructure | Auto | `tools.identify_server_ips`, `tools.ip_asn` |
| 4 | Set expected behaviour: threat type, malware family, known services; domain features | Auto | `tools.expected_behaviour`, `tools.domain_features`, `knowledge.py` |
| 5 | Analyse flows between host and flagged IP, and the names (SNI/DNS) the host used on it | Auto | `tools.indicator_flows`, `tools.indicator_names`, `analysis.py` |
| 6 | Compare with expected compromised behaviour | Agent | prompt in `assess.py` |
| 7 | Compare with the host's traffic to other IPs, incl. platform hints | Auto + agent | `tools.host_other_traffic` |
| 8 | Other internal hosts on the flagged IP, and every name on it campus-wide | Auto | `tools.indicator_peers`, `tools.ip_passive_dns` |
| 9 | Signals, behaviour category and baseline verdict (code), then the model's verdict, checked by code | Auto + agent | `signals.py`, `behaviour.py`, `assess.py` |
| 10 | Write the three-paragraph report | Auto | `narrative.py`, `report.py` |

The report is written in code from the evidence, so every number is real and
the remaining risk (e.g. a tunnel exposing a campus host) is never dropped.
The model's job is the judgement: its verdict (checked against the baseline),
a reading of the case for the reviewer, and follow-up queries if it wants
them. Keeping its reply short also keeps each case to a few seconds.

Each case gets a **behaviour category** (`agent/behaviour.py`): tunnelling,
remote access, connection to a tunnel's public port, C2-like beaconing,
persistent connection to an unrecognised service, file download, web visit
to the flagged site, web browsing through shared infrastructure, other, or no
traffic. It drives the report's wording and next steps.

Checks that must always happen are run in Python, not left to the model: in
testing, a small local model skipped optional tools almost every time.

Step 5 separates a **held-open connection** (a few flows lasting hours or days
at a steady packet rate, e.g. a tunnel) from **repeated short check-ins** (many
brief flows at a regular interval, the real beacon pattern). Daily presence on
its own is never treated as beaconing.

When a live query finds nothing (usually because `subscriber_activity_1m`
keeps only about 15 days), the feed's own copy of the matched rows is used
instead, labelled "from the IOC feed, not re-queried".

### Signals and the baseline verdict

Before the model runs, `agent/signals.py` computes eight signals, each
`supports_threat` (strong or weak), `against_threat` or `neutral`, with a
one-line reason:

| Signal | Against threat when | Supports threat when |
|---|---|---|
| `shared_infrastructure` | CDN/cloud range or ASN, many campus hosts, many domains on the IP, or a known public service | One domain on the IP and not a shared ASN (weak) |
| `sni_matches_indicator` | The names the host used on the IP are ordinary sites | Domain indicator named in the traffic; or a name that is itself flagged, dynamic DNS, or rare and DGA-like (strong); rare, new, DGA-like or free hosting alone (weak) |
| `protocol_fit` | QUIC (UDP/443) or TLS web browsing, for a custom-TCP family | TCP to a non-web port, for a custom-TCP family (weak) |
| `traffic_shape_fit` | A few short sessions (botnet_cc); a tiny transfer (payload_delivery) | Regular check-ins (strong); a payload-sized download (weak) |
| `recurrence` | A one-off, or irregular human-like use | Regular contact across several days (weak) |
| `platform_fit` | Only other-OS signs (e.g. Apple for a `win.` family) | Signs of the targeted OS (weak) |
| `campus_spread` | Many campus hosts, none independently flagged | Peers flagged by *other* indicators for the same family (strong) |
| `known_service` | Only the service's own client ports | Other ports on the service (e.g. a tunnel's public port) (strong) |

ThreatFox confidence is not a signal: it rates the indicator, not the host.

The baseline verdict follows fixed rules (`signals.baseline_verdict`):

1. No traffic, live or in the feed: **INSUFFICIENT_DATA** (set in code, whatever the model says)
2. 2+ strong threat signals, or 1 strong + 2 weak: **LIKELY_THREAT**
3. 1 strong threat signal: **SUSPICIOUS**
4. Shared infrastructure or a known service's normal client, at most 2 weak threat signals: **LIKELY_FALSE_POSITIVE**
5. 2+ weak threat signals: **SUSPICIOUS**
6. Only signals against threat: **LIKELY_FALSE_POSITIVE** (low confidence)
7. Nothing either way: **SUSPICIOUS** (low confidence)

The model may disagree only by naming the signal it overrides in
`BASELINE_OVERRIDE` with the evidence against it (not ThreatFox confidence);
otherwise the baseline stands. Any disagreement, and any reply that
contradicts the evidence (says "does not match" but escalates, claims
exfiltration with no flow over the threshold, contradicts the shared-
infrastructure signal, or quotes numbers not in the evidence), marks the case
for human review.

### Follow-up tools the model can call

All are bound to the case's host in code.

| Tool | Use |
|---|---|
| `timeline_around(time, minutes)` | Everything the host did around one time: a browsing burst or a lone connection? |
| `host_baseline(days)` | The host's normal daily volume, destinations and active hours |
| `compare_sessions(date_a, date_b)` | The host's traffic with the flagged IP on two dates |
| `run_sql(sql)` | Anything else: SELECT only, allowed tables, must filter on the host and a time column, 50-row cap |

Up to `MAX_TOOL_ROUNDS` (default 4) rounds per case. Every call is logged in the report.

## Layout

```
assess.py            entry point: runs the steps for each case
agent/
  config.py          settings, read from .env
  evidence.py        feed loading, grouping, query windows
  db.py              ClickHouse queries and the guarded run_sql tool
  analysis.py        flow analysis on DataFrames (no I/O, so it is testable offline)
  tools.py           one function per workflow question, plus the model's follow-up tools
  signals.py         evidence signals and the baseline verdict rules
  behaviour.py       behaviour category (tunnelling, beaconing, web on shared infrastructure, ...)
  narrative.py       the report's three paragraphs, written from the evidence
  domain_features.py offline domain/IP features (registered domain, shared ASNs, DGA-like)
  knowledge.py       threat type, malware, service and shared-infrastructure profiles
  casefile.py        renders the evidence as the text the model reads
  llm_client.py      Ollama / OpenRouter client with a small tool loop
  report.py          HTML overview and per-case Markdown reports
data/sample/         fake feed in the real format, safe to publish
eval/                expected-verdict evaluation (run_eval.py; example file with fake IPs)
```

## Requirements

- Python 3.11 or newer
- Access to the SuperNetFlow ClickHouse database (see below)
- Ollama with a tool-calling model, or an OpenRouter API key

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Install Ollama and a model

1. Install Ollama:
   - **macOS:** download the app from [ollama.com](https://ollama.com/download), or `brew install ollama`
   - **Linux:** `curl -fsSL https://ollama.com/install.sh | sh`
   - **Windows:** run the installer from [ollama.com](https://ollama.com/download)
2. Start the server (the desktop app starts it for you):
   ```bash
   ollama serve
   ```
3. Pull the default model:
   ```bash
   ollama pull qwen2.5:7b
   ```

A larger model gives better verdicts if your hardware allows it (for example
`qwen2.5:14b` or `qwen2.5:32b`). Set `OLLAMA_MODEL` in `.env` to use it. The
agent asks Ollama for a 16k-token context (`OLLAMA_NUM_CTX`); Ollama's 4k
default is too small and would silently cut off the start of the prompt.

### Optional: OpenRouter

To use a cloud model instead, set `LLM_PROVIDER=openrouter` and
`OPENROUTER_API_KEY` in `.env`. The free tier allows about 50 requests a day;
if the quota runs out mid-batch, the run stops cleanly and `--resume` picks up
where it left off.

## Database access

The flow data lives in a SuperNetFlow ClickHouse database (schema documented at
https://supernetflow.com/database-schema). You need network access to your
deployment and a read-only account; put the connection details in `.env`.
Three tables are used:

- `canopus.subscriber_activity_1m`: per-minute traffic per (client, server,
  port), with SNI, DNS and root domain. Keeps about 15 days. Queried in chunks
  of at most 5 days, because larger queries hit ClickHouse's 200-million-row
  read limit. This is also the only source of names for a server IP:
  `public.dns_tuple` records which resolver a client asked, with no names.
- `public.long_flow_summary`: one row per flow over a size/duration threshold.
  Each flow is deleted 65 days after it finishes (a table TTL), and short
  flows are missing. Reports flag cases whose evidence reaches that edge.
- `canopus.asn`: ASN by CIDR, for flagged IPs with no flow rows.

All timestamps are UTC. The retention periods and row limit above are from
the deployment this was built on; yours may differ, and the query windows can
be changed in `.env`.

## Setup

```bash
cp .env.example .env
```

`.env` is the one place for every secret and site-specific setting: the
ClickHouse host, user and password, `OLLAMA_API_KEY` (only for Ollama Cloud or
a remote server behind auth), `OPENROUTER_API_KEY`, model choices, and
`ORG_NAME` (the organisation named in prompts and reports; generic wording if
unset), `LOCAL_TIMEZONE` (case files add local times next to UTC so the model
can judge time of day) and `SITE_CONTEXT` (free-text background for the model). Fill it
in; `.env.example` lists every setting with placeholders. `.env` is gitignored,
and the agent stops with a clear message if it is missing.

The host's name comes from reverse DNS (turn off with `REVERSE_DNS=0`) and is
reported as a fact. What the name and the host's traffic suggest about the
machine is the model's reading, labelled in the report as unconfirmed.

Optionally, copy `data/sample/ioc_metadata.example.json` to
`data/ioc_metadata.json` and paste in real ThreatFox fields (first seen, last
seen, reporter) for an IOC. The feed does not carry these: its
`first_seen_utc` / `last_seen_utc` are the matched flow's own times, which the
agent reports as `evidence_first_seen` / `evidence_last_seen`.

## Running it

```bash
# fake sample feed (the hosts are fake, so expect "no traffic found")
python assess.py --input data/sample/ioc_matches_sample.json

# a real feed
python assess.py --input data/ioc_matches.json

# one indicator only
python assess.py --input data/ioc_matches.json --indicator bore.pub

# the first 5 cases, then continue later without redoing finished ones
python assess.py --input data/ioc_matches.json --limit 5
python assess.py --input data/ioc_matches.json --resume
```

| Flag | Meaning |
|---|---|
| `--input` | IOC-match feed (JSON list). Default `data/ioc_matches.json` |
| `--output-dir` | Where to write results. Default `output/` |
| `--limit N` | Only assess the first N cases (highest ThreatFox confidence first) |
| `--indicator X` | Only assess cases for this exact indicator |
| `--resume` | Keep cases that already succeeded and assess the rest |
| `--pause S` | Seconds between cases (for rate-limited providers) |

### Evaluation

`eval/run_eval.py` runs the agent on a quick sample (one case per indicator,
at most 6, about a minute and a half) or, with `--all`, every case with an
expected verdict, and prints expected vs baseline vs model vs final, with
confusion tables.
Expected verdicts come from `data/expected_verdicts.json` (real IPs,
gitignored) if present, else `eval/expected_verdicts.json` (fake IPs).

```bash
python eval/run_eval.py --list              # every case in the feed, to fill in expected verdicts
python eval/run_eval.py                        # quick sample: one case per indicator, at most 6
python eval/run_eval.py --all --repeat 2       # everything, model twice per case: checks determinism (slow)
python eval/run_eval.py --from-output output/assessments.json   # compare a saved run, no new model calls
```

## Outputs

- `output/cases/<indicator>__<host>.md`: one short report per case in three
  paragraphs: **Summary** (host and name, the flagged indicator, what the match
  would usually mean, what the flow data shows, the verdict and whether the
  rule-based baseline agrees, and any risk that remains), **Behaviour
  analysis** (the workflow steps: which name the host used on the flagged IP,
  the flows, the comparison with a real victim, the host's other traffic and
  likely role, other hosts on the IP) and **Conclusion and next steps**.
  Next to it, `<indicator>__<host>.casefile.txt` holds the evidence the model saw.
- `output/report.html`: the same paragraphs as one card per case, worst first,
  with the behaviour category and a "human review" marker; the agent's own
  judgement, the case file and tool calls are folded away for reviewers.
- `output/assessments.json`: everything, for reuse.

**Outputs contain real internal IP addresses and per-host activity, including
personal devices.** They are gitignored. Do not share them outside the team.

## Limitations

- **No internet research.** Malware and service context comes only from
  `agent/knowledge.py`. Entries marked "uncertain" have not been checked
  against the service's documentation.
- **Flow data only.** No payloads, so the content of a session is unknown.
  Visitors reaching a host through a tunnel appear as the tunnel server's IP.
- **Retention.** Per-minute data keeps about 15 days; older cases have only
  `long_flow_summary`, which misses short flows, plus the feed's own rows.
  Passive DNS and domain popularity for older cases use current data, which
  is labelled as such.
- **Heuristic thresholds.** Rare (at most 1 campus host in 5 days), popular,
  DGA-like and exfiltration thresholds are judgement calls, set in
  `agent/config.py`, `agent/signals.py` and `agent/domain_features.py`.
- **Small models make mistakes.** Verdicts are a first-pass triage. Read the
  case file before acting. When there is no traffic for a case, the traffic
  fields are replaced with fixed text, because small models were found to
  invent SNI, ASN and byte counts.
- `run_sql` guardrails (SELECT only, allowed tables, must filter on the case's
  host and a time column, 50-row cap) stop unsafe or unbounded queries, not
  wrong ones.

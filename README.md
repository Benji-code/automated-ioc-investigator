# Automated IOC Investigator

An LLM agent that investigates threat-intelligence alerts on a campus network
and writes the incident report an analyst would.

When a campus host contacts an address or domain listed on
[ThreatFox](https://threatfox.abuse.ch), most matches turn out to be noise: a
CDN address shared by thousands of sites, an ad pulled in by a web page, a
tunnel client doing exactly what it was installed for. This project works
through each match the way an analyst would. It pulls the host's flow records
from SuperNetFlow (ClickHouse), works out what the host was actually doing,
and writes a report with a verdict, charts and the evidence behind it.

Three design choices keep the reports trustworthy:

- **Evidence first, in code.** Everything that must be checked runs in Python
  before the model sees the case. A small local model skipped optional tools
  almost every time, so it gets the results instead of being trusted to fetch
  them.
- **The model reviews blind.** A rule-based verdict is computed from the same
  evidence but never shown to the model; when it was shown, the model just
  agreed with it. Where they disagree, an analyst decides.
- **Nothing unverified slips through.** Every number in a report is checked
  against the evidence, along with claims like "exfiltration" or "not shared
  infrastructure". Anything that fails is flagged for review, never quietly
  rewritten.

The agent has no internet access, and with a local Ollama model no flow data
leaves the network.

## How it works

```mermaid
%%{init: {"flowchart": {"nodeSpacing": 18, "rankSpacing": 40}}}%%
flowchart LR
    feed["IOC match feed<br/>ThreatFox indicator + campus host"] --> cases["One case per<br/>host and indicator"]
    cases --> gather

    subgraph gather["Gather evidence (code)"]
        direction TB
        g1["Flagged address<br/>owner, shared or dedicated"]
        g2["Flows, site names and<br/>contact pattern"]
        g3["Timeline of the host's<br/>traffic around each contact"]
        g4["Host profile<br/>type, usage, uptime"]
        g1 ~~~ g2 ~~~ g3 ~~~ g4
    end

    gather --> investigate
    gather --> rules["Rule-based<br/>verdict"]

    subgraph investigate["Investigate (LLM agent)"]
        direction TB
        m1["Reads the evidence"]
        m2["Runs follow-up queries<br/>and picks charts"]
        m3["Writes the report<br/>and a verdict"]
        m1 --> m2 --> m3
    end

    investigate --> check

    subgraph check["Check (code)"]
        direction TB
        c1{"Every number found<br/>in the evidence?"}
        c2{"Agrees with the<br/>rule-based verdict?"}
        c1 -- yes --> c2
    end

    rules -. "never shown<br/>to the model" .-> c2
    check -. "problems found:<br/>one revision pass" .-> investigate
    c2 -- yes --> done["Report<br/>verdict stands"]
    c1 -- no --> review["Report marked for<br/>analyst review"]
    c2 -- no --> review

    classDef code fill:#e8f0fe,stroke:#3b6fd4,color:#111
    classDef model fill:#fff4d6,stroke:#c98a00,color:#111
    classDef io fill:#f2f2f2,stroke:#777,color:#111
    classDef good fill:#e6f4ea,stroke:#2e7d4f,color:#111
    classDef warn fill:#fdecea,stroke:#c0392b,color:#111
    class g1,g2,g3,g4,c1,c2,rules code
    class m1,m2,m3 model
    class feed,cases io
    class done good
    class review warn
    style gather fill:none,stroke:#3b6fd4
    style investigate fill:none,stroke:#c98a00
    style check fill:none,stroke:#3b6fd4
```

Each alert becomes a case: one campus host and one indicator. Steps 2 to 9
run in code before the model sees anything, and the model only gets the
evidence from steps 2 to 8. The rule-based verdict from step 9 is kept back
for the final check.

| # | Step | Who | Where |
|---|---|---|---|
| 1 | Group the feed into cases, one per host and indicator; merge duplicate visits and note domains shared across cases | Code | `evidence.py`, `correlation.py` |
| 2 | Identify the flagged address: its owner and whether it's shared infrastructure | Code | `tools.identify_server_ips`, `tools.ip_asn` |
| 3 | Set the expected behaviour: threat type, malware family and known services such as tunnels | Code | `tools.expected_behaviour`, `knowledge.py` |
| 4 | Analyse the contact: flows, the site names the host used, and whether it looks like a beacon, a held-open tunnel or a one-off | Code | `tools.indicator_flows`, `tools.indicator_names`, `beacon.py` |
| 5 | Build a timeline of everything the host did in the minutes around each contact | Code | `timeline.py` |
| 6 | Profile the host: what it's used for, its uptime, apps and DNS behaviour | Code | `tools.host_other_traffic`, `analysis.activity_profile`, `tools.host_dns_behaviour` |
| 7 | Classify the host and compare it with typical hosts of its type | Code | `host_type.py`, `host_classification/` |
| 8 | Look campus-wide: other hosts on the address and every site seen on it | Code | `tools.indicator_peers`, `tools.names_on_ip` |
| 9 | Compute signals and a rule-based baseline verdict | Code | `signals.py` |
| 10 | Investigate: read the evidence, run follow-up queries, pick charts, write the report and a verdict | Agent | `assess.py`, `tools.py`, `charts.py` |
| 11 | Check the report against the evidence and the baseline; send problems back for one revision, then flag anything that still fails | Code | `assess.py` |
| 12 | Write the HTML and Markdown reports | Code | `report.py` |

## Architecture

```mermaid
%%{init: {"flowchart": {"nodeSpacing": 18, "rankSpacing": 40}}}%%
flowchart TB
    db[("SuperNetFlow<br/>campus flow records in ClickHouse")]

    subgraph hc["Host classification"]
        direction TB
        rf["Random forest<br/>weakly supervised labels"] --> prof["Host type and<br/>its normal range"]
    end

    subgraph feed["Threat feed (upstream)"]
        direction TB
        tf["ThreatFox<br/>indicators"] --> match["Matched against<br/>campus traffic"]
    end

    subgraph core["Investigation agent"]
        direction TB
        kb["Knowledge base<br/>malware, services, sites"] --> ev["Evidence gathering<br/>fixed queries and analysis"]
        ev --> llm["LLM agent<br/>local Ollama model"]
        llm --> fc["Fact check and<br/>rule-based cross-check"]
    end

    db --> hc
    db --> feed
    db --> ev
    llm -. "guarded read-only SQL" .-> db
    prof --> ev
    match --> ev
    fc --> rep["HTML report<br/>verdict, charts, flow table"]
    rep --> analyst(["Security analyst<br/>makes the final call"])

    classDef code fill:#e8f0fe,stroke:#3b6fd4,color:#111
    classDef model fill:#fff4d6,stroke:#c98a00,color:#111
    classDef data fill:#f2f2f2,stroke:#777,color:#111
    classDef good fill:#e6f4ea,stroke:#2e7d4f,color:#111
    class rf,prof,kb,ev,fc,tf,match code
    class llm model
    class db,rep data
    class analyst good
    style hc fill:none,stroke:#3b6fd4
    style feed fill:none,stroke:#3b6fd4
    style core fill:none,stroke:#c98a00
```

- **Host classification** labels campus hosts (workstation, NAT gateway, web
  server, ...) with a random forest trained on weakly supervised labels, and
  measures what's normal for each type. See
  [host_classification/](host_classification/README.md).
- **Threat feed** comes from upstream: ThreatFox indicators already matched
  against campus traffic.
- **Investigation agent** (`assess.py`, `agent/`) gathers the evidence, runs
  the model and checks what it writes.

## The report

Each case gets a short report written for the security team:

- **Executive summary**: what happened, the verdict and the one thing to do.
- **Background**: what the host appears to be and who likely uses it, judged
  from its own traffic (personal browsing such as entertainment, gaming or
  streaming points to a student's device); what the threat is; and what an
  infected host would look like.
- **Analysis**: a timestamped walk through the evidence that cites the
  connections it relies on and weighs the benign explanation against the
  malicious one.
- **Conclusion and next steps**: verdict, confidence, remaining risk and
  what to do about this host.

Below it sit the charts the model chose and a table of every connection
around the contact, each with a note on what it most likely was. That table
is what separates, say, a flagged ad domain loaded in the same minute as a
busy ad-funded site from a lone connection at 3 am.

## Getting started

You'll need Python 3.11+, read access to a SuperNetFlow ClickHouse database,
and [Ollama](https://ollama.com) with a tool-calling model (or an OpenRouter
key).

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # ClickHouse login, model and site settings
ollama pull qwen3.5:9b
```

Then point it at a feed of matches (JSON or JSON Lines):

```bash
python assess.py data/ioc_matches.jsonl                       # every case
python assess.py data/ioc_matches.jsonl --indicator bore.pub  # one indicator
python assess.py data/ioc_matches.jsonl --limit 5             # a batch, then --resume
python assess.py data/sample/ioc_matches_sample.json          # fake sample feed
```

Results land in `output/`: `report.html` with every case (worst first,
filterable), a Markdown report per case with its charts, and
`assessments.json` with everything. They contain internal IPs and per-host
activity, so they're gitignored.

A couple of things worth knowing:

- The agent asks Ollama for a 32k-token context (`OLLAMA_NUM_CTX`). Ollama's
  4k default silently cuts off the start of the prompt.
- Every setting lives in `.env.example`, with placeholders.

## Evaluation

`eval/run_eval.py` runs the agent on cases with an expected verdict and
compares the expected, rule-based and model verdicts side by side.

```bash
python eval/run_eval.py                                        # quick sample
python eval/run_eval.py --all --repeat 2                       # everything, twice, to check consistency
python eval/run_eval.py --from-output output/assessments.json  # re-score a saved run, no model calls
```

## Project layout

```
assess.py               runs each case: evidence, model, checks, report
agent/
  tools.py, db.py       evidence queries and the model's guarded tools
  analysis.py           flow analysis: contact pattern, timelines, usage
  beacon.py, timeline.py
  signals.py            rule-based signals and the baseline verdict
  casefile.py           the evidence as the model reads it
  knowledge.py          malware, service and site profiles
  llm_client.py         Ollama / OpenRouter client with a tool loop
  charts.py, report.py  SVG charts and the HTML and Markdown reports
host_classification/    host-type classifier and per-type profiles
eval/                   verdict evaluation
docs/                   design notes and the data schema
```

## Limitations

- Flow records only: there are no payloads, so what was inside a session is
  unknown.
- Per-minute data is kept for about 15 days; older cases rely on large flows
  and the feed's own rows.
- Malware and service context comes from a local knowledge base, not live
  research.
- Thresholds for "rare", "popular" and "exfiltration-sized" are judgement
  calls.
- A report is a first assessment for an analyst to confirm, not a final
  answer.

For the full list of signals, checks and tools, see
[docs/how-it-works.md](docs/how-it-works.md).

## Future improvements

The agent only investigates what the feed hands it, and right now that's
ThreatFox alone. That has two consequences:

- **It only knows what's already been reported.** ThreatFox is
  community-driven, so coverage leans towards some malware families, new
  infrastructure appears only after someone spots and submits it, and many
  entries are shared addresses (CDNs, cloud hosting) that match plenty of
  innocent traffic.
- **It can't find what nobody has listed.** A host talking to a command
  server that isn't on any list never becomes a case, however strange its
  traffic looks.

Two natural next steps:

- **More threat feeds.** Indicators from other sources, such as abuse.ch's
  URLhaus and Feodo Tracker, Spamhaus or a MISP instance, normalised into the
  same case format, so the investigation could stay largely as it is.
- **An anomaly detection flow.** Much of the groundwork exists: per-type
  profiles of normal host behaviour and a per-minute beacon detector. Running
  those across all campus hosts, rather than only flagged ones, would raise
  cases with no indicator at all, which the same agent could then
  investigate.

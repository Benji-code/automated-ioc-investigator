# Host classification

Works out what kind of machine a campus host is (a workstation, a NAT gateway,
a web server, ...) and what normal behaviour looks like for that kind of
machine. The IOC agent uses it to ask whether a flagged host's traffic is
unusual *for a host of its type*.

## Host types

| Label | What it is |
|---|---|
| `end_host` | A workstation, laptop or personal device: a client, mostly web |
| `NAT_gateway` | One address shared by many devices: many apps, ports and peers, TCP and UDP |
| `website_server` | Answers HTTP(S) from many clients |
| `web_proxy` | Makes very many HTTP(S) connections on behalf of others |
| `remote_computing_server` | Answers SSH, RDP or VNC (login nodes, lab servers) |
| `non_typical_tcp_server` | Answers another TCP service (e.g. a database) |

What each normally looks like, what would be abnormal, and what compromise
would look like are in `agent/knowledge.py` (`HOST_TYPE_PROFILES`).

## Building the classifier and profiles

Real campus IPs never go in this folder: seed labels, features, the model
and the profiles all live in `data/host_classification/` (gitignored).

1. Seed labels: verified hosts in `data/host_classification/seed_labels.csv`
   (format: `seed_labels.example.csv`; columns `ip,label,coarse_label,certainty,reason`).
2. Set `CAMPUS_CIDR` in `.env` (the ClickHouse settings come from there too).
3. Run everything for one recent week (the seeds must be verified for that
   period: see "Seeds go stale" below):

   ```bash
   pip install scikit-learn        # only for training the forest
   python -m host_classification build --start 2026-09-24 --end 2026-10-01
   ```

   This extracts features for up to 8,000 active campus hosts, checks the
   rule classifier against the seeds, trains the random forest, labels every
   host, and writes per-type profiles (aggregates only, no IPs).

Each step can also run alone (`extract`, `check-rules`, `train`, `label`,
`profiles`); `classify <ip>` shows one host as the agent sees it, and
`dump-schema` writes every table's columns and example rows to
`data/schema_dump/`.

## How the agent uses it

For each case, `agent/host_type.py` extracts the same features for the host
over the `HOST_TYPE_WINDOW_DAYS` (default 7) before the match, labels it with
the trained forest (or the rules, without one), and compares each key feature
with the type's measured 5th-95th percentile range, or with rough priors from
the knowledge base if no profile is built yet. The case file shows the type,
how sure the label is, and which features are unusual for the type; the
model weighs that in its analysis.

## What the data can and cannot show

SuperNetFlow records every flow from the campus host's side: the campus host
is always `client_ip` and the remote party `server_ip`, whoever connected to
whom (checked: no campus host appears as `server_ip` in `long_flow_summary`
or `app_server_enriched_1h`). The original scripts' "server role" features
(the host as `server_ip`) were therefore always empty and have been dropped.
A server shows up through what it does instead: it sends more than it
receives (`client_up_byte_ratio`), to many addresses, on a narrow set of
ports.

The original "connected in every hour of the day" check (script.py) was also
dropped: every active seed host scored the same, because background traffic
reaches every hour.

The rule classifier was calibrated on the seed hosts' traffic over the 14
days to early October 2026: it agreed with 14 of the 21 seeds that still had
traffic. All 7 disagreements were June `website_server` or `web_proxy` seeds
whose current traffic looks like a workstation's or a NAT gateway's, which
suggests those addresses have been reassigned since they were labelled.

## Limits

- **Seeds go stale.** Addresses are reassigned, so a label is only good for
  the period it was verified in. Train on features from that period:
  `long_flow_summary` keeps about 65 days, so verify seeds against recent
  traffic and extract the same period.

- **Few seeds.** With a few dozen verified hosts the forest's labels are
  pseudo-labels. Hosts below the review threshold are marked
  `needs_manual_review`; verify some and add them to the seeds.
- **Large flows only.** The flow features come from `long_flow_summary`
  (flows over 1 MB), so a quiet host can have none.
- **Rule thresholds are judgement calls** (`classify.rule_classify`). Check them
  with `check-rules` after each extraction.
- A NAT gateway's traffic is many devices at once: a match on one says some
  device behind it made the contact, not which.

# How it works

Reference notes behind the [README](../README.md): what evidence is gathered,
how the rule-based cross-check decides, what gets a case flagged, and what
the model can do on its own.

## Evidence gathered for each case

All of this runs in Python before the model is called. In testing, a small
local model skipped optional tools almost every time, so anything that must
happen is not left to it.

| Evidence | Where |
|---|---|
| The flagged address, its ASN and whether it's shared infrastructure | `tools.identify_server_ips`, `tools.ip_asn` |
| What the threat should look like: threat type, malware family, known services (tunnels, remote access) | `tools.expected_behaviour`, `knowledge.py` |
| Flows between the host and the address, and the site names (SNI/DNS) it used there | `tools.indicator_flows`, `tools.indicator_names` |
| Contact pattern from per-minute data: regular check-ins, a held-open connection, human use or a one-off | `beacon.py` |
| A timeline of everything the host did from 5 minutes before to 2 minutes after each contact | `timeline.py` |
| What the host is used for, by kind of site, with volumes | `analysis.activity_profile` |
| Host type (workstation, NAT gateway, server, ...) and how it compares with others of its type | `host_type.py`, `host_classification/` |
| App labels, DNS resolvers, load and uptime | `tools.app_context_for_indicator`, `tools.host_dns_behaviour`, `tools.host_load_baseline` |
| Other campus hosts on the address, and every site name seen on it | `tools.indicator_peers`, `tools.names_on_ip` |

A held-open connection (a few flows lasting hours at a steady packet rate,
like a tunnel) is kept separate from beaconing (many short contacts at a
regular interval). Daily presence alone is never treated as a beacon.

When per-minute data has expired (it's kept for about 15 days), the feed's own
copy of the matched rows is used and labelled as such.

## Signals and the rule-based verdict

`signals.py` turns the evidence into ten signals, each for or against a
threat (strong or weak) or neutral:

| Signal | Against a threat | For a threat |
|---|---|---|
| `shared_infrastructure` | CDN or cloud range, many campus hosts, many sites on the address, a known public service | One site on the address, not a shared ASN (weak) |
| `sni_matches_indicator` | The host used ordinary sites on the address | A name that is itself flagged, dynamic DNS, or rare and random-looking (strong); rare, new or free hosting (weak). A domain indicator's own name is neutral: it only confirms the contact |
| `protocol_fit` | QUIC or TLS web traffic, for a custom-TCP malware family | TCP to a non-web port, for a custom-TCP family (weak) |
| `traffic_shape_fit` | A few short sessions; a tiny transfer | Regular check-ins (strong); a payload-sized download (weak) |
| `contact_pattern` | One-off or human use, or a pattern a recognised app explains | Unexplained regular check-ins day and night (strong); an unexplained held-open connection (weak) |
| `app_explained` | SuperNetFlow labels it as a known app or session | — |
| `dns_anomaly` | — | Rarely used resolvers, or many unanswered queries (weak) |
| `platform_fit` | Only signs of another operating system | User agents mostly from the targeted OS (weak) |
| `campus_spread` | Many campus hosts, none independently flagged | Other hosts flagged for the same malware family (strong) |
| `known_service` | Only the service's own client ports | Other ports on the service, e.g. a tunnel's public port (strong) |

ThreatFox confidence is deliberately not a signal: it rates the indicator,
not the host.

The baseline verdict follows fixed rules (`signals.baseline_verdict`):

1. No traffic at all: **insufficient data** (always set in code)
2. Two strong signals for a threat, or one strong and two weak: **likely threat**
3. One strong signal: **suspicious**
4. Shared infrastructure, a known service's normal client or a recognised app, with at most two weak signals: **likely false positive**
5. Two or more weak signals: **suspicious**
6. Only signals against: **likely false positive** (low confidence)
7. Nothing either way: **suspicious** (low confidence)

## When a case goes to an analyst

The model never sees the signals or the baseline. Its verdict is the
report's verdict, and the baseline is a cross-check. A case is marked for
review when:

- the model and the rules disagree (both readings are shown);
- the report quotes a number that isn't in the evidence or a query result;
- it claims exfiltration with no flow large enough, or calls a shared address
  dedicated;
- it cites a timeline row that doesn't exist, or talks about itself rather
  than the case;
- the report is missing a part or too short to be one.

Before that, the model gets its draft back once with a checklist and any
problems code found, and can query again to fix them. The checklist never
reveals the rules' verdict.

## The model's tools

All are bound to the case's host in code.

| Tool | Use |
|---|---|
| `timeline_around(time, minutes)` | Everything the host did around one moment |
| `host_baseline(days)` | The host's normal daily volume, destinations and hours |
| `compare_sessions(date_a, date_b)` | Contact with the flagged address on two dates |
| `run_sql(sql)` | Anything else: SELECT only, allowed tables, must filter on the host or flagged address and a bounded time range, 50 rows |
| `add_chart(...)` | A custom chart, under the same SQL rules |

Most charts need no tool call: the evidence step builds ready-made ones
(contact over time, the host's hourly load, what the host is used for, where
it sits among hosts of its type, sites and campus hosts on the address) and
the model places them with `[[chart name]]`. Charts are drawn as
self-contained SVG, with the data and source under each.

## Host classification

The host's own traffic over the 7 days before the match becomes the same
features used campus-wide: volume and upload share, night against day,
peers, ports, protocols and app variety. A random forest trained on weakly
supervised labels assigns its type, and each feature is placed on that
type's measured 5th–95th percentile range. A match from a NAT gateway, for
example, means some device behind it made the contact. See
[host_classification/README.md](../host_classification/README.md).

## Cross-case links

A domain behind two or more flagged addresses in the same feed is usually how
the indicator was reported (a Cloudflare site always has several addresses).
That becomes one note at the top of the report rather than evidence against
each host, and a host is only flagged for it if its own contact was more than
one visit.

## The data

The tables used, what each can and can't show, and how long each keeps data
are in [schema.md](schema.md).

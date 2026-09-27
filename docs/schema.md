# SuperNetFlow tables used by the IOC triage agent

Generated from `agent/schema.py`. Verified against the deployed database: `DESCRIBE TABLE`, table TTLs, bounded probes for the earliest data, and column fill rates on a one-hour sample. The public schema is at https://supernetflow.com/database-schema.

**IP format:** plain IPv4 text, e.g. '203.0.113.5' (no IPv4-mapped IPv6 seen in any table). **Times:** UTC.

## `canopus.subscriber_activity_1m`

- **Grain:** one row per minute per (client_ip, server_ip, server_port, application) with traffic
- **Kept:** 15 days (TTL time + 15 days)
- **Good for:** per-minute contact pattern (beacons), names used, apps, volume; campus-wide lookups by server_ip in 1-day chunks. Sorted by subscriber_id: add subscriber_id = '<from the case file>' to per-host queries or every row in the window is read
- **Not for:** anything older than 15 days; queries over more than 5 days (200M-row read limit)
- **run_sql:** allowed, at most 5 days per query

| Column | Meaning |
|---|---|
| `time` | minute (DateTime, UTC) |
| `client_ip / server_ip / server_port` | the campus host, the remote IP and port |
| `transport_protocol` | 6 = TCP, 17 = UDP |
| `application / application_category` | SuperNetFlow's app label ('_unknown' if none) |
| `sni / dns / root_domain` | names for the server IP; dns is filled on only ~4% of rows and is sometimes the CLIENT's own name |
| `user_agent` | HTTP user agent, filled on ~0.5% of rows |
| `up_volume__bytes / down_volume__bytes / up_volume__packets / down_volume__packets` | volume that minute (up = host to server) |
| `flow_count` | flows active that minute (1 across a run of minutes = one held-open connection) |
| `server_metadata__asn / server_metadata__asn_organization / server_metadata__geo_country` | ASN and country of the server IP |

**Differs from the public docs:**

- network_metadata__*, subscriber_metadata__* and labels__apn are all empty on this network (a mobile-network feature set).
- Rows labelled 'Web Browsing' have an empty server_ip: plain browsing cannot be tied to a server IP, so per-IP queries only see other apps and '_unknown' traffic.
- Sorted by subscriber_id, not client_ip; each IP maps to one subscriber_id.

## `canopus_dbt.app_subscriber_server_enriched_5m`

- **Grain:** one row per 5 minutes per (client_ip, server_ip, application); no port
- **Kept:** no TTL; data back to about June 2025
- **Good for:** contact history between a host and a server beyond the 15-day per-minute window. Sorted by subscriber_id: add subscriber_id = '<from the case file>' or a month reads ~500M rows and fails
- **Not for:** unlabelled traffic: rows with application_category '_unknown' are dropped, so contact with an unrecognised (possibly malicious) server is NOT here; ports; minute timing
- **run_sql:** allowed, at most 30 days per query

| Column | Meaning |
|---|---|
| `time` | 5-minute bucket start |
| `client_ip / server_ip` | host and remote IP |
| `application / application_category` | app label |
| `active_minutes` | minutes with traffic in the bucket (0-5) |
| `metrics_sum__up_volume__bytes / metrics_sum__down_volume__bytes` | volume in the bucket |

**Differs from the public docs:**

- Drops every '_unknown'-category row (checked against subscriber_activity_1m for the same host and days).
- No session_id_count column.
- Peak-rate and most RTT percentile columns are empty on this network.

## `canopus_dbt.subscriber_ip_load_enriched_1h`

- **Grain:** one row per hour per client_ip
- **Kept:** no TTL; data back to June 2025
- **Good for:** host baseline: always-on or not, normal volume, whether the match time stands out
- **Not for:** who the host talked to (no server column)
- **run_sql:** allowed, at most 90 days per query

| Column | Meaning |
|---|---|
| `time` | hour |
| `client_ip` | the campus host |
| `active_minutes` | minutes with any traffic in the hour |
| `metrics_sum__up_volume__bytes / metrics_sum__down_volume__bytes` | the host's total volume in the hour |

**Differs from the public docs:**

- RTT and peak-rate percentile columns are empty on this network.

## `canopus_dbt.app_server_enriched_1h`

- **Grain:** one row per hour per (server_ip, application), campus-wide
- **Kept:** no TTL; data back to June 2025
- **Good for:** what app SuperNetFlow ties to a server IP across campus, and how many hosts use it
- **Not for:** per-host detail; unlabelled traffic ('_unknown' is not in this table)
- **run_sql:** allowed, at most 90 days per query

| Column | Meaning |
|---|---|
| `time` | hour |
| `server_ip` | remote IP |
| `application / application_category` | app label for traffic to that IP |
| `client_ip_count` | distinct campus hosts that hour |

## `public.long_flow_summary`

- **Grain:** one row per individual flow over 1 MB
- **Kept:** 65 days after the flow FINISHES (TTL finish + 65 days)
- **Good for:** large transfers, upload-heavy sessions and long held-open sessions over 1 MB; names from attributes.sni when the per-minute data has expired
- **Not for:** beacons or any small or short connection: flows under 1 MB are not stored, so a missing row is not evidence of no traffic
- **run_sql:** allowed, at most 90 days per query

| Column | Meaning |
|---|---|
| `start / finish / duration_sec` | flow timing |
| `client_ip / server_ip / client_port / server_port / protocol` | the connection (6 = TCP, 17 = UDP) |
| `up_bytes / down_bytes / up_packets / down_packets` | flow totals |
| `attributes` | JSON; attributes.sni is filled on ~95% of rows, attributes.dns on ~7% |

**Differs from the public docs:**

- TTL is on finish, so a long flow can keep a start date older than 65 days.

## `public.ux_sessions`

- **Grain:** one row per completed application session (e.g. a YouTube video, a game match)
- **Kept:** 400 days after finish (TTL)
- **Good for:** whether the flagged IP was part of a recognised app session, which explains the traffic
- **Not for:** unrecognised apps (only known providers make sessions)
- **run_sql:** allowed, at most 90 days per query

| Column | Meaning |
|---|---|
| `start / finish / duration_sec` | session timing |
| `client_ip` | the campus host |
| `type / provider` | e.g. Video / YouTube, Gameplay / Minecraft, Software Update / Google |
| `servers.server_ip` | array of server IPs used in the session (use has(servers.server_ip, '...')) |

## `public.dns_tuple`

- **Grain:** DNS performance per (client_ip, DNS server) per hour
- **Kept:** 400 days (TTL)
- **Good for:** which external DNS resolvers a host uses directly, how rare they are on campus, and the unanswered rate
- **Not for:** domain names (there are none); NXDOMAIN/SERVFAIL rates (rcode is always -1 here); hosts that only use the campus resolvers (that traffic is not captured)
- **run_sql:** allowed, at most 30 days per query

| Column | Meaning |
|---|---|
| `client_ip` | the host that asked |
| `server_ip` | the DNS server it asked |
| `n_complete_sessions / n_unanswered_sessions` | answered and unanswered DNS exchanges |
| `mean_service_nanos` | mean response time |

**Differs from the public docs:**

- No n_nxdomain, n_servfail or n_refused columns; a single rcode column that is always -1, so response codes are not available.
- Only DNS crossing the border is captured: most hosts are absent, and the campus resolver itself appears as a client.

## `public.dns_server`

- **Grain:** DNS counters per DNS server per hour
- **Kept:** 400 days (TTL)
- **Good for:** telling commonly used resolvers from rare ones
- **Not for:** query names (the question column is empty here) or response codes (rcode is always -1)
- **run_sql:** allowed, at most 30 days per query

| Column | Meaning |
|---|---|
| `server_ip` | DNS server |
| `n_unique_client_tags` | distinct clients |

**Differs from the public docs:**

- question is empty and rcode is always -1.

## `canopus.asn`

- **Grain:** one row per announced CIDR
- **Kept:** lookup table
- **Good for:** ASN and organisation for an IP when the flow rows have none
- **Not for:** -

| Column | Meaning |
|---|---|
| `asn_cidr / asn / asn_organization` | lower-case column names |

**Differs from the public docs:**

- Column names are lower case (docs show ASN_CIDR etc.).

## `canopus.geo`

- **Grain:** one row per geo CIDR
- **Kept:** lookup table
- **Good for:** country and city for an IP when the flow rows have none
- **Not for:** -

| Column | Meaning |
|---|---|
| `geo_cidr / geo_country / geo_city` | lower-case column names |

**Differs from the public docs:**

- Column names are lower case (docs show GEO_* ).

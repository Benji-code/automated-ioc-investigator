"""ClickHouse (SuperNetFlow) queries.

Two kinds of access live here:
  - fetch_* functions: fixed, parameterised queries behind the deterministic
    tools in tools.py. They return pandas DataFrames; analysis.py does the rest.
  - run_sql(): the one general query tool the model can call for open-ended
    follow-ups. Its guardrails are enforced here in code, not asked for in the
    prompt (a lesson from the APAN62 agents workshop): each rejection returns
    a plain-text error the model can read and fix its query from.

Connection settings come from .env (see config.py).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import pandas as pd

from . import config

from .schema import RUN_SQL_TABLES, SCHEMA_CARD  # noqa: E402,F401  (SCHEMA_CARD re-exported for the prompt)

LONG_FLOW_TABLE = "public.long_flow_summary"
SUBSCRIBER_ACTIVITY_TABLE = "canopus.subscriber_activity_1m"
APP_SERVER_5M_TABLE = "canopus_dbt.app_subscriber_server_enriched_5m"
IP_LOAD_1H_TABLE = "canopus_dbt.subscriber_ip_load_enriched_1h"
APP_SERVER_CAMPUS_1H_TABLE = "canopus_dbt.app_server_enriched_1h"
UX_SESSIONS_TABLE = "public.ux_sessions"
DNS_TUPLE_TABLE = "public.dns_tuple"
ASN_TABLE = "canopus.asn"
GEO_TABLE = "canopus.geo"
ALLOWED_TABLES = tuple(RUN_SQL_TABLES)
FIVE_MIN_CHUNK_DAYS = 30   # 5-minute tables: at most 30 days per query
CAMPUS_CHUNK_DAYS = 1      # campus-wide per-minute lookups: 1 day per query

MAX_SQL_ROWS = 50           # row cap for run_sql, enforced in the tool
MAX_INDICATOR_FLOWS = 2000  # every flow is needed for interval analysis, not just the largest
MAX_PEERS = 20
MAX_NAME_ROWS = 50
MAX_PASSIVE_DNS_ROWS = 40
MAX_TIMELINE_ROWS = 40
MAX_TIMELINE_MINUTES = 180
MAX_MATCH_WINDOWS = 20      # ±N-minute windows around feed matches, merged and capped
MAX_OTHER_LONG_FLOWS = 200
OTHER_LONG_FLOW_MIN_SEC = 3600
# Aggregates are aliased *_total because ClickHouse substitutes an alias that
# matches a column name (sum(up_bytes) AS up_bytes) into the rest of the query.
TOTALS_TO_BYTES = {"up_total": "up_bytes", "down_total": "down_bytes"}

DOMAIN_NOTES = """
- All timestamps are UTC.
- "up" is from the internal host to the server; "down" is server to host.
- "cloudflare-ech.com" as an SNI is a TLS Encrypted Client Hello placeholder,
  not a real destination: the real SNI was encrypted.
- There is no table of DNS answers. public.dns_tuple only records which DNS
  resolver a client asked, with no names and no response codes (rcode is
  always -1 here), so names for a server IP come from subscriber_activity_1m
  (sni, dns, root_domain) and long_flow_summary (attributes.sni).
- long_flow_summary only holds flows over 1 MB: no rows there is NOT evidence
  of no traffic, and it cannot show beacons.
- subscriber_activity_1m keeps about 15 days. An older match can return 0 rows
  even though the traffic happened. That is retention, not a false positive.
- long_flow_summary only has flows over a size/duration threshold. Short flows
  are missing, so a real small connection can have no rows there.
- SuperNetFlow application labels (classifier/type) are often inconsistent;
  prefer ports, names and traffic shape.
- Flow data has no payloads. Visitors reaching a host through a tunnel appear
  as the tunnel server's IP, not their own.
- A query without a client_ip filter and a time filter can hit the
  200-million-row read limit. run_sql rejects such queries.
"""


# --- connection -----------------------------------------------------------------

@lru_cache(maxsize=1)
def _client():
    import clickhouse_connect  # imported lazily so offline tests never need it

    settings = config.clickhouse_settings()
    return clickhouse_connect.get_client(connect_timeout=10, **settings)


def query(sql: str) -> pd.DataFrame:
    return _client().query_df(sql)


def _escape(value) -> str:
    """Single-quote escaping for values put into SQL. Callers pass IPs and
    domains from the feed, but a malformed feed value shouldn't break a query."""
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def _ip_list(ips: list[str]) -> str:
    return ", ".join(f"'{_escape(ip)}'" for ip in ips)


def _time_filter(column: str, start: datetime, end: datetime) -> str:
    return (
        f"{column} >= toDateTime('{start:%Y-%m-%d %H:%M:%S}', 'UTC') "
        f"AND {column} < toDateTime('{end:%Y-%m-%d %H:%M:%S}', 'UTC')"
    )


def time_chunks(start: datetime, end: datetime, chunk_days: int) -> list[tuple[datetime, datetime]]:
    """Split [start, end) into consecutive pieces of at most chunk_days."""
    chunks = []
    step = timedelta(days=chunk_days)
    chunk_start = start
    while chunk_start < end:
        chunk_end = min(chunk_start + step, end)
        chunks.append((chunk_start, chunk_end))
        chunk_start = chunk_end
    return chunks


def _query_activity_chunked(sql_template: str, start: datetime | None, end: datetime | None,
                            chunk_days: int | None = None) -> pd.DataFrame:
    """Run a query once per chunk (default ACTIVITY_CHUNK_DAYS, for
    subscriber_activity_1m) and stack the results. sql_template must contain
    {time_filter}. Callers re-aggregate the stacked rows in pandas."""
    if start is None or end is None or start >= end:
        return pd.DataFrame()
    frames = []
    for chunk_start, chunk_end in time_chunks(start, end, chunk_days or config.ACTIVITY_CHUNK_DAYS):
        sql = sql_template.format(time_filter=_time_filter("time", chunk_start, chunk_end))
        frame = query(sql)
        if not frame.empty:
            frames.append(frame)
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)


# subscriber_activity_1m and the 5-minute app table are sorted by
# subscriber_id, not client_ip: a client_ip filter alone scans every row in
# the time range (a 30-day 5-minute query read 500M rows and failed). Each IP
# maps to one subscriber_id (checked: 0 of ~9,800 IPs had two in a day), so it
# is looked up once per host from the hourly load table (sorted by client_ip)
# and added to per-host queries on those tables.
@lru_cache(maxsize=512)
def subscriber_ids(client_ip: str) -> tuple[str, ...]:
    for days in (30, 120):
        try:
            frame = query(f"""
            SELECT groupUniqArray(20)(subscriber_id) AS ids FROM {IP_LOAD_1H_TABLE}
            WHERE client_ip = '{_escape(client_ip)}' AND time >= now() - INTERVAL {days} DAY
            """)
        except Exception:  # noqa: BLE001 - fall back to a client_ip-only filter
            return ()
        ids = tuple(frame["ids"].iloc[0]) if not frame.empty else ()
        if ids:
            return ids
    return ()


def _host(client_ip: str) -> str:
    """WHERE clause for one host on a subscriber_id-sorted table."""
    clause = f"client_ip = '{_escape(client_ip)}'"
    ids = subscriber_ids(client_ip)
    if ids:
        clause = f"subscriber_id IN ({_ip_list(list(ids))}) AND " + clause
    return clause


# --- fixed queries behind tools.py -------------------------------------------------

# SuperNetFlow sometimes puts the CLIENT's own reverse-DNS name in the `dns`
# column (and derives root_domain from it), so a destination appears to be
# the host's own domain. When the host's name is known, those rows lose
# their dns/root_domain. Aliased *_name so ClickHouse does not substitute
# the expression back into the column it reads (see the TOTALS note above).
NAME_RENAMES = {"dns_name": "dns", "root_name": "root_domain"}


def _name_columns(own_name: str | None) -> str:
    if not own_name:
        return "dns AS dns_name, root_domain AS root_name"
    own = _escape(own_name.lower())
    return (f"if(lower(dns) = '{own}', '', dns) AS dns_name, "
            f"if(lower(dns) = '{own}', '', root_domain) AS root_name")


def fetch_long_flow_retention_start() -> datetime | None:
    """Earliest finish time still in long_flow_summary. The table is
    partitioned by finish day, so flows that ended before this are gone
    whatever the query window."""
    frame = query(f"SELECT min(finish) AS earliest FROM {LONG_FLOW_TABLE}")
    if frame.empty or pd.isna(frame["earliest"].iloc[0]):
        return None
    return pd.Timestamp(frame["earliest"].iloc[0]).to_pydatetime()

def fetch_domain_ips(client_ip: str, domain: str, start: datetime | None, end: datetime | None) -> pd.DataFrame:
    """Server IPs this host reached under this domain (DNS, SNI or root domain)."""
    d = _escape(domain)
    template = f"""
    SELECT server_ip, any(dns) AS dns_name, any(sni) AS sni_name, count() AS minutes
    FROM {SUBSCRIBER_ACTIVITY_TABLE}
    WHERE {_host(client_ip)}
      AND (dns = '{d}' OR sni = '{d}' OR root_domain = '{d}')
      AND {{time_filter}}
    GROUP BY server_ip
    """
    return _query_activity_chunked(template, start, end)


def fetch_indicator_long_flows(client_ip: str, server_ips: list[str], start: datetime, end: datetime) -> pd.DataFrame:
    """Every long flow between the host and the flagged IP(s) in the window."""
    sql = f"""
    SELECT start, finish, duration_sec, server_ip, server_port, client_port, protocol,
           up_bytes, down_bytes, up_packets, down_packets, classifier, type
    FROM {LONG_FLOW_TABLE}
    WHERE client_ip = '{_escape(client_ip)}' AND server_ip IN ({_ip_list(server_ips)})
      AND {_time_filter("start", start, end)}
    ORDER BY start
    LIMIT {MAX_INDICATOR_FLOWS}
    """
    return query(sql)


def fetch_indicator_activity(client_ip: str, server_ips: list[str],
                             start: datetime | None, end: datetime | None, own_name: str | None = None) -> pd.DataFrame:
    """Per-day activity between the host and the flagged IP(s), by port and name."""
    template = f"""
    SELECT toDate(time) AS day, server_ip, server_port, transport_protocol, sni, {_name_columns(own_name)},
           server_metadata__asn AS asn, server_metadata__asn_organization AS asn_org,
           server_metadata__geo_country AS country,
           count() AS minutes,
           sum(up_volume__bytes) AS up_bytes, sum(down_volume__bytes) AS down_bytes,
           sum(up_volume__packets) AS up_packets, sum(down_volume__packets) AS down_packets,
           min(time) AS first_time, max(time) AS last_time
    FROM {SUBSCRIBER_ACTIVITY_TABLE}
    WHERE {_host(client_ip)} AND server_ip IN ({_ip_list(server_ips)})
      AND {{time_filter}}
    GROUP BY day, server_ip, server_port, transport_protocol, sni, dns_name, root_name, asn, asn_org, country
    """
    return _query_activity_chunked(template, start, end).rename(columns=NAME_RENAMES)


def fetch_host_activity(client_ip: str, exclude_ips: list[str],
                        start: datetime | None, end: datetime | None, own_name: str | None = None) -> pd.DataFrame:
    """The host's activity to every other destination, by domain, IP and port."""
    exclude = f"AND server_ip NOT IN ({_ip_list(exclude_ips)})" if exclude_ips else ""
    template = f"""
    SELECT {_name_columns(own_name)}, server_ip, server_port, transport_protocol,
           count() AS minutes,
           sum(up_volume__bytes) AS up_total, sum(down_volume__bytes) AS down_total
    FROM {SUBSCRIBER_ACTIVITY_TABLE}
    WHERE {_host(client_ip)} {exclude}
      AND {{time_filter}}
    GROUP BY root_name, dns_name, server_ip, server_port, transport_protocol
    """
    frame = _query_activity_chunked(template, start, end).rename(columns={**NAME_RENAMES, **TOTALS_TO_BYTES})
    return frame.drop(columns=["dns"], errors="ignore")


def fetch_host_long_lived_flows(client_ip: str, exclude_ips: list[str], start: datetime, end: datetime) -> pd.DataFrame:
    """The host's long-lived flows (an hour or more) to other IPs, per IP and port."""
    exclude = f"AND server_ip NOT IN ({_ip_list(exclude_ips)})" if exclude_ips else ""
    sql = f"""
    SELECT server_ip, server_port, protocol,
           count() AS flows, sum(duration_sec) AS total_duration_sec, max(duration_sec) AS max_duration_sec,
           sum(up_bytes) AS up_total, sum(down_bytes) AS down_total,
           min(start) AS first_start, max(finish) AS last_finish
    FROM {LONG_FLOW_TABLE}
    WHERE client_ip = '{_escape(client_ip)}' {exclude}
      AND duration_sec >= {OTHER_LONG_FLOW_MIN_SEC}
      AND {_time_filter("start", start, end)}
    GROUP BY server_ip, server_port, protocol
    ORDER BY up_total + down_total DESC
    LIMIT {MAX_OTHER_LONG_FLOWS}
    """
    return query(sql).rename(columns=TOTALS_TO_BYTES)


def fetch_peers(server_ip: str, server_port: int | None = None) -> pd.DataFrame:
    """Internal hosts that talked to this server over the peer lookback window."""
    port_clause = f"AND server_port = {int(server_port)}" if server_port else ""
    sql = f"""
    SELECT client_ip,
           count()          AS flows,
           min(start)       AS first_seen,
           max(finish)      AS last_seen,
           sum(up_bytes)    AS up_total,
           sum(down_bytes)  AS down_total,
           groupUniqArray(10)(server_port) AS ports
    FROM {LONG_FLOW_TABLE}
    WHERE server_ip = '{_escape(server_ip)}' {port_clause}
      AND start >= now() - INTERVAL {int(config.PEER_LOOKBACK_DAYS)} DAY
    GROUP BY client_ip
    ORDER BY flows DESC
    LIMIT {MAX_PEERS}
    """
    return query(sql).rename(columns=TOTALS_TO_BYTES)


def _match_condition(windows: list[tuple[datetime, datetime]]) -> str:
    """SQL condition: time falls inside any of the given windows."""
    if not windows:
        return "0"
    return "(" + " OR ".join(f"({_time_filter('time', a, b)})" for a, b in windows) + ")"


def fetch_indicator_names(client_ip: str, server_ips: list[str], start: datetime | None, end: datetime | None,
                          match_windows: list[tuple[datetime, datetime]], own_name: str | None = None) -> pd.DataFrame:
    """Names (SNI, DNS, root domain) the host used on the flagged IP(s), with
    minutes and bytes per name, and how many of those minutes fall within
    ±NAMES_WINDOW_MINUTES of a feed match."""
    near = _match_condition(match_windows[:MAX_MATCH_WINDOWS])
    template = f"""
    SELECT sni, {_name_columns(own_name)}, server_ip, server_port, transport_protocol,
           count() AS minutes, countIf({near}) AS near_match_minutes,
           sum(up_volume__bytes) AS up_total, sum(down_volume__bytes) AS down_total,
           min(time) AS first_time, max(time) AS last_time
    FROM {SUBSCRIBER_ACTIVITY_TABLE}
    WHERE {_host(client_ip)} AND server_ip IN ({_ip_list(server_ips)})
      AND {{time_filter}}
    GROUP BY sni, dns_name, root_name, server_ip, server_port, transport_protocol
    ORDER BY minutes DESC
    LIMIT {MAX_NAME_ROWS}
    """
    return _query_activity_chunked(template, start, end).rename(columns={**NAME_RENAMES, **TOTALS_TO_BYTES})


def fetch_names_on_ip(server_ip: str, start: datetime, end: datetime) -> pd.DataFrame:
    """Campus-wide: the names seen on this server IP and how many distinct
    campus hosts used each (one chunk of at most CAMPUS_LOOKUP_DAYS)."""
    sql = f"""
    SELECT root_domain, sni, dns, uniqExact(client_ip) AS hosts, count() AS minutes,
           any(server_metadata__asn) AS asn_id, any(server_metadata__asn_organization) AS asn_org
    FROM {SUBSCRIBER_ACTIVITY_TABLE}
    WHERE server_ip = '{_escape(server_ip)}' AND {_time_filter("time", start, end)}
    GROUP BY root_domain, sni, dns
    ORDER BY hosts DESC, minutes DESC
    LIMIT {MAX_PASSIVE_DNS_ROWS}
    """
    return query(sql)


def fetch_ip_host_count(server_ip: str, start: datetime, end: datetime) -> int:
    """Distinct campus hosts on this server IP (subscriber_activity_1m, one chunk)."""
    sql = f"""
    SELECT uniqExact(client_ip) AS hosts FROM {SUBSCRIBER_ACTIVITY_TABLE}
    WHERE server_ip = '{_escape(server_ip)}' AND {_time_filter("time", start, end)}
    """
    frame = query(sql)
    return int(frame["hosts"].iloc[0]) if not frame.empty else 0


def fetch_asn(ip: str) -> dict | None:
    """Most specific ASN entry for an IPv4 address from canopus.asn."""
    sql = f"""
    SELECT asn, asn_organization, asn_cidr FROM {ASN_TABLE}
    WHERE isIPAddressInRange('{_escape(ip)}', asn_cidr)
    ORDER BY toUInt8OrZero(splitByChar('/', asn_cidr)[2]) DESC
    LIMIT 1
    """
    frame = query(sql)
    if frame.empty:
        return None
    row = frame.iloc[0]
    return {"asn": str(row["asn"]), "asn_org": str(row["asn_organization"]), "cidr": str(row["asn_cidr"])}


def fetch_domain_popularity(root_domains: list[str], start: datetime, end: datetime,
                            client_ip: str = "") -> pd.DataFrame:
    """Distinct campus hosts per root domain over one chunk (at most
    CAMPUS_LOOKUP_DAYS): all hosts, and hosts other than this case's."""
    sql = f"""
    SELECT root_domain, uniqExact(client_ip) AS hosts,
           uniqExactIf(client_ip, client_ip != '{_escape(client_ip)}') AS other_hosts
    FROM {SUBSCRIBER_ACTIVITY_TABLE}
    WHERE root_domain IN ({_ip_list(root_domains)}) AND {_time_filter("time", start, end)}
    GROUP BY root_domain
    """
    return query(sql)


def fetch_domain_first_seen(root_domains: list[str], start: datetime, end: datetime) -> pd.DataFrame:
    """Earliest minute each root domain appears on campus within retention."""
    template = f"""
    SELECT root_domain, min(time) AS first_time
    FROM {SUBSCRIBER_ACTIVITY_TABLE}
    WHERE root_domain IN ({_ip_list(root_domains)}) AND {{time_filter}}
    GROUP BY root_domain
    """
    frame = _query_activity_chunked(template, start, end)
    if frame.empty:
        return frame
    return frame.groupby("root_domain", as_index=False)["first_time"].min()


def fetch_host_timeline(client_ip: str, start: datetime, end: datetime, own_name: str | None = None) -> pd.DataFrame:
    """Everything the host did in a short window: destinations, names, bytes."""
    sql = f"""
    SELECT {_name_columns(own_name)}, sni, server_ip, server_port, transport_protocol,
           count() AS minutes, sum(up_volume__bytes) AS up_total, sum(down_volume__bytes) AS down_total,
           min(time) AS first_time, max(time) AS last_time
    FROM {SUBSCRIBER_ACTIVITY_TABLE}
    WHERE {_host(client_ip)} AND {_time_filter("time", start, end)}
    GROUP BY root_name, dns_name, sni, server_ip, server_port, transport_protocol
    ORDER BY up_total + down_total DESC
    LIMIT {MAX_TIMELINE_ROWS}
    """
    return query(sql).rename(columns={**NAME_RENAMES, **TOTALS_TO_BYTES})


def fetch_host_baseline(client_ip: str, start: datetime, end: datetime) -> pd.DataFrame:
    """Per-day volume, destination counts and active hours for the host."""
    template = f"""
    SELECT toDate(time) AS day, uniqExact(server_ip) AS server_ips, uniqExact(root_domain) AS root_domains,
           count() AS minutes, sum(up_volume__bytes) AS up_total, sum(down_volume__bytes) AS down_total,
           groupUniqArray(toHour(time)) AS hours
    FROM {SUBSCRIBER_ACTIVITY_TABLE}
    WHERE {_host(client_ip)} AND {{time_filter}}
    GROUP BY day
    """
    return _query_activity_chunked(template, start, end).rename(columns=TOTALS_TO_BYTES)


# --- task 3: per-minute contact series, apps, DNS, load, sessions ----------------------

def _port_clause(port: int | None) -> str:
    return f"AND server_port = {int(port)}" if port else ""


def fetch_contact_series_1m(client_ip: str, server_ips: list[str], port: int | None,
                            start: datetime | None, end: datetime | None) -> pd.DataFrame:
    """One row per active minute between the host and the flagged IP(s):
    flows active, bytes, packets, and SuperNetFlow's app label."""
    template = f"""
    SELECT time, sum(flow_count) AS flows,
           sum(up_volume__bytes) AS up_total, sum(down_volume__bytes) AS down_total,
           sum(up_volume__packets) AS up_pkts, sum(down_volume__packets) AS down_pkts,
           any(application) AS app, any(application_category) AS app_category
    FROM {SUBSCRIBER_ACTIVITY_TABLE}
    WHERE {_host(client_ip)} AND server_ip IN ({_ip_list(server_ips)}) {_port_clause(port)}
      AND {{time_filter}}
    GROUP BY time ORDER BY time
    """
    return _query_activity_chunked(template, start, end).rename(columns=TOTALS_TO_BYTES)


def fetch_contact_series_5m(client_ip: str, server_ips: list[str], start: datetime, end: datetime) -> pd.DataFrame:
    """One row per active 5-minute bucket (no port), for older contact history."""
    template = f"""
    SELECT time, sum(active_minutes) AS active,
           sum(metrics_sum__up_volume__bytes) AS up_total, sum(metrics_sum__down_volume__bytes) AS down_total,
           any(application) AS app, any(application_category) AS app_category
    FROM {APP_SERVER_5M_TABLE}
    WHERE {_host(client_ip)} AND server_ip IN ({_ip_list(server_ips)}) AND {{time_filter}}
    GROUP BY time ORDER BY time
    """
    return _query_activity_chunked(template, start, end, FIVE_MIN_CHUNK_DAYS).rename(columns=TOTALS_TO_BYTES)


def fetch_indicator_apps(client_ip: str, server_ips: list[str], start: datetime, end: datetime) -> pd.DataFrame:
    """App labels on the host's traffic to the flagged IP(s) (5-minute table, long history)."""
    template = f"""
    SELECT application, application_category, count() AS buckets, sum(active_minutes) AS minutes
    FROM {APP_SERVER_5M_TABLE}
    WHERE {_host(client_ip)} AND server_ip IN ({_ip_list(server_ips)}) AND {{time_filter}}
    GROUP BY application, application_category
    """
    return _query_activity_chunked(template, start, end, FIVE_MIN_CHUNK_DAYS)


def fetch_server_apps_campus(server_ips: list[str], start: datetime, end: datetime) -> pd.DataFrame:
    """Campus-wide app labels for the flagged IP(s) and the peak number of hosts per hour."""
    sql = f"""
    SELECT server_ip, application, application_category,
           max(client_ip_count) AS peak_hosts, sum(active_minutes) AS minutes
    FROM {APP_SERVER_CAMPUS_1H_TABLE}
    WHERE server_ip IN ({_ip_list(server_ips)}) AND {_time_filter("time", start, end)}
    GROUP BY server_ip, application, application_category
    ORDER BY minutes DESC LIMIT 20
    """
    return query(sql)


def fetch_ux_sessions(client_ip: str | None, server_ips: list[str], start: datetime, end: datetime) -> pd.DataFrame:
    """Recognised app sessions that used the flagged IP(s): for this host, or
    campus-wide when client_ip is None."""
    host = f"AND client_ip = '{_escape(client_ip)}'" if client_ip else ""
    sql = f"""
    SELECT type, provider, count() AS sessions, uniqExact(client_ip) AS hosts,
           min(start) AS first_start, max(finish) AS last_finish
    FROM {UX_SESSIONS_TABLE}
    WHERE hasAny(servers.server_ip, [{_ip_list(server_ips)}]) {host} AND {_time_filter("start", start, end)}
    GROUP BY type, provider ORDER BY sessions DESC LIMIT 10
    """
    return query(sql)


def fetch_host_applications(client_ip: str, start: datetime | None, end: datetime | None) -> pd.DataFrame:
    """The host's traffic by app label (subscriber_activity_1m)."""
    template = f"""
    SELECT application_category, application, count() AS minutes,
           sum(up_volume__bytes) AS up_total, sum(down_volume__bytes) AS down_total
    FROM {SUBSCRIBER_ACTIVITY_TABLE}
    WHERE {_host(client_ip)} AND {{time_filter}}
    GROUP BY application_category, application
    """
    return _query_activity_chunked(template, start, end).rename(columns=TOTALS_TO_BYTES)


def fetch_host_user_agents(client_ip: str, start: datetime | None, end: datetime | None,
                           flow_start: datetime, flow_end: datetime) -> pd.DataFrame:
    """HTTP user agents the host sent: subscriber_activity_1m plus
    long_flow_summary attributes (which keep longer)."""
    template = f"""
    SELECT user_agent AS agent, count() AS minutes FROM {SUBSCRIBER_ACTIVITY_TABLE}
    WHERE {_host(client_ip)} AND user_agent != '' AND {{time_filter}}
    GROUP BY agent
    """
    recent = _query_activity_chunked(template, start, end)
    older = query(f"""
    SELECT attributes.http_user_agent AS agent, count() AS minutes FROM {LONG_FLOW_TABLE}
    WHERE client_ip = '{_escape(client_ip)}' AND attributes.http_user_agent != ''
      AND {_time_filter("start", flow_start, flow_end)}
    GROUP BY agent LIMIT 50
    """)
    frames = [f for f in (recent, older) if not f.empty]
    if not frames:
        return pd.DataFrame(columns=["agent", "minutes"])
    return pd.concat(frames).groupby("agent", as_index=False)["minutes"].sum()


def fetch_host_dns(client_ip: str, start: datetime, end: datetime) -> pd.DataFrame:
    """External DNS servers the host asked directly (dns_tuple)."""
    sql = f"""
    SELECT server_ip, any(server_group) AS server_group,
           sum(n_complete_sessions) AS answered, sum(n_unanswered_sessions) AS unanswered
    FROM {DNS_TUPLE_TABLE}
    WHERE client_ip = '{_escape(client_ip)}' AND {_time_filter("time", start, end)}
    GROUP BY server_ip ORDER BY answered DESC LIMIT 20
    """
    return query(sql)


def fetch_dns_campus_baseline(server_ips: list[str], start: datetime, end: datetime) -> tuple[pd.DataFrame, float | None]:
    """How many campus clients used each of these DNS servers, and the
    campus median unanswered ratio per client, over the period (dns_tuple)."""
    clients = pd.DataFrame(columns=["server_ip", "clients"])
    if server_ips:
        clients = query(f"""
        SELECT server_ip, uniqExact(client_ip) AS clients FROM {DNS_TUPLE_TABLE}
        WHERE server_ip IN ({_ip_list(server_ips)}) AND {_time_filter("time", start, end)}
        GROUP BY server_ip
        """)
    median = query(f"""
    SELECT quantile(0.5)(ratio) AS median_ratio FROM (
        SELECT client_ip, sum(n_unanswered_sessions) / greatest(sum(n_complete_sessions) + sum(n_unanswered_sessions), 1) AS ratio
        FROM {DNS_TUPLE_TABLE} WHERE {_time_filter("time", start, end)} GROUP BY client_ip)
    """)
    value = median["median_ratio"].iloc[0] if not median.empty else None
    return clients, (float(value) if value is not None and not pd.isna(value) else None)


def fetch_dns_public_only_share(public_ips: list[str], start: datetime, end: datetime) -> float | None:
    """Share of campus clients in dns_tuple that only ask the given public
    resolvers (the campus resolver itself excluded, as it asks everyone)."""
    frame = query(f"""
    SELECT avg(only_public) AS share FROM (
        SELECT client_ip, min(server_ip IN ({_ip_list(public_ips)})) AS only_public
        FROM {DNS_TUPLE_TABLE} WHERE {_time_filter("time", start, end)}
        GROUP BY client_ip HAVING uniqExact(server_ip) < 50)
    """)
    value = frame["share"].iloc[0] if not frame.empty else None
    return float(value) if value is not None and not pd.isna(value) else None


def fetch_host_load_1h(client_ip: str, start: datetime, end: datetime) -> pd.DataFrame:
    """The host's hourly load (subscriber_ip_load_enriched_1h, long history)."""
    sql = f"""
    SELECT time, sum(active_minutes) AS active,
           sum(metrics_sum__up_volume__bytes) AS up_total, sum(metrics_sum__down_volume__bytes) AS down_total
    FROM {IP_LOAD_1H_TABLE}
    WHERE client_ip = '{_escape(client_ip)}' AND {_time_filter("time", start, end)}
    GROUP BY time ORDER BY time
    """
    return query(sql).rename(columns=TOTALS_TO_BYTES)


def fetch_names_on_ip_long_flows(server_ip: str, start: datetime, end: datetime) -> pd.DataFrame:
    """Campus-wide SNIs on one server IP from long_flow_summary attributes."""
    sql = f"""
    SELECT attributes.sni AS sni_name, uniqExact(client_ip) AS hosts, count() AS flows
    FROM {LONG_FLOW_TABLE}
    WHERE server_ip = '{_escape(server_ip)}' AND attributes.sni != '' AND {_time_filter("start", start, end)}
    GROUP BY sni_name ORDER BY hosts DESC LIMIT 30
    """
    return query(sql)


def fetch_indicator_flow_names(client_ip: str, server_ips: list[str], start: datetime, end: datetime) -> pd.DataFrame:
    """SNI/DNS names in long_flow_summary attributes for the host's flows to the flagged IP(s)."""
    sql = f"""
    SELECT attributes.sni AS sni_name, attributes.dns AS dns_name, count() AS flows,
           sum(up_bytes) AS up_total, sum(down_bytes) AS down_total
    FROM {LONG_FLOW_TABLE}
    WHERE client_ip = '{_escape(client_ip)}' AND server_ip IN ({_ip_list(server_ips)})
      AND {_time_filter("start", start, end)}
    GROUP BY sni_name, dns_name
    """
    return query(sql).rename(columns=TOTALS_TO_BYTES)


def fetch_geo(ip: str) -> dict | None:
    """Most specific geo entry for an IPv4 address from canopus.geo."""
    frame = query(f"""
    SELECT geo_country, geo_city, geo_cidr FROM {GEO_TABLE}
    WHERE isIPAddressInRange('{_escape(ip)}', geo_cidr)
    ORDER BY toUInt8OrZero(splitByChar('/', geo_cidr)[2]) DESC LIMIT 1
    """)
    if frame.empty:
        return None
    row = frame.iloc[0]
    return {"country": str(row["geo_country"]), "city": str(row["geo_city"])}


# --- run_sql: the model's general query tool -------------------------------------------

DATETIME_LITERAL_RE = re.compile(r"'(\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?)'")
NOW_INTERVAL_RE = re.compile(r"(?i)now\(\)\s*-\s*(?:toIntervalDay\((\d+)\)|INTERVAL\s+(\d+)\s+(MINUTE|HOUR|DAY|WEEK|MONTH))")
INTERVAL_DAYS = {"MINUTE": 1 / 1440, "HOUR": 1 / 24, "DAY": 1, "WEEK": 7, "MONTH": 31}


def query_span_days(sql: str, now: datetime | None = None) -> float | None:
    """How many days a query's time bounds cover: two literal datetimes, or
    'now() - INTERVAL n unit', or one literal lower bound up to now. None if
    the span cannot be read."""
    now = (now or datetime.now(timezone.utc)).replace(tzinfo=None)
    spans = []
    for match in NOW_INTERVAL_RE.finditer(sql):
        if match.group(1):
            spans.append(float(match.group(1)))
        else:
            spans.append(float(match.group(2)) * INTERVAL_DAYS[match.group(3).upper()])
    stamps = [datetime.fromisoformat(v.replace("T", " ")) for v in DATETIME_LITERAL_RE.findall(sql)]
    if len(stamps) >= 2:
        spans.append((max(stamps) - min(stamps)).total_seconds() / 86400)
    elif len(stamps) == 1 and not spans:
        spans.append((now - stamps[0]).total_seconds() / 86400)
    return max(spans) if spans else None


def check_sql(sql: str, case_client_ip: str, case_server_ips: list[str] | tuple = (),
              row_cap: int = MAX_SQL_ROWS) -> tuple[str | None, str]:
    """Check a model-written query in code. Returns (error, query to run):
      - SELECT only, on the tables in schema.RUN_SQL_TABLES;
      - filtered on this case's client_ip, or on one of its flagged server IPs;
      - filtered on a time column, spanning at most the table's limit (e.g.
        5 days for per-minute tables, 30 for 5-minute, 90 for hourly);
      - a LIMIT of row_cap added if the query has none.
    Each error says why, so the model can fix its query."""
    stripped = sql.strip().rstrip(";")
    lowered = stripped.lower()

    if not re.match(r"(?is)^\s*select\b", stripped):
        return "Error: only SELECT statements are allowed.", ""

    for forbidden in ("drop", "delete", "insert", "update", "alter", "truncate", "create", "grant", "attach"):
        if re.search(rf"(?i)\b{forbidden}\b", lowered):
            return f"Error: '{forbidden}' is not allowed - only SELECT.", ""

    tables = [name for name in RUN_SQL_TABLES if name in lowered]
    if not tables:
        return f"Error: query must reference one of the allowed tables: {', '.join(RUN_SQL_TABLES)}.", ""

    allowed_ips = [case_client_ip, *case_server_ips]
    if not any(f"'{ip}'" in stripped for ip in allowed_ips):
        return (
            f"Error: query must filter on this case's client_ip ('{case_client_ip}') or on a flagged server_ip "
            f"({', '.join(repr(ip) for ip in case_server_ips) or 'none'}) - without it the query scans the "
            "whole table and can hit ClickHouse's 200-million-row read limit.", "")

    if not re.search(r"(?i)\b(time|start|finish)\b\s*(>=|>|<=|<|=|between)", lowered):
        return ("Error: query must filter on a time column (time, start or finish) - the tables are too large "
                "to scan without a time bound."), ""

    limit_days = min(RUN_SQL_TABLES[name].run_sql_max_days for name in tables)
    span = query_span_days(stripped)
    if span is None:
        return ("Error: could not read the query's time span. Bound the time column with literal datetimes "
                "('2026-09-15 00:00:00') or now() - INTERVAL n DAY."), ""
    if span > limit_days + 1e-6:
        return (f"Error: the query spans {span:.1f} days, but {', '.join(tables)} allows at most {limit_days} "
                "days per query. Narrow the window, or use a coarser table (5-minute or hourly) for long ranges."), ""

    if "limit" not in lowered:
        stripped += f" LIMIT {row_cap}"
    return None, stripped


def run_sql(sql: str, case_client_ip: str, case_server_ips: list[str] | tuple = ()) -> str:
    """Run a model-written query after check_sql, capped at MAX_SQL_ROWS rows.
    It uses a real shared-database credential, so it is stricter than a
    teaching sandbox: an unscoped query can hit the 200-million-row read limit."""
    error, checked = check_sql(sql, case_client_ip, case_server_ips)
    if error:
        return error

    try:
        df = query(checked)
    except Exception as exc:  # noqa: BLE001 - the ClickHouse error is what the model needs to fix its query
        return f"Error running query: {exc}"

    if df.empty:
        return "Query ran successfully but returned 0 rows."

    table = df.head(MAX_SQL_ROWS).to_markdown(index=False)
    if len(df) >= MAX_SQL_ROWS:
        table += f"\n\n(truncated at {MAX_SQL_ROWS} rows)"
    return table

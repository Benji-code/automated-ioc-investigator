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
from datetime import datetime, timedelta
from functools import lru_cache

import pandas as pd

from . import config

LONG_FLOW_TABLE = "public.long_flow_summary"
SUBSCRIBER_ACTIVITY_TABLE = "canopus.subscriber_activity_1m"
ASN_TABLE = "canopus.asn"
ALLOWED_TABLES = (LONG_FLOW_TABLE, SUBSCRIBER_ACTIVITY_TABLE)

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

# A "schema card": grain, key columns and what each table answers. Given to
# the model once in the system prompt.
SCHEMA_CARD = """
## Table: canopus.subscriber_activity_1m
One row per minute per (client_ip, server_ip, server_port, application) with
any traffic. Answers "what did this connection look like": names, bytes,
packets. Keeps about 15 days. Query it in chunks of at most 5 days: even with
a client_ip filter, a ~20-day query hit the 200-million-row read limit.
Columns (from DESCRIBE TABLE): time DateTime, client_ip String, server_ip
String, server_port UInt16, transport_protocol UInt8 (6=TCP, 17=UDP),
ip_protocol UInt8 (4/6), application, application_category, classifier, sni,
dns, user_agent, root_domain (all String), up_volume__bytes,
down_volume__bytes, up_volume__packets, down_volume__packets (Int64),
flow_count UInt64, internal_rtt__ms, external_rtt__ms, ttfb__ms (Float32,
nullable), server_metadata__asn, server_metadata__asn_organization,
server_metadata__geo_country, server_metadata__geo_city (String, nullable).

## Table: public.long_flow_summary
One row per TCP/UDP flow that crossed a size/duration threshold. Each flow is
deleted 65 days after it finishes (TTL). NOT a complete log: short flows are
missing. Answers "how long did this session run and how much did it move".
Columns (from DESCRIBE TABLE): start, finish DateTime64(6), duration_sec
Float64, client_ip, server_ip String, client_port, server_port UInt32,
protocol UInt16 (6=TCP, 17=UDP), up_bytes, down_bytes, up_packets,
down_packets UInt64, classifier String, type String, initiator String.
"""


DOMAIN_NOTES = """
- All timestamps are UTC.
- "up" is from the internal host to the server; "down" is server to host.
- "cloudflare-ech.com" as an SNI is a TLS Encrypted Client Hello placeholder,
  not a real destination: the real SNI was encrypted.
- There is no table of DNS answers. public.dns_tuple only records which DNS
  resolver a client asked, with no names, so names for a server IP come from
  the sni/dns/root_domain columns of subscriber_activity_1m.
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


def _query_activity_chunked(sql_template: str, start: datetime | None, end: datetime | None) -> pd.DataFrame:
    """Run a subscriber_activity_1m query once per chunk of at most
    ACTIVITY_CHUNK_DAYS and stack the results. sql_template must contain
    {time_filter}. Callers re-aggregate the stacked rows in pandas."""
    if start is None or end is None or start >= end:
        return pd.DataFrame()
    frames = []
    for chunk_start, chunk_end in time_chunks(start, end, config.ACTIVITY_CHUNK_DAYS):
        sql = sql_template.format(time_filter=_time_filter("time", chunk_start, chunk_end))
        frame = query(sql)
        if not frame.empty:
            frames.append(frame)
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)


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
    WHERE client_ip = '{_escape(client_ip)}'
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
    WHERE client_ip = '{_escape(client_ip)}' AND server_ip IN ({_ip_list(server_ips)})
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
    WHERE client_ip = '{_escape(client_ip)}' {exclude}
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
    WHERE client_ip = '{_escape(client_ip)}' AND server_ip IN ({_ip_list(server_ips)})
      AND {{time_filter}}
    GROUP BY sni, dns_name, root_name, server_ip, server_port, transport_protocol
    ORDER BY minutes DESC
    LIMIT {MAX_NAME_ROWS}
    """
    return _query_activity_chunked(template, start, end).rename(columns={**NAME_RENAMES, **TOTALS_TO_BYTES})


def fetch_ip_passive_dns(server_ip: str, start: datetime, end: datetime) -> pd.DataFrame:
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
    WHERE client_ip = '{_escape(client_ip)}' AND {_time_filter("time", start, end)}
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
    WHERE client_ip = '{_escape(client_ip)}' AND {{time_filter}}
    GROUP BY day
    """
    return _query_activity_chunked(template, start, end).rename(columns=TOTALS_TO_BYTES)


# --- run_sql: the model's general query tool -------------------------------------------

def run_sql(sql: str, case_client_ip: str) -> str:
    """Run a model-written query after checking it in code: SELECT only, an
    allowed table, filtered on this case's client_ip and on a time column, and
    capped at MAX_SQL_ROWS rows. It uses a real shared-database credential, so
    it is stricter than a teaching sandbox would be: an unscoped query on
    these tables can hit ClickHouse's 200-million-row read limit.
    """
    stripped = sql.strip().rstrip(";")
    lowered = stripped.lower()

    if not re.match(r"(?is)^\s*select\b", stripped):
        return "Error: only SELECT statements are allowed."

    for forbidden in ("drop", "delete", "insert", "update", "alter", "truncate", "create", "grant", "attach"):
        if re.search(rf"(?i)\b{forbidden}\b", lowered):
            return f"Error: '{forbidden}' is not allowed - only SELECT."

    if not any(t in lowered for t in ALLOWED_TABLES):
        return f"Error: query must reference one of the allowed tables: {', '.join(ALLOWED_TABLES)}."

    if case_client_ip not in stripped:
        return (
            f"Error: query must filter on this case's client_ip ('{case_client_ip}') - "
            "a query without it can scan the whole table and get rejected by ClickHouse's "
            "200-million-row read limit. Add e.g. \"client_ip = '" + case_client_ip + "'\" to the WHERE clause."
        )

    if not re.search(r"(?i)\b(time|start)\b\s*[<>=]", lowered):
        return (
            "Error: query must filter on a time column (time >= ... or start >= ...) - "
            "the tables are too large to scan without a time bound."
        )

    if "limit" not in lowered:
        stripped += f" LIMIT {MAX_SQL_ROWS}"

    try:
        df = query(stripped)
    except Exception as exc:  # noqa: BLE001 - the ClickHouse error is what the model needs to fix its query
        return f"Error running query: {exc}"

    if df.empty:
        return "Query ran successfully but returned 0 rows."

    table = df.head(MAX_SQL_ROWS).to_markdown(index=False)
    if len(df) >= MAX_SQL_ROWS:
        table += f"\n\n(truncated at {MAX_SQL_ROWS} rows)"
    return table

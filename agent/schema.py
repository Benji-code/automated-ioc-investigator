"""The SuperNetFlow tables this agent uses, as verified against the deployed
ClickHouse (task 3, step 0: DESCRIBE TABLE, table TTLs, bounded probes for
the earliest data, column fill rates on a one-hour sample, IP formats).

One structured entry per table. Two views are generated from it:
  SCHEMA_CARD  compact text for the model's system prompt (run_sql and
               reading the evidence)
  markdown()   the full description, written to docs/schema.md

Where the deployment differs from the public SuperNetFlow docs, the entry
says so under "differs_from_docs".
"""
from __future__ import annotations

from dataclasses import dataclass, field

IP_FORMAT = "plain IPv4 text, e.g. '203.0.113.5' (no IPv4-mapped IPv6 seen in any table)"


@dataclass(frozen=True)
class Table:
    name: str
    grain: str
    retention: str
    time_column: str
    key_columns: dict[str, str]
    good_for: str
    not_for: str
    run_sql_max_days: int | None = None  # None: not open to run_sql
    differs_from_docs: list[str] = field(default_factory=list)


TABLES: list[Table] = [
    Table(
        name="canopus.subscriber_activity_1m",
        grain="one row per minute per (client_ip, server_ip, server_port, application) with traffic",
        retention="15 days (TTL time + 15 days)",
        time_column="time",
        key_columns={
            "time": "minute (DateTime, UTC)",
            "client_ip / server_ip / server_port": "the campus host, the remote IP and port",
            "transport_protocol": "6 = TCP, 17 = UDP",
            "application / application_category": "SuperNetFlow's app label ('_unknown' if none)",
            "sni / dns / root_domain": "names for the server IP; dns is filled on only ~4% of rows and is "
                                       "sometimes the CLIENT's own name",
            "user_agent": "HTTP user agent, filled on ~0.5% of rows",
            "up_volume__bytes / down_volume__bytes / up_volume__packets / down_volume__packets": "volume that minute (up = host to server)",
            "flow_count": "flows active that minute (1 across a run of minutes = one held-open connection)",
            "server_metadata__asn / server_metadata__asn_organization / server_metadata__geo_country": "ASN and country of the server IP",
        },
        good_for="per-minute contact pattern (beacons), names used, apps, volume; campus-wide lookups by "
                 "server_ip in 1-day chunks. Sorted by subscriber_id: add subscriber_id = '<from the case file>' "
                 "to per-host queries or every row in the window is read",
        not_for="anything older than 15 days; queries over more than 5 days (200M-row read limit)",
        run_sql_max_days=5,
        differs_from_docs=["network_metadata__*, subscriber_metadata__* and labels__apn are all empty on "
                           "this network (a mobile-network feature set).",
                           "Rows labelled 'Web Browsing' have an empty server_ip: plain browsing cannot be tied "
                           "to a server IP, so per-IP queries only see other apps and '_unknown' traffic.",
                           "Sorted by subscriber_id, not client_ip; each IP maps to one subscriber_id."],
    ),
    Table(
        name="canopus_dbt.app_subscriber_server_enriched_5m",
        grain="one row per 5 minutes per (client_ip, server_ip, application); no port",
        retention="no TTL; data back to about June 2025",
        time_column="time",
        key_columns={
            "time": "5-minute bucket start",
            "client_ip / server_ip": "host and remote IP",
            "application / application_category": "app label",
            "active_minutes": "minutes with traffic in the bucket (0-5)",
            "metrics_sum__up_volume__bytes / metrics_sum__down_volume__bytes": "volume in the bucket",
        },
        good_for="contact history between a host and a server beyond the 15-day per-minute window. Sorted by "
                 "subscriber_id: add subscriber_id = '<from the case file>' or a month reads ~500M rows and fails",
        not_for="unlabelled traffic: rows with application_category '_unknown' are dropped, so contact with "
                "an unrecognised (possibly malicious) server is NOT here; ports; minute timing",
        run_sql_max_days=30,
        differs_from_docs=["Drops every '_unknown'-category row (checked against subscriber_activity_1m for the "
                           "same host and days).",
                           "No session_id_count column.",
                           "Peak-rate and most RTT percentile columns are empty on this network."],
    ),
    Table(
        name="canopus_dbt.subscriber_ip_load_enriched_1h",
        grain="one row per hour per client_ip",
        retention="no TTL; data back to June 2025",
        time_column="time",
        key_columns={
            "time": "hour",
            "client_ip": "the campus host",
            "active_minutes": "minutes with any traffic in the hour",
            "metrics_sum__up_volume__bytes / metrics_sum__down_volume__bytes": "the host's total volume in the hour",
        },
        good_for="host baseline: always-on or not, normal volume, whether the match time stands out",
        not_for="who the host talked to (no server column)",
        run_sql_max_days=90,
        differs_from_docs=["RTT and peak-rate percentile columns are empty on this network."],
    ),
    Table(
        name="canopus_dbt.app_server_enriched_1h",
        grain="one row per hour per (server_ip, application), campus-wide",
        retention="no TTL; data back to June 2025",
        time_column="time",
        key_columns={
            "time": "hour",
            "server_ip": "remote IP",
            "application / application_category": "app label for traffic to that IP",
            "client_ip_count": "distinct campus hosts that hour",
        },
        good_for="what app SuperNetFlow ties to a server IP across campus, and how many hosts use it",
        not_for="per-host detail; unlabelled traffic ('_unknown' is not in this table)",
        run_sql_max_days=90,
    ),
    Table(
        name="public.long_flow_summary",
        grain="one row per individual flow over 1 MB",
        retention="65 days after the flow FINISHES (TTL finish + 65 days)",
        time_column="start",
        key_columns={
            "start / finish / duration_sec": "flow timing",
            "client_ip / server_ip / client_port / server_port / protocol": "the connection (6 = TCP, 17 = UDP)",
            "up_bytes / down_bytes / up_packets / down_packets": "flow totals",
            "attributes": "JSON; attributes.sni is filled on ~95% of rows, attributes.dns on ~7%",
        },
        good_for="large transfers, upload-heavy sessions and long held-open sessions over 1 MB; names "
                 "from attributes.sni when the per-minute data has expired",
        not_for="beacons or any small or short connection: flows under 1 MB are not stored, so a missing "
                "row is not evidence of no traffic",
        run_sql_max_days=90,
        differs_from_docs=["TTL is on finish, so a long flow can keep a start date older than 65 days."],
    ),
    Table(
        name="public.ux_sessions",
        grain="one row per completed application session (e.g. a YouTube video, a game match)",
        retention="400 days after finish (TTL)",
        time_column="start",
        key_columns={
            "start / finish / duration_sec": "session timing",
            "client_ip": "the campus host",
            "type / provider": "e.g. Video / YouTube, Gameplay / Minecraft, Software Update / Google",
            "servers.server_ip": "array of server IPs used in the session (use has(servers.server_ip, '...'))",
        },
        good_for="whether the flagged IP was part of a recognised app session, which explains the traffic",
        not_for="unrecognised apps (only known providers make sessions)",
        run_sql_max_days=90,
    ),
    Table(
        name="public.dns_tuple",
        grain="DNS performance per (client_ip, DNS server) per hour",
        retention="400 days (TTL)",
        time_column="time",
        key_columns={
            "client_ip": "the host that asked",
            "server_ip": "the DNS server it asked",
            "n_complete_sessions / n_unanswered_sessions": "answered and unanswered DNS exchanges",
            "mean_service_nanos": "mean response time",
        },
        good_for="which external DNS resolvers a host uses directly, how rare they are on campus, and the "
                 "unanswered rate",
        not_for="domain names (there are none); NXDOMAIN/SERVFAIL rates (rcode is always -1 here); hosts "
                "that only use the campus resolvers (that traffic is not captured)",
        run_sql_max_days=30,
        differs_from_docs=["No n_nxdomain, n_servfail or n_refused columns; a single rcode column that is "
                           "always -1, so response codes are not available.",
                           "Only DNS crossing the border is captured: most hosts are absent, and the campus "
                           "resolver itself appears as a client."],
    ),
    Table(
        name="public.dns_server",
        grain="DNS counters per DNS server per hour",
        retention="400 days (TTL)",
        time_column="time",
        key_columns={"server_ip": "DNS server", "n_unique_client_tags": "distinct clients"},
        good_for="telling commonly used resolvers from rare ones",
        not_for="query names (the question column is empty here) or response codes (rcode is always -1)",
        run_sql_max_days=30,
        differs_from_docs=["question is empty and rcode is always -1."],
    ),
    Table(
        name="canopus.asn",
        grain="one row per announced CIDR",
        retention="lookup table",
        time_column="",
        key_columns={"asn_cidr / asn / asn_organization": "lower-case column names"},
        good_for="ASN and organisation for an IP when the flow rows have none",
        not_for="-",
        differs_from_docs=["Column names are lower case (docs show ASN_CIDR etc.)."],
    ),
    Table(
        name="canopus.geo",
        grain="one row per geo CIDR",
        retention="lookup table",
        time_column="",
        key_columns={"geo_cidr / geo_country / geo_city": "lower-case column names"},
        good_for="country and city for an IP when the flow rows have none",
        not_for="-",
        differs_from_docs=["Column names are lower case (docs show GEO_* )."],
    ),
]

TABLE_BY_NAME = {t.name: t for t in TABLES}
RUN_SQL_TABLES = {t.name: t for t in TABLES if t.run_sql_max_days}


def source_note(name: str) -> str:
    """One line for the case file: which table, and what it can't show."""
    t = TABLE_BY_NAME[name]
    return f"(from {t.name.split('.')[-1]}: {t.grain}; kept {t.retention}; not for: {t.not_for})"


def _card_entry(t: Table) -> str:
    """Compact: the local model's context is small. Column names only, plus
    what the table cannot show; docs/schema.md has the full version."""
    cols = ", ".join(t.key_columns)
    return (f"- {t.name} [{t.grain}; kept {t.retention.split(' (')[0]}; max {t.run_sql_max_days} days/query]: "
            f"{cols}. Not for: {t.not_for}.")


SCHEMA_CARD = ("Tables (6=TCP, 17=UDP; up = host to server; IPs are plain IPv4 text; times UTC). "
               "subscriber_activity_1m and the 5-minute table are sorted by subscriber_id: add "
               "subscriber_id = '<from the case file>' to per-host queries on them.\n"
               + "\n".join(_card_entry(t) for t in RUN_SQL_TABLES.values()) + "\n")


def markdown() -> str:
    """Full human-readable schema notes (docs/schema.md)."""
    out = ["# SuperNetFlow tables used by the IOC triage agent", "",
           "Generated from `agent/schema.py`. Verified against the deployed database: `DESCRIBE TABLE`, table "
           "TTLs, bounded probes for the earliest data, and column fill rates on a one-hour sample. The public "
           "schema is at https://supernetflow.com/database-schema.", "",
           f"**IP format:** {IP_FORMAT}. **Times:** UTC.", ""]
    for t in TABLES:
        out += [f"## `{t.name}`", "", f"- **Grain:** {t.grain}", f"- **Kept:** {t.retention}",
                f"- **Good for:** {t.good_for}", f"- **Not for:** {t.not_for}"]
        if t.run_sql_max_days:
            out.append(f"- **run_sql:** allowed, at most {t.run_sql_max_days} days per query")
        out += ["", "| Column | Meaning |", "|---|---|"]
        out += [f"| `{k}` | {v} |" for k, v in t.key_columns.items()]
        if t.differs_from_docs:
            out += ["", "**Differs from the public docs:**", ""] + [f"- {d}" for d in t.differs_from_docs]
        out.append("")
    return "\n".join(out)

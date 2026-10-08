"""Settings for the IOC investigation agent.

Everything secret or site-specific (ClickHouse host, user, password, API
keys) comes from a `.env` file at the project root, never from code. Copy
`.env.example` to `.env` and fill it in. Variables already set in the shell
take precedence over `.env`.

Two LLM providers are supported, switched with LLM_PROVIDER:
  - "ollama" (default): a local model served by `ollama serve`. No key, no quota.
    OLLAMA_API_KEY is only needed for Ollama Cloud or a remote server behind auth.
  - "openrouter": cloud fallback. Needs OPENROUTER_API_KEY. The free tier is
    capped at 50 requests/day and some reasoning models truncate replies
    (see llm_client.py).
llm_client.py uses Ollama's native API (so it can set the context size) and
OpenRouter's OpenAI-style API, and converts between the two.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = PROJECT_ROOT / ".env"


def _load_env_file(path: Path) -> None:
    """Minimal .env reader: KEY=value lines, optional `export ` prefix,
    optional quotes, # comments. Does not override variables already set."""
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if value[:1] in ('"', "'"):
            value = value.strip('"').strip("'")
        else:
            value = value.split(" #", 1)[0].strip()  # trailing comment on an unquoted value
        if key and key not in os.environ:
            os.environ[key] = value


_load_env_file(ENV_PATH)


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name, "").strip()
    return int(value) if value else default


# --- LLM -------------------------------------------------------------------
PROVIDER = os.getenv("LLM_PROVIDER", "ollama").strip().lower()

OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "http://localhost:11434/api/chat")
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY", "").strip()  # optional
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")  # any locally pulled tool-calling model
# Thinking mode for models that have one (e.g. the Qwen3 family): "0" off,
# "1" on, unset = don't send the option (the model's default; models without
# thinking reject it). Off is faster and keeps hidden reasoning from using up
# the reply budget; on may reason better but is much slower.
_THINK = os.getenv("OLLAMA_THINK", "").strip().lower()
OLLAMA_THINK = None if _THINK == "" else _THINK in ("1", "true", "yes", "on")
# Context window in tokens. The system prompt plus case file is 8-11k tokens,
# and the model's own queries and charts add more; Ollama silently drops the
# START of a prompt that overflows. Lower it for a model with a smaller window.
OLLAMA_NUM_CTX = _int_env("OLLAMA_NUM_CTX", 32768)

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
# Free models rotate; check https://openrouter.ai/models?max_price=0 if every
# case starts failing with the same upstream error.
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "nvidia/nemotron-3-super-120b-a12b:free")

TEMPERATURE = 0.0  # identical evidence should give an identical answer
SEED = 0           # Ollama: fixed sampling seed, for the same reason
# Tool rounds per case (follow-up queries and charts) before a final text
# answer is forced. A round can hold several calls.
MAX_TOOL_ROUNDS = _int_env("MAX_TOOL_ROUNDS", 12)
# Self-check passes: the model gets its report back with a proofreading
# checklist and any problems code found, and returns a corrected report. It
# may call tools again (e.g. to fix a chart). 0 turns it off.
MODEL_REFINE_ROUNDS = _int_env("MODEL_REFINE_ROUNDS", 1)
REFINE_TOOL_ROUNDS = 4
# Reply budget: the model writes the whole report. Thinking models spend part
# of it on hidden reasoning; llm_client grows it on retry if a reply is cut off.
MAX_TOKENS = _int_env("MAX_TOKENS", 8000)
# Seconds to wait for one model reply (a large local model writing a whole
# report can take minutes).
LLM_TIMEOUT_SEC = _int_env("LLM_TIMEOUT_SEC", 900)
# Charts the model may add to one case's report (add_chart).
MAX_CHARTS = 3

SITE_URL = "https://github.com/local/ioc-triage-agent"
SITE_NAME = "IOC Investigation Agent"

# --- ClickHouse (SuperNetFlow) ----------------------------------------------
CLICKHOUSE_ENV_VARS = ("CLICKHOUSE_HOST", "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD")
CLICKHOUSE_PORT = _int_env("CLICKHOUSE_PORT", 8123)

# --- Time windows (all UTC) ------------------------------------------------
# long_flow_summary keeps months of data, so look well before the matched
# evidence and a little after it.
FLOW_LOOKBACK_DAYS = _int_env("FLOW_LOOKBACK_DAYS", 90)
FLOW_LOOKAHEAD_DAYS = _int_env("FLOW_LOOKAHEAD_DAYS", 14)
# subscriber_activity_1m keeps about 15 days, and even a client_ip-filtered
# query over ~20 days hit ClickHouse's 200-million-row read limit, so it is
# only queried inside its retention window, in chunks of at most 5 days.
ACTIVITY_RETENTION_DAYS = _int_env("ACTIVITY_RETENTION_DAYS", 16)
ACTIVITY_CHUNK_DAYS = min(_int_env("ACTIVITY_CHUNK_DAYS", 5), 5)
PEER_LOOKBACK_DAYS = _int_env("PEER_LOOKBACK_DAYS", 60)
# Names the host used on the flagged IP are also looked for this many
# minutes either side of each feed match.
NAMES_WINDOW_MINUTES = _int_env("NAMES_WINDOW_MINUTES", 10)
# Campus-wide lookups (passive DNS on the flagged IP, domain popularity) use
# the most recent days of subscriber_activity_1m, one chunk.
CAMPUS_LOOKUP_DAYS = min(_int_env("CAMPUS_LOOKUP_DAYS", 5), 5)

# --- Contact pattern (beacon) thresholds, per-minute data (task 3) ----------
# A periodic check-in needs enough repeats to judge an interval at all.
BEACON_MIN_BURSTS = 6
# Gap regularity (0-100, median/MAD of the gaps between burst starts) at or
# above this counts as a regular interval. 70 means the typical deviation is
# under 30% of the typical gap.
BEACON_MIN_REGULARITY = 70.0
# Bytes-per-burst consistency (0-100, 100 = identical sizes). Check-ins send
# near-identical payloads; people do not.
BEACON_MIN_VOLUME_CONSISTENCY = 60.0
# Check-ins are small: median bytes per burst (up + down) at or below this.
BEACON_MAX_BURST_BYTES = 100_000
# Beacons run around the clock. A pattern with no activity between 00:00 and
# 06:00 local time looks like a person, not a timer.
BEACON_MIN_NIGHT_SHARE = 0.05
# Held open: the host is in contact for most of the window, in long unbroken
# runs, over about one flow.
HELD_OPEN_MIN_DUTY_CYCLE = 0.5
HELD_OPEN_MIN_RUN_MINUTES = 60
HELD_OPEN_MAX_FLOWS_PER_MINUTE = 1.5
# A keepalive is small per minute; more than this per minute is a transfer.
HELD_OPEN_MAX_BYTES_PER_MINUTE = 200_000
# Bulk transfer: a handful of bursts, each big.
BULK_MAX_BURSTS = 5
BULK_MIN_BURST_BYTES = 10_000_000
# People are mostly awake: under this night share counts as waking hours.
HUMAN_MAX_NIGHT_SHARE = 0.15
# A destination used by at least this many OTHER campus hosts is a popular
# service, which explains a periodic pattern (many devices check in to it).
POPULAR_DESTINATION_MIN_HOSTS = 5

# --- Calibration thresholds ------------------------------------------------
# A flow only supports an "exfiltration" claim if it is this upload-heavy.
EXFIL_MIN_RATIO = 3.0            # up bytes / down bytes
EXFIL_MIN_UP_BYTES = 10_000_000  # 10 MB up
# Many distinct campus hosts, or many unrelated domains, on one IP mean it is
# shared infrastructure.
SHARED_PEER_HOSTS = 5
SHARED_PASSIVE_DNS_DOMAINS = 5
# A registered domain that at most this many OTHER campus hosts contacted is
# "rare" (only this host used it).
RARE_DOMAIN_MAX_OTHER_HOSTS = 0

# Organisation whose network is monitored (e.g. set ORG_NAME in .env). Used
# only in prompts, case files and reports; unset gives generic wording.
ORG_NAME = os.getenv("ORG_NAME", "").strip()
HOST_LABEL = f"{ORG_NAME} host" if ORG_NAME else "internal host"
NETWORK_LABEL = f"the {ORG_NAME} network" if ORG_NAME else "the monitored network"

# Local time zone of the monitored site (IANA name, e.g. Australia/Sydney).
# Data stays in UTC; case files add local times so the model can judge time
# of day without converting.
LOCAL_TIMEZONE = os.getenv("LOCAL_TIMEZONE", "UTC").strip() or "UTC"
# Free-text background on the site (kinds of hosts, usage patterns), given to
# the model as context. Optional.
SITE_CONTEXT = os.getenv("SITE_CONTEXT", "").strip()

# Name of the feed field holding the internal host's IP. Records are
# normalised to "affected_asset" on load, so a feed can use its own name.
FEED_ASSET_FIELD = os.getenv("FEED_ASSET_FIELD", "affected_asset").strip()

# Reverse DNS for the host's name in reports (a PTR lookup through the local
# resolver). Set REVERSE_DNS=0 to turn it off.
REVERSE_DNS = os.getenv("REVERSE_DNS", "1").strip() not in ("0", "false", "no")
REVERSE_DNS_TIMEOUT_SEC = 3.0

# Optional, gitignored: real ThreatFox fields pasted in by hand per IOC.
IOC_METADATA_PATH = PROJECT_ROOT / "data" / "ioc_metadata.json"

# --- Host classification (host_classification/) -------------------------------
# The campus address range, for selecting campus hosts to profile (e.g.
# 192.0.2.0/24). Site-specific, so it lives in .env.
CAMPUS_CIDR = os.getenv("CAMPUS_CIDR", "").strip()
# Everything derived from real hosts stays in data/ (gitignored): seed labels,
# features, the trained model and the per-type profiles.
HOST_CLASSIFICATION_DIR = PROJECT_ROOT / "data" / "host_classification"
HOST_SEED_LABELS_PATH = HOST_CLASSIFICATION_DIR / "seed_labels.csv"
HOST_FEATURES_PATH = HOST_CLASSIFICATION_DIR / "features.csv"
HOST_LABELLED_PATH = HOST_CLASSIFICATION_DIR / "labelled.csv"
HOST_MODEL_PATH = HOST_CLASSIFICATION_DIR / "model.joblib"
HOST_PROFILES_PATH = HOST_CLASSIFICATION_DIR / "host_type_profiles.json"
# Days of the case host's own traffic, up to the match, used to classify it.
HOST_TYPE_WINDOW_DAYS = _int_env("HOST_TYPE_WINDOW_DAYS", 7)


def clickhouse_settings() -> dict:
    """Connection settings for ClickHouse. Exits with a clear message if the
    .env file or any required variable is missing."""
    missing = [name for name in CLICKHOUSE_ENV_VARS if not os.getenv(name)]
    if missing and not ENV_PATH.exists():
        raise SystemExit(
            f"No .env file found at {ENV_PATH}.\n"
            "Copy .env.example to .env and fill in the ClickHouse settings."
        )
    if missing:
        raise SystemExit(
            f"Missing in {ENV_PATH.name}: {', '.join(missing)}.\n"
            "See .env.example for the full list of settings."
        )
    return {
        "host": os.environ["CLICKHOUSE_HOST"],
        "port": CLICKHOUSE_PORT,
        "username": os.environ["CLICKHOUSE_USER"],
        "password": os.environ["CLICKHOUSE_PASSWORD"],
    }


def api_url() -> str:
    if PROVIDER == "ollama":
        return OLLAMA_API_URL
    return OPENROUTER_API_URL


def model() -> str:
    if PROVIDER == "ollama":
        return OLLAMA_MODEL
    return OPENROUTER_MODEL


def api_key() -> str | None:
    """OpenRouter needs a key. Ollama's is optional (None for a local server)."""
    if PROVIDER == "ollama":
        return OLLAMA_API_KEY or None
    key = os.getenv("OPENROUTER_API_KEY")
    if not key:
        raise SystemExit(
            "OPENROUTER_API_KEY is not set. Add it to .env, or set LLM_PROVIDER=ollama "
            "(the default) to use a local model."
        )
    return key


def local_zone() -> ZoneInfo:
    try:
        return ZoneInfo(LOCAL_TIMEZONE)
    except ZoneInfoNotFoundError:
        raise SystemExit(f"LOCAL_TIMEZONE={LOCAL_TIMEZONE!r} is not a known time zone (e.g. Australia/Sydney).")


def to_local(value) -> str:
    """UTC timestamp (string or datetime) as local time with weekday, e.g.
    "2026-09-15 20:00 Tue AEST". Empty if no local zone is set or the value
    can't be parsed."""
    if LOCAL_TIMEZONE == "UTC" or not value:
        return ""
    try:
        moment = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(local_zone()).strftime("%Y-%m-%d %H:%M %a %Z")

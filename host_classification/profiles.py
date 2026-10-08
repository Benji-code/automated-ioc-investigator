"""Typical behaviour per host type, and how one host compares with it.

build() turns the labelled campus population into per-type quantiles of a
few readable features: aggregates only, no IPs. compare() places one host
on its type's distribution: within the typical range (5th-95th percentile),
or unusually high or low. Without measured profiles it falls back to the
rough priors in agent/knowledge.py, and says so.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from agent import config

# The features compared, with how to read and format them. Chosen to be
# readable to an analyst and to separate host types.
KEY_FEATURES: dict[str, tuple[str, str]] = {
    "load_daily_bytes": ("traffic per day (all destinations)", "bytes"),
    "load_up_byte_ratio": ("share of all traffic sent (upload)", "share"),
    "load_night_day_ratio": ("night-time vs daytime hourly volume", "ratio"),
    "load_hourly_bytes_cv": ("hour-to-hour variability of volume", "ratio"),
    "client_flows": ("large flows (over 1 MB)", "count"),
    "client_unique_peers": ("distinct remote addresses in large flows", "count"),
    "client_unique_ports": ("distinct remote ports in large flows", "count"),
    "client_up_byte_ratio": ("share of large-flow bytes sent", "share"),
    "client_udp_flows_ratio": ("share of large flows over UDP", "share"),
    "client_web_https_flows_ratio": ("share of large flows on HTTPS", "share"),
    "client_remote_flows_ratio": ("share of large flows on remote-access ports", "share"),
    "client_database_flows_ratio": ("share of large flows on database ports", "share"),
    "client_p95_duration_sec": ("long flows (95th percentile duration)", "seconds"),
    "app_unique_apps": ("distinct apps", "count"),
    "app_unique_categories": ("distinct app categories", "count"),
}
QUANTILES = (0.05, 0.25, 0.5, 0.75, 0.95)
MIN_HOSTS = 5   # fewer hosts of a type than this gives no profile for it


def build(labelled: pd.DataFrame, min_score: float = 0.7) -> dict:
    """Quantiles of KEY_FEATURES per label, from confidently labelled hosts."""
    confident = labelled[(labelled["label_source"] == "seed") | (labelled["label_score"] >= min_score)]
    types = {}
    for label, group in confident.groupby("label"):
        if len(group) < MIN_HOSTS:
            continue
        stats = {}
        for column in KEY_FEATURES:
            if column not in group:
                continue
            values = pd.to_numeric(group[column], errors="coerce").dropna()
            if values.empty:
                continue
            stats[column] = {f"p{int(q * 100)}": float(values.quantile(q)) for q in QUANTILES}
        types[str(label)] = {"hosts": int(len(group)), "features": stats}
    return {"built_at": datetime.now(timezone.utc).isoformat(), "period": labelled.attrs.get("period", ""),
            "min_score": min_score, "types": types}


def save(profiles: dict, path: Path | None = None) -> Path:
    path = Path(path or config.HOST_PROFILES_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(profiles, indent=2), encoding="utf-8")
    return path


def load(path: Path | None = None) -> dict | None:
    path = Path(path or config.HOST_PROFILES_PATH)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _percentile(value: float, quantiles: dict) -> float:
    """Where a value sits on the type's distribution, from its quantiles
    (linear between them, clamped to 0-100)."""
    points = sorted((float(k[1:]), v) for k, v in quantiles.items())
    xs, ps = [v for _, v in points], [p for p, _ in points]
    if value <= xs[0]:
        return 0.0 if value < xs[0] else ps[0]
    if value >= xs[-1]:
        return 100.0 if value > xs[-1] else ps[-1]
    return float(np.interp(value, xs, ps))


def compare(features: dict, label: str, profiles: dict | None, priors: dict | None) -> dict:
    """Each key feature of one host against its type. Measured profiles if
    there are enough hosts of the type; else the knowledge base's rough
    priors, which give a range but no percentiles."""
    measured = ((profiles or {}).get("types") or {}).get(label)
    rows = []
    if measured:
        source = (f"measured: {measured['hosts']} campus hosts labelled {label}"
                  + (f", {profiles['period']}" if profiles.get("period") else ""))
        for column, quantiles in measured["features"].items():
            if column not in features:
                continue
            value = float(features[column] or 0)
            low, high = quantiles["p5"], quantiles["p95"]
            rows.append(_row(column, value, low, high, quantiles["p50"], _percentile(value, quantiles)))
    elif priors:
        source = "rough priors from the knowledge base (no measured profile for this type yet)"
        for column, (low, high) in priors.items():
            if column in features:
                rows.append(_row(column, float(features[column] or 0), low, high, None, None))
    else:
        source = "none: no measured profile or prior for this type"
    return {"source": source, "measured": bool(measured), "rows": rows,
            "unusual": [r for r in rows if r["position"] != "typical"]}


def _row(column: str, value: float, low: float, high: float, median: float | None, percentile: float | None) -> dict:
    description, unit = KEY_FEATURES.get(column, (column, "count"))
    position = "typical"
    if value > high:
        position = "unusually high"
    elif value < low:
        position = "unusually low"
    return {"feature": column, "description": description, "unit": unit, "value": value, "typical_low": low,
            "typical_high": high, "median": median,
            "percentile": None if percentile is None else round(percentile), "position": position}

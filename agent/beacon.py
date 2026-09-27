"""Contact pattern between a host and the flagged IP, from per-minute data
(task 3). This replaces the old beacon check on long_flow_summary, which
only stores flows over 1 MB: real check-ins are small and never appear there,
while big streaming or sync flows can look regular.

Input: one row per active time bin (1 minute from subscriber_activity_1m, or
5 minutes from app_subscriber_server_enriched_5m for older history).
Consecutive active bins are merged into bursts; the features below describe
the bursts; classify() names the pattern. Thresholds are in config.py.

Features:
  active_minutes     minutes with contact
  duty_cycle         active minutes / minutes from first to last contact
  window_share       active minutes / the whole query window
  bursts             runs of consecutive active bins (count, median length, starts)
  gap_regularity     0-100 regularity of the gaps between burst starts (median/MAD)
  median_gap_min     typical interval between burst starts
  volume_consistency 0-100, how alike the bytes per burst are (100 = identical)
  bytes_per_burst    median up and down bytes per burst
  flows_per_minute   median flows active per active minute (1-minute data only)
  bytes_per_minute   median bytes per active minute
  hour_spread        distinct local hours of the day with contact (0-24)
  night_share        share of active minutes between 00:00 and 06:00 local time
"""
from __future__ import annotations

from zoneinfo import ZoneInfo

import numpy as np
import pandas as pd

from . import config
from .analysis import _regularity_score, fmt_time

PATTERNS = {
    "periodic_checkin": "Repeated small check-ins at a regular interval, day and night",
    "held_open": "One connection held open for long unbroken runs, with steady small traffic",
    "human_interactive": "Bursty, mostly in waking hours, with varying volume: like a person using an app",
    "bulk_transfer": "A few large transfers",
    "one_off": "One or two short contacts",
    "irregular": "Repeated contact with no regular interval, at all hours",
    "insufficient_data": "No per-minute contact data in the window",
}
MAX_LISTED_BURSTS = 8


def _local_hours(times: pd.Series) -> pd.Series:
    zone = ZoneInfo(config.LOCAL_TIMEZONE)
    stamps = pd.to_datetime(times)
    if stamps.dt.tz is None:
        stamps = stamps.dt.tz_localize("UTC")
    return stamps.dt.tz_convert(zone).dt.hour


def _bursts(frame: pd.DataFrame, bin_minutes: int) -> list[dict]:
    """Merge consecutive active bins into bursts."""
    bursts: list[dict] = []
    previous = None
    for row in frame.itertuples(index=False):
        t = pd.Timestamp(row.time)
        joined = previous is not None and (t - previous).total_seconds() <= bin_minutes * 60
        if not joined:
            bursts.append({"start": t, "end": t, "bins": 0, "minutes": 0, "up": 0, "down": 0})
        b = bursts[-1]
        b["end"] = t
        b["bins"] += 1
        b["minutes"] += int(getattr(row, "active", bin_minutes if bin_minutes > 1 else 1) or 0)
        b["up"] += int(row.up_bytes or 0)
        b["down"] += int(row.down_bytes or 0)
        previous = t
    return bursts


def features(frame: pd.DataFrame, bin_minutes: int, window_minutes: float) -> dict:
    """Contact features from active bins (see module docstring)."""
    frame = frame.sort_values("time")
    frame = frame[(frame["up_bytes"] + frame["down_bytes"]) > 0] if "active" not in frame else frame[frame["active"] > 0]
    if frame.empty:
        return {"active_minutes": 0, "bursts": 0}
    bursts = _bursts(frame, bin_minutes)
    active_minutes = int(frame["active"].sum()) if "active" in frame else int(len(frame))
    first, last = pd.Timestamp(frame["time"].iloc[0]), pd.Timestamp(frame["time"].iloc[-1])
    span_minutes = (last - first).total_seconds() / 60 + bin_minutes
    burst_bytes = np.array([b["up"] + b["down"] for b in bursts], dtype=float)
    starts = np.array([b["start"].timestamp() for b in bursts])
    gaps = np.diff(starts) / 60
    consistency = 0.0
    if len(burst_bytes) > 1 and burst_bytes.mean() > 0:
        consistency = round(100.0 * (1 - min(float(burst_bytes.std() / burst_bytes.mean()), 1.0)), 1)
    hours = _local_hours(frame["time"])
    minute_weights = frame["active"] if "active" in frame else pd.Series(1, index=frame.index)
    night = float(minute_weights[hours < 6].sum()) / max(float(minute_weights.sum()), 1)
    per_minute = (frame["up_bytes"] + frame["down_bytes"]) / (minute_weights.clip(lower=1) if "active" in frame else 1)
    return {
        "active_minutes": active_minutes,
        "duty_cycle": round(min(active_minutes / span_minutes, 1.0), 3),
        "window_share": round(min(active_minutes / max(window_minutes, 1), 1.0), 4),
        "bursts": len(bursts),
        "median_burst_min": float(np.median([b["bins"] * bin_minutes for b in bursts])),
        "longest_run_min": int(max(b["bins"] for b in bursts) * bin_minutes),
        "burst_starts": [fmt_time(b["start"]) for b in bursts[:MAX_LISTED_BURSTS]],
        "gap_regularity": _regularity_score(gaps) if len(gaps) >= 2 else None,
        "median_gap_min": round(float(np.median(gaps)), 1) if len(gaps) else None,
        "volume_consistency": consistency if len(bursts) > 1 else None,
        "median_burst_up_bytes": int(np.median([b["up"] for b in bursts])),
        "median_burst_down_bytes": int(np.median([b["down"] for b in bursts])),
        "median_burst_bytes": int(np.median(burst_bytes)),
        "flows_per_minute": float(frame["flows"].median()) if "flows" in frame else None,
        "bytes_per_minute": int(per_minute.median()),
        "hour_spread": int(hours.nunique()),
        "night_share": round(night, 3),
        "first": fmt_time(first),
        "last": fmt_time(last),
    }


def classify(f: dict) -> str:
    """Name the pattern. The first rule that matches wins."""
    if not f.get("active_minutes"):
        return "insufficient_data"
    flows_ok = f.get("flows_per_minute") is None or f["flows_per_minute"] <= config.HELD_OPEN_MAX_FLOWS_PER_MINUTE
    if (f["median_burst_min"] >= config.HELD_OPEN_MIN_RUN_MINUTES and f["duty_cycle"] >= config.HELD_OPEN_MIN_DUTY_CYCLE
            and flows_ok and f["bytes_per_minute"] <= config.HELD_OPEN_MAX_BYTES_PER_MINUTE):
        return "held_open"
    if f["bursts"] <= 2:
        return "one_off"
    if f["bursts"] <= config.BULK_MAX_BURSTS and f["median_burst_bytes"] >= config.BULK_MIN_BURST_BYTES:
        return "bulk_transfer"
    if (f["bursts"] >= config.BEACON_MIN_BURSTS
            and (f["gap_regularity"] or 0) >= config.BEACON_MIN_REGULARITY
            and (f["volume_consistency"] or 0) >= config.BEACON_MIN_VOLUME_CONSISTENCY
            and f["median_burst_bytes"] <= config.BEACON_MAX_BURST_BYTES
            and f["night_share"] >= config.BEACON_MIN_NIGHT_SHARE):
        return "periodic_checkin"
    if f["night_share"] <= config.HUMAN_MAX_NIGHT_SHARE:
        return "human_interactive"
    return "irregular"


def analyse(frame: pd.DataFrame, bin_minutes: int, window_minutes: float, source: str) -> dict:
    """Features, pattern and a one-line description for one contact series."""
    f = features(frame, bin_minutes, window_minutes) if not frame.empty else {"active_minutes": 0, "bursts": 0}
    pattern = classify(f)
    return {"pattern": pattern, "description": PATTERNS[pattern], "features": f,
            "source": source, "resolution_min": bin_minutes}

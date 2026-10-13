"""Host type classification.

Two classifiers over the features in features.py:

  - a random forest trained on weakly supervised labels: a small set of
    seed hosts, each with a certainty that weights it in training (refined
    from the original classification.py). The seeds hold real campus IPs, so they live
    in a gitignored CSV (config.HOST_SEED_LABELS_PATH); seed_labels.example.csv
    shows the format. The trained model is saved with the exact feature
    columns it was fitted on, so a single case host is scored the same way.
  - transparent rules (rule_classify), from the reasons written next to the
    seeds. They give a label with no trained model, and a readable reason
    beside the forest's label.

Labels (the seeds' fine labels): end_host, NAT_gateway, website_server,
web_proxy, remote_computing_server, non_typical_tcp_server. Profiles of what
each normally looks like are in agent/knowledge.py (HOST_TYPE_PROFILES).

With a few dozen seeds the forest's labels are pseudo-labels: add more
seeds and retrain. scikit-learn is only needed to train or apply the forest.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from agent import config

from .features import LIST_COLUMNS, PORT_GROUPS

LABELS = ("end_host", "NAT_gateway", "website_server", "web_proxy", "remote_computing_server",
          "non_typical_tcp_server")
NOT_FEATURES = {"ip", "dns_hostname", "dns_hint_label", "label", "coarse_label", "certainty", "reason",
                *LIST_COLUMNS}
# Raw counts and volumes grow with how busy a host is, not what it is; log
# scale keeps a few huge hosts from dominating the forest's splits.
RAW_SCALE_HINTS = ("bytes", "flows", "rows", "unique_peers", "unique_ports", "minutes", "hours", "duration",
                   "days", "campus_hosts")
RATIO_HINTS = ("ratio", "share", "per_", "_cv", "peak_to_mean")
WEB_PORTS = {80, 443, 8000, 8008, 8080, 8443, 8888}


# --- seeds ----------------------------------------------------------------------------------

def load_seeds(path: Path | None = None) -> pd.DataFrame:
    """ip,label[,coarse_label,certainty,reason] for the seed hosts."""
    path = Path(path or config.HOST_SEED_LABELS_PATH)
    if not path.exists():
        raise SystemExit(f"No seed labels at {path}. Copy host_classification/seed_labels.example.csv there and "
                         "fill in seed hosts (real IPs stay in data/, which is gitignored).")
    seeds = pd.read_csv(path)
    missing = {"ip", "label"} - set(seeds.columns)
    if missing:
        raise SystemExit(f"{path} is missing columns: {', '.join(sorted(missing))}")
    seeds["ip"] = seeds["ip"].astype(str)
    seeds["certainty"] = pd.to_numeric(seeds.get("certainty", 1.0), errors="coerce").fillna(1.0)
    for col in ("coarse_label", "reason"):
        if col not in seeds:
            seeds[col] = ""
    return seeds[["ip", "label", "coarse_label", "certainty", "reason"]]


# --- the forest -----------------------------------------------------------------------------

def feature_columns(frame: pd.DataFrame) -> list[str]:
    """Numeric columns that vary across hosts."""
    cols = []
    for col in frame.columns:
        if col in NOT_FEATURES:
            continue
        values = pd.to_numeric(frame[col], errors="coerce")
        if values.notna().any() and values.nunique(dropna=True) > 1:
            cols.append(col)
    if not cols:
        raise SystemExit("No usable numeric feature columns.")
    return cols


def matrix(frame: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    """The model's input: the given columns (missing ones as 0), raw counts
    and volumes on a log scale."""
    X = pd.DataFrame({col: pd.to_numeric(frame[col], errors="coerce") if col in frame else 0.0
                      for col in columns}, index=frame.index)
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    for col in columns:
        lower = col.lower()
        if any(h in lower for h in RAW_SCALE_HINTS) and not any(h in lower for h in RATIO_HINTS):
            X[col] = np.log1p(X[col].clip(lower=0))
    return X


def train(features: pd.DataFrame, seeds: pd.DataFrame, max_depth: int = 4, min_samples_leaf: int = 1) -> dict:
    """Fit the forest on the seed hosts found in `features`. Returns a bundle
    that predict() and save() understand."""
    from sklearn.ensemble import RandomForestClassifier

    labelled = features.merge(seeds, on="ip", how="inner")
    if labelled["label"].nunique() < 2:
        raise SystemExit(f"Need seeds of at least two labels in the feature matrix; found "
                         f"{len(labelled)} seed host(s). Were the seeds active in this period?")
    columns = feature_columns(features)
    model = RandomForestClassifier(n_estimators=200, max_depth=max_depth, min_samples_leaf=min_samples_leaf,
                                   class_weight="balanced", random_state=7)
    model.fit(matrix(labelled, columns), labelled["label"].astype(str),
              sample_weight=labelled["certainty"].to_numpy(dtype=float))
    importance = sorted(zip(columns, model.feature_importances_), key=lambda p: -p[1])
    return {"model": model, "columns": columns, "classes": list(model.classes_), "seeds": len(labelled),
            "seed_counts": labelled["label"].value_counts().to_dict(),
            "importance": [(c, round(float(v), 4)) for c, v in importance[:25]],
            "period": features.attrs.get("period", ""), "trained_at": datetime.now(timezone.utc).isoformat()}


def save(bundle: dict, path: Path | None = None) -> Path:
    import joblib

    path = Path(path or config.HOST_MODEL_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)
    return path


def load(path: Path | None = None) -> dict | None:
    """The saved bundle, or None if none was trained (or scikit-learn is missing)."""
    path = Path(path or config.HOST_MODEL_PATH)
    if not path.exists():
        return None
    try:
        import joblib

        return joblib.load(path)
    except ImportError:
        return None


def predict(bundle: dict, features: pd.DataFrame) -> pd.DataFrame:
    """label, score (the forest's vote share) and the full probabilities, per row."""
    proba = bundle["model"].predict_proba(matrix(features, bundle["columns"]))
    classes = bundle["classes"]
    best = proba.argmax(axis=1)
    return pd.DataFrame({
        "ip": features["ip"].values,
        "model_label": [classes[i] for i in best],
        "model_score": proba.max(axis=1).round(3),
        "model_probabilities": [{c: round(float(p), 3) for c, p in zip(classes, row) if p >= 0.05}
                                for row in proba],
    })


# --- rules ----------------------------------------------------------------------------------

def _value(row, name: str) -> float:
    try:
        value = float(row.get(name, 0) or 0)
    except (TypeError, ValueError):
        return 0.0
    return 0.0 if np.isnan(value) else value


def _top_port(row, role: str) -> int | None:
    ports = row.get(f"{role}_top_ports") or []
    return int(ports[0]) if len(ports) else None


def rule_classify(row) -> tuple[str, float, str]:
    """(label, confidence 0-1, reason) from a few readable thresholds.

    SuperNetFlow records every flow from the campus host's side, so a server
    shows up through what it does (sends more than it receives, to many
    peers), not a direction field. Thresholds were set from the seed hosts'
    traffic over 14 days to early October 2026 and are judgement calls:
    re-check them with `python -m host_classification check-rules`."""
    v = lambda name: _value(row, name)  # noqa: E731
    flows, peers = v("client_flows"), v("client_unique_peers")
    if not flows and not v("load_rows"):
        return "unknown", 0.0, "no traffic in the window"
    if v("client_database_flows_ratio") >= 0.3:
        return ("non_typical_tcp_server", 0.7,
                f"{v('client_database_flows_ratio'):.0%} of its large flows are on database ports")
    if v("client_remote_flows_ratio") >= 0.1:
        return ("remote_computing_server", 0.6,
                f"{v('client_remote_flows_ratio'):.0%} of its large flows are on remote-access ports")
    sent = v("client_up_byte_ratio")
    web = v("client_web_https_flows_ratio") + v("client_web_http_flows_ratio")
    if sent >= 0.6 and peers >= 100:
        if web >= 0.9 and flows >= 3000:
            return "web_proxy", 0.7, f"sends {sent:.0%} of its large-flow bytes, over HTTPS, to {peers:.0f} addresses"
        return "website_server", 0.6, f"sends {sent:.0%} of its large-flow bytes to {peers:.0f} addresses"
    apps, udp = v("app_unique_apps"), v("client_udp_flows_ratio")
    if peers >= 400 or apps >= 200 or (udp >= 0.4 and peers >= 200):
        return ("NAT_gateway", 0.6,
                f"{peers:.0f} remote addresses, {apps:.0f} apps and {udp:.0%} UDP: many devices' worth of traffic")
    if not flows:
        return "end_host", 0.3, "no large flows: a quiet client"
    return "end_host", 0.6, f"a client receiving most of its traffic, {peers:.0f} remote addresses, {apps:.0f} apps"


def check_rules(features: pd.DataFrame, seeds: pd.DataFrame) -> pd.DataFrame:
    """How the rules do on the seeds: one row per seed host found in features."""
    labelled = features.merge(seeds, on="ip", how="inner")
    rows = []
    for _, row in labelled.iterrows():
        label, confidence, reason = rule_classify(row)
        rows.append({"ip": row["ip"], "seed_label": row["label"], "rule_label": label,
                     "agrees": label == row["label"], "rule_reason": reason})
    return pd.DataFrame(rows)


def label_population(features: pd.DataFrame, bundle: dict | None, seeds: pd.DataFrame | None = None,
                     review_threshold: float = 0.7) -> pd.DataFrame:
    """Every host's label: the seed label for seed hosts, else the forest's
    (or the rules' without a forest), with the rules' reading beside it."""
    out = features.copy()
    rules = [rule_classify(row) for _, row in out.iterrows()]
    out["rule_label"] = [r[0] for r in rules]
    out["rule_confidence"] = [r[1] for r in rules]
    out["rule_reason"] = [r[2] for r in rules]
    if bundle:
        out = out.merge(predict(bundle, out).drop(columns=["model_probabilities"]), on="ip", how="left")
        out["label"], out["label_score"] = out["model_label"], out["model_score"]
        out["label_source"] = "model"
    else:
        out["label"], out["label_score"], out["label_source"] = out["rule_label"], out["rule_confidence"], "rules"
    if seeds is not None and not seeds.empty:
        seed_map = seeds.set_index("ip")["label"]
        is_seed = out["ip"].isin(seed_map.index)
        out.loc[is_seed, "label"] = out.loc[is_seed, "ip"].map(seed_map)
        out.loc[is_seed, "label_score"] = 1.0
        out.loc[is_seed, "label_source"] = "seed"
    out["needs_manual_review"] = (out["label_source"] != "seed") & (out["label_score"] < review_threshold)
    return out

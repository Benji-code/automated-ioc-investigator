"""Host classification from the command line.

    python -m host_classification build --start "2026-06-07" --end "2026-06-14"
        extract features for active campus hosts, train on the seeds, label
        every host and build per-type profiles (all of the steps below)

    python -m host_classification extract --start ... --end ... [--max-ips N] [--no-reverse-dns]
    python -m host_classification check-rules      # the rule classifier against the seeds
    python -m host_classification train            # random forest from the seeds
    python -m host_classification label            # label every extracted host
    python -m host_classification profiles         # per-type behaviour profiles
    python -m host_classification classify 192.0.2.10 [--days 7]   # one host, as the agent sees it
    python -m host_classification dump-schema      # every table's columns and example rows

Everything is written under data/host_classification/ (gitignored: it holds
real campus IPs). The agent reads the model and profiles from there.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta, timezone

from agent import config

from . import classify, dump_schema, features, profiles


def _time(text: str) -> datetime:
    moment = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _paths() -> None:
    config.HOST_CLASSIFICATION_DIR.mkdir(parents=True, exist_ok=True)


def cmd_extract(args) -> None:
    _paths()
    frame = features.extract_population(_time(args.start), _time(args.end), args.max_ips,
                                        reverse_dns=not args.no_reverse_dns)
    features.to_csv(frame, config.HOST_FEATURES_PATH)
    (config.HOST_CLASSIFICATION_DIR / "period.txt").write_text(frame.attrs.get("period", ""), encoding="utf-8")
    print(f"{len(frame)} hosts x {len(frame.columns)} columns -> {config.HOST_FEATURES_PATH}")


def _read_features():
    if not config.HOST_FEATURES_PATH.exists():
        raise SystemExit(f"No features at {config.HOST_FEATURES_PATH}: run `extract` first.")
    frame = features.read_csv(config.HOST_FEATURES_PATH)
    period = config.HOST_CLASSIFICATION_DIR / "period.txt"
    frame.attrs["period"] = period.read_text(encoding="utf-8") if period.exists() else ""
    return frame


def cmd_check_rules(args) -> None:
    result = classify.check_rules(_read_features(), classify.load_seeds())
    print(result.to_string(index=False))
    if not result.empty:
        print(f"\nRules agree with {int(result['agrees'].sum())}/{len(result)} seed hosts.")


def cmd_train(args) -> None:
    frame = _read_features()
    bundle = classify.train(frame, classify.load_seeds(), args.max_depth, args.min_samples_leaf)
    path = classify.save(bundle)
    print(f"Trained on {bundle['seeds']} seed hosts {bundle['seed_counts']} -> {path}")
    print("Most important features:")
    for name, value in bundle["importance"][:12]:
        print(f"  {name:<40} {value}")
    print("With few seeds these labels are pseudo-labels: add more seeds and retrain.")


def cmd_label(args) -> None:
    frame = _read_features()
    bundle = classify.load()
    if bundle is None:
        print("No trained model (or scikit-learn missing): labelling with the rules only.")
    labelled = classify.label_population(frame, bundle, classify.load_seeds(), args.review_threshold)
    labelled.attrs["period"] = frame.attrs.get("period", "")
    features.to_csv(labelled, config.HOST_LABELLED_PATH)
    print(labelled["label"].value_counts().to_string())
    print(f"\n{int(labelled['needs_manual_review'].sum())} host(s) below {args.review_threshold} need review "
          f"-> {config.HOST_LABELLED_PATH}")


def cmd_profiles(args) -> None:
    if not config.HOST_LABELLED_PATH.exists():
        raise SystemExit(f"No labelled hosts at {config.HOST_LABELLED_PATH}: run `label` first.")
    labelled = features.read_csv(config.HOST_LABELLED_PATH)
    period = config.HOST_CLASSIFICATION_DIR / "period.txt"
    labelled.attrs["period"] = period.read_text(encoding="utf-8") if period.exists() else ""
    built = profiles.build(labelled, args.min_score)
    path = profiles.save(built)
    for label, info in built["types"].items():
        print(f"  {label:<26} {info['hosts']} hosts")
    print(f"-> {path}")


def cmd_build(args) -> None:
    cmd_extract(args)
    cmd_check_rules(args)
    try:
        cmd_train(args)
    except ImportError:
        print("scikit-learn is not installed: skipping the forest (pip install scikit-learn).")
    cmd_label(args)
    cmd_profiles(args)


def cmd_classify(args) -> None:
    from agent import host_type

    end = _time(args.end) if args.end else datetime.now(timezone.utc)
    result = host_type.assess_host(args.ip, {"evidence_last_seen": end.isoformat()}, None, days=args.days)
    print(json.dumps(result, indent=2, default=str))


def cmd_dump_schema(args) -> None:
    path = dump_schema.dump_all(config.PROJECT_ROOT / "data" / "schema_dump")
    print(f"-> {path}")


def main() -> None:
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(message)s")
    parser = argparse.ArgumentParser(prog="python -m host_classification", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def period(p):
        p.add_argument("--start", required=True, help="inclusive, UTC, e.g. 2026-06-07 or '2026-06-07 00:00'")
        p.add_argument("--end", required=True, help="exclusive, UTC")
        p.add_argument("--max-ips", type=int, default=10000, help="busiest hosts to extract (a safety cap); 0 = no cap")
        p.add_argument("--no-reverse-dns", action="store_true",
                       help="skip PTR lookups (much faster; host names are only a weak hint)")

    def training(p):
        p.add_argument("--max-depth", type=int, default=4)
        p.add_argument("--min-samples-leaf", type=int, default=1)

    def labelling(p):
        p.add_argument("--review-threshold", type=float, default=0.7)
        p.add_argument("--min-score", type=float, default=0.7, help="label score a host needs to join a profile")

    p = sub.add_parser("build", help="every step below")
    period(p), training(p), labelling(p)
    p.set_defaults(func=cmd_build)
    p = sub.add_parser("extract", help="features for active campus hosts")
    period(p)
    p.set_defaults(func=cmd_extract)
    sub.add_parser("check-rules", help="rule classifier vs the seeds").set_defaults(func=cmd_check_rules)
    p = sub.add_parser("train", help="random forest from the seeds")
    training(p)
    p.set_defaults(func=cmd_train)
    p = sub.add_parser("label", help="label every extracted host")
    labelling(p)
    p.set_defaults(func=cmd_label)
    p = sub.add_parser("profiles", help="per-type behaviour profiles")
    labelling(p)
    p.set_defaults(func=cmd_profiles)
    p = sub.add_parser("classify", help="one host, as the agent sees it")
    p.add_argument("ip")
    p.add_argument("--days", type=int, default=config.HOST_TYPE_WINDOW_DAYS)
    p.add_argument("--end", default=None, help="end of the window (UTC); default now")
    p.set_defaults(func=cmd_classify)
    sub.add_parser("dump-schema", help="columns and example rows of every table").set_defaults(func=cmd_dump_schema)

    args = parser.parse_args()
    config.clickhouse_settings()  # fail early, with a clear message, if .env is missing
    args.func(args)


if __name__ == "__main__":
    main()

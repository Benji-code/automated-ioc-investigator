"""Compare expected verdicts with the agent's baseline and model verdicts.

    python eval/run_eval.py                        # quick: one case per indicator, at most 6 (a few minutes)
    python eval/run_eval.py --all                  # every case with an expected verdict (slow)
    python eval/run_eval.py --limit 3 --repeat 2   # 3 cases, model run twice on the same evidence
    python eval/run_eval.py --from-output output/assessments.json   # no new runs, compare saved results
    python eval/run_eval.py --list                 # print every case in the feed, to fill in expected verdicts

Expected verdicts: data/expected_verdicts.json (real IPs, gitignored) if it
exists, else eval/expected_verdicts.json (fake IPs, committed). Format:
    {"cases": [{"indicator": "bore.pub", "host": "192.0.2.10",
                "expected": "LIKELY_FALSE_POSITIVE", "note": "why"}]}
"expected": null means not decided yet; those cases are listed but not scored.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import assess  # noqa: E402
from agent import config, report  # noqa: E402

VERDICTS = ["LIKELY_THREAT", "SUSPICIOUS", "LIKELY_FALSE_POSITIVE", "INSUFFICIENT_DATA"]
SHORT = {"LIKELY_THREAT": "THREAT", "SUSPICIOUS": "SUSP", "LIKELY_FALSE_POSITIVE": "FP",
         "INSUFFICIENT_DATA": "NODATA", "ERROR": "ERROR", None: "-"}


def default_expected_path() -> Path:
    real = ROOT / "data" / "expected_verdicts.json"
    return real if real.exists() else HERE / "expected_verdicts.json"


def load_expected(path: Path) -> dict[tuple[str, str], dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {(c["indicator"], c["host"]): c for c in data["cases"]}


def confusion(rows: list[dict], column: str) -> str:
    """Expected (rows) against one predicted column, as a text table."""
    counts = Counter((r["expected"], r[column]) for r in rows if r["expected"])
    predicted = VERDICTS + (["ERROR"] if any(r[column] == "ERROR" for r in rows) else [])
    width = 8
    corner = f"expected / {column}"
    lines = [f"{corner:<24}" + "".join(f"{SHORT[v]:>{width}}" for v in predicted)]
    for expected in VERDICTS:
        if not any(r["expected"] == expected for r in rows):
            continue
        lines.append(f"{SHORT[expected]:<24}" + "".join(f"{counts[(expected, v)]:>{width}}" for v in predicted))
    scored = [r for r in rows if r["expected"]]
    correct = sum(1 for r in scored if r["expected"] == r[column])
    lines.append(f"accuracy: {correct}/{len(scored)}")
    return "\n".join(lines)


def quick_sample(cases, expected: dict, limit: int):
    """One case per distinct indicator, cases with a decided expected verdict
    first, so a few minutes' run still covers different kinds of case."""
    seen: set[str] = set()
    picked = []
    decided = sorted(cases, key=lambda c: expected[(c[0]["indicator"], c[0]["affected_asset"])].get("expected") is None)
    for case in decided:
        if case[0]["indicator"] in seen:
            continue
        seen.add(case[0]["indicator"])
        picked.append(case)
    return picked[:limit]


def run_cases(cases, asset_index, repeat: int, save_dir: Path, links: dict | None = None,
              link_checks: dict | None = None, also_matched: dict | None = None) -> list[dict]:
    """Gather evidence once per case, then run the model `repeat` times on it.
    The first run's full results go to save_dir (assessments.json, report.html,
    cases/), rewritten after every case."""
    results = []
    full: list[dict] = []
    (save_dir / "cases").mkdir(parents=True, exist_ok=True)
    for i, (identity, rows) in enumerate(cases):
        print(f"[{i + 1}/{len(cases)}] {identity['indicator']} <-> {identity['affected_asset']}", flush=True)
        try:
            ev = assess.gather_evidence(identity, rows, asset_index)
            assess.attach_links(ev, links, link_checks)
            ev["also_matched"] = (also_matched or {}).get((identity["indicator"], identity["affected_asset"]), [])
            runs = [assess.assess_evidence(identity, ev) for _ in range(repeat)]
        except Exception as exc:  # noqa: BLE001 - one bad case shouldn't stop the eval
            print(f"  FAILED: {exc}")
            results.append({"indicator": identity["indicator"], "host": identity["affected_asset"],
                            "baseline": "ERROR", "model": "ERROR", "final": "ERROR", "stable": None, "review": True})
            continue
        first = runs[0]
        full.append(first)
        report.write_case_files(first, save_dir / "cases")
        (save_dir / "assessments.json").write_text(json.dumps(full, indent=2, default=str), encoding="utf-8")
        (save_dir / "report.html").write_text(report.render(full), encoding="utf-8")
        print(f"  baseline={first['baseline_verdict']} model={first['model_verdict']} final={first['VERDICT']}"
              + ("" if repeat == 1 else f" runs={[r['VERDICT'] for r in runs]}"), flush=True)
        results.append({
            "indicator": identity["indicator"], "host": identity["affected_asset"],
            "baseline": first["baseline_verdict"], "model": first["model_verdict"], "final": first["VERDICT"],
            "stable": len({(r["model_verdict"], r["VERDICT"]) for r in runs}) == 1 if repeat > 1 else None,
            "review": first["needs_review"],
            "finding": first.get("additional_finding"),
        })
    return results


def recheck(saved: list[dict]) -> list[dict]:
    """Re-apply the code checks (reconciliation, guards, consistency flags)
    to saved replies, without calling the model again."""
    out = []
    for r in saved:
        if not r.get("evidence") or not r.get("model_reply_raw"):
            out.append(r)
            continue
        identity = {k: r[k] for k in ("indicator", "indicator_type", "affected_asset", "malware", "threat_type",
                                      "threatfox_confidence", "evidence_first_seen", "evidence_last_seen",
                                      "ioc_metadata", "match_ids", "n_events") if k in r}
        out.append(assess.finish_result(identity, r["evidence"], r["case_file"], r["model_reply_raw"],
                                        r.get("tool_calls") or []))
    return out


def from_output(path: Path, rechecked: bool) -> list[dict]:
    saved = json.loads(path.read_text(encoding="utf-8"))
    if rechecked:
        saved = recheck(saved)
        path.write_text(json.dumps(saved, indent=2, default=str), encoding="utf-8")
        (path.parent / "report.html").write_text(report.render(saved), encoding="utf-8")
        print(f"Re-applied code checks and rewrote {path} and {path.parent / 'report.html'}")
    results = []
    for r in saved:
        results.append({"indicator": r["indicator"], "host": r["affected_asset"],
                        "baseline": r.get("baseline_verdict", "ERROR"), "model": r.get("model_verdict", "ERROR"),
                        "final": r.get("VERDICT"), "stable": None, "review": r.get("needs_review"),
                        "finding": r.get("additional_finding")})
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("feed", type=Path, nargs="?", default=None,
                        help="IOC-match feed (JSON or JSON Lines); default as for assess.py")
    parser.add_argument("--input", type=Path, default=None, help="same as the positional feed argument")
    parser.add_argument("--expected", type=Path, default=None)
    parser.add_argument("--from-output", type=Path, default=None, help="compare a saved assessments.json instead")
    parser.add_argument("--recheck", action="store_true",
                        help="with --from-output: re-apply the code checks to the saved replies first")
    parser.add_argument("--limit", type=int, default=6, help="cases to run in the quick sample (default 6)")
    parser.add_argument("--all", action="store_true", help="run every case with an expected verdict")
    parser.add_argument("--repeat", type=int, default=1, help="model runs per case, to check determinism")
    parser.add_argument("--list", action="store_true", help="print every case in the feed and exit")
    parser.add_argument("--save-dir", type=Path, default=ROOT / "output" / "eval",
                        help="where the first run's assessments and report go (gitignored)")
    args = parser.parse_args()
    args.input = assess.feed_path(args.feed, args.input)

    if args.list:
        cases, _, _ = assess.load_cases(args.input)
        for identity, _rows in cases:
            print(f"{identity['indicator']:<28} {identity['affected_asset']:<16} {identity['malware']:<16} "
                  f"{identity['threat_type']:<18} {identity['n_events']:>5} match(es)  "
                  f"{(identity['evidence_first_seen'] or '')[:10]}")
        return

    expected_path = args.expected or default_expected_path()
    expected = load_expected(expected_path)
    print(f"Expected verdicts: {expected_path} ({sum(1 for c in expected.values() if c.get('expected'))} decided)")

    if args.from_output:
        results = from_output(args.from_output, args.recheck)
    else:
        config.clickhouse_settings()
        cases, asset_index, _ = assess.load_cases(args.input)
        links, link_checks = assess.cross_case_links(cases)  # over the whole feed, before sampling
        cases, also_matched = assess.merge_same_visits(cases, links)
        cases = [c for c in cases if (c[0]["indicator"], c[0]["affected_asset"]) in expected]
        if not args.all:
            cases = quick_sample(cases, expected, args.limit)
        results = run_cases(cases, asset_index, max(args.repeat, 1), args.save_dir, links, link_checks,
                            also_matched)

    rows = []
    for r in results:
        case = expected.get((r["indicator"], r["host"]))
        if case is None:
            continue
        rows.append({**r, "expected": case.get("expected")})

    print(f"\n{'indicator':<26} {'host':<16} {'expected':>9} {'baseline':>9} {'model':>9} {'final':>9}  notes")
    for r in rows:
        notes = []
        if r["expected"] and r["final"] != r["expected"]:
            notes.append("MISMATCH")
        if r["review"]:
            notes.append("review")
        if r.get("finding"):
            notes.append("agent finding")
        if r["stable"] is False:
            notes.append("UNSTABLE across runs")
        print(f"{r['indicator'][:26]:<26} {r['host']:<16} {SHORT[r['expected']]:>9} {SHORT.get(r['baseline'], r['baseline']):>9} "
              f"{SHORT.get(r['model'], r['model']):>9} {SHORT.get(r['final'], r['final']):>9}  {', '.join(notes)}")

    for column in ("baseline", "model", "final"):
        print(f"\n{column.upper()} vs expected\n{confusion(rows, column)}")
    judged = [r for r in rows if r["baseline"] not in ("ERROR", "INSUFFICIENT_DATA")]
    if judged:
        agreed = sum(1 for r in judged if r["model"] == r["baseline"])
        print(f"\nBlind review agreed with the rules on {agreed}/{len(judged)} case(s) "
              "(the model does not see the rules' verdict).")
    findings = [r for r in rows if r.get("finding")]
    print(f"Agent findings (edge cases the rules do not cover) on {len(findings)}/{len(rows)} case(s):")
    for r in findings:
        print(f"  - {r['indicator']} / {r['host']}: {r['finding'][:200]}")
    stable = [r["stable"] for r in rows if r["stable"] is not None]
    if stable:
        print(f"\nDeterminism: {sum(stable)}/{len(stable)} case(s) gave the same verdict on every run.")


if __name__ == "__main__":
    main()

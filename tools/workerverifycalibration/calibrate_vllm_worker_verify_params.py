#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import platform
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Sequence, Tuple

from analyze_vllm_worker_verify import (
    FP_SCALE,
    JUDGMENT_FUNCTION_VERSION,
    LOWER_BOUND_METRICS,
    METRICS_FILENAME,
    SAMPLE_THRESHOLD_METRICS,
    UPPER_BOUND_METRICS,
    collect_fields,
    evaluate_sample,
    fp_1e6,
    mean,
    model_selector_matches,
    quantile,
    resolve_inputs,
    safe_float,
    safe_int,
    summarize_sample_rows,
    process_metrics_file,
    write_csv,
    write_json,
)


def log(message: str) -> None:
    print(message, flush=True)


def runtime_metadata(argv: Sequence[str]) -> Dict[str, Any]:
    return {
        "created_at_unix": time.time(),
        "python": sys.version,
        "platform": platform.platform(),
        "argv": list(argv),
    }


def finite_values(rows: Sequence[Dict[str, Any]], metric: str) -> List[float]:
    return [
        value
        for value in (safe_float(row.get(metric)) for row in rows)
        if math.isfinite(value)
    ]


def metric_direction(metric: str) -> str:
    if metric in UPPER_BOUND_METRICS:
        return "upper_is_worse"
    if metric in LOWER_BOUND_METRICS:
        return "lower_is_worse"
    raise ValueError(f"Unknown metric: {metric}")


def threshold_key(metric: str, bound: str) -> str:
    return f"{metric}_{bound}"


def metric_stats(values: Sequence[float]) -> Dict[str, Any]:
    finite = [value for value in values if math.isfinite(value)]
    return {
        "count": len(finite),
        "min": min(finite, default=float("nan")),
        "p01": quantile(finite, 0.01),
        "p05": quantile(finite, 0.05),
        "p50": quantile(finite, 0.50),
        "p90": quantile(finite, 0.90),
        "p95": quantile(finite, 0.95),
        "p99": quantile(finite, 0.99),
        "max": max(finite, default=float("nan")),
        "mean": mean(finite),
    }


def pass_rate(values: Sequence[float], metric: str, bound: float) -> float:
    finite = [value for value in values if math.isfinite(value)]
    if not finite or not math.isfinite(bound):
        return float("nan")
    if metric in UPPER_BOUND_METRICS:
        return sum(1 for value in finite if value <= bound) / len(finite)
    return sum(1 for value in finite if value >= bound) / len(finite)


def reject_rate(values: Sequence[float], metric: str, bound: float) -> float:
    finite = [value for value in values if math.isfinite(value)]
    if not finite or not math.isfinite(bound):
        return float("nan")
    if metric in UPPER_BOUND_METRICS:
        return sum(1 for value in finite if value > bound) / len(finite)
    return sum(1 for value in finite if value < bound) / len(finite)


def midpoint_candidates(values: Sequence[float]) -> List[float]:
    finite = sorted(set(value for value in values if math.isfinite(value)))
    if not finite:
        return []
    if len(finite) == 1:
        return finite
    candidates = [finite[0]]
    for left, right in zip(finite, finite[1:]):
        candidates.append((left + right) / 2.0)
    candidates.append(finite[-1])
    return candidates


def optimize_reject_bound(
    base_values: Sequence[float],
    challenger_values: Sequence[float],
    metric: str,
    *,
    max_base_reject_rate: float,
) -> Tuple[float, float, float, float]:
    candidates = midpoint_candidates([*base_values, *challenger_values])
    if not candidates:
        return float("nan"), float("nan"), float("nan"), float("nan")

    best: Optional[Tuple[float, float, float, float]] = None
    for candidate in candidates:
        base_fp = reject_rate(base_values, metric, candidate)
        challenger_tp = reject_rate(challenger_values, metric, candidate)
        if not math.isfinite(base_fp) or not math.isfinite(challenger_tp):
            continue
        if base_fp > max_base_reject_rate:
            continue
        youden = challenger_tp - base_fp
        score = (youden, challenger_tp, -base_fp)
        if best is None or score > (best[3], best[2], -best[1]):
            best = (candidate, base_fp, challenger_tp, youden)
    if best is not None:
        return best

    # Fallback: no candidate satisfies the base false reject constraint.
    if metric in UPPER_BOUND_METRICS:
        candidate = quantile(base_values, 1.0 - max_base_reject_rate)
    else:
        candidate = quantile(base_values, max_base_reject_rate)
    base_fp = reject_rate(base_values, metric, candidate)
    challenger_tp = reject_rate(challenger_values, metric, candidate)
    return candidate, base_fp, challenger_tp, challenger_tp - base_fp


def calibrated_pass_bound(base_values: Sequence[float], metric: str,
                          target_base_pass_rate: float,
                          safety_multiplier: float,
                          lower_margin: float) -> float:
    if metric == "missing_compared_count":
        return max(base_values, default=0.0)
    if metric in UPPER_BOUND_METRICS:
        value = quantile(base_values, target_base_pass_rate)
        return value * safety_multiplier if value >= 0.0 else value / safety_multiplier
    value = quantile(base_values, 1.0 - target_base_pass_rate)
    return max(0.0, value - lower_margin)


def calibrated_reject_bound(base_values: Sequence[float],
                            challenger_values: Sequence[float],
                            metric: str,
                            *,
                            max_base_reject_rate: float,
                            pass_bound: float) -> Tuple[float, float, float, float]:
    if metric == "missing_compared_count":
        bound = pass_bound + 1
        return (
            bound,
            reject_rate(base_values, metric, bound),
            reject_rate(challenger_values, metric, bound),
            reject_rate(challenger_values, metric, bound) - reject_rate(base_values, metric, bound),
        )
    optimized, base_fp, challenger_tp, youden = optimize_reject_bound(
        base_values,
        challenger_values,
        metric,
        max_base_reject_rate=max_base_reject_rate,
    )
    if not math.isfinite(optimized):
        return optimized, base_fp, challenger_tp, youden
    if metric in UPPER_BOUND_METRICS:
        optimized = max(optimized, pass_bound)
    else:
        optimized = min(optimized, pass_bound)
    return (
        optimized,
        reject_rate(base_values, metric, optimized),
        reject_rate(challenger_values, metric, optimized),
        reject_rate(challenger_values, metric, optimized) - reject_rate(base_values, metric, optimized),
    )


def separation_gap(base_stats: Dict[str, Any],
                   challenger_stats: Dict[str, Any],
                   metric: str) -> float:
    if metric in UPPER_BOUND_METRICS:
        return safe_float(challenger_stats.get("p50")) - safe_float(base_stats.get("p99"))
    return safe_float(base_stats.get("p01")) - safe_float(challenger_stats.get("p50"))


def calibrate_metric(
    metric: str,
    base_samples: Sequence[Dict[str, Any]],
    challenger_samples: Sequence[Dict[str, Any]],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    base_values = finite_values(base_samples, metric)
    challenger_values = finite_values(challenger_samples, metric)
    base_stats = metric_stats(base_values)
    challenger_stats = metric_stats(challenger_values)
    pass_bound = calibrated_pass_bound(
        base_values,
        metric,
        args.target_base_pass_rate,
        args.pass_safety_multiplier,
        args.lower_margin,
    )
    reject_bound, base_false_reject_rate, challenger_reject_rate, youden = calibrated_reject_bound(
        base_values,
        challenger_values,
        metric,
        max_base_reject_rate=args.max_base_false_reject_rate,
        pass_bound=pass_bound,
    )
    bound_type = "max" if metric in UPPER_BOUND_METRICS else "min"
    row: Dict[str, Any] = {
        "metric": metric,
        "direction": metric_direction(metric),
        "threshold_key": threshold_key(metric, bound_type),
        "pass_bound": pass_bound,
        "pass_bound_fp_1e6": fp_1e6(pass_bound),
        "reject_bound": reject_bound,
        "reject_bound_fp_1e6": fp_1e6(reject_bound),
        "base_count": len(base_values),
        "challenger_count": len(challenger_values),
        "base_pass_rate_at_pass_bound": pass_rate(base_values, metric, pass_bound),
        "challenger_pass_rate_at_pass_bound": pass_rate(challenger_values, metric, pass_bound),
        "base_false_reject_rate_at_reject_bound": base_false_reject_rate,
        "challenger_reject_rate_at_reject_bound": challenger_reject_rate,
        "youden_at_reject_bound": youden,
        "separation_gap": separation_gap(base_stats, challenger_stats, metric),
        "base_min": base_stats["min"],
        "base_p50": base_stats["p50"],
        "base_p95": base_stats["p95"],
        "base_p99": base_stats["p99"],
        "base_max": base_stats["max"],
        "challenger_min": challenger_stats["min"],
        "challenger_p50": challenger_stats["p50"],
        "challenger_p95": challenger_stats["p95"],
        "challenger_p99": challenger_stats["p99"],
        "challenger_max": challenger_stats["max"],
    }
    return row


def thresholds_from_calibration(metric_rows: Sequence[Dict[str, Any]],
                                args: argparse.Namespace) -> Dict[str, Any]:
    pass_thresholds: Dict[str, Any] = {}
    reject_thresholds: Dict[str, Any] = {}
    pass_fp_1e6: Dict[str, Any] = {}
    reject_fp_1e6: Dict[str, Any] = {}
    for row in metric_rows:
        key = str(row["threshold_key"])
        pass_thresholds[key] = safe_float(row.get("pass_bound"))
        reject_thresholds[key] = safe_float(row.get("reject_bound"))
        pass_fp_1e6[key] = safe_int(row.get("pass_bound_fp_1e6"), "")
        reject_fp_1e6[key] = safe_int(row.get("reject_bound_fp_1e6"), "")
    return {
        "source": "calibrated_from_experiment_data",
        "judgment_function_version": JUDGMENT_FUNCTION_VERSION,
        "token_scope": "ALL_GENERATED_OUTPUT_TOKENS",
        "pass": pass_thresholds,
        "reject": reject_thresholds,
        "pass_fp_1e6": pass_fp_1e6,
        "reject_fp_1e6": reject_fp_1e6,
        "calibration_policy": {
            "target_base_pass_rate_per_metric": args.target_base_pass_rate,
            "max_base_false_reject_rate_per_metric": args.max_base_false_reject_rate,
            "pass_safety_multiplier": args.pass_safety_multiplier,
            "lower_margin": args.lower_margin,
            "reject_bound_selection": (
                "maximize challenger reject rate / Youden subject to base false "
                "reject constraint, then keep reject bound outside pass bound"
            ),
        },
    }


def apply_thresholds(samples: Sequence[Dict[str, Any]], thresholds: Dict[str, Any]) -> None:
    for row in samples:
        evaluate_sample(row, thresholds)


def split_samples(sample_rows: Sequence[Dict[str, Any]],
                  args: argparse.Namespace) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    base = [row for row in sample_rows if row.get("model_role") == "base"]
    challengers = [row for row in sample_rows if row.get("model_role") != "base"]
    if args.challenger_run or args.challenger_model:
        challengers = [
            row for row in challengers
            if challenger_selector_matches(row, args.challenger_run, args.challenger_model)
        ]
    return base, challengers


def challenger_selector_matches(row: Dict[str, Any],
                                challenger_runs: Sequence[str],
                                challenger_models: Sequence[str]) -> bool:
    haystack = " ".join(
        str(row.get(key, ""))
        for key in [
            "run_id",
            "worker_variant_id",
            "verifier_variant_id",
            "worker_model",
            "verifier_model",
            "metrics_path",
        ]
    ).lower()
    for selector in challenger_runs:
        if selector.lower() in haystack:
            return True
    for selector in challenger_models:
        if model_selector_matches(selector, str(row.get("verifier_model", ""))):
            return True
        if model_selector_matches(selector, str(row.get("verifier_variant_id", ""))):
            return True
    return False


def verdict_counts(samples: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {"PASS": 0, "REJECT": 0, "INCONCLUSIVE": 0}
    for row in samples:
        verdict = str(row.get("metric_sample_verdict", ""))
        if verdict in counts:
            counts[verdict] += 1
    total = sum(counts.values())
    return {
        "sample_count": total,
        "pass_count": counts["PASS"],
        "reject_count": counts["REJECT"],
        "inconclusive_count": counts["INCONCLUSIVE"],
        "pass_rate": counts["PASS"] / total if total else "",
        "reject_rate": counts["REJECT"] / total if total else "",
        "inconclusive_rate": counts["INCONCLUSIVE"] / total if total else "",
    }


def build_group_rows(samples: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for row in samples:
        key = (
            str(row.get("model_role", "")),
            str(row.get("verifier_variant_id", "")),
            str(row.get("verifier_model", "")),
        )
        grouped.setdefault(key, []).append(row)
    out = []
    for (role, variant, model), rows in sorted(grouped.items()):
        summary = summarize_sample_rows(rows, variant or model or role)
        summary.update({
            "model_role": role,
            "verifier_variant_id": variant,
            "verifier_model": model,
            **verdict_counts(rows),
        })
        out.append(summary)
    return out


def write_markdown(path: Path,
                   metric_rows: Sequence[Dict[str, Any]],
                   group_rows: Sequence[Dict[str, Any]],
                   thresholds: Dict[str, Any],
                   base_count: int,
                   challenger_count: int) -> None:
    lines = [
        "# vLLM worker verify parameter calibration",
        "",
        f"- judgment_function_version: `{JUDGMENT_FUNCTION_VERSION}`",
        f"- base samples: {base_count}",
        f"- challenger samples: {challenger_count}",
        f"- threshold output: `recommended_thresholds.json`",
        "",
        "## Recommended Thresholds",
        "",
        "| metric | pass bound | reject bound | base pass | challenger pass | base false reject | challenger reject | separation gap |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in metric_rows:
        lines.append(
            "| {metric} | {pass_bound:.8g} | {reject_bound:.8g} | {base_pass:.6g} | {challenger_pass:.6g} | {base_reject:.6g} | {challenger_reject:.6g} | {gap:.8g} |".format(
                metric=row.get("metric", ""),
                pass_bound=safe_float(row.get("pass_bound")),
                reject_bound=safe_float(row.get("reject_bound")),
                base_pass=safe_float(row.get("base_pass_rate_at_pass_bound")),
                challenger_pass=safe_float(row.get("challenger_pass_rate_at_pass_bound")),
                base_reject=safe_float(row.get("base_false_reject_rate_at_reject_bound")),
                challenger_reject=safe_float(row.get("challenger_reject_rate_at_reject_bound")),
                gap=safe_float(row.get("separation_gap")),
            )
        )
    lines.extend([
        "",
        "## Combined Sample Verdicts",
        "",
        "| role | verifier | samples | pass | reject | inconclusive | pass rate | reject rate |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ])
    for row in group_rows:
        lines.append(
            "| {role} | {verifier} | {samples} | {passed} | {rejected} | {inc} | {pass_rate:.6g} | {reject_rate:.6g} |".format(
                role=row.get("model_role", ""),
                verifier=row.get("verifier_variant_id") or row.get("verifier_model", ""),
                samples=row.get("sample_count", ""),
                passed=row.get("pass_count", ""),
                rejected=row.get("reject_count", ""),
                inc=row.get("inconclusive_count", ""),
                pass_rate=safe_float(row.get("pass_rate")),
                reject_rate=safe_float(row.get("reject_rate")),
            )
        )
    lines.extend([
        "",
        "## Notes",
        "",
        "- PASS bounds are calibrated to retain base samples per metric.",
        "- REJECT bounds are calibrated to reject challengers while respecting the base false-reject constraint.",
        "- This is an experiment-derived recommendation; protocol values still need profile/governance review.",
        "",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Calibrate PREFILL_GENERATED_TOKEN_METRICS_V1 threshold parameters "
            "from base-model and challenger-model experiment data."
        )
    )
    parser.add_argument(
        "--input",
        action="append",
        default=[],
        help=(
            "Metrics CSV, verifier output dir, or root dir to scan recursively. "
            "Repeat as needed. Defaults to results/vllm_worker_verify_runs."
        ),
    )
    parser.add_argument("--output-dir", default="calibration")
    parser.add_argument(
        "--base-run",
        action="append",
        default=[],
        help="Substring marking a run/path/variant as base. Repeat as needed.",
    )
    parser.add_argument(
        "--base-model",
        action="append",
        default=[],
        help="Exact model name or path basename marking a verifier model as base.",
    )
    parser.add_argument(
        "--challenger-run",
        action="append",
        default=[],
        help="Optional substring filter for challenger runs. Repeat as needed.",
    )
    parser.add_argument(
        "--challenger-model",
        action="append",
        default=[],
        help="Optional exact model name/path basename filter for challenger models.",
    )
    parser.add_argument("--target-base-pass-rate", type=float, default=0.99)
    parser.add_argument("--max-base-false-reject-rate", type=float, default=0.01)
    parser.add_argument("--pass-safety-multiplier", type=float, default=1.10)
    parser.add_argument("--lower-margin", type=float, default=0.02)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    input_paths = args.input or ["results/vllm_worker_verify_runs"]
    metrics_files = resolve_inputs(input_paths)
    if not metrics_files:
        parser.error(f"No {METRICS_FILENAME} files found")
    if not args.base_run and not args.base_model:
        parser.error("At least one --base-run or --base-model selector is required")

    process_args = SimpleNamespace(
        base_run=args.base_run,
        base_model=args.base_model,
        top_outliers_per_run=0,
    )
    processed = [process_metrics_file(path, process_args) for path in metrics_files]
    sample_rows = [row for item in processed for row in item["sample_rows"]]
    base_samples, challenger_samples = split_samples(sample_rows, args)
    if not base_samples:
        parser.error("No base samples matched. Check --base-run / --base-model.")
    if not challenger_samples:
        parser.error("No challenger samples matched. Check inputs or challenger filters.")

    metric_rows = [
        calibrate_metric(metric, base_samples, challenger_samples, args)
        for metric in SAMPLE_THRESHOLD_METRICS
    ]
    thresholds = thresholds_from_calibration(metric_rows, args)
    apply_thresholds(sample_rows, thresholds)
    group_rows = build_group_rows(sample_rows)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "recommended_thresholds.json", thresholds)
    write_csv(output_dir / "metric_calibration.csv", metric_rows, collect_fields(metric_rows, [
        "metric",
        "direction",
        "threshold_key",
        "pass_bound",
        "pass_bound_fp_1e6",
        "reject_bound",
        "reject_bound_fp_1e6",
        "base_count",
        "challenger_count",
        "base_pass_rate_at_pass_bound",
        "challenger_pass_rate_at_pass_bound",
        "base_false_reject_rate_at_reject_bound",
        "challenger_reject_rate_at_reject_bound",
        "youden_at_reject_bound",
        "separation_gap",
    ]))
    write_csv(output_dir / "group_verdicts.csv", group_rows, collect_fields(group_rows, [
        "model_role",
        "verifier_variant_id",
        "verifier_model",
        "run_count",
        "sample_count",
        "pass_count",
        "reject_count",
        "inconclusive_count",
        "pass_rate",
        "reject_rate",
        "inconclusive_rate",
        "mean_abs_logprob_diff_sample_mean",
        "abs_logprob_diff_p99_sample_mean",
        "rank_delta_nonzero_rate_sample_mean",
        "topk_jaccard_mean_sample_mean",
        "union_js_p99_sample_mean",
    ]))
    write_csv(output_dir / "sample_verdicts.csv", sample_rows, collect_fields(sample_rows, [
        "model_role",
        "run_id",
        "sample_id",
        "worker_variant_id",
        "verifier_variant_id",
        "verifier_model",
        "mean_abs_logprob_diff",
        "abs_logprob_diff_p95",
        "abs_logprob_diff_p99",
        "rank_delta_nonzero_rate",
        "topk_jaccard_mean",
        "union_js_p99",
        "metric_sample_verdict",
        "threshold_breach_count",
        "reject_breach_count",
        "threshold_breaches",
        "reject_breaches",
    ]))
    write_json(output_dir / "calibration_metadata.json", {
        "metadata": runtime_metadata(sys.argv),
        "judgment_function_version": JUDGMENT_FUNCTION_VERSION,
        "input_metrics_files": [str(path) for path in metrics_files],
        "base_sample_count": len(base_samples),
        "challenger_sample_count": len(challenger_samples),
        "output_files": [
            "recommended_thresholds.json",
            "metric_calibration.csv",
            "group_verdicts.csv",
            "sample_verdicts.csv",
            "summary.md",
        ],
    })
    write_markdown(
        output_dir / "summary.md",
        metric_rows,
        group_rows,
        thresholds,
        len(base_samples),
        len(challenger_samples),
    )

    log(f"Wrote {output_dir / 'recommended_thresholds.json'}")
    log(f"Wrote {output_dir / 'metric_calibration.csv'}")
    log(f"Wrote {output_dir / 'summary.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

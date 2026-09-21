#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import platform
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


METRICS_FILENAME = "worker_vs_verifier_depth_metrics.csv"
JUDGMENT_FUNCTION_VERSION = "PREFILL_GENERATED_TOKEN_METRICS_V1"
FP_SCALE = 1_000_000

UPPER_BOUND_METRICS = [
    "missing_compared_count",
    "mean_abs_logprob_diff",
    "abs_logprob_diff_p95",
    "abs_logprob_diff_p99",
    "rank_delta_nonzero_rate",
    "union_js_p99",
]
LOWER_BOUND_METRICS = [
    "topk_jaccard_mean",
]
SAMPLE_THRESHOLD_METRICS = UPPER_BOUND_METRICS + LOWER_BOUND_METRICS


def log(message: str) -> None:
    print(message, flush=True)


def runtime_metadata(argv: Sequence[str]) -> Dict[str, Any]:
    return {
        "created_at_unix": time.time(),
        "python": sys.version,
        "platform": platform.platform(),
        "argv": list(argv),
    }


def read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload if isinstance(payload, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)


def safe_float(value: Any, default: float = float("nan")) -> float:
    if value in {"", None}:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value in {"", None}:
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def is_finite(value: Any) -> bool:
    return math.isfinite(safe_float(value))


def mean(values: Sequence[float]) -> float:
    finite = [value for value in values if math.isfinite(value)]
    return sum(finite) / len(finite) if finite else float("nan")


def quantile(values: Sequence[float], q: float) -> float:
    finite = sorted(value for value in values if math.isfinite(value))
    if not finite:
        return float("nan")
    if len(finite) == 1:
        return finite[0]
    pos = (len(finite) - 1) * q
    low = int(math.floor(pos))
    high = int(math.ceil(pos))
    if low == high:
        return finite[low]
    weight = pos - low
    return finite[low] * (1.0 - weight) + finite[high] * weight


def fp_1e6(value: Any) -> str:
    number = safe_float(value)
    if not math.isfinite(number):
        return ""
    return str(int(round(number * FP_SCALE)))


def input_bucket(token_count: int) -> str:
    if token_count <= 128:
        return "00000-00128"
    if token_count <= 512:
        return "00129-00512"
    if token_count <= 2048:
        return "00513-02048"
    if token_count <= 8192:
        return "02049-08192"
    if token_count <= 16384:
        return "08193-16384"
    return "16385+"


def output_depth_bucket(depth: int) -> str:
    if depth <= 16:
        return "000-016"
    if depth <= 32:
        return "017-032"
    if depth <= 64:
        return "033-064"
    if depth <= 128:
        return "065-128"
    if depth <= 256:
        return "129-256"
    return "257+"


def resolve_metrics_file(path: Path) -> Optional[Path]:
    if path.is_file() and path.name == METRICS_FILENAME:
        return path
    if path.is_dir():
        candidate = path / METRICS_FILENAME
        if candidate.exists():
            return candidate
    return None


def resolve_inputs(paths: Sequence[str]) -> List[Path]:
    metrics_files: List[Path] = []
    seen = set()
    for raw in paths:
        path = Path(raw)
        direct = resolve_metrics_file(path)
        if direct is not None:
            resolved = direct.resolve()
            if resolved not in seen:
                metrics_files.append(direct)
                seen.add(resolved)
            continue
        if path.is_dir():
            for found in sorted(path.rglob(METRICS_FILENAME)):
                resolved = found.resolve()
                if resolved not in seen:
                    metrics_files.append(found)
                    seen.add(resolved)
            continue
        raise FileNotFoundError(f"Cannot find {METRICS_FILENAME} under {path}")
    return metrics_files


def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: Sequence[Dict[str, Any]], fields: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def collect_fields(rows: Sequence[Dict[str, Any]], preferred: Sequence[str]) -> List[str]:
    fields = list(preferred)
    present = set(fields)
    for row in rows:
        for key in row:
            if key not in present:
                fields.append(key)
                present.add(key)
    return fields


def parse_labels_from_dir(name: str) -> Tuple[str, str]:
    marker = "_worker_vs_"
    suffix = "_verifier"
    if marker not in name:
        return "", ""
    left, right = name.split(marker, 1)
    if right.endswith(suffix):
        right = right[: -len(suffix)]
    return left, right


def find_pipeline_metadata(metrics_path: Path) -> Optional[Dict[str, Any]]:
    for parent in [metrics_path.parent, *metrics_path.parents]:
        candidate = parent / "pipeline_metadata.json"
        if candidate.exists():
            return read_json(candidate)
    return None


def run_context(metrics_path: Path) -> Dict[str, str]:
    parent = metrics_path.parent
    verifier_metadata = read_json(parent / "metadata.json") or {}
    pipeline_metadata = find_pipeline_metadata(metrics_path) or {}
    worker_label, verifier_label = parse_labels_from_dir(parent.name)

    pipeline_args = pipeline_metadata.get("args", {})
    verifier_variant = verifier_metadata.get("verifier_variant", {})
    verifier_args = verifier_metadata.get("args", {})

    worker_variant_id = str(
        pipeline_metadata.get("baseline_variant_id")
        or worker_label
        or ""
    )
    verifier_variant_id = str(
        pipeline_metadata.get("comparison_variant_id")
        or verifier_variant.get("variant_id")
        or verifier_label
        or ""
    )
    worker_model = str(pipeline_args.get("baseline_model") or "")
    verifier_model = str(
        pipeline_args.get("comparison_model")
        or verifier_variant.get("model")
        or verifier_args.get("model")
        or ""
    )
    run_id = str(pipeline_metadata.get("run_id") or parent.name)
    output_dir = str(parent)

    return {
        "run_id": run_id,
        "metrics_path": str(metrics_path),
        "output_dir": output_dir,
        "worker_variant_id": worker_variant_id,
        "verifier_variant_id": verifier_variant_id,
        "worker_model": worker_model,
        "verifier_model": verifier_model,
        "verifier_backend": str(verifier_variant.get("backend") or ""),
        "verifier_backend_version": str(verifier_variant.get("backend_version") or ""),
        "verifier_dtype": str(verifier_variant.get("dtype") or verifier_args.get("dtype") or ""),
        "verifier_quantization": str(
            verifier_variant.get("quantization")
            or verifier_args.get("quantization")
            or ""
        ),
        "verifier_gpu": str(verifier_variant.get("gpu") or verifier_args.get("gpu") or ""),
    }


def mark_model_role(context: Dict[str, str], base_runs: Sequence[str],
                    base_models: Sequence[str]) -> str:
    haystack = " ".join(
        str(context.get(key, ""))
        for key in [
            "run_id",
            "output_dir",
            "worker_variant_id",
            "verifier_variant_id",
            "worker_model",
            "verifier_model",
        ]
    ).lower()
    for selector in base_runs:
        if selector.lower() in haystack:
            return "base"
    for selector in base_models:
        if model_selector_matches(selector, str(context.get("verifier_model", ""))):
            return "base"
        if model_selector_matches(selector, str(context.get("verifier_variant_id", ""))):
            return "base"
    worker_model = context.get("worker_model")
    verifier_model = context.get("verifier_model")
    if worker_model and verifier_model and worker_model == verifier_model:
        return "base"
    return "other"


def model_selector_matches(selector: str, value: str) -> bool:
    selector_l = selector.strip().lower().rstrip("/")
    value_l = value.strip().lower().rstrip("/")
    if not selector_l or not value_l:
        return False
    if selector_l == value_l:
        return True
    selector_name = Path(selector_l).name
    value_name = Path(value_l).name
    return bool(selector_name and selector_name == value_name)


def missing_selected(row: Dict[str, str]) -> bool:
    return (
        not is_finite(row.get("worker_selected_logprob"))
        or not is_finite(row.get("verifier_selected_logprob"))
        or not is_finite(row.get("abs_logprob_diff"))
    )


def summarize_token_rows(rows: Sequence[Dict[str, str]], label: str) -> Dict[str, Any]:
    abs_values = [safe_float(row.get("abs_logprob_diff")) for row in rows]
    abs_values = [value for value in abs_values if math.isfinite(value)]
    rank_deltas = [
        safe_float(row.get("rank_delta_verifier_minus_worker"))
        for row in rows
    ]
    rank_deltas = [value for value in rank_deltas if math.isfinite(value)]
    jaccards = [safe_float(row.get("topk_jaccard")) for row in rows]
    jaccards = [value for value in jaccards if math.isfinite(value)]
    union_js = [safe_float(row.get("union_js_divergence")) for row in rows]
    union_js = [value for value in union_js if math.isfinite(value)]
    common_counts = [safe_float(row.get("common_top_count")) for row in rows]
    common_counts = [value for value in common_counts if math.isfinite(value)]
    union_counts = [safe_float(row.get("union_top_count")) for row in rows]
    union_counts = [value for value in union_counts if math.isfinite(value)]
    input_counts = [
        safe_int(row.get("input_token_count"), 0) or 0
        for row in rows
    ]
    output_counts = [
        safe_int(row.get("output_token_count"), 0) or 0
        for row in rows
    ]
    sample_ids = {str(row.get("sample_id", "")) for row in rows if row.get("sample_id")}

    summary: Dict[str, Any] = {
        "group": label,
        "sample_count": len(sample_ids),
        "depth_row_count": len(rows),
        "finite_count": len(abs_values),
        "missing_compared_count": sum(1 for row in rows if missing_selected(row)),
        "mean_abs_logprob_diff": mean(abs_values),
        "abs_logprob_diff_p50": quantile(abs_values, 0.50),
        "abs_logprob_diff_p90": quantile(abs_values, 0.90),
        "abs_logprob_diff_p95": quantile(abs_values, 0.95),
        "abs_logprob_diff_p99": quantile(abs_values, 0.99),
        "abs_logprob_diff_p999": quantile(abs_values, 0.999),
        "max_abs_logprob_diff": max(abs_values, default=float("nan")),
        "compared_rank_count": len(rank_deltas),
        "rank_delta_nonzero_rate": (
            sum(1 for value in rank_deltas if value != 0.0) / len(rank_deltas)
            if rank_deltas else float("nan")
        ),
        "compared_topk_count": len(jaccards),
        "topk_jaccard_mean": mean(jaccards),
        "topk_jaccard_p01": quantile(jaccards, 0.01),
        "topk_jaccard_p05": quantile(jaccards, 0.05),
        "topk_jaccard_min": min(jaccards, default=float("nan")),
        "union_js_p95": quantile(union_js, 0.95),
        "union_js_p99": quantile(union_js, 0.99),
        "union_js_max": max(union_js, default=float("nan")),
        "common_top_count_mean": mean(common_counts),
        "union_top_count_mean": mean(union_counts),
        "input_token_count_min": min(input_counts, default=""),
        "input_token_count_max": max(input_counts, default=""),
        "output_token_count_min": min(output_counts, default=""),
        "output_token_count_max": max(output_counts, default=""),
    }
    add_fp_columns(summary)
    return summary


def add_fp_columns(summary: Dict[str, Any]) -> None:
    for key in [
        "mean_abs_logprob_diff",
        "abs_logprob_diff_p50",
        "abs_logprob_diff_p90",
        "abs_logprob_diff_p95",
        "abs_logprob_diff_p99",
        "abs_logprob_diff_p999",
        "max_abs_logprob_diff",
        "rank_delta_nonzero_rate",
        "topk_jaccard_mean",
        "topk_jaccard_p01",
        "topk_jaccard_p05",
        "topk_jaccard_min",
        "union_js_p95",
        "union_js_p99",
        "union_js_max",
    ]:
        summary[f"{key}_fp_1e6"] = fp_1e6(summary.get(key))


def summarize_by_sample(rows: Sequence[Dict[str, str]],
                        context: Dict[str, str]) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get("sample_id", ""))].append(row)

    sample_rows = []
    for sample_id, group_rows in sorted(grouped.items()):
        summary = summarize_token_rows(group_rows, sample_id)
        first = group_rows[0]
        summary.update(context)
        summary.update({
            "sample_id": sample_id,
            "input_token_count": safe_int(first.get("input_token_count"), ""),
            "output_token_count": safe_int(first.get("output_token_count"), ""),
            "input_bucket": input_bucket(safe_int(first.get("input_token_count"), 0) or 0),
        })
        sample_rows.append(summary)
    return sample_rows


def summarize_grouped_tokens(rows: Sequence[Dict[str, str]], context: Dict[str, str],
                             group_name: str) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for row in rows:
        if group_name == "input_bucket":
            key = input_bucket(safe_int(row.get("input_token_count"), 0) or 0)
        elif group_name == "output_depth_bucket":
            key = output_depth_bucket(safe_int(row.get("depth"), 0) or 0)
        else:
            key = str(row.get(group_name, ""))
        grouped[key].append(row)

    out = []
    for key, group_rows in sorted(grouped.items()):
        summary = summarize_token_rows(group_rows, key)
        summary.update(context)
        summary[group_name] = key
        out.append(summary)
    return out


def threshold_key(metric: str, bound: str) -> str:
    return f"{metric}_{bound}"


def normalize_thresholds(payload: Dict[str, Any]) -> Dict[str, Any]:
    thresholds = {
        "source": payload.get("source", "provided"),
        "judgment_function_version": payload.get(
            "judgment_function_version",
            JUDGMENT_FUNCTION_VERSION,
        ),
        "pass": {},
        "reject": {},
    }
    for section in ["pass", "reject"]:
        raw = payload.get(section, {})
        if not isinstance(raw, dict):
            continue
        for key, value in raw.items():
            if value in {"", None}:
                continue
            thresholds[section][str(key)] = value
    return thresholds


def load_thresholds(path: Path) -> Dict[str, Any]:
    payload = read_json(path)
    if payload is None:
        raise ValueError(f"Invalid thresholds JSON: {path}")
    return normalize_thresholds(payload)


def derive_thresholds_from_base(
    base_samples: Sequence[Dict[str, Any]],
    *,
    pass_quantile: float,
    pass_multiplier: float,
    reject_multiplier: float,
    jaccard_floor_margin: float,
) -> Dict[str, Any]:
    if not base_samples:
        raise ValueError("No base samples found for threshold derivation")

    pass_thresholds: Dict[str, Any] = {}
    reject_thresholds: Dict[str, Any] = {}
    for metric in UPPER_BOUND_METRICS:
        values = [safe_float(row.get(metric)) for row in base_samples]
        values = [value for value in values if math.isfinite(value)]
        if not values:
            continue
        if metric == "missing_compared_count":
            pass_value = max(values)
            reject_value = pass_value + 1
        else:
            pass_value = quantile(values, pass_quantile) * pass_multiplier
            reject_value = pass_value * reject_multiplier
        pass_thresholds[threshold_key(metric, "max")] = pass_value
        reject_thresholds[threshold_key(metric, "max")] = reject_value

    for metric in LOWER_BOUND_METRICS:
        values = [safe_float(row.get(metric)) for row in base_samples]
        values = [value for value in values if math.isfinite(value)]
        if not values:
            continue
        low = quantile(values, 1.0 - pass_quantile)
        pass_value = max(0.0, low - jaccard_floor_margin)
        reject_value = max(0.0, pass_value / reject_multiplier)
        pass_thresholds[threshold_key(metric, "min")] = pass_value
        reject_thresholds[threshold_key(metric, "min")] = reject_value

    return {
        "source": "derived_from_base_samples",
        "judgment_function_version": JUDGMENT_FUNCTION_VERSION,
        "derivation": {
            "base_sample_count": len(base_samples),
            "pass_quantile": pass_quantile,
            "pass_multiplier": pass_multiplier,
            "reject_multiplier": reject_multiplier,
            "jaccard_floor_margin": jaccard_floor_margin,
            "note": (
                "Exploratory local thresholds. Protocol thresholds must come "
                "from ProfileState.verification_thresholds."
            ),
        },
        "pass": pass_thresholds,
        "reject": reject_thresholds,
    }


def pass_checks(row: Dict[str, Any], thresholds: Dict[str, Any]) -> List[Tuple[str, bool]]:
    checks = []
    pass_thresholds = thresholds.get("pass", {})
    for metric in UPPER_BOUND_METRICS:
        key = threshold_key(metric, "max")
        if key not in pass_thresholds:
            continue
        value = safe_float(row.get(metric))
        limit = safe_float(pass_thresholds.get(key))
        checks.append((key, math.isfinite(value) and value <= limit))
    for metric in LOWER_BOUND_METRICS:
        key = threshold_key(metric, "min")
        if key not in pass_thresholds:
            continue
        value = safe_float(row.get(metric))
        limit = safe_float(pass_thresholds.get(key))
        checks.append((key, math.isfinite(value) and value >= limit))
    return checks


def reject_checks(row: Dict[str, Any], thresholds: Dict[str, Any]) -> List[Tuple[str, bool]]:
    checks = []
    reject_thresholds = thresholds.get("reject", {})
    for metric in UPPER_BOUND_METRICS:
        key = threshold_key(metric, "max")
        if key not in reject_thresholds:
            continue
        value = safe_float(row.get(metric))
        limit = safe_float(reject_thresholds.get(key))
        checks.append((key, math.isfinite(value) and value > limit))
    for metric in LOWER_BOUND_METRICS:
        key = threshold_key(metric, "min")
        if key not in reject_thresholds:
            continue
        value = safe_float(row.get(metric))
        limit = safe_float(reject_thresholds.get(key))
        checks.append((key, math.isfinite(value) and value < limit))
    return checks


def evaluate_sample(row: Dict[str, Any], thresholds: Optional[Dict[str, Any]]) -> None:
    if not thresholds:
        row["metric_sample_verdict"] = ""
        row["threshold_breach_count"] = ""
        row["reject_breach_count"] = ""
        return

    p_checks = pass_checks(row, thresholds)
    r_checks = reject_checks(row, thresholds)
    pass_breaches = [name for name, ok in p_checks if not ok]
    reject_breaches = [name for name, breached in r_checks if breached]
    if p_checks and not pass_breaches:
        verdict = "PASS"
    elif reject_breaches:
        verdict = "REJECT"
    else:
        verdict = "INCONCLUSIVE"
    row["metric_sample_verdict"] = verdict
    row["threshold_breach_count"] = len(pass_breaches)
    row["reject_breach_count"] = len(reject_breaches)
    row["threshold_breaches"] = ";".join(pass_breaches)
    row["reject_breaches"] = ";".join(reject_breaches)


def add_verdict_counts(summary: Dict[str, Any], samples: Sequence[Dict[str, Any]]) -> None:
    counts = defaultdict(int)
    breach_total = 0
    reject_breach_total = 0
    for row in samples:
        counts[str(row.get("metric_sample_verdict", ""))] += 1
        breach_total += safe_int(row.get("threshold_breach_count"), 0) or 0
        reject_breach_total += safe_int(row.get("reject_breach_count"), 0) or 0
    total = sum(value for key, value in counts.items() if key)
    for verdict in ["PASS", "REJECT", "INCONCLUSIVE"]:
        summary[f"sample_{verdict.lower()}_count"] = counts.get(verdict, 0)
        summary[f"sample_{verdict.lower()}_rate"] = (
            counts.get(verdict, 0) / total if total else ""
        )
    summary["threshold_breach_count"] = breach_total if total else ""
    summary["reject_breach_count"] = reject_breach_total if total else ""


def process_metrics_file(metrics_path: Path, args: argparse.Namespace) -> Dict[str, Any]:
    rows = read_csv_rows(metrics_path)
    context = run_context(metrics_path)
    context["model_role"] = mark_model_role(context, args.base_run, args.base_model)
    log(f"Loaded {len(rows)} depth rows from {metrics_path}")

    run_summary = summarize_token_rows(rows, context["run_id"])
    run_summary.update(context)
    sample_rows = summarize_by_sample(rows, context)
    by_input = summarize_grouped_tokens(rows, context, "input_bucket")
    by_depth = summarize_grouped_tokens(rows, context, "output_depth_bucket")

    top_rows = []
    for row in sorted(
        rows,
        key=lambda item: safe_float(item.get("abs_logprob_diff"), -1.0),
        reverse=True,
    )[: args.top_outliers_per_run]:
        top = dict(context)
        top.update({
            "sample_id": row.get("sample_id", ""),
            "depth": row.get("depth", ""),
            "input_token_count": row.get("input_token_count", ""),
            "output_token_count": row.get("output_token_count", ""),
            "target_token_id": row.get("target_token_id", ""),
            "target_decoded_token": row.get("target_decoded_token", ""),
            "worker_selected_logprob": row.get("worker_selected_logprob", ""),
            "verifier_selected_logprob": row.get("verifier_selected_logprob", ""),
            "abs_logprob_diff": row.get("abs_logprob_diff", ""),
            "rank_delta_verifier_minus_worker": row.get(
                "rank_delta_verifier_minus_worker",
                "",
            ),
            "topk_jaccard": row.get("topk_jaccard", ""),
            "union_js_divergence": row.get("union_js_divergence", ""),
        })
        top["abs_logprob_diff_fp_1e6"] = fp_1e6(top["abs_logprob_diff"])
        top_rows.append(top)

    return {
        "context": context,
        "run_summary": run_summary,
        "sample_rows": sample_rows,
        "by_input": by_input,
        "by_depth": by_depth,
        "top_outliers": top_rows,
    }


def summarize_sample_rows(rows: Sequence[Dict[str, Any]], label: str) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "group": label,
        "run_count": len({row.get("run_id") for row in rows}),
        "sample_count": len(rows),
        "depth_row_count": sum(safe_int(row.get("depth_row_count"), 0) or 0 for row in rows),
        "finite_count": sum(safe_int(row.get("finite_count"), 0) or 0 for row in rows),
        "missing_compared_count": sum(
            safe_int(row.get("missing_compared_count"), 0) or 0
            for row in rows
        ),
    }
    for metric in [
        "mean_abs_logprob_diff",
        "abs_logprob_diff_p95",
        "abs_logprob_diff_p99",
        "rank_delta_nonzero_rate",
        "topk_jaccard_mean",
        "union_js_p99",
    ]:
        values = [safe_float(row.get(metric)) for row in rows]
        values = [value for value in values if math.isfinite(value)]
        summary[f"{metric}_sample_mean"] = mean(values)
        summary[f"{metric}_sample_p50"] = quantile(values, 0.50)
        summary[f"{metric}_sample_p90"] = quantile(values, 0.90)
        summary[f"{metric}_sample_p99"] = quantile(values, 0.99)
    add_fp_columns(summary)
    add_verdict_counts(summary, rows)
    return summary


def build_model_summary(sample_rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = defaultdict(list)
    for row in sample_rows:
        key = (
            str(row.get("model_role", "")),
            str(row.get("verifier_variant_id", "")),
            str(row.get("verifier_model", "")),
        )
        grouped[key].append(row)

    out = []
    for (role, variant, model), rows in sorted(grouped.items()):
        label = variant or model or role
        summary = summarize_sample_rows(rows, label)
        summary.update({
            "model_role": role,
            "verifier_variant_id": variant,
            "verifier_model": model,
        })
        out.append(summary)
    return out


def markdown_number(value: Any) -> str:
    number = safe_float(value)
    if not math.isfinite(number):
        return ""
    return f"{number:.6g}"


def write_markdown(path: Path, run_rows: Sequence[Dict[str, Any]],
                   model_rows: Sequence[Dict[str, Any]],
                   thresholds: Optional[Dict[str, Any]]) -> None:
    lines = [
        "# vLLM worker verify metric analysis",
        "",
        f"- judgment_function_version: `{JUDGMENT_FUNCTION_VERSION}`",
        "- token_scope: `ALL_GENERATED_OUTPUT_TOKENS`",
        "- metrics: abs logprob diff, rank delta, top-k Jaccard, union JS",
        "",
    ]
    if thresholds:
        lines.extend([
            "## thresholds",
            "",
            f"- source: `{thresholds.get('source', '')}`",
            f"- pass keys: `{', '.join(sorted(thresholds.get('pass', {})))}`",
            f"- reject keys: `{', '.join(sorted(thresholds.get('reject', {})))}`",
            "",
        ])
    else:
        lines.extend([
            "## thresholds",
            "",
            "No thresholds were supplied or derived, so verdict columns are left blank.",
            "",
        ])

    lines.extend([
        "## by run",
        "",
        "| role | run | worker | verifier | samples | depth rows | mean_abs | p95 | p99 | rank_delta_rate | jaccard_mean | union_js_p99 | pass/reject/inconclusive |",
        "|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for row in run_rows:
        verdict = "{}/{}/{}".format(
            row.get("sample_pass_count", ""),
            row.get("sample_reject_count", ""),
            row.get("sample_inconclusive_count", ""),
        )
        lines.append(
            "| {role} | {run} | {worker} | {verifier} | {samples} | {depth} | {mean} | {p95} | {p99} | {rank} | {jac} | {js} | {verdict} |".format(
                role=row.get("model_role", ""),
                run=row.get("run_id", ""),
                worker=row.get("worker_variant_id", ""),
                verifier=row.get("verifier_variant_id", ""),
                samples=row.get("sample_count", ""),
                depth=row.get("depth_row_count", ""),
                mean=markdown_number(row.get("mean_abs_logprob_diff")),
                p95=markdown_number(row.get("abs_logprob_diff_p95")),
                p99=markdown_number(row.get("abs_logprob_diff_p99")),
                rank=markdown_number(row.get("rank_delta_nonzero_rate")),
                jac=markdown_number(row.get("topk_jaccard_mean")),
                js=markdown_number(row.get("union_js_p99")),
                verdict=verdict,
            )
        )

    lines.extend([
        "",
        "## by verifier model",
        "",
        "| role | verifier | runs | samples | mean_abs sample mean | p99 sample mean | rank_delta sample mean | jaccard sample mean | pass/reject/inconclusive |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for row in model_rows:
        verdict = "{}/{}/{}".format(
            row.get("sample_pass_count", ""),
            row.get("sample_reject_count", ""),
            row.get("sample_inconclusive_count", ""),
        )
        lines.append(
            "| {role} | {verifier} | {runs} | {samples} | {mean} | {p99} | {rank} | {jac} | {verdict} |".format(
                role=row.get("model_role", ""),
                verifier=row.get("verifier_variant_id") or row.get("verifier_model", ""),
                runs=row.get("run_count", ""),
                samples=row.get("sample_count", ""),
                mean=markdown_number(row.get("mean_abs_logprob_diff_sample_mean")),
                p99=markdown_number(row.get("abs_logprob_diff_p99_sample_mean")),
                rank=markdown_number(row.get("rank_delta_nonzero_rate_sample_mean")),
                jac=markdown_number(row.get("topk_jaccard_mean_sample_mean")),
                verdict=verdict,
            )
        )
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze worker_vs_verifier_depth_metrics.csv outputs using "
            "PREFILL_GENERATED_TOKEN_METRICS_V1-style aggregate metrics."
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
    parser.add_argument("--output-dir", default="analysis")
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
        help="Substring marking a verifier model/variant as base. Repeat as needed.",
    )
    parser.add_argument(
        "--thresholds",
        default=None,
        help="Optional JSON file containing pass/reject thresholds.",
    )
    parser.add_argument(
        "--derive-thresholds-from-base",
        action="store_true",
        help="Derive exploratory thresholds from rows marked as base.",
    )
    parser.add_argument("--base-pass-quantile", type=float, default=0.99)
    parser.add_argument("--base-pass-multiplier", type=float, default=1.25)
    parser.add_argument("--reject-multiplier", type=float, default=3.0)
    parser.add_argument("--jaccard-floor-margin", type=float, default=0.02)
    parser.add_argument("--top-outliers-per-run", type=int, default=100)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)

    input_paths = args.input or ["results/vllm_worker_verify_runs"]
    try:
        metrics_files = resolve_inputs(input_paths)
    except FileNotFoundError as exc:
        parser.error(str(exc))
    if not metrics_files:
        parser.error("No worker_vs_verifier_depth_metrics.csv files found")

    processed = [process_metrics_file(path, args) for path in metrics_files]
    run_rows = [item["run_summary"] for item in processed]
    sample_rows = [row for item in processed for row in item["sample_rows"]]
    by_input_rows = [row for item in processed for row in item["by_input"]]
    by_depth_rows = [row for item in processed for row in item["by_depth"]]
    top_outliers = [row for item in processed for row in item["top_outliers"]]

    thresholds: Optional[Dict[str, Any]] = None
    if args.thresholds:
        thresholds = load_thresholds(Path(args.thresholds))
    elif args.derive_thresholds_from_base:
        base_samples = [row for row in sample_rows if row.get("model_role") == "base"]
        thresholds = derive_thresholds_from_base(
            base_samples,
            pass_quantile=args.base_pass_quantile,
            pass_multiplier=args.base_pass_multiplier,
            reject_multiplier=args.reject_multiplier,
            jaccard_floor_margin=args.jaccard_floor_margin,
        )

    for row in sample_rows:
        evaluate_sample(row, thresholds)

    samples_by_run: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in sample_rows:
        samples_by_run[str(row.get("metrics_path", ""))].append(row)
    for row in run_rows:
        add_verdict_counts(row, samples_by_run.get(str(row.get("metrics_path", "")), []))

    model_rows = build_model_summary(sample_rows)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    write_csv(output_dir / "run_summary.csv", run_rows, collect_fields(run_rows, [
        "model_role",
        "run_id",
        "worker_variant_id",
        "verifier_variant_id",
        "worker_model",
        "verifier_model",
        "sample_count",
        "depth_row_count",
        "finite_count",
        "missing_compared_count",
        "mean_abs_logprob_diff",
        "abs_logprob_diff_p95",
        "abs_logprob_diff_p99",
        "rank_delta_nonzero_rate",
        "topk_jaccard_mean",
        "union_js_p99",
        "sample_pass_count",
        "sample_reject_count",
        "sample_inconclusive_count",
        "threshold_breach_count",
    ]))
    write_csv(output_dir / "model_summary.csv", model_rows, collect_fields(model_rows, [
        "model_role",
        "verifier_variant_id",
        "verifier_model",
        "run_count",
        "sample_count",
        "depth_row_count",
        "mean_abs_logprob_diff_sample_mean",
        "abs_logprob_diff_p99_sample_mean",
        "rank_delta_nonzero_rate_sample_mean",
        "topk_jaccard_mean_sample_mean",
        "union_js_p99_sample_mean",
        "sample_pass_count",
        "sample_reject_count",
        "sample_inconclusive_count",
    ]))
    write_csv(output_dir / "sample_summary.csv", sample_rows, collect_fields(sample_rows, [
        "model_role",
        "run_id",
        "sample_id",
        "worker_variant_id",
        "verifier_variant_id",
        "input_token_count",
        "output_token_count",
        "finite_count",
        "missing_compared_count",
        "mean_abs_logprob_diff",
        "mean_abs_logprob_diff_fp_1e6",
        "abs_logprob_diff_p95",
        "abs_logprob_diff_p95_fp_1e6",
        "abs_logprob_diff_p99",
        "abs_logprob_diff_p99_fp_1e6",
        "rank_delta_nonzero_rate",
        "rank_delta_nonzero_rate_fp_1e6",
        "topk_jaccard_mean",
        "topk_jaccard_mean_fp_1e6",
        "union_js_p99",
        "union_js_p99_fp_1e6",
        "compared_topk_count",
        "compared_rank_count",
        "metric_sample_verdict",
        "threshold_breach_count",
        "reject_breach_count",
    ]))
    write_csv(output_dir / "by_input_bucket.csv", by_input_rows, collect_fields(by_input_rows, [
        "model_role",
        "run_id",
        "input_bucket",
        "worker_variant_id",
        "verifier_variant_id",
        "sample_count",
        "depth_row_count",
        "mean_abs_logprob_diff",
        "abs_logprob_diff_p95",
        "abs_logprob_diff_p99",
        "rank_delta_nonzero_rate",
        "topk_jaccard_mean",
        "union_js_p99",
    ]))
    write_csv(output_dir / "by_output_depth_bucket.csv", by_depth_rows, collect_fields(by_depth_rows, [
        "model_role",
        "run_id",
        "output_depth_bucket",
        "worker_variant_id",
        "verifier_variant_id",
        "sample_count",
        "depth_row_count",
        "mean_abs_logprob_diff",
        "abs_logprob_diff_p95",
        "abs_logprob_diff_p99",
        "rank_delta_nonzero_rate",
        "topk_jaccard_mean",
        "union_js_p99",
    ]))
    write_csv(output_dir / "top_outlier_tokens.csv", top_outliers, collect_fields(top_outliers, [
        "model_role",
        "run_id",
        "worker_variant_id",
        "verifier_variant_id",
        "sample_id",
        "depth",
        "target_token_id",
        "target_decoded_token",
        "abs_logprob_diff",
        "abs_logprob_diff_fp_1e6",
        "rank_delta_verifier_minus_worker",
        "topk_jaccard",
        "union_js_divergence",
    ]))
    write_json(output_dir / "thresholds.json", thresholds or {
        "source": "none",
        "judgment_function_version": JUDGMENT_FUNCTION_VERSION,
        "pass": {},
        "reject": {},
    })
    write_json(output_dir / "analysis_metadata.json", {
        "metadata": runtime_metadata(sys.argv),
        "judgment_function_version": JUDGMENT_FUNCTION_VERSION,
        "token_scope": "ALL_GENERATED_OUTPUT_TOKENS",
        "input_metrics_files": [str(path) for path in metrics_files],
        "output_files": [
            "run_summary.csv",
            "model_summary.csv",
            "sample_summary.csv",
            "by_input_bucket.csv",
            "by_output_depth_bucket.csv",
            "top_outlier_tokens.csv",
            "thresholds.json",
            "summary.md",
        ],
        "thresholds_source": (thresholds or {}).get("source", "none"),
    })
    write_markdown(output_dir / "summary.md", run_rows, model_rows, thresholds)

    log(f"Wrote {output_dir / 'summary.md'}")
    log(f"Wrote {output_dir / 'run_summary.csv'}")
    log(f"Wrote {output_dir / 'model_summary.csv'}")
    log(f"Wrote {output_dir / 'sample_summary.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

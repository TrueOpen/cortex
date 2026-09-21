#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import math
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from pipeline_common import quantile, safe_float


QUANTILES = [
    ("p50", 0.50),
    ("p90", 0.90),
    ("p95", 0.95),
    ("p99", 0.99),
    ("p999", 0.999),
]


def read_csv(path: Path) -> List[dict]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: Sequence[dict], fields: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def metrics_path(path: Path) -> Path:
    if path.is_dir():
        return path / "worker_vs_verifier_depth_metrics.csv"
    return path


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


def summarize_rows(rows: Sequence[dict], label: str) -> dict:
    values = [safe_float(row.get("abs_logprob_diff")) for row in rows]
    values = [value for value in values if math.isfinite(value)]
    out = {
        "group": label,
        "count": len(rows),
        "finite_count": len(values),
        "missing_selected_count": sum(
            1 for row in rows
            if row.get("verifier_selected_logprob") in {"", None}
        ),
        "mean_abs_logprob_diff": (
            sum(values) / len(values) if values else float("nan")
        ),
        "max_abs_logprob_diff": max(values, default=float("nan")),
    }
    for name, q in QUANTILES:
        out[f"abs_logprob_diff_{name}"] = quantile(values, q)
    rank_deltas = [
        abs(safe_float(row.get("rank_delta_verifier_minus_worker")))
        for row in rows
    ]
    rank_deltas = [value for value in rank_deltas if math.isfinite(value)]
    out["rank_delta_nonzero_rate"] = (
        sum(1 for value in rank_deltas if value != 0.0) / len(rank_deltas)
        if rank_deltas else float("nan")
    )
    jaccards = [safe_float(row.get("topk_jaccard")) for row in rows]
    jaccards = [value for value in jaccards if math.isfinite(value)]
    out["topk_jaccard_p01"] = quantile(jaccards, 0.01)
    out["topk_jaccard_p05"] = quantile(jaccards, 0.05)
    out["topk_jaccard_mean"] = sum(jaccards) / len(jaccards) if jaccards else float("nan")
    union_js = [safe_float(row.get("union_js_divergence")) for row in rows]
    union_js = [value for value in union_js if math.isfinite(value)]
    out["union_js_p95"] = quantile(union_js, 0.95)
    out["union_js_p99"] = quantile(union_js, 0.99)
    out["union_js_max"] = max(union_js, default=float("nan"))
    return out


def grouped_summary(rows: Sequence[dict], key_name: str) -> List[dict]:
    grouped: Dict[str, List[dict]] = defaultdict(list)
    for row in rows:
        if key_name == "input_bucket":
            key = input_bucket(int(row.get("input_token_count", 0)))
        elif key_name == "output_depth_bucket":
            key = output_depth_bucket(int(row.get("depth", 0)))
        elif key_name == "output_depth":
            key = f"{int(row.get('depth', 0)):03d}"
        elif key_name == "sample_id":
            key = str(row.get("sample_id"))
        else:
            key = str(row.get(key_name, ""))
        grouped[key].append(row)
    return [
        summarize_rows(group_rows, key)
        for key, group_rows in sorted(grouped.items())
    ]


def write_markdown(path: Path, overall: dict, by_input: Sequence[dict],
                   by_depth: Sequence[dict],
                   by_exact_depth: Sequence[dict]) -> None:
    lines = [
        "# worker verify distribution",
        "",
        "## overall",
        "",
        "| count | mean | p50 | p90 | p95 | p99 | p999 | max | rank_delta_rate |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        "| {count} | {mean:.8g} | {p50:.8g} | {p90:.8g} | {p95:.8g} | {p99:.8g} | {p999:.8g} | {maxv:.8g} | {rank:.8g} |".format(
            count=overall.get("count"),
            mean=safe_float(overall.get("mean_abs_logprob_diff")),
            p50=safe_float(overall.get("abs_logprob_diff_p50")),
            p90=safe_float(overall.get("abs_logprob_diff_p90")),
            p95=safe_float(overall.get("abs_logprob_diff_p95")),
            p99=safe_float(overall.get("abs_logprob_diff_p99")),
            p999=safe_float(overall.get("abs_logprob_diff_p999")),
            maxv=safe_float(overall.get("max_abs_logprob_diff")),
            rank=safe_float(overall.get("rank_delta_nonzero_rate")),
        ),
        "",
        "## by input length",
        "",
        "| bucket | count | p90 | p95 | p99 | max | jaccard p05 | union_js p99 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in by_input:
        lines.append(
            "| {group} | {count} | {p90:.8g} | {p95:.8g} | {p99:.8g} | {maxv:.8g} | {jac:.8g} | {js:.8g} |".format(
                group=row.get("group"),
                count=row.get("count"),
                p90=safe_float(row.get("abs_logprob_diff_p90")),
                p95=safe_float(row.get("abs_logprob_diff_p95")),
                p99=safe_float(row.get("abs_logprob_diff_p99")),
                maxv=safe_float(row.get("max_abs_logprob_diff")),
                jac=safe_float(row.get("topk_jaccard_p05")),
                js=safe_float(row.get("union_js_p99")),
            )
        )
    lines.extend([
        "",
        "## by output depth",
        "",
        "| bucket | count | p90 | p95 | p99 | max | jaccard p05 | union_js p99 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for row in by_depth:
        lines.append(
            "| {group} | {count} | {p90:.8g} | {p95:.8g} | {p99:.8g} | {maxv:.8g} | {jac:.8g} | {js:.8g} |".format(
                group=row.get("group"),
                count=row.get("count"),
                p90=safe_float(row.get("abs_logprob_diff_p90")),
                p95=safe_float(row.get("abs_logprob_diff_p95")),
                p99=safe_float(row.get("abs_logprob_diff_p99")),
                maxv=safe_float(row.get("max_abs_logprob_diff")),
                jac=safe_float(row.get("topk_jaccard_p05")),
                js=safe_float(row.get("union_js_p99")),
            )
        )
    lines.extend([
        "",
        "## by exact output depth",
        "",
        "| depth | count | mean | p50 | p90 | p95 | p99 | max | rank_delta_rate | jaccard p05 | union_js p99 |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for row in by_exact_depth:
        lines.append(
            "| {group} | {count} | {mean:.8g} | {p50:.8g} | {p90:.8g} | {p95:.8g} | {p99:.8g} | {maxv:.8g} | {rank:.8g} | {jac:.8g} | {js:.8g} |".format(
                group=row.get("group"),
                count=row.get("count"),
                mean=safe_float(row.get("mean_abs_logprob_diff")),
                p50=safe_float(row.get("abs_logprob_diff_p50")),
                p90=safe_float(row.get("abs_logprob_diff_p90")),
                p95=safe_float(row.get("abs_logprob_diff_p95")),
                p99=safe_float(row.get("abs_logprob_diff_p99")),
                maxv=safe_float(row.get("max_abs_logprob_diff")),
                rank=safe_float(row.get("rank_delta_nonzero_rate")),
                jac=safe_float(row.get("topk_jaccard_p05")),
                js=safe_float(row.get("union_js_p99")),
            )
        )
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Summarize worker-vs-verifier abs logprob diff distributions."
    )
    parser.add_argument("--metrics", required=True,
                        help="worker_vs_verifier_depth_metrics.csv or its parent dir.")
    parser.add_argument("--output-dir", default=None)
    args = parser.parse_args(argv)

    path = metrics_path(Path(args.metrics))
    rows = read_csv(path)
    output_dir = Path(args.output_dir) if args.output_dir else path.parent / "distribution"
    output_dir.mkdir(parents=True, exist_ok=True)

    overall = summarize_rows(rows, "overall")
    by_input = grouped_summary(rows, "input_bucket")
    by_depth = grouped_summary(rows, "output_depth_bucket")
    by_exact_depth = grouped_summary(rows, "output_depth")
    by_sample = grouped_summary(rows, "sample_id")

    fields = sorted(set(overall) | {field for row in by_input + by_depth + by_exact_depth + by_sample for field in row})
    write_csv(output_dir / "overall.csv", [overall], fields)
    write_csv(output_dir / "by_input_bucket.csv", by_input, fields)
    write_csv(output_dir / "by_output_depth_bucket.csv", by_depth, fields)
    write_csv(output_dir / "by_output_depth.csv", by_exact_depth, fields)
    write_csv(output_dir / "by_sample.csv", by_sample, fields)
    write_markdown(output_dir / "summary.md", overall, by_input, by_depth, by_exact_depth)
    print(f"Wrote {output_dir / 'summary.md'}")
    print(f"Wrote {output_dir / 'overall.csv'}")
    print(f"Wrote {output_dir / 'by_input_bucket.csv'}")
    print(f"Wrote {output_dir / 'by_output_depth_bucket.csv'}")
    print(f"Wrote {output_dir / 'by_output_depth.csv'}")
    print(f"Wrote {output_dir / 'by_sample.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

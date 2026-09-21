#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import math
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from pipeline_common import (
    VariantInfo,
    build_llm_kwargs,
    build_sampling_params,
    dataclass_to_dict,
    logprob_for_token,
    make_tokens_prompt,
    normalize_logprob_dict,
    probability_metrics,
    rank_for_token,
    read_jsonl,
    runtime_metadata,
    safe_float,
    sorted_token_ids,
    tokenizer_hash,
    tokenizer_name,
    write_json,
)


def log(message: str) -> None:
    print(message, flush=True)


def vllm_version() -> str:
    try:
        import vllm

        return vllm.__version__
    except Exception:
        return ""


def make_variant(args: argparse.Namespace, tokenizer: object) -> VariantInfo:
    tok_hash = tokenizer_hash(tokenizer)
    return VariantInfo(
        variant_id=args.variant_id,
        model=args.model,
        tokenizer_hash=tok_hash,
        tokenizer_name=tokenizer_name(tokenizer),
        quantization=args.quantization,
        gpu=args.gpu,
        backend="vllm",
        backend_version=vllm_version(),
        dtype=args.dtype,
        extra={
            "cuda_visible_devices": os.environ.get("CUDA_VISIBLE_DEVICES"),
            "tensor_parallel_size": args.tensor_parallel_size,
            "gpu_memory_utilization": args.gpu_memory_utilization,
            "max_model_len": args.max_model_len,
            "max_num_seqs": args.max_num_seqs,
            "max_num_batched_tokens": args.max_num_batched_tokens,
            "max_logprobs": args.max_logprobs,
        },
    )


def top_map(items: Sequence[dict]) -> Dict[str, Dict[str, object]]:
    return {
        str(int(item["token_id"])): {
            "logprob": item.get("logprob"),
            "rank": item.get("rank"),
            "decoded_token": item.get("decoded_token"),
        }
        for item in items
    }


def vector_metrics(worker_top: Dict[str, Dict[str, object]],
                   verifier_top: Dict[str, Dict[str, object]],
                   missing_logprob: float) -> dict:
    worker_tokens = set(worker_top)
    verifier_tokens = set(verifier_top)
    common = sorted_token_ids(worker_tokens & verifier_tokens)
    union = sorted_token_ids(worker_tokens | verifier_tokens)
    common_prob = probability_metrics(worker_top, verifier_top, common, missing_logprob)
    union_prob = probability_metrics(worker_top, verifier_top, union, missing_logprob)
    return {
        "common_top_count": len(common),
        "union_top_count": len(union),
        "topk_jaccard": len(common) / len(union) if union else float("nan"),
        "missing_from_verifier_count": len(worker_tokens - verifier_tokens),
        "extra_in_verifier_count": len(verifier_tokens - worker_tokens),
        "common_js_divergence": common_prob["js_divergence"],
        "union_js_divergence": union_prob["js_divergence"],
        "common_prob_cosine": common_prob["prob_cosine"],
        "union_prob_cosine": union_prob["prob_cosine"],
    }


def compare_depth(worker_depth: dict,
                  verifier_logprobs: Dict[str, Dict[str, object]],
                  missing_logprob: float) -> dict:
    target_token_id = int(worker_depth["target_token_id"])
    worker_logprob = worker_depth.get("selected_logprob")
    verifier_logprob = logprob_for_token(verifier_logprobs, target_token_id)
    worker_rank = worker_depth.get("selected_rank")
    verifier_rank = rank_for_token(verifier_logprobs, target_token_id)
    worker_top = top_map(worker_depth.get("top_logprobs", []))
    verifier_top = verifier_logprobs
    lp_diff = (
        safe_float(verifier_logprob) - safe_float(worker_logprob)
        if worker_logprob is not None and verifier_logprob is not None
        else float("nan")
    )
    if worker_rank is not None and verifier_rank is not None:
        rank_delta = int(verifier_rank) - int(worker_rank)
    else:
        rank_delta = ""
    return {
        "depth": worker_depth.get("depth"),
        "target_token_id": target_token_id,
        "target_decoded_token": worker_depth.get("target_decoded_token"),
        "worker_selected_logprob": worker_logprob,
        "verifier_selected_logprob": verifier_logprob,
        "logprob_diff_verifier_minus_worker": lp_diff,
        "abs_logprob_diff": abs(lp_diff) if math.isfinite(lp_diff) else float("nan"),
        "worker_selected_rank": worker_rank,
        "verifier_selected_rank": verifier_rank,
        "rank_delta_verifier_minus_worker": rank_delta,
        **vector_metrics(worker_top, verifier_top, missing_logprob),
    }


def write_csv(path: Path, rows: Sequence[dict], fields: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def write_summary(path: Path, rows: Sequence[dict]) -> None:
    finite_abs = [safe_float(row.get("abs_logprob_diff")) for row in rows]
    finite_abs = [value for value in finite_abs if math.isfinite(value)]
    missing_selected = sum(
        1 for row in rows
        if row.get("verifier_selected_logprob") in {"", None}
    )
    max_abs = max(finite_abs, default=float("nan"))
    mean_abs = sum(finite_abs) / len(finite_abs) if finite_abs else float("nan")
    sorted_rows = sorted(
        rows,
        key=lambda row: safe_float(row.get("abs_logprob_diff"), -1.0),
        reverse=True,
    )
    lines = [
        "# vLLM worker evidence verification",
        "",
        f"- depth rows: {len(rows)}",
        f"- missing verifier selected logprob: {missing_selected}",
        f"- max abs logprob diff: {max_abs:.8g}",
        f"- mean abs logprob diff: {mean_abs:.8g}",
        "",
        "| sample | depth | token | worker_lp | verifier_lp | abs_diff | worker/verifier_rank | jaccard | union_js |",
        "|---|---:|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in sorted_rows[:50]:
        lines.append(
            "| {sample} | {depth} | `{token}` | {worker:.8g} | {verifier:.8g} | {diff:.8g} | "
            "{wrank}/{vrank} | {jaccard:.8g} | {js:.8g} |".format(
                sample=row.get("sample_id"),
                depth=row.get("depth"),
                token=str(row.get("target_decoded_token", "")).replace("\n", "\\n"),
                worker=safe_float(row.get("worker_selected_logprob")),
                verifier=safe_float(row.get("verifier_selected_logprob")),
                diff=safe_float(row.get("abs_logprob_diff")),
                wrank=row.get("worker_selected_rank"),
                vrank=row.get("verifier_selected_rank"),
                jaccard=safe_float(row.get("topk_jaccard")),
                js=safe_float(row.get("union_js_divergence")),
            )
        )
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Recompute vLLM prompt logprobs for worker evidence and compare per output token."
    )
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--output-dir", default="results/vllm_worker_verify")
    parser.add_argument("--model", required=True)
    parser.add_argument("--variant-id", required=True)
    parser.add_argument("--gpu", default="")
    parser.add_argument("--quantization", default="bf16")
    parser.add_argument("--dtype", default="auto")
    parser.add_argument("--trust-remote-code", action="store_true")
    parser.add_argument("--tensor-parallel-size", type=int, default=1)
    parser.add_argument("--gpu-memory-utilization", type=float, default=None)
    parser.add_argument("--max-model-len", type=int, default=None)
    parser.add_argument("--max-num-seqs", type=int, default=None)
    parser.add_argument("--max-num-batched-tokens", type=int, default=None)
    parser.add_argument("--max-logprobs", type=int, default=None)
    parser.add_argument("--prompt-logprobs", type=int, default=64)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--top-p", type=float, default=1.0)
    parser.add_argument("--top-k", type=int, default=0)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--missing-logprob", type=float, default=-100.0)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--max-total-tokens", type=int, default=0,
                        help="Skip evidence rows whose input+output token count exceeds this value.")
    args = parser.parse_args(argv)

    from transformers import AutoTokenizer
    from vllm import LLM

    tokenizer = AutoTokenizer.from_pretrained(
        args.model,
        trust_remote_code=args.trust_remote_code,
    )
    variant = make_variant(args, tokenizer)
    llm_kwargs = build_llm_kwargs(args)
    log(f"Loading verifier vLLM with kwargs: {llm_kwargs}")
    llm = LLM(**llm_kwargs)
    sampling_params = build_sampling_params(
        args,
        max_tokens=1,
        logprobs=None,
        prompt_logprobs=args.prompt_logprobs,
        detokenize=False,
    )

    evidence_rows = []
    skipped_too_long = 0
    for index, row in enumerate(read_jsonl(Path(args.evidence)), start=1):
        if args.limit and index > args.limit:
            break
        total_tokens = len(row.get("input_ids", [])) + len(row.get("output_ids", []))
        if args.max_total_tokens and total_tokens > args.max_total_tokens:
            skipped_too_long += 1
            continue
        evidence_rows.append(row)
    log(
        f"Loaded evidence rows: {len(evidence_rows)} "
        f"(skipped_too_long={skipped_too_long})"
    )

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    metric_rows: List[dict] = []
    total_start = time.time()
    for batch_start in range(0, len(evidence_rows), args.batch_size):
        batch = evidence_rows[batch_start:batch_start + args.batch_size]
        prompts = [
            make_tokens_prompt(row["input_ids"] + row["output_ids"])
            for row in batch
        ]
        lengths = [len(row["input_ids"]) + len(row["output_ids"]) for row in batch]
        log(
            f"Verifier prompt_logprobs batch {batch_start // args.batch_size + 1}, "
            f"size={len(batch)}, max_tokens={max(lengths)}, total_tokens={sum(lengths)}"
        )
        outputs = llm.generate(prompts, sampling_params)
        if len(outputs) != len(batch):
            raise RuntimeError(f"vLLM returned {len(outputs)} outputs for {len(batch)} prompts")
        for evidence, request_output in zip(batch, outputs):
            input_len = len(evidence["input_ids"])
            prompt_logprobs = list(getattr(request_output, "prompt_logprobs", []) or [])
            worker_trace = evidence.get("worker_trace", [])
            for worker_depth in worker_trace:
                depth = int(worker_depth["depth"])
                prompt_pos = input_len + depth
                verifier_logprobs = (
                    normalize_logprob_dict(prompt_logprobs[prompt_pos])
                    if prompt_pos < len(prompt_logprobs) else {}
                )
                row = compare_depth(worker_depth, verifier_logprobs, args.missing_logprob)
                row.update({
                    "sample_id": evidence.get("sample_id"),
                    "input_token_count": input_len,
                    "output_token_count": len(evidence.get("output_ids", [])),
                    "worker_trace_mode": evidence.get("worker_trace_mode"),
                    "verifier_trace_mode": "vllm_prompt_logprobs_full_prefill",
                })
                metric_rows.append(row)

    fields = [
        "sample_id",
        "depth",
        "input_token_count",
        "output_token_count",
        "target_token_id",
        "target_decoded_token",
        "worker_trace_mode",
        "verifier_trace_mode",
        "worker_selected_logprob",
        "verifier_selected_logprob",
        "logprob_diff_verifier_minus_worker",
        "abs_logprob_diff",
        "worker_selected_rank",
        "verifier_selected_rank",
        "rank_delta_verifier_minus_worker",
        "common_top_count",
        "union_top_count",
        "topk_jaccard",
        "missing_from_verifier_count",
        "extra_in_verifier_count",
        "common_js_divergence",
        "union_js_divergence",
        "common_prob_cosine",
        "union_prob_cosine",
    ]
    write_csv(output_dir / "worker_vs_verifier_depth_metrics.csv", metric_rows, fields)
    write_summary(output_dir / "summary.md", metric_rows)
    write_json(output_dir / "metadata.json", {
        "metadata": runtime_metadata(sys.argv),
        "args": vars(args),
        "verifier_variant": dataclass_to_dict(variant),
        "evidence_count": len(evidence_rows),
        "skipped_too_long": skipped_too_long,
        "depth_row_count": len(metric_rows),
        "elapsed_seconds": time.time() - total_start,
    })
    log(f"Wrote {output_dir / 'worker_vs_verifier_depth_metrics.csv'}")
    log(f"Wrote {output_dir / 'summary.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

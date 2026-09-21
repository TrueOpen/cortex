#!/usr/bin/env python3
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from pipeline_common import runtime_metadata, stable_json_hash, write_json, write_jsonl


CATEGORIES = [
    "short_qa",
    "code",
    "math_numeric",
    "json_structured",
    "mixed_language",
    "summarization",
    "logs",
    "chat",
    "needle",
    "low_margin",
]


BASE_SNIPPETS = {
    "short_qa": [
        "Question: What is the operational risk of silently accepting a wrong model worker? Answer carefully.",
        "Explain why deterministic verification should separate input evidence from output evidence.",
        "Give a concise answer about why top-k support changes matter in logits verification.",
    ],
    "code": [
        "Review this Python function and continue with a corrected version:\n\n"
        "def merge_counts(left, right):\n"
        "    out = left\n"
        "    for key, value in right.items():\n"
        "        out[key] = out.get(key, 0) + value\n"
        "    return out\n\n",
        "Write a TypeScript helper that normalizes a worker trace row before saving it.",
        "Explain this shell failure and propose a robust command sequence: CUDA out of memory while loading shard 19.",
    ],
    "math_numeric": [
        "Solve step by step, then give the final integer only: 173 * 29 - 418.",
        "A service processes 384 requests per second per GPU. Estimate throughput for 7 GPUs after a 12% overhead.",
        "Compare the numeric stability of accumulating 1024 small deltas in fp16, bf16, and fp32.",
    ],
    "json_structured": [
        "Return a JSON object with keys sample_id, verdict, confidence, and notes for a worker verification event.",
        "Convert the following policy into YAML with exactly three top-level keys: identity, drift, action.",
        "Produce a compact JSONL example for two token-depth trace rows.",
    ],
    # The point of this category is a prompt that switches script mid-sequence,
    # which is where tokenizers disagree most. The specific languages do not
    # matter, only that they are not all Latin-script English.
    "mixed_language": [
        "Explica en español por qué un teacher-forced replay sobre el mismo contexto evita la divergencia de generación.",
        "Translate and summarize: числовой дрейф нужно измерять по глубине токена, because accumulated error is not uniform.",
        "Écris une incident note bilingue: le worker a renvoyé la sortie d'une version quantifiée incorrecte.",
    ],
    "summarization": [
        "Summarize the incident: a deployment silently switched one worker from BF16 to AWQ; latency improved, but verification drift increased.",
        "Condense the following design note into bullet points while preserving the main constraints.",
        "Write an executive summary of a GPU drift calibration experiment.",
    ],
    "logs": [
        "Analyze these logs and identify the likely failure: rank=0 loaded qwen shard, rank=1 timeout, verifier reported top-k fingerprint mismatch.",
        "Given a trace with depth, selected_logprob, rank, and margin columns, describe what anomaly to look for.",
        "Explain this monitoring alert: cumulative_nll_delta_p99 exceeded profile envelope for bucket 257-1024.",
    ],
    "chat": [
        "User: My worker output verifies on H100 but fails on 6000. Assistant:",
        "System: You are a careful verification service.\nUser: Decide whether this trace belongs to Qwen3-32B BF16.",
        "User: Why is output text equality insufficient for model identity verification?\nAssistant:",
    ],
    "needle": [
        "Remember this verifier nonce: TRACE-ANCHOR-73491. Later, state the nonce and explain its purpose.",
        "The important token is hidden in the context: delta_margin_bucket=low_0.05_0.25. Use it in the final answer.",
        "Store the key phrase 'same context, not same branch' and use it in a short explanation.",
    ],
    "low_margin": [
        "Choose the most plausible next word between two close alternatives and explain uncertainty.",
        "Complete the sentence with one token if possible: The result is either valid or",
        "Rank the next action when the verifier is almost tied between accept and reject.",
    ],
}


FILLERS = [
    "The verifier records depth, selected token rank, top-k support, and cumulative negative log-likelihood.",
    "A worker is accepted only when its fingerprint fits the calibrated same-weight cross-GPU envelope.",
    "Low-margin positions are useful because small numerical changes can alter the argmax there.",
    "Quantized models may preserve text quality while changing the local probability distribution.",
    "The experiment freezes the canonical output so later comparisons stay on the same context path.",
    "A trace row should be compact enough to store, but rich enough to explain failures.",
    "Structured outputs, code, numbers, Chinese text, and log-like data exercise different tokenizer regions.",
    "The profile should report percentiles by depth bucket instead of averaging over all positions.",
    "Probe tokens make it harder for a non-anchor model to mimic only the selected output path.",
    "The result is an identity-style fingerprint, not merely an output plausibility score.",
]


def try_load_tokenizer(model: Optional[str], trust_remote_code: bool) -> Optional[object]:
    if not model:
        return None
    try:
        from transformers import AutoTokenizer
    except Exception:
        return None
    return AutoTokenizer.from_pretrained(model, trust_remote_code=trust_remote_code)


def token_count(tokenizer: Optional[object], text: str) -> int:
    if tokenizer is None:
        return max(1, len(text.split()))
    return len(tokenizer.encode(text, add_special_tokens=False))


def build_prompt(category: str,
                 target_tokens: int,
                 index: int,
                 rng: random.Random,
                 tokenizer: Optional[object]) -> str:
    base = rng.choice(BASE_SNIPPETS[category])
    header = (
        f"Calibration sample {index}. Category: {category}. "
        "Respond as the model would during a worker verification benchmark.\n\n"
    )
    parts = [header, base]
    loops = 0
    while token_count(tokenizer, "\n".join(parts)) < target_tokens:
        loops += 1
        filler = rng.choice(FILLERS)
        if category == "json_structured":
            filler = (
                '{"depth": %d, "metric": "selected_logprob", '
                '"note": "stable schema matters"}' % loops
            )
        elif category == "code":
            filler = (
                "def trace_step_%d(row):\n"
                "    return row.get('selected_logprob'), row.get('selected_rank')\n" % loops
            )
        elif category == "logs":
            filler = (
                "2026-06-25T12:%02d:00Z worker=%02d level=INFO "
                "event=trace_depth depth=%d margin=0.%03d\n"
                % (loops % 60, index % 32, loops * 17, rng.randint(10, 999))
            )
        elif category == "mixed_language":
            filler = "el mismo camino de contexto sirve para comparar el дрейф; the output path is frozen for replay."
        elif category == "needle" and loops == 3:
            filler = f"The hidden checksum for this sample is CHECK-{index:05d}-{target_tokens}."
        parts.append(filler)
        if loops > target_tokens * 4:
            break

    text = "\n".join(parts)
    current = token_count(tokenizer, text)
    if tokenizer is None or current <= int(target_tokens * 1.25):
        return text

    token_ids = tokenizer.encode(text, add_special_tokens=False)[:target_tokens]
    return tokenizer.decode(token_ids, skip_special_tokens=False)


def parse_buckets(raw: str) -> List[int]:
    buckets = []
    for item in raw.split(","):
        item = item.strip()
        if item:
            buckets.append(int(item))
    if not buckets:
        raise ValueError("At least one bucket is required")
    return buckets


def rows_for_dataset(buckets: Sequence[int],
                     per_bucket: int,
                     tokenizer: Optional[object],
                     seed: int) -> List[Dict[str, object]]:
    rng = random.Random(seed)
    rows: List[Dict[str, object]] = []
    for bucket in buckets:
        for index in range(per_bucket):
            category = CATEGORIES[(index + bucket) % len(CATEGORIES)]
            prompt = build_prompt(category, bucket, index, rng, tokenizer)
            actual_tokens = token_count(tokenizer, prompt)
            sample_id = stable_json_hash({
                "bucket": bucket,
                "index": index,
                "category": category,
                "input_text": prompt,
            }, length=20)
            rows.append({
                "sample_id": sample_id,
                "input_text": prompt,
                "canonical_output_text": "",
                "category": category,
                "target_input_tokens": bucket,
                "anchor_variant": "",
                "decode_config": None,
                "tokenizations": {},
                "metadata": {
                    "generator": "vllm_worker_verify_pipeline.generate_prompts",
                    "bucket_input_tokens": bucket,
                    "actual_input_tokens": actual_tokens,
                    "bucket_index": index,
                },
            })
    return rows


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a calibration input dataset across token-length buckets."
    )
    parser.add_argument("--output", default="data/prompts.jsonl")
    parser.add_argument("--model", default=None,
                        help="Optional tokenizer model used to measure token lengths.")
    parser.add_argument("--trust-remote-code", action="store_true")
    parser.add_argument("--buckets", default="32,128,512,2048,8192,16384")
    parser.add_argument("--per-bucket", type=int, default=50)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)

    tokenizer = try_load_tokenizer(args.model, args.trust_remote_code)
    buckets = parse_buckets(args.buckets)
    rows = rows_for_dataset(
        buckets=buckets,
        per_bucket=args.per_bucket,
        tokenizer=tokenizer,
        seed=args.seed,
    )

    output_path = Path(args.output)
    write_jsonl(output_path, rows)
    write_json(output_path.with_suffix(output_path.suffix + ".metadata.json"), {
        "metadata": runtime_metadata(sys.argv),
        "args": vars(args),
        "sample_count": len(rows),
        "buckets": buckets,
    })
    print(f"Wrote {len(rows)} samples to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

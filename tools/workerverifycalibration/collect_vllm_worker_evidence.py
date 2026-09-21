#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence

from pipeline_common import (
    DecodeConfig,
    VariantInfo,
    build_llm_kwargs,
    build_sampling_params,
    dataclass_to_dict,
    decode_tokens,
    encode_text,
    logprob_for_token,
    normalize_logprob_dict,
    parse_worker_sample,
    rank_for_token,
    read_jsonl,
    runtime_metadata,
    sorted_top_logprobs,
    tokenizer_hash,
    tokenizer_name,
    write_json,
    write_jsonl_row,
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


def trace_from_completion(completion: object,
                          tokenizer: object,
                          output_ids: Sequence[int]) -> List[dict]:
    logprob_steps = list(getattr(completion, "logprobs", []) or [])
    rows = []
    for depth, token_id in enumerate(output_ids):
        step_logprobs = (
            normalize_logprob_dict(logprob_steps[depth])
            if depth < len(logprob_steps) else {}
        )
        selected_logprob = logprob_for_token(step_logprobs, int(token_id))
        selected_rank = rank_for_token(step_logprobs, int(token_id))
        rows.append({
            "depth": depth,
            "target_token_id": int(token_id),
            "target_decoded_token": tokenizer.decode([int(token_id)], skip_special_tokens=False),
            "selected_logprob": selected_logprob,
            "selected_rank": selected_rank,
            "top_logprobs": sorted_top_logprobs(step_logprobs),
        })
    return rows


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate vLLM worker evidence: input, output, and decode-time logprob trace."
    )
    parser.add_argument("--input", default="data/prompts.jsonl")
    parser.add_argument("--output", default="data/worker_evidence.jsonl")
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
    parser.add_argument("--max-new-tokens", type=int, default=128)
    parser.add_argument("--logprobs", type=int, default=64)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--top-p", type=float, default=1.0)
    parser.add_argument("--top-k", type=int, default=0)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args(argv)

    from transformers import AutoTokenizer
    from vllm import LLM

    tokenizer = AutoTokenizer.from_pretrained(
        args.model,
        trust_remote_code=args.trust_remote_code,
    )
    variant = make_variant(args, tokenizer)
    llm_kwargs = build_llm_kwargs(args)
    log(f"Loading vLLM with kwargs: {llm_kwargs}")
    llm = LLM(**llm_kwargs)
    sampling_params = build_sampling_params(
        args,
        max_tokens=args.max_new_tokens,
        logprobs=args.logprobs,
        prompt_logprobs=None,
        detokenize=False,
    )
    config = DecodeConfig(
        max_new_tokens=args.max_new_tokens,
        temperature=args.temperature,
        top_p=args.top_p,
        top_k=args.top_k,
        seed=args.seed,
        do_sample=args.temperature > 0.0,
    )

    samples = []
    for index, payload in enumerate(read_jsonl(Path(args.input)), start=1):
        if args.limit and index > args.limit:
            break
        samples.append((index, parse_worker_sample(payload)))

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    total_start = time.time()
    count = 0
    with output_path.open("w", encoding="utf-8") as handle:
        for batch_start in range(0, len(samples), args.batch_size):
            batch = samples[batch_start:batch_start + args.batch_size]
            prompts = [sample.input_text for _, sample in batch]
            log(f"Generating worker evidence batch {batch_start // args.batch_size + 1}, size={len(batch)}")
            outputs = llm.generate(prompts, sampling_params)
            if len(outputs) != len(batch):
                raise RuntimeError(f"vLLM returned {len(outputs)} outputs for {len(batch)} prompts")
            for (index, sample), request_output in zip(batch, outputs):
                completion = request_output.outputs[0] if request_output.outputs else None
                if completion is None:
                    raise RuntimeError(f"No completion for sample {sample.sample_id}")
                input_ids = encode_text(tokenizer, sample.input_text)
                output_ids = [int(token_id) for token_id in list(getattr(completion, "token_ids", []))]
                row = {
                    "sample_id": sample.sample_id,
                    "input_text": sample.input_text,
                    "input_ids": input_ids,
                    "output_text": decode_tokens(tokenizer, output_ids),
                    "output_ids": output_ids,
                    "category": sample.category,
                    "target_input_tokens": sample.target_input_tokens,
                    "worker_variant": dataclass_to_dict(variant),
                    "decode_config": dataclass_to_dict(config),
                    "worker_trace_mode": "vllm_decode_generate",
                    "worker_trace": trace_from_completion(completion, tokenizer, output_ids),
                }
                write_jsonl_row(handle, row)
                count += 1
                log(
                    f"[{index}] sample={sample.sample_id} "
                    f"input_tokens={len(input_ids)} output_tokens={len(output_ids)}"
                )

    write_json(output_path.with_suffix(output_path.suffix + ".metadata.json"), {
        "metadata": runtime_metadata(sys.argv),
        "args": vars(args),
        "worker_variant": dataclass_to_dict(variant),
        "sample_count": count,
    })
    log(f"Wrote {count} worker evidence rows to {output_path} in {time.time() - total_start:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

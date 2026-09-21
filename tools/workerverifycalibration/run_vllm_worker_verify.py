#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import platform
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


def log(message: str) -> None:
    print(message, flush=True)


def runtime_metadata(argv: Sequence[str]) -> Dict[str, Any]:
    return {
        "created_at_unix": time.time(),
        "python": sys.version,
        "platform": platform.platform(),
        "argv": list(argv),
    }


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)


def slugify(value: str, default: str = "model") -> str:
    raw = value.rstrip("/")
    name = Path(raw).name if raw else ""
    if not name:
        name = raw or default
    chars = []
    for char in name.lower():
        if char.isalnum():
            chars.append(char)
        elif char in {"-", "_", "."}:
            chars.append(char)
        else:
            chars.append("-")
    slug = "".join(chars).strip("-_.")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or default


def default_run_id(baseline_model: str, comparison_model: str) -> str:
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    return (
        f"{timestamp}_"
        f"{slugify(baseline_model, 'baseline')}_vs_"
        f"{slugify(comparison_model, 'comparison')}"
    )


def validate_run_id(parser: argparse.ArgumentParser, run_id: str) -> None:
    path = Path(run_id)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        parser.error("--run-id must be a relative path and must not contain '..'")


def add_value(command: List[str], flag: str, value: Any, *, include_empty: bool = False) -> None:
    if value is None:
        return
    if value == "" and not include_empty:
        return
    command.extend([flag, str(value)])


def add_positive_int(command: List[str], flag: str, value: Optional[int]) -> None:
    if value is not None and value > 0:
        command.extend([flag, str(value)])


def add_float(command: List[str], flag: str, value: Optional[float]) -> None:
    if value is not None:
        command.extend([flag, str(value)])


def add_common_vllm_args(
    command: List[str],
    args: argparse.Namespace,
    *,
    role: str,
) -> None:
    tensor_parallel_size = (
        getattr(args, f"{role}_tensor_parallel_size")
        or args.tensor_parallel_size
    )
    gpu_memory_utilization = (
        getattr(args, f"{role}_gpu_memory_utilization")
        if getattr(args, f"{role}_gpu_memory_utilization") is not None
        else args.gpu_memory_utilization
    )
    max_model_len = (
        getattr(args, f"{role}_max_model_len")
        or args.max_model_len
    )
    max_num_seqs = (
        getattr(args, f"{role}_max_num_seqs")
        or args.max_num_seqs
    )
    max_num_batched_tokens = (
        getattr(args, f"{role}_max_num_batched_tokens")
        or args.max_num_batched_tokens
    )

    add_value(command, "--tensor-parallel-size", tensor_parallel_size)
    add_float(command, "--gpu-memory-utilization", gpu_memory_utilization)
    add_positive_int(command, "--max-model-len", max_model_len)
    add_positive_int(command, "--max-num-seqs", max_num_seqs)
    add_positive_int(command, "--max-num-batched-tokens", max_num_batched_tokens)
    add_positive_int(command, "--max-logprobs", args.max_logprobs)


def script_dir() -> Path:
    return Path(__file__).resolve().parent


def base_command(args: argparse.Namespace, local_script: str) -> List[str]:
    return [args.python, str(script_dir() / local_script)]


def build_generate_prompts_command(
    args: argparse.Namespace,
    prompts_path: Path,
) -> List[str]:
    command = base_command(
        args,
        "generate_prompts.py",
    )
    command.extend([
        "--model",
        args.prompt_tokenizer_model or args.baseline_model,
        "--buckets",
        args.buckets,
        "--per-bucket",
        str(args.per_bucket),
        "--output",
        str(prompts_path),
        "--seed",
        str(args.prompt_seed),
    ])
    if args.trust_remote_code:
        command.append("--trust-remote-code")
    command.extend(args.generate_extra_arg)
    return command


def build_collect_evidence_command(
    args: argparse.Namespace,
    prompts_path: Path,
    evidence_path: Path,
    baseline_variant_id: str,
) -> List[str]:
    command = base_command(
        args,
        "collect_vllm_worker_evidence.py",
    )
    command.extend([
        "--input",
        str(prompts_path),
        "--output",
        str(evidence_path),
        "--model",
        args.baseline_model,
        "--variant-id",
        baseline_variant_id,
        "--quantization",
        args.baseline_quantization,
        "--dtype",
        args.baseline_dtype,
        "--max-new-tokens",
        str(args.max_new_tokens),
        "--logprobs",
        str(args.logprobs),
        "--temperature",
        str(args.temperature),
        "--top-p",
        str(args.top_p),
        "--top-k",
        str(args.top_k),
        "--seed",
        str(args.seed),
        "--batch-size",
        str(args.worker_batch_size),
    ])
    add_value(command, "--gpu", args.baseline_gpu)
    if args.trust_remote_code:
        command.append("--trust-remote-code")
    add_common_vllm_args(command, args, role="baseline")
    add_positive_int(command, "--limit", args.limit)
    command.extend(args.worker_extra_arg)
    return command


def build_verify_evidence_command(
    args: argparse.Namespace,
    evidence_path: Path,
    output_dir: Path,
    comparison_variant_id: str,
) -> List[str]:
    command = base_command(
        args,
        "verify_vllm_worker_evidence.py",
    )
    command.extend([
        "--evidence",
        str(evidence_path),
        "--output-dir",
        str(output_dir),
        "--model",
        args.comparison_model,
        "--variant-id",
        comparison_variant_id,
        "--quantization",
        args.comparison_quantization,
        "--dtype",
        args.comparison_dtype,
        "--prompt-logprobs",
        str(args.prompt_logprobs),
        "--temperature",
        str(args.temperature),
        "--top-p",
        str(args.top_p),
        "--top-k",
        str(args.top_k),
        "--seed",
        str(args.seed),
        "--batch-size",
        str(args.verifier_batch_size),
        "--missing-logprob",
        str(args.missing_logprob),
    ])
    add_value(command, "--gpu", args.comparison_gpu)
    if args.trust_remote_code:
        command.append("--trust-remote-code")
    add_common_vllm_args(command, args, role="comparison")
    add_positive_int(command, "--limit", args.limit)
    add_positive_int(command, "--max-total-tokens", args.max_total_tokens)
    command.extend(args.verifier_extra_arg)
    return command


def build_summarize_command(args: argparse.Namespace, verifier_output_dir: Path) -> List[str]:
    command = base_command(
        args,
        "summarize_worker_verify.py",
    )
    command.extend([
        "--metrics",
        str(verifier_output_dir),
        "--output-dir",
        str(verifier_output_dir / "distribution"),
    ])
    command.extend(args.summarize_extra_arg)
    return command


def path_exists(path: Path, *, is_dir: bool = False) -> bool:
    return path.is_dir() if is_dir else path.exists()


def decide_step_status(
    output_path: Path,
    args: argparse.Namespace,
    *,
    is_dir: bool = False,
) -> str:
    if args.dry_run:
        return "run"
    if path_exists(output_path, is_dir=is_dir):
        if args.force:
            return "run"
        if args.resume:
            return "skip"
        kind = "directory" if is_dir else "file"
        raise FileExistsError(
            f"Refusing to overwrite existing {kind}: {output_path}. "
            "Use --force to overwrite it or --resume to reuse completed outputs."
        )
    return "run"


def run_step(step: Dict[str, Any], *, dry_run: bool) -> None:
    command = step["command"]
    log("")
    log(f"==> {step['name']}")
    log(f"$ {shlex.join(command)}")
    if dry_run:
        step["status"] = "dry_run"
        return
    start = time.time()
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as exc:
        step["status"] = "failed"
        step["returncode"] = exc.returncode
        step["elapsed_seconds"] = time.time() - start
        raise
    step["status"] = "completed"
    step["elapsed_seconds"] = time.time() - start


def serializable_args(args: argparse.Namespace) -> Dict[str, Any]:
    return {key: value for key, value in sorted(vars(args).items())}


def write_pipeline_metadata(path: Path, payload: Dict[str, Any]) -> None:
    write_json(path, payload)
    log(f"Wrote {path}")


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the vLLM worker evidence pipeline: generate prompts, collect "
            "baseline worker evidence, verify it with a comparison model, and "
            "summarize the final metrics."
        )
    )
    parser.add_argument("--baseline-model", "--worker-model", required=True,
                        help="Model repo/path used to generate worker evidence.")
    parser.add_argument("--comparison-model", "--verifier-model", required=True,
                        help="Model repo/path used to recompute verifier prompt logprobs.")
    parser.add_argument("--output-root", default="results/vllm_worker_verify_runs")
    parser.add_argument("--run-id", default=None,
                        help="Relative run directory name under --output-root.")
    parser.add_argument("--prompts", default=None,
                        help="Existing prompts.jsonl to reuse. If omitted, prompts are generated.")
    parser.add_argument("--prompt-tokenizer-model", default=None,
                        help="Tokenizer model for prompt length measurement. Defaults to --baseline-model.")
    parser.add_argument("--buckets", default="32,128,512,2048,8192,16384")
    parser.add_argument("--per-bucket", type=int, default=50)
    parser.add_argument("--prompt-seed", type=int, default=0)

    parser.add_argument("--baseline-variant-id", default=None)
    parser.add_argument("--comparison-variant-id", default=None)
    parser.add_argument("--baseline-gpu", default="")
    parser.add_argument("--comparison-gpu", default="")
    parser.add_argument("--baseline-quantization", default="bf16")
    parser.add_argument("--comparison-quantization", default="bf16")
    parser.add_argument("--baseline-dtype", default="auto")
    parser.add_argument("--comparison-dtype", default="auto")

    parser.add_argument("--max-new-tokens", type=int, default=128)
    parser.add_argument("--logprobs", type=int, default=64)
    parser.add_argument("--prompt-logprobs", type=int, default=64)
    parser.add_argument("--max-logprobs", type=int, default=64)
    parser.add_argument("--worker-batch-size", type=int, default=8)
    parser.add_argument("--verifier-batch-size", type=int, default=4)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--top-p", type=float, default=1.0)
    parser.add_argument("--top-k", type=int, default=0)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--missing-logprob", type=float, default=-100.0)
    parser.add_argument("--max-total-tokens", type=int, default=0)

    parser.add_argument("--trust-remote-code", action="store_true")
    parser.add_argument("--tensor-parallel-size", type=int, default=1,
                        help="Default tensor parallel size for both vLLM stages.")
    parser.add_argument("--baseline-tensor-parallel-size", type=int, default=None)
    parser.add_argument("--comparison-tensor-parallel-size", type=int, default=None)
    parser.add_argument("--gpu-memory-utilization", type=float, default=None)
    parser.add_argument("--baseline-gpu-memory-utilization", type=float, default=None)
    parser.add_argument("--comparison-gpu-memory-utilization", type=float, default=None)
    parser.add_argument("--max-model-len", type=int, default=None)
    parser.add_argument("--baseline-max-model-len", type=int, default=None)
    parser.add_argument("--comparison-max-model-len", type=int, default=None)
    parser.add_argument("--max-num-seqs", type=int, default=None)
    parser.add_argument("--baseline-max-num-seqs", type=int, default=None)
    parser.add_argument("--comparison-max-num-seqs", type=int, default=None)
    parser.add_argument("--max-num-batched-tokens", type=int, default=None)
    parser.add_argument("--baseline-max-num-batched-tokens", type=int, default=None)
    parser.add_argument("--comparison-max-num-batched-tokens", type=int, default=None)

    parser.add_argument("--skip-distribution-summary", action="store_true",
                        help="Do not run summarize_worker_verify.py after verification.")
    parser.add_argument("--resume", action="store_true",
                        help="Reuse already completed step outputs.")
    parser.add_argument("--force", action="store_true",
                        help="Overwrite existing step outputs.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the planned commands without executing them.")
    parser.add_argument("--python", default=sys.executable,
                        help="Python executable used for local subprocesses.")
    parser.add_argument("--generate-extra-arg", action="append", default=[],
                        help="Extra argument passed to prompt generation. Repeat as needed.")
    parser.add_argument("--worker-extra-arg", action="append", default=[],
                        help="Extra argument passed to worker evidence collection. Repeat as needed.")
    parser.add_argument("--verifier-extra-arg", action="append", default=[],
                        help="Extra argument passed to verifier evidence comparison. Repeat as needed.")
    parser.add_argument("--summarize-extra-arg", action="append", default=[],
                        help="Extra argument passed to distribution summarization. Repeat as needed.")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)

    if args.force and args.resume:
        parser.error("--force and --resume cannot be used together")

    run_id = args.run_id or default_run_id(args.baseline_model, args.comparison_model)
    validate_run_id(parser, run_id)

    baseline_variant_id = (
        args.baseline_variant_id
        or f"{slugify(args.baseline_model, 'baseline')}-baseline"
    )
    comparison_variant_id = (
        args.comparison_variant_id
        or f"{slugify(args.comparison_model, 'comparison')}-comparison"
    )
    baseline_slug = slugify(baseline_variant_id, "baseline")
    comparison_slug = slugify(comparison_variant_id, "comparison")

    run_dir = Path(args.output_root) / run_id
    data_dir = run_dir / "data"
    worker_verify_root = run_dir / "worker_verify"
    prompts_path = Path(args.prompts) if args.prompts else data_dir / "prompts.jsonl"
    evidence_path = data_dir / f"worker_evidence.{baseline_slug}.jsonl"
    verifier_output_dir = (
        worker_verify_root
        / f"{baseline_slug}_worker_vs_{comparison_slug}_verifier"
    )
    pipeline_metadata_path = run_dir / "pipeline_metadata.json"

    if args.prompts and not args.dry_run and not prompts_path.exists():
        parser.error(f"--prompts does not exist: {prompts_path}")

    if not args.dry_run:
        data_dir.mkdir(parents=True, exist_ok=True)
        worker_verify_root.mkdir(parents=True, exist_ok=True)

    steps: List[Dict[str, Any]] = []
    if args.prompts:
        steps.append({
            "name": "reuse prompts",
            "status": "skipped",
            "reason": "--prompts was provided",
            "output": str(prompts_path),
        })
    else:
        steps.append({
            "name": "generate prompts",
            "command": build_generate_prompts_command(args, prompts_path),
            "output": str(prompts_path),
            "status": "planned",
        })

    steps.extend([
        {
            "name": "collect worker evidence",
            "command": build_collect_evidence_command(
                args,
                prompts_path,
                evidence_path,
                baseline_variant_id,
            ),
            "output": str(evidence_path),
            "status": "planned",
        },
        {
            "name": "verify worker evidence",
            "command": build_verify_evidence_command(
                args,
                evidence_path,
                verifier_output_dir,
                comparison_variant_id,
            ),
            "output": str(verifier_output_dir),
            "status": "planned",
        },
    ])
    if not args.skip_distribution_summary:
        steps.append({
            "name": "summarize verifier metrics",
            "command": build_summarize_command(args, verifier_output_dir),
            "output": str(verifier_output_dir / "distribution"),
            "status": "planned",
        })

    payload: Dict[str, Any] = {
        "metadata": runtime_metadata(sys.argv),
        "args": serializable_args(args),
        "run_id": run_id,
        "run_dir": str(run_dir),
        "baseline_variant_id": baseline_variant_id,
        "comparison_variant_id": comparison_variant_id,
        "paths": {
            "prompts": str(prompts_path),
            "worker_evidence": str(evidence_path),
            "verifier_output_dir": str(verifier_output_dir),
            "depth_metrics": str(verifier_output_dir / "worker_vs_verifier_depth_metrics.csv"),
            "summary": str(verifier_output_dir / "summary.md"),
            "distribution_summary": str(verifier_output_dir / "distribution" / "summary.md"),
        },
        "steps": steps,
    }

    try:
        for step in steps:
            if "command" not in step:
                log(f"Skipping {step['name']}: {step.get('reason', '')}")
                continue
            if step["name"] == "verify worker evidence":
                status = decide_step_status(
                    verifier_output_dir / "worker_vs_verifier_depth_metrics.csv",
                    args,
                )
            elif step["name"] == "summarize verifier metrics":
                status = decide_step_status(
                    verifier_output_dir / "distribution" / "summary.md",
                    args,
                )
            else:
                status = decide_step_status(Path(step["output"]), args)
            if status == "skip":
                step["status"] = "skipped"
                step["reason"] = "--resume found existing output"
                log(f"Skipping {step['name']}: existing output at {step['output']}")
                continue
            run_step(step, dry_run=args.dry_run)
    except (subprocess.CalledProcessError, FileExistsError) as exc:
        payload["status"] = "failed"
        payload["error"] = str(exc)
        write_pipeline_metadata(pipeline_metadata_path, payload)
        log(str(exc))
        return getattr(exc, "returncode", 1) or 1

    payload["status"] = "dry_run" if args.dry_run else "completed"
    if args.dry_run:
        log("")
        log(f"Dry run complete; no files were written. Planned metadata path: {pipeline_metadata_path}")
    else:
        write_pipeline_metadata(pipeline_metadata_path, payload)
    log("")
    log("Pipeline outputs:")
    log(f"- prompts: {prompts_path}")
    log(f"- worker evidence: {evidence_path}")
    log(f"- verifier metrics: {verifier_output_dir / 'worker_vs_verifier_depth_metrics.csv'}")
    log(f"- verifier summary: {verifier_output_dir / 'summary.md'}")
    if not args.skip_distribution_summary:
        log(f"- distribution summary: {verifier_output_dir / 'distribution' / 'summary.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

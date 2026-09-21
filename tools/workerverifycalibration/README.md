# vLLM Worker Verify Pipeline

This directory holds the standalone pipeline scripts. The main script chains
together the local implementations in the same directory:

1. `generate_prompts.py`
2. `collect_vllm_worker_evidence.py`
3. `verify_vllm_worker_evidence.py`
4. `summarize_worker_verify.py`

The vLLM stages still need `transformers`, `vllm` and the model's GPU runtime
installed in the current Python environment.

```bash
python3 -m pip install transformers vllm
```

Then run:

```bash
./run_vllm_worker_verify.py \
  --baseline-model /models/Qwen3-32B \
  --comparison-model /models/Qwen3-32B-FP8 \
  --baseline-variant-id qwen3-32b-bf16-worker \
  --comparison-variant-id qwen3-32b-fp8-verifier \
  --baseline-dtype bfloat16 \
  --comparison-quantization fp8 \
  --comparison-dtype auto \
  --trust-remote-code
```

Common options:

- `--dry-run`: print the commands only, write no output.
- `--prompts path/to/prompts.jsonl`: reuse existing prompts and skip generation.
- `--resume`: reuse existing stage artifacts.
- `--force`: overwrite existing stage artifacts.
- `--python /path/to/python`: the Python the local sub-scripts should use.

Output defaults to the current directory:

```text
results/vllm_worker_verify_runs/<run-id>/
  data/prompts.jsonl
  data/worker_evidence.<baseline>.jsonl
  worker_verify/<baseline>_worker_vs_<comparison>_verifier/
    worker_vs_verifier_depth_metrics.csv
    summary.md
    distribution/summary.md
```

## Parameter calibration and statistical analysis

Use this in three steps:

1. `run_vllm_worker_verify.py` produces the base / challenger experiment data.
2. `calibrate_vllm_worker_verify_params.py` derives recommended parameters from
   that data.
3. `analyze_vllm_worker_verify.py` uses the step 2 parameters to check whether
   they separate the base model from the others.

### 2. Automatic parameter calibration

Derives each metric's PASS / REJECT boundary from the base and challenger
models' `worker_vs_verifier_depth_metrics.csv`:

```bash
./calibrate_vllm_worker_verify_params.py \
  --input results/vllm_worker_verify_runs \
  --base-model Qwen/Qwen3-32B \
  --output-dir calibration
```

Output files:

```text
calibration/
  recommended_thresholds.json   # recommended parameters, feed straight to analyze
  metric_calibration.csv        # per metric: base/other distribution, boundary, separation
  group_verdicts.csv            # model-level verdicts replayed with the recommended parameters
  sample_verdicts.csv           # sample-level verdicts replayed with the recommended parameters
  summary.md                    # quick report
```

Common calibration-strategy options:

```bash
--target-base-pass-rate 0.99          # how many base samples the PASS boundary should cover
--max-base-false-reject-rate 0.01     # how many base samples the REJECT boundary may falsely reject
--pass-safety-multiplier 1.10         # PASS safety margin for upper-bound metrics
--lower-margin 0.02                   # PASS safety margin for lower-bound metrics such as jaccard
```

### 3. Using the parameters for statistics and verification

Produces protocol-shaped statistics tables from the `recommended_thresholds.json`
that step 2 wrote:

```bash
./analyze_vllm_worker_verify.py \
  --input results/vllm_worker_verify_runs \
  --base-model Qwen/Qwen3-32B \
  --thresholds calibration/recommended_thresholds.json \
  --output-dir analysis
```

Output files:

```text
analysis/
  run_summary.csv              # overall metrics per run/model
  model_summary.csv            # aggregated by verifier model
  sample_summary.csv           # per-sample metric summary + PASS/REJECT/INCONCLUSIVE
  by_input_bucket.csv          # aggregated by input token bucket
  by_output_depth_bucket.csv   # aggregated by generated token depth bucket
  top_outlier_tokens.csv       # the tokens with the largest abs_logprob_diff
  thresholds.json              # the local analysis thresholds used, or derived from base
  summary.md                   # report shaped for quick reading
```

The statistics scripts follow `PREFILL_GENERATED_TOKEN_METRICS_V1` and cover,
across all generated output tokens:

- `mean_abs_logprob_diff`
- `abs_logprob_diff_p95 / p99`
- `rank_delta_nonzero_rate`
- `topk_jaccard_mean`
- `union_js_p99`
- `missing_compared_count`

Note: the calibration script emits recommended parameters derived from
experiment data, which suits an initial profile value and backtesting. The
protocol's final thresholds still have to land in
`ProfileState.verification_thresholds` and be confirmed through review and
governance.

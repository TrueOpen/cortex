# Model Profile Builder

This tool combines two kinds of offline information into the
`ModelProfileProjection` ProtoJSON profile the current Cortex implementation
accepts:

1. The `recommended_thresholds.json` produced by `tools/workerverifycalibration`
2. The model files already installed in a local Hugging Face cache/snapshot

The output file can be fed straight to `cortexctl model manifest generate
--profile`. It is aligned with `txclient.ModelProfileProjectionMessage`,
`ValidateModelProfileProjection` and `configs/model-profile.current.example.json`
in the current Cortex implementation.

```bash
./tools/modelprofilebuilder/build_model_profile.py \
  --model Qwen/Qwen3-8B \
  --thresholds tools/modelprofilebuilder/recommended_thresholds.example.json \
  --output profile.json

bin/cortexctl model manifest generate \
  --profile profile.json \
  --version 1.0.0 \
  --tokenizer qwen-tokenizer-v1 \
  --model-service model-service-main \
  --format json > model.json
```

`internal/keepercontract.CanonicalModelProfileProjection` derives the frozen
chain projection Node uses from this ProtoJSON profile during the registration
signing flow. This tool does not emit `chain_projection.canonical.json`.

## Input conventions

`--thresholds` should point at the calibration script's
`recommended_thresholds.json`. The script prefers `pass_fp_1e6` /
`reject_fp_1e6` and writes the profile's integer threshold fields.
`missing_compared_count_max` is a count field and uses the raw count rather
than FP_1E6.

`--model` may be an HF repo id, a local HF cache repo root, or a
`snapshots/<commit>` model directory:

```bash
./tools/modelprofilebuilder/build_model_profile.py \
  --model /home/cortex/.cache/huggingface/hub/models--Qwen--Qwen3-8B \
  --thresholds calibration/recommended_thresholds.json \
  --output profile.json
```

Given a repo id the script reads the local cache only and never downloads the
model. It looks in `HUGGINGFACE_HUB_CACHE`, then `HF_HOME/hub`, then
`~/.cache/huggingface/hub`. If the local cache holds several snapshots and has
no `refs/main`, the script requires an explicit snapshot path instead.

If the script cannot resolve the repo id, the immutable revision or
`config.json` from the local HF cache/snapshot it fails outright: that means
this local environment cannot declare support for the model.

## Generated fields

The script derives these profile fields from the local model files, and offers
no CLI override for them:

- `model_id`: deterministic, of the form `hf-<sha256(huggingface:<repo_id>)>`
- `manifest_hash`: framed hash of the local model artifact file manifest
- `tokenizer_hash`: tokenizer / tokenizer config / chat template bundle hash
- `metadata_hash`: stable hash of repo/revision, artifact hashes, the model
  configuration digest and license metadata
- `verification_thresholds`: from the calibration recommendations

These bytes32 fields are emitted as base64 per the Cortex ProtoJSON rules.
`uint32` fields are emitted as JSON numbers and `uint64` fields as quoted
decimal strings, matching `internal/txclient`'s ProtoJSON typing.

## Template fields

The default template is:

```text
configs/model-profile.current.example.json
```

`--base-profile` can point at a profile draft that has already been reviewed.
The script only overwrites the fields the local model information and the
calibration thresholds can determine; governance fields such as
`profile_version`, `required_top_k`, `resource_tier`, the schema hash, the
evidence schema hash, the display tag hash, pricing, timeout and registration
fee keep their template values and get a basic check against Cortex's current
validation rules at generation time.

A bytes32 field in the base profile may be written as `sha256:<hex>`,
`0x<hex>`, bare hex or ProtoJSON base64; the output is normalized to ProtoJSON
base64. Every consensus field still needs human review before on-chain
registration.

## Threshold mapping

| calibration key | profile field |
|---|---|
| `pass.mean_abs_logprob_diff_max` | `pass_mean_abs_logprob_diff_max` |
| `pass.abs_logprob_diff_p95_max` | `pass_abs_logprob_diff_p95_max` |
| `pass.abs_logprob_diff_p99_max` | `pass_abs_logprob_diff_p99_max` |
| `pass.rank_delta_nonzero_rate_max` | `pass_rank_delta_nonzero_rate_max` |
| `pass.topk_jaccard_mean_min` | `pass_topk_jaccard_mean_min` |
| `pass.union_js_p99_max` | `pass_union_js_p99_max` |
| `pass.missing_compared_count_max` | `pass_max_missing_compared_count` |
| `reject.mean_abs_logprob_diff_max` | `reject_mean_abs_logprob_diff_min` |
| `reject.abs_logprob_diff_p95_max` | `reject_abs_logprob_diff_p95_min` |
| `reject.abs_logprob_diff_p99_max` | `reject_abs_logprob_diff_p99_min` |
| `reject.rank_delta_nonzero_rate_max` | `reject_rank_delta_nonzero_rate_min` |
| `reject.topk_jaccard_mean_min` | `reject_topk_jaccard_mean_max` |
| `reject.union_js_p99_max` | `reject_union_js_p99_min` |

`pass_min_finite_count` is not currently derived by the calibration script and
keeps the template value; write it into the base profile when it needs to
change.

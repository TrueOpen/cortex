# Model Profile Builder

Builds everything a model registration needs from a model in the local
Hugging Face cache:

1. the full V4 model manifest (`manifest.canonical.json`), whose bytes the
   registrant hosts at `manifest_uri`;
2. the `ModelProfileProjection` ProtoJSON profile (`profile.json`) that
   `cortexctl model manifest generate --profile` accepts;
3. the chain projection and registration digest the chain re-derives.

Hashes follow the wire hub vectors (`model_id_v1`, `model_manifest_v4`,
`model_registration_chain_v1`, `model_profile_canonical_v3`): Manifest V4,
chain projection V3, registration digest V3.

## Inputs

| Input | Flag | Notes |
|---|---|---|
| Model | `--model` | HF repo id, local HF cache repo root, or `snapshots/<commit>` directory. Read from the local cache only, never downloaded. |
| Thresholds | `--thresholds` + `--min-finite-count` | The calibration `recommended_thresholds.json` from `tools/workerverifycalibration`. |
| | or `--verification-thresholds-json` | A ready 14-field `verification_thresholds` object, used as is. |
| Chain | `--chain-id` | Target chain, e.g. `trueopen-testnet-1`. |
| Registrant | `--proposer-address` | The account that will sign the registration (bech32, HRP `trueopen`). |
| Manifest location | `--manifest-uri` | `https://` or `ipfs://`; pass `""` on the first run (see below). |

`model_id = H_FIELDS_V1("TRUEOPEN_MODEL_ID_V1", chain_id, provider, repo_id,
proposer_address)`. It goes into the manifest, `evidence_schema_hash` and
`manifest_hash`, so a different chain or a different registrant means
regenerating everything. The chain rejects a registration whose signer is not
the `--proposer-address` used here.

## Usage

`manifest_uri` is not inside the manifest and does not enter `manifest_hash`;
it only enters the chain projection. So generate the manifest first, host it,
then generate again with its URI:

```bash
# 1. manifest
./tools/modelprofilebuilder/build_model_profile.py \
  --model Qwen/Qwen3-8B \
  --thresholds calibration/recommended_thresholds.json --min-finite-count 6 \
  --chain-id trueopen-testnet-1 \
  --proposer-address trueopen1... \
  --tool-call-parser-name hermes --reasoning-parser-name qwen3 \
  --license-ref apache-2.0 \
  --decode-vectors-path decode_vectors.json \
  --manifest-uri "" \
  --output-dir out/qwen3-8b-0

# 2. host out/qwen3-8b-0/manifest.canonical.json byte for byte at <manifest-uri>

# 3. final profile: same flags, only --manifest-uri / --output-dir change
./tools/modelprofilebuilder/build_model_profile.py \
  ...same flags... \
  --manifest-uri "<manifest-uri>" \
  --output-dir out/qwen3-8b-1

bin/cortexctl model manifest generate \
  --profile out/qwen3-8b-1/profile.json \
  --version 1.0.0 \
  --tokenizer qwen-tokenizer-v1 \
  --model-service model-service-main \
  --format json > model.json
```

Check that both runs print the same `manifest_hash`, and that the hosted bytes
match:

```bash
curl -sL "<manifest-uri>" | cmp - out/qwen3-8b-0/manifest.canonical.json && echo OK
```

Host `manifest.canonical.json`, never `manifest.pretty.json`: retrievers hash
the exact bytes they download.

## Outputs

| File | Use |
|---|---|
| `manifest.canonical.json` | The canonical manifest bytes `manifest_hash` is computed over; host this file. No trailing newline. |
| `manifest.pretty.json` | Human-readable view only. |
| `profile.json` | ProtoJSON `ModelProfileProjection` for `cortexctl model manifest generate --profile`. Only valid from the run with the final `--manifest-uri`. |
| `chain_projection.canonical.json` | Canonical chain projection. |
| `registration_data.json` | `manifest_hash`, `chain_projection_hash`, `registration_digest`, the expected Msg and states. |

The run also prints warnings, placeholder fields and a `REVIEW` list of flags
still on their built-in defaults (denom, fees, pricing, timeouts, ...).

## Thresholds

`--thresholds` converts the calibration output:

- FP_1E6 fields use `pass_fp_1e6` / `reject_fp_1e6` when present, else
  `round(float * 1e6)` of `pass` / `reject`.
- The reject group takes the protocol direction:

  | calibration key | profile field |
  |---|---|
  | `pass.mean_abs_logprob_diff_max` | `pass_mean_abs_logprob_diff_max` |
  | `pass.abs_logprob_diff_p95_max` | `pass_abs_logprob_diff_p95_max` |
  | `pass.abs_logprob_diff_p99_max` | `pass_abs_logprob_diff_p99_max` |
  | `pass.rank_delta_nonzero_rate_max` | `pass_rank_delta_nonzero_rate_max` |
  | `pass.topk_jaccard_mean_min` | `pass_topk_jaccard_mean_min` |
  | `pass.union_js_p99_max` | `pass_union_js_p99_max` |
  | `pass.missing_compared_count_max` | `pass_max_missing_compared_count` (raw count) |
  | `reject.mean_abs_logprob_diff_max` | `reject_mean_abs_logprob_diff_min` |
  | `reject.abs_logprob_diff_p95_max` | `reject_abs_logprob_diff_p95_min` |
  | `reject.abs_logprob_diff_p99_max` | `reject_abs_logprob_diff_p99_min` |
  | `reject.rank_delta_nonzero_rate_max` | `reject_rank_delta_nonzero_rate_min` |
  | `reject.topk_jaccard_mean_min` | `reject_topk_jaccard_mean_max` |
  | `reject.union_js_p99_max` | `reject_union_js_p99_min` |

- `pass_min_finite_count` is not produced by calibration: give it with
  `--min-finite-count` (a report rule `finite_count > 5` means `6`).
  `--max-missing-compared-count` overrides the calibration count.

Either way the 14 fields must all be present, fit uint32, and every PASS
bound must be strictly tighter than its REJECT bound, or the script stops.

`recommended_thresholds.example.json` is an example calibration file; its
values equal the built-in defaults and are not calibrated for any model.

## Other inputs

- `--schema-hash` defaults to the placeholder `0x99…99` and is reported under
  `placeholder_fields`; set the real value before registering.
- `--decode-vectors-path` adds a `DECODE_VECTORS` file (see
  `tools/decodevectors`) as `trueopen/decode_vectors.json`; without it
  `output_decoding.decode_vectors_path` is empty and nodes skip the check.
- `evidence_schema_hash` is derived, not an input. Shape the evidence schema
  with `--evidence-schema-json` if needed.
- Pricing, timeouts and batch verification take JSON files
  (`--pricing-profile-json`, `--timeout-bootstrap-profile-json`,
  `--batch-verification-json`); run with `--help` for every flag.

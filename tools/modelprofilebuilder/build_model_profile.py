#!/usr/bin/env python3
"""Build a model's V4 manifest and registration profile from a local HF snapshot.

Inputs: a model in the local Hugging Face cache, the calibration thresholds
(tools/workerverifycalibration recommended_thresholds.json), the target chain_id
and the registrant's proposer address. Outputs (see write_outputs):
manifest.canonical.json -- the exact bytes to host at manifest_uri --,
profile.json for `cortexctl model manifest generate --profile`, and the chain
projection / registration digest. Hashes follow the wire hub vectors
(model_id_v1, model_manifest_v4, model_registration_chain_v1,
model_profile_canonical_v3): Manifest V4, chain projection V3, registration
digest V3.

It intentionally produces a *draft* package: production registration still needs
real chain params, a registrant-authored DECODE_VECTORS file, the finalized
`schema_hash` (the input/output component merged hash, derived by the
authoritative producer from the frozen typed schema / golden vectors — not
reproducible from the docs alone), a governance-approved parser choice, and a
Cosmos-account signature over the whole Msg.

Byte-exact per the docs and computed here:
  - H_V1 / H_FIELDS_V1 / FRAME_V1 framing.
  - All TRUEOPEN_MODEL_* artifact / manifest / projection / registration domains.
  - model_id = H_FIELDS_V1("TRUEOPEN_MODEL_ID_V1", chain_id, provider, repo_id,
    proposer_address) with the proposer address bech32-decoded to codec bytes.
  - evidence_schema_hash = H_FIELDS_V1("TRUEOPEN_EVIDENCE_SCHEMA_V1", ...), the
    exact value the chain re-derives and checks (bound to the profile's model_id,
    profile_version, schema_hash and tokenizer_hash).
  - Manifest V4 structure, chain_projection V3 field set.

Draft placeholders (must be finalized before real registration; each emits a warning):
  - schema_hash, decode_vectors_path/DECODE_VECTORS file,
    manifest_uri (unless provided), parser choices (unless provided).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import struct
import sys
import unicodedata
from pathlib import Path
from typing import Any


EMPTY_BYTES32 = "0x" + "0" * 64
PLACEHOLDER_SCHEMA_HASH = "0x" + "9" * 64

# V1 registration only accepts HuggingFace.
SUPPORTED_PROVIDER = "HUGGINGFACE"

# Manifest V4 required_capabilities.
DEFAULT_REQUIRED_CAPABILITIES = [
    "LOAD_HF_CAUSAL_LM",
    "RETURN_GENERATED_TOKEN_IDS",
    "PREFILL_LOGPROBS_FOR_GIVEN_TOKEN_IDS",
    "RETURN_TOPK_LOGPROBS",
    "RAW_SPECIAL_TOKENS_SUPPORTED",
]

# Exactly two required_infer_evidence entries,
# ordered by EvidenceKind numeric ascending (WORKER_VALUE_OPENING then WORKER_TOKEN_OPENING).
DEFAULT_EVIDENCE_SCHEMA = {
    "schema_version": 1,
    "required_infer_evidence": [
        {
            "evidence_kind": "WORKER_VALUE_OPENING",
            "commitment_schema_version": 3,
            "max_encoded_size_bytes": 1073741824,
        },
        {
            "evidence_kind": "WORKER_TOKEN_OPENING",
            "commitment_schema_version": 1,
            "max_encoded_size_bytes": 67108864,
        },
    ],
}

DEFAULT_VERIFICATION_THRESHOLDS = {
    "pass_min_finite_count": 16,
    "pass_max_missing_compared_count": 0,
    "pass_mean_abs_logprob_diff_max": 50000,
    "pass_abs_logprob_diff_p95_max": 100000,
    "pass_abs_logprob_diff_p99_max": 200000,
    "pass_rank_delta_nonzero_rate_max": 50000,
    "pass_topk_jaccard_mean_min": 900000,
    "pass_union_js_p99_max": 50000,
    "reject_mean_abs_logprob_diff_min": 300000,
    "reject_abs_logprob_diff_p95_min": 500000,
    "reject_abs_logprob_diff_p99_min": 800000,
    "reject_rank_delta_nonzero_rate_min": 300000,
    "reject_topk_jaccard_mean_max": 600000,
    "reject_union_js_p99_min": 200000,
}

DEFAULT_BATCH_VERIFICATION = {
    "enabled": False,
    "min_sample_count": 0,
    "min_valid_sample_count": 0,
    "pass_min_sample_pass_ratio_bps": 0,
    "reject_min_sample_reject_ratio_bps": 0,
}

# PricingProfile V2: old price-band / pricing_unit fields removed.
DEFAULT_PRICING_PROFILE = {
    "initial_output_price": 10,
    "verify_ratio_bps": 1000,
    "min_order_value": 1000,
}

DEFAULT_TIMEOUT_BOOTSTRAP_PROFILE = {
    "infer_timeout_bootstrap_blocks": 100,
    "verify_timeout_bootstrap_blocks": 50,
    "commit_timeout_bootstrap_blocks": 20,
    "bootstrap_valid_until_epoch": 1000,
}

# max_manifest_uri_bytes is a governance param; use a conservative draft cap.
MAX_MANIFEST_URI_BYTES = 2048

MODEL_FILE_NAMES = {
    "config.json",
    "generation_config.json",
    "tokenizer.json",
    "tokenizer.model",
    "tokenizer_config.json",
    "special_tokens_map.json",
    "added_tokens.json",
    "vocab.json",
    "merges.txt",
    "preprocessor_config.json",
    "processor_config.json",
    "quantization_config.json",
    "quant_config.json",
}


# ---------------------------------------------------------------------------
# Canonical encoding & domain hashing (docs/.../00-基础规范/Canonical编码与域哈希.md)
# ---------------------------------------------------------------------------


def canonical_json_bytes(value: Any) -> bytes:
    """Return Manifest Canonical JSON V1 bytes for generated ASCII-key objects."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def frame_v1(*values: bytes) -> bytes:
    """FRAME_V1(v1..vn) = concat( u64_be(len(vi)) || vi )."""

    out = bytearray()
    for value in values:
        out += len(value).to_bytes(8, "big")
        out += value
    return bytes(out)


def h_v1(domain: str, payload: bytes) -> str:
    """H_V1(domain, payload) with the TRUEOPEN_FRAME_V1 magic."""

    domain_bytes = domain.encode("utf-8")
    frame = (
        b"TRUEOPEN_FRAME_V1"
        + len(domain_bytes).to_bytes(4, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    )
    return "0x" + hashlib.sha256(frame).hexdigest()


def h_fields_v1(domain: str, *fields: bytes) -> str:
    """H_FIELDS_V1(domain, f1..fn) = SHA256(FRAME_V1(utf8(domain), f1..fn))."""

    frame = frame_v1(domain.encode("utf-8"), *fields)
    return "0x" + hashlib.sha256(frame).hexdigest()


# ---- bech32 (BIP173) address decoding, for the model_id address field --------

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_decode(bech: str) -> tuple[str, list[int]]:
    if any(ord(c) < 33 or ord(c) > 126 for c in bech):
        raise ValueError("address contains non-printable characters")
    if bech.lower() != bech and bech.upper() != bech:
        raise ValueError("address has mixed case")
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech):
        raise ValueError("invalid bech32 separator position")
    hrp = bech[:pos]
    data: list[int] = []
    for c in bech[pos + 1 :]:
        d = _BECH32_CHARSET.find(c)
        if d == -1:
            raise ValueError(f"invalid bech32 data character: {c!r}")
        data.append(d)
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != 1:
        raise ValueError("invalid bech32 checksum")
    return hrp, data[:-6]


def _convertbits(data: list[int], frombits: int, tobits: int) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError("invalid value for bit conversion")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("invalid padding in bech32 data")
    return ret


def address_codec_bytes(bech: str, expected_hrp: str = "trueopen") -> bytes:
    """canonical Bech32 -> address-codec bytes; HRP is not part of the preimage."""

    if bech != bech.strip():
        raise ValueError("address has leading/trailing whitespace")
    hrp, data5 = _bech32_decode(bech)
    if hrp != expected_hrp:
        raise ValueError(
            f"address HRP {hrp!r} != expected {expected_hrp!r}; current-chain HRP is lowercase 'trueopen'"
        )
    decoded = bytes(_convertbits(data5, 5, 8))
    if not (1 <= len(decoded) <= 255):
        raise ValueError("decoded address must be 1..255 bytes")
    return decoded


# ---------------------------------------------------------------------------
# model_id identity derivation
# ---------------------------------------------------------------------------


def validate_hf_repo_id(repo_id: str) -> None:
    """provider-scoped canonical check for HuggingFace repo_id."""

    if repo_id != repo_id.strip():
        raise ValueError("repo_id has leading/trailing whitespace")
    if unicodedata.normalize("NFC", repo_id) != repo_id:
        raise ValueError("repo_id is not NFC-normalized")
    if len(repo_id.encode("utf-8")) > 255:
        raise ValueError("repo_id exceeds 255 bytes")
    if not re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", repo_id):
        raise ValueError(
            "HF repo_id must be namespace/name with exactly one '/', "
            "both segments non-empty, charset [A-Za-z0-9._-]"
        )


def compute_model_id(
    chain_id: str, provider: str, repo_id: str, proposer_address: str
) -> str:
    if provider != SUPPORTED_PROVIDER:
        raise ValueError(
            f"provider {provider!r} not supported for V1 registration "
            f"(only {SUPPORTED_PROVIDER}); ERR_PROVIDER_NOT_SUPPORTED"
        )
    validate_hf_repo_id(repo_id)
    if not chain_id:
        raise ValueError("chain_id is required for model_id derivation")
    return h_fields_v1(
        "TRUEOPEN_MODEL_ID_V1",
        chain_id.encode("utf-8"),
        provider.encode("utf-8"),
        repo_id.encode("utf-8"),
        address_codec_bytes(proposer_address, "trueopen"),
    )


# ---------------------------------------------------------------------------
# evidence_schema_hash (TRUEOPEN_EVIDENCE_SCHEMA_V1)
#
# Byte-exact port of internal/keepercontract/model_registration.go
# evidenceSchemaHash(). The typed H_FIELDS_V1 framing (internal/hfields) encodes
# uint32/uint64 as fixed-width big endian, bool as one byte, a string as its
# UTF-8 bytes and a nested group as a bare FRAME_V1 (frame_v1) carried as one
# length-prefixed field -- NOT as decimal text. required_infer_evidence is one
# nested frame that begins with its own element_count, and element_count is ALSO
# repeated as a separate top-level requirement_count field just before it; both
# carry the same number (see the long note in the Go source).
# ---------------------------------------------------------------------------

EVIDENCE_SCHEMA_DOMAIN = "TRUEOPEN_EVIDENCE_SCHEMA_V1"

# Enum -> uint32 number, keyed on the prefix-trimmed name the manifest carries.
_GENERATION_TYPE_NUM = {"DETERMINISTIC": 1, "SAMPLED": 2}
_VERIFICATION_MODE_NUM = {"SINGLE_SAMPLE": 1}
_TOKEN_SCOPE_NUM = {"ALL_GENERATED_OUTPUT_TOKENS": 1}
_NUMERIC_SCALE_NUM = {"FP_1E6": 1}
_EVIDENCE_KIND_NUM = {
    "WORKER_VALUE_OPENING": 1,
    "VERIFIER_VALUE_OPENING": 2,
    "SETTLEMENT_ROOT_OPENING": 3,
    "WORKER_TOKEN_OPENING": 4,
}


def _u32(value: int) -> bytes:
    return int(value).to_bytes(4, "big")


def _u64(value: int) -> bytes:
    return int(value).to_bytes(8, "big")


def _bool_byte(value: Any) -> bytes:
    return b"\x01" if value else b"\x00"


def _hash32_bytes(value: str) -> bytes:
    raw = bytes.fromhex(value[2:] if value.startswith("0x") else value)
    if len(raw) != 32:
        raise ValueError(f"expected a 32-byte hash, got {len(raw)} bytes: {value!r}")
    return raw


def _enum_number(value: str, table: dict[str, int], prefix: str, label: str) -> int:
    name = value[len(prefix):] if value.startswith(prefix) else value
    if name not in table:
        raise ValueError(f"unknown {label} enum value: {value!r}")
    return table[name]


def compute_evidence_schema_hash(
    *,
    model_id: str,
    profile_version: int,
    schema_hash: str,
    tokenizer_hash: str,
    generation_type: str,
    required_top_k: int,
    batch_verification: dict[str, Any],
    verification_profile: dict[str, Any],
) -> str:
    """Derive evidence_schema_hash exactly as the chain re-derives and checks it.

    Returns the 0x-prefixed 32-byte hex. It is bound to model_id, profile_version,
    schema_hash and tokenizer_hash, so it is only valid for this exact profile;
    note it is derived over whatever schema_hash the profile carries, so a
    placeholder schema_hash still yields a self-consistent, chain-accepted
    evidence_schema_hash.
    """

    vp = verification_profile
    metrics = vp["metrics"]
    evidence = vp["evidence_schema"]
    required = evidence["required_infer_evidence"]

    fields: list[bytes] = [
        _u32(evidence["schema_version"]),
        _hash32_bytes(model_id),
        _u32(profile_version),
        _hash32_bytes(schema_hash),
        _hash32_bytes(tokenizer_hash),
        _u32(_enum_number(generation_type, _GENERATION_TYPE_NUM, "GENERATION_TYPE_", "generation_type")),
        _u32(required_top_k),
        frame_v1(
            _bool_byte(batch_verification["enabled"]),
            _u32(batch_verification["min_sample_count"]),
            _u32(batch_verification["min_valid_sample_count"]),
            _u32(batch_verification["pass_min_sample_pass_ratio_bps"]),
            _u32(batch_verification["reject_min_sample_reject_ratio_bps"]),
        ),
        _u32(vp["verification_profile_id"]),
        vp["judgment_function_version"].encode("utf-8"),
        vp["canonical_encoding_version"].encode("utf-8"),
        vp["metric_aggregate_proof_version"].encode("utf-8"),
        _u32(_enum_number(vp["verification_mode"], _VERIFICATION_MODE_NUM, "VERIFICATION_MODE_", "verification_mode")),
        _u32(_enum_number(vp["token_scope"], _TOKEN_SCOPE_NUM, "TOKEN_SCOPE_", "token_scope")),
        _bool_byte(vp["include_generated_special_tokens"]),
        _bool_byte(vp["include_prompt_tokens"]),
        _bool_byte(vp["include_padding_tokens"]),
        _bool_byte(vp["require_output_token_ids"]),
        _bool_byte(vp["require_finish_reason"]),
        frame_v1(
            _bool_byte(metrics["compare_logprob_diff"]),
            _bool_byte(metrics["compare_rank_delta"]),
            _bool_byte(metrics["compare_topk_jaccard"]),
            _bool_byte(metrics["compare_union_js"]),
            _u32(metrics["compared_top_k"]),
            _u32(_enum_number(metrics["numeric_scale"], _NUMERIC_SCALE_NUM, "NUMERIC_SCALE_", "numeric_scale")),
        ),
        _u32(len(required)),
    ]

    # required_infer_evidence: one nested frame that starts with element_count,
    # then one sub-frame per requirement, ordered by EvidenceKind ascending.
    elements: list[bytes] = [_u32(len(required))]
    previous = 0
    for index, req in enumerate(required):
        kind = _enum_number(req["evidence_kind"], _EVIDENCE_KIND_NUM, "EVIDENCE_KIND_", "evidence_kind")
        size = int(req["max_encoded_size_bytes"])
        if (
            (index > 0 and kind <= previous)
            or int(req["commitment_schema_version"]) == 0
            or size == 0
            or size > (1 << 40)
        ):
            raise ValueError(
                "required_infer_evidence must be known, sorted ascending by kind, unique, and bounded"
            )
        previous = kind
        elements.append(
            frame_v1(_u32(kind), _u32(req["commitment_schema_version"]), _u64(size))
        )
    fields.append(frame_v1(*elements))

    return h_fields_v1(EVIDENCE_SCHEMA_DOMAIN, *fields)


# ---------------------------------------------------------------------------
# File discovery & digests
# ---------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def read_json_file(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def read_optional_json_arg(path: str | None, default: dict[str, Any]) -> dict[str, Any]:
    if not path:
        return dict(default)
    return read_json_file(Path(path))


# ---------------------------------------------------------------------------
# verification_thresholds from calibration
#
# --thresholds takes the calibration recommended_thresholds.json
# ({"pass": .., "reject": .., "pass_fp_1e6": .., "reject_fp_1e6": ..}, keyed by
# calibration metric). --verification-thresholds-json takes the 14-field
# protocol object as is.
# ---------------------------------------------------------------------------

FP_SCALE = 1_000_000
UINT32_MAX = (1 << 32) - 1

# (calibration group, calibration key, protocol field); all FP_1E6-scaled. A
# calibration reject.<metric>_max is the protocol reject_<metric>_min and vice versa.
CALIBRATION_FP_FIELDS = [
    ("pass", "mean_abs_logprob_diff_max", "pass_mean_abs_logprob_diff_max"),
    ("pass", "abs_logprob_diff_p95_max", "pass_abs_logprob_diff_p95_max"),
    ("pass", "abs_logprob_diff_p99_max", "pass_abs_logprob_diff_p99_max"),
    ("pass", "rank_delta_nonzero_rate_max", "pass_rank_delta_nonzero_rate_max"),
    ("pass", "topk_jaccard_mean_min", "pass_topk_jaccard_mean_min"),
    ("pass", "union_js_p99_max", "pass_union_js_p99_max"),
    ("reject", "mean_abs_logprob_diff_max", "reject_mean_abs_logprob_diff_min"),
    ("reject", "abs_logprob_diff_p95_max", "reject_abs_logprob_diff_p95_min"),
    ("reject", "abs_logprob_diff_p99_max", "reject_abs_logprob_diff_p99_min"),
    ("reject", "rank_delta_nonzero_rate_max", "reject_rank_delta_nonzero_rate_min"),
    ("reject", "topk_jaccard_mean_min", "reject_topk_jaccard_mean_max"),
    ("reject", "union_js_p99_max", "reject_union_js_p99_min"),
]

# (pass field, reject field, True when lower values are better).
THRESHOLD_ORDERING = [
    ("pass_mean_abs_logprob_diff_max", "reject_mean_abs_logprob_diff_min", True),
    ("pass_abs_logprob_diff_p95_max", "reject_abs_logprob_diff_p95_min", True),
    ("pass_abs_logprob_diff_p99_max", "reject_abs_logprob_diff_p99_min", True),
    ("pass_rank_delta_nonzero_rate_max", "reject_rank_delta_nonzero_rate_min", True),
    ("pass_union_js_p99_max", "reject_union_js_p99_min", True),
    ("pass_topk_jaccard_mean_min", "reject_topk_jaccard_mean_max", False),
]


def _present(value: Any) -> bool:
    return value is not None and value != ""


def _group_value(data: dict[str, Any], group: str, key: str) -> Any:
    section = data.get(group)
    return section.get(key) if isinstance(section, dict) else None


def _uint32(value: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= UINT32_MAX:
        raise ValueError(f"{field} = {value!r} must be a uint32 integer")
    return value


def _calibration_fp_value(data: dict[str, Any], group: str, key: str, field: str) -> int:
    scaled = _group_value(data, f"{group}_fp_1e6", key)
    if _present(scaled):
        return _uint32(scaled, f"{group}_fp_1e6.{key}")
    raw = _group_value(data, group, key)
    if not _present(raw):
        raise ValueError(f"calibration thresholds miss {group}.{key} (and {group}_fp_1e6.{key})")
    number = float(raw)
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{group}.{key} must be a non-negative finite number, got {raw!r}")
    return _uint32(int(round(number * FP_SCALE)), field)


def thresholds_from_calibration(
    data: dict[str, Any],
    min_finite_count: int,
    max_missing_compared_count: int | None,
) -> dict[str, int]:
    """Convert calibration recommended_thresholds.json into the 14-field object."""

    out: dict[str, int] = {"pass_min_finite_count": _uint32(min_finite_count, "--min-finite-count")}
    if max_missing_compared_count is None:
        raw = _group_value(data, "pass", "missing_compared_count_max")
        if not _present(raw):
            raise ValueError(
                "calibration thresholds miss pass.missing_compared_count_max; "
                "pass --max-missing-compared-count"
            )
        number = float(raw)
        if not number.is_integer() or number < 0:
            raise ValueError(f"pass.missing_compared_count_max must be a count, got {raw!r}")
        max_missing_compared_count = int(number)
    # A raw count, not FP_1E6.
    out["pass_max_missing_compared_count"] = _uint32(
        max_missing_compared_count, "pass_max_missing_compared_count"
    )
    for group, key, field in CALIBRATION_FP_FIELDS:
        out[field] = _calibration_fp_value(data, group, key, field)
    return {key: out[key] for key in DEFAULT_VERIFICATION_THRESHOLDS}


def validate_verification_thresholds(thresholds: dict[str, Any]) -> None:
    expected = set(DEFAULT_VERIFICATION_THRESHOLDS)
    if set(thresholds) != expected:
        missing = sorted(expected - set(thresholds))
        extra = sorted(set(thresholds) - expected)
        raise ValueError(f"verification_thresholds fields mismatch: missing={missing} extra={extra}")
    for key, value in thresholds.items():
        _uint32(value, key)
    errors = []
    for pass_field, reject_field, lower_is_better in THRESHOLD_ORDERING:
        p, r = thresholds[pass_field], thresholds[reject_field]
        if lower_is_better and not p < r:
            errors.append(f"{pass_field} ({p}) must be < {reject_field} ({r})")
        if not lower_is_better and not p > r:
            errors.append(f"{pass_field} ({p}) must be > {reject_field} ({r})")
    if errors:
        raise ValueError("PASS bounds must be strictly tighter than REJECT bounds: " + "; ".join(errors))


def load_verification_thresholds(args: argparse.Namespace) -> dict[str, Any]:
    if bool(args.thresholds) == bool(args.verification_thresholds_json):
        raise ValueError("pass exactly one of --thresholds or --verification-thresholds-json")
    if args.thresholds:
        if args.min_finite_count is None:
            raise ValueError(
                "--min-finite-count is required with --thresholds "
                "(calibration does not produce pass_min_finite_count)"
            )
        thresholds = thresholds_from_calibration(
            read_json_file(Path(args.thresholds)),
            args.min_finite_count,
            args.max_missing_compared_count,
        )
    else:
        thresholds = read_json_file(Path(args.verification_thresholds_json))
    validate_verification_thresholds(thresholds)
    return thresholds


def is_probably_model_file(path: Path, include_readme: bool) -> bool:
    name = path.name
    lower = name.lower()
    if any(part.startswith(".") for part in path.parts):
        return False
    if lower in MODEL_FILE_NAMES:
        return True
    if lower.endswith((".safetensors", ".bin", ".pt", ".gguf")):
        return True
    if lower.endswith(".index.json"):
        return True
    if lower.endswith(".jinja") or "chat_template" in lower:
        return True
    if "decode_vectors" in lower:
        return True
    if lower.endswith(".py"):
        return True
    if lower in {"license", "license.txt", "notice", "notice.txt"}:
        return True
    if include_readme and lower.endswith((".md", ".rst", ".txt")):
        return True
    return False


def role_for_path(path: str) -> str:
    name = Path(path).name.lower()
    if name == "config.json":
        return "MODEL_CONFIG"
    if name == "generation_config.json":
        return "GENERATION_CONFIG"
    if "decode_vectors" in name:
        return "DECODE_VECTORS"
    if name in {
        "tokenizer.json",
        "tokenizer.model",
        "vocab.json",
        "merges.txt",
    }:
        return "TOKENIZER"
    if name in {
        "tokenizer_config.json",
        "special_tokens_map.json",
        "added_tokens.json",
    }:
        return "TOKENIZER_CONFIG"
    if name in {"quantization_config.json", "quant_config.json"}:
        return "QUANT_CONFIG"
    if name.endswith(".safetensors") or name.endswith(".bin") or name.endswith(".pt"):
        return "WEIGHT_SHARD"
    if name.endswith(".jinja") or "chat_template" in name:
        return "CHAT_TEMPLATE"
    return "OTHER_REQUIRED"


def discover_model_files(model_dir: Path, include_readme: bool) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for root, dir_names, file_names in os.walk(model_dir):
        dir_names[:] = [
            d
            for d in dir_names
            if not d.startswith(".") and d not in {"refs", "snapshots", "blobs"}
        ]
        for file_name in file_names:
            absolute = Path(root) / file_name
            relative = absolute.relative_to(model_dir).as_posix()
            if not is_probably_model_file(Path(relative), include_readme):
                continue
            stat = absolute.stat()
            files.append(
                {
                    "path": relative,
                    "role": role_for_path(relative),
                    "size_bytes": stat.st_size,
                    "digest": sha256_file(absolute),
                }
            )
    files.sort(key=lambda item: item["path"].encode("utf-8"))
    return files


def read_ref_revision(model_root: Path, ref_name: str = "main") -> str:
    ref_path = model_root / "refs" / ref_name
    if not ref_path.is_file():
        return ""
    return ref_path.read_text(encoding="utf-8").strip()


def hf_hub_cache_dir() -> Path:
    hub_cache = os.environ.get("HUGGINGFACE_HUB_CACHE")
    if hub_cache:
        return Path(hub_cache).expanduser()
    hf_home = os.environ.get("HF_HOME")
    if hf_home:
        return Path(hf_home).expanduser() / "hub"
    return Path.home() / ".cache" / "huggingface" / "hub"


def hf_cache_model_root(repo_id: str) -> Path:
    return hf_hub_cache_dir() / ("models--" + repo_id.replace("/", "--"))


def resolve_model_dir(input_dir: Path) -> tuple[Path, list[str]]:
    """Accept either a snapshot directory or a HF cache model root."""

    warnings: list[str] = []
    model_dir = input_dir.expanduser().resolve()
    if (model_dir / "config.json").exists():
        return model_dir, warnings

    snapshots_dir = model_dir / "snapshots"
    if not snapshots_dir.is_dir():
        return model_dir, warnings

    snapshots = sorted(
        [path for path in snapshots_dir.iterdir() if path.is_dir()],
        key=lambda path: path.name,
    )
    if not snapshots:
        return model_dir, warnings

    ref_revision = read_ref_revision(model_dir, "main")
    if ref_revision:
        snapshot = snapshots_dir / ref_revision
        if not snapshot.is_dir():
            raise ValueError(
                f"HF refs/main points to {ref_revision}, but snapshot is missing: {snapshot}"
            )
        warnings.append(f"using HF refs/main snapshot: {ref_revision}")
        return snapshot.resolve(), warnings

    if len(snapshots) == 1:
        warnings.append(
            f"HF refs/main not found; using the only local snapshot: {snapshots[0].name}"
        )
        return snapshots[0].resolve(), warnings

    raise ValueError(
        "multiple HF snapshots found, but refs/main is missing; cannot determine latest revision"
    )


def resolve_model_ref(model_ref: str) -> tuple[Path, list[str], str | None]:
    """Resolve a HF model name or local path to a concrete snapshot directory."""

    candidate = Path(model_ref).expanduser()
    if candidate.exists():
        model_dir, warnings = resolve_model_dir(candidate)
        return model_dir, warnings, None

    if model_ref.startswith(("/", "~", ".")):
        raise ValueError(f"model path does not exist: {model_ref}")

    repo_id = model_ref.strip()
    if not repo_id or "/" not in repo_id:
        raise ValueError(
            "model must be a HuggingFace repo id like Qwen/Qwen3-8B "
            "or an existing local path"
        )

    model_root = hf_cache_model_root(repo_id)
    if not model_root.is_dir():
        raise ValueError(
            f"HF cache for {repo_id} was not found at {model_root}. "
            "Download the model with vLLM/HuggingFace first."
        )

    model_dir, warnings = resolve_model_dir(model_root)
    return model_dir, [f"resolved {repo_id} to local HF cache: {model_root}"] + warnings, repo_id


def infer_hf_identity(model_dir: Path) -> tuple[str | None, str | None]:
    """Infer repo_id and revision from a HuggingFace cache snapshot path."""

    parts = model_dir.resolve().parts
    revision: str | None = None
    repo_id: str | None = None
    for idx, part in enumerate(parts):
        if part == "snapshots" and idx + 1 < len(parts):
            revision = parts[idx + 1]
            for prev in reversed(parts[:idx]):
                if prev.startswith("models--"):
                    repo_id = prev.removeprefix("models--").replace("--", "/")
                    break
            break
    return repo_id, revision


def find_file(model_dir: Path, name: str) -> Path | None:
    candidate = model_dir / name
    if candidate.exists():
        return candidate
    matches = sorted(model_dir.rglob(name), key=lambda p: p.as_posix())
    return matches[0] if matches else None


def hash_file_or_empty(domain: str, path: Path | None) -> str:
    if path is None:
        return EMPTY_BYTES32
    return h_v1(domain, path.read_bytes())


def hash_chat_template(model_dir: Path, tokenizer_config: dict[str, Any] | None) -> tuple[str, str]:
    template_file = find_file(model_dir, "chat_template.jinja")
    if template_file is not None:
        return (
            h_v1("TRUEOPEN_MODEL_CHAT_TEMPLATE_V1", template_file.read_bytes()),
            template_file.relative_to(model_dir).as_posix(),
        )
    if tokenizer_config and isinstance(tokenizer_config.get("chat_template"), str):
        payload = tokenizer_config["chat_template"].encode("utf-8")
        return h_v1("TRUEOPEN_MODEL_CHAT_TEMPLATE_V1", payload), "tokenizer_config.json:chat_template"
    return EMPTY_BYTES32, "empty"


def hash_quant_config(model_dir: Path, config: dict[str, Any]) -> tuple[str, str]:
    quant_file = find_file(model_dir, "quantization_config.json") or find_file(
        model_dir, "quant_config.json"
    )
    if quant_file is not None:
        return (
            h_v1("TRUEOPEN_MODEL_QUANT_CONFIG_V1", quant_file.read_bytes()),
            quant_file.relative_to(model_dir).as_posix(),
        )
    quant_config = config.get("quantization_config")
    if isinstance(quant_config, dict):
        return (
            h_v1("TRUEOPEN_MODEL_QUANT_CONFIG_V1", canonical_json_bytes(quant_config)),
            "config.json:quantization_config",
        )
    return EMPTY_BYTES32, "empty"


def tokenizer_bundle_hash(files: list[dict[str, Any]]) -> tuple[str, list[str]]:
    tokenizer_roles = {"TOKENIZER", "TOKENIZER_CONFIG", "CHAT_TEMPLATE"}
    bundle = [
        {
            "digest": item["digest"],
            "path": item["path"],
            "role": item["role"],
            "size_bytes": item["size_bytes"],
        }
        for item in files
        if item["role"] in tokenizer_roles
    ]
    bundle.sort(key=lambda item: item["path"].encode("utf-8"))
    return h_v1("TRUEOPEN_MODEL_TOKENIZER_BUNDLE_V1", canonical_json_bytes(bundle)), [
        item["path"] for item in bundle
    ]


def weight_bundle_hash(files: list[dict[str, Any]]) -> tuple[str, list[str]]:
    shards = [
        {
            "digest": item["digest"],
            "path": item["path"],
            "size_bytes": item["size_bytes"],
        }
        for item in files
        if item["role"] == "WEIGHT_SHARD"
    ]
    shards.sort(key=lambda item: item["path"].encode("utf-8"))
    return h_v1("TRUEOPEN_MODEL_WEIGHT_BUNDLE_V1", canonical_json_bytes(shards)), [
        item["path"] for item in shards
    ]


def dtype_bits(dtype: str | None) -> tuple[str, int]:
    normalized = (dtype or "").lower()
    if normalized in {"bfloat16", "bf16", "torch.bfloat16"}:
        return "BF16", 16
    if normalized in {"float16", "fp16", "torch.float16", "half"}:
        return "FP16", 16
    if normalized in {"float32", "fp32", "torch.float32"}:
        return "FP32", 32
    if normalized:
        return normalized.upper(), 0
    return "UNKNOWN", 0


def infer_quantization(config: dict[str, Any]) -> dict[str, Any]:
    quant = config.get("quantization_config")
    if isinstance(quant, dict):
        method = str(quant.get("quant_method") or quant.get("method") or "UNKNOWN").upper()
        bits = quant.get("bits")
        if not isinstance(bits, int):
            if quant.get("load_in_4bit"):
                bits = 4
            elif quant.get("load_in_8bit"):
                bits = 8
            else:
                bits = 0
        return {"method": method, "bits": bits}
    method, bits = dtype_bits(config.get("torch_dtype") or config.get("dtype"))
    return {"method": method, "bits": bits}


def infer_context_length(config: dict[str, Any]) -> int:
    for key in (
        "max_position_embeddings",
        "seq_length",
        "n_positions",
        "max_sequence_length",
        "model_max_length",
    ):
        value = config.get(key)
        if isinstance(value, int) and value > 0:
            return value
    return 0


def tensor_count_from_safetensors(path: Path) -> int:
    with path.open("rb") as f:
        header_len_bytes = f.read(8)
        if len(header_len_bytes) != 8:
            return 0
        header_len = struct.unpack("<Q", header_len_bytes)[0]
        header = json.loads(f.read(header_len))
    count = 0
    for name, meta in header.items():
        if name == "__metadata__" or not isinstance(meta, dict):
            continue
        shape = meta.get("shape")
        if isinstance(shape, list) and all(isinstance(dim, int) for dim in shape):
            count += math.prod(shape)
    return count


def estimate_parameter_count(model_dir: Path, files: list[dict[str, Any]]) -> int:
    total = 0
    for item in files:
        if item["role"] != "WEIGHT_SHARD" or not item["path"].endswith(".safetensors"):
            continue
        total += tensor_count_from_safetensors(model_dir / item["path"])
    return total


def infer_moe(config: dict[str, Any]) -> dict[str, Any]:
    num_experts = config.get("num_experts") or config.get("num_routed_experts") or 0
    num_experts_per_tok = (
        config.get("num_experts_per_tok")
        or config.get("num_experts_per_token")
        or config.get("top_k")
        or 0
    )
    enabled = bool(isinstance(num_experts, int) and num_experts > 0)
    return {
        "enabled": enabled,
        "num_experts": num_experts if isinstance(num_experts, int) else 0,
        "num_experts_per_tok": (
            num_experts_per_tok if isinstance(num_experts_per_tok, int) else 0
        ),
    }


def architecture_from_config(config: dict[str, Any]) -> str:
    architectures = config.get("architectures")
    if isinstance(architectures, list) and any(
        isinstance(item, str) and "CausalLM" in item for item in architectures
    ):
        return "causal_lm"
    return "causal_lm"


def extract_eos_token_ids(generation_config: dict[str, Any] | None) -> list[int]:
    """output_decoding.eos_token_ids from generation_config."""

    if not generation_config:
        return []
    value = generation_config.get("eos_token_id")
    ids: list[int] = []
    if isinstance(value, bool):
        return []
    if isinstance(value, int):
        ids = [value]
    elif isinstance(value, list):
        ids = [v for v in value if isinstance(v, int) and not isinstance(v, bool)]
    return sorted(set(ids))


# ---------------------------------------------------------------------------
# Parser blocks & manifest_uri
# ---------------------------------------------------------------------------


def build_parser_ref(name: str, version: int) -> dict[str, Any]:
    """ParserRefV1: {name, version} when named, else the empty {} = not supported."""

    if not name:
        return {}
    if version < 1:
        raise ValueError("parser version must be >= 1 when a parser name is given")
    return {"name": name, "version": version}


def validate_manifest_uri(uri: str) -> None:
    """Minimal legal syntax for manifest_uri, draft-permissive on empty."""

    if not uri:
        return
    if any(ord(c) < 0x21 or ord(c) > 0x7E for c in uri):
        raise ValueError("manifest_uri must be ASCII printable, no whitespace/control chars")
    length = len(uri.encode("utf-8"))
    if not (1 <= length <= MAX_MANIFEST_URI_BYTES):
        raise ValueError(f"manifest_uri length must be 1..{MAX_MANIFEST_URI_BYTES} bytes")
    if not (uri.startswith("https://") or uri.startswith("ipfs://")):
        raise ValueError("manifest_uri scheme must be https:// or ipfs://")


# ---------------------------------------------------------------------------
# Manifest assembly
# ---------------------------------------------------------------------------


def build_manifest(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    model_dir, path_warnings, repo_id_from_ref = resolve_model_ref(args.model)
    if not model_dir.is_dir():
        raise ValueError(f"model dir does not exist: {model_dir}")

    inferred_repo_id, inferred_revision = infer_hf_identity(model_dir)
    repo_id = repo_id_from_ref or args.hf_repo_id or inferred_repo_id
    revision = inferred_revision
    warnings: list[str] = list(path_warnings)
    assumptions: list[str] = [
        "tokenizer_hash payload is canonical JSON of tokenizer-related file digest records",
        "model_weight_digest payload is canonical JSON of ordered weight shard digest records",
        "file_manifest_hash payload is canonical JSON of included model file records",
        "missing optional artifact hashes use EMPTY_BYTES32",
        "model_id = H_FIELDS_V1(TRUEOPEN_MODEL_ID_V1, chain_id, provider, repo_id, proposer_address)",
    ]

    if not repo_id:
        raise ValueError("--hf-repo-id is required when repo_id cannot be inferred")
    if not revision:
        raise ValueError(
            "HF revision cannot be inferred. Pass a HF cache repo root with refs/main "
            "or a snapshots/<commit_sha> directory."
        )
    if revision in {"main", "master"}:
        raise ValueError(
            f"resolved HF revision is mutable ({revision}); expected an immutable commit sha"
        )

    config_path = find_file(model_dir, "config.json")
    if config_path is None:
        raise ValueError("config.json not found")
    config = read_json_file(config_path)

    tokenizer_config_path = find_file(model_dir, "tokenizer_config.json")
    tokenizer_config = (
        read_json_file(tokenizer_config_path) if tokenizer_config_path is not None else None
    )
    generation_config_path = find_file(model_dir, "generation_config.json")
    generation_config = (
        read_json_file(generation_config_path) if generation_config_path is not None else None
    )

    files = discover_model_files(model_dir, args.include_readme)

    # Optionally merge a registrant-authored DECODE_VECTORS file that lives outside
    # the snapshot (it is a TrueOpen artifact, not an HF download).
    if args.decode_vectors_path:
        dv_path = Path(args.decode_vectors_path).expanduser()
        if not dv_path.is_file():
            raise ValueError(f"--decode-vectors-path not found: {dv_path}")
        try:
            rel = dv_path.resolve().relative_to(model_dir).as_posix()
        except ValueError:
            rel = args.decode_vectors_manifest_path
        if not any(item["path"] == rel for item in files):
            files.append(
                {
                    "path": rel,
                    "role": "DECODE_VECTORS",
                    "size_bytes": dv_path.stat().st_size,
                    "digest": sha256_file(dv_path),
                }
            )
            files.sort(key=lambda item: item["path"].encode("utf-8"))

    if not files:
        raise ValueError("no model files discovered")

    weight_digest, weight_paths = weight_bundle_hash(files)
    if not weight_paths:
        warnings.append("no WEIGHT_SHARD files discovered; model_weight_digest is hash of empty list")

    tokenizer_hash, tokenizer_paths = tokenizer_bundle_hash(files)
    if not tokenizer_paths:
        warnings.append("no tokenizer-related files discovered")

    tokenizer_config_hash = hash_file_or_empty(
        "TRUEOPEN_MODEL_TOKENIZER_CONFIG_V1", tokenizer_config_path
    )
    chat_template_hash, chat_template_source = hash_chat_template(model_dir, tokenizer_config)
    quant_config_hash, quant_config_source = hash_quant_config(model_dir, config)

    estimated_params = estimate_parameter_count(model_dir, files)
    if not estimated_params:
        warnings.append(
            "parameter count could not be estimated from safetensors headers; override with --total-params"
        )

    total_params = args.total_params or estimated_params
    active_params = args.active_params or total_params
    if not total_params:
        warnings.append("model_config_summary.total_params is 0")

    quantization = infer_quantization(config)
    model_type = str(config.get("model_type") or "unknown")
    display_name = args.display_name or repo_id.split("/")[-1].replace("-", " ")

    model_id = args.model_id or compute_model_id(
        args.chain_id, SUPPORTED_PROVIDER, repo_id, args.proposer_address
    )

    # --- output_decoding ---
    decode_vectors_entry = next(
        (item for item in files if item["role"] == "DECODE_VECTORS"), None
    )
    decode_vectors_path = decode_vectors_entry["path"] if decode_vectors_entry else ""
    if not decode_vectors_entry:
        warnings.append(
            "no DECODE_VECTORS file; output_decoding.decode_vectors_path is empty. "
            "A registrant-authored decode vectors file is REQUIRED for real registration "
            "; provide it via --decode-vectors-path before submitting."
        )
    eos_token_ids = extract_eos_token_ids(generation_config)
    if not eos_token_ids:
        warnings.append(
            "output_decoding.eos_token_ids is empty (no eos_token_id in generation_config); "
            "registration requires a non-empty, ascending, unique set"
        )
    output_decoding = {
        "decoder": "HF_TOKENIZERS_V1",
        "eos_token_ids": eos_token_ids,
        "strip_trailing_eos": True,
        "render_special_tokens": True,
        "clean_up_tokenization_spaces": False,
        "decode_vectors_path": decode_vectors_path,
    }

    # --- tool_calling / reasoning_parsing ---
    tool_call_parser = build_parser_ref(args.tool_call_parser_name, args.tool_call_parser_version)
    reasoning_parser = build_parser_ref(args.reasoning_parser_name, args.reasoning_parser_version)
    if tool_call_parser:
        tool_calling: dict[str, Any] = {
            "parser": tool_call_parser,
            "call_id_format": args.call_id_format,
        }
    else:
        tool_calling = {}
        warnings.append(
            "tool_calling is empty {} (no --tool-call-parser-name): profile declares NO tool calling"
        )
    if reasoning_parser:
        reasoning_parsing: dict[str, Any] = {"parser": reasoning_parser}
    else:
        reasoning_parsing = {}
        warnings.append(
            "reasoning_parsing is empty {} (no --reasoning-parser-name): profile declares NO reasoning split"
        )

    verification_profile = {
        "verification_profile_id": args.verification_profile_id,
        "judgment_function_version": "PREFILL_GENERATED_TOKEN_METRICS_V1",
        "canonical_encoding_version": args.canonical_encoding_version,
        "evidence_schema_hash": "",  # derived below from the typed evidence_schema
        "evidence_schema": read_optional_json_arg(
            args.evidence_schema_json, DEFAULT_EVIDENCE_SCHEMA
        ),
        "metric_aggregate_proof_version": args.metric_aggregate_proof_version,
        "verification_mode": args.verification_mode,
        "token_scope": "ALL_GENERATED_OUTPUT_TOKENS",
        "include_generated_special_tokens": True,
        "include_prompt_tokens": False,
        "include_padding_tokens": False,
        "require_output_token_ids": True,
        "require_finish_reason": True,
        "metrics": {
            "compare_logprob_diff": True,
            "compare_rank_delta": True,
            "compare_topk_jaccard": True,
            "compare_union_js": True,
            "compared_top_k": args.required_top_k,
            "numeric_scale": "FP_1E6",
        },
    }

    verification_thresholds = load_verification_thresholds(args)
    batch_verification = read_optional_json_arg(
        args.batch_verification_json, DEFAULT_BATCH_VERIFICATION
    )

    # evidence_schema_hash is fully derived from the typed evidence_schema (the
    # chain re-derives and checks it), so it is computed here, not a user knob.
    verification_profile["evidence_schema_hash"] = compute_evidence_schema_hash(
        model_id=model_id,
        profile_version=args.profile_version,
        schema_hash=args.schema_hash,
        tokenizer_hash=tokenizer_hash,
        generation_type=args.generation_type,
        required_top_k=args.required_top_k,
        batch_verification=batch_verification,
        verification_profile=verification_profile,
    )

    pricing_profile = read_optional_json_arg(args.pricing_profile_json, DEFAULT_PRICING_PROFILE)
    timeout_bootstrap_profile = read_optional_json_arg(
        args.timeout_bootstrap_profile_json, DEFAULT_TIMEOUT_BOOTSTRAP_PROFILE
    )

    validate_manifest_uri(args.manifest_uri)

    source = {
        "provider": SUPPORTED_PROVIDER,
        "repo_id": repo_id,
        "repo_type": "model",
        "revision": revision,
        "source_uri": f"hf://{repo_id}@{revision}",
        "resolver_version": "HF_RESOLVER_V1",
    }

    manifest = {
        "manifest_version": 4,
        "identity": {
            "model_id": model_id,
            "profile_version": args.profile_version,
            "previous_profile_version": args.previous_profile_version,
            "display_name": display_name,
        },
        "source": source,
        "artifacts": {
            "file_manifest_hash": h_v1(
                "TRUEOPEN_MODEL_FILE_MANIFEST_V1", canonical_json_bytes(files)
            ),
            "files": files,
            "model_weight_digest": weight_digest,
            "model_config_hash": h_v1(
                "TRUEOPEN_MODEL_CONFIG_V1", config_path.read_bytes()
            ),
            "generation_config_hash": hash_file_or_empty(
                "TRUEOPEN_MODEL_GENERATION_CONFIG_V1", generation_config_path
            ),
            "tokenizer_hash": tokenizer_hash,
            "tokenizer_config_hash": tokenizer_config_hash,
            "chat_template_hash": chat_template_hash,
            "quant_config_hash": quant_config_hash,
        },
        "model_config_summary": {
            "model_type": model_type,
            "architecture": architecture_from_config(config),
            "modality": ["TEXT"],
            "total_params": total_params,
            "active_params": active_params,
            "context_length": infer_context_length(config),
            "quantization": quantization,
            "moe": infer_moe(config),
        },
        "runtime_requirements": {
            "recommended_engine": args.recommended_engine,
            "recommended_engine_version": args.recommended_engine_version,
            "runtime_class": args.runtime_class,
            "required_top_k": args.required_top_k,
            "required_capabilities": list(DEFAULT_REQUIRED_CAPABILITIES),
        },
        "output_decoding": output_decoding,
        "tool_calling": tool_calling,
        "reasoning_parsing": reasoning_parsing,
        "profile_spec": {
            "task_types": args.task_types,
            "generation_type": args.generation_type,
            "schema_hash": args.schema_hash,
            "resource_tier": args.resource_tier,
            "min_stake": {
                "denom": args.denom,
                "amount": args.min_stake_amount,
            },
            "challenge_open_window_blocks": args.challenge_open_window_blocks,
            "require_encrypted": False,
        },
        "verification_profile": verification_profile,
        "verification_thresholds": verification_thresholds,
        "batch_verification": batch_verification,
        "pricing_profile": pricing_profile,
        "timeout_bootstrap_profile": timeout_bootstrap_profile,
        "metadata": {
            "license_ref": args.license_ref,
            "metadata_uri": args.metadata_uri,
            "display_tag_hash": args.display_tag_hash,
        },
    }

    derivation = {
        "model_ref": args.model,
        "model_dir": str(model_dir),
        "warnings": warnings,
        "assumptions": assumptions,
        # evidence_schema_hash is now derived (not a placeholder); only
        # schema_hash still needs the authoritative producer.
        "placeholder_fields": [
            name
            for name, value in {
                "schema_hash": args.schema_hash,
            }.items()
            if value == PLACEHOLDER_SCHEMA_HASH
        ],
        "artifact_sources": {
            "config_path": config_path.relative_to(model_dir).as_posix(),
            "generation_config_path": (
                generation_config_path.relative_to(model_dir).as_posix()
                if generation_config_path
                else ""
            ),
            "tokenizer_config_path": (
                tokenizer_config_path.relative_to(model_dir).as_posix()
                if tokenizer_config_path
                else ""
            ),
            "chat_template_source": chat_template_source,
            "quant_config_source": quant_config_source,
            "weight_paths": weight_paths,
            "tokenizer_paths": tokenizer_paths,
        },
    }
    return manifest, derivation


# ---------------------------------------------------------------------------
# Chain projection V3 + registration payload
# ---------------------------------------------------------------------------


def build_chain_projection(
    manifest: dict[str, Any],
    manifest_hash: str,
    args: argparse.Namespace,
) -> dict[str, Any]:
    """The MsgRegisterModelProfile profile projection (ProfileState-bound fields).

    Display metadata/tags (license, metadata_uri, display_tag_hash) do NOT enter the
    projection or chain state. registration_fee IS part of the
    canonical projection -- it enters chain_projection_hash and, through it, the
    registration digest -- matching wire's model_profile_canonical_v3.json golden
    vector and the chain's CanonicalModelProfileProjection. Only proposer_address
    stays a Msg-envelope field carried outside the projection.
    """

    profile_spec = manifest["profile_spec"]
    runtime = manifest["runtime_requirements"]
    identity = manifest["identity"]
    return {
        "model_id": identity["model_id"],
        "profile_version": identity["profile_version"],
        "previous_profile_version": identity["previous_profile_version"],
        "manifest_hash": manifest_hash,
        "manifest_uri": args.manifest_uri,
        "registration_fee": {
            "denom": args.denom,
            "amount": args.registration_fee_amount,
        },
        "source": manifest["source"],
        "tokenizer_hash": manifest["artifacts"]["tokenizer_hash"],
        "runtime_class": runtime["runtime_class"],
        "required_top_k": runtime["required_top_k"],
        "task_types": profile_spec["task_types"],
        "generation_type": profile_spec["generation_type"],
        "tool_call_parser": manifest["tool_calling"].get("parser", {}),
        "reasoning_parser": manifest["reasoning_parsing"].get("parser", {}),
        "resource_tier": profile_spec["resource_tier"],
        "min_stake": profile_spec["min_stake"],
        "challenge_open_window_blocks": profile_spec["challenge_open_window_blocks"],
        "schema_hash": profile_spec["schema_hash"],
        "verification_profile": manifest["verification_profile"],
        "verification_thresholds": manifest["verification_thresholds"],
        "batch_verification": manifest["batch_verification"],
        "pricing_profile": manifest["pricing_profile"],
        "timeout_bootstrap_profile": manifest["timeout_bootstrap_profile"],
    }


def build_registration_package(
    manifest: dict[str, Any],
    derivation: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    canonical_manifest = canonical_json_bytes(manifest)
    manifest_hash = h_v1("TRUEOPEN_MODEL_MANIFEST_V4", canonical_manifest)

    chain_projection = build_chain_projection(manifest, manifest_hash, args)
    chain_projection_bytes = canonical_json_bytes(chain_projection)
    chain_projection_hash = h_v1(
        "TRUEOPEN_MODEL_CHAIN_PROJECTION_V3", chain_projection_bytes
    )
    registration_payload = {
        "chain_id": args.chain_id,
        "chain_projection_hash": chain_projection_hash,
        "manifest_hash": manifest_hash,
        "profile_version": manifest["identity"]["profile_version"],
        "proposer_address": args.proposer_address,
    }
    registration_payload_bytes = canonical_json_bytes(registration_payload)
    registration_digest = h_v1(
        "TRUEOPEN_MODEL_REGISTRATION_DIGEST_V3", registration_payload_bytes
    )

    registration_fee = {"denom": args.denom, "amount": args.registration_fee_amount}

    # MsgRegisterModelProfile = profile projection + Msg-envelope fields.
    # Authorization is the proposer's Cosmos Tx signature over the whole Msg;
    # there is no separate registrant_signature field.
    msg_register_model_profile = dict(chain_projection)
    msg_register_model_profile["registration_fee"] = registration_fee
    msg_register_model_profile["proposer_address"] = args.proposer_address

    # expected ProfileState = chain_projection + keeper-owned fields.
    expected_profile_state = dict(chain_projection)
    expected_profile_state.update(
        {
            "status": "REGISTERED",
            "ref_price": manifest["pricing_profile"]["initial_output_price"],
            "registration_fee_paid": registration_fee,
        }
    )

    # expected ModelState created on first profile of this model_id.
    expected_model_state = {
        "model_id": manifest["identity"]["model_id"],
        "provider": manifest["source"]["provider"],
        "repo_id": manifest["source"]["repo_id"],
        "status": "REGISTERED",
        "active_supporter_count": 0,
        "active_support_stake": 0,
        "status_source": "AUTO_SUPPORT",
        "registration_fee_paid": registration_fee["amount"],
    }

    return {
        "manifest_hash": manifest_hash,
        "chain_projection_hash": chain_projection_hash,
        "registration_digest": registration_digest,
        "registration_payload": registration_payload,
        "chain_projection": chain_projection,
        "msg_register_model_profile": msg_register_model_profile,
        "expected_profile_state": expected_profile_state,
        "expected_model_state": expected_model_state,
        "canonical_manifest_bytes_hex": canonical_manifest.hex(),
        "chain_projection_bytes_hex": chain_projection_bytes.hex(),
        "registration_payload_bytes": registration_payload_bytes.decode("utf-8"),
        "derivation": derivation,
    }


# ---------------------------------------------------------------------------
# cortexctl ProtoJSON profile (cmd/cortexctl `model manifest generate --profile`)
# ---------------------------------------------------------------------------


def _hash_to_protojson_base64(value: str) -> str:
    """0x-prefixed 32-byte hex -> ProtoJSON std base64 (cortex ProtoBytes32)."""

    raw = bytes.fromhex(value[2:] if value.startswith("0x") else value)
    if len(raw) != 32:
        raise ValueError(f"expected a 32-byte hash, got {len(raw)} bytes: {value!r}")
    return base64.b64encode(raw).decode("ascii")


def _enum_with_prefix(value: str, prefix: str) -> str:
    """Re-attach the proto enum prefix the canonical projection strips."""

    return value if value.startswith(prefix) else prefix + value


def build_cortexctl_profile(chain_projection: dict[str, Any]) -> dict[str, Any]:
    """ModelProfileProjection in cortex ProtoJSON, ready for
    `cortexctl model manifest generate --profile <file>`.

    This is the SAME projection as chain_projection.canonical.json, re-encoded
    into the ProtoJSON shape cortex/internal/txclient decodes
    (ModelProfileProjectionMessage):
      - bytes32 (model_id / manifest_hash / tokenizer_hash / schema_hash /
        evidence_schema_hash): std base64 of the raw 32 bytes, not 0x-hex.
      - uint32 -> JSON number; uint64 -> quoted decimal string.
      - enums carry their proto prefix (TASK_TYPE_/GENERATION_TYPE_/
        VERIFICATION_MODE_/TOKEN_SCOPE_/NUMERIC_SCALE_/EVIDENCE_KIND_); cortex
        trims the prefix again when it recomputes the canonical projection.
      - an absent parser is {}.

    cortex re-derives chain_projection_hash / registration_digest from this file,
    so the on-chain digest still matches wire's golden vector. evidence_schema_hash
    is derived by this tool and passes cortex's check. The one field cortex still
    needs is a real schema_hash (the component-schema merged hash from the
    authoritative producer): with the tool's placeholder schema_hash the profile
    is structurally valid but production registration should replace it first.
    """

    def parser(ref: dict[str, Any]) -> dict[str, Any]:
        if not ref:
            return {}
        return {"name": ref["name"], "version": ref["version"]}

    vp = chain_projection["verification_profile"]
    metrics = vp["metrics"]
    evidence = vp["evidence_schema"]
    min_stake = chain_projection["min_stake"]
    fee = chain_projection["registration_fee"]
    pricing = chain_projection["pricing_profile"]
    timeout = chain_projection["timeout_bootstrap_profile"]

    return {
        "model_id": _hash_to_protojson_base64(chain_projection["model_id"]),
        "profile_version": chain_projection["profile_version"],
        "manifest_hash": _hash_to_protojson_base64(chain_projection["manifest_hash"]),
        "tokenizer_hash": _hash_to_protojson_base64(chain_projection["tokenizer_hash"]),
        "runtime_class": chain_projection["runtime_class"],
        "required_top_k": chain_projection["required_top_k"],
        "task_types": [
            _enum_with_prefix(t, "TASK_TYPE_") for t in chain_projection["task_types"]
        ],
        "generation_type": _enum_with_prefix(
            chain_projection["generation_type"], "GENERATION_TYPE_"
        ),
        "resource_tier": chain_projection["resource_tier"],
        "min_stake": {"denom": min_stake["denom"], "amount": str(min_stake["amount"])},
        "challenge_open_window_blocks": str(chain_projection["challenge_open_window_blocks"]),
        "verification_profile": {
            "verification_profile_id": vp["verification_profile_id"],
            "judgment_function_version": vp["judgment_function_version"],
            "verification_mode": _enum_with_prefix(
                vp["verification_mode"], "VERIFICATION_MODE_"
            ),
            "token_scope": _enum_with_prefix(vp["token_scope"], "TOKEN_SCOPE_"),
            "include_generated_special_tokens": vp["include_generated_special_tokens"],
            "include_prompt_tokens": vp["include_prompt_tokens"],
            "include_padding_tokens": vp["include_padding_tokens"],
            "require_output_token_ids": vp["require_output_token_ids"],
            "require_finish_reason": vp["require_finish_reason"],
            "metrics": {
                "compare_logprob_diff": metrics["compare_logprob_diff"],
                "compare_rank_delta": metrics["compare_rank_delta"],
                "compare_topk_jaccard": metrics["compare_topk_jaccard"],
                "compare_union_js": metrics["compare_union_js"],
                "compared_top_k": metrics["compared_top_k"],
                "numeric_scale": _enum_with_prefix(
                    metrics["numeric_scale"], "NUMERIC_SCALE_"
                ),
            },
            "canonical_encoding_version": vp["canonical_encoding_version"],
            "evidence_schema_hash": _hash_to_protojson_base64(vp["evidence_schema_hash"]),
            "metric_aggregate_proof_version": vp["metric_aggregate_proof_version"],
            "evidence_schema": {
                "schema_version": evidence["schema_version"],
                "required_infer_evidence": [
                    {
                        "evidence_kind": _enum_with_prefix(
                            req["evidence_kind"], "EVIDENCE_KIND_"
                        ),
                        "commitment_schema_version": req["commitment_schema_version"],
                        "max_encoded_size_bytes": str(req["max_encoded_size_bytes"]),
                    }
                    for req in evidence["required_infer_evidence"]
                ],
            },
        },
        "verification_thresholds": dict(chain_projection["verification_thresholds"]),
        "batch_verification": dict(chain_projection["batch_verification"]),
        "pricing_profile": {
            "initial_output_price": str(pricing["initial_output_price"]),
            "verify_ratio_bps": pricing["verify_ratio_bps"],
            "min_order_value": str(pricing["min_order_value"]),
        },
        "timeout_bootstrap_profile": {
            "infer_timeout_bootstrap_blocks": timeout["infer_timeout_bootstrap_blocks"],
            "verify_timeout_bootstrap_blocks": timeout["verify_timeout_bootstrap_blocks"],
            "commit_timeout_bootstrap_blocks": timeout["commit_timeout_bootstrap_blocks"],
            "bootstrap_valid_until_epoch": str(timeout["bootstrap_valid_until_epoch"]),
        },
        "schema_hash": _hash_to_protojson_base64(chain_projection["schema_hash"]),
        "previous_profile_version": chain_projection["previous_profile_version"],
        "registration_fee": {"denom": fee["denom"], "amount": str(fee["amount"])},
        "source": {
            "provider": chain_projection["source"]["provider"],
            "source_uri": chain_projection["source"]["source_uri"],
            "revision": chain_projection["source"]["revision"],
            "resolver_version": chain_projection["source"]["resolver_version"],
            "repo_id": chain_projection["source"]["repo_id"],
            "repo_type": chain_projection["source"]["repo_type"],
        },
        "tool_call_parser": parser(chain_projection["tool_call_parser"]),
        "reasoning_parser": parser(chain_projection["reasoning_parser"]),
        "manifest_uri": chain_projection["manifest_uri"],
    }


def write_outputs(
    output_dir: Path,
    manifest: dict[str, Any],
    package: dict[str, Any],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    # manifest.canonical.json holds the EXACT canonical bytes that manifest_hash is
    # computed over (H_V1("TRUEOPEN_MODEL_MANIFEST_V4", these bytes)). This is the file
    # to host at manifest_uri: retrievers recompute the hash over the exact bytes they
    # download, so it must have NO trailing newline and no reformatting.
    (output_dir / "manifest.canonical.json").write_bytes(canonical_json_bytes(manifest))

    text_files = {
        # Human-readable view only; do NOT host this one (indentation changes the bytes).
        "manifest.pretty.json": json.dumps(
            manifest, ensure_ascii=False, sort_keys=True, indent=2
        )
        + "\n",
        "chain_projection.canonical.json": canonical_json_bytes(
            package["chain_projection"]
        ).decode("utf-8")
        + "\n",
        "registration_data.json": json.dumps(
            package, ensure_ascii=False, sort_keys=True, indent=2
        )
        + "\n",
        # The ProtoJSON ModelProfileProjection to pass to
        # `cortexctl model manifest generate --profile <this file>`. cortex
        # re-canonicalizes it, so its own formatting is not hash-bound.
        "profile.json": json.dumps(
            build_cortexctl_profile(package["chain_projection"]),
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
    }
    for name, content in text_files.items():
        (output_dir / name).write_text(content, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a model's V4 manifest and registration profile from a local HF snapshot."
    )
    parser.add_argument(
        "--model",
        required=True,
        help="HF model name like Qwen/Qwen3-8B, a local HF cache repo root, or a snapshots/<commit> directory",
    )
    parser.add_argument("--output-dir", default="", help="Directory for generated files")
    parser.add_argument(
        "--hf-repo-id",
        default="",
        help="HF repo id (namespace/name); needed only when --model is a plain local path",
    )
    parser.add_argument(
        "--model-id",
        default="",
        help="Override model_id (else derived via TRUEOPEN_MODEL_ID_V1)",
    )
    parser.add_argument("--display-name", default="", help="Manifest display name")
    parser.add_argument("--profile-version", type=int, default=1)
    parser.add_argument("--previous-profile-version", type=int, default=0)
    parser.add_argument("--task-types", nargs="+", default=["TEXT_GENERATION", "CHAT"])
    parser.add_argument("--generation-type", default="SAMPLED")
    parser.add_argument(
        "--schema-hash",
        default=PLACEHOLDER_SCHEMA_HASH,
        help="input/output component schema merged hash (bytes32); default is a PLACEHOLDER "
        "(shown in placeholder_fields) — set the real value before on-chain registration",
    )
    # No --evidence-schema-hash: it is auto-derived under TRUEOPEN_EVIDENCE_SCHEMA_V1
    # from the typed evidence_schema. Shape the schema via --evidence-schema-json.
    parser.add_argument("--evidence-schema-json", default="")
    parser.add_argument("--display-tag-hash", default=EMPTY_BYTES32)
    parser.add_argument("--resource-tier", type=int, default=2)
    parser.add_argument(
        "--denom",
        default="uusdc",
        help="business_denom for min_stake / registration_fee; must equal Genesis business_denom "
        "byte-for-byte (default 'uusdc' is the golden-vector value, not necessarily production)",
    )
    parser.add_argument("--min-stake-amount", type=int, default=1000000)
    parser.add_argument("--registration-fee-amount", type=int, default=1000000)
    parser.add_argument("--challenge-open-window-blocks", type=int, default=100)
    parser.add_argument("--runtime-class", default="CAUSAL_LM_PREFILL_LOGPROBS_V1")
    parser.add_argument("--required-top-k", type=int, default=20)
    parser.add_argument("--recommended-engine", default="vllm")
    parser.add_argument("--recommended-engine-version", default="0.8.x")
    parser.add_argument(
        "--manifest-uri",
        required=True,
        help="https:// or ipfs:// manifest pointer; required",
    )
    parser.add_argument("--tool-call-parser-name", default="", help="canonical tool-call parser name; empty = unsupported")
    parser.add_argument("--tool-call-parser-version", type=int, default=1)
    parser.add_argument("--call-id-format", default="OPENAI_CALL_PREFIX")
    parser.add_argument("--reasoning-parser-name", default="", help="canonical reasoning parser name; empty = none")
    parser.add_argument("--reasoning-parser-version", type=int, default=1)
    parser.add_argument("--decode-vectors-path", default="", help="REQUIRED unless a DECODE_VECTORS file is already inside the model dir: path to a DECODE_VECTORS file to hash and include")
    parser.add_argument("--decode-vectors-manifest-path", default="trueopen/decode_vectors.json")
    parser.add_argument("--verification-profile-id", type=int, default=1)
    parser.add_argument("--verification-mode", default="SINGLE_SAMPLE")
    parser.add_argument("--canonical-encoding-version", default="CANONICAL_OUTPUT_TEXT_V1")
    parser.add_argument(
        "--metric-aggregate-proof-version",
        default="PREFILL_METRIC_AGGREGATE_PROOF_V1",
    )
    parser.add_argument(
        "--thresholds",
        default="",
        help="calibration recommended_thresholds.json (tools/workerverifycalibration); "
        "needs --min-finite-count. Exclusive with --verification-thresholds-json",
    )
    parser.add_argument(
        "--min-finite-count",
        type=int,
        default=None,
        help="pass_min_finite_count for --thresholds; a report rule `finite_count > 5` means 6",
    )
    parser.add_argument(
        "--max-missing-compared-count",
        type=int,
        default=None,
        help="override pass_max_missing_compared_count (default: calibration pass.missing_compared_count_max)",
    )
    parser.add_argument(
        "--verification-thresholds-json",
        default="",
        help="14-field verification_thresholds JSON, used as is. Exclusive with --thresholds",
    )
    parser.add_argument("--batch-verification-json", default="")
    parser.add_argument("--pricing-profile-json", default="")
    parser.add_argument("--timeout-bootstrap-profile-json", default="")
    parser.add_argument("--license-ref", default="unknown")
    parser.add_argument("--metadata-uri", default="")
    parser.add_argument(
        "--chain-id",
        required=True,
        help="target business chain_id (participates in model_id and registration digest); required",
    )
    parser.add_argument(
        "--proposer-address",
        required=True,
        help="registrant / fee payer bech32 address (HRP 'trueopen'); participates in model_id; required",
    )
    parser.add_argument("--total-params", type=int, default=0)
    parser.add_argument("--active-params", type=int, default=0)
    parser.add_argument("--include-readme", action="store_true")

    args = parser.parse_args()
    argv = sys.argv[1:]
    provided: set[str] = set()
    for action in parser._actions:
        for opt in action.option_strings:
            if opt in argv or any(tok.startswith(opt + "=") for tok in argv):
                provided.add(action.dest)
    args._provided = provided
    return args


def review_default_fields(args: argparse.Namespace) -> list[str]:
    """List operational fields still on their built-in default (not user-provided).

    Identity / security / economic-denom fields are argparse-required (no default), so
    they never appear here; this surfaces the remaining defaults for review."""

    provided = getattr(args, "_provided", set())
    scalar_fields = [
        ("denom", "--denom", args.denom),
        ("profile_version", "--profile-version", args.profile_version),
        ("previous_profile_version", "--previous-profile-version", args.previous_profile_version),
        ("task_types", "--task-types", args.task_types),
        ("generation_type", "--generation-type", args.generation_type),
        ("resource_tier", "--resource-tier", args.resource_tier),
        ("min_stake_amount", "--min-stake-amount", args.min_stake_amount),
        ("registration_fee_amount", "--registration-fee-amount", args.registration_fee_amount),
        ("challenge_open_window_blocks", "--challenge-open-window-blocks", args.challenge_open_window_blocks),
        ("runtime_class", "--runtime-class", args.runtime_class),
        ("required_top_k", "--required-top-k", args.required_top_k),
        ("recommended_engine", "--recommended-engine", args.recommended_engine),
        ("recommended_engine_version", "--recommended-engine-version", args.recommended_engine_version),
        ("verification_profile_id", "--verification-profile-id", args.verification_profile_id),
        ("verification_mode", "--verification-mode", args.verification_mode),
        ("canonical_encoding_version", "--canonical-encoding-version", args.canonical_encoding_version),
        ("metric_aggregate_proof_version", "--metric-aggregate-proof-version", args.metric_aggregate_proof_version),
        ("call_id_format", "--call-id-format", args.call_id_format),
        ("license_ref", "--license-ref", args.license_ref),
        ("metadata_uri", "--metadata-uri", args.metadata_uri),
        ("display_tag_hash", "--display-tag-hash", args.display_tag_hash),
    ]
    block_fields = [
        ("evidence_schema_json", "--evidence-schema-json", "built-in evidence_schema (2 entries)"),
        ("batch_verification_json", "--batch-verification-json", "built-in default (batch disabled)"),
        ("pricing_profile_json", "--pricing-profile-json", "built-in default pricing {10/1000/1000}"),
        ("timeout_bootstrap_profile_json", "--timeout-bootstrap-profile-json", "built-in default timeouts"),
    ]
    notices: list[str] = []
    for dest, flag, value in scalar_fields:
        if dest not in provided:
            notices.append(f"{flag} = {value!r}")
    for dest, flag, desc in block_fields:
        if dest not in provided:
            notices.append(f"{flag} -> {desc}")
    return notices


def safe_output_name(model_id: str, profile_version: int) -> str:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", model_id)
    return f"{name}-v{profile_version}"


def main() -> int:
    args = parse_args()
    try:
        manifest, derivation = build_manifest(args)
        package = build_registration_package(manifest, derivation, args)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    output_dir = (
        Path(args.output_dir)
        if args.output_dir
        else Path("out/model-profile")
        / safe_output_name(manifest["identity"]["model_id"], manifest["identity"]["profile_version"])
    )
    write_outputs(output_dir, manifest, package)
    print(f"wrote: {output_dir}")
    print(f"cortexctl --profile: {output_dir / 'profile.json'}")
    print(f"model_id: {manifest['identity']['model_id']}")
    print(f"manifest_hash: {package['manifest_hash']}")
    print(f"chain_projection_hash: {package['chain_projection_hash']}")
    print(f"registration_digest: {package['registration_digest']}")
    if package["derivation"]["warnings"]:
        print("warnings:")
        for warning in package["derivation"]["warnings"]:
            print(f"  - {warning}")
    if package["derivation"]["placeholder_fields"]:
        print("placeholder_fields:")
        for field in package["derivation"]["placeholder_fields"]:
            print(f"  - {field}")
    default_notices = review_default_fields(args)
    if default_notices:
        print("REVIEW — using tool defaults (pass the flag to override):")
        for line in default_notices:
            print(f"  - {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

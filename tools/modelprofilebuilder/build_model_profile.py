#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import math
import os
import re
import struct
import sys
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence


FP_SCALE = 1_000_000
EMPTY_BYTES32_HEX = "0x" + "0" * 64


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


THRESHOLD_FIELDS = [
    ("pass", "mean_abs_logprob_diff_max", "pass_mean_abs_logprob_diff_max", True),
    ("pass", "abs_logprob_diff_p95_max", "pass_abs_logprob_diff_p95_max", True),
    ("pass", "abs_logprob_diff_p99_max", "pass_abs_logprob_diff_p99_max", True),
    ("pass", "rank_delta_nonzero_rate_max", "pass_rank_delta_nonzero_rate_max", True),
    ("pass", "topk_jaccard_mean_min", "pass_topk_jaccard_mean_min", True),
    ("pass", "union_js_p99_max", "pass_union_js_p99_max", True),
    ("reject", "mean_abs_logprob_diff_max", "reject_mean_abs_logprob_diff_min", True),
    ("reject", "abs_logprob_diff_p95_max", "reject_abs_logprob_diff_p95_min", True),
    ("reject", "abs_logprob_diff_p99_max", "reject_abs_logprob_diff_p99_min", True),
    ("reject", "rank_delta_nonzero_rate_max", "reject_rank_delta_nonzero_rate_min", True),
    ("reject", "topk_jaccard_mean_min", "reject_topk_jaccard_mean_max", True),
    ("reject", "union_js_p99_max", "reject_union_js_p99_min", True),
    ("pass", "missing_compared_count_max", "pass_max_missing_compared_count", False),
]


def read_json_object(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def h_v1(domain: str, payload: bytes) -> str:
    domain_bytes = domain.encode("utf-8")
    frame = (
        b"TRUEOPEN_FRAME_V1"
        + len(domain_bytes).to_bytes(4, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    )
    return "0x" + hashlib.sha256(frame).hexdigest()

def nested_fields(fields: Sequence[bytes]) -> bytes:
    return b"".join(len(field).to_bytes(8, "big") + field for field in fields)


def hfields_digest(domain: str, fields: Sequence[bytes]) -> bytes:
    return hashlib.sha256(nested_fields([domain.encode("utf-8"), *fields])).digest()


def evidence_schema_hash(profile: Mapping[str, Any]) -> str:
    verification = as_mapping(profile["verification_profile"])
    schema = as_mapping(verification["evidence_schema"])
    metrics = as_mapping(verification["metrics"])
    batch = as_mapping(profile["batch_verification"])
    enum = {
        "GENERATION_TYPE_DETERMINISTIC": 1, "GENERATION_TYPE_SAMPLED": 2,
        "VERIFICATION_MODE_SINGLE_SAMPLE": 1,
        "TOKEN_SCOPE_ALL_GENERATED_OUTPUT_TOKENS": 1,
        "NUMERIC_SCALE_FP_1E6": 1,
        "EVIDENCE_KIND_WORKER_VALUE_OPENING": 1,
        "EVIDENCE_KIND_VERIFIER_VALUE_OPENING": 2,
        "EVIDENCE_KIND_SETTLEMENT_ROOT_OPENING": 3,
    }
    u32 = lambda value: int(value).to_bytes(4, "big")
    u64 = lambda value: int(value).to_bytes(8, "big")
    boolean = lambda value: b"\x01" if value else b"\x00"
    batch_frame = nested_fields([
        boolean(batch["enabled"]), u32(batch["min_sample_count"]), u32(batch["min_valid_sample_count"]),
        u32(batch["pass_min_sample_pass_ratio_bps"]), u32(batch["reject_min_sample_reject_ratio_bps"]),
    ])
    metric_frame = nested_fields([
        boolean(metrics["compare_logprob_diff"]), boolean(metrics["compare_rank_delta"]),
        boolean(metrics["compare_topk_jaccard"]), boolean(metrics["compare_union_js"]),
        u32(metrics["compared_top_k"]), u32(enum[metrics["numeric_scale"]]),
    ])
    requirements = list(schema["required_infer_evidence"])
    fields = [
        u32(schema["schema_version"]), profile["model_id"].encode(), u32(profile["profile_version"]),
        base64.b64decode(profile["schema_hash"], validate=True), base64.b64decode(profile["tokenizer_hash"], validate=True),
        u32(enum[profile["generation_type"]]), u32(profile["required_top_k"]), batch_frame,
        u32(verification["verification_profile_id"]), verification["judgment_function_version"].encode(),
        verification["canonical_encoding_version"].encode(), verification["metric_aggregate_proof_version"].encode(),
        u32(enum[verification["verification_mode"]]), u32(enum[verification["token_scope"]]),
        boolean(verification["include_generated_special_tokens"]), boolean(verification["include_prompt_tokens"]),
        boolean(verification["include_padding_tokens"]), boolean(verification["require_output_token_ids"]),
        boolean(verification["require_finish_reason"]), metric_frame, u32(len(requirements)),
    ]
    for requirement in requirements:
        fields.append(nested_fields([
            u32(enum[requirement["evidence_kind"]]), u32(requirement["commitment_schema_version"]),
            u64(requirement["max_encoded_size_bytes"]),
        ]))
    return base64.b64encode(hfields_digest("TRUEOPEN_EVIDENCE_SCHEMA_V1", fields)).decode("ascii")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def read_json_file(path: Path) -> Dict[str, Any]:
    payload = read_json_object(path)
    return payload


def as_mapping(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def value_at(payload: Mapping[str, Any], *keys: str) -> Any:
    current: Any = payload
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def parse_uint(value: Any, field: str, bits: int) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an unsigned integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, float) and math.isfinite(value) and value.is_integer():
        parsed = int(value)
    elif isinstance(value, str):
        text = value.strip()
        if text == "":
            raise ValueError(f"{field} must be an unsigned integer")
        parsed = int(text, 10)
    else:
        raise ValueError(f"{field} must be an unsigned integer")
    if parsed < 0 or parsed > (1 << bits) - 1:
        raise ValueError(f"{field} must fit uint{bits}")
    return parsed


def parse_uint32(value: Any, field: str) -> int:
    return parse_uint(value, field, 32)


def parse_threshold(value: Any, field: str, *, fp_scaled: bool) -> int:
    if fp_scaled:
        parsed = parse_uint(value, field, 32)
    else:
        number = float(value)
        if not math.isfinite(number) or number < 0:
            raise ValueError(f"{field} must be a non-negative finite number")
        parsed = int(round(number))
    if parsed < 0 or parsed > (1 << 32) - 1:
        raise ValueError(f"{field} must fit uint32")
    return parsed


def bytes32_raw(value: Any, field: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a bytes32 string")
    text = value.strip()
    if text.startswith("sha256:"):
        text = text[len("sha256:") :]
    if text.startswith("0x"):
        text = text[2:]
    if len(text) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in text):
        raw = bytes.fromhex(text)
    else:
        try:
            raw = base64.b64decode(text, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"{field} must be 32-byte hex, sha256:hex, 0xhex, or base64") from exc
    if len(raw) != 32:
        raise ValueError(f"{field} must decode to exactly 32 bytes")
    return raw


def protojson_bytes32(value: Any, field: str) -> str:
    return base64.b64encode(bytes32_raw(value, field)).decode("ascii")


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


def read_ref_revision(model_root: Path, ref_name: str = "main") -> str:
    ref_path = model_root / "refs" / ref_name
    if not ref_path.is_file():
        return ""
    return ref_path.read_text(encoding="utf-8").strip()


def resolve_cache_root(input_path: Path) -> tuple[Path, list[str]]:
    warnings: list[str] = []
    model_dir = input_path.expanduser().resolve()
    if (model_dir / "config.json").exists():
        return model_dir, warnings

    snapshots_dir = model_dir / "snapshots"
    if not snapshots_dir.is_dir():
        return model_dir, warnings

    snapshots = sorted([path for path in snapshots_dir.iterdir() if path.is_dir()], key=lambda path: path.name)
    if not snapshots:
        return model_dir, warnings

    ref_revision = read_ref_revision(model_dir, "main")
    if ref_revision:
        snapshot = snapshots_dir / ref_revision
        if not snapshot.is_dir():
            raise ValueError(f"HF refs/main points to {ref_revision}, but snapshot is missing: {snapshot}")
        warnings.append(f"using HF refs/main snapshot: {ref_revision}")
        return snapshot.resolve(), warnings

    if len(snapshots) == 1:
        warnings.append(f"HF refs/main not found; using the only local snapshot: {snapshots[0].name}")
        return snapshots[0].resolve(), warnings

    raise ValueError("multiple HF snapshots found, but refs/main is missing; cannot determine latest revision")


def resolve_model(model_ref: str) -> tuple[Path, list[str], Optional[str]]:
    candidate = Path(model_ref).expanduser()
    if candidate.exists():
        model_dir, warnings = resolve_cache_root(candidate)
        return model_dir, warnings, None

    if model_ref.startswith(("/", "~", ".")):
        raise ValueError(f"model path does not exist: {model_ref}")

    repo_id = model_ref.strip()
    if not repo_id or "/" not in repo_id:
        raise ValueError("model must be a Hugging Face repo id like Qwen/Qwen3-8B or an existing local path")

    model_root = hf_cache_model_root(repo_id)
    if not model_root.is_dir():
        raise ValueError(f"HF cache for {repo_id} was not found at {model_root}. Download the model first.")

    model_dir, warnings = resolve_cache_root(model_root)
    return model_dir, [f"resolved {repo_id} to local HF cache: {model_root}"] + warnings, repo_id


def infer_hf_identity(model_dir: Path) -> tuple[Optional[str], Optional[str]]:
    parts = model_dir.resolve().parts
    revision: Optional[str] = None
    repo_id: Optional[str] = None
    for idx, part in enumerate(parts):
        if part == "snapshots" and idx + 1 < len(parts):
            revision = parts[idx + 1]
            for prev in reversed(parts[:idx]):
                if prev.startswith("models--"):
                    repo_id = prev.removeprefix("models--").replace("--", "/")
                    break
            break
    return repo_id, revision


def default_model_id(repo_id: str) -> str:
    digest = hashlib.sha256(("huggingface:" + repo_id).encode("utf-8")).hexdigest()
    return "hf-" + digest


def find_file(model_dir: Path, name: str) -> Optional[Path]:
    candidate = model_dir / name
    if candidate.exists():
        return candidate
    matches = sorted(model_dir.rglob(name), key=lambda path: path.as_posix())
    return matches[0] if matches else None


def is_model_file(relative_path: Path, include_readme: bool) -> bool:
    lower = relative_path.name.lower()
    if any(part.startswith(".") for part in relative_path.parts):
        return False
    if lower in MODEL_FILE_NAMES:
        return True
    if lower.endswith((".safetensors", ".bin", ".pt", ".gguf")):
        return True
    if lower.endswith(".index.json"):
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
    if name in {"tokenizer.json", "tokenizer.model", "vocab.json", "merges.txt"}:
        return "TOKENIZER"
    if name in {"tokenizer_config.json", "special_tokens_map.json", "added_tokens.json"}:
        return "TOKENIZER_CONFIG"
    if name in {"quantization_config.json", "quant_config.json"}:
        return "QUANT_CONFIG"
    if name.endswith((".safetensors", ".bin", ".pt", ".gguf")):
        return "WEIGHT_SHARD"
    if name.endswith(".jinja") or "chat_template" in name:
        return "CHAT_TEMPLATE"
    return "OTHER_REQUIRED"


def discover_model_files(model_dir: Path, include_readme: bool) -> list[Dict[str, Any]]:
    files: list[Dict[str, Any]] = []
    for root, dir_names, file_names in os.walk(model_dir):
        dir_names[:] = [name for name in dir_names if not name.startswith(".") and name not in {"refs", "snapshots", "blobs"}]
        for file_name in file_names:
            absolute = Path(root) / file_name
            relative = absolute.relative_to(model_dir)
            if not is_model_file(relative, include_readme):
                continue
            stat = absolute.stat()
            files.append({
                "path": relative.as_posix(),
                "role": role_for_path(relative.as_posix()),
                "size_bytes": stat.st_size,
                "digest": sha256_file(absolute),
            })
    files.sort(key=lambda item: item["path"].encode("utf-8"))
    return files


def hash_file_or_empty(domain: str, path: Optional[Path]) -> str:
    if path is None:
        return EMPTY_BYTES32_HEX
    return h_v1(domain, path.read_bytes())


def tokenizer_bundle_hash(files: list[Dict[str, Any]]) -> tuple[str, list[str]]:
    tokenizer_roles = {"TOKENIZER", "TOKENIZER_CONFIG", "CHAT_TEMPLATE"}
    bundle = [
        {"digest": item["digest"], "path": item["path"], "role": item["role"], "size_bytes": item["size_bytes"]}
        for item in files
        if item["role"] in tokenizer_roles
    ]
    bundle.sort(key=lambda item: item["path"].encode("utf-8"))
    return h_v1("TRUEOPEN_MODEL_TOKENIZER_BUNDLE_V1", canonical_json_bytes(bundle)), [item["path"] for item in bundle]


def weight_bundle_hash(files: list[Dict[str, Any]]) -> tuple[str, list[str]]:
    shards = [
        {"digest": item["digest"], "path": item["path"], "size_bytes": item["size_bytes"]}
        for item in files
        if item["role"] == "WEIGHT_SHARD"
    ]
    shards.sort(key=lambda item: item["path"].encode("utf-8"))
    return h_v1("TRUEOPEN_MODEL_WEIGHT_BUNDLE_V1", canonical_json_bytes(shards)), [item["path"] for item in shards]


def hash_chat_template(model_dir: Path, tokenizer_config: Optional[Mapping[str, Any]]) -> tuple[str, str]:
    template_file = find_file(model_dir, "chat_template.jinja")
    if template_file is not None:
        return h_v1("TRUEOPEN_MODEL_CHAT_TEMPLATE_V1", template_file.read_bytes()), template_file.relative_to(model_dir).as_posix()
    if tokenizer_config and isinstance(tokenizer_config.get("chat_template"), str):
        return h_v1("TRUEOPEN_MODEL_CHAT_TEMPLATE_V1", tokenizer_config["chat_template"].encode("utf-8")), "tokenizer_config.json:chat_template"
    return EMPTY_BYTES32_HEX, "empty"


def hash_quant_config(model_dir: Path, config: Mapping[str, Any]) -> tuple[str, str]:
    quant_file = find_file(model_dir, "quantization_config.json") or find_file(model_dir, "quant_config.json")
    if quant_file is not None:
        return h_v1("TRUEOPEN_MODEL_QUANT_CONFIG_V1", quant_file.read_bytes()), quant_file.relative_to(model_dir).as_posix()
    quant_config = config.get("quantization_config")
    if isinstance(quant_config, dict):
        return h_v1("TRUEOPEN_MODEL_QUANT_CONFIG_V1", canonical_json_bytes(quant_config)), "config.json:quantization_config"
    return EMPTY_BYTES32_HEX, "empty"


def dtype_bits(dtype: Optional[str]) -> tuple[str, int]:
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


def infer_quantization(config: Mapping[str, Any]) -> Dict[str, Any]:
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
    method, bits = dtype_bits(str(config.get("torch_dtype") or config.get("dtype") or ""))
    return {"method": method, "bits": bits}


def infer_context_length(config: Mapping[str, Any]) -> int:
    for key in ("max_position_embeddings", "seq_length", "n_positions", "max_sequence_length", "model_max_length"):
        value = config.get(key)
        if isinstance(value, int) and value > 0:
            return value
    return 0


def infer_moe(config: Mapping[str, Any]) -> Dict[str, Any]:
    num_experts = config.get("num_experts") or config.get("num_routed_experts") or 0
    num_experts_per_tok = config.get("num_experts_per_tok") or config.get("num_experts_per_token") or config.get("top_k") or 0
    enabled = bool(isinstance(num_experts, int) and num_experts > 0)
    return {
        "enabled": enabled,
        "num_experts": num_experts if isinstance(num_experts, int) else 0,
        "num_experts_per_tok": num_experts_per_tok if isinstance(num_experts_per_tok, int) else 0,
    }


def architecture_from_config(config: Mapping[str, Any]) -> str:
    architectures = config.get("architectures")
    if isinstance(architectures, list) and any(isinstance(item, str) and "CausalLM" in item for item in architectures):
        return "causal_lm"
    return "causal_lm"


def tensor_count_from_safetensors(path: Path) -> int:
    with path.open("rb") as handle:
        header_len_bytes = handle.read(8)
        if len(header_len_bytes) != 8:
            return 0
        header_len = struct.unpack("<Q", header_len_bytes)[0]
        header = json.loads(handle.read(header_len))
    count = 0
    for name, meta in header.items():
        if name == "__metadata__" or not isinstance(meta, dict):
            continue
        shape = meta.get("shape")
        if isinstance(shape, list) and all(isinstance(dim, int) for dim in shape):
            count += math.prod(shape)
    return count


def estimate_parameter_count(model_dir: Path, files: list[Dict[str, Any]]) -> int:
    total = 0
    for item in files:
        if item["role"] != "WEIGHT_SHARD" or not item["path"].endswith(".safetensors"):
            continue
        total += tensor_count_from_safetensors(model_dir / item["path"])
    return total


def detect_license(model_dir: Path) -> Dict[str, Any]:
    result: Dict[str, Any] = {"license_ref": "", "license_files": []}
    for name in ("README.md", "README.rst"):
        readme = find_file(model_dir, name)
        if readme is None:
            continue
        text = readme.read_text(encoding="utf-8", errors="replace")
        frontmatter = re.match(r"\A---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
        if frontmatter:
            match = re.search(r"(?m)^license:\s*[\"']?([^\"'\n#]+)[\"']?\s*(?:#.*)?$", frontmatter.group(1))
            if match:
                result["license_ref"] = match.group(1).strip()
        result["readme_path"] = readme.relative_to(model_dir).as_posix()
        break

    for pattern in ("LICENSE", "LICENSE.txt", "NOTICE", "NOTICE.txt"):
        license_file = find_file(model_dir, pattern)
        if license_file is not None:
            result["license_files"].append({
                "path": license_file.relative_to(model_dir).as_posix(),
                "digest": sha256_file(license_file),
                "size_bytes": license_file.stat().st_size,
            })
    return result


def extract_local_hf_model(model_ref: str) -> Dict[str, Any]:
    model_dir, warnings, repo_id_from_ref = resolve_model(model_ref)
    inferred_repo_id, revision = infer_hf_identity(model_dir)
    repo_id = repo_id_from_ref or inferred_repo_id
    if not repo_id:
        raise ValueError("repo id cannot be inferred from the local Hugging Face model path")
    if not revision:
        raise ValueError("HF revision cannot be inferred. Use a HF cache repo root or a snapshots/<commit_sha> directory.")
    if revision in {"main", "master"}:
        raise ValueError(f"resolved HF revision is mutable ({revision}); expected an immutable commit sha")

    config_path = find_file(model_dir, "config.json")
    if config_path is None:
        raise ValueError("config.json not found in local model directory")
    config = read_json_file(config_path)
    tokenizer_config_path = find_file(model_dir, "tokenizer_config.json")
    tokenizer_config = read_json_file(tokenizer_config_path) if tokenizer_config_path is not None else None
    generation_config_path = find_file(model_dir, "generation_config.json")

    files = discover_model_files(model_dir, include_readme=False)
    weight_digest, weight_paths = weight_bundle_hash(files)
    tokenizer_hash, tokenizer_paths = tokenizer_bundle_hash(files)
    chat_template_hash, chat_template_source = hash_chat_template(model_dir, tokenizer_config)
    quant_config_hash, quant_config_source = hash_quant_config(model_dir, config)
    estimated_params = estimate_parameter_count(model_dir, files)

    if not estimated_params:
        warnings.append("parameter count could not be estimated from safetensors headers")
    if not weight_paths:
        warnings.append("no WEIGHT_SHARD files discovered")
    if not tokenizer_paths:
        warnings.append("no tokenizer-related files discovered")

    license_info = detect_license(model_dir)
    if not license_info["license_ref"] and not license_info["license_files"]:
        warnings.append("license metadata was not found in local model files")

    artifacts = {
        "file_manifest_hash": h_v1("TRUEOPEN_MODEL_FILE_MANIFEST_V1", canonical_json_bytes(files)),
        "files": files,
        "model_weight_digest": weight_digest,
        "model_config_hash": h_v1("TRUEOPEN_MODEL_CONFIG_V1", config_path.read_bytes()),
        "generation_config_hash": hash_file_or_empty("TRUEOPEN_MODEL_GENERATION_CONFIG_V1", generation_config_path),
        "tokenizer_hash": tokenizer_hash,
        "tokenizer_config_hash": hash_file_or_empty("TRUEOPEN_MODEL_TOKENIZER_CONFIG_V1", tokenizer_config_path),
        "chat_template_hash": chat_template_hash,
        "quant_config_hash": quant_config_hash,
    }
    return {
        "model_ref": model_ref,
        "model_dir": str(model_dir),
        "identity": {
            "model_id": default_model_id(repo_id),
            "display_name": repo_id.split("/")[-1].replace("-", " "),
        },
        "source": {
            "provider": "HUGGINGFACE",
            "repo_id": repo_id,
            "repo_type": "model",
            "revision": revision,
            "source_uri": f"hf://{repo_id}@{revision}",
            "resolver_version": "HF_RESOLVER_V1",
        },
        "artifacts": artifacts,
        "model_config_summary": {
            "model_type": str(config.get("model_type") or "unknown"),
            "architecture": architecture_from_config(config),
            "modality": ["TEXT"],
            "total_params": estimated_params,
            "active_params": estimated_params,
            "context_length": infer_context_length(config),
            "quantization": infer_quantization(config),
            "moe": infer_moe(config),
        },
        "metadata": {
            "license_ref": license_info["license_ref"],
            "license_files": license_info["license_files"],
        },
        "derivation": {
            "warnings": warnings,
            "artifact_sources": {
                "config_path": config_path.relative_to(model_dir).as_posix(),
                "generation_config_path": generation_config_path.relative_to(model_dir).as_posix() if generation_config_path else "",
                "tokenizer_config_path": tokenizer_config_path.relative_to(model_dir).as_posix() if tokenizer_config_path else "",
                "chat_template_source": chat_template_source,
                "quant_config_source": quant_config_source,
                "weight_paths": weight_paths,
                "tokenizer_paths": tokenizer_paths,
            },
        },
    }


def threshold_from_group(thresholds: Mapping[str, Any], group: str, key: str, fp_scaled: bool) -> Any:
    fp_group = f"{group}_fp_1e6"
    if fp_scaled:
        fp_value = value_at(thresholds, fp_group, key)
        if fp_value is not None and fp_value != "":
            return fp_value
        raw = value_at(thresholds, group, key)
        if raw is None or raw == "":
            return None
        number = float(raw)
        if not math.isfinite(number):
            raise ValueError(f"{group}.{key} must be finite")
        return int(round(number * FP_SCALE))
    return value_at(thresholds, group, key)


def apply_thresholds(profile: Dict[str, Any], thresholds: Mapping[str, Any], *, allow_missing: bool) -> None:
    target = dict(as_mapping(profile.get("verification_thresholds")))
    missing = []
    for group, key, target_key, fp_scaled in THRESHOLD_FIELDS:
        value = threshold_from_group(thresholds, group, key, fp_scaled)
        if value is None or value == "":
            missing.append(f"{group}.{key}")
            continue
        target[target_key] = parse_threshold(value, target_key, fp_scaled=fp_scaled)
    if missing and not allow_missing:
        raise ValueError("threshold file is missing required keys: " + ", ".join(missing))
    profile["verification_thresholds"] = target


UINT32_PATHS = [
    ("profile_version",),
    ("required_top_k",),
    ("resource_tier",),
    ("previous_profile_version",),
    ("verification_profile", "verification_profile_id"),
    ("verification_profile", "metrics", "compared_top_k"),
    ("verification_thresholds", "pass_min_finite_count"),
    ("verification_thresholds", "pass_max_missing_compared_count"),
    ("verification_thresholds", "pass_mean_abs_logprob_diff_max"),
    ("verification_thresholds", "pass_abs_logprob_diff_p95_max"),
    ("verification_thresholds", "pass_abs_logprob_diff_p99_max"),
    ("verification_thresholds", "pass_rank_delta_nonzero_rate_max"),
    ("verification_thresholds", "pass_topk_jaccard_mean_min"),
    ("verification_thresholds", "pass_union_js_p99_max"),
    ("verification_thresholds", "reject_mean_abs_logprob_diff_min"),
    ("verification_thresholds", "reject_abs_logprob_diff_p95_min"),
    ("verification_thresholds", "reject_abs_logprob_diff_p99_min"),
    ("verification_thresholds", "reject_rank_delta_nonzero_rate_min"),
    ("verification_thresholds", "reject_topk_jaccard_mean_max"),
    ("verification_thresholds", "reject_union_js_p99_min"),
    ("batch_verification", "min_sample_count"),
    ("batch_verification", "min_valid_sample_count"),
    ("batch_verification", "pass_min_sample_pass_ratio_bps"),
    ("batch_verification", "reject_min_sample_reject_ratio_bps"),
    ("pricing_profile", "pricing_profile_id"),
    ("pricing_profile", "price_band_low_bps"),
    ("pricing_profile", "price_band_high_bps"),
    ("pricing_profile", "verify_fee_ratio_bps"),
    ("timeout_bootstrap_profile", "infer_timeout_bootstrap_blocks"),
    ("timeout_bootstrap_profile", "verify_timeout_bootstrap_blocks"),
    ("timeout_bootstrap_profile", "commit_timeout_bootstrap_blocks"),
]


UINT64_PATHS = [
    ("min_stake", "amount"),
    ("challenge_open_window_blocks",),
    ("pricing_profile", "reference_unit_price"),
    ("pricing_profile", "min_order_value"),
    ("timeout_bootstrap_profile", "bootstrap_valid_until_epoch"),
    ("registration_fee", "amount"),
]


BYTES32_PATHS = [
    ("manifest_hash",),
    ("tokenizer_hash",),
    ("schema_hash",),
    ("verification_profile", "evidence_schema_hash"),
]


KNOWN_TASK_TYPES = {
    "TASK_TYPE_TEXT_GENERATION",
    "TASK_TYPE_CHAT",
    "TASK_TYPE_EMBEDDING",
    "TASK_TYPE_CLASSIFICATION",
    "TASK_TYPE_IMAGE_GENERATION",
    "TASK_TYPE_MULTIMODAL",
}


def path_name(path: tuple[str, ...]) -> str:
    return ".".join(path)


def get_required(payload: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict) or key not in current:
            raise ValueError(f"profile is missing required field: {path_name(path)}")
        current = current[key]
    return current


def set_required(payload: Dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    current: Any = payload
    for key in path[:-1]:
        if not isinstance(current, dict) or key not in current or not isinstance(current[key], dict):
            raise ValueError(f"profile is missing required object: {path_name(path[:-1])}")
        current = current[key]
    current[path[-1]] = value


def sha256_json_protojson(value: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json_bytes(value)).digest()
    return base64.b64encode(digest).decode("ascii")


def stable_metadata_payload(model_info: Mapping[str, Any]) -> Dict[str, Any]:
    artifacts = as_mapping(model_info.get("artifacts"))
    artifact_hashes = {
        key: artifacts.get(key, "")
        for key in (
            "file_manifest_hash",
            "model_weight_digest",
            "model_config_hash",
            "generation_config_hash",
            "tokenizer_hash",
            "tokenizer_config_hash",
            "chat_template_hash",
            "quant_config_hash",
        )
    }
    return {
        "identity": as_mapping(model_info.get("identity")),
        "source": as_mapping(model_info.get("source")),
        "artifacts": artifact_hashes,
        "model_config_summary": as_mapping(model_info.get("model_config_summary")),
        "metadata": as_mapping(model_info.get("metadata")),
    }


def apply_local_model_fields(profile: Dict[str, Any], model_info: Mapping[str, Any]) -> None:
    identity = as_mapping(model_info.get("identity"))
    artifacts = as_mapping(model_info.get("artifacts"))
    model_id = identity.get("model_id")
    if not isinstance(model_id, str) or not model_id or model_id.strip() != model_id:
        raise ValueError("local Hugging Face model identity did not produce a canonical model_id")
    if not model_id.startswith("hf-"):
        raise ValueError("local Hugging Face model_id must use the hf- prefix")

    profile["model_id"] = model_id
    profile["manifest_hash"] = protojson_bytes32(artifacts.get("file_manifest_hash"), "artifacts.file_manifest_hash")
    profile["tokenizer_hash"] = protojson_bytes32(artifacts.get("tokenizer_hash"), "artifacts.tokenizer_hash")

def normalize_profile_protojson(profile: Dict[str, Any]) -> None:
    for path in UINT32_PATHS:
        set_required(profile, path, parse_uint32(get_required(profile, path), path_name(path)))
    for path in UINT64_PATHS:
        set_required(profile, path, str(parse_uint(get_required(profile, path), path_name(path), 64)))
    for path in BYTES32_PATHS:
        set_required(profile, path, protojson_bytes32(get_required(profile, path), path_name(path)))

    schema = get_required(profile, ("verification_profile", "evidence_schema"))
    if not isinstance(schema, dict):
        raise ValueError("verification_profile.evidence_schema must be an object")
    schema["schema_version"] = parse_uint32(schema.get("schema_version"), "verification_profile.evidence_schema.schema_version")
    requirements = schema.get("required_infer_evidence")
    if not isinstance(requirements, list) or not requirements:
        raise ValueError("verification_profile.evidence_schema.required_infer_evidence must be non-empty")
    for index, requirement in enumerate(requirements):
        if not isinstance(requirement, dict):
            raise ValueError(f"required_infer_evidence[{index}] must be an object")
        requirement["commitment_schema_version"] = parse_uint32(requirement.get("commitment_schema_version"), f"required_infer_evidence[{index}].commitment_schema_version")
        requirement["max_encoded_size_bytes"] = str(parse_uint(requirement.get("max_encoded_size_bytes"), f"required_infer_evidence[{index}].max_encoded_size_bytes", 64))

def require_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a JSON boolean")
    return value


def validate_profile_shape(profile: Mapping[str, Any]) -> None:
    required = [
        "model_id",
        "profile_version",
        "manifest_hash",
        "tokenizer_hash",
        "runtime_class",
        "required_top_k",
        "task_types",
        "generation_type",
        "resource_tier",
        "min_stake",
        "challenge_open_window_blocks",
        "verification_profile",
        "verification_thresholds",
        "batch_verification",
        "pricing_profile",
        "timeout_bootstrap_profile",
        "schema_hash",
        "previous_profile_version",
        "registration_fee",
    ]
    def missing_value(value: Any) -> bool:
        return value is None or value == ""

    missing = [key for key in required if key not in profile or missing_value(profile[key])]
    if missing:
        raise ValueError("profile is missing required fields: " + ", ".join(missing))

    model_id = profile.get("model_id")
    runtime_class = profile.get("runtime_class")
    if not isinstance(model_id, str) or not model_id.startswith("hf-") or model_id.strip() != model_id:
        raise ValueError("model_id must be canonical and use the hf- prefix")
    if runtime_class != "CAUSAL_LM_PREFILL_LOGPROBS_V1":
        raise ValueError("unsupported model profile runtime_class")

    profile_version = parse_uint32(profile["profile_version"], "profile_version")
    previous_profile_version = parse_uint32(profile["previous_profile_version"], "previous_profile_version")
    if profile_version == 0:
        raise ValueError("profile_version must be non-zero")
    if (profile_version == 1 and previous_profile_version != 0) or (
        profile_version > 1 and previous_profile_version + 1 != profile_version
    ):
        raise ValueError("profile_version must immediately follow previous_profile_version")

    required_top_k = parse_uint32(profile["required_top_k"], "required_top_k")
    compared_top_k = parse_uint32(value_at(profile, "verification_profile", "metrics", "compared_top_k"), "verification_profile.metrics.compared_top_k")
    if required_top_k != compared_top_k:
        raise ValueError("required_top_k must match verification_profile.metrics.compared_top_k")
    if required_top_k == 0 or parse_uint32(profile["resource_tier"], "resource_tier") == 0:
        raise ValueError("required_top_k and resource_tier must be non-zero")

    task_types = profile.get("task_types")
    if not isinstance(task_types, list) or not task_types:
        raise ValueError("task_types must be a non-empty list")
    task_numbers = {
        "TASK_TYPE_TEXT_GENERATION": 1, "TASK_TYPE_CHAT": 2, "TASK_TYPE_EMBEDDING": 3,
        "TASK_TYPE_CLASSIFICATION": 4, "TASK_TYPE_IMAGE_GENERATION": 5, "TASK_TYPE_MULTIMODAL": 6,
    }
    previous_task_type = 0
    for task_type in task_types:
        number = task_numbers.get(task_type, 0)
        if number == 0 or number <= previous_task_type:
            raise ValueError("task_types must be known, sorted, and unique Cortex enum numbers")
        previous_task_type = number

    if profile.get("generation_type") not in {"GENERATION_TYPE_DETERMINISTIC", "GENERATION_TYPE_SAMPLED"}:
        raise ValueError("generation_type is unsupported")

    verification = as_mapping(profile.get("verification_profile"))
    metrics = as_mapping(verification.get("metrics"))
    if (
        parse_uint32(verification.get("verification_profile_id"), "verification_profile.verification_profile_id") == 0
        or verification.get("verification_mode") != "VERIFICATION_MODE_SINGLE_SAMPLE"
        or verification.get("token_scope") != "TOKEN_SCOPE_ALL_GENERATED_OUTPUT_TOKENS"
        or metrics.get("numeric_scale") != "NUMERIC_SCALE_FP_1E6"
    ):
        raise ValueError("verification identity, mode, token scope, and scale must match Cortex support")
    if (
        verification.get("judgment_function_version") != "PREFILL_GENERATED_TOKEN_METRICS_V1"
        or verification.get("canonical_encoding_version") != "CANONICAL_OUTPUT_TEXT_V1"
        or verification.get("metric_aggregate_proof_version") != "PREFILL_METRIC_AGGREGATE_PROOF_V1"
    ):
        raise ValueError("unsupported verification wire identifiers")
    batch = as_mapping(profile.get("batch_verification"))
    if require_bool(batch.get("enabled"), "batch_verification.enabled") or any(
        parse_uint32(batch.get(field), f"batch_verification.{field}") != 0
        for field in (
            "min_sample_count",
            "min_valid_sample_count",
            "pass_min_sample_pass_ratio_bps",
            "reject_min_sample_reject_ratio_bps",
        )
    ):
        raise ValueError("only disabled single-sample batch verification is supported")

    pricing = as_mapping(profile.get("pricing_profile"))
    if pricing.get("pricing_unit") not in {
        "PRICING_UNIT_PER_INPUT_TOKEN",
        "PRICING_UNIT_PER_OUTPUT_TOKEN",
        "PRICING_UNIT_PER_REQUEST",
        "PRICING_UNIT_PER_SECOND",
    }:
        raise ValueError("pricing_profile.pricing_unit is unsupported")
    if (
        parse_uint32(pricing.get("pricing_profile_id"), "pricing_profile.pricing_profile_id") == 0
        or parse_uint(pricing.get("reference_unit_price"), "pricing_profile.reference_unit_price", 64) == 0
        or parse_uint(pricing.get("min_order_value"), "pricing_profile.min_order_value", 64) == 0
        or parse_uint32(pricing.get("price_band_low_bps"), "pricing_profile.price_band_low_bps")
        > parse_uint32(pricing.get("price_band_high_bps"), "pricing_profile.price_band_high_bps")
        or parse_uint32(pricing.get("verify_fee_ratio_bps"), "pricing_profile.verify_fee_ratio_bps") > 10_000
    ):
        raise ValueError("invalid model profile pricing configuration")

    min_stake = as_mapping(profile.get("min_stake"))
    registration_fee = as_mapping(profile.get("registration_fee"))
    if min_stake.get("denom") != "utrueopen" or parse_uint(min_stake.get("amount"), "min_stake.amount", 64) == 0:
        raise ValueError("min_stake must be a non-zero utrueopen coin")
    fee_amount = parse_uint(registration_fee.get("amount"), "registration_fee.amount", 64)
    if registration_fee.get("denom") != "utrueopen" or fee_amount < 10_000_000 or fee_amount > 50_000_000:
        raise ValueError("registration_fee must be a utrueopen coin in the 10000000..50000000 range")
    challenge_window = parse_uint(profile.get("challenge_open_window_blocks"), "challenge_open_window_blocks", 64)
    if challenge_window < 1_800 or challenge_window > 28_800:
        raise ValueError("challenge_open_window_blocks must be in the 1800..28800 range")


def build_model_profile(base_profile: Mapping[str, Any], model_info: Mapping[str, Any], thresholds: Mapping[str, Any]) -> Dict[str, Any]:
    profile = copy.deepcopy(base_profile)
    apply_local_model_fields(profile, model_info)
    apply_thresholds(profile, thresholds, allow_missing=False)
    normalize_profile_protojson(profile)
    profile["verification_profile"]["evidence_schema_hash"] = evidence_schema_hash(profile)
    validate_profile_shape(profile)
    return profile


def default_base_profile() -> Path:
    return Path(__file__).resolve().parents[2] / "configs" / "model-profile.current.example.json"


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a Cortex current ModelProfileProjection ProtoJSON profile from a local Hugging Face model and calibrated verify thresholds."
    )
    parser.add_argument("--model", required=True, help="HF repo id like Qwen/Qwen3-8B, HF cache root, or local snapshots/<commit> model path.")
    parser.add_argument("--thresholds", required=True, help="workerverifycalibration recommended_thresholds.json path.")
    parser.add_argument("--output", default="profile.json", help="Output Cortex ModelProfileProjection ProtoJSON path.")
    parser.add_argument(
        "--base-profile",
        default=str(default_base_profile()),
        help="Template ModelProfileProjection ProtoJSON path. Defaults to configs/model-profile.current.example.json.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    try:
        base_profile = read_json_object(Path(args.base_profile))
        model_info = extract_local_hf_model(args.model)
        thresholds = read_json_object(Path(args.thresholds))
        profile = build_model_profile(base_profile, model_info, thresholds)
        output = Path(args.output)
        write_json(output, profile)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Wrote {output}")
    print(f"Profile: {profile['model_id']}@{profile['profile_version']}")
    print(f"manifest_hash: {profile['manifest_hash']}")
    print(f"tokenizer_hash: {profile['tokenizer_hash']}")
    warnings = value_at(model_info, "derivation", "warnings")
    if warnings:
        print("Warnings:")
        for warning in warnings:
            print(f"  - {warning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import hashlib
import inspect
import json
import math
import platform
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence


JSONDict = Dict[str, Any]


@dataclass
class DecodeConfig:
    max_new_tokens: int = 128
    temperature: float = 0.0
    top_p: float = 1.0
    top_k: int = 0
    seed: int = 0
    do_sample: bool = False


@dataclass
class VariantInfo:
    variant_id: str
    model: str
    tokenizer_hash: str
    tokenizer_name: str = ""
    quantization: str = "bf16"
    gpu: str = ""
    backend: str = "vllm"
    backend_version: str = ""
    dtype: str = ""
    extra: JSONDict = field(default_factory=dict)


@dataclass
class Tokenization:
    tokenizer_hash: str
    tokenizer_name: str
    input_ids: List[int]
    output_ids: List[int]


@dataclass
class WorkerSample:
    sample_id: str
    input_text: str
    canonical_output_text: str = ""
    category: str = ""
    target_input_tokens: Optional[int] = None
    anchor_variant: str = ""
    decode_config: Optional[DecodeConfig] = None
    tokenizations: Dict[str, Tokenization] = field(default_factory=dict)
    metadata: JSONDict = field(default_factory=dict)


def runtime_metadata(argv: Sequence[str]) -> JSONDict:
    return {
        "created_at_unix": time.time(),
        "python": sys.version,
        "platform": platform.platform(),
        "argv": list(argv),
    }


def stable_json_hash(payload: Any, length: int = 16) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:length]


def dataclass_to_dict(value: Any) -> JSONDict:
    return asdict(value)


def read_jsonl(path: Path) -> Iterator[JSONDict]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSONL row") from exc


def write_jsonl(path: Path, rows: Iterable[JSONDict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def write_json(path: Path, payload: JSONDict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)


def parse_decode_config(payload: Optional[JSONDict]) -> Optional[DecodeConfig]:
    if payload is None:
        return None
    return DecodeConfig(**payload)


def parse_tokenizations(payload: Optional[JSONDict]) -> Dict[str, Tokenization]:
    if not payload:
        return {}
    return {
        str(key): Tokenization(**value)
        for key, value in payload.items()
    }


def parse_worker_sample(payload: JSONDict) -> WorkerSample:
    data = dict(payload)
    data["decode_config"] = parse_decode_config(data.get("decode_config"))
    data["tokenizations"] = parse_tokenizations(data.get("tokenizations"))
    return WorkerSample(**data)


def safe_float(value: object, default: float = float("nan")) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def sorted_token_ids(token_ids: Iterable[str]) -> List[str]:
    return sorted((str(token_id) for token_id in token_ids), key=lambda item: int(item))


def normalize_logprobs(logprobs: Sequence[float]) -> List[float]:
    if not logprobs:
        return []
    max_logprob = max(logprobs)
    if not math.isfinite(max_logprob):
        return [float("nan") for _ in logprobs]
    weights = [math.exp(value - max_logprob) for value in logprobs]
    total = sum(weights)
    if total <= 0.0 or not math.isfinite(total):
        return [float("nan") for _ in logprobs]
    return [value / total for value in weights]


def cosine(left: Sequence[float], right: Sequence[float]) -> float:
    if not left or not right or len(left) != len(right):
        return float("nan")
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(a * a for a in left))
    right_norm = math.sqrt(sum(b * b for b in right))
    if left_norm == 0.0 or right_norm == 0.0:
        return float("nan")
    return dot / (left_norm * right_norm)


def kl_divergence(p: Sequence[float], q: Sequence[float]) -> float:
    if not p or not q or len(p) != len(q):
        return float("nan")
    total = 0.0
    for p_value, q_value in zip(p, q):
        if p_value <= 0.0:
            continue
        if q_value <= 0.0:
            return float("inf")
        total += p_value * math.log(p_value / q_value)
    return total


def js_divergence(p: Sequence[float], q: Sequence[float]) -> float:
    if not p or not q or len(p) != len(q):
        return float("nan")
    middle = [(p_value + q_value) / 2.0 for p_value, q_value in zip(p, q)]
    return 0.5 * kl_divergence(p, middle) + 0.5 * kl_divergence(q, middle)


def logprob_value(logprobs: Mapping[str, Mapping[str, object]],
                  token_id: str,
                  missing_logprob: float) -> float:
    if token_id not in logprobs:
        return missing_logprob
    return safe_float(logprobs[token_id].get("logprob"))


def probability_metrics(left: Mapping[str, Mapping[str, object]],
                        right: Mapping[str, Mapping[str, object]],
                        token_ids: Sequence[str],
                        missing_logprob: float) -> Dict[str, float]:
    left_logprobs = [
        logprob_value(left, token_id, missing_logprob)
        for token_id in token_ids
    ]
    right_logprobs = [
        logprob_value(right, token_id, missing_logprob)
        for token_id in token_ids
    ]
    left_probs = normalize_logprobs(left_logprobs)
    right_probs = normalize_logprobs(right_logprobs)
    return {
        "prob_cosine": cosine(left_probs, right_probs),
        "kl_left_to_right": kl_divergence(left_probs, right_probs),
        "kl_right_to_left": kl_divergence(right_probs, left_probs),
        "js_divergence": js_divergence(left_probs, right_probs),
    }


def quantile(values: Sequence[float], q: float) -> float:
    clean = sorted(value for value in values if math.isfinite(value))
    if not clean:
        return float("nan")
    if len(clean) == 1:
        return clean[0]
    position = (len(clean) - 1) * q
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return clean[lower]
    frac = position - lower
    return clean[lower] * (1.0 - frac) + clean[upper] * frac


def tokenizer_hash(tokenizer: Any, length: int = 16) -> str:
    parts = {
        "class": tokenizer.__class__.__name__,
        "name_or_path": str(getattr(tokenizer, "name_or_path", "")),
        "vocab_size": int(getattr(tokenizer, "vocab_size", 0) or 0),
        "bos_token_id": getattr(tokenizer, "bos_token_id", None),
        "eos_token_id": getattr(tokenizer, "eos_token_id", None),
        "pad_token_id": getattr(tokenizer, "pad_token_id", None),
        "unk_token_id": getattr(tokenizer, "unk_token_id", None),
        "chat_template": getattr(tokenizer, "chat_template", None),
    }
    backend = getattr(tokenizer, "backend_tokenizer", None)
    if backend is not None and hasattr(backend, "to_str"):
        parts["backend_sha256"] = hashlib.sha256(
            backend.to_str().encode("utf-8")
        ).hexdigest()
    else:
        try:
            vocab_items = sorted(tokenizer.get_vocab().items())
        except Exception:
            vocab_items = []
        parts["vocab_sha256"] = hashlib.sha256(
            json.dumps(vocab_items, sort_keys=True).encode("utf-8")
        ).hexdigest()
    encoded = json.dumps(parts, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:length]


def tokenizer_name(tokenizer: Any) -> str:
    return str(getattr(tokenizer, "name_or_path", "") or tokenizer.__class__.__name__)


def encode_text(tokenizer: Any, text: str) -> List[int]:
    return list(tokenizer.encode(text, add_special_tokens=False))


def decode_tokens(tokenizer: Any, token_ids: Sequence[int]) -> str:
    return tokenizer.decode(list(token_ids), skip_special_tokens=False)


def normalize_logprob_value(value: Any) -> Dict[str, Any]:
    if hasattr(value, "logprob"):
        return {
            "logprob": float(value.logprob),
            "rank": getattr(value, "rank", None),
            "decoded_token": getattr(value, "decoded_token", None),
        }
    if isinstance(value, dict):
        logprob = value.get("logprob", value.get("value"))
        return {
            "logprob": float(logprob),
            "rank": value.get("rank"),
            "decoded_token": value.get("decoded_token"),
        }
    return {"logprob": float(value), "rank": None, "decoded_token": None}


def normalize_logprob_dict(raw: Any) -> Dict[str, Dict[str, Any]]:
    if raw is None:
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    for token_id, value in dict(raw).items():
        out[str(int(token_id))] = normalize_logprob_value(value)
    return out


def sorted_top_logprobs(logprobs: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    def sort_key(item: tuple) -> tuple:
        token_id, token_info = item
        rank = token_info.get("rank")
        rank_key = float("inf") if rank is None else safe_float(rank, float("inf"))
        return rank_key, -safe_float(token_info.get("logprob")), int(token_id)

    rows = []
    for position, (token_id, token_info) in enumerate(
        sorted(logprobs.items(), key=sort_key),
        start=1,
    ):
        rows.append({
            "position": position,
            "token_id": int(token_id),
            "logprob": safe_float(token_info.get("logprob")),
            "rank": token_info.get("rank"),
            "decoded_token": token_info.get("decoded_token"),
        })
    return rows


def logprob_for_token(logprobs: Dict[str, Dict[str, Any]], token_id: int) -> Optional[float]:
    item = logprobs.get(str(int(token_id)))
    if item is None:
        return None
    return safe_float(item.get("logprob"))


def rank_for_token(logprobs: Dict[str, Dict[str, Any]], token_id: int) -> Optional[int]:
    item = logprobs.get(str(int(token_id)))
    if item is None:
        return None
    rank = item.get("rank")
    if rank is None:
        return None
    return int(rank)


def make_tokens_prompt(token_ids: Sequence[int]) -> Any:
    ids = [int(token_id) for token_id in token_ids]
    try:
        from vllm.inputs import TokensPrompt

        return TokensPrompt(prompt_token_ids=ids)
    except Exception:
        return {"prompt_token_ids": ids}


def build_llm_kwargs(args: Any) -> Dict[str, Any]:
    kwargs = {
        "model": args.model,
        "dtype": args.dtype,
        "trust_remote_code": args.trust_remote_code,
        "tensor_parallel_size": args.tensor_parallel_size,
        "gpu_memory_utilization": args.gpu_memory_utilization,
        "max_model_len": args.max_model_len,
        "max_num_seqs": getattr(args, "max_num_seqs", None),
        "max_num_batched_tokens": getattr(args, "max_num_batched_tokens", None),
        "max_logprobs": args.max_logprobs,
        "quantization": None if args.quantization == "bf16" else args.quantization,
    }
    return {key: value for key, value in kwargs.items() if value is not None}


def build_sampling_params(args: Any,
                          *,
                          max_tokens: int,
                          logprobs: Optional[int] = None,
                          prompt_logprobs: Optional[int] = None,
                          detokenize: bool = False) -> Any:
    from vllm import SamplingParams

    kwargs = {
        "temperature": args.temperature,
        "top_p": args.top_p,
        "top_k": args.top_k if args.top_k > 0 else -1,
        "max_tokens": max_tokens,
        "logprobs": logprobs,
        "prompt_logprobs": prompt_logprobs,
        "seed": args.seed,
        "detokenize": detokenize,
    }
    supported = set()
    try:
        supported = set(inspect.signature(SamplingParams).parameters)
    except (TypeError, ValueError):
        pass
    if supported:
        kwargs = {key: value for key, value in kwargs.items() if key in supported}
    return SamplingParams(**kwargs)


def write_jsonl_row(handle: Any, payload: Dict[str, Any], flush: bool = True) -> None:
    handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    handle.write("\n")
    if flush:
        handle.flush()

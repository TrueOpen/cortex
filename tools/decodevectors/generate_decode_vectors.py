#!/usr/bin/env python3
"""Generate a model profile's DECODE_VECTORS artifact.

DECODE_VECTORS (protocol spec, verification algorithm §8.2) is a JSON array of
{token_ids, expected_bytes_hex} cases authored against the profile's own
tokenizer. A node proves it decodes like the profile by reproducing every
case before committing anything; cortex enforces that in
internal/modelservice.ensureDecodeVectorsPass.

Each vector's token_ids is a full generated sequence T and expected_bytes_hex
is the committed output under output_decoding: HF decode with special tokens
rendered and no cleanup, exactly one trailing EOS stripped when T ends in one,
ill-formed tails folded to U+FFFD. This script derives the expected bytes with
the HF tokenizer itself, so it must run against the exact tokenizer the
manifest's tokenizer_hash commits to.

The emitted file covers the five classes the spec requires at minimum:
a body special token, a multi-byte character, one character split across
tokens, the trailing-EOS strip, and a no-EOS truncation in the middle of a
character -- plus an all-EOS sequence whose committed output is empty.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

# Characters tried when looking for one whose UTF-8 bytes span several tokens
# (byte-level BPE splits rare codepoints into byte-fragment tokens).
MULTI_TOKEN_CHAR_CANDIDATES = "\U0001f984\U0001f30d\U0001d11e\U0001f680亜龘"

ASCII_SENTENCE = "Hello world, these decode vectors bind one tokenizer."
MULTIBYTE_SENTENCE = "你好，世界 \U0001f30d café"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", required=True, help="HF repo id or local path of the profile's tokenizer")
    parser.add_argument("--eos-token-ids", required=True,
                        help="comma-separated output_decoding.eos_token_ids, e.g. 248044,248046")
    parser.add_argument("--output", default="decode_vectors.json", help="where to write the artifact")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        from transformers import AutoTokenizer
    except ImportError:
        print("pip install transformers (and tokenizers) first", file=sys.stderr)
        return 1
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    eos_ids = [int(field) for field in args.eos_token_ids.split(",") if field.strip()]
    if not eos_ids:
        print("--eos-token-ids must name at least one id", file=sys.stderr)
        return 1
    for eos in eos_ids:
        token = tokenizer.convert_ids_to_tokens(eos)
        if token is None:
            print(f"eos token id {eos} is not in this tokenizer's vocabulary", file=sys.stderr)
            return 1

    def decode(ids: list[int]) -> str:
        return tokenizer.decode(ids, skip_special_tokens=False, clean_up_tokenization_spaces=False)

    def encode(text: str) -> list[int]:
        return tokenizer.encode(text, add_special_tokens=False)

    def vector(ids: list[int]) -> dict:
        committed = ids[:-1] if ids and ids[-1] in eos_ids else ids
        expected = decode(committed) if committed else ""
        return {"token_ids": ids, "expected_bytes_hex": expected.encode("utf-8").hex()}

    primary_eos = eos_ids[0]
    ascii_ids = encode(ASCII_SENTENCE)
    multibyte_ids = encode(MULTIBYTE_SENTENCE)

    split_char = next((c for c in MULTI_TOKEN_CHAR_CANDIDATES if len(encode(c)) >= 2), None)
    if split_char is None:
        print("no candidate character encodes to 2+ tokens; add one that does for this tokenizer",
              file=sys.stderr)
        return 1
    split_ids = encode(split_char)
    truncated_ids = split_ids[:-1]
    if "�" not in decode(truncated_ids):
        print(f"dropping the last token of {split_char!r} did not cut mid-character; "
              "pick a candidate whose byte fragments span tokens", file=sys.stderr)
        return 1

    vectors = [
        # Plain text, and the same text with one trailing EOS to strip.
        vector(ascii_ids),
        vector(ascii_ids + [primary_eos]),
        # A special token in the body renders literally and is never stripped.
        vector(encode("A") + [primary_eos] + encode("B")),
        # Multi-byte characters survive byte-exactly.
        vector(multibyte_ids),
        # One character whose UTF-8 bytes span several tokens reassembles.
        vector(split_ids),
        # A generation truncated mid-character (no trailing EOS) folds the
        # incomplete tail to U+FFFD. The spec requires this case.
        vector(encode("ok ") + truncated_ids),
        # Nothing but an EOS commits the empty output.
        vector([primary_eos]),
    ]
    # Every secondary EOS id must strip too.
    for eos in eos_ids[1:]:
        vectors.append(vector(ascii_ids + [eos]))

    for entry in vectors:
        bytes.fromhex(entry["expected_bytes_hex"]).decode("utf-8")  # must be valid UTF-8

    body = json.dumps(vectors, indent=1).encode("utf-8") + b"\n"
    output = Path(args.output)
    output.write_bytes(body)
    digest = hashlib.sha256(body).hexdigest()
    print(f"wrote {len(vectors)} vectors to {output} ({len(body)} bytes)")
    print(f"sha256: {digest}")
    print("manifest artifacts.files entry:")
    print(json.dumps({"digest": f"sha256:{digest}", "path": "trueopen/decode_vectors.json",
                      "role": "DECODE_VECTORS", "size_bytes": len(body)}))
    print(f"cortexd cache name: {digest}.decode_vectors.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())

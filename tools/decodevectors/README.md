# Decode Vectors Generator

Generates a model profile's `DECODE_VECTORS` artifact: the conformance cases
(`[{token_ids, expected_bytes_hex}, ...]`) a node must reproduce with its own
engine before it may commit outputs (Worker) or decode comparisons (Verifier)
under that profile. Cortex enforces them in
`internal/modelservice.ensureDecodeVectorsPass`, fed by
`internal/modelmanifest.(*Fetcher).DecodeVectors`.

Run it against the exact tokenizer the manifest's `tokenizer_hash` commits to:

```bash
pip install transformers tokenizers
./tools/decodevectors/generate_decode_vectors.py \
  --model Qwen/Qwen3-8B \
  --eos-token-ids 151645,151643 \
  --output decode_vectors.json
```

It emits the five case classes the protocol spec (verification algorithm §8.2)
requires at minimum -- a body special token, a multi-byte character, one
character split across tokens, the trailing-EOS strip, a no-EOS truncation in
the middle of a character -- plus an all-EOS sequence, and one strip case per
secondary EOS id.

## Shipping the file

1. Place the file in the model directory as `trueopen/decode_vectors.json`.
2. In the manifest, set `output_decoding.decode_vectors_path` to that path and
   add the printed `artifacts.files` entry (role `DECODE_VECTORS`). Changing
   the manifest changes `manifest_hash`, so this lands with a new profile
   version.
3. Make the bytes reachable for nodes: either drop the file into each node's
   manifest cache dir under the printed `<sha256>.decode_vectors.json` name, or
   serve it from a manifest mirror at `<mirror>/<sha256 hex>`. Trust comes from
   the digest, not the transport.

A profile whose `decode_vectors_path` is empty (like the current testnet
manifest) declares no vectors, and nodes skip the check.

# Wire Bindings

Cortex consumes the descriptor released as `TrueOpen/wire` v0.2.0, commit
`c8476fd8c26bc5d9d77f570125f57d79224ff81d`. Hub, Task, shared, Bus and Nexus use
one Google Protobuf descriptor graph. The previous mixed Node revisions,
handwritten `Frozen*` subsets and duplicate Bus Task types are retired.

This replaces `SingaXYZ/wire` v0.4.3 and is a rename, not an upgrade: the proto
packages lost their `singa` prefix (`bus.v1` is `bus.v1`, `task.v1` is
`task.v1`, and so on), every signing domain moved from `TRUEOPEN_*` to
`TRUEOPEN_*`, the bech32 HRP moved from `singa` to `trueopen`, and the NATS
subjects moved from `trueopen.*` to `trueopen.*`. A domain literal is framed into
its own preimage, so **every digest this repository produces changed**. Deploy
with Node and Nexus builds that made the same move; a node on either side of the
rename cannot verify the other's signatures.

Message shapes did not change. The descriptor's non-Singa dependency closure
(amino, cosmos, cosmos_proto, gogoproto, google) regenerates byte for byte
against the v0.4.3 output, which is what shows the rename carried no field
changes with it.

## Reproduction

The release descriptor is committed as `proto/testdata/wire-v0.2.0.binpb`. Its
SHA-256 is
`0eae8af1536e489f38f668dfa87c848d1e889b460513607e13df54d9fde54887`, which is the
`wire.binpb.sha256` asset of
https://github.com/TrueOpen/wire/releases/tag/v0.2.0.

Generation uses `protoc v6.33.2`, `protoc-gen-go v1.36.11` and
`protoc-gen-connect-go v1.18.1`. Install these tools before running:

```sh
make proto-gen-chain CHAIN_GEN_OUT=bin/wire-v020-review
make proto-drift-chain
```

The output directory must be empty. Generation never deletes files or writes
into the committed tree. Review generated output before adopting it.
`scripts/wiregen` verifies the descriptor checksum and generates every v1 Hub,
Task, shared and Bus source plus Nexus ingress and their transitive imports.
Explicit Go import mappings keep these dependencies local under `proto/`;
Google well-known types use the Protobuf runtime. No Cosmos SDK application
dependency or handwritten protobuf subset is needed.

`TestChainBindingsMatchReleasedDescriptor` compares the complete compiled
contract descriptors, including field numbers, types, oneofs and services,
against the pinned release. Source locations and Buf compiler metadata are excluded. A duplicate type
registration fails process startup. Import checks prevent accidental SDK imports.
Nexus provenance is also recorded in `proto/nexus/v1/README.md`.
`proto/cortex/v1` remains Cortex's own model-service contract.

## Active Contracts

Released fixture bytes are kept unchanged under `internal/wirevectors/testdata/v020`.
This is a reviewed breaking release despite its patch version:

- InferReceiptV2 and WorkerValueCommitmentV2 are the only active Worker contracts.
  Both sign the output MMR leaf count; no V1 decoder or alias is retained.
- OUTPUT uses signed Header/Chunk/Fin streams. Chunk boundaries are committed by
  `TRUEOPEN_OUTPUT_MMR_V1`; one chunk still uses the MMR formula, and an empty
  output is exactly one empty leaf. Fin establishes STORED only, and since SingaXYZ/wire v0.2.0
  it also carries the Worker's normalized successful `FinishReasonV1` under a
  raw64 `TRUEOPEN_OUTPUT_FIN_V1` signature; neither field enters the OUTPUT MMR,
  `output_hash` or object metadata.
- Worker evidence has exactly four artifacts: checkpoint, generated token IDs,
  input token IDs and trace. Its locator is the typed V2 commitment, while the
  manifest's hash independently checks transport integrity. Token artifacts use
  raw `u32_be(count) || repeated u32_be(token_id)` bytes.
- FinalizeTaskResult is the only transition to READY and the only source of
  Worker output/evidence storage confirmations.

The released receipt, Worker commitment and model-profile vectors match the
canonical formulas. The Task-data auth and Builder confirmation vectors no longer
carry the unverifiable bech32 label they had through v0.4.1; their `bech32`
column now decodes to its `hex` sibling. Digest tests still read the published
raw address bytes, because a preimage frames the address codec bytes and never
the presentation text.

The daemon still schedules first-round verification only. It now explicitly
quarantines an unsupported effective round instead of relabeling it as round one.
Automatic challenge-round execution requires separate per-round durable state.
This migration does not introduce that workflow.

Deploy with compatible Node and Nexus builds together. Drain outstanding work
before replacing the previous protocol: V1 orders/results and old evidence
commitments cannot be resumed as V2 material by changing their version labels.

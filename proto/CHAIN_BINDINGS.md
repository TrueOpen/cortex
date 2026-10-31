# Wire Bindings

Cortex consumes the descriptor built from `TrueOpen/wire` commit
`916e3936355cb787f6e82509619f55c6b5aad7e2` (916e393, wire#49), the Phase 1
candidate contract. It is not a release: go.mod pins the pseudo-version
`v0.5.2-0.20261029083751-916e3936355c`, and the pin moves to the release asset
once wire tags it. Hub, Task, shared, Nexus and Cortex use one Google Protobuf
descriptor graph. The previous mixed Node revisions, handwritten `Frozen*`
subsets and duplicate Bus Task types are retired.

The cross-language test vectors in `internal/wirevectors` are `testdata/v1` of
the same commit. Against rc.2, v0.3.0 retires `ModelState.active_profile_count`
(field 4 is reserved: ACTIVE is derived from model support alone), adds the
model-support deactivation cursor that runs after a model is FROZEN or DELISTED
with its per-block budget
`SupportParamsV1.max_model_support_deactivate_items_per_block`, and corrects
comments only in the evidence-commitments framing and the payload modes.

v0.3.1 adds `manifest_uri`, the registrant-hosted pointer to the model
manifest: `ModelProfileProjection.manifest_uri` (field 23, inside the V3
projection and registration digests but not `manifest_hash`),
`ProfileState.manifest_uri` (field 34) and its length cap
`ModelParamsV1.max_manifest_uri_bytes` (field 12). The V3 projection and
registration digests change in place; the projection vector's `manifest_uri`
contains `&`, which canonical JSON writes literally.

v0.3.2 ships the same descriptor byte for byte. It changes one fixture:
`shared/params_v1.json` now sets
`SupportParamsV1.max_model_support_deactivate_items_per_block` to 32, which
moves the `hub_params_v2` digest. Cortex does not derive that digest.

v0.3.3 changes comments only: the descriptor without source info is
identical to v0.3.2's, so the regenerated bindings differ in comments alone.
Its fixtures add vectors and tighten expectations. In
`task_data_auth_v1.json`, each `evidence_kind` mutation now lands on a kind
that is illegal for that object or request, so it is expected to be rejected
before hashing (`reject_before_hash`) instead of changing the digest.

v0.4.0 is a reviewed breaking release, but the break is entirely on the user
request path Cortex never signs or verifies: `SDKRequestEnvelopeV1` is renamed
`SDKRequestEnvelopeV2` (nexus.v1, same field numbers), its signature moves to
65-byte EIP-712 `R||S||V` under the new `"TrueOpen SDK Request"` domain, and the
optional `SessionGrantV1` message lets a short-lived session key sign the read
and delivery-progress requests. Cortex talks to the Builder over Bus envelopes
and SERVICE-signed Task data requests, so no production code references the
renamed types; the regenerated bindings compile without a source change. Every
other proto edit in v0.4.0 is comment-only (`hub/v1/model_profile_state.proto`,
`shared/v1/model_profile.proto`, `task/v1/msg_assignment.proto`, and the
retirement notes on `SubmitOrder`, `FetchOutputRef` and `RefreshCredential`).
The fixtures add `task/generation_params_ranges_v1.json` (the Keeper's
inclusive DecodingParams ranges), `task/order_economics_v1.json` (the
`order_value` derivation), `task/task_order_eip712_v1.json`,
`task/sdk_request_body_v1.json`, `hub/model_registration_chain_v1.json` and
`shared/rest_json_shapes_v1.json`, and revise `shared/account_signing_v1.json`,
`hub/manifest_uri_v1.json` and `task/task_order_v3.json` (mutation rows gain a
machine-readable `edit`; digests unchanged).

v0.5.0 is a reviewed breaking release (wire#42, wire#44). The EIP-712 domain
`chainId` is chosen by the signer and carried as `signature_chain_id`
(`task.v1.SignedOrderV2` field 4, `nexus.v1.SessionGrantV1` field 7,
`nexus.v1.TaskDataRequestAuthV1` field 13, `nexus.v1.SDKRequestEnvelopeV2`
field 14), and `hub.v1.Phase0ParamsV1.evm_chain_id` is removed (field 11
reserved). A CORTEX_SERVICE Task data request carries `signature_chain_id` 0,
which is what Cortex already sends. The text form of a Hash32 in REST and on the
Nexus ingress becomes `0x` followed by 64 lowercase hex; Cortex converts at the
ingress boundary (`internal/builderclient/ingress_hash32.go`). No digest, Store
or preimage bytes change.

The v0.5.0 descriptor is byte for byte the one built from wire main
`41af15b5`, which these bindings were already generated from: the release
commit changes `CHANGELOG.md` only. Pinning the release changes provenance, not
a single generated line.

v0.5.1 adds registered session signing keys (wire#47). A session owner can
register one key on its `StreamState` (fields 7-11: `session_key`,
`session_key_expiry_height`, `session_key_spend_cap`, `session_key_spent`,
`session_key_set_height`), set or clear it through `MsgUpdateSessionKey` (Msg
RPC `UpdateSessionKey`), which emits `session_key_updated` (protocol event code
106). `SessionParamsV1.max_session_key_blocks` (field 11) bounds a
registration, and it moves the `TRUEOPEN_TASK_PARAMS_V1` commitment; Cortex
does not derive that commitment. A `SignedOrderV2` may now recover to the
session's registered key instead of `user_address`. The order, request and
SessionGrant preimages, task and order IDs and the EIP-712 domains are
unchanged, and the Keeper stays the only authority over who may sign: the
daemon checks that a broadcast order carries a signature, not whose it is, so
it admits a session-signed order the Keeper accepted.
`nodewire.VerifySignedOrderEnvelope` still verifies only the wallet branch; it
backs tests, not admission. Cortex signs its Task data
requests as CORTEX_SERVICE, which the new registered-key branch of the Nexus
ingress does not touch. The regenerated bindings differ in eight files
(`nexus/v1/ingress`, `shared/v1/event`, `task/v1/{event, msg_assignment,
msg_session, params, session, tx}`) and compile without a source change. The
fixtures add `task/session_key_authorization_v1.json` and
`task/session_key_amino_v1.json`, and revise `shared/params_v1.json` (the new
parameter and the digests it moves).

916e393 replaces the Phase 0 bus with the direct Builder stream
`nexus.v1.IngressAPI/DispatchStream` (`nexus/v1/dispatch.proto`). It removes the
`bus.v1` package, `BusEnvelope`, the NATS user binding, the per-task Worker
handraise (`WorkerHandraiseV1`, `MsgSubmitWorkerHandraises`), the assignment
beacon and randomness queries, and the events `EventWorkerHandraisesAccepted`,
`EventWorkerAssignmentFinalized` and `EventAssignmentFailed`. It adds the
dispatch record, compensation and omission-challenge messages and events in
`task.v1` (`dispatch*.proto`, `msg_dispatch.proto`, `query_dispatch.proto`,
`value_evidence.proto`) and `hub/v1/dispatch.proto`. Cortex deletes its NATS
transport with the bus; the stream client lands separately.

`cortex.v1` joined that graph in v0.2.1. It used to live in this repository, as
`.proto` sources generated by hand and committed, which is how the schema here
and the copy an SDK reads could drift apart without either side noticing. The
sources are gone from `proto/cortex/v1`; only generated code remains, produced
from the same release descriptor as everything else.

wire **withholds** `cortex.v1`: its fields are not frozen, so the release makes
no compatibility promise about it. That is a statement about the contract, not
about generation -- a withheld package is still in the descriptor and still
generates normally. ADR-0022 assigns further changes to `chat_input`, and wire
releases the package once those land.

What this pins is a rename of the previous contract generation, not an upgrade
of it. The proto packages carry no vendor prefix (`bus.v1`, `task.v1`, `hub.v1`,
`shared.v1`, `nexus.v1`), every signing domain is `TRUEOPEN_*`, the bech32 HRP is
`trueopen`, and the NATS subjects are `trueopen.*`. A domain literal is framed
into its own preimage, so **every digest this repository produces moved with the
rename**. Deploy with Node and Nexus builds of the same generation: a node on
either side of it cannot verify the other's signatures.

Message shapes did not change. The descriptor's vendor-neutral dependency
closure (amino, cosmos, cosmos_proto, gogoproto, google) regenerates byte for
byte against the previous generation's output, which is what shows the rename
carried no field changes with it.

## Phase 1 dispatch (916e393)

Cortex runs one `nexus.v1.IngressAPI/DispatchStream` per Builder in
`dispatch.builders` (HTTP/2; h2c only for a devnet plaintext descriptor).
Endpoint and TLS pin come only from the Builder's current on-chain service
descriptor (`NEXUS_GRPC`, `tls_pubkey_hash`); a pin mismatch drops the
descriptor cache and the next reconnect re-reads it. The first frame is
`DispatchStreamBindingV1` signed by the current Cortex service key; every
Builder frame is checked against `QueryCurrentServiceKey(BUILDER)` read once
per committed height. Keepalive probes from this side are even.

Frames Cortex sends: `StandingHandraiseV1`, `DispatchAcceptV1`,
`DispatchRejectV1`, `DispatchInputRequestV1`, `VerifierHandraiseV1` and
`VerifyResultSubmittedNoticeV1` (the last two to every stream). Frames it
handles: `HandraiseRootNoticeV1`, `DispatchOfferV1`, `DispatchRevokeV1`,
`DispatchInputResponseV1`, `RecordResultNoticeV1` (a hint; the record is
`QueryDispatchRecord`), `OpenVerifyV1` and `VerifierAssignmentNotifyV1`.
`GetDispatchRoster` is a unary IngressAPI call (signed
`DispatchRosterRequestV1`).

Chain reads: `/hub.v1.Query/{Params,Beacon,VrfKey,CurrentServiceKey}`,
`/task.v1.Query/{Session,Params,DispatchRecord,Task,TaskAssignment,
DispatchCompensationClaim,DispatchCompensationClaimsByBuilder,
DispatchWinnerIneligible,DispatchChallenge,VerifyCommit}`. Events:
`dispatch_recorded`, the compensation `claimed/paid/rebutted` and the
challenge `opened/resolved` events.

**Remote signer prerequisite.** The signing service must register these type
URLs and decode their payloads as ProtoJSON of the generated `task.v1` types
(`txclient.PhaseOneMsgKinds`): `/task.v1.MsgReportDataUnavailable`,
`/task.v1.MsgClaimDispatchCompensation`, `/task.v1.MsgChallengeDispatchOmission`,
`/task.v1.MsgReportDispatchRosterUnavailable`. Each is submitted with the
current service address as submitter, the same address the broadcaster signs as.
A node without `tx.enabled` submits none of them.

**Not implemented.** The `FetchTaskData(INPUT)` fallback authorized by
`DispatchAcceptV1` (CD §4.2.0 "取 input"): 916e393's `TaskDataRequestAuthV1`
has no slot for an accept, so input is re-requested on the same stream only.

**Known drift past 916e393** (wire `feature/phase1-dispatch-prefund@337c45a`,
for the release re-pin): `MsgChallengeDispatchOmission.bound_handraise_root`
(field 9) is required when the challenge proves a newer root than the round's
bound one; `DispatchRecordV1.dispatch_ticket_hash` may be ZERO32 for an
unfinished record and must then read as "not recorded"; input chunks are
zero-based (already so here); Builder keepalive probes are odd. The release
re-pin also regenerates the descriptor and recopies `testdata/v1`.

## Reproduction

The descriptor is committed as `proto/testdata/wire-916e393.binpb`.
Its SHA-256 is
`ad68a72183f458830515a8d2f161c2f4f7801eeb4ce68f32bfc4d1ddefbe2467`.

There is no release asset for 916e393; it is `buf build` of that commit with
the buf version wire's `contract.yml` pins:

```sh
git clone https://github.com/TrueOpen/wire && cd wire
git checkout 916e3936355cb787f6e82509619f55c6b5aad7e2 && mkdir -p build
go run github.com/bufbuild/buf/cmd/buf@v1.71.0 build -o build/wire.binpb
shasum -a 256 build/wire.binpb
```

The buf version is part of the pin. A different one may lay the same contract
out differently, and the checksum is then the only thing that would notice.

Generation uses `protoc v6.33.2`, `protoc-gen-go v1.36.11`,
`protoc-gen-connect-go v1.18.1` and `protoc-gen-go-grpc v1.6.2`. Install these
tools before running:

The three service plugins are not interchangeable and each covers one file:
connect-go generates the Nexus ingress client, go-grpc generates the
model-service client, and go covers every selected file. Running either service
plugin over the other's file would emit a second, unused client for the same
service.

```sh
make proto-gen-chain CHAIN_GEN_OUT=bin/wire-916e393-review
make proto-drift-chain
```

The output directory must be empty. Generation never deletes files or writes
into the committed tree. Review generated output before adopting it.
`scripts/wiregen` verifies the descriptor checksum and generates every v1 Hub,
Task, shared and Cortex source plus Nexus ingress and their transitive imports.
Explicit Go import mappings keep these dependencies local under `proto/`;
Google well-known types use the Protobuf runtime. No Cosmos SDK application
dependency or handwritten protobuf subset is needed.

`TestChainBindingsMatchReleasedDescriptor` compares the complete compiled
contract descriptors, including field numbers, types, oneofs and services,
against the pinned descriptor. Source locations and Buf compiler metadata are excluded. A duplicate type
registration fails process startup. Import checks prevent accidental SDK imports.
Nexus provenance is also recorded in `proto/nexus/v1/README.md`.
`proto/cortex/v1` remains Cortex's own model-service contract.

## Active Contracts

Released fixture bytes are kept unchanged under `internal/wirevectors/testdata/p1-916e393`.
wire v0.3.0 is a reviewed breaking release:

- `model_id` is a Hash32 (`TRUEOPEN_MODEL_ID_V1`). Cortex carries it as 64
  lowercase hex; operators configure it explicitly and the daemon binds it to
  the chain ModelState's `repo_id` at startup. Support and capability are
  model-scoped.
- TaskOrderV3 (EIP-712 domain version 3, `bytes32 modelId`), InferReceiptV3 and
  ResultReceiptV3 are the only active order and receipt contracts. Every
  encryption key slot is ZERO32 in plaintext.
- Worker evidence is two bundles. WORKER_TOKEN_OPENING (kind 4,
  `TRUEOPEN_WORKER_TOKEN_COMMITMENT_V1`) holds the generated and input token
  IDs; WORKER_VALUE_OPENING (kind 1, `TRUEOPEN_WORKER_VALUE_COMMITMENT_V3`)
  holds `worker_values`, the fixed-point value leaves rooted by
  `worker_value_root`. A receipt commits [value, token], and each bundle is
  uploaded and finalized under its own kind.
- The commit binds `verifier_value_root` and the salt (ResultCommitmentV3); the
  metric leaf (V3) binds the same root, and VerifierResultPayloadV2 carries it.
- OUTPUT uses signed Header/Chunk/Fin streams; the Worker signs the plaintext
  OutputStreamHeaderV2. Chunk boundaries are committed by
  `TRUEOPEN_OUTPUT_MMR_V1`, and an empty output is exactly one empty leaf.
- FinalizeTaskResult is the only transition to READY and the only source of
  Worker output/evidence storage confirmations.

The daemon still schedules first-round verification only. It now explicitly
quarantines an unsupported effective round instead of relabeling it as round one.
Automatic challenge-round execution requires separate per-round durable state.
This migration does not introduce that workflow.

Deploy with compatible Node and Nexus builds together. Drain outstanding work
before replacing the previous protocol: V2 orders, receipts and evidence cannot
be resumed as V3 material by changing their version labels.

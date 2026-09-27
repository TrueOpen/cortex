package txclient

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestFakeRecordsAcceptedAndRejectedSelfRescueSettlementAndProofTxs(t *testing.T) {
	ctx := context.Background()
	fake := NewFake()
	kinds := []Kind{
		MsgSubmitInferReceipt,
		MsgSubmitVerifyCommit,
		MsgSubmitVerifyResult,
		MsgSettleTask,
		MsgSweepDeadline,
		MsgDeclareModelSupport,
		MsgBatchConfirmModelSupport,
	}

	for _, kind := range kinds {
		obs, err := fake.Submit(ctx, Request{
			TaskID:  "task-1",
			Kind:    kind,
			Payload: validPayload(t, kind),
		})
		if err != nil {
			t.Fatalf("submit %s: %v", kind, err)
		}
		if !obs.Accepted || obs.Kind != kind || obs.TxHash == "" {
			t.Fatalf("accepted observation for %s = %#v", kind, obs)
		}
	}

	fake.RejectNext(MsgSubmitVerifyCommit, "deadline expired")
	rejected, err := fake.Submit(ctx, Request{
		TaskID:  "task-1",
		Kind:    MsgSubmitVerifyCommit,
		Payload: validPayload(t, MsgSubmitVerifyCommit),
	})
	if err != nil {
		t.Fatalf("submit rejected observation: %v", err)
	}
	if rejected.Accepted || rejected.RejectReason != "deadline expired" {
		t.Fatalf("rejected observation = %#v", rejected)
	}
	if got := fake.Accepted(MsgSubmitVerifyCommit); len(got) != 1 {
		t.Fatalf("accepted commits = %d, want only first accepted commit", len(got))
	}
	if got := fake.Rejected(MsgSubmitVerifyCommit); len(got) != 1 {
		t.Fatalf("rejected commits = %d, want 1", len(got))
	}
}

func validPayload(t testing.TB, kind Kind) []byte {
	t.Helper()
	hash := strings.Repeat("ab", 32)
	sig := strings.Repeat("cd", 64)
	var value any
	switch kind {
	case MsgRegisterModelProfile:
		value = validRegisterModelProfileMessage()
	case MsgDeclareModelSupport:
		value = DeclareModelSupportMessage{OperatorAddress: "trueopen1operator", ModelID: "0101010101010101010101010101010101010101010101010101010101010101", InferenceCapability: true}
	case MsgBatchConfirmModelSupport:
		value = BatchConfirmModelSupportMessage{SubmitterAddress: "trueopen1operator", EpochIndex: 1, Confirmations: []ModelSupportConfirmation{{OperatorAddress: "node-1", SupportedModels: []ProtoBytes32{"0101010101010101010101010101010101010101010101010101010101010101"}, ServiceAuthorizationNonce: 3, ExpiryHeight: 101, ServiceSignature: ProtoBytes(sig)}}}
	case MsgSubmitInferReceipt:
		value = validSubmitInferReceiptMessage()
	case MsgSubmitVerifyCommit:
		value = validSubmitVerifyCommitMessage()
	case MsgSubmitVerifyResult:
		value = validSubmitVerifyResultMessage()
	case MsgSettleTask:
		value = SettleTaskMessage{TaskID: ProtoBytes32(hash), SubmitterAddress: "trueopen1settler"}
	case MsgSweepDeadline:
		value = SweepDeadlineMessage{
			Locator:          DeadlineLocatorMessage{Task: &TaskDeadlineLocatorMessage{TaskID: ProtoBytes32(hash), DeadlineKind: DeadlineKindWorkerInfer}},
			SubmitterAddress: "trueopen1settler",
		}
	default:
		t.Fatalf("no test payload for kind %s", kind)
	}
	payload, err := MarshalMessage(kind, value)
	if err != nil {
		t.Fatalf("MarshalMessage(%s) error = %v", kind, err)
	}
	if len(payload) == 0 {
		t.Fatalf("MarshalMessage(%s) returned empty payload", kind)
	}
	return payload
}

func validRegisterModelProfileMessage() RegisterModelProfileMessage {
	hash := ProtoBytes32(strings.Repeat("ab", 32))
	return RegisterModelProfileMessage{
		ProposerAddress: "trueopen1operator",
		Profile: ModelProfileProjectionMessage{ModelID: "0101010101010101010101010101010101010101010101010101010101010101", ProfileVersion: 1, ManifestHash: hash, TokenizerHash: hash,
			RuntimeClass: "CAUSAL_LM_PREFILL_LOGPROBS_V1", RequiredTopK: 20, TaskTypes: []string{"TASK_TYPE_CHAT"}, GenerationType: "GENERATION_TYPE_SAMPLED",
			ResourceTier: 2, MinStake: CoinMessage{Denom: "uusdc", Amount: 1_000_000}, ChallengeOpenWindowBlocks: 1_800,
			VerificationProfile: VerificationProfileMessage{VerificationProfileID: 1, JudgmentFunctionVersion: "PREFILL_GENERATED_TOKEN_METRICS_V1", VerificationMode: "VERIFICATION_MODE_SINGLE_SAMPLE", TokenScope: "TOKEN_SCOPE_ALL_GENERATED_OUTPUT_TOKENS",
				IncludeGeneratedSpecialTokens: true, RequireOutputTokenIDs: true, RequireFinishReason: true,
				Metrics:                  MetricSpecMessage{CompareLogprobDiff: true, CompareRankDelta: true, CompareTopKJaccard: true, CompareUnionJS: true, ComparedTopK: 20, NumericScale: "NUMERIC_SCALE_FP_1E6"},
				CanonicalEncodingVersion: "CANONICAL_OUTPUT_TEXT_V1", EvidenceSchemaHash: hash, MetricAggregateProofVersion: "PREFILL_METRIC_AGGREGATE_PROOF_V1", EvidenceSchema: WorkerEvidenceSchemaV3(1<<30, 1<<30)},
			VerificationThresholds:  VerificationThresholdsMessage{PassMinFiniteCount: 16, PassMeanAbsLogprobDiffMax: 50_000, RejectMeanAbsLogprobDiffMin: 300_000},
			PricingProfile:          PricingProfileMessage{InitialOutputPrice: 10, VerifyRatioBPS: 1_000, MinOrderValue: 1_000},
			TimeoutBootstrapProfile: TimeoutBootstrapProfileMessage{InferTimeoutBootstrapBlocks: 100, VerifyTimeoutBootstrapBlocks: 50, CommitTimeoutBootstrapBlocks: 20, BootstrapValidUntilEpoch: 1_000},
			SchemaHash:              hash, RegistrationFee: CoinMessage{Denom: "uusdc", Amount: 10_000_000}, ManifestURI: "https://models.trueopen.example/manifests/org-model/v1.json",
			Source: SourceRefMessage{Provider: "HUGGINGFACE", RepoID: "org/model", RepoType: "model", ResolverVersion: "HF_RESOLVER_V1",
				Revision: strings.Repeat("0a", 20), SourceURI: "hf://org/model@" + strings.Repeat("0a", 20)}},
	}
}

func validSubmitInferReceiptMessage() SubmitInferReceiptMessage {
	hash := ProtoBytes32(strings.Repeat("ab", 32))
	zero := ProtoBytes32(strings.Repeat("00", 32))
	return SubmitInferReceiptMessage{
		Receipt: InferReceiptMessage{
			SchemaVersion: InferReceiptSchemaVersionV3, ChainID: "trueopen-devnet-1",
			TaskID: hash, TaskHash: hash, WorkerOperatorAddress: "trueopen1worker",
			ServiceAuthorizationNonce: 7, GenerationParamsDigest: hash, OutputHash: hash,
			OutputSizeBytes: 4_096, GeneratedTokenCount: 32, OutputLeafCount: 32,
			RequiredEvidenceCommitments: []EvidenceCommitmentMessage{
				{EvidenceKind: EvidenceKindWorkerValueOpening, EvidenceHashOrRoot: hash, EncodedSizeBytes: 512},
				{EvidenceKind: EvidenceKindWorkerTokenOpening, EvidenceHashOrRoot: hash, EncodedSizeBytes: 136},
			},
			ExpiryHeight: 900, ServiceSignature: ProtoBytes(strings.Repeat("cd", 64)),
			OutputKeyCommitment: zero, WorkerTokenKeyCommitment: zero, WorkerValueKeyCommitment: zero, CiphertextOutputRoot: zero,
		},
		SubmitterAddress: "trueopen1service",
	}
}

func validSubmitVerifyCommitMessage() SubmitVerifyCommitMessage {
	hash := ProtoBytes32(strings.Repeat("ab", 32))
	return SubmitVerifyCommitMessage{
		Commit: VerifyCommitMessage{
			SchemaVersion: TaskWireSchemaVersionV1, ChainID: "trueopen-devnet-1", TaskID: hash,
			VerifyRound: VerifyRoundV1, VerifierOperatorAddress: "trueopen1verifier",
			ServiceAuthorizationNonce: 7, CommitHash: hash, ExpiryHeight: 900,
			ServiceSignature: ProtoBytes(strings.Repeat("cd", 64)),
		},
		SubmitterAddress: "trueopen1service",
	}
}

func validSubmitVerifyResultMessage() SubmitVerifyResultMessage {
	hash := ProtoBytes32(strings.Repeat("ab", 32))
	return SubmitVerifyResultMessage{
		Receipt: ResultReceiptMessage{
			SchemaVersion: ResultReceiptSchemaVersionV3, ChainID: "trueopen-devnet-1", TaskID: hash,
			VerifyRound: VerifyRoundV1, VerifierOperatorAddress: "trueopen1verifier",
			ServiceAuthorizationNonce: 7, GenerationParamsDigest: hash, MetricRoot: hash,
			MetricSummary:      MetricSummaryMessage{FiniteCount: 16, ComparedTopkCount: 20, ComparedRankCount: 20},
			AggregateProofHash: hash, VerifierEvidenceBundleHash: hash, VerifierEvidenceManifestSizeBytes: 512, Salt: hash, ExpiryHeight: 900,
			ServiceSignature:  ProtoBytes(strings.Repeat("cd", 64)),
			VerifierValueRoot: hash, MetricLeafCount: 16, VerifierEvidenceKeyCommitment: ProtoBytes32(strings.Repeat("00", 32)),
		},
		SubmitterAddress: "trueopen1service",
	}
}

// TestMarshalSweepDeadlineRequiresFrozenLocator pins the frozen MsgSweepDeadline
// shape: a typed DeadlineLocatorV1 with exactly one member and a V1-registered
// DeadlineKindV1. The four K-BLOCK-03/04 gated kinds have no ACTIVE writer and
// must be refused before a transaction is built.
func TestMarshalSweepDeadlineRequiresFrozenLocator(t *testing.T) {
	hash := ProtoBytes32(strings.Repeat("ab", 32))
	if _, err := MarshalMessage(MsgSweepDeadline, SweepDeadlineMessage{SubmitterAddress: "trueopen1settler"}); err == nil ||
		!strings.Contains(err.Error(), "exactly one member") {
		t.Fatalf("MarshalMessage() error = %v, want empty locator rejection", err)
	}
	for _, gated := range []string{
		"DEADLINE_KIND_V1_EVIDENCE_REQUEST", "DEADLINE_KIND_V1_CHALLENGE_RESOLVE",
		"DEADLINE_KIND_V1_CHALLENGE_CLOSE",
		"DEADLINE_KIND_V1_UNSPECIFIED", "VERIFY_DEADLINE",
	} {
		_, err := MarshalMessage(MsgSweepDeadline, SweepDeadlineMessage{
			Locator:          DeadlineLocatorMessage{Task: &TaskDeadlineLocatorMessage{TaskID: hash, DeadlineKind: gated}},
			SubmitterAddress: "trueopen1settler",
		})
		if err == nil || !strings.Contains(err.Error(), "unsupported task deadline kind") {
			t.Fatalf("MarshalMessage(%s) error = %v, want unregistered deadline kind rejection", gated, err)
		}
	}
}

// TestMarshalSettleTaskCarriesOnlyTaskAndSubmitter pins the reshape: MsgSettleTask
// has exactly two fields, so any Keeper-derived fact must be impossible to
// express, and a non-canonical task_id must be refused.
func TestMarshalSettleTaskCarriesOnlyTaskAndSubmitter(t *testing.T) {
	hash := ProtoBytes32(strings.Repeat("ab", 32))
	payload, err := MarshalMessage(MsgSettleTask, SettleTaskMessage{TaskID: hash, SubmitterAddress: "trueopen1settler"})
	if err != nil {
		t.Fatalf("MarshalMessage() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decode settle payload: %v", err)
	}
	if len(decoded) != 2 {
		t.Fatalf("settle payload fields = %v, want only task_id and submitter_address", decoded)
	}
	if _, ok := decoded["task_id"]; !ok {
		t.Fatalf("settle payload = %v, want task_id", decoded)
	}
	if _, ok := decoded["submitter_address"]; !ok {
		t.Fatalf("settle payload = %v, want submitter_address", decoded)
	}
	if _, err := MarshalMessage(MsgSettleTask, SettleTaskMessage{TaskID: ProtoBytes32("ab"), SubmitterAddress: "trueopen1settler"}); err == nil {
		t.Fatal("MarshalMessage() accepted a non-canonical task_id")
	}
	if _, err := MarshalMessage(MsgSettleTask, SettleTaskMessage{TaskID: hash}); err == nil {
		t.Fatal("MarshalMessage() accepted a missing submitter_address")
	}
}

func TestFakeRejectsUnknownTxKind(t *testing.T) {
	fake := NewFake()
	if _, err := fake.Submit(context.Background(), Request{
		TaskID:  "task-1",
		Kind:    Kind("MsgUnknownTx"),
		Payload: []byte("payload"),
	}); err == nil {
		t.Fatalf("unknown tx kind accepted")
	}
}

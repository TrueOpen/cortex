package txclient

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
)

func TestKeeperConfirmerUsesCodeZeroInclusionForUnqueryableRecords(t *testing.T) {
	confirmer := NewKeeperConfirmer(&confirmationReader{})
	for _, kind := range []Kind{MsgSubmitVerifyCommit, MsgSubmitVerifyResult} {
		confirmed, err := confirmer.Confirm(context.Background(), Request{TaskID: "task-1", Kind: kind, Payload: validPayload(t, kind)}, InclusionResult{Code: CodeOK, Height: 42})
		if err != nil || !confirmed {
			t.Fatalf("Confirm(%s) = %v, %v", kind, confirmed, err)
		}
	}
}

func TestKeeperConfirmerRejectsFailedOrMissingInclusion(t *testing.T) {
	confirmer := NewKeeperConfirmer(&confirmationReader{})
	for _, inclusion := range []InclusionResult{{Code: 7, Height: 42}, {Code: CodeOK, Height: 0}} {
		if _, err := confirmer.Confirm(context.Background(), Request{TaskID: "task-1", Kind: MsgSubmitVerifyCommit, Payload: validPayload(t, MsgSubmitVerifyCommit)}, inclusion); err == nil {
			t.Fatalf("Confirm(%#v) error = nil", inclusion)
		}
	}
}

func TestKeeperConfirmerMatchesCurrentAtomicModelProfileProjection(t *testing.T) {
	message := validRegisterModelProfileMessage()
	reader := &confirmationReader{currentProfile: currentStateForMessage(message, 42)}
	payload, err := MarshalMessage(MsgRegisterModelProfile, message)
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := NewKeeperConfirmer(reader).Confirm(context.Background(), Request{TaskID: "registration", Kind: MsgRegisterModelProfile, Payload: payload}, InclusionResult{Code: CodeOK, Height: 42})
	if err != nil || !confirmed {
		t.Fatalf("Confirm(current registration) = %v, %v", confirmed, err)
	}
	if reader.currentModelID != message.Profile.ModelID.Hex() || reader.currentProfileVersion != "1" {
		t.Fatalf("current profile query = %q/%q", reader.currentModelID, reader.currentProfileVersion)
	}

	reader.currentProfile.Profile.PricingProfile.InitialOutputPrice++
	confirmed, err = NewKeeperConfirmer(reader).Confirm(context.Background(), Request{TaskID: "registration", Kind: MsgRegisterModelProfile, Payload: payload}, InclusionResult{Code: CodeOK, Height: 42})
	if err != nil || confirmed {
		t.Fatalf("Confirm(current registration mismatch) = %v, %v", confirmed, err)
	}
}

func TestKeeperConfirmerConfirmsDeclareAgainstCurrentCapabilityState(t *testing.T) {
	payload := validPayload(t, MsgDeclareModelSupport)
	var message DeclareModelSupportMessage
	if err := json.Unmarshal(payload, &message); err != nil {
		t.Fatal(err)
	}
	reader := &confirmationReader{capability: capabilityStateForMessage(message), support: supportStateForMessage(message)}
	confirmed, err := NewKeeperConfirmer(reader).Confirm(context.Background(), Request{TaskID: "support", Kind: MsgDeclareModelSupport, Payload: payload}, InclusionResult{Code: CodeOK, Height: 42})
	if err != nil || !confirmed {
		t.Fatalf("Confirm(MsgDeclareModelSupport) = %v, %v", confirmed, err)
	}
	if reader.capabilityProvider != "trueopen1operator" || reader.capabilityModel != "0101010101010101010101010101010101010101010101010101010101010101" {
		t.Fatalf("capability query = %q/%q, want operator-level key", reader.capabilityProvider, reader.capabilityModel)
	}
	pending, err := NewKeeperConfirmer(&confirmationReader{capabilityErr: chainclient.ErrNotFound}).Confirm(context.Background(), Request{TaskID: "support", Kind: MsgDeclareModelSupport, Payload: payload}, InclusionResult{Code: CodeOK, Height: 42})
	if err != nil || pending {
		t.Fatalf("Confirm(pending capability) = %v, %v", pending, err)
	}

	tests := []struct {
		name   string
		mutate func(*chainclient.ModelCapabilitySnapshot)
	}{
		{name: "inference flag", mutate: func(s *chainclient.ModelCapabilitySnapshot) { s.InferenceCapability = !s.InferenceCapability }},
		{name: "verification flag", mutate: func(s *chainclient.ModelCapabilitySnapshot) { s.VerificationCapability = !s.VerificationCapability }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := capabilityStateForMessage(message)
			tt.mutate(&state)
			confirmed, err := NewKeeperConfirmer(&confirmationReader{capability: state, support: supportStateForMessage(message)}).Confirm(context.Background(), Request{TaskID: "support", Kind: MsgDeclareModelSupport, Payload: payload}, InclusionResult{Code: CodeOK, Height: 42})
			if err != nil || confirmed {
				t.Fatalf("Confirm(mismatch) = %v, %v", confirmed, err)
			}
		})
	}
}

func TestKeeperConfirmerUsesNodeLevelModelSupportKeyForBatchRefresh(t *testing.T) {
	reader := &confirmationReader{support: chainclient.ModelSupportSnapshot{
		OperatorAddress: "node-1", ModelID: "0101010101010101010101010101010101010101010101010101010101010101", DeclaredSupport: true,
		SupportVersion: 1, LastRefreshHeight: 42,
	}}
	confirmed, err := NewKeeperConfirmer(reader).Confirm(context.Background(), Request{TaskID: "support", Kind: MsgBatchConfirmModelSupport, Payload: validPayload(t, MsgBatchConfirmModelSupport)}, InclusionResult{Code: CodeOK, Height: 42})
	if err != nil || !confirmed {
		t.Fatalf("Confirm(MsgBatchConfirmModelSupport) = %v, %v", confirmed, err)
	}
	if reader.supportProvider != "node-1" || reader.supportModel != "0101010101010101010101010101010101010101010101010101010101010101" {
		t.Fatalf("support query = %q/%q, want node-level key", reader.supportProvider, reader.supportModel)
	}
}

func TestKeeperConfirmerMatchesSessionScopedInferReceipt(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	reader := &confirmationReader{task: chainclient.TaskSnapshot{
		Assignment:   chainclient.AssignmentSnapshot{SessionID: "session-1", TaskID: hash, SelectedWorker: "trueopen1worker"},
		InferReceipt: chainclient.InferReceiptSnapshot{OutputHash: keeperHash(t, hash)},
	}}
	confirmed, err := NewKeeperConfirmer(reader).Confirm(context.Background(),
		Request{TaskID: hash, SessionID: "session-1", Kind: MsgSubmitInferReceipt, Payload: validPayload(t, MsgSubmitInferReceipt)},
		InclusionResult{Code: CodeOK, Height: 42})
	if err != nil || !confirmed {
		t.Fatalf("Confirm() = %v, %v", confirmed, err)
	}
	// The frozen receipt carries no session_id, so the session must come from the
	// request envelope rather than the message body.
	if reader.taskSession != "session-1" || reader.taskID != hash {
		t.Fatalf("Task query = %q/%q", reader.taskSession, reader.taskID)
	}
}

// TestKeeperConfirmerSettlesWithoutAssertingKeeperDerivedFacts pins the
// MsgSettleTask reshape: the message asserts no verdict or settlement id, so the
// confirmation uses the registered Task view, including idempotent submissions
// whose original settlement predates the new code-0 inclusion.
func TestKeeperConfirmerSettlesWithoutAssertingKeeperDerivedFacts(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	payload, err := MarshalMessage(MsgSettleTask, SettleTaskMessage{TaskID: ProtoBytes32(hash), SubmitterAddress: "trueopen1settler"})
	if err != nil {
		t.Fatalf("MarshalMessage() error = %v", err)
	}
	request := Request{TaskID: hash, SessionID: "session-1", Kind: MsgSettleTask, Payload: payload}
	reader := &settlementConfirmationReader{confirmationReader: &confirmationReader{}, state: chainclient.SettlementContext{
		SessionID: "session-1", TaskID: hash, Phase: 8, ObservedHeight: 50, UpdatedHeight: 40,
	}}
	confirmed, err := NewKeeperConfirmer(reader).Confirm(context.Background(), request, InclusionResult{Code: CodeOK, Height: 42})
	if err != nil || !confirmed {
		t.Fatalf("Confirm() = %v, %v", confirmed, err)
	}
	stale := *reader
	stale.state.ObservedHeight = 41
	confirmed, err = NewKeeperConfirmer(&stale).Confirm(context.Background(), request, InclusionResult{Code: CodeOK, Height: 42})
	if err != nil || confirmed {
		t.Fatalf("Confirm(stale settlement) = %v, %v", confirmed, err)
	}
	unsettled := *reader
	unsettled.state.Phase = 7
	confirmed, err = NewKeeperConfirmer(&unsettled).Confirm(context.Background(), request, InclusionResult{Code: CodeOK, Height: 42})
	if err != nil || confirmed {
		t.Fatalf("Confirm(no settlement row) = %v, %v", confirmed, err)
	}
}

type settlementConfirmationReader struct {
	*confirmationReader
	state chainclient.SettlementContext
	err   error
}

func (r *settlementConfirmationReader) SettlementContext(context.Context, string) (chainclient.SettlementContext, error) {
	return r.state, r.err
}

func (r *settlementConfirmationReader) Settlement(context.Context, string, string) (chainclient.TaskSettlementSnapshot, error) {
	return chainclient.TaskSettlementSnapshot{}, fmt.Errorf("retired Settlement RPC must not be called")
}

func TestSettlementConfirmationRequiresMatchingTerminalTask(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	payload, err := MarshalMessage(MsgSettleTask, SettleTaskMessage{TaskID: ProtoBytes32(hash), SubmitterAddress: "trueopen1settler"})
	if err != nil {
		t.Fatal(err)
	}
	request := Request{TaskID: hash, SessionID: "session-1", Kind: MsgSettleTask, Payload: payload}
	for _, mutate := range []func(*chainclient.SettlementContext){
		func(s *chainclient.SettlementContext) { s.TaskID = strings.Repeat("cd", 32) },
		func(s *chainclient.SettlementContext) { s.SessionID = "other-session" },
		func(s *chainclient.SettlementContext) { s.Phase = 6 },
		func(s *chainclient.SettlementContext) { s.UpdatedHeight = 0 },
	} {
		reader := &settlementConfirmationReader{confirmationReader: &confirmationReader{}, state: chainclient.SettlementContext{
			TaskID: hash, SessionID: "session-1", Phase: 8, UpdatedHeight: 40, ObservedHeight: 50,
		}}
		mutate(&reader.state)
		confirmed, err := NewKeeperConfirmer(reader).Confirm(context.Background(), request, InclusionResult{Code: CodeOK, Height: 42})
		if err != nil || confirmed {
			t.Fatalf("state=%#v confirmed=%t error=%v", reader.state, confirmed, err)
		}
	}
}

// TestKeeperConfirmerSweepRequiresTaskStateToMove pins the MsgSweepDeadline
// reshape: the response counts visited work rather than a named mutation, so the
// observable proof is the swept task's own updated height.
func TestKeeperConfirmerSweepRequiresTaskStateToMove(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	payload := validPayload(t, MsgSweepDeadline)
	request := Request{TaskID: hash, SessionID: "session-1", Kind: MsgSweepDeadline, Payload: payload}
	reader := &confirmationReader{task: chainclient.TaskSnapshot{
		UpdatedHeight: chainclient.NewUint64String(42),
		Assignment:    chainclient.AssignmentSnapshot{SessionID: "session-1", TaskID: hash},
	}}
	confirmed, err := NewKeeperConfirmer(reader).Confirm(context.Background(), request, InclusionResult{Code: CodeOK, Height: 42})
	if err != nil || !confirmed {
		t.Fatalf("Confirm() = %v, %v", confirmed, err)
	}
	stale := *reader
	stale.task.UpdatedHeight = chainclient.NewUint64String(41)
	confirmed, err = NewKeeperConfirmer(&stale).Confirm(context.Background(), request, InclusionResult{Code: CodeOK, Height: 42})
	if err != nil || confirmed {
		t.Fatalf("Confirm(unmoved task) = %v, %v", confirmed, err)
	}
}

func TestKeeperConfirmerRejectsMissingReaderAndMalformedPayload(t *testing.T) {
	if _, err := NewKeeperConfirmer(nil).Confirm(context.Background(), Request{}, InclusionResult{}); err == nil {
		t.Fatal("Confirm error = nil, want missing reader error")
	}
	if _, err := NewKeeperConfirmer(&confirmationReader{}).Confirm(context.Background(), Request{TaskID: "task-1", Kind: MsgSubmitVerifyCommit, Payload: []byte(`{}`)}, InclusionResult{Code: CodeOK, Height: 42}); err == nil {
		t.Fatal("Confirm error = nil, want invalid payload error")
	}
}

type confirmationReader struct {
	task                  chainclient.TaskSnapshot
	model                 chainclient.ModelSnapshot
	profile               chainclient.ProfileSnapshot
	capability            chainclient.ModelCapabilitySnapshot
	capabilityErr         error
	support               chainclient.ModelSupportSnapshot
	settlement            chainclient.TaskSettlementSnapshot
	challengeCommit       chainclient.ChallengeCommitSnapshot
	challengeResult       chainclient.ChallengeResultReceiptSnapshot
	challengeFull         chainclient.ChallengeFullResultRevealSnapshot
	currentProfile        chainclient.CurrentModelProfileSnapshot
	taskSession           string
	taskID                string
	modelID               string
	profileID             string
	profileVersion        string
	supportProvider       string
	supportModel          string
	supportProfile        string
	capabilityProvider    string
	capabilityModel       string
	capabilityProfile     string
	currentModelID        string
	currentProfileVersion string
}

func (r *confirmationReader) CurrentModelProfile(_ context.Context, modelID, profileVersion string) (chainclient.CurrentModelProfileSnapshot, error) {
	r.currentModelID, r.currentProfileVersion = modelID, profileVersion
	return r.currentProfile, nil
}

func (r *confirmationReader) Task(_ context.Context, sessionID, taskID string) (chainclient.TaskSnapshot, error) {
	r.taskSession, r.taskID = sessionID, taskID
	return r.task, nil
}
func (r *confirmationReader) Model(_ context.Context, modelID string) (chainclient.ModelSnapshot, error) {
	r.modelID = modelID
	return r.model, nil
}
func (r *confirmationReader) Profile(_ context.Context, modelID, profileVersion string) (chainclient.ProfileSnapshot, error) {
	r.profileID, r.profileVersion = modelID, profileVersion
	return r.profile, nil
}
func (r *confirmationReader) ModelSupport(_ context.Context, provider, model string) (chainclient.ModelSupportSnapshot, error) {
	r.supportProvider, r.supportModel = provider, model
	return r.support, nil
}
func (r *confirmationReader) ModelCapability(_ context.Context, provider, model string) (chainclient.ModelCapabilitySnapshot, error) {
	r.capabilityProvider, r.capabilityModel = provider, model
	return r.capability, r.capabilityErr
}
func (r *confirmationReader) Settlement(context.Context, string, string) (chainclient.TaskSettlementSnapshot, error) {
	return r.settlement, nil
}
func (r *confirmationReader) ChallengeCommit(context.Context, string, string) (chainclient.ChallengeCommitSnapshot, error) {
	return r.challengeCommit, nil
}
func (r *confirmationReader) ChallengeResultReceipt(context.Context, string, string) (chainclient.ChallengeResultReceiptSnapshot, error) {
	return r.challengeResult, nil
}

func currentStateForMessage(message RegisterModelProfileMessage, height uint64) chainclient.CurrentModelProfileSnapshot {
	p := message.Profile
	decode := func(value ProtoBytes32) chainclient.ProtoBytes32 {
		decoded, _ := hex.DecodeString(value.Hex())
		return chainclient.ProtoBytes32(decoded)
	}
	return chainclient.CurrentModelProfileSnapshot{
		Model: chainclient.CurrentModelSnapshot{ModelID: p.ModelID.Hex(), ProposerAddress: message.ProposerAddress, Provider: p.Source.Provider, RepoID: p.Source.RepoID},
		Profile: chainclient.CurrentProfileSnapshot{
			Source:  chainclient.CurrentProfileSourceSnapshot{SourceURI: p.Source.SourceURI, Revision: p.Source.Revision, ResolverVersion: p.Source.ResolverVersion, RepoType: p.Source.RepoType},
			ModelID: p.ModelID.Hex(), ProfileVersion: chainclient.NewProfileVersion(uint32(p.ProfileVersion)), ManifestHash: decode(p.ManifestHash), TokenizerHash: decode(p.TokenizerHash),
			RuntimeClass: p.RuntimeClass, RequiredTopK: uint32(p.RequiredTopK), TaskTypes: append([]string(nil), p.TaskTypes...), GenerationType: p.GenerationType,
			ResourceTier: uint32(p.ResourceTier), MinStake: chainclient.NewUint64String(uint64(p.MinStake.Amount)), ChallengeOpenWindowBlocks: chainclient.NewUint64String(uint64(p.ChallengeOpenWindowBlocks)),
			VerificationProfile: chainclient.CurrentVerificationProfileSnapshot{
				VerificationProfileID: uint32(p.VerificationProfile.VerificationProfileID), JudgmentFunctionVersion: p.VerificationProfile.JudgmentFunctionVersion,
				VerificationMode: p.VerificationProfile.VerificationMode, TokenScope: p.VerificationProfile.TokenScope,
				IncludeGeneratedSpecialTokens: p.VerificationProfile.IncludeGeneratedSpecialTokens, IncludePromptTokens: p.VerificationProfile.IncludePromptTokens,
				IncludePaddingTokens: p.VerificationProfile.IncludePaddingTokens, RequireOutputTokenIDs: p.VerificationProfile.RequireOutputTokenIDs,
				RequireFinishReason: p.VerificationProfile.RequireFinishReason,
				Metrics: chainclient.CurrentMetricSpecSnapshot{
					CompareLogprobDiff: p.VerificationProfile.Metrics.CompareLogprobDiff, CompareRankDelta: p.VerificationProfile.Metrics.CompareRankDelta,
					CompareTopKJaccard: p.VerificationProfile.Metrics.CompareTopKJaccard, CompareUnionJS: p.VerificationProfile.Metrics.CompareUnionJS,
					ComparedTopK: uint32(p.VerificationProfile.Metrics.ComparedTopK), NumericScale: p.VerificationProfile.Metrics.NumericScale,
				},
				CanonicalEncodingVersion: p.VerificationProfile.CanonicalEncodingVersion, EvidenceSchemaHash: decode(p.VerificationProfile.EvidenceSchemaHash),
				MetricAggregateProofVersion: p.VerificationProfile.MetricAggregateProofVersion,
				EvidenceSchema:              currentStateEvidenceSchema(p.VerificationProfile.EvidenceSchema),
			},
			VerificationThresholds: currentStateThresholds(p.VerificationThresholds),
			BatchVerification: chainclient.CurrentBatchVerificationSnapshot{
				Enabled: p.BatchVerification.Enabled, MinSampleCount: uint32(p.BatchVerification.MinSampleCount), MinValidSampleCount: uint32(p.BatchVerification.MinValidSampleCount),
				PassMinSamplePassRatioBPS: uint32(p.BatchVerification.PassMinSamplePassRatioBPS), RejectMinSampleRejectRatioBPS: uint32(p.BatchVerification.RejectMinSampleRejectRatioBPS),
			},
			PricingProfile: chainclient.CurrentPricingProfileSnapshot{
				InitialOutputPrice: chainclient.NewUint64String(uint64(p.PricingProfile.InitialOutputPrice)), VerifyRatioBPS: uint32(p.PricingProfile.VerifyRatioBPS), MinOrderValue: chainclient.NewUint64String(uint64(p.PricingProfile.MinOrderValue)),
			},
			TimeoutBootstrapProfile: chainclient.CurrentTimeoutBootstrapProfileSnapshot{
				InferTimeoutBootstrapBlocks: uint32(p.TimeoutBootstrapProfile.InferTimeoutBootstrapBlocks), VerifyTimeoutBootstrapBlocks: uint32(p.TimeoutBootstrapProfile.VerifyTimeoutBootstrapBlocks),
				CommitTimeoutBootstrapBlocks: uint32(p.TimeoutBootstrapProfile.CommitTimeoutBootstrapBlocks), BootstrapValidUntilEpoch: chainclient.NewUint64String(uint64(p.TimeoutBootstrapProfile.BootstrapValidUntilEpoch)),
			},
			SchemaHash: decode(p.SchemaHash), PreviousProfileVersion: chainclient.NewProfileVersion(uint32(p.PreviousProfileVersion)),
			RegistrationFeePaid: chainclient.NewUint64String(uint64(p.RegistrationFee.Amount)),
			ProposerAddress:     message.ProposerAddress, CreatedHeight: chainclient.NewUint64String(height),
		},
	}
}

func currentStateEvidenceSchema(schema EvidenceSchemaMessage) chainclient.CurrentEvidenceSchemaSnapshot {
	requirements := make([]chainclient.CurrentInferEvidenceRequirementSnapshot, len(schema.RequiredInferEvidence))
	for index, requirement := range schema.RequiredInferEvidence {
		kind := int32(0)
		switch requirement.EvidenceKind {
		case "EVIDENCE_KIND_WORKER_VALUE_OPENING":
			kind = 1
		case "EVIDENCE_KIND_VERIFIER_VALUE_OPENING":
			kind = 2
		case "EVIDENCE_KIND_SETTLEMENT_ROOT_OPENING":
			kind = 3
		case "EVIDENCE_KIND_WORKER_TOKEN_OPENING":
			kind = 4
		}
		requirements[index] = chainclient.CurrentInferEvidenceRequirementSnapshot{
			EvidenceKind: kind, CommitmentSchemaVersion: uint32(requirement.CommitmentSchemaVersion),
			MaxEncodedSizeBytes: chainclient.NewUint64String(uint64(requirement.MaxEncodedSizeBytes)),
		}
	}
	return chainclient.CurrentEvidenceSchemaSnapshot{SchemaVersion: uint32(schema.SchemaVersion), RequiredInferEvidence: requirements}
}

func currentStateThresholds(p VerificationThresholdsMessage) chainclient.CurrentVerificationThresholdsSnapshot {
	return chainclient.CurrentVerificationThresholdsSnapshot{
		PassMinFiniteCount: uint32(p.PassMinFiniteCount), PassMaxMissingComparedCount: uint32(p.PassMaxMissingComparedCount),
		PassMeanAbsLogprobDiffMax: uint32(p.PassMeanAbsLogprobDiffMax), PassAbsLogprobDiffP95Max: uint32(p.PassAbsLogprobDiffP95Max), PassAbsLogprobDiffP99Max: uint32(p.PassAbsLogprobDiffP99Max),
		PassRankDeltaNonzeroRateMax: uint32(p.PassRankDeltaNonzeroRateMax), PassTopKJaccardMeanMin: uint32(p.PassTopKJaccardMeanMin), PassUnionJSP99Max: uint32(p.PassUnionJSP99Max),
		RejectMeanAbsLogprobDiffMin: uint32(p.RejectMeanAbsLogprobDiffMin), RejectAbsLogprobDiffP95Min: uint32(p.RejectAbsLogprobDiffP95Min), RejectAbsLogprobDiffP99Min: uint32(p.RejectAbsLogprobDiffP99Min),
		RejectRankDeltaNonzeroRateMin: uint32(p.RejectRankDeltaNonzeroRateMin), RejectTopKJaccardMeanMax: uint32(p.RejectTopKJaccardMeanMax), RejectUnionJSP99Min: uint32(p.RejectUnionJSP99Min),
	}
}
func (r *confirmationReader) ChallengeFullResultReveal(context.Context, string, string) (chainclient.ChallengeFullResultRevealSnapshot, error) {
	return r.challengeFull, nil
}

func keeperHash(t *testing.T, value string) chainclient.HexHash {
	t.Helper()
	var hash chainclient.HexHash
	if err := hash.UnmarshalJSON([]byte(`"` + value + `"`)); err != nil {
		t.Fatalf("decode hash: %v", err)
	}
	return hash
}

func codecHashString(hash codec.Hash) string {
	return fmt.Sprintf("%x", hash[:])
}

func capabilityStateForMessage(message DeclareModelSupportMessage) chainclient.ModelCapabilitySnapshot {
	return chainclient.ModelCapabilitySnapshot{
		OperatorAddress: message.OperatorAddress, ModelID: message.ModelID.Hex(),
		InferenceCapability: message.InferenceCapability, VerificationCapability: message.VerificationCapability, CapabilityVersion: 1,
	}
}

func supportStateForMessage(message DeclareModelSupportMessage) chainclient.ModelSupportSnapshot {
	return chainclient.ModelSupportSnapshot{
		OperatorAddress: message.OperatorAddress, ModelID: message.ModelID.Hex(),
		DeclaredSupport: true, SupportVersion: 1,
	}
}

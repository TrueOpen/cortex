package modelmanifest

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/keepercontract"
	"github.com/TrueOpen/cortex/internal/txclient"
)

// Projection is the ModelProfileProjection this manifest projects onto, given
// its manifest_hash. Fields that are not inside the manifest are left zero:
// registration_fee, which the registrant supplies with the transaction, and
// the manifest's own retrieval location. A caller rebuilding the full
// projection takes those from the chain.
func (m *Manifest) Projection(manifestHash codec.Hash) txclient.ModelProfileProjectionMessage {
	taskTypes := make([]string, len(m.ProfileSpec.TaskTypes))
	for index, value := range m.ProfileSpec.TaskTypes {
		taskTypes[index] = "TASK_TYPE_" + value
	}
	requirements := make([]txclient.InferEvidenceRequirementMessage, len(m.VerificationProfile.EvidenceSchema.RequiredInferEvidence))
	for index, requirement := range m.VerificationProfile.EvidenceSchema.RequiredInferEvidence {
		requirements[index] = txclient.InferEvidenceRequirementMessage{
			EvidenceKind:            "EVIDENCE_KIND_" + requirement.EvidenceKind,
			CommitmentSchemaVersion: txclient.ProtoUint32(requirement.CommitmentSchemaVersion),
			MaxEncodedSizeBytes:     txclient.ProtoUint64(requirement.MaxEncodedSizeBytes),
		}
	}
	verification := m.VerificationProfile
	thresholds := m.VerificationThresholds
	return txclient.ModelProfileProjectionMessage{
		ModelID:                   bytes32Hex(m.Identity.ModelID),
		ProfileVersion:            txclient.ProtoUint32(m.Identity.ProfileVersion),
		ManifestHash:              txclient.ProtoBytes32(manifestHash.String()),
		TokenizerHash:             bytes32Hex(m.Artifacts.TokenizerHash),
		RuntimeClass:              m.RuntimeRequirements.RuntimeClass,
		RequiredTopK:              txclient.ProtoUint32(m.RuntimeRequirements.RequiredTopK),
		TaskTypes:                 taskTypes,
		GenerationType:            "GENERATION_TYPE_" + m.ProfileSpec.GenerationType,
		ResourceTier:              txclient.ProtoUint32(m.ProfileSpec.ResourceTier),
		MinStake:                  txclient.CoinMessage{Denom: m.ProfileSpec.MinStake.Denom, Amount: txclient.ProtoUint64(m.ProfileSpec.MinStake.Amount)},
		ChallengeOpenWindowBlocks: txclient.ProtoUint64(m.ProfileSpec.ChallengeOpenWindowBlocks),
		VerificationProfile: txclient.VerificationProfileMessage{
			VerificationProfileID:         txclient.ProtoUint32(verification.VerificationProfileID),
			JudgmentFunctionVersion:       verification.JudgmentFunctionVersion,
			VerificationMode:              "VERIFICATION_MODE_" + verification.VerificationMode,
			TokenScope:                    "TOKEN_SCOPE_" + verification.TokenScope,
			IncludeGeneratedSpecialTokens: verification.IncludeGeneratedSpecialTokens,
			IncludePromptTokens:           verification.IncludePromptTokens,
			IncludePaddingTokens:          verification.IncludePaddingTokens,
			RequireOutputTokenIDs:         verification.RequireOutputTokenIDs,
			RequireFinishReason:           verification.RequireFinishReason,
			Metrics: txclient.MetricSpecMessage{
				CompareLogprobDiff: verification.Metrics.CompareLogprobDiff,
				CompareRankDelta:   verification.Metrics.CompareRankDelta,
				CompareTopKJaccard: verification.Metrics.CompareTopKJaccard,
				CompareUnionJS:     verification.Metrics.CompareUnionJS,
				ComparedTopK:       txclient.ProtoUint32(verification.Metrics.ComparedTopK),
				NumericScale:       "NUMERIC_SCALE_" + verification.Metrics.NumericScale,
			},
			CanonicalEncodingVersion:    verification.CanonicalEncodingVersion,
			EvidenceSchemaHash:          bytes32Hex(verification.EvidenceSchemaHash),
			MetricAggregateProofVersion: verification.MetricAggregateProofVersion,
			EvidenceSchema: txclient.EvidenceSchemaMessage{
				SchemaVersion:         txclient.ProtoUint32(verification.EvidenceSchema.SchemaVersion),
				RequiredInferEvidence: requirements,
			},
		},
		VerificationThresholds: txclient.VerificationThresholdsMessage{
			PassMinFiniteCount:            txclient.ProtoUint32(thresholds.PassMinFiniteCount),
			PassMaxMissingComparedCount:   txclient.ProtoUint32(thresholds.PassMaxMissingComparedCount),
			PassMeanAbsLogprobDiffMax:     txclient.ProtoUint32(thresholds.PassMeanAbsLogprobDiffMax),
			PassAbsLogprobDiffP95Max:      txclient.ProtoUint32(thresholds.PassAbsLogprobDiffP95Max),
			PassAbsLogprobDiffP99Max:      txclient.ProtoUint32(thresholds.PassAbsLogprobDiffP99Max),
			PassRankDeltaNonzeroRateMax:   txclient.ProtoUint32(thresholds.PassRankDeltaNonzeroRateMax),
			PassTopKJaccardMeanMin:        txclient.ProtoUint32(thresholds.PassTopKJaccardMeanMin),
			PassUnionJSP99Max:             txclient.ProtoUint32(thresholds.PassUnionJSP99Max),
			RejectMeanAbsLogprobDiffMin:   txclient.ProtoUint32(thresholds.RejectMeanAbsLogprobDiffMin),
			RejectAbsLogprobDiffP95Min:    txclient.ProtoUint32(thresholds.RejectAbsLogprobDiffP95Min),
			RejectAbsLogprobDiffP99Min:    txclient.ProtoUint32(thresholds.RejectAbsLogprobDiffP99Min),
			RejectRankDeltaNonzeroRateMin: txclient.ProtoUint32(thresholds.RejectRankDeltaNonzeroRateMin),
			RejectTopKJaccardMeanMax:      txclient.ProtoUint32(thresholds.RejectTopKJaccardMeanMax),
			RejectUnionJSP99Min:           txclient.ProtoUint32(thresholds.RejectUnionJSP99Min),
		},
		BatchVerification: txclient.BatchVerificationMessage{
			Enabled:                       m.BatchVerification.Enabled,
			MinSampleCount:                txclient.ProtoUint32(m.BatchVerification.MinSampleCount),
			MinValidSampleCount:           txclient.ProtoUint32(m.BatchVerification.MinValidSampleCount),
			PassMinSamplePassRatioBPS:     txclient.ProtoUint32(m.BatchVerification.PassMinSamplePassRatioBPS),
			RejectMinSampleRejectRatioBPS: txclient.ProtoUint32(m.BatchVerification.RejectMinSampleRejectRatioBPS),
		},
		PricingProfile: txclient.PricingProfileMessage{
			InitialOutputPrice: txclient.ProtoUint64(m.PricingProfile.InitialOutputPrice),
			VerifyRatioBPS:     txclient.ProtoUint32(m.PricingProfile.VerifyRatioBPS),
			MinOrderValue:      txclient.ProtoUint64(m.PricingProfile.MinOrderValue),
		},
		TimeoutBootstrapProfile: txclient.TimeoutBootstrapProfileMessage{
			InferTimeoutBootstrapBlocks:  txclient.ProtoUint32(m.TimeoutBootstrapProfile.InferTimeoutBootstrapBlocks),
			VerifyTimeoutBootstrapBlocks: txclient.ProtoUint32(m.TimeoutBootstrapProfile.VerifyTimeoutBootstrapBlocks),
			CommitTimeoutBootstrapBlocks: txclient.ProtoUint32(m.TimeoutBootstrapProfile.CommitTimeoutBootstrapBlocks),
			BootstrapValidUntilEpoch:     txclient.ProtoUint64(m.TimeoutBootstrapProfile.BootstrapValidUntilEpoch),
		},
		SchemaHash:             bytes32Hex(m.ProfileSpec.SchemaHash),
		PreviousProfileVersion: txclient.ProtoUint32(m.Identity.PreviousProfileVersion),
		Source: txclient.SourceRefMessage{
			Provider: m.Source.Provider, SourceURI: m.Source.SourceURI, Revision: m.Source.Revision,
			ResolverVersion: m.Source.ResolverVersion, RepoID: m.Source.RepoID, RepoType: m.Source.RepoType,
		},
		ToolCallParser:  parserRef(m.ToolCalling.Parser),
		ReasoningParser: parserRef(m.ReasoningParsing.Parser),
	}
}

// CompareWithChain checks every projection field the manifest carries against
// the chain's registered state, which wins on any disagreement. The chain
// keeps coin amounts without their denomination, so denominations are not
// compared; registration_fee is not inside the manifest and is taken from
// the chain.
func (m *Manifest) CompareWithChain(manifestHash codec.Hash, chain chainclient.CurrentModelProfileSnapshot) error {
	fromChain := txclient.ProjectionFromChainState(chain.Model, chain.Profile)
	fromManifest := m.Projection(manifestHash)
	fromManifest.MinStake.Denom = ""
	fromManifest.RegistrationFee = fromChain.RegistrationFee
	if chain.Model.ModelID != chain.Profile.ModelID {
		return fmt.Errorf("chain model %s and profile %s disagree", chain.Model.ModelID, chain.Profile.ModelID)
	}
	manifestFields, err := canonicalProjectionFields(fromManifest)
	if err != nil {
		return fmt.Errorf("manifest projection: %w", err)
	}
	chainFields, err := canonicalProjectionFields(fromChain)
	if err != nil {
		return fmt.Errorf("chain projection: %w", err)
	}
	var mismatched []string
	diffFields("", manifestFields, chainFields, &mismatched)
	if len(mismatched) > 0 {
		sort.Strings(mismatched)
		return fmt.Errorf("manifest disagrees with the chain profile on %s", strings.Join(mismatched, ", "))
	}
	return nil
}

// canonicalProjectionFields renders a projection the way the registration
// digests see it, so enum spellings and number encodings cannot hide or
// invent a difference. It also re-derives evidence_schema_hash.
func canonicalProjectionFields(profile txclient.ModelProfileProjectionMessage) (map[string]any, error) {
	encoded, err := keepercontract.CanonicalModelProfileProjection(profile)
	if err != nil {
		return nil, err
	}
	var fields map[string]any
	return fields, json.Unmarshal(encoded, &fields)
}

func diffFields(prefix string, left, right map[string]any, out *[]string) {
	keys := map[string]struct{}{}
	for key := range left {
		keys[key] = struct{}{}
	}
	for key := range right {
		keys[key] = struct{}{}
	}
	for key := range keys {
		leftChild, leftIsMap := left[key].(map[string]any)
		rightChild, rightIsMap := right[key].(map[string]any)
		switch {
		case leftIsMap && rightIsMap:
			diffFields(prefix+key+".", leftChild, rightChild, out)
		case !reflect.DeepEqual(left[key], right[key]):
			*out = append(*out, prefix+key)
		}
	}
}

func parserRef(parser *ParserRef) txclient.ParserRefMessage {
	if parser == nil {
		return txclient.ParserRefMessage{}
	}
	return txclient.ParserRefMessage{Name: parser.Name, Version: txclient.ProtoUint32(parser.Version)}
}

// bytes32Hex strips the manifest's 0x prefix; the projection carries bare hex.
func bytes32Hex(value string) txclient.ProtoBytes32 {
	return txclient.ProtoBytes32(strings.TrimPrefix(value, "0x"))
}

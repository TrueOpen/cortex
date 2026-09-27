package chainclient

import (
	"encoding/hex"
	"strings"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
)

func currentProfileSnapshotFromWire(profile *hubv1.ProfileState) CurrentProfileSnapshot {
	taskTypes := make([]string, len(profile.GetTaskTypes()))
	for index, value := range profile.GetTaskTypes() {
		taskTypes[index] = sharedv1.TaskType(value).String()
	}
	requirements := make([]CurrentInferEvidenceRequirementSnapshot, len(profile.GetVerificationProfile().GetEvidenceSchema().GetRequiredInferEvidence()))
	for index, requirement := range profile.GetVerificationProfile().GetEvidenceSchema().GetRequiredInferEvidence() {
		requirements[index] = CurrentInferEvidenceRequirementSnapshot{
			EvidenceKind:            int32(requirement.GetEvidenceKind()),
			CommitmentSchemaVersion: requirement.GetCommitmentSchemaVersion(),
			MaxEncodedSizeBytes:     NewUint64String(requirement.GetMaxEncodedSizeBytes()),
		}
	}
	verification := profile.GetVerificationProfile()
	return CurrentProfileSnapshot{
		ModelID:                   hex.EncodeToString(profile.GetModelId()),
		ProfileVersion:            NewProfileVersion(profile.GetProfileVersion()),
		ManifestHash:              ProtoBytes32(profile.GetManifestHash()),
		TokenizerHash:             ProtoBytes32(profile.GetTokenizerHash()),
		RuntimeClass:              profile.GetRuntimeClass(),
		RequiredTopK:              profile.GetRequiredTopK(),
		TaskTypes:                 taskTypes,
		GenerationType:            sharedv1.GenerationType(profile.GetGenerationType()).String(),
		ResourceTier:              profile.GetResourceTier(),
		MinStake:                  NewUint64String(profile.GetMinStake()),
		ChallengeOpenWindowBlocks: NewUint64String(profile.GetChallengeOpenWindowBlocks()),
		VerificationProfile: CurrentVerificationProfileSnapshot{
			VerificationProfileID:         verification.GetVerificationProfileId(),
			JudgmentFunctionVersion:       verification.GetJudgmentFunctionVersion(),
			VerificationMode:              sharedv1.VerificationMode(verification.GetVerificationMode()).String(),
			TokenScope:                    sharedv1.TokenScope(verification.GetTokenScope()).String(),
			IncludeGeneratedSpecialTokens: verification.GetIncludeGeneratedSpecialTokens(),
			IncludePromptTokens:           verification.GetIncludePromptTokens(),
			IncludePaddingTokens:          verification.GetIncludePaddingTokens(),
			RequireOutputTokenIDs:         verification.GetRequireOutputTokenIds(),
			RequireFinishReason:           verification.GetRequireFinishReason(),
			Metrics: CurrentMetricSpecSnapshot{
				CompareLogprobDiff: verification.GetMetrics().GetCompareLogprobDiff(),
				CompareRankDelta:   verification.GetMetrics().GetCompareRankDelta(),
				CompareTopKJaccard: verification.GetMetrics().GetCompareTopkJaccard(),
				CompareUnionJS:     verification.GetMetrics().GetCompareUnionJs(),
				ComparedTopK:       verification.GetMetrics().GetComparedTopK(),
				NumericScale:       sharedv1.NumericScale(verification.GetMetrics().GetNumericScale()).String(),
			},
			CanonicalEncodingVersion:    verification.GetCanonicalEncodingVersion(),
			EvidenceSchemaHash:          ProtoBytes32(verification.GetEvidenceSchemaHash()),
			MetricAggregateProofVersion: verification.GetMetricAggregateProofVersion(),
			EvidenceSchema: CurrentEvidenceSchemaSnapshot{
				SchemaVersion:         verification.GetEvidenceSchema().GetSchemaVersion(),
				RequiredInferEvidence: requirements,
			},
		},
		VerificationThresholds: CurrentVerificationThresholdsSnapshot{
			PassMinFiniteCount:            profile.GetVerificationThresholds().GetPassMinFiniteCount(),
			PassMaxMissingComparedCount:   profile.GetVerificationThresholds().GetPassMaxMissingComparedCount(),
			PassMeanAbsLogprobDiffMax:     profile.GetVerificationThresholds().GetPassMeanAbsLogprobDiffMax(),
			PassAbsLogprobDiffP95Max:      profile.GetVerificationThresholds().GetPassAbsLogprobDiffP95Max(),
			PassAbsLogprobDiffP99Max:      profile.GetVerificationThresholds().GetPassAbsLogprobDiffP99Max(),
			PassRankDeltaNonzeroRateMax:   profile.GetVerificationThresholds().GetPassRankDeltaNonzeroRateMax(),
			PassTopKJaccardMeanMin:        profile.GetVerificationThresholds().GetPassTopkJaccardMeanMin(),
			PassUnionJSP99Max:             profile.GetVerificationThresholds().GetPassUnionJsP99Max(),
			RejectMeanAbsLogprobDiffMin:   profile.GetVerificationThresholds().GetRejectMeanAbsLogprobDiffMin(),
			RejectAbsLogprobDiffP95Min:    profile.GetVerificationThresholds().GetRejectAbsLogprobDiffP95Min(),
			RejectAbsLogprobDiffP99Min:    profile.GetVerificationThresholds().GetRejectAbsLogprobDiffP99Min(),
			RejectRankDeltaNonzeroRateMin: profile.GetVerificationThresholds().GetRejectRankDeltaNonzeroRateMin(),
			RejectTopKJaccardMeanMax:      profile.GetVerificationThresholds().GetRejectTopkJaccardMeanMax(),
			RejectUnionJSP99Min:           profile.GetVerificationThresholds().GetRejectUnionJsP99Min(),
		},
		BatchVerification: CurrentBatchVerificationSnapshot{
			Enabled:                       profile.GetBatchVerification().GetEnabled(),
			MinSampleCount:                profile.GetBatchVerification().GetMinSampleCount(),
			MinValidSampleCount:           profile.GetBatchVerification().GetMinValidSampleCount(),
			PassMinSamplePassRatioBPS:     profile.GetBatchVerification().GetPassMinSamplePassRatioBps(),
			RejectMinSampleRejectRatioBPS: profile.GetBatchVerification().GetRejectMinSampleRejectRatioBps(),
		},
		PricingProfile: CurrentPricingProfileSnapshot{
			InitialOutputPrice: NewUint64String(profile.GetPricingProfile().GetInitialOutputPrice()),
			VerifyRatioBPS:     profile.GetPricingProfile().GetVerifyRatioBps(),
			MinOrderValue:      NewUint64String(profile.GetPricingProfile().GetMinOrderValue()),
		},
		TimeoutBootstrapProfile: CurrentTimeoutBootstrapProfileSnapshot{
			InferTimeoutBootstrapBlocks:  profile.GetTimeoutBootstrapProfile().GetInferTimeoutBootstrapBlocks(),
			VerifyTimeoutBootstrapBlocks: profile.GetTimeoutBootstrapProfile().GetVerifyTimeoutBootstrapBlocks(),
			CommitTimeoutBootstrapBlocks: profile.GetTimeoutBootstrapProfile().GetCommitTimeoutBootstrapBlocks(),
			BootstrapValidUntilEpoch:     NewUint64String(profile.GetTimeoutBootstrapProfile().GetBootstrapValidUntilEpoch()),
		},
		SchemaHash:             ProtoBytes32(profile.GetSchemaHash()),
		Status:                 strings.TrimPrefix(hubv1.ModelProfileStatus(profile.GetStatus()).String(), "MODEL_PROFILE_STATUS_"),
		StatusSource:           strings.TrimPrefix(hubv1.ProfileStatusSource(profile.GetStatusSource()).String(), "PROFILE_STATUS_SOURCE_"),
		RegistrationFeePaid:    NewUint64String(profile.GetRegistrationFeePaid()),
		PreviousProfileVersion: NewProfileVersion(profile.GetPreviousProfileVersion()),
		ProposerAddress:        profile.GetProposerAddress(),
		RegistrationDigest:     ProtoBytes32(profile.GetRegistrationDigest()),
		CreatedHeight:          NewUint64String(profile.GetCreatedHeight()),
		UpdatedHeight:          NewUint64String(profile.GetUpdatedHeight()),
		Source: CurrentProfileSourceSnapshot{
			SourceURI: profile.GetSource().GetSourceUri(), Revision: profile.GetSource().GetRevision(),
			ResolverVersion: profile.GetSource().GetResolverVersion(), RepoType: profile.GetSource().GetRepoType(),
		},
		ToolCallParser:  CurrentParserSnapshot{Name: profile.GetToolCallParser().GetName(), Version: profile.GetToolCallParser().GetVersion()},
		ReasoningParser: CurrentParserSnapshot{Name: profile.GetReasoningParser().GetName(), Version: profile.GetReasoningParser().GetVersion()},
	}
}

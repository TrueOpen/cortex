package policy

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelservice"
)

type OutputPackageSummary struct {
	TaskID            string
	OutputRef         string
	TokenIDsRef       string
	PositionValuesRef string
	OutputHash        codec.Hash
	PackageHash       codec.Hash
	// FromTaskData marks a package confirmed by reading the OUTPUT object off
	// the task-data plane rather than by loading a canonical package from a
	// store the Worker and the Verifier share. Such a package carries no
	// artifact refs -- they are Worker-local model-service addresses that no
	// wire transports -- so the package-hash recomputation below has no inputs
	// and is skipped. The hash it would have recomputed is a Keeper commitment
	// the Verifier read from the chain, not a value it could derive: only the
	// node that produced the artifacts can.
	FromTaskData bool
}

type VerifierPrecheckInput struct {
	Phase                      string
	ChainSynced                bool
	CurrentHeight              uint64
	SessionID                  string
	OrderDigest                codec.Hash
	ExpectedTaskID             string
	VerifierAddress            string
	WorkerAddress              string
	SupportState               string
	SupportLastConfirmedHeight uint64
	SupportFreshnessWindow     uint64
	Profile                    string
	SupportedProfiles          []string
	OutputPackage              OutputPackageSummary
	AvailableSlots             int
	VerifyDeadlineHeight       uint64
	CommitDeadlineHeight       uint64
	BeaconDelayHeights         uint64
	OpenVerifyAccepted         bool
}

type VerifierDecision struct {
	Accepted                    bool
	RejectCode                  string
	ShouldSignVerifierHandraise bool
	OutputPackageHash           codec.Hash
	AuditSummary                string
}

func EvaluateVerifierPrecheck(in VerifierPrecheckInput) VerifierDecision {
	decision := VerifierDecision{
		OutputPackageHash: in.OutputPackage.PackageHash,
		AuditSummary:      fmt.Sprintf("profile=%s output_ref=%s", in.Profile, in.OutputPackage.OutputRef),
	}
	if !in.ChainSynced {
		return rejectVerifier(decision, "L0_CHAIN_NOT_SYNCED")
	}
	if in.Phase == "handraise" && in.OpenVerifyAccepted {
		return rejectVerifier(decision, "L4_OPEN_VERIFY_ALREADY_ACCEPTED")
	}
	if in.SessionID == "" || in.OrderDigest == (codec.Hash{}) {
		return rejectVerifier(decision, "L2_TASK_IDENTITY_MISSING")
	}
	if in.ExpectedTaskID != "" && in.OutputPackage.TaskID != "" && in.OutputPackage.TaskID != in.ExpectedTaskID {
		return rejectVerifier(decision, "L2_OUTPUT_PACKAGE_TASK_MISMATCH")
	}
	if in.VerifierAddress != "" && in.WorkerAddress != "" && in.VerifierAddress == in.WorkerAddress {
		return rejectVerifier(decision, "L1_WORKER_VERIFIER_MUTUAL_EXCLUSION")
	}
	if in.VerifyDeadlineHeight > 0 && in.CurrentHeight >= in.VerifyDeadlineHeight {
		return rejectVerifier(decision, "L4_VERIFY_DEADLINE_EXPIRED")
	}
	if in.CommitDeadlineHeight > 0 && in.CurrentHeight+in.BeaconDelayHeights >= in.CommitDeadlineHeight {
		return rejectVerifier(decision, "COMMIT_WINDOW_UNSAFE_FOR_BEACON_DELAY")
	}
	if !verifierSupportEligible(in) {
		return rejectVerifier(decision, "L1_SUPPORT_STALE")
	}
	if !verifierProfileSupported(in.Profile, in.SupportedProfiles) {
		return rejectVerifier(decision, "L2_UNSUPPORTED_PROFILE")
	}
	if err := validateOutputPackage(in.OutputPackage); err != nil {
		return rejectVerifier(decision, err.Error())
	}
	if in.AvailableSlots <= 0 {
		return rejectVerifier(decision, "L3_INSUFFICIENT_CAPACITY")
	}
	decision.Accepted = true
	decision.ShouldSignVerifierHandraise = true
	return decision
}

func VerificationResultDigest(canonicalValues [][]byte) codec.Hash {
	fields := make([][]byte, 0, len(canonicalValues))
	for _, value := range canonicalValues {
		fields = append(fields, append([]byte(nil), value...))
	}
	return codec.HashWithDomain("TRUEOPEN_VERIFICATION_RESULT_DIGEST_V1", fields...)
}

func rejectVerifier(decision VerifierDecision, code string) VerifierDecision {
	decision.Accepted = false
	decision.RejectCode = code
	decision.ShouldSignVerifierHandraise = false
	return decision
}

func verifierSupportEligible(in VerifierPrecheckInput) bool {
	if in.SupportState != SupportActive && in.SupportState != SupportDeclaredBootstrap {
		return false
	}
	if in.SupportFreshnessWindow == 0 {
		return false
	}
	if in.CurrentHeight < in.SupportLastConfirmedHeight {
		return false
	}
	return in.CurrentHeight-in.SupportLastConfirmedHeight <= in.SupportFreshnessWindow
}

func verifierProfileSupported(profile string, supported []string) bool {
	if profile != modelservice.CapabilityLLMTextV1 {
		return false
	}
	return slices.Contains(supported, profile)
}

func validateOutputPackage(pkg OutputPackageSummary) error {
	if pkg.FromTaskData {
		// output_hash and nothing else. It is V1's only output content commitment
		// (keeper-service-design-appendix.md item 50), and cortex-detailed-design.md:1032 puts "a parallel
		// commitment such as a package hash or a delivery hash" among the §13 hard
		// boundaries -- the chain commits none, so requiring one here rejected every
		// real-chain task.
		if pkg.TaskID == "" || pkg.OutputHash == (codec.Hash{}) {
			return fmt.Errorf("L2_OUTPUT_PACKAGE_MISSING")
		}
		return nil
	}
	if pkg.TaskID == "" || pkg.OutputRef == "" || pkg.TokenIDsRef == "" || pkg.PositionValuesRef == "" || pkg.OutputHash == (codec.Hash{}) || pkg.PackageHash == (codec.Hash{}) {
		return fmt.Errorf("L2_OUTPUT_PACKAGE_MISSING")
	}
	expected := codec.HashWithDomain(
		"TRUEOPEN_OUTPUT_PACKAGE_V1",
		[]byte(pkg.TaskID),
		[]byte(pkg.OutputRef),
		[]byte(pkg.TokenIDsRef),
		[]byte(pkg.PositionValuesRef),
		pkg.OutputHash[:],
	)
	if !bytes.Equal(pkg.PackageHash[:], expected[:]) {
		return fmt.Errorf("L2_OUTPUT_PACKAGE_HASH_MISMATCH")
	}
	return nil
}

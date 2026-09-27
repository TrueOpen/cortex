package policy

import (
	"bytes"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelservice"
)

func TestVerifierL0L4AnyFailureDoesNotSignHandraise(t *testing.T) {
	valid := validVerifierInput()
	cases := []struct {
		name string
		mut  func(*VerifierPrecheckInput)
		code string
	}{
		{name: "chain not synced", mut: func(in *VerifierPrecheckInput) { in.ChainSynced = false }, code: "L0_CHAIN_NOT_SYNCED"},
		{name: "same node worker role", mut: func(in *VerifierPrecheckInput) { in.WorkerAddress = in.VerifierAddress }, code: "L1_WORKER_VERIFIER_MUTUAL_EXCLUSION"},
		{name: "support stale", mut: func(in *VerifierPrecheckInput) { in.SupportLastConfirmedHeight = 1 }, code: "L1_SUPPORT_STALE"},
		{name: "support window missing", mut: func(in *VerifierPrecheckInput) { in.SupportFreshnessWindow = 0 }, code: "L1_SUPPORT_STALE"},
		{name: "unsupported profile", mut: func(in *VerifierPrecheckInput) { in.Profile = "black_box_v1" }, code: "L2_UNSUPPORTED_PROFILE"},
		{name: "missing output package", mut: func(in *VerifierPrecheckInput) { in.OutputPackage = OutputPackageSummary{} }, code: "L2_OUTPUT_PACKAGE_MISSING"},
		{name: "capacity exhausted", mut: func(in *VerifierPrecheckInput) { in.AvailableSlots = 0 }, code: "L3_INSUFFICIENT_CAPACITY"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := valid
			tc.mut(&in)
			got := EvaluateVerifierPrecheck(in)
			if got.ShouldSignVerifierHandraise {
				t.Fatalf("decision signs VerifierHandraise on failure")
			}
			if got.Accepted {
				t.Fatalf("decision accepted failure")
			}
			if got.RejectCode != tc.code {
				t.Fatalf("reject code = %q, want %q", got.RejectCode, tc.code)
			}
		})
	}
}

func TestVerifierAcceptsKeeperEligibleDeclaredBootstrapSupport(t *testing.T) {
	in := validVerifierInput()
	in.SupportState = SupportDeclaredBootstrap
	if got := EvaluateVerifierPrecheck(in); !got.Accepted {
		t.Fatalf("declared bootstrap support rejected: %+v", got)
	}
}

func TestVerifierOutputPackageValidationRejectsMissingAndHashMismatch(t *testing.T) {
	in := validVerifierInput()
	in.OutputPackage = OutputPackageSummary{}
	got := EvaluateVerifierPrecheck(in)
	if got.Accepted || got.ShouldSignVerifierHandraise || got.RejectCode != "L2_OUTPUT_PACKAGE_MISSING" {
		t.Fatalf("missing package decision = %#v", got)
	}

	in = validVerifierInput()
	in.OutputPackage.PackageHash = codec.HashWithDomain("BAD_PACKAGE_HASH", []byte("bad"))
	got = EvaluateVerifierPrecheck(in)
	if got.Accepted || got.ShouldSignVerifierHandraise || got.RejectCode != "L2_OUTPUT_PACKAGE_HASH_MISMATCH" {
		t.Fatalf("hash mismatch decision = %#v", got)
	}
}

func TestVerifierAcceptedBeforeOpenVerifySignsHandraise(t *testing.T) {
	in := validVerifierInput()
	in.OpenVerifyAccepted = false

	got := EvaluateVerifierPrecheck(in)

	if !got.Accepted || !got.ShouldSignVerifierHandraise {
		t.Fatalf("pre-open-verify verifier should handraise, got %#v", got)
	}
	if got.OutputPackageHash != in.OutputPackage.PackageHash {
		t.Fatalf("decision package hash = %x, want %x", got.OutputPackageHash, in.OutputPackage.PackageHash)
	}
}

func TestVerifierHandraiseDoesNotDependOnLocalTransactionFeeCap(t *testing.T) {
	in := validVerifierInput()

	got := EvaluateVerifierPrecheck(in)
	if !got.Accepted || !got.ShouldSignVerifierHandraise || got.RejectCode != "" {
		t.Fatalf("verifier decision = %+v, want accepted without a local fee eligibility input", got)
	}
}

func TestVerifierUnsafeCommitWindowRejects(t *testing.T) {
	in := validVerifierInput()
	in.CurrentHeight = 250
	in.SupportLastConfirmedHeight = 250
	in.CommitDeadlineHeight = 254
	in.BeaconDelayHeights = 5

	got := EvaluateVerifierPrecheck(in)

	if got.Accepted || got.ShouldSignVerifierHandraise {
		t.Fatalf("unsafe commit window accepted: %#v", got)
	}
	if got.RejectCode != "COMMIT_WINDOW_UNSAFE_FOR_BEACON_DELAY" {
		t.Fatalf("reject code = %q", got.RejectCode)
	}
}

func TestVerificationResultDigestUsesCanonicalValues(t *testing.T) {
	values := [][]byte{[]byte("checkpoint:2=value:abc"), []byte("checkpoint:8=value:def")}
	digest := VerificationResultDigest(values)
	verdictOnly := VerificationResultDigest([][]byte{[]byte{1}})
	if bytes.Equal(digest[:], verdictOnly[:]) {
		t.Fatalf("result digest collapsed to verdict bit")
	}
}

func validVerifierInput() VerifierPrecheckInput {
	outputHash := codec.OutputHash([]byte("worker output"))
	pkg := OutputPackageSummary{
		TaskID:            "task-1",
		OutputRef:         "cortex-artifact://fake/out?size=13",
		TokenIDsRef:       "cortex-artifact://fake/trace?size=5",
		PositionValuesRef: "cortex-artifact://fake/checkpoint?size=10",
		OutputHash:        outputHash,
	}
	pkg.PackageHash = codec.HashWithDomain(
		"TRUEOPEN_OUTPUT_PACKAGE_V1",
		[]byte(pkg.TaskID),
		[]byte(pkg.OutputRef),
		[]byte(pkg.TokenIDsRef),
		[]byte(pkg.PositionValuesRef),
		pkg.OutputHash[:],
	)
	return VerifierPrecheckInput{
		Phase:                      "handraise",
		ChainSynced:                true,
		CurrentHeight:              200,
		SessionID:                  "session-1",
		OrderDigest:                codec.HashWithDomain("TEST_ORDER_DIGEST", []byte("order-1")),
		ExpectedTaskID:             "task-1",
		VerifierAddress:            "verifier-1",
		WorkerAddress:              "worker-1",
		SupportState:               SupportActive,
		SupportLastConfirmedHeight: 190,
		SupportFreshnessWindow:     20,
		Profile:                    modelservice.CapabilityLLMTextV1,
		SupportedProfiles:          []string{modelservice.CapabilityLLMTextV1},
		OutputPackage:              pkg,
		AvailableSlots:             1,
		VerifyDeadlineHeight:       280,
		CommitDeadlineHeight:       260,
		BeaconDelayHeights:         5,
	}
}

// TestVerifierPrecheckAcceptsATaskDataOutputWithNoPackageHash pins the §13 hard
// boundary from cortex-detailed-design.md:1032 -- "the general layer no longer generates
// required_evidence_commitments[], a package hash, a delivery hash or any other
// parallel commitment". output_hash is V1's only output content commitment, so a
// package confirmed off the task-data plane has to pass with the package hash
// absent: the chain carries none to compare against.
func TestVerifierPrecheckAcceptsATaskDataOutputWithNoPackageHash(t *testing.T) {
	in := validVerifierInput()
	in.OutputPackage = OutputPackageSummary{
		TaskID:       in.OutputPackage.TaskID,
		OutputHash:   in.OutputPackage.OutputHash,
		FromTaskData: true,
	}

	got := EvaluateVerifierPrecheck(in)

	if !got.Accepted || !got.ShouldSignVerifierHandraise {
		t.Fatalf("task-data output with no package hash = %#v, want an accepted handraise", got)
	}
}

// TestVerifierPrecheckStillRequiresTheOutputHash is the other half: dropping the
// package hash must not drop the commitment that replaced it.
func TestVerifierPrecheckStillRequiresTheOutputHash(t *testing.T) {
	in := validVerifierInput()
	in.OutputPackage = OutputPackageSummary{TaskID: in.OutputPackage.TaskID, FromTaskData: true}

	got := EvaluateVerifierPrecheck(in)

	if got.Accepted || got.RejectCode != "L2_OUTPUT_PACKAGE_MISSING" {
		t.Fatalf("task-data output with no output hash = %#v, want L2_OUTPUT_PACKAGE_MISSING", got)
	}
}

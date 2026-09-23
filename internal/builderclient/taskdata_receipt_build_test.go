package builderclient

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// completeInferReceiptFacts is the hypothetical complete input set. Nothing in
// production can produce it today, which is the point: each fail-closed test
// removes exactly one field so the refusal it asserts is the refusal for that
// field and not a side effect of another missing one.
func completeInferReceiptFacts(t *testing.T) InferReceiptFacts {
	t.Helper()
	return InferReceiptFacts{
		ChainID:                   "trueopen-task-1",
		TaskID:                    strings.Repeat("11", 32),
		TaskHash:                  strings.Repeat("22", 32),
		WorkerOperatorAddress:     "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc",
		ServiceAuthorizationNonce: 7,
		GenerationParamsDigest:    strings.Repeat("33", 32),
		OutputHash:                codec.HashBytes([]byte("output")),
		OutputSizeBytes:           6,
		OutputLeafCount:           1,
		RequiredEvidenceCommitments: []EvidenceCommitment{{
			EvidenceKind:       nodewire.EvidenceKindWorkerValueOpening,
			EvidenceHashOrRoot: codec.HashBytes([]byte("trace")),
			EncodedSizeBytes:   5,
		}},
		// The locked Profile's requirement set. Only max_encoded_size_bytes needs a
		// real Profile read; the derived V1 shape at the contract ceiling keeps the
		// per-field cases below about the field each one blanks.
		ProfileEvidenceRequirements: WorkerValueEvidenceRequirementsV2(),
		ExpiryHeight:                1200,
	}
}

func TestBuildInferReceiptProducesTheFrozenWire(t *testing.T) {
	facts := completeInferReceiptFacts(t)
	receipt, digest, err := BuildInferReceipt(facts)
	if err != nil {
		t.Fatalf("BuildInferReceipt: %v", err)
	}
	if receipt.SchemaVersion != nodewire.InferReceiptSchemaVersionV2 {
		t.Fatalf("schema_version = %d, want the frozen constant %d",
			receipt.SchemaVersion, nodewire.InferReceiptSchemaVersionV2)
	}
	if receipt.OutputHash != hex.EncodeToString(facts.OutputHash[:]) {
		t.Fatalf("output_hash = %q, want the hex of the committed output hash", receipt.OutputHash)
	}
	if receipt.ServiceSignature != "" {
		t.Fatal("BuildInferReceipt returned a signature; signing is the caller's step")
	}
	want, err := InferReceiptSigningDigest(receipt)
	if err != nil || want != digest {
		t.Fatalf("returned digest = %x, %v; want the receipt's own digest %x", digest, err, want)
	}

	// The returned commitments must not alias the caller's slice, or a later
	// mutation at the callsite would silently change what was signed.
	facts.RequiredEvidenceCommitments[0].EncodedSizeBytes = 999
	after, err := InferReceiptSigningDigest(receipt)
	if err != nil || after != digest {
		t.Fatalf("digest moved after the caller mutated its own slice: %x -> %x (%v)", digest, after, err)
	}
}

// TestBuildInferReceiptFailsClosedOnUnavailableInputs is the whole point of the
// constructor. Each case blanks exactly one field and asserts the refusal names
// the blocking issue, because an operator reading "receipt is invalid" cannot
// tell an upstream gap from a Cortex bug.
//
// Each case then repeats the assertion for the value a caller reaches for when it
// has nothing to put in the field. The frozen wire frames every one of these
// fields unconditionally, so "unset" and "the empty value" are the same claim to
// the Keeper, and the refusal has to cover both or the gate only stops the honest
// caller.
func TestBuildInferReceiptFailsClosedOnUnavailableInputs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		remove   func(*InferReceiptFacts)
		contains []string
		// forbidden is the shape-valid stand-in the refusal exists to prevent: it
		// reaches a signature without tripping any format check, so it must be
		// refused by exactly the same gate as the unset field.
		forbidden func(*InferReceiptFacts)
	}{
		{
			// The locked Profile's max_encoded_size_bytes is the one evidence bound
			// no derivation can supply, and the frozen handler compares
			// encoded_size_bytes against that Profile's own value. Without the read
			// there is no receipt to sign, so the requirement set is an unavailable
			// input rather than a field with a permissive default.
			name:   "profile evidence requirements",
			remove: func(f *InferReceiptFacts) { f.ProfileEvidenceRequirements = nil },
			contains: []string{
				"required_evidence_commitments must be bounded by the locked Profile's",
				"evidence_schema.required_infer_evidence",
				"hub.v1.Query/Profile",
				"profile.verification_profile.evidence_schema.required_infer_evidence",
				"the contract ceiling is not a substitute",
			},
			forbidden: func(f *InferReceiptFacts) { f.ProfileEvidenceRequirements = []InferEvidenceRequirement{} },
		},
	} {
		assertRefused := func(t *testing.T, apply func(*InferReceiptFacts)) {
			t.Helper()
			facts := completeInferReceiptFacts(t)
			apply(&facts)
			receipt, digest, err := BuildInferReceipt(facts)
			if err == nil {
				t.Fatalf("BuildInferReceipt accepted a receipt with no usable %s", tc.name)
			}
			if !errors.Is(err, ErrInferReceiptInputUnavailable) {
				t.Fatalf("error = %v, want ErrInferReceiptInputUnavailable", err)
			}
			for _, want := range tc.contains {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q does not name %q", err, want)
				}
			}
			// A refusal that blames a closed upstream issue sends an operator to
			// the wrong place. The locked Profile's evidence requirements are the
			// only unavailable input left here, and the message has to name the
			// query that would serve them.
			for _, stale := range []string{"node#99", "node#100", "never writes", "does not read yet"} {
				if strings.Contains(err.Error(), stale) {
					t.Fatalf("error %q still blames %q, which d8792e6 contradicts", err, stale)
				}
			}
			// Nothing signable may escape a refusal.
			if digest != (codec.Hash{}) || receipt.SchemaVersion != 0 {
				t.Fatalf("refused build still returned receipt %#v and digest %x", receipt, digest)
			}
		}
		t.Run(tc.name+"/unset", func(t *testing.T) { assertRefused(t, tc.remove) })
		t.Run(tc.name+"/forbidden substitution", func(t *testing.T) { assertRefused(t, tc.forbidden) })
	}
}

// TestBuildInferReceiptStillRefusesUnsourcedConsensusHashes is the cutover
// guard. task_hash and generation_params_digest used to be refused by
// BuildInferReceipt itself because nothing read them; the Worker now reads both
// through chainclient.KeeperABCIClient.TaskReceiptFacts, so that refusal is
// gone. What must NOT be gone is the fail-closed behaviour: an unset or all-zero
// value still has to stop short of a signature, now at
// InferReceiptSigningDigest's own gate.
//
// The 32-zero case is the dangerous one. It passes every format check, so a
// constructor that only validated shape would hand back a signable digest over a
// positive claim about consensus state that the Keeper can only reject.
func TestBuildInferReceiptStillRefusesUnsourcedConsensusHashes(t *testing.T) {
	for name, tc := range map[string]struct {
		apply    func(*InferReceiptFacts)
		contains string
	}{
		"unset task_hash": {
			func(f *InferReceiptFacts) { f.TaskHash = "" },
			"infer receipt task_hash must be lowercase 32-byte hex",
		},
		"zero task_hash": {
			func(f *InferReceiptFacts) { f.TaskHash = strings.Repeat("00", 32) },
			"infer receipt task_hash must not be 32 zero bytes",
		},
		"unset generation_params_digest": {
			func(f *InferReceiptFacts) { f.GenerationParamsDigest = "" },
			"infer receipt generation_params_digest must be lowercase 32-byte hex",
		},
		"zero generation_params_digest": {
			func(f *InferReceiptFacts) { f.GenerationParamsDigest = strings.Repeat("00", 32) },
			"infer receipt generation_params_digest must not be 32 zero bytes",
		},
	} {
		t.Run(name, func(t *testing.T) {
			facts := completeInferReceiptFacts(t)
			tc.apply(&facts)
			receipt, digest, err := BuildInferReceipt(facts)
			if err == nil || !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("BuildInferReceipt error = %v, want %q", err, tc.contains)
			}
			// It is no longer an "unavailable input": the reader exists and the
			// Worker calls it, so a caller that arrives here has a bug rather than
			// an upstream gap, and the sentinel must not say otherwise.
			if errors.Is(err, ErrInferReceiptInputUnavailable) {
				t.Fatalf("error = %v, want a malformed-receipt refusal rather than an upstream-gap sentinel", err)
			}
			if digest != (codec.Hash{}) || receipt.SchemaVersion != 0 {
				t.Fatalf("refused build still returned receipt %#v and digest %x", receipt, digest)
			}
		})
	}
}

// TestBuildInferReceiptEnforcesEveryHandlerEvidencePrecondition walks the
// boundary of what the frozen SubmitInferReceipt handler accepts in
// required_evidence_commitments. Each case is a list the handler would reject, so
// accepting any of them here would mean signing a receipt that can only be
// refused on chain -- after the signature exists.
//
// The empty list is in the table rather than in the unavailable-input table above
// because it is no longer an unavailable input: the requirement set is registered
// upstream, and an empty list is simply the wrong list.
func TestBuildInferReceiptEnforcesEveryHandlerEvidencePrecondition(t *testing.T) {
	worker := func(root string, size uint64) EvidenceCommitment {
		return EvidenceCommitment{
			EvidenceKind:       nodewire.EvidenceKindWorkerValueOpening,
			EvidenceHashOrRoot: codec.HashBytes([]byte(root)),
			EncodedSizeBytes:   size,
		}
	}
	for _, tc := range []struct {
		name     string
		apply    func(*InferReceiptFacts)
		contains string
	}{
		{
			name:     "count below the requirement set",
			apply:    func(f *InferReceiptFacts) { f.RequiredEvidenceCommitments = nil },
			contains: "must exactly match the locked Profile requirement count",
		},
		{
			name:     "explicitly empty list",
			apply:    func(f *InferReceiptFacts) { f.RequiredEvidenceCommitments = []EvidenceCommitment{} },
			contains: "must exactly match the locked Profile requirement count",
		},
		{
			// Both worker artifacts filed as two commitments. They belong in ONE
			// WorkerValueCommitmentV2, so a second element is always a count error.
			name: "both worker artifacts as two commitments",
			apply: func(f *InferReceiptFacts) {
				f.RequiredEvidenceCommitments = []EvidenceCommitment{worker("trace", 5), worker("checkpoint", 10)}
			},
			contains: "must exactly match the locked Profile requirement count",
		},
		{
			name: "wrong evidence kind",
			apply: func(f *InferReceiptFacts) {
				f.RequiredEvidenceCommitments[0].EvidenceKind = nodewire.EvidenceKindSettlementRootOpening
			},
			contains: "does not match the locked Profile kind",
		},
		{
			name: "unspecified evidence kind",
			apply: func(f *InferReceiptFacts) {
				f.RequiredEvidenceCommitments[0].EvidenceKind = nodewire.EvidenceKindUnspecified
			},
			contains: "does not match the locked Profile kind",
		},
		{
			name:     "zero encoded size",
			apply:    func(f *InferReceiptFacts) { f.RequiredEvidenceCommitments[0].EncodedSizeBytes = 0 },
			contains: "is outside the locked Profile's 1..",
		},
		{
			name: "encoded size above the contract ceiling",
			apply: func(f *InferReceiptFacts) {
				f.RequiredEvidenceCommitments[0].EncodedSizeBytes = nodewire.MaxEvidenceEncodedSizeBytesV1 + 1
			},
			contains: "is outside the locked Profile's 1..",
		},
		{
			name: "encoded size above a tighter profile bound",
			apply: func(f *InferReceiptFacts) {
				f.ProfileEvidenceRequirements = []InferEvidenceRequirement{{
					EvidenceKind:            nodewire.EvidenceKindWorkerValueOpening,
					CommitmentSchemaVersion: nodewire.WorkerValueCommitmentSchemaVersionV2,
					MaxEncodedSizeBytes:     4,
				}}
				f.RequiredEvidenceCommitments[0].EncodedSizeBytes = 5
			},
			contains: "is outside the locked Profile's 1..4",
		},
		{
			name:     "all-zero commitment root",
			apply:    func(f *InferReceiptFacts) { f.RequiredEvidenceCommitments[0].EvidenceHashOrRoot = codec.Hash{} },
			contains: "evidence_hash_or_root must not be 32 zero bytes",
		},
		{
			// A profile that requires a schema V1 cannot support, e.g. a verifier
			// opening asked of a Worker.
			name: "requirement V1 does not support",
			apply: func(f *InferReceiptFacts) {
				f.ProfileEvidenceRequirements = []InferEvidenceRequirement{{
					EvidenceKind:            nodewire.EvidenceKindVerifierValueOpening,
					CommitmentSchemaVersion: nodewire.WorkerValueCommitmentSchemaVersionV2,
					MaxEncodedSizeBytes:     nodewire.MaxEvidenceEncodedSizeBytesV1,
				}}
				f.RequiredEvidenceCommitments[0].EvidenceKind = nodewire.EvidenceKindVerifierValueOpening
			},
			contains: "unsupported commitment schema",
		},
		{
			name: "commitment schema version the handler rejects",
			apply: func(f *InferReceiptFacts) {
				f.ProfileEvidenceRequirements = []InferEvidenceRequirement{{
					EvidenceKind:            nodewire.EvidenceKindWorkerValueOpening,
					CommitmentSchemaVersion: nodewire.WorkerValueCommitmentSchemaVersionV2 + 1,
					MaxEncodedSizeBytes:     nodewire.MaxEvidenceEncodedSizeBytesV1,
				}}
			},
			contains: "unsupported commitment schema",
		},
		{
			// Ordering is unreachable through a well-formed V1 profile, because a
			// V1 requirement set holds exactly one kind. It stays checked as
			// defence in depth against a malformed profile whose own requirement
			// list repeats a kind: a duplicated kind must not be silently re-sorted
			// into an ascending list the Keeper would then accept.
			name: "duplicate kinds under a malformed requirement set",
			apply: func(f *InferReceiptFacts) {
				requirement := WorkerValueEvidenceRequirementsV2()[0]
				f.ProfileEvidenceRequirements = []InferEvidenceRequirement{requirement, requirement}
				f.RequiredEvidenceCommitments = []EvidenceCommitment{worker("trace", 5), worker("checkpoint", 10)}
			},
			contains: "strictly ascending",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := completeInferReceiptFacts(t)
			tc.apply(&facts)
			receipt, digest, err := BuildInferReceipt(facts)
			if err == nil {
				t.Fatalf("BuildInferReceipt accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("error = %v, want it to name %q", err, tc.contains)
			}
			if digest != (codec.Hash{}) || receipt.SchemaVersion != 0 {
				t.Fatalf("refused build still returned receipt %#v and digest %x", receipt, digest)
			}
		})
	}
}

// A commitment that satisfies a tighter real profile bound must still build:
// supplying the profile's requirements may only ever narrow what is accepted, and
// a bound the commitment respects is not a refusal.
func TestBuildInferReceiptAcceptsATighterProfileBound(t *testing.T) {
	facts := completeInferReceiptFacts(t)
	facts.ProfileEvidenceRequirements = []InferEvidenceRequirement{{
		EvidenceKind:            nodewire.EvidenceKindWorkerValueOpening,
		CommitmentSchemaVersion: nodewire.WorkerValueCommitmentSchemaVersionV2,
		MaxEncodedSizeBytes:     facts.RequiredEvidenceCommitments[0].EncodedSizeBytes,
	}}
	if _, _, err := BuildInferReceipt(facts); err != nil {
		t.Fatalf("BuildInferReceipt refused a commitment exactly at the profile bound: %v", err)
	}
}

// TestBuildInferReceiptBindsTaskHashToTheReceiptDigest pins the consequence of
// the specific substitution the pre-freeze code made: it hex-encoded the
// assignment's order_digest and called it task_hash. The two commit different
// things, and BuildInferReceipt cannot tell them apart from the value alone -- an
// order digest is a perfectly well-formed non-zero Hash32 -- so this does not and
// cannot assert a refusal. What it asserts is that task_hash reaches the receipt
// digest, which is why the swap is fatal rather than cosmetic: a receipt built
// that way is locally valid and rejected on chain at the Keeper's
// core.AcceptedTaskHash comparison. The refusal that does protect this field is
// the unavailable-input gate in
// TestBuildInferReceiptFailsClosedOnUnavailableInputs, which never lets a caller
// reach this constructor without a real accepted_task_hash.
func TestBuildInferReceiptBindsTaskHashToTheReceiptDigest(t *testing.T) {
	orderDigest := codec.HashBytes([]byte("order envelope"))
	facts := completeInferReceiptFacts(t)
	facts.TaskHash = hex.EncodeToString(orderDigest[:])
	substituted, _, err := BuildInferReceipt(facts)
	if err != nil {
		t.Fatalf("BuildInferReceipt: %v", err)
	}
	honest := completeInferReceiptFacts(t)
	real, _, err := BuildInferReceipt(honest)
	if err != nil {
		t.Fatalf("BuildInferReceipt: %v", err)
	}
	substitutedDigest, err := InferReceiptSigningDigest(substituted)
	if err != nil {
		t.Fatal(err)
	}
	realDigest, err := InferReceiptSigningDigest(real)
	if err != nil {
		t.Fatal(err)
	}
	if substitutedDigest == realDigest {
		t.Fatal("task_hash does not reach the receipt digest; substituting order_digest would be undetectable on chain")
	}
}

func TestBuildInferReceiptRejectsMalformedFacts(t *testing.T) {
	for name, mutate := range map[string]func(*InferReceiptFacts){
		"empty chain id":     func(f *InferReceiptFacts) { f.ChainID = "" },
		"non-hash task id":   func(f *InferReceiptFacts) { f.TaskID = "task-1" },
		"non-bech32 worker":  func(f *InferReceiptFacts) { f.WorkerOperatorAddress = "worker" },
		"zero nonce":         func(f *InferReceiptFacts) { f.ServiceAuthorizationNonce = 0 },
		"zero output leaves": func(f *InferReceiptFacts) { f.OutputLeafCount = 0 },
		"zero expiry height": func(f *InferReceiptFacts) { f.ExpiryHeight = 0 },
		"unspecified kind": func(f *InferReceiptFacts) {
			f.RequiredEvidenceCommitments[0].EvidenceKind = nodewire.EvidenceKindUnspecified
		},
		"zero evidence root":     func(f *InferReceiptFacts) { f.RequiredEvidenceCommitments[0].EvidenceHashOrRoot = codec.Hash{} },
		"zero evidence size":     func(f *InferReceiptFacts) { f.RequiredEvidenceCommitments[0].EncodedSizeBytes = 0 },
		"uppercase task hash":    func(f *InferReceiptFacts) { f.TaskHash = strings.Repeat("AB", 32) },
		"short generation param": func(f *InferReceiptFacts) { f.GenerationParamsDigest = strings.Repeat("33", 31) },
	} {
		t.Run(name, func(t *testing.T) {
			facts := completeInferReceiptFacts(t)
			mutate(&facts)
			if _, _, err := BuildInferReceipt(facts); err == nil {
				t.Fatalf("BuildInferReceipt accepted %s", name)
			}
		})
	}
}

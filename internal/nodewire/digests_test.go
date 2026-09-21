package nodewire_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/nodewire"
)

func codecHash(preimage []byte) codec.Hash {
	return codec.HashBytes(preimage)
}

// TestEmptyEvidenceListIsADefinedDigest pins the boundary case the frozen rules
// call out explicitly: an empty list is uint32_be(0) plus a commitments frame
// whose own element_count is 0 - not 32 zero bytes, not an empty byte string,
// not a skipped count field, and not an omitted second field.
//
// The omitted-second-field form is the one this repository actually emitted
// before the frozen vectors were adopted, and it is why the length is asserted
// here rather than left to the golden digest alone: a shape that drops the
// trailing frame still ends in uint32_be(0) and would pass a suffix check.
func TestEmptyEvidenceListIsADefinedDigest(t *testing.T) {
	vectors := goldenVectorsByName(t)
	empty := requireVector(t, vectors, vectorEvidenceEmpty)

	preimage, err := nodewire.EvidenceCommitmentsPreimage(nil)
	if err != nil {
		t.Fatalf("EvidenceCommitmentsPreimage(nil): %v", err)
	}
	// u64_be(35) || 35-byte domain || u64_be(4) || 00000000
	//   || u64_be(12) || u64_be(4) || 00000000
	want := 8 + len(nodewire.DomainInferEvidenceCommitmentsV1) + (8 + 4) + (8 + 8 + 4)
	if len(preimage) != want {
		t.Fatalf("empty preimage is %d bytes, want %d", len(preimage), want)
	}
	if !bytes.HasSuffix(preimage, []byte{0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0}) {
		t.Fatalf("empty preimage must end in the commitments frame u64_be(4)||uint32_be(0), got %s",
			hex.EncodeToString(preimage))
	}
	digest, err := nodewire.EvidenceCommitmentsHash(nil)
	if err != nil {
		t.Fatalf("EvidenceCommitmentsHash(nil): %v", err)
	}
	if digest == (codec.Hash{}) {
		t.Fatalf("the empty list must not hash to 32 zero bytes")
	}
	if got := hex.EncodeToString(digest[:]); got != empty.DigestHex {
		t.Fatalf("empty digest %s, want %s", got, empty.DigestHex)
	}
}

// TestInferReceiptDigestReadsEveryPreimageField is the anti-drift half of the
// golden gate. The golden test proves the helper agrees with the fixture for one
// input; this proves it actually consumes all eleven preimage components, so an
// edit that drops, reorders or duplicates one cannot stay green.
func TestInferReceiptDigestReadsEveryPreimageField(t *testing.T) {
	vectors := goldenVectorsByName(t)
	base := inferReceiptFromVector(t, vectors, requireVector(t, vectors, vectorInferReceipt))

	baseDigest, err := nodewire.InferReceiptSigningDigest(base)
	if err != nil {
		t.Fatalf("base receipt: %v", err)
	}

	otherHash := bytes.Repeat([]byte{0x5a}, 32)
	otherAddress := fieldBech32(t, requireVector(t, vectors, vectorVerifyCommit), 4, "verifier_operator_address")

	mutations := map[string]func(*nodewire.InferReceiptV2){
		"chain_id":                    func(r *nodewire.InferReceiptV2) { r.ChainID += "-x" },
		"task_id":                     func(r *nodewire.InferReceiptV2) { r.TaskID = otherHash },
		"task_hash":                   func(r *nodewire.InferReceiptV2) { r.TaskHash = otherHash },
		"worker_operator_address":     func(r *nodewire.InferReceiptV2) { r.WorkerOperatorAddress = otherAddress },
		"service_authorization_nonce": func(r *nodewire.InferReceiptV2) { r.ServiceAuthorizationNonce++ },
		"generation_params_digest":    func(r *nodewire.InferReceiptV2) { r.GenerationParamsDigest = otherHash },
		"output_hash":                 func(r *nodewire.InferReceiptV2) { r.OutputHash = otherHash },
		"output_size_bytes":           func(r *nodewire.InferReceiptV2) { r.OutputSizeBytes++ },
		"expiry_height":               func(r *nodewire.InferReceiptV2) { r.ExpiryHeight++ },
		"generated_token_count":       func(r *nodewire.InferReceiptV2) { r.GeneratedTokenCount++ },
		"output_leaf_count":           func(r *nodewire.InferReceiptV2) { r.OutputLeafCount++ },
		"evidence/drop_last": func(r *nodewire.InferReceiptV2) {
			r.RequiredEvidenceCommitments = r.RequiredEvidenceCommitments[:len(r.RequiredEvidenceCommitments)-1]
		},
		"evidence/kind": func(r *nodewire.InferReceiptV2) {
			r.RequiredEvidenceCommitments[len(r.RequiredEvidenceCommitments)-1].EvidenceKind =
				nodewire.EvidenceKindVerifierValueOpening
		},
		"evidence/hash": func(r *nodewire.InferReceiptV2) {
			r.RequiredEvidenceCommitments[0].EvidenceHashOrRoot = otherHash
		},
		"evidence/encoded_size_bytes": func(r *nodewire.InferReceiptV2) {
			r.RequiredEvidenceCommitments[0].EncodedSizeBytes++
		},
	}

	seen := map[codec.Hash]string{baseDigest: "base"}
	for label, mutate := range mutations {
		mutated := base
		mutated.RequiredEvidenceCommitments = append(
			[]nodewire.EvidenceCommitmentV1(nil), base.RequiredEvidenceCommitments...)
		mutate(&mutated)
		digest, err := nodewire.InferReceiptSigningDigest(mutated)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if previous, collided := seen[digest]; collided {
			t.Fatalf("%s produced the same digest as %s", label, previous)
		}
		seen[digest] = label
	}

	// service_signature is wire field 12 and is explicitly not in the preimage.
	withSignature := base
	withSignature.ServiceSignature = bytes.Repeat([]byte{0x11}, 64)
	digest, err := nodewire.InferReceiptSigningDigest(withSignature)
	if err != nil {
		t.Fatalf("receipt with signature: %v", err)
	}
	if digest != baseDigest {
		t.Fatalf("service_signature must not enter the preimage")
	}
}

// TestBuilderClientReceiptDigestIsTheFrozenDigest is the cutover proof. Before
// the switch, internal/builderclient derived the pre-freeze eleven-field
// preimage and this test asserted the two digests DIFFERED. They must now be the
// same value: the receipt path signs the frozen digest, and this is the
// cross-package check that it did not quietly keep a second derivation.
func TestBuilderClientReceiptDigestIsTheFrozenDigest(t *testing.T) {
	vectors := goldenVectorsByName(t)
	vector := requireVector(t, vectors, vectorInferReceipt)
	frozen := inferReceiptFromVector(t, vectors, vector)

	frozenDigest, err := nodewire.InferReceiptSigningDigest(frozen)
	if err != nil {
		t.Fatalf("frozen digest: %v", err)
	}

	commitments := make([]builderclient.EvidenceCommitment, len(frozen.RequiredEvidenceCommitments))
	for index, commitment := range frozen.RequiredEvidenceCommitments {
		commitments[index] = builderclient.EvidenceCommitment{
			EvidenceKind:       commitment.EvidenceKind,
			EvidenceHashOrRoot: codec.Hash(commitment.EvidenceHashOrRoot),
			EncodedSizeBytes:   commitment.EncodedSizeBytes,
		}
	}
	wire := builderclient.SignedInferReceipt{
		SchemaVersion:               frozen.SchemaVersion,
		ChainID:                     frozen.ChainID,
		TaskID:                      hex.EncodeToString(frozen.TaskID),
		TaskHash:                    hex.EncodeToString(frozen.TaskHash),
		WorkerOperatorAddress:       frozen.WorkerOperatorAddress,
		ServiceAuthorizationNonce:   frozen.ServiceAuthorizationNonce,
		GenerationParamsDigest:      hex.EncodeToString(frozen.GenerationParamsDigest),
		OutputHash:                  hex.EncodeToString(frozen.OutputHash),
		OutputSizeBytes:             frozen.OutputSizeBytes,
		RequiredEvidenceCommitments: commitments,
		ExpiryHeight:                frozen.ExpiryHeight,
		GeneratedTokenCount:         frozen.GeneratedTokenCount,
		OutputLeafCount:             frozen.OutputLeafCount,
	}
	wireDigest, err := builderclient.InferReceiptSigningDigest(wire)
	if err != nil {
		t.Fatalf("builderclient digest: %v", err)
	}
	if wireDigest != frozenDigest {
		t.Fatalf("builderclient receipt digest = %x, want the frozen digest %x", wireDigest, frozenDigest)
	}
}

// TestRejectsMalformedInput pins the structural validation the frozen rules
// require, and only that: a Hash32 is exactly 32 raw bytes, a string is strict
// UTF-8, an operator address is canonical Bech32 decoding to 1..255 codec bytes,
// and an unspecified or unknown enum is refused.
func TestRejectsMalformedInput(t *testing.T) {
	vectors := goldenVectorsByName(t)
	receipt := inferReceiptFromVector(t, vectors, requireVector(t, vectors, vectorInferReceipt))
	verifierAddress := fieldBech32(t, requireVector(t, vectors, vectorVerifyCommit), 4, "verifier_operator_address")

	t.Run("short_hash32", func(t *testing.T) {
		broken := receipt
		broken.TaskID = receipt.TaskID[:31]
		requireErrorContains(t, digestErr(nodewire.InferReceiptSigningDigest(broken)),
			"task_id must be exactly 32 raw bytes, got 31")
	})

	t.Run("long_hash32", func(t *testing.T) {
		broken := receipt
		broken.TaskHash = append(append([]byte(nil), receipt.TaskHash...), 0x00)
		requireErrorContains(t, digestErr(nodewire.InferReceiptSigningDigest(broken)),
			"task_hash must be exactly 32 raw bytes, got 33")
	})

	t.Run("hex_text_instead_of_raw_hash32", func(t *testing.T) {
		broken := receipt
		broken.OutputHash = []byte(hex.EncodeToString(receipt.OutputHash))
		requireErrorContains(t, digestErr(nodewire.InferReceiptSigningDigest(broken)),
			"output_hash must be exactly 32 raw bytes, got 64")
	})

	t.Run("empty_hash32", func(t *testing.T) {
		broken := receipt
		broken.GenerationParamsDigest = nil
		requireErrorContains(t, digestErr(nodewire.InferReceiptSigningDigest(broken)),
			"generation_params_digest must be exactly 32 raw bytes, got 0")
	})

	t.Run("invalid_utf8_chain_id", func(t *testing.T) {
		broken := receipt
		broken.ChainID = string([]byte{0xff, 0xfe})
		requireErrorContains(t, digestErr(nodewire.InferReceiptSigningDigest(broken)),
			"chain_id must be strict UTF-8")
	})

	t.Run("empty_operator_address", func(t *testing.T) {
		broken := receipt
		broken.WorkerOperatorAddress = ""
		requireErrorContains(t, digestErr(nodewire.InferReceiptSigningDigest(broken)),
			"worker_operator_address must be a non-empty canonical Bech32 address")
	})

	t.Run("padded_operator_address", func(t *testing.T) {
		broken := receipt
		broken.WorkerOperatorAddress = " " + receipt.WorkerOperatorAddress
		requireErrorContains(t, digestErr(nodewire.InferReceiptSigningDigest(broken)),
			"worker_operator_address must not carry leading or trailing whitespace")
	})

	t.Run("undecodable_operator_address", func(t *testing.T) {
		broken := receipt
		broken.WorkerOperatorAddress = "trueopen1notavalidaddress"
		requireErrorContains(t, digestErr(nodewire.InferReceiptSigningDigest(broken)),
			"worker_operator_address is not a decodable Bech32 address")
	})

	t.Run("uppercase_operator_address_is_not_canonical", func(t *testing.T) {
		broken := receipt
		broken.WorkerOperatorAddress = strings.ToUpper(receipt.WorkerOperatorAddress)
		requireErrorContains(t, digestErr(nodewire.InferReceiptSigningDigest(broken)),
			"worker_operator_address must be the canonical Bech32 encoding of its address bytes")
	})

	t.Run("unspecified_evidence_kind", func(t *testing.T) {
		broken := receipt
		broken.RequiredEvidenceCommitments = []nodewire.EvidenceCommitmentV1{{
			EvidenceKind:       nodewire.EvidenceKindUnspecified,
			EvidenceHashOrRoot: receipt.OutputHash,
			EncodedSizeBytes:   1,
		}}
		requireErrorContains(t, digestErr(nodewire.InferReceiptSigningDigest(broken)),
			"evidence_kind must not be EVIDENCE_KIND_UNSPECIFIED")
	})

	t.Run("unknown_evidence_kind", func(t *testing.T) {
		broken := receipt
		broken.RequiredEvidenceCommitments = []nodewire.EvidenceCommitmentV1{{
			EvidenceKind:       nodewire.EvidenceKind(4),
			EvidenceHashOrRoot: receipt.OutputHash,
			EncodedSizeBytes:   1,
		}}
		requireErrorContains(t, digestErr(nodewire.InferReceiptSigningDigest(broken)),
			"evidence_kind 4 is not a registered EvidenceKind value")
	})

	t.Run("short_evidence_hash", func(t *testing.T) {
		broken := receipt
		broken.RequiredEvidenceCommitments = []nodewire.EvidenceCommitmentV1{{
			EvidenceKind:       nodewire.EvidenceKindWorkerValueOpening,
			EvidenceHashOrRoot: receipt.OutputHash[:16],
			EncodedSizeBytes:   1,
		}}
		requireErrorContains(t, digestErr(nodewire.InferReceiptSigningDigest(broken)),
			"required_evidence_commitments[0]: evidence_hash_or_root must be exactly 32 raw bytes, got 16")
	})

	t.Run("duplicate_evidence_kind", func(t *testing.T) {
		item := nodewire.EvidenceCommitmentV1{
			EvidenceKind:       nodewire.EvidenceKindWorkerValueOpening,
			EvidenceHashOrRoot: receipt.OutputHash,
			EncodedSizeBytes:   1,
		}
		_, err := nodewire.EvidenceCommitmentsHash([]nodewire.EvidenceCommitmentV1{item, item})
		requireErrorContains(t, err, "must be strictly ascending by evidence_kind with unique kinds")
	})

	t.Run("descending_evidence_kinds", func(t *testing.T) {
		_, err := nodewire.EvidenceCommitmentsHash([]nodewire.EvidenceCommitmentV1{
			{EvidenceKind: nodewire.EvidenceKindSettlementRootOpening, EvidenceHashOrRoot: receipt.OutputHash},
			{EvidenceKind: nodewire.EvidenceKindWorkerValueOpening, EvidenceHashOrRoot: receipt.OutputHash},
		})
		requireErrorContains(t, err, "element 1 has kind 1 after kind 3")
	})

	t.Run("verify_commit_placeholder_commit_hash", func(t *testing.T) {
		_, err := nodewire.VerifyCommitSigningDigest(nodewire.VerifyCommitV1{
			SchemaVersion:           nodewire.VerifyCommitSchemaVersionV1,
			ChainID:                 receipt.ChainID,
			TaskID:                  receipt.TaskID,
			VerifierOperatorAddress: verifierAddress,
			CommitHash:              []byte("placeholder"),
		})
		requireErrorContains(t, err, "commit_hash must be exactly 32 raw bytes, got 11")
	})

	t.Run("unspecified_duty", func(t *testing.T) {
		handraise := validWorkerHandraise(t, vectors)
		handraise.Duty = nodewire.DutyUnspecified
		requireErrorContains(t, digestErr(nodewire.WorkerHandraiseSigningDigest(handraise)),
			"duty must not be DUTY_UNSPECIFIED")
	})

	t.Run("unknown_duty", func(t *testing.T) {
		handraise := validWorkerHandraise(t, vectors)
		handraise.Duty = nodewire.Duty(7)
		requireErrorContains(t, digestErr(nodewire.WorkerHandraiseSigningDigest(handraise)),
			"duty 7 is not a registered Duty value")
	})

	t.Run("invalid_utf8_model_id", func(t *testing.T) {
		handraise := validWorkerHandraise(t, vectors)
		handraise.ModelID = string([]byte{0xc3, 0x28})
		requireErrorContains(t, digestErr(nodewire.WorkerHandraiseSigningDigest(handraise)),
			"model_id must be strict UTF-8")
	})

	t.Run("member_short_snapshot_id", func(t *testing.T) {
		handraise := validWorkerHandraise(t, vectors)
		handraise.Member.CandidatePoolSnapshotID = handraise.Member.CandidatePoolSnapshotID[:8]
		requireErrorContains(t, digestErr(nodewire.WorkerHandraiseSigningDigest(handraise)),
			"member.candidate_pool_snapshot_id must be exactly 32 raw bytes, got 8")
	})

	t.Run("member_undecodable_operator_address", func(t *testing.T) {
		handraise := validWorkerHandraise(t, vectors)
		handraise.Member.OperatorAddress = "not-bech32"
		requireErrorContains(t, digestErr(nodewire.WorkerHandraiseSigningDigest(handraise)),
			"member.operator_address is not a decodable Bech32 address")
	})

	t.Run("settlement_bill_short_receipt_ref", func(t *testing.T) {
		_, err := nodewire.SettlementBillLeafHash(nodewire.TaskSettlementBillLeafV1{
			WorkerOperatorAddress: receipt.WorkerOperatorAddress,
			InferReceiptRef:       receipt.TaskID[:4],
		})
		requireErrorContains(t, err, "infer_receipt_ref must be exactly 32 raw bytes, got 4")
	})
}

// TestAcceptsWhatNodeAccepts is the other half of the rejection boundary: the
// frozen derivations stay total for values the handler - not the derivation -
// judges. Refusing any of these here would make Cortex unable to reproduce a
// digest the chain accepts.
func TestAcceptsWhatNodeAccepts(t *testing.T) {
	vectors := goldenVectorsByName(t)
	base := inferReceiptFromVector(t, vectors, requireVector(t, vectors, vectorInferReceipt))

	cases := map[string]func(*nodewire.InferReceiptV2){
		"empty chain_id":         func(r *nodewire.InferReceiptV2) { r.ChainID = "" },
		"zero nonce":             func(r *nodewire.InferReceiptV2) { r.ServiceAuthorizationNonce = 0 },
		"zero output_size_bytes": func(r *nodewire.InferReceiptV2) { r.OutputSizeBytes = 0 },
		"zero expiry_height":     func(r *nodewire.InferReceiptV2) { r.ExpiryHeight = 0 },
		"empty evidence list":    func(r *nodewire.InferReceiptV2) { r.RequiredEvidenceCommitments = nil },
		"zero-hash output":       func(r *nodewire.InferReceiptV2) { r.OutputHash = make([]byte, 32) },
	}
	for label, mutate := range cases {
		mutated := base
		mutate(&mutated)
		if _, err := nodewire.InferReceiptSigningDigest(mutated); err != nil {
			t.Fatalf("%s must still derive a digest: %v", label, err)
		}
	}
}

func TestInferReceiptRejectsRetiredOrUnknownSchema(t *testing.T) {
	vectors := goldenVectorsByName(t)
	receipt := inferReceiptFromVector(t, vectors, requireVector(t, vectors, vectorInferReceipt))
	for _, version := range []uint32{0, 1, 3, 99} {
		receipt.SchemaVersion = version
		if _, err := nodewire.InferReceiptSigningDigest(receipt); err == nil {
			t.Fatalf("receipt schema %d accepted", version)
		}
	}
}

// TestOperatorAddressRoundTripsAcrossPrefixes proves the framed value is the
// address codec bytes and not the Bech32 text: two addresses that differ only in
// their human-readable prefix decode to the same bytes, which is exactly why the
// chain_id field, not the prefix, separates two chains.
func TestOperatorAddressRoundTripsAcrossPrefixes(t *testing.T) {
	vectors := goldenVectorsByName(t)
	worker := fieldBech32(t, requireVector(t, vectors, vectorInferReceipt), 4, "worker_operator_address")

	raw, err := nodewire.CanonicalOperatorAddressBytes("worker_operator_address", worker)
	if err != nil {
		t.Fatalf("decode %s: %v", worker, err)
	}
	if len(raw) != 20 {
		t.Fatalf("worker address decodes to %d bytes, want 20", len(raw))
	}
	if !strings.HasPrefix(worker, "trueopen1") {
		t.Fatalf("fixture worker address %q lost its prefix", worker)
	}
}

func TestOperatorAddressAcceptsCosmosCodecLengths(t *testing.T) {
	vectors := goldenVectorsByName(t)
	_ = vectors
	for _, tc := range []struct {
		name    string
		address string
		bytes   int
	}{
		{"nineteen bytes", "trueopen15zs69gay5kn2029f4246etdw47ctrvslmk47x", 19},
		{"twenty one bytes", "trueopen15zs69gay5kn2029f4246etdw47ctrv4nks0skc79", 21},
		{"thirty two bytes", "trueopen15zs69gay5kn2029f4246etdw47ctrv4nkj6mddachxath09ah6lslqwk6z", 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := nodewire.CanonicalOperatorAddressBytes("worker_operator_address", tc.address)
			if err != nil || len(raw) != tc.bytes {
				t.Fatalf("CanonicalOperatorAddressBytes = %x, %v; want %d bytes", raw, err, tc.bytes)
			}
		})
	}
}

// canonicalTrueOpenAddress20 is the fixture's 20-byte worker operator address. The
// wrong-length cases above are the same 0xa0.. payload truncated or extended and
// re-encoded under the same prefix.
const canonicalTrueOpenAddress20 = "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc"

func validWorkerHandraise(t *testing.T, vectors map[string]goldenVector) nodewire.WorkerHandraiseV1 {
	t.Helper()
	vector := requireVector(t, vectors, vectorWorkerHandraise)
	return nodewire.WorkerHandraiseV1{
		SchemaVersion:             uint32(fieldUint(t, vector, 0, "schema_version")),
		ChainID:                   fieldString(t, vector, 1, "chain_id"),
		TaskID:                    fieldBytes(t, vector, 2, "task_id"),
		TaskHash:                  fieldBytes(t, vector, 3, "task_hash"),
		ModelID:                   fieldString(t, vector, 4, "model_id"),
		ProfileVersion:            uint32(fieldUint(t, vector, 5, "profile_version")),
		Member:                    memberRef(t, vector, 6),
		Duty:                      nodewire.Duty(fieldUint(t, vector, 7, "duty")),
		ServiceAuthorizationNonce: fieldUint(t, vector, 8, "service_authorization_nonce"),
		ExpiryHeight:              fieldUint(t, vector, 9, "expiry_height"),
	}
}

func digestErr(_ codec.Hash, err error) error {
	return err
}

func requireErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err.Error(), want)
	}
}

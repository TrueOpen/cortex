package builderclient

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

const otherFixtureWorkerAddress = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"

// Receipt construction inputs retained from the earlier fixture. These helpers
// are not provenance assertions about the replaced task-data request protocol.
func TestInferReceiptEmptyEvidenceListIsRefused(t *testing.T) {
	want, err := nodewire.EvidenceCommitmentsHash(nil)
	if err != nil {
		t.Fatal(err)
	}
	emptyList, err := nodewire.EvidenceCommitmentsHash([]nodewire.EvidenceCommitmentV1{})
	if err != nil || emptyList != want {
		t.Fatalf("empty evidence list digest = %x, %v; want %x", emptyList, err, want)
	}
	if want == (codec.Hash{}) {
		t.Fatal("the empty evidence list digest must not be 32 zero bytes")
	}

	// The tenth preimage field must carry that digest rather than be skipped, so
	// the same receipt with and without commitments must hash differently. Proved
	// at the nodewire layer, which is the layer allowed to hold an empty list.
	receipt := taskDataTestReceipt(t, newTaskDataTestKeyPair(t), "chain-A", []byte("output"))
	wire, err := inferReceiptWire(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nodewire.InferReceiptSigningDigest(wire); err != nil {
		t.Fatal(err)
	}
	// A V3 receipt carries exactly [value, token]; an empty list is refused.
	wire.RequiredEvidenceCommitments = nil
	if _, err := nodewire.InferReceiptSigningDigest(wire); err == nil {
		t.Fatal("a V3 receipt without evidence commitments was hashed")
	}

	// The signer, unlike the hash, must refuse it: an empty list cannot become a
	// submittable receipt through any builderclient entry point.
	empty := receipt
	empty.RequiredEvidenceCommitments = nil
	if _, err := InferReceiptSigningDigest(empty); err == nil {
		t.Fatal("InferReceiptSigningDigest signed a receipt with no evidence commitments")
	}
}

func TestInferReceiptSigningDigestBindsEveryPreimageField(t *testing.T) {
	base := taskDataTestReceipt(t, newTaskDataTestKeyPair(t), "chain-A", []byte("output"))
	want, err := InferReceiptSigningDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*SignedInferReceipt){
		"chain_id":                    func(v *SignedInferReceipt) { v.ChainID = "other-chain" },
		"task_id":                     func(v *SignedInferReceipt) { v.TaskID = strings.Repeat("1", 63) + "2" },
		"task_hash":                   func(v *SignedInferReceipt) { v.TaskHash = strings.Repeat("8", 63) + "9" },
		"worker_operator_address":     func(v *SignedInferReceipt) { v.WorkerOperatorAddress = otherFixtureWorkerAddress },
		"service_authorization_nonce": func(v *SignedInferReceipt) { v.ServiceAuthorizationNonce++ },
		"generation_params_digest":    func(v *SignedInferReceipt) { v.GenerationParamsDigest = strings.Repeat("2", 63) + "3" },
		"output_hash":                 func(v *SignedInferReceipt) { v.OutputHash = strings.Repeat("3", 63) + "4" },
		"output_size_bytes":           func(v *SignedInferReceipt) { v.OutputSizeBytes++ },
		"output_leaf_count":           func(v *SignedInferReceipt) { v.OutputLeafCount++ },
		"expiry_height":               func(v *SignedInferReceipt) { v.ExpiryHeight++ },
		"token_evidence_hash_or_root": func(v *SignedInferReceipt) {
			v.RequiredEvidenceCommitments[1].EvidenceHashOrRoot = mustHash(t, strings.Repeat("6", 63)+"7")
		},
		"evidence_hash_or_root": func(v *SignedInferReceipt) {
			v.RequiredEvidenceCommitments[0].EvidenceHashOrRoot = mustHash(t, strings.Repeat("4", 63)+"5")
		},
		"evidence_encoded_size_bytes": func(v *SignedInferReceipt) {
			v.RequiredEvidenceCommitments[0].EncodedSizeBytes++
		},
	}
	for name, mutate := range map[string]func(*SignedInferReceipt){
		"evidence_kind": func(v *SignedInferReceipt) {
			v.RequiredEvidenceCommitments[1].EvidenceKind = nodewire.EvidenceKindVerifierValueOpening
		},
		"evidence_quantity": func(v *SignedInferReceipt) {
			v.RequiredEvidenceCommitments = v.RequiredEvidenceCommitments[:1]
		},
	} {
		changed := base
		changed.RequiredEvidenceCommitments = append([]EvidenceCommitment(nil), base.RequiredEvidenceCommitments...)
		mutate(&changed)
		if _, err := InferReceiptSigningDigest(changed); err == nil {
			t.Fatalf("%s: a receipt outside the V3 evidence shape was accepted", name)
		}
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := base
			changed.RequiredEvidenceCommitments = append([]EvidenceCommitment(nil), base.RequiredEvidenceCommitments...)
			mutate(&changed)
			got, err := InferReceiptSigningDigest(changed)
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatalf("%s mutation did not change the receipt digest", name)
			}
		})
	}

	// service_signature is wire field 12 and must stay out of the preimage.
	unsigned := base
	unsigned.ServiceSignature = ""
	unsignedDigest, err := InferReceiptSigningDigest(unsigned)
	if err != nil || unsignedDigest != want {
		t.Fatalf("unsigned receipt digest = %x, %v; want %x", unsignedDigest, err, want)
	}
}

func mustHash(t *testing.T, value string) codec.Hash {
	t.Helper()
	decoded := mustDecodeHex(t, value)
	if len(decoded) != sha256.Size {
		t.Fatalf("hash %q decoded to %d bytes", value, len(decoded))
	}
	var out codec.Hash
	copy(out[:], decoded)
	return out
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

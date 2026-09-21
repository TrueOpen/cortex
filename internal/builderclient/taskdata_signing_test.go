package builderclient

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/nodewire"
	"os"
	"strings"
	"testing"
)

const otherFixtureWorkerAddress = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"

// Receipt construction inputs retained from the earlier fixture. These helpers
// are not provenance assertions about the replaced task-data request protocol.
type fixtureReceipt struct {
	SchemaVersion               uint32 `json:"schema_version"`
	ChainID                     string `json:"chain_id"`
	TaskID                      string `json:"task_id"`
	TaskHash                    string `json:"task_hash"`
	WorkerOperatorAddress       string `json:"worker_operator_address"`
	ServiceAuthorizationNonce   uint64 `json:"service_authorization_nonce"`
	GenerationParamsDigest      string `json:"generation_params_digest"`
	OutputHash                  string `json:"output_hash"`
	OutputSizeBytes             uint64 `json:"output_size_bytes"`
	RequiredEvidenceCommitments []struct {
		EvidenceKind       int32  `json:"evidence_kind"`
		EvidenceHashOrRoot string `json:"evidence_hash_or_root"`
		EncodedSizeBytes   uint64 `json:"encoded_size_bytes"`
	} `json:"required_evidence_commitments"`
	ExpiryHeight             uint64 `json:"expiry_height"`
	ServiceSignature         string `json:"service_signature"`
	ExpectedSigningDigestHex string `json:"expected_signing_digest_hex"`
}

type taskDataSigningFixture struct {
	NexusSourceCommit string `json:"nexus_source_commit"`
	NodeSourceCommit  string `json:"node_source_commit"`
	Request           struct {
		Method                  string `json:"method"`
		ChainID                 string `json:"chain_id"`
		BuilderAddress          string `json:"builder_address"`
		SessionID               string `json:"session_id"`
		TaskID                  string `json:"task_id"`
		DataKind                string `json:"data_kind"`
		Requester               string `json:"requester"`
		RequesterPubkeyHex      string `json:"requester_pubkey_hex"`
		RequestNonceHex         string `json:"request_nonce_hex"`
		ExpiresAtHeight         uint64 `json:"expires_at_height"`
		BodyDigestHex           string `json:"body_digest_hex"`
		ExpectedSigningBytesHex string `json:"expected_signing_bytes_hex"`
		ExpectedDigestHex       string `json:"expected_digest_hex"`
	} `json:"request"`
	Range struct {
		Method                  string `json:"method"`
		ChainID                 string `json:"chain_id"`
		BuilderAddress          string `json:"builder_address"`
		SessionID               string `json:"session_id"`
		TaskID                  string `json:"task_id"`
		DataKind                string `json:"data_kind"`
		Recipient               string `json:"recipient"`
		RecipientPubkeyHex      string `json:"recipient_pubkey_hex"`
		Offset                  uint64 `json:"offset"`
		Length                  uint64 `json:"length"`
		RequestNonceHex         string `json:"request_nonce_hex"`
		ExpiresAtHeight         uint64 `json:"expires_at_height"`
		ExpectedSigningBytesHex string `json:"expected_signing_bytes_hex"`
		ExpectedDigestHex       string `json:"expected_digest_hex"`
	} `json:"range"`
	Receipt                 fixtureReceipt `json:"receipt"`
	NodeFrozenReceiptGolden struct {
		fixtureReceipt
		ExpectedDigestHex                 string `json:"expected_digest_hex"`
		EmptyEvidenceCommitmentsDigestHex string `json:"empty_evidence_commitments_digest_hex"`
	} `json:"node_frozen_receipt_golden"`
	UploadBody struct {
		Method            string `json:"method"`
		SessionID         string `json:"session_id"`
		TaskID            string `json:"task_id"`
		DataKind          string `json:"data_kind"`
		SizeBytes         uint64 `json:"size_bytes"`
		SemanticHash      string `json:"semantic_hash"`
		MediaType         string `json:"media_type"`
		ExpectedDigestHex string `json:"expected_digest_hex"`
	} `json:"upload_body"`
	ReceiptRelayBody struct {
		Domain            string `json:"domain"`
		SessionID         string `json:"session_id"`
		ExpectedDigestHex string `json:"expected_digest_hex"`
	} `json:"receipt_relay_body"`
	StorageConfirmation struct {
		Domain                  string `json:"domain"`
		ChainID                 string `json:"chain_id"`
		TaskID                  string `json:"task_id"`
		DataKind                string `json:"data_kind"`
		OutputHash              string `json:"output_hash"`
		SizeBytes               uint64 `json:"size_bytes"`
		BuilderOperator         string `json:"builder_operator"`
		RetentionUntilHeight    uint64 `json:"retention_until_height"`
		ExpectedSigningBytesHex string `json:"expected_signing_bytes_hex"`
		ExpectedDigestHex       string `json:"expected_digest_hex"`
	} `json:"storage_confirmation"`
}

func TestInferReceiptEmptyEvidenceListIsThePublishedDigest(t *testing.T) {
	fixture := loadTaskDataSigningFixture(t)
	golden := fixture.NodeFrozenReceiptGolden
	want := mustHash(t, golden.EmptyEvidenceCommitmentsDigestHex)

	nilList, err := nodewire.EvidenceCommitmentsHash(nil)
	if err != nil {
		t.Fatal(err)
	}
	if nilList != want {
		t.Fatalf("nil evidence list digest = %x, want %x", nilList, want)
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
	receipt := receiptFromFixture(t, golden.fixtureReceipt)
	wire, err := inferReceiptWire(receipt)
	if err != nil {
		t.Fatal(err)
	}
	withEvidence, err := nodewire.InferReceiptSigningDigest(wire)
	if err != nil {
		t.Fatal(err)
	}
	wire.RequiredEvidenceCommitments = nil
	withoutEvidence, err := nodewire.InferReceiptSigningDigest(wire)
	if err != nil {
		t.Fatal(err)
	}
	if withoutEvidence == withEvidence {
		t.Fatal("dropping every evidence commitment did not change the receipt digest")
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
	fixture := loadTaskDataSigningFixture(t)
	base := receiptFromFixture(t, fixture.Receipt)
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
		"evidence_kind": func(v *SignedInferReceipt) {
			v.RequiredEvidenceCommitments[1].EvidenceKind = nodewire.EvidenceKindVerifierValueOpening
		},
		"evidence_hash_or_root": func(v *SignedInferReceipt) {
			v.RequiredEvidenceCommitments[0].EvidenceHashOrRoot = mustHash(t, strings.Repeat("4", 63)+"5")
		},
		"evidence_encoded_size_bytes": func(v *SignedInferReceipt) {
			v.RequiredEvidenceCommitments[0].EncodedSizeBytes++
		},
		"evidence_quantity": func(v *SignedInferReceipt) {
			v.RequiredEvidenceCommitments = v.RequiredEvidenceCommitments[:1]
		},
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

func loadTaskDataSigningFixture(t *testing.T) taskDataSigningFixture {
	t.Helper()
	payload, err := os.ReadFile("testdata/taskdata_signing_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture taskDataSigningFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func receiptFromFixture(t *testing.T, fixture fixtureReceipt) SignedInferReceipt {
	t.Helper()
	commitments := make([]EvidenceCommitment, len(fixture.RequiredEvidenceCommitments))
	for index, commitment := range fixture.RequiredEvidenceCommitments {
		commitments[index] = EvidenceCommitment{
			EvidenceKind:       nodewire.EvidenceKind(commitment.EvidenceKind),
			EvidenceHashOrRoot: mustHash(t, commitment.EvidenceHashOrRoot),
			EncodedSizeBytes:   commitment.EncodedSizeBytes,
		}
	}
	return SignedInferReceipt{
		SchemaVersion:               nodewire.InferReceiptSchemaVersionV2,
		ChainID:                     fixture.ChainID,
		TaskID:                      fixture.TaskID,
		TaskHash:                    fixture.TaskHash,
		WorkerOperatorAddress:       fixture.WorkerOperatorAddress,
		ServiceAuthorizationNonce:   fixture.ServiceAuthorizationNonce,
		GenerationParamsDigest:      fixture.GenerationParamsDigest,
		OutputHash:                  fixture.OutputHash,
		OutputSizeBytes:             fixture.OutputSizeBytes,
		OutputLeafCount:             1,
		RequiredEvidenceCommitments: commitments,
		ExpiryHeight:                fixture.ExpiryHeight,
		ServiceSignature:            fixture.ServiceSignature,
	}
}

func assertHash(t *testing.T, got codec.Hash, err error, wantHex string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if want := mustHash(t, wantHex); got != want {
		t.Fatalf("digest = %x, want %x", got, want)
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

package nodewire

import (
	"encoding/hex"
	"testing"
)

// Values measured on chain: this receipt is the one Keeper refused during local
// integration, and both expected values come straight from node's own
// EvidenceCommitmentsHash / InferReceiptSigningDigest output.
//
// The difference was in how a repeated value is assembled: the chain folds the whole
// list into **one nested frame** (the element count written once inside the frame,
// then each element in turn), while this used to flatten every element into a
// top-level field, losing that wrapper. The element frames themselves agree on both
// sides, and an empty list happens to produce the same value either way, so only a
// real receipt carrying evidence commitments exposes it - the digest the Worker signs
// is not the one the chain derives, and the transaction is necessarily refused:
// "invalid current service signature: signature does not verify against signing digest".
func TestEvidenceCommitmentsHashMatchesChain(t *testing.T) {
	const (
		wantCommitments = "fcfc775b30d732bdb69387af47eb6a1893386054fa12799a126f1bc8a7830e09"
		wantDigest      = "c0692fa5683eb14c66912c21ecdaf0f8a5e7317a6a8548f39ba881cb489e6f92"
		wantEmpty       = "f029302b7f33dd77ad8e5217897a4e8386bf321dde9a510c1c6a287e408b9873"
	)
	mustHash := func(s string) []byte {
		raw, err := hex.DecodeString(s)
		if err != nil || len(raw) != 32 {
			t.Fatalf("bad fixture hash %q", s)
		}
		return raw
	}

	commitments := []EvidenceCommitmentV1{{
		EvidenceKind:       1,
		EvidenceHashOrRoot: mustHash("69784b36f25819ef6b2444f0188e947b17faa651ccd52af1a21c142f24e5f028"),
		EncodedSizeBytes:   145,
	}}
	got, err := EvidenceCommitmentsHash(commitments)
	if err != nil {
		t.Fatalf("commitments hash: %v", err)
	}
	if hex.EncodeToString(got[:]) != wantCommitments {
		t.Fatalf("evidence_commitments_hash = %x, the chain derives %s", got[:], wantCommitments)
	}

	empty, err := EvidenceCommitmentsHash(nil)
	if err != nil {
		t.Fatalf("empty commitments hash: %v", err)
	}
	if hex.EncodeToString(empty[:]) != wantEmpty {
		t.Fatalf("empty list = %x, the chain derives %s", empty[:], wantEmpty)
	}

	receipt := InferReceiptV2{
		SchemaVersion:               InferReceiptSchemaVersionV2,
		ChainID:                     "trueopen-localnet-1",
		TaskID:                      mustHash("0696367c45d8ab4de9e18b289fa5df76d86e8a20539e3ddac33551d78f72fed6"),
		TaskHash:                    mustHash("dd149868c68a888924870c031af1d83784580d72c7541c29f68c78c2717cddb0"),
		WorkerOperatorAddress:       "trueopen1n76x6eelp8s6nx737vnmp29rdme7peaypql50k",
		ServiceAuthorizationNonce:   1,
		GenerationParamsDigest:      mustHash("2f4fac4607c697feb81161ed776ed2cbabd2a93f42a5cd0b3f984b0db19d423d"),
		OutputHash:                  mustHash("3f473a5930a3b347f63a6579f443cd456cdf05f2b4ef607be850179af9a35753"),
		OutputSizeBytes:             88,
		ExpiryHeight:                131708,
		RequiredEvidenceCommitments: commitments,
		OutputLeafCount:             1,
	}
	digest, err := InferReceiptSigningDigest(receipt)
	if err != nil {
		t.Fatalf("receipt digest: %v", err)
	}
	if hex.EncodeToString(digest[:]) == wantDigest {
		t.Fatal("retired receipt digest must differ from the v0.4.1 schema")
	}
}

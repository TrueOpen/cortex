package keepercontract

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/txclient"
	"github.com/TrueOpen/cortex/internal/wirevectors"
)

// The released V3 model fixture is verified by wirevectors.File.
const modelProfileCanonicalGoldenPath = "hub/model_profile_canonical_v3.json"

type modelProfileCanonicalGolden struct {
	Schema              string         `json:"schema"`
	ChainID             string         `json:"chain_id"`
	ProposerAddress     string         `json:"proposer_address"`
	CanonicalProjection map[string]any `json:"canonical_projection"`
	EvidenceSchemaHash  string         `json:"evidence_schema_hash"`
	ChainProjectionHash string         `json:"chain_projection_hash"`
	RegistrationDigest  string         `json:"registration_digest"`
	ProjectionBytes     int            `json:"canonical_projection_bytes"`
	PayloadBytes        string         `json:"registration_payload_bytes"`
}

func loadModelProfileCanonicalGolden(t *testing.T) modelProfileCanonicalGolden {
	t.Helper()
	raw, err := wirevectors.File("hub/model_profile_canonical_v3.json")
	if err != nil {
		t.Fatalf("read %s: %v", modelProfileCanonicalGoldenPath, err)
	}
	var golden modelProfileCanonicalGolden
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatalf("decode %s: %v", modelProfileCanonicalGoldenPath, err)
	}
	return golden
}

// The model fixture declares its two Worker commitment requirements and hash.
var wireGoldenEvidenceSchemaHash = func() string {
	raw, err := wirevectors.File(modelProfileCanonicalGoldenPath)
	if err != nil {
		return ""
	}
	var golden modelProfileCanonicalGolden
	if err := json.Unmarshal(raw, &golden); err != nil {
		return ""
	}
	return strings.TrimPrefix(golden.EvidenceSchemaHash, "0x")
}()

func TestModelProfileCanonicalGoldenIsWireVerbatim(t *testing.T) {
	_, err := wirevectors.File("hub/model_profile_canonical_v3.json")
	if err != nil {
		t.Fatalf("read %s: %v", modelProfileCanonicalGoldenPath, err)
	}
}

// TestCanonicalModelProfileProjectionAgreesWithWireGolden is the check that
// caught the drift this file exists for. Comparing only the digests would say
// "these differ" and nothing more; comparing the projections field by field
// says which field differs, and it also proves the whole JSON projection -- key
// order, number formatting, enum trimming -- and not just its hash.
//
// The drift it caught: TRUEOPEN_EVIDENCE_SCHEMA_V1's repeated
// required_infer_evidence was flattened into the outer field list instead of
// being wrapped in one nested frame carrying its own element_count. That moved
// evidence_schema_hash, which sits inside the canonical projection, which moved
// chain_projection_hash and registration_digest with it -- so every model
// registration this node signed disagreed with the chain's own derivation.
func TestCanonicalModelProfileProjectionAgreesWithWireGolden(t *testing.T) {
	golden := loadModelProfileCanonicalGolden(t)
	profile := nodeGoldenModelProfileProjection()

	evidenceHash, err := EvidenceSchemaHash(profile)
	if err != nil {
		t.Fatalf("EvidenceSchemaHash: %v", err)
	}
	if got := hex.EncodeToString(evidenceHash[:]); got != strings.TrimPrefix(golden.EvidenceSchemaHash, "0x") {
		t.Fatalf("evidence schema hash %s, published %s", got, golden.EvidenceSchemaHash)
	}
	invalid := profile
	invalid.VerificationProfile.EvidenceSchemaHash = txclient.ProtoBytes32(strings.Repeat("00", 32))
	if _, err := CanonicalModelProfileProjection(invalid); err == nil {
		t.Fatal("accepted an incorrect evidence schema hash")
	}

	digest, projection, err := ModelRegistrationDigest(golden.ChainID, golden.ProposerAddress, profile)
	if err != nil {
		t.Fatalf("ModelRegistrationDigest: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(projection, &got); err != nil {
		t.Fatalf("decode produced projection: %v", err)
	}
	if !reflect.DeepEqual(got, golden.CanonicalProjection) {
		for _, key := range projectionKeyUnion(got, golden.CanonicalProjection) {
			if !reflect.DeepEqual(got[key], golden.CanonicalProjection[key]) {
				t.Errorf("canonical projection %q = %#v, wire golden = %#v", key, got[key], golden.CanonicalProjection[key])
			}
		}
		t.FailNow()
	}

	expectedProjection, err := codec.CanonicalJSON(golden.CanonicalProjection)
	if err != nil {
		t.Fatal(err)
	}
	// The golden manifest_uri carries '&'. Canonical JSON writes it as
	// itself; an HTML-escaping encoder would write \u0026 and every digest
	// would move.
	if !bytes.Equal(projection, expectedProjection) || len(projection) != golden.ProjectionBytes || !bytes.Contains(projection, []byte("?rev=3&sig=ab")) {
		t.Fatalf("projection bytes (%d) differ from the published %d-byte projection:\n%s", len(projection), golden.ProjectionBytes, projection)
	}
	projectionHash := codec.HashV1("TRUEOPEN_MODEL_CHAIN_PROJECTION_V3", expectedProjection)
	if projectionHash.String() != strings.TrimPrefix(golden.ChainProjectionHash, "0x") {
		t.Fatalf("chain projection hash %s, published %s", projectionHash, golden.ChainProjectionHash)
	}
	if digest.String() != strings.TrimPrefix(golden.RegistrationDigest, "0x") {
		t.Fatalf("registration digest %s, published %s", digest, golden.RegistrationDigest)
	}
	expectedPayload, err := codec.CanonicalJSON(map[string]any{"chain_id": golden.ChainID, "chain_projection_hash": "0x" + hex.EncodeToString(projectionHash[:]),
		"manifest_hash": golden.CanonicalProjection["manifest_hash"], "profile_version": golden.CanonicalProjection["profile_version"], "proposer_address": golden.ProposerAddress})
	if err != nil {
		t.Fatal(err)
	}
	if string(expectedPayload) != golden.PayloadBytes {
		t.Fatalf("registration payload %s, published %s", expectedPayload, golden.PayloadBytes)
	}
	if want := codec.HashV1("TRUEOPEN_MODEL_REGISTRATION_DIGEST_V3", expectedPayload); digest != want {
		t.Fatalf("registration digest %x, independent formula %x", digest, want)
	}
}

func projectionKeyUnion(a, b map[string]any) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	keys := make([]string, 0, len(a)+len(b))
	for _, source := range []map[string]any{a, b} {
		for key := range source {
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
	}
	return keys
}

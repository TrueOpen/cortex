package chainclient

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestProtoBytes32UsesProtoJSONBase64(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	var value ProtoBytes32
	if err := json.Unmarshal([]byte(`"`+encoded+`"`), &value); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if value.Hex() != "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" {
		t.Fatalf("value = %q", value.Hex())
	}
	marshaled, err := json.Marshal(value)
	if err != nil || string(marshaled) != `"`+encoded+`"` {
		t.Fatalf("Marshal = %s, %v", marshaled, err)
	}
}

func TestProtoBytes32RejectsNonCanonicalWireValues(t *testing.T) {
	for name, raw := range map[string]string{
		"hex":          `"` + strings.Repeat("ab", 32) + `"`,
		"short base64": `"` + base64.StdEncoding.EncodeToString(make([]byte, 31)) + `"`,
		"number":       `7`,
		"null":         `null`,
	} {
		t.Run(name, func(t *testing.T) {
			var value ProtoBytes32
			if err := json.Unmarshal([]byte(raw), &value); err == nil {
				t.Fatalf("Unmarshal(%s) error = nil, want bytes32 protocol error", raw)
			}
		})
	}
}

func TestUint64StringDecodesProtoJSONDecimalString(t *testing.T) {
	var value Uint64String
	if err := json.Unmarshal([]byte(`"18446744073709551615"`), &value); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if value.Uint64() != math.MaxUint64 {
		t.Fatalf("value = %d, want MaxUint64", value.Uint64())
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if string(encoded) != `"18446744073709551615"` {
		t.Fatalf("encoded = %s", encoded)
	}
}

func TestUint64StringRejectsNonProtoJSONValues(t *testing.T) {
	for name, raw := range map[string]string{
		"numeric":  `42`,
		"negative": `"-1"`,
		"overflow": `"18446744073709551616"`,
		"space":    `" 42"`,
		"empty":    `""`,
	} {
		t.Run(name, func(t *testing.T) {
			var value Uint64String
			if err := json.Unmarshal([]byte(raw), &value); err == nil {
				t.Fatalf("Unmarshal(%s) error = nil, want protocol error", raw)
			}
		})
	}
}

func TestProfileVersionUsesNodeUint32ProtoJSON(t *testing.T) {
	var version ProfileVersion
	if err := json.Unmarshal([]byte(`7`), &version); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if version.Uint32() != 7 || version.String() != "7" {
		t.Fatalf("version = %q (%d), want 7", version.String(), version.Uint32())
	}

	encoded, err := json.Marshal(version)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if string(encoded) != `7` {
		t.Fatalf("encoded = %s, want numeric uint32", encoded)
	}

	for name, raw := range map[string]string{
		"quoted":   `"7"`,
		"negative": `-1`,
		"overflow": `4294967296`,
		"decimal":  `1.0`,
	} {
		t.Run(name, func(t *testing.T) {
			var invalid ProfileVersion
			if err := json.Unmarshal([]byte(raw), &invalid); err == nil {
				t.Fatalf("Unmarshal(%s) error = nil, want uint32 protocol error", raw)
			}
		})
	}
}

func TestAssignmentSnapshotRejectsQuotedLegacyProfileVersion(t *testing.T) {
	var assignment AssignmentSnapshot
	err := json.Unmarshal([]byte(`{"model_id":"model-a","profile_version":"llm_text_v1"}`), &assignment)
	if err == nil || !strings.Contains(err.Error(), "uint32") {
		t.Fatalf("Unmarshal legacy assignment error = %v, want uint32 rejection", err)
	}
}

func TestHexHashDecodesLowercaseSHA256(t *testing.T) {
	raw := strings.Repeat("ab", 32)
	var value HexHash
	if err := json.Unmarshal([]byte(`"`+raw+`"`), &value); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if value.String() != raw {
		t.Fatalf("value = %q, want %q", value.String(), raw)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if string(encoded) != `"`+raw+`"` {
		t.Fatalf("encoded = %s", encoded)
	}
}

func TestHexHashRejectsInvalidEncoding(t *testing.T) {
	for name, raw := range map[string]string{
		"short":     strings.Repeat("ab", 31),
		"uppercase": strings.Repeat("AB", 32),
		"prefix":    "0x" + strings.Repeat("ab", 32),
		"nonhex":    strings.Repeat("zz", 32),
	} {
		t.Run(name, func(t *testing.T) {
			var value HexHash
			if err := json.Unmarshal([]byte(`"`+raw+`"`), &value); err == nil {
				t.Fatalf("Unmarshal(%q) error = nil, want protocol error", raw)
			}
		})
	}
}

func TestKeeperSnapshotsValidateRequiredIdentityAndDeadlineFields(t *testing.T) {
	node := CortexNodeSnapshot{
		OperatorAddress:       "trueopen1operator",
		CurrentServiceAddress: "trueopen1service",
		CurrentServicePubkey:  "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AuthorizationNonce:    NewUint64String(1),
		Status:                "ACTIVE",
	}
	if err := node.Validate(); err != nil {
		t.Fatalf("CortexNodeSnapshot.Validate returned error: %v", err)
	}
	node.OperatorAddress = ""
	if err := node.Validate(); err == nil {
		t.Fatalf("CortexNodeSnapshot.Validate error = nil, want missing operator")
	}

	task := TaskSnapshot{
		Status:          "VERIFYING",
		CurrentContract: true,
		Assignment: AssignmentSnapshot{
			SessionID:                "session-1",
			TaskID:                   "task-1",
			OrderSequence:            NewUint64String(1),
			SelectedWorker:           "trueopen1node",
			InferDeadlineHeight:      NewUint64String(120),
			ModelID:                  "model-1",
			ProfileVersion:           NewProfileVersion(1),
			AcceptedOrderPayloadHash: HexHash{2},
			TaskReceiptFactsSnapshot: TaskReceiptFactsSnapshot{AcceptedTaskHash: ProtoBytes32(make([]byte, 32))},
		},
		VerifierAssignment: VerifierAssignmentSnapshot{
			SessionID:                         "session-1",
			TaskID:                            "task-1",
			OpenVerifyHeight:                  NewUint64String(125),
			FormalVerifierSet:                 []string{"trueopen1verifier"},
			SampleSeedReadyHeight:             NewUint64String(126),
			VerificationSampleSeed:            HexHash{3},
			CommitDeadlineHeight:              NewUint64String(130),
			WorkerRevealDeadlineHeight:        NewUint64String(135),
			RevealDeadlineHeight:              NewUint64String(140),
			VerifyDeadlineHeight:              NewUint64String(150),
			SampleSeedStatus:                  "READY",
			VerifierCandidateWindowHash:       HexHash{4},
			ParamVersion:                      "task-params-v7",
			SampleRandomnessAggregationBlocks: NewUint64String(2),
			WorkerRevealWindowBlocks:          NewUint64String(5),
			RevealWindowBlocks:                NewUint64String(5),
			Stage3BuilderGraceBlocks:          NewUint64String(10),
		},
	}
	if err := task.Validate(); err != nil {
		t.Fatalf("TaskSnapshot.Validate returned error: %v", err)
	}
	task.Assignment.AcceptedTaskHash = nil
	if err := task.Validate(); err == nil {
		t.Fatalf("TaskSnapshot.Validate error = nil, want missing accepted task hash")
	}
	task.Assignment.AcceptedTaskHash = ProtoBytes32(make([]byte, 32))
	task.Assignment.ModelID = ""
	if err := task.Validate(); err == nil {
		t.Fatalf("TaskSnapshot.Validate error = nil, want missing model")
	}
}

package builderclient

import (
	"encoding/hex"
	"encoding/json"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/wirevectors"
	"strings"
	"testing"
)

type taskDataGoldenField struct {
	Name    string                `json:"name"`
	Type    string                `json:"type"`
	Hex     string                `json:"hex"`
	UTF8    string                `json:"utf8"`
	Bech32  string                `json:"bech32"`
	Value   uint64                `json:"value"`
	Present bool                  `json:"present"`
	Fields  []taskDataGoldenField `json:"fields"`
}
type taskDataGolden struct {
	Name   string                `json:"name"`
	Domain string                `json:"domain"`
	Fields []taskDataGoldenField `json:"fields"`
	Digest string                `json:"digest_hex"`
}

func goldenField(t *testing.T, fields []taskDataGoldenField, name string) taskDataGoldenField {
	t.Helper()
	for _, field := range fields {
		if field.Name == name {
			return field
		}
	}
	t.Fatalf("missing field %s", name)
	return taskDataGoldenField{}
}
func goldenKey(t *testing.T, field taskDataGoldenField) TaskDataKey {
	t.Helper()
	f := func(name string) taskDataGoldenField { return goldenField(t, field.Fields, name) }
	operator := ""
	optional := f("producer_operator")
	if optional.Present {
		operator = goldenAddress(t, goldenField(t, optional.Fields, "value"))
	}
	return TaskDataKey{TaskHash: f("task_hash").Hex, SessionID: f("session_id").Hex, TaskID: f("task_id").Hex, Kind: DataKind(f("object_kind").Value), ContentHash: f("content_hash").Hex, EvidenceProducerKind: EvidenceProducerKind(f("evidence_producer_kind").Value), VerifyRound: uint32(f("verify_round").Value), ProducerOperator: operator}
}
func loadTaskDataGoldens(t *testing.T, path string) []taskDataGolden {
	t.Helper()
	raw, err := wirevectors.File(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []taskDataGolden `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	return file.Vectors
}

func TestTaskDataV040PublishedAuthenticationDigests(t *testing.T) {
	for _, v := range loadTaskDataGoldens(t, "task/task_data_auth_v1.json") {
		t.Run(v.Name, func(t *testing.T) {
			f := func(name string) taskDataGoldenField { return goldenField(t, v.Fields, name) }
			var got codec.Hash
			var err error
			switch v.Domain {
			case "TRUEOPEN_TASK_DATA_UPLOAD_BODY_V1":
				got, err = TaskDataUploadBodyDigest(goldenKey(t, f("object_ref")), f("size_bytes").Value, f("media_type").UTF8)
			case "TRUEOPEN_TASK_DATA_METADATA_BODY_V1":
				got, err = TaskDataMetadataBodyDigest(goldenKey(t, f("object_ref")))
			case "TRUEOPEN_TASK_DATA_FETCH_BODY_V1":
				rangeField := goldenField(t, f("range").Fields, "value")
				got, err = TaskDataFetchBodyDigest(goldenKey(t, f("object_ref")), &TaskDataRange{Offset: goldenField(t, rangeField.Fields, "offset").Value, Length: goldenField(t, rangeField.Fields, "length").Value})
			case "TRUEOPEN_TASK_DATA_FINALIZE_RESULT_BODY_V1":
				scope, e := finalizeScope(f("task_hash").Hex, f("session_id").Hex, f("task_id").Hex)
				if e != nil {
					t.Fatal(e)
				}
				got, err = taskDataFinalizeResultDigest(scope, mustHash(t, f("infer_receipt_hash").Hex), mustHash(t, f("infer_receipt_signature_digest").Hex))
			case "TRUEOPEN_TASK_DATA_FINALIZE_VERIFIER_BODY_V1":
				scope, e := finalizeScope(f("task_hash").Hex, f("session_id").Hex, f("task_id").Hex)
				if e != nil {
					t.Fatal(e)
				}
				operator, e := nodewire.CanonicalOperatorAddressBytes("verifier_operator", goldenAddress(t, f("verifier_operator")))
				if e != nil {
					t.Fatal(e)
				}
				got, err = taskDataFinalizeVerifierDigest(scope, uint32(f("verify_round").Value), operator, mustHash(t, f("result_receipt_signing_digest").Hex), mustHash(t, f("result_receipt_signature_digest").Hex))
			case "TRUEOPEN_TASK_DATA_REQUEST_V1":
				got, err = TaskDataRequestSigningHash(TaskDataRequestAuth{SchemaVersion: uint32(f("schema_version").Value), ChainID: f("chain_id").UTF8, BuilderAddress: goldenAddress(t, f("builder_operator_address")), Method: f("rpc_method").UTF8, BodyDigest: mustHash(t, f("body_digest").Hex), RequesterKind: TaskDataRequesterKind(f("requester_kind").Value), Requester: goldenAddress(t, f("requester_address")), ServiceAuthorizationNonce: f("service_authorization_nonce").Value, RequestNonce: mustDecodeHex(t, f("request_nonce").Hex), ExpiresAtHeight: f("expiry_height").Value})
			default:
				t.Fatalf("unhandled published domain %s", v.Domain)
			}
			assertHash(t, got, err, v.Digest)
		})
	}
}

func TestTaskDataV040PublishedStorageConfirmations(t *testing.T) {
	for _, v := range loadTaskDataGoldens(t, "task/builder_confirmation_v1.json") {
		t.Run(v.Name, func(t *testing.T) {
			f := func(name string) taskDataGoldenField { return goldenField(t, v.Fields, name) }
			got, err := StorageConfirmationSigningHash(StorageConfirmation{SchemaVersion: uint32(f("schema_version").Value), ChainID: f("chain_id").UTF8, BuilderOperator: goldenAddress(t, f("builder_operator_address")), ServiceAuthorizationNonce: f("service_authorization_nonce").Value, Key: goldenKey(t, f("object_ref")), SizeBytes: f("size_bytes").Value, ArtifactTotalSizeBytes: f("artifact_total_size_bytes").Value, RetentionUntilHeight: f("retention_until_height").Value})
			assertHash(t, got, err, v.Digest)
		})
	}
}

func TestObjectRefAndRangePresenceCannotBeConfused(t *testing.T) {
	key := TaskDataKey{TaskHash: strings.Repeat("11", 32), SessionID: strings.Repeat("22", 32), TaskID: strings.Repeat("33", 32), Kind: DataKindOutput, ContentHash: strings.Repeat("44", 32)}
	whole, err := TaskDataFetchBodyDigest(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	partial, err := TaskDataFetchBodyDigest(key, &TaskDataRange{Length: 1})
	if err != nil {
		t.Fatal(err)
	}
	if whole == partial {
		t.Fatal("range presence is not signed")
	}
	if _, err := TaskDataFetchBodyDigest(key, &TaskDataRange{}); err == nil {
		t.Fatal("present empty range accepted")
	}
	if _, err := TaskDataFetchBodyDigest(key, &TaskDataRange{Offset: ^uint64(0), Length: 1}); err == nil {
		t.Fatal("overflow accepted")
	}
	for name, mutate := range map[string]func(*TaskDataKey){
		"producer on output":        func(k *TaskDataKey) { k.EvidenceProducerKind = EvidenceProducerWorker },
		"round on output":           func(k *TaskDataKey) { k.VerifyRound = 1 },
		"missing evidence producer": func(k *TaskDataKey) { k.Kind = DataKindEvidenceArtifact },
		"uppercase hash":            func(k *TaskDataKey) { k.ContentHash = strings.Repeat("AA", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := key
			mutate(&bad)
			if err := ValidateTaskDataKey(bad); err == nil {
				t.Fatal("malformed object ref accepted")
			}
		})
	}
}

// wire v0.4.2 corrected the previously unverifiable Bech32 column on the
// c0..d3 raw address fields (task/task_data_auth_v1.json and
// task/builder_confirmation_v1.json) to trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe,
// with no digest change. The fixture's annotation is now well-formed, so it
// is verified like any other published address instead of being whitelisted
// as a known-malformed exception.
func goldenAddress(t *testing.T, field taskDataGoldenField) string {
	t.Helper()
	address := field.Bech32
	raw, err := nodewire.CanonicalOperatorAddressBytes(field.Name, address)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(raw) != field.Hex {
		t.Fatalf("address annotation does not match raw fixture bytes: %s", field.Name)
	}
	return address
}

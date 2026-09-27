package builderclient

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/wirevectors"
)

type v2Node struct {
	Name    string          `json:"name"`
	Value   json.RawMessage `json:"value"`
	UTF8    string          `json:"utf8"`
	Hex     string          `json:"hex"`
	Bech32  string          `json:"bech32"`
	Present *bool           `json:"present"`
	Fields  []v2Node        `json:"fields"`
}

type v2Vector struct {
	Name      string   `json:"name"`
	Domain    string   `json:"domain"`
	Fields    []v2Node `json:"fields"`
	DigestHex string   `json:"digest_hex"`
	Mutations []struct {
		FieldPath string `json:"field_path"`
		DigestHex string `json:"digest_hex"`
	} `json:"mutations"`
}

func v2Vectors(t *testing.T, path string) map[string]v2Vector {
	t.Helper()
	data, err := wirevectors.PrereleaseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []v2Vector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	out := make(map[string]v2Vector, len(file.Vectors))
	for _, v := range file.Vectors {
		out[v.Name] = v
	}
	return out
}

// field returns the named field at index, asserting the published order.
func v2Field(t *testing.T, fields []v2Node, index int, name string) v2Node {
	t.Helper()
	if index >= len(fields) || fields[index].Name != name {
		t.Fatalf("field %d is not %q", index, name)
	}
	return fields[index]
}

func (n v2Node) u64(t *testing.T) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(string(n.Value), 10, 64)
	if err != nil {
		t.Fatalf("%s: %v", n.Name, err)
	}
	return v
}

func (n v2Node) digest(t *testing.T) codec.Hash {
	t.Helper()
	raw, err := hex.DecodeString(n.Hex)
	if err != nil || len(raw) != 32 {
		t.Fatalf("%s is not a Hash32", n.Name)
	}
	var h codec.Hash
	copy(h[:], raw)
	return h
}

// objectRef reads a nine-field TaskDataObjectRefV1 frame.
func objectRef(t *testing.T, ref v2Node) (TaskDataKey, nodewire.EvidenceKind) {
	t.Helper()
	f := ref.Fields
	if len(f) != 9 {
		t.Fatalf("object ref has %d fields, want 9", len(f))
	}
	key := TaskDataKey{
		TaskHash:             v2Field(t, f, 0, "task_hash").Hex,
		SessionID:            v2Field(t, f, 1, "session_id").Hex,
		TaskID:               v2Field(t, f, 2, "task_id").Hex,
		Kind:                 DataKind(v2Field(t, f, 3, "object_kind").u64(t)),
		ContentHash:          v2Field(t, f, 4, "content_hash").Hex,
		EvidenceProducerKind: EvidenceProducerKind(v2Field(t, f, 5, "evidence_producer_kind").u64(t)),
		VerifyRound:          uint32(v2Field(t, f, 6, "verify_round").u64(t)),
	}
	if operator := v2Field(t, f, 7, "producer_operator"); operator.Present != nil && *operator.Present {
		key.ProducerOperator = operator.Fields[0].Bech32
	}
	return key, nodewire.EvidenceKind(v2Field(t, f, 8, "evidence_kind").u64(t))
}

func assertDigest(t *testing.T, name string, got codec.Hash, err error, want string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("%s = %x, published %s", name, got, want)
	}
}

func TestTaskDataBodiesV2ReproducePublishedVectors(t *testing.T) {
	vectors := v2Vectors(t, "task/task_data_auth_v1.json")

	upload := vectors["task_data_upload_body_v2"]
	key, kind := objectRef(t, v2Field(t, upload.Fields, 0, "object_ref"))
	size := v2Field(t, upload.Fields, 1, "size_bytes").u64(t)
	media := v2Field(t, upload.Fields, 2, "media_type").UTF8
	uploadDigest, err := TaskDataUploadBodyDigestV2(key, kind, size, media)
	assertDigest(t, upload.Name, uploadDigest, err, upload.DigestHex)
	for _, m := range upload.Mutations {
		if m.FieldPath == "object_ref.evidence_kind" {
			// The +1 mutation is not a legal kind for a Verifier bundle, so it
			// is refused rather than hashed.
			if _, err := TaskDataUploadBodyDigestV2(key, kind+1, size, media); err == nil {
				t.Fatal("a Verifier bundle accepted a non-Verifier evidence kind")
			}
		}
	}

	metadata := vectors["task_data_metadata_body_v2"]
	key, kind = objectRef(t, v2Field(t, metadata.Fields, 0, "object_ref"))
	got, err := TaskDataMetadataBodyDigestV2(key, kind)
	assertDigest(t, metadata.Name, got, err, metadata.DigestHex)
	if _, err := TaskDataMetadataBodyDigestV2(key, nodewire.EvidenceKindWorkerValueOpening); err == nil {
		t.Fatal("an OUTPUT object accepted an evidence kind")
	}

	fetch := vectors["task_data_fetch_body_v2"]
	key, kind = objectRef(t, v2Field(t, fetch.Fields, 0, "object_ref"))
	bounds := v2Field(t, fetch.Fields, 1, "range").Fields[0].Fields
	got, err = TaskDataFetchBodyDigestV2(key, kind, &TaskDataRange{
		Offset: v2Field(t, bounds, 0, "offset").u64(t), Length: v2Field(t, bounds, 1, "length").u64(t),
	})
	assertDigest(t, fetch.Name, got, err, fetch.DigestHex)

	result := vectors["task_data_finalize_result_body_v2"]
	f := result.Fields
	resultKind := nodewire.EvidenceKind(v2Field(t, f, 5, "evidence_kind").u64(t))
	got, err = TaskDataFinalizeResultBodyDigestV2(v2Field(t, f, 0, "task_hash").Hex, v2Field(t, f, 1, "session_id").Hex, v2Field(t, f, 2, "task_id").Hex,
		v2Field(t, f, 3, "infer_receipt_hash").digest(t), v2Field(t, f, 4, "infer_receipt_signature_digest").digest(t), resultKind)
	assertDigest(t, result.Name, got, err, result.DigestHex)
	for _, m := range result.Mutations {
		if m.FieldPath == "evidence_kind" {
			// kind 1 + 1 is VERIFIER_VALUE_OPENING, which a result finalize refuses.
			if _, err := TaskDataFinalizeResultBodyDigestV2(v2Field(t, f, 0, "task_hash").Hex, v2Field(t, f, 1, "session_id").Hex, v2Field(t, f, 2, "task_id").Hex,
				v2Field(t, f, 3, "infer_receipt_hash").digest(t), v2Field(t, f, 4, "infer_receipt_signature_digest").digest(t), resultKind+1); err == nil {
				t.Fatal("a result finalize accepted a non-Worker evidence kind")
			}
		}
	}

	verifier := vectors["task_data_finalize_verifier_body_v2"]
	f = verifier.Fields
	got, err = TaskDataFinalizeVerifierBodyDigestV2(v2Field(t, f, 0, "task_hash").Hex, v2Field(t, f, 1, "session_id").Hex, v2Field(t, f, 2, "task_id").Hex,
		uint32(v2Field(t, f, 3, "verify_round").u64(t)), v2Field(t, f, 4, "verifier_operator").Bech32,
		v2Field(t, f, 5, "result_receipt_signing_digest").digest(t), v2Field(t, f, 6, "result_receipt_signature_digest").digest(t))
	assertDigest(t, verifier.Name, got, err, verifier.DigestHex)

	// The request signature binds the V2 upload digest; the request domain
	// itself is unchanged.
	request := vectors["task_data_request_v1_cortex_service"]
	f = request.Fields
	if v2Field(t, f, 4, "body_digest").Hex != hex.EncodeToString(uploadDigest[:]) {
		t.Fatal("the request vector does not bind the V2 upload body digest")
	}
	nonce, _ := hex.DecodeString(v2Field(t, f, 8, "request_nonce").Hex)
	got, err = TaskDataRequestSigningHash(TaskDataRequestAuth{
		SchemaVersion: uint32(v2Field(t, f, 0, "schema_version").u64(t)), ChainID: v2Field(t, f, 1, "chain_id").UTF8,
		BuilderAddress: v2Field(t, f, 2, "builder_operator_address").Bech32, Method: v2Field(t, f, 3, "rpc_method").UTF8,
		BodyDigest: uploadDigest, RequesterKind: TaskDataRequesterKind(v2Field(t, f, 5, "requester_kind").u64(t)),
		Requester: v2Field(t, f, 6, "requester_address").Bech32, ServiceAuthorizationNonce: v2Field(t, f, 7, "service_authorization_nonce").u64(t),
		RequestNonce: nonce, ExpiresAtHeight: v2Field(t, f, 9, "expiry_height").u64(t),
	})
	assertDigest(t, request.Name, got, err, request.DigestHex)
}

func TestStorageConfirmationV2ReproducesPublishedVectors(t *testing.T) {
	vectors := v2Vectors(t, "task/builder_confirmation_v1.json")
	if len(vectors) != 5 {
		t.Fatalf("builder_confirmation_v1.json publishes %d vectors, want 5", len(vectors))
	}
	kinds := map[nodewire.EvidenceKind]bool{}
	for name, v := range vectors {
		f := v.Fields
		if v.Domain != storageConfirmationDomainV2 || len(f) != 8 {
			t.Fatalf("%s is not an eight-field %s vector", name, storageConfirmationDomainV2)
		}
		key, kind := objectRef(t, v2Field(t, f, 4, "object_ref"))
		kinds[kind] = true
		confirmation := StorageConfirmation{
			SchemaVersion:             uint32(v2Field(t, f, 0, "schema_version").u64(t)),
			ChainID:                   v2Field(t, f, 1, "chain_id").UTF8,
			BuilderOperator:           v2Field(t, f, 2, "builder_operator_address").Bech32,
			ServiceAuthorizationNonce: v2Field(t, f, 3, "service_authorization_nonce").u64(t),
			Key:                       key,
			SizeBytes:                 v2Field(t, f, 5, "size_bytes").u64(t),
			ArtifactTotalSizeBytes:    v2Field(t, f, 6, "artifact_total_size_bytes").u64(t),
			RetentionUntilHeight:      v2Field(t, f, 7, "retention_until_height").u64(t),
		}
		got, err := StorageConfirmationSigningHashV2(confirmation, kind)
		assertDigest(t, name, got, err, v.DigestHex)
	}
	// INPUT/OUTPUT, Verifier, and both Worker levels are all covered.
	for _, kind := range []nodewire.EvidenceKind{nodewire.EvidenceKindUnspecified, nodewire.EvidenceKindWorkerValueOpening,
		nodewire.EvidenceKindVerifierValueOpening, nodewire.EvidenceKindWorkerTokenOpening} {
		if !kinds[kind] {
			t.Fatalf("no confirmation vector covers evidence kind %d", kind)
		}
	}
	token := vectors["builder_confirmation_worker_token_evidence"]
	key, _ := objectRef(t, v2Field(t, token.Fields, 4, "object_ref"))
	if _, err := StorageConfirmationSigningHashV2(StorageConfirmation{
		SchemaVersion: 1, ChainID: "c", BuilderOperator: v2Field(t, token.Fields, 2, "builder_operator_address").Bech32,
		ServiceAuthorizationNonce: 1, Key: key, RetentionUntilHeight: 1,
	}, nodewire.EvidenceKindVerifierValueOpening); err == nil {
		t.Fatal("a Worker bundle confirmation accepted VERIFIER_VALUE_OPENING")
	}
}

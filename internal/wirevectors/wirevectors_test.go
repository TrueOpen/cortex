package wirevectors

import (
	"strings"
	"testing"
)

func TestEmbeddedHubVectorsAreWireVerbatim(t *testing.T) {
	if err := VerifyProvenance(); err != nil {
		t.Fatalf("VerifyProvenance: %v", err)
	}
}

// The four domains this repository derives itself. A vector that disappears
// upstream has to fail here rather than in whichever package quietly stopped
// being checked.
func TestEveryDerivedHubDomainHasAPublishedVector(t *testing.T) {
	for _, domain := range []string{
		"TRUEOPEN_EVIDENCE_SCHEMA_V1",
		"TRUEOPEN_DAILY_SUPPORT_CONFIRMATION_V1",
		"TRUEOPEN_PROFILE_VERIFICATION_SNAPSHOT_V1",
	} {
		vector, err := HubDomain(domain)
		if err != nil {
			t.Fatalf("HubDomain(%s): %v", domain, err)
		}
		if vector.Framing != "H_FIELDS_V1" || vector.PreimageHex == "" {
			t.Fatalf("%s vector = %#v, want an H_FIELDS_V1 vector with a preimage", domain, vector)
		}
	}
}

func TestHubDomainRefusesAnUnpublishedDomain(t *testing.T) {
	if _, err := HubDomain("TRUEOPEN_NOT_A_DOMAIN_V1"); err == nil {
		t.Fatal("HubDomain() error = nil, want a refusal for an unpublished domain")
	}
}

// Every 916e393 file this repository derives must be registered in the
// release manifest.
func TestReleasedVectorsMatchTheirManifest(t *testing.T) {
	for _, path := range []string{
		"task/worker_token_commitment_v1.json",
		"task/worker_value_commitment_v3.json",
		"task/worker_value_leaf_v1.json",
		"task/verifier_value_leaf_v1.json",
		"task/infer_receipt_v3.json",
		"task/result_receipt_v3.json",
		"task/metric_leaf_v3.json",
		"task/result_metric_v3.json",
		"task/task_order_v3.json",
		"task/output_stream_header_v1.json",
		"task/task_data_auth_v1.json",
		"task/builder_confirmation_v1.json",
		"task/canonical_json_v1.json",
		"task/task_domains_v1.json",
		"task/dispatch_v1.json",
		"hub/model_id_v1.json",
		"hub/model_manifest_v4.json",
		"hub/model_profile_canonical_v3.json",
		"hub/manifest_uri_v1.json",
	} {
		if _, err := File(path); err != nil {
			t.Fatalf("File(%s): %v", path, err)
		}
	}
	if _, err := File("task/infer_receipt_v2.json"); err == nil {
		t.Fatal("File() error = nil for a file wire 916e393 does not publish")
	}
}

// The fixture manifest is served only when it matches its pinned checksum,
// like every file it lists.
func TestManifestIsServedOnlyWithItsPinnedChecksum(t *testing.T) {
	if _, err := releasedSet.file("manifest.json"); err != nil {
		t.Fatalf("pinned manifest: %v", err)
	}
	tampered := releasedSet
	tampered.manifestSum = strings.Repeat("0", 64)
	if _, err := tampered.file("manifest.json"); err == nil {
		t.Fatal("a manifest that does not match its pinned checksum was served")
	}
}

func TestDispatchVectorsLoadSignedRows(t *testing.T) {
	rows, err := DispatchVectors()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"task_v1_dispatchticketv1": false, "task_v1_standinghandraisev1": false, "nexus_v1_dispatchstreambindingv1": false}
	for _, r := range rows {
		if r.MessageName == "" || r.ProtobufHex == "" {
			t.Fatalf("row %s carries no protobuf message", r.Name)
		}
		if _, ok := want[r.Name]; ok {
			want[r.Name] = r.DigestHex != "" && r.SignatureHex != "" && r.PublicKeyHex != ""
		}
	}
	for name, ok := range want {
		if !ok {
			t.Fatalf("vector %s missing or incomplete", name)
		}
	}
}

func TestParseDispatchVectorsRefusesHalfPopulatedRows(t *testing.T) {
	for name, doc := range map[string]string{
		"name without bytes": `{"vectors":[{"name":"a","message_name":"task.v1.X","digest_hex":"00"}]}`,
		"bytes without name": `{"vectors":[{"name":"a","protobuf_hex":"08","digest_hex":"00"}]}`,
	} {
		if _, err := parseDispatchVectors([]byte(doc)); err == nil {
			t.Fatalf("%s: half-populated row accepted", name)
		}
	}
	rows, err := parseDispatchVectors([]byte(`{"vectors":[{"name":"d","digest_hex":"00"},{"name":"m","message_name":"task.v1.X","protobuf_hex":"08"}]}`))
	if err != nil || len(rows) != 1 || rows[0].Name != "m" {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
}

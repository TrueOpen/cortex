package wirevectors

import "testing"

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

// Every v0.3.2 file this repository derives must be registered in the
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
		t.Fatal("File() error = nil for a file wire v0.3.2 does not publish")
	}
}

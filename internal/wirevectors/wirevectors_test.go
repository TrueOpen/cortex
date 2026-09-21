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
		"TRUEOPEN_SUPPORT_PROFILES_V1",
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

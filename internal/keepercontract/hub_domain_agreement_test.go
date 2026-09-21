package keepercontract

import (
	"encoding/hex"
	"testing"

	"github.com/SingaXYZ/cortex/internal/txclient"
	"github.com/SingaXYZ/cortex/internal/wirevectors"
)

// wireHubFixtureProfiles are the two profiles wire's support_profiles_v1 and
// daily_support_confirmation_v1 vectors frame, in the frozen order.
func wireHubFixtureProfiles() []ProfileRef {
	return []ProfileRef{
		{ModelID: "model-fixture-a", ProfileVersion: 1},
		{ModelID: "model-fixture-b", ProfileVersion: 2},
	}
}

// wireHubFixtureOperator is the Bech32 spelling of the 20 account bytes
// a1a2…b4 that wire's vectors frame. The vectors frame address-codec bytes, not
// Bech32 text, which is why the production helper decodes before framing.
const wireHubFixtureOperator = "trueopen15x328f9956n632d24wk2mt40kzcm9va5vw5e0a"

// TestSupportProfilesHashAgreesWithWireVector drives the production digest with
// the inputs wire's own vector declares and compares against the digest wire
// publishes. Every other test in this package signs and verifies with the same
// function and would stay green through a total drift; this one would not.
//
// It is the test that caught the drift it now guards: the repeated profile list
// was flattened into the outer field list instead of being wrapped in one
// nested frame carrying its own element_count.
func TestSupportProfilesHashAgreesWithWireVector(t *testing.T) {
	vector, err := wirevectors.HubDomain(DomainSupportProfiles)
	if err != nil {
		t.Fatalf("wire vector: %v", err)
	}
	got, err := SupportedProfilesHash(wireHubFixtureProfiles())
	if err != nil {
		t.Fatalf("SupportedProfilesHash: %v", err)
	}
	if hex.EncodeToString(got[:]) != vector.DigestHex {
		t.Fatalf("%s = %s, wire %s publishes %s",
			DomainSupportProfiles, hex.EncodeToString(got[:]), wirevectors.WireVersion, vector.DigestHex)
	}
}

// DailySupportConfirmation is signed with the Keeper-confirmed ServiceKey, so a
// drift here produced a signature over a preimage the chain never derives.
func TestDailySupportConfirmationAgreesWithWireVector(t *testing.T) {
	vector, err := wirevectors.HubDomain(DomainDailySupportConfirmation)
	if err != nil {
		t.Fatalf("wire vector: %v", err)
	}
	got, err := DailySupportConfirmation(
		"trueopen-fixture-1", wireHubFixtureOperator,
		42, 7, 2000,
		wireHubFixtureProfiles(),
	)
	if err != nil {
		t.Fatalf("DailySupportConfirmation: %v", err)
	}
	if hex.EncodeToString(got[:]) != vector.DigestHex {
		t.Fatalf("%s = %s, wire %s publishes %s",
			DomainDailySupportConfirmation, hex.EncodeToString(got[:]), wirevectors.WireVersion, vector.DigestHex)
	}
}

// The generic Hub framing vector retains commitment schema 1; the current
// model-profile fixture separately pins commitment schema 2.
func TestEvidenceSchemaHashAgreesWithWireVector(t *testing.T) {
	vector, err := wirevectors.HubDomain(evidenceSchemaDomain)
	if err != nil {
		t.Fatalf("wire vector: %v", err)
	}
	profile := nodeGoldenModelProfileProjection()
	profile.VerificationProfile.EvidenceSchema.RequiredInferEvidence[0].CommitmentSchemaVersion = 1
	got, err := EvidenceSchemaHash(profile)
	if err != nil {
		t.Fatalf("EvidenceSchemaHash: %v", err)
	}
	if hex.EncodeToString(got[:]) != vector.DigestHex {
		t.Fatalf("%s = %s, wire %s publishes %s",
			evidenceSchemaDomain, hex.EncodeToString(got[:]), wirevectors.WireVersion, vector.DigestHex)
	}
}

// A second profile with a different requirement set, so the agreement above
// cannot be satisfied by a framing that happens to be right for one element.
func TestEvidenceSchemaHashDistinguishesRequirementSets(t *testing.T) {
	base := nodeGoldenModelProfileProjection()
	first, err := EvidenceSchemaHash(base)
	if err != nil {
		t.Fatalf("EvidenceSchemaHash: %v", err)
	}
	changed := base
	changed.VerificationProfile.EvidenceSchema = txclient.WorkerValueEvidenceSchemaV2(1 << 20)
	second, err := EvidenceSchemaHash(changed)
	if err != nil {
		t.Fatalf("EvidenceSchemaHash(changed): %v", err)
	}
	if first == second {
		t.Fatal("evidence schema hash did not bind max_encoded_size_bytes")
	}
}

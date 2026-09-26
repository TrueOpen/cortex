package keepercontract

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/txclient"
	"github.com/TrueOpen/cortex/internal/wirevectors"
)

// wireHubFixtureModels are the two model ids wire's support_models_v1 and
// daily_support_confirmation_v1 vectors frame, in the frozen order.
func wireHubFixtureModels() []string {
	return []string{strings.Repeat("01", 32), strings.Repeat("02", 32)}
}

// wireHubFixtureOperator is the Bech32 spelling of the 20 account bytes
// a1a2…b4 that wire's vectors frame. The vectors frame address-codec bytes, not
// Bech32 text, which is why the production helper decodes before framing.
const wireHubFixtureOperator = "trueopen15x328f9956n632d24wk2mt40kzcm9va5vw5e0a"

// TestSupportModelsHashAgreesWithWireVector drives the production digest with
// the inputs wire's own vector declares and compares against the digest wire
// publishes. Every other test in this package signs and verifies with the same
// function and would stay green through a total drift; this one would not.
//
// The repeated model list is one nested frame carrying its own element_count.
func TestSupportModelsHashAgreesWithWireVector(t *testing.T) {
	vector, err := wirevectors.HubDomain(DomainSupportModels)
	if err != nil {
		t.Fatalf("wire vector: %v", err)
	}
	got, err := SupportedModelsHash(wireHubFixtureModels())
	if err != nil {
		t.Fatalf("SupportedModelsHash: %v", err)
	}
	if hex.EncodeToString(got[:]) != vector.DigestHex {
		t.Fatalf("%s = %s, wire %s publishes %s",
			DomainSupportModels, hex.EncodeToString(got[:]), wirevectors.WireVersion, vector.DigestHex)
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
		wireHubFixtureModels(),
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
	changed.VerificationProfile.EvidenceSchema = txclient.WorkerEvidenceSchemaV3(1<<20, 1<<20)
	second, err := EvidenceSchemaHash(changed)
	if err != nil {
		t.Fatalf("EvidenceSchemaHash(changed): %v", err)
	}
	if first == second {
		t.Fatal("evidence schema hash did not bind max_encoded_size_bytes")
	}
}

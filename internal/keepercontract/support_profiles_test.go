package keepercontract

import (
	"reflect"
	"strings"
	"testing"
)

// Node orders supported profiles by model_id and then by the numeric
// profile_version (validateCanonicalSupportedProfiles). Comparing the decimal
// text instead would put "10" before "2", so a list the chain accepts would be
// refused here and a list the chain refuses would be signed.
func TestSupportedProfilesOrderProfileVersionsNumerically(t *testing.T) {
	ascending := []ProfileRef{{ModelID: "model-a", ProfileVersion: 2}, {ModelID: "model-a", ProfileVersion: 10}}
	if _, err := SupportedProfilesHash(ascending); err != nil {
		t.Fatalf("SupportedProfilesHash(v2, v10) error = %v, want accepted", err)
	}
	if _, err := DailySupportConfirmation("chain-1", wireHubFixtureOperator, 1, 1, 10, ascending); err != nil {
		t.Fatalf("DailySupportConfirmation(v2, v10) error = %v, want accepted", err)
	}

	descending := []ProfileRef{{ModelID: "model-a", ProfileVersion: 10}, {ModelID: "model-a", ProfileVersion: 2}}
	if _, err := SupportedProfilesHash(descending); err == nil {
		t.Fatal("SupportedProfilesHash(v10, v2) error = nil, want ordering rejection")
	}
}

func TestSupportedProfilesOrderModelIDsBeforeVersions(t *testing.T) {
	ordered := []ProfileRef{{ModelID: "model-a", ProfileVersion: 9}, {ModelID: "model-b", ProfileVersion: 1}}
	if _, err := SupportedProfilesHash(ordered); err != nil {
		t.Fatalf("SupportedProfilesHash(a@9, b@1) error = %v, want accepted", err)
	}
	// "model" is a prefix of "model-a", so it sorts first regardless of version.
	prefixed := []ProfileRef{{ModelID: "model", ProfileVersion: 5}, {ModelID: "model-a", ProfileVersion: 1}}
	if _, err := SupportedProfilesHash(prefixed); err != nil {
		t.Fatalf("SupportedProfilesHash(model@5, model-a@1) error = %v, want accepted", err)
	}
}

func TestCanonicalProfileRefsSortsIntoNodeOrder(t *testing.T) {
	input := []ProfileRef{
		{ModelID: "model-b", ProfileVersion: 1},
		{ModelID: "model-a", ProfileVersion: 10},
		{ModelID: "model-a", ProfileVersion: 2},
	}
	got, err := CanonicalProfileRefs(input)
	if err != nil {
		t.Fatalf("CanonicalProfileRefs error = %v", err)
	}
	want := []ProfileRef{
		{ModelID: "model-a", ProfileVersion: 2},
		{ModelID: "model-a", ProfileVersion: 10},
		{ModelID: "model-b", ProfileVersion: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CanonicalProfileRefs = %#v, want %#v", got, want)
	}
	if input[0].ModelID != "model-b" {
		t.Fatalf("CanonicalProfileRefs reordered its input: %#v", input)
	}
	if _, err := SupportedProfilesHash(got); err != nil {
		t.Fatalf("canonical list refused by SupportedProfilesHash: %v", err)
	}
}

func TestCanonicalProfileRefsRejectsInvalidSets(t *testing.T) {
	cases := map[string][]ProfileRef{
		"empty":              nil,
		"duplicate":          {{ModelID: "model-a", ProfileVersion: 1}, {ModelID: "model-a", ProfileVersion: 1}},
		"missing model id":   {{ModelID: "", ProfileVersion: 1}},
		"zero version":       {{ModelID: "model-a", ProfileVersion: 0}},
		"untrimmed model id": {{ModelID: " model-a", ProfileVersion: 1}},
	}
	for name, profiles := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := CanonicalProfileRefs(profiles)
			if err == nil {
				t.Fatalf("CanonicalProfileRefs(%#v) error = nil", profiles)
			}
			if name == "duplicate" && !strings.Contains(err.Error(), "duplicate") {
				t.Fatalf("CanonicalProfileRefs duplicate error = %v, want it named", err)
			}
		})
	}
}

package keepercontract

import (
	"reflect"
	"strings"
	"testing"
)

func TestCanonicalModelIDsSortsAndRefusesInvalidSets(t *testing.T) {
	a, b := strings.Repeat("01", 32), strings.Repeat("02", 32)
	got, err := CanonicalModelIDs([]string{b, a})
	if err != nil || !reflect.DeepEqual(got, []string{a, b}) {
		t.Fatalf("CanonicalModelIDs = %v, %v", got, err)
	}
	for name, ids := range map[string][]string{
		"empty":     nil,
		"duplicate": {a, a},
		"uppercase": {strings.Repeat("AB", 32)},
		"not hex":   {"model-a"},
		"prefixed":  {"0x" + a},
	} {
		if _, err := CanonicalModelIDs(ids); err == nil {
			t.Errorf("%s: CanonicalModelIDs accepted %v", name, ids)
		}
	}
	if _, err := SupportedModelsHash([]string{b, a}); err == nil {
		t.Fatal("SupportedModelsHash accepted a descending list")
	}
}

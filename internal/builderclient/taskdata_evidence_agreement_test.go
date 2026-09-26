package builderclient

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/wirevectors"
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

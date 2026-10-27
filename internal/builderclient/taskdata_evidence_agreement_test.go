package builderclient

import (
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

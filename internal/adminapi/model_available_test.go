package adminapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

type fakeChainModelReader struct {
	models  []chainclient.CurrentModelSnapshot
	support map[string]chainclient.ModelSupportSnapshot
	errs    map[string]error
	reads   *int
}

func (f fakeChainModelReader) Models(context.Context) ([]chainclient.CurrentModelSnapshot, error) {
	return f.models, nil
}

func (f fakeChainModelReader) ModelSupport(_ context.Context, operator, modelID string) (chainclient.ModelSupportSnapshot, error) {
	if f.reads != nil {
		*f.reads++
	}
	if err := f.errs[modelID]; err != nil {
		return chainclient.ModelSupportSnapshot{}, err
	}
	if row, ok := f.support[modelID]; ok && row.OperatorAddress == operator {
		return row, nil
	}
	return chainclient.ModelSupportSnapshot{}, chainclient.ErrNotFound
}

func availableTestReader() (fakeChainModelReader, [3]string) {
	ids := [3]string{strings.Repeat("b2", 32), strings.Repeat("a6", 32), strings.Repeat("6d", 32)}
	return fakeChainModelReader{
		models: []chainclient.CurrentModelSnapshot{
			{ModelID: ids[0], Provider: "HUGGINGFACE", RepoID: "Qwen/Qwen3.8-27B-FP8", Status: "REGISTERED", LatestProfileVersion: chainclient.NewProfileVersion(1)},
			{ModelID: ids[1], Provider: "HUGGINGFACE", RepoID: "Qwen/Qwen3-8B", Status: "ACTIVE", LatestProfileVersion: chainclient.NewProfileVersion(2), ActiveSupporterCount: 4},
			{ModelID: ids[2], Provider: "HUGGINGFACE", RepoID: "trueopen/golden-model", Status: "ACTIVE", LatestProfileVersion: chainclient.NewProfileVersion(1)},
		},
		support: map[string]chainclient.ModelSupportSnapshot{
			ids[0]: {OperatorAddress: "trueopen1me", ModelID: ids[0], DeclaredSupport: true},
			ids[1]: {OperatorAddress: "trueopen1me", ModelID: ids[1], DeclaredSupport: true, SupportActive: true},
		},
	}, ids
}

func TestListAvailableModelsJoinsOperatorSupport(t *testing.T) {
	reader, ids := availableTestReader()
	got, err := ListAvailableModels(context.Background(), "trueopen1me", reader)
	if err != nil {
		t.Fatal(err)
	}
	if got.OperatorAddress != "trueopen1me" || len(got.Models) != 3 {
		t.Fatalf("response = %+v", got)
	}
	// No support row is "not supported", not an error.
	for i, want := range [][2]bool{{true, false}, {true, true}, {false, false}} {
		row := got.Models[i]
		if row.ModelID != ids[i] || row.Supported == nil || row.SupportActive == nil || *row.Supported != want[0] || *row.SupportActive != want[1] {
			t.Fatalf("models[%d] = %+v, want supported=%v active=%v", i, row, want[0], want[1])
		}
	}
	if got.Models[1].LatestProfileVersion != 2 || got.Models[1].ActiveSupporterCount != 4 || got.Models[1].RepoID != "Qwen/Qwen3-8B" {
		t.Fatalf("models[1] chain fields = %+v", got.Models[1])
	}
}

// Without an operator there is nobody's support to read: the support fields
// stay absent and no support query is made.
func TestListAvailableModelsWithoutOperatorSkipsSupport(t *testing.T) {
	reader, _ := availableTestReader()
	reads := 0
	reader.reads = &reads
	got, err := ListAvailableModels(context.Background(), " ", reader)
	if err != nil {
		t.Fatal(err)
	}
	if reads != 0 || got.OperatorAddress != "" || len(got.Models) != 3 {
		t.Fatalf("reads = %d, response = %+v", reads, got)
	}
	for i, row := range got.Models {
		if row.Supported != nil || row.SupportActive != nil {
			t.Fatalf("models[%d] carries support without an operator: %+v", i, row)
		}
	}
	table := formatTable(got)
	if !strings.Contains(table, "Qwen/Qwen3-8B\tACTIVE\t2\t4\t-\t-\n") {
		t.Fatalf("table %q does not render absent support as -", table)
	}
}

// A support read that fails for any reason other than "no row" must fail the
// listing: reporting the model as unsupported would be a guess.
func TestListAvailableModelsFailsOnSupportReadError(t *testing.T) {
	reader, ids := availableTestReader()
	reader.errs = map[string]error{ids[1]: errors.New("rpc unavailable")}
	if _, err := ListAvailableModels(context.Background(), "trueopen1me", reader); err == nil || !strings.Contains(err.Error(), "rpc unavailable") {
		t.Fatalf("err = %v, want the support read error", err)
	}
}

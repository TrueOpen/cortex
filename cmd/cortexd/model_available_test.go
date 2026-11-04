package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/adminapi"
	"github.com/TrueOpen/cortex/internal/chainclient"
)

type fakeChainModelReader struct {
	models  []chainclient.CurrentModelSnapshot
	support map[string]chainclient.ModelSupportSnapshot
	errs    map[string]error
}

func (f fakeChainModelReader) Models(context.Context) ([]chainclient.CurrentModelSnapshot, error) {
	return f.models, nil
}

func (f fakeChainModelReader) ModelSupport(_ context.Context, operator, modelID string) (chainclient.ModelSupportSnapshot, error) {
	if err := f.errs[modelID]; err != nil {
		return chainclient.ModelSupportSnapshot{}, err
	}
	if row, ok := f.support[modelID]; ok && row.OperatorAddress == operator {
		return row, nil
	}
	return chainclient.ModelSupportSnapshot{}, chainclient.ErrNotFound
}

func TestListAvailableModelsJoinsOperatorSupport(t *testing.T) {
	declared, active, undeclared := strings.Repeat("b2", 32), strings.Repeat("a6", 32), strings.Repeat("6d", 32)
	reader := fakeChainModelReader{
		models: []chainclient.CurrentModelSnapshot{
			{ModelID: declared, Provider: "HUGGINGFACE", RepoID: "Qwen/Qwen3.8-27B-FP8", Status: "REGISTERED", LatestProfileVersion: chainclient.NewProfileVersion(1)},
			{ModelID: active, Provider: "HUGGINGFACE", RepoID: "Qwen/Qwen3-8B", Status: "ACTIVE", LatestProfileVersion: chainclient.NewProfileVersion(2), ActiveSupporterCount: 4},
			{ModelID: undeclared, Provider: "HUGGINGFACE", RepoID: "trueopen/golden-model", Status: "ACTIVE", LatestProfileVersion: chainclient.NewProfileVersion(1)},
		},
		support: map[string]chainclient.ModelSupportSnapshot{
			declared: {OperatorAddress: "trueopen1me", ModelID: declared, DeclaredSupport: true},
			active:   {OperatorAddress: "trueopen1me", ModelID: active, DeclaredSupport: true, SupportActive: true},
		},
	}
	got, err := listAvailableModels("trueopen1me", reader)(context.Background(), adminapi.ModelAvailableRequest{})
	if err != nil {
		t.Fatal(err)
	}
	want := []adminapi.ModelAvailableRow{
		{ModelID: declared, Provider: "HUGGINGFACE", RepoID: "Qwen/Qwen3.8-27B-FP8", Status: "REGISTERED", LatestProfileVersion: 1, Supported: true},
		{ModelID: active, Provider: "HUGGINGFACE", RepoID: "Qwen/Qwen3-8B", Status: "ACTIVE", LatestProfileVersion: 2, ActiveSupporterCount: 4, Supported: true, SupportActive: true},
		// No support row is "not supported", not an error.
		{ModelID: undeclared, Provider: "HUGGINGFACE", RepoID: "trueopen/golden-model", Status: "ACTIVE", LatestProfileVersion: 1},
	}
	if got.OperatorAddress != "trueopen1me" || len(got.Models) != len(want) {
		t.Fatalf("response = %+v", got)
	}
	for i := range want {
		if got.Models[i] != want[i] {
			t.Fatalf("models[%d] = %+v, want %+v", i, got.Models[i], want[i])
		}
	}
}

// A support read that fails for any reason other than "no row" must fail the
// listing: reporting the model as unsupported would be a guess.
func TestListAvailableModelsFailsOnSupportReadError(t *testing.T) {
	modelID := strings.Repeat("b2", 32)
	reader := fakeChainModelReader{
		models: []chainclient.CurrentModelSnapshot{{ModelID: modelID, Status: "REGISTERED", LatestProfileVersion: chainclient.NewProfileVersion(1)}},
		errs:   map[string]error{modelID: errors.New("rpc unavailable")},
	}
	if _, err := listAvailableModels("trueopen1me", reader)(context.Background(), adminapi.ModelAvailableRequest{}); err == nil || !strings.Contains(err.Error(), "rpc unavailable") {
		t.Fatalf("err = %v, want the support read error", err)
	}
}

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/modelservice"
)

const bindTestModelID = "c2e5065e9dda862ec6970d2c54765ad9414f22fe7ae82cf94dae6825828129c1"

// bindTestKeeper serves one ModelState, or an error.
type bindTestKeeper struct {
	model chainclient.CurrentModelSnapshot
	err   error
}

func (k bindTestKeeper) ChainHeight(context.Context) (uint64, error) { return 10, nil }
func (k bindTestKeeper) CurrentModel(context.Context, string) (chainclient.CurrentModelSnapshot, error) {
	return k.model, k.err
}

func bindTestModel(provider, repo string) chainclient.CurrentModelSnapshot {
	return chainclient.CurrentModelSnapshot{
		ModelID: bindTestModelID, ProposerAddress: "trueopen1proposer", Status: "ACTIVE", StatusSource: "AUTO_SUPPORT",
		LatestProfileVersion: chainclient.NewProfileVersion(1), CreatedHeight: chainclient.NewUint64String(1),
		UpdatedHeight: chainclient.NewUint64String(2), Provider: provider, RepoID: repo,
	}
}

// vllmServing is a vLLM stub that serves the given model names.
func vllmServing(t *testing.T, served ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			data := make([]map[string]string, 0, len(served))
			for _, name := range served {
				data = append(data, map[string]string{"id": name})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/metrics":
			_, _ = w.Write([]byte("vllm:num_requests_running 0\nvllm:num_requests_waiting 0\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Every way a configured model id can fail to bind is refused with a reason,
// and model_service readiness reports it red.
func TestBindLocalModelsRefusalsKeepModelServiceRed(t *testing.T) {
	for name, tc := range map[string]struct {
		keeper bindTestKeeper
		served []string
		ids    []string
		want   string
	}{
		"no model configured": {bindTestKeeper{model: bindTestModel("HUGGINGFACE", "org/model")}, []string{"org/model"}, nil, "no model id is configured"},
		"not registered":      {bindTestKeeper{err: errors.New("model not found")}, []string{"org/model"}, []string{bindTestModelID}, "query ModelState"},
		"invalid ModelState":  {bindTestKeeper{model: chainclient.CurrentModelSnapshot{ModelID: bindTestModelID}}, []string{"org/model"}, []string{bindTestModelID}, "required"},
		"answer for another id": {bindTestKeeper{model: func() chainclient.CurrentModelSnapshot {
			m := bindTestModel("HUGGINGFACE", "org/model")
			m.ModelID = strings.Repeat("ab", 32)
			return m
		}()}, []string{"org/model"}, []string{bindTestModelID}, "answered for model"},
		"not a HUGGINGFACE source": {bindTestKeeper{model: bindTestModel("OCI", "org/model")}, []string{"org/model"}, []string{bindTestModelID}, "source provider"},
		"repo not served":          {bindTestKeeper{model: bindTestModel("HUGGINGFACE", "org/model")}, []string{"org/other"}, []string{bindTestModelID}, "vLLM serves"},
	} {
		t.Run(name, func(t *testing.T) {
			local := modelservice.NewLocalService(vllmServing(t, tc.served...).URL, "local", 1, 0, 0)
			err := bindLocalModels(context.Background(), tc.keeper, local, tc.ids)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("bindLocalModels = %v, want a refusal containing %q", err, tc.want)
			}
			if len(tc.ids) == 0 {
				return
			}
			cfg := config.Config{LocalIdentity: config.LocalIdentityConfig{SupportedModelProfiles: []string{bindTestModelID + "@1=llm_text_v1"}, ModelServiceID: "local"}}
			rt := &Runtime{cfg: cfg, Dependencies: Dependencies{Keeper: tc.keeper, Model: local}}
			status := rt.checkModelServiceReadiness(context.Background())
			if status.Ready || !strings.Contains(status.Error, tc.want) {
				t.Fatalf("model_service readiness = %+v, want red with %q", status, tc.want)
			}
		})
	}
	// The bound, served model binds and a second bind to another repository is refused.
	local := modelservice.NewLocalService(vllmServing(t, "org/model").URL, "local", 1, 0, 0)
	if err := bindLocalModels(context.Background(), bindTestKeeper{model: bindTestModel("HUGGINGFACE", "org/model")}, local, []string{bindTestModelID}); err != nil {
		t.Fatalf("a served HUGGINGFACE model did not bind: %v", err)
	}
	if err := local.BindModel(bindTestModelID, modelservice.LocalModelProvider, "org/other"); err == nil {
		t.Fatal("a model id was rebound to another repository")
	}
}

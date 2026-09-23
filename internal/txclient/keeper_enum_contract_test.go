package txclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	"google.golang.org/protobuf/proto"
)

// TestKeeperEnumPrefixContract pins the enum handling that chainclient's typed
// projection boundary depends on.
//
// chainclient strips the prefix from the three Keeper *status* enums because
// handraise eligibility compares them bare. It deliberately does not strip the
// shared profile enums, because a decoded profile is copied straight back
// into a registration projection whose validator matches on the full value
// names. Normalizing every string in the Keeper response would therefore
// silently break model profile registration (and could corrupt identifiers).
//
// This test runs the whole pipeline that would break: protobuf response -> ABCI
// decode -> projection -> validation.
func TestKeeperEnumPrefixContract(t *testing.T) {
	server := newProfileABCIServer(t)
	defer server.Close()

	state, err := chainclient.NewKeeperABCIClient(server.URL).CurrentModelProfile(context.Background(), "hf/org/model", "7")
	if err != nil {
		t.Fatalf("CurrentModelProfile() error = %v", err)
	}

	// Status enums must arrive bare: handraise eligibility compares them
	// against "ACTIVE"/"REGISTERED".
	if state.Model.Status != "ACTIVE" || state.Profile.Status != "ACTIVE" {
		t.Fatalf("status = model %q profile %q, want bare enum values", state.Model.Status, state.Profile.Status)
	}

	// Profile enums remain their full protobuf value names. They are inputs to
	// local profile selection and canonical profile validation, not status
	// labels, so broad prefix stripping would change their meaning.
	if state.Profile.GenerationType != "GENERATION_TYPE_DETERMINISTIC" ||
		state.Profile.VerificationProfile.VerificationMode != "VERIFICATION_MODE_SINGLE_SAMPLE" ||
		state.Profile.VerificationProfile.TokenScope != "TOKEN_SCOPE_ALL_GENERATED_OUTPUT_TOKENS" ||
		state.Profile.VerificationProfile.Metrics.NumericScale != "NUMERIC_SCALE_FP_1E6" ||
		len(state.Profile.TaskTypes) != 1 || state.Profile.TaskTypes[0] != "TASK_TYPE_TEXT_GENERATION" {
		t.Fatalf("profile enum projection = generation=%q verification=%q token_scope=%q numeric_scale=%q task_types=%v",
			state.Profile.GenerationType, state.Profile.VerificationProfile.VerificationMode,
			state.Profile.VerificationProfile.TokenScope, state.Profile.VerificationProfile.Metrics.NumericScale,
			state.Profile.TaskTypes)
	}
}

func newProfileABCIServer(t testing.TB) *httptest.Server {
	t.Helper()
	bytes32 := make([]byte, 32)
	for i := range bytes32 {
		bytes32[i] = 0x5a
	}
	modelResponse := &hubv1.QueryModelResponse{Model: &hubv1.ModelState{
		ModelId: "hf/org/model", ProposerAddress: "trueopen1proposer",
		Status: hubv1.ModelProfileStatus_MODEL_PROFILE_STATUS_ACTIVE, ActiveProfileCount: 1,
		LatestProfileVersion: 7, StatusSource: hubv1.ModelStatusSource_MODEL_STATUS_SOURCE_AUTO_PROFILE,
		CreatedHeight: 40, UpdatedHeight: 41,
	}}
	profileResponse := &hubv1.QueryProfileResponse{Profile: &hubv1.ProfileState{
		ModelId: "hf/org/model", ProfileVersion: 7,
		ManifestHash: bytes32, TokenizerHash: bytes32, RuntimeClass: "CAUSAL_LM_PREFILL_LOGPROBS_V1",
		RequiredTopK: 20, TaskTypes: []sharedv1.TaskType{1}, GenerationType: 1,
		ResourceTier: 1, MinStake: 100, ChallengeOpenWindowBlocks: 1800,
		VerificationProfile: &sharedv1.VerificationProfile{
			VerificationProfileId: 1, JudgmentFunctionVersion: "PREFILL_GENERATED_TOKEN_METRICS_V1",
			VerificationMode: 1, TokenScope: 1,
			Metrics:                  &sharedv1.MetricSpec{ComparedTopK: 20, NumericScale: 1},
			CanonicalEncodingVersion: "CANONICAL_OUTPUT_TEXT_V1", EvidenceSchemaHash: bytes32,
			MetricAggregateProofVersion: "PREFILL_METRIC_AGGREGATE_PROOF_V1",
			EvidenceSchema: &sharedv1.EvidenceSchemaV1{
				SchemaVersion: 1,
				RequiredInferEvidence: []*sharedv1.InferEvidenceRequirementV1{{
					EvidenceKind: 1, CommitmentSchemaVersion: 1, MaxEncodedSizeBytes: 1 << 30,
				}},
			},
		},
		SchemaHash: bytes32, Status: 2, StatusSource: 1,
		ProposerAddress: "trueopen1proposer", RegistrationDigest: bytes32, PreviousProfileVersion: 6,
		RegistrationFeePaid: 20_000_000, CreatedHeight: 40, UpdatedHeight: 41,
	}}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/abci_info" {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": -1, "result": map[string]any{
				"response": map[string]any{"last_block_height": "10"},
			}})
			return
		}
		if r.URL.Path != "/abci_query" {
			http.NotFound(w, r)
			return
		}
		var response proto.Message
		switch strings.Trim(r.URL.Query().Get("path"), "\"") {
		case "/hub.v1.Query/Model":
			response = modelResponse
		case "/hub.v1.Query/Profile":
			response = profileResponse
		default:
			t.Fatalf("unexpected ABCI path %q", r.URL.Query().Get("path"))
		}
		payload, err := proto.Marshal(response)
		if err != nil {
			t.Fatalf("marshal ABCI response: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": -1,
			"result": map[string]any{"response": map[string]any{
				"code": 0, "log": "", "value": base64.StdEncoding.EncodeToString(payload), "height": "10",
			}},
		})
	}))
}

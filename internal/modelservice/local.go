package modelservice

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/metric"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

const (
	defaultVLLMBaseURL                  = "http://127.0.0.1:8000"
	defaultVLLMAPIKey                   = "EMPTY"
	defaultLocalSvcID                   = "local-model-service"
	defaultTopK                         = 16
	defaultTopP                         = 1.0
	defaultTopKSample                   = 0
	defaultSeed                         = 0
	missingLogprob                      = -100.0
	localVerifierID                     = "local-vllm-verifier-v1"
	defaultLocalRuntimeClass            = "CAUSAL_LM_PREFILL_LOGPROBS_V1"
	defaultLocalTraceMode               = "vllm_prompt_logprobs_full_prefill"
	defaultLocalJudgmentFunctionVersion = "PREFILL_GENERATED_TOKEN_METRICS_V1"
	defaultLocalCanonicalEncoding       = "CANONICAL_OUTPUT_TEXT_V1"
	defaultLocalMetricProofVersion      = "PREFILL_METRIC_AGGREGATE_PROOF_V1"
	defaultLocalTokenScope              = "ALL_GENERATED_OUTPUT_TOKENS"
	defaultLocalNumericScale            = "FP_1E6"
	huggingFaceModelIDPrefix            = "hf-"
	huggingFaceModelIDDomain            = "huggingface:"
)

const (
	verdictPass         = "PASS_SINGLE"
	verdictPassStrict   = "PASS_SINGLE_STRICT"
	verdictReject       = "REJECT_SINGLE"
	verdictInconclusive = "INCONCLUSIVE_SINGLE"
)

const (
	passMinFiniteCount          = 5
	passMeanAbsLogprobDiffMax   = 0.018
	passAbsLogprobDiffP95Max    = 0.100
	passAbsLogprobDiffP99Max    = 0.200
	passRankMismatchRateMax     = 0.025
	passTopKJaccardMeanMin      = 0.935
	passUnionJSP99Max           = 0.012
	rejectMeanAbsLogprobDiffMin = 0.023
	rejectAbsLogprobDiffP95Min  = 0.130
	rejectAbsLogprobDiffP99Min  = 0.280
	rejectRankMismatchRateMin   = 0.040
	rejectTopKJaccardMeanMax    = 0.910
	rejectUnionJSP99Min         = 0.025
)

// LocalService is an in-process model service that fulfils Infer/Verify by
// calling a local vLLM OpenAI-compatible /v1/completions endpoint. Produced
// artifacts (output, trace, checkpoint, verify sample sequence) are kept in an
// in-memory store and served back through FetchArtifact, mirroring FakeService.
type LocalService struct {
	baseURL         string
	apiKey          string
	serviceID       string
	http            *http.Client
	profileResolver LocalProfileResolver

	// inferStreamObserver, when set, receives the per-frame delta of each SSE
	// chunk during a streaming Infer. It is a best-effort delivery hook (nil by
	// default) reserved for a future user-facing SubscribeOutput forwarder; it
	// never affects the committed artifacts or the returned InferResponse.
	inferStreamObserver InferStreamObserver

	// maxConcurrency is the operator-selected admission budget for Cortex work.
	// vLLM does not publish that policy limit, so it is configured rather than
	// inferred from an engine-specific batching setting.
	maxConcurrency uint32

	// inferTimeout bounds Infer and Verify calls to vLLM.
	inferTimeout time.Duration
	// probeTimeout bounds /health, /v1/models, and /metrics probes.
	probeTimeout time.Duration

	// streamInference selects the vLLM transport for the generation path: when
	// true, Infer requests server-sent events and reassembles them in memory into
	// the same completionResponse a non-streaming call would decode. It is a
	// node-local execution detail -- never carried on InferRequest, never part of
	// the profile -- and must not change the committed output. Defaults to true;
	// SetStreamInference is the only way to turn it off. Verify is unaffected and
	// always non-streaming.
	streamInference bool

	// configuredModelIDs are the chain model identifiers this node declares
	// support for. vLLM serves its own names (Qwen/Qwen3-8B), so without these
	// the node can never advertise the protocol id handraise matches on.
	configuredModelIDs []string

	mu        sync.RWMutex
	artifacts map[string][]byte
	aliases   map[string]string // protocol model id -> vLLM served model id
	// profiles caches resolved profiles by "<model_id>@<profile_version>".
	//
	// Keeper has no message that edits a registered profile in place: changing
	// any parameter registers a new version, and MsgRegisterModelProfile
	// requires the new version to immediately follow the previous one. So the
	// verification parameters of a given (model_id, profile_version) never
	// change and the entry never needs invalidating.
	//
	// Only those parameters are cached. A profile's status does change on the
	// same version, but it is not read here -- handraise eligibility queries it
	// separately and uncached, so a freeze still takes effect immediately.
	//
	// Caching per version is also what the protocol wants rather than only an
	// optimisation: a task pins its profile_version through the assignment and
	// must complete under that version, because the verifier recomputes against
	// the same one. A version published mid-task must not change it.
	profiles map[string]localModelProfile
}

type LocalProfileResolver interface {
	ResolveLocalProfile(context.Context, string, string) (chainclient.CurrentProfileSnapshot, error)
}

func NewLocalService(baseURL, serviceID string, maxConcurrency uint32, inferTimeout, probeTimeout time.Duration, configuredModelIDs ...string) *LocalService {
	serviceID = strings.TrimSpace(serviceID)
	if serviceID == "" {
		serviceID = defaultLocalSvcID
	}
	ids := make([]string, 0, len(configuredModelIDs))
	seenIDs := make(map[string]struct{}, len(configuredModelIDs))
	for _, id := range configuredModelIDs {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			if _, exists := seenIDs[trimmed]; exists {
				continue
			}
			seenIDs[trimmed] = struct{}{}
			ids = append(ids, trimmed)
		}
	}
	if inferTimeout <= 0 {
		inferTimeout = 60 * time.Second
	}
	if probeTimeout <= 0 {
		probeTimeout = 5 * time.Second
	}
	return &LocalService{
		baseURL:            normalizeLocalBaseURL(baseURL),
		apiKey:             defaultVLLMAPIKey,
		serviceID:          serviceID,
		maxConcurrency:     maxConcurrency,
		configuredModelIDs: ids,
		http:               &http.Client{},
		artifacts:          make(map[string][]byte),
		aliases:            make(map[string]string),
		profiles:           make(map[string]localModelProfile),
		inferTimeout:       inferTimeout,
		probeTimeout:       probeTimeout,
		streamInference:    true,
	}
}

// withInferTimeout returns a context bound by the configured inference timeout.
func (s *LocalService) withInferTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.inferTimeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, s.inferTimeout)
}

// withProbeTimeout returns a context bound by the configured probe timeout.
func (s *LocalService) withProbeTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.probeTimeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, s.probeTimeout)
}

func (s *LocalService) SetProfileResolver(resolver LocalProfileResolver) {
	s.mu.Lock()
	s.profileResolver = resolver
	s.mu.Unlock()
}

// SetStreamInference toggles the vLLM SSE transport for the generation path. It
// exists mainly so tests can pin the non-streaming path; production takes the
// constructor default (on).
func (s *LocalService) SetStreamInference(enabled bool) {
	s.mu.Lock()
	s.streamInference = enabled
	s.mu.Unlock()
}

func (s *LocalService) streamInferenceEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.streamInference
}

// SetInferStreamObserver installs the best-effort per-frame sink for streaming
// Infer. Passing nil clears it. Reserved for a future SubscribeOutput forwarder.
func (s *LocalService) SetInferStreamObserver(observer InferStreamObserver) {
	s.mu.Lock()
	s.inferStreamObserver = observer
	s.mu.Unlock()
}

func (s *LocalService) inferObserver() InferStreamObserver {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inferStreamObserver
}

// InferStreamFrame is the incremental delta carried by one vLLM SSE chunk during
// a streaming Infer, tagged with the originating request's identity so a consumer
// can route it. Slice fields alias the accumulator and must not be retained past
// the ObserveInferFrame call.
type InferStreamFrame struct {
	RequestID string
	JobID     string
	TaskID    string
	ModelID   string

	// TextDelta is the text emitted by this chunk. TokenIDs / TokenLogprobs /
	// TopLogprobs are the generated-token deltas of this chunk, positionally
	// aligned. FinishReason is set only on the terminal chunk.
	TextDelta     string
	TokenIDs      []int
	TokenLogprobs []float64
	TopLogprobs   []map[string]float64
	FinishReason  string
	// Done is true on the final frame (the [DONE] sentinel or stream EOF).
	Done bool
}

// InferStreamObserver receives per-frame deltas during a streaming Infer.
// Delivery is best-effort: an error stops further frames for that call but never
// fails the inference, and context cancellation aborts the whole call.
type InferStreamObserver interface {
	ObserveInferFrame(context.Context, InferStreamFrame) error
}

// inferStreamIdentity is the request-identifying prefix stamped onto every frame.
type inferStreamIdentity struct {
	requestID string
	jobID     string
	taskID    string
	modelID   string
}

// completionRequest is the OpenAI-compatible /v1/completions payload plus the
// vLLM prompt_logprobs / return_token_ids extensions.
type completionRequest struct {
	Model                  string   `json:"model"`
	Prompt                 any      `json:"prompt"` // generate: input text (string); verify: token id array ([]int)
	MaxTokens              int      `json:"max_tokens"`
	Temperature            float64  `json:"temperature"`
	TopP                   float64  `json:"top_p"`
	TopK                   int      `json:"top_k"`
	Seed                   *int     `json:"seed,omitempty"`
	PresencePenalty        float64  `json:"presence_penalty"`
	FrequencyPenalty       float64  `json:"frequency_penalty"`
	RepetitionPenalty      float64  `json:"repetition_penalty"`
	Stop                   []string `json:"stop"`
	StopTokenIDs           []int    `json:"stop_token_ids"`
	Logprobs               *int     `json:"logprobs,omitempty"`
	PromptLogprobs         *int     `json:"prompt_logprobs,omitempty"`
	Echo                   bool     `json:"echo,omitempty"`
	Stream                 bool     `json:"stream"`
	ReturnTokenIDs         bool     `json:"return_token_ids,omitempty"`
	ReturnTokensAsTokenIDs bool     `json:"return_tokens_as_token_ids,omitempty"`
	SkipSpecialTokens      *bool    `json:"skip_special_tokens,omitempty"`
}

// logprobEntry is a single "token id -> detail" entry in a prompt_logprobs
// position dictionary.
type logprobEntry struct {
	Logprob      float64 `json:"logprob"`
	Rank         int     `json:"rank"`
	DecodedToken string  `json:"decoded_token"`
}

// completionLogprobs is the /v1/completions logprobs block, named (rather than
// inline-anonymous) so the chat path can construct it when it projects a chat
// response onto completionResponse for the shared post-processing.
type completionLogprobs struct {
	Tokens        []string             `json:"tokens"`
	TokenLogprobs []float64            `json:"token_logprobs"`
	TopLogprobs   []map[string]float64 `json:"top_logprobs"`
}

// completionChoice is one /v1/completions choice, named so the chat path can
// construct it directly when projecting a chat response onto completionResponse.
type completionChoice struct {
	Text           string                    `json:"text"`
	FinishReason   string                    `json:"finish_reason"`
	StopReason     json.RawMessage           `json:"stop_reason,omitempty"`
	PromptTokenIDs []int                     `json:"prompt_token_ids"`
	TokenIDs       []int                     `json:"token_ids"`
	Logprobs       *completionLogprobs       `json:"logprobs"`
	PromptLogprobs []map[string]logprobEntry `json:"prompt_logprobs"`
}

type completionResponse struct {
	Choices []completionChoice `json:"choices"`
}

type modelListResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

type localModelProfile struct {
	ModelID        string
	ProfileVersion string
	ServedModel    string
	RuntimeClass   string
	RequiredTopK   int
	ContextLength  int
	Sampling       localSamplingProfile
	Verification   localVerificationProfile
	Thresholds     singleSampleThresholds
}

type localSamplingProfile struct {
	Temperature            float64
	TopP                   float64
	TopK                   int
	Seed                   int
	Logprobs               int
	PromptLogprobs         int
	SkipSpecialTokens      bool
	ReturnTokenIDs         bool
	ReturnTokensAsTokenIDs bool
}

type localVerificationProfile struct {
	ProfileID                   int
	JudgmentFunctionVersion     string
	CanonicalEncodingVersion    string
	MetricAggregateProofVersion string
	TraceMode                   string
	TokenScope                  string
	IncludeGeneratedSpecial     bool
	IncludePromptTokens         bool
	IncludePaddingTokens        bool
	RequireOutputTokenIDs       bool
	RequireFinishReason         bool
	ComparedTopK                int
	NumericScale                string
	MissingLogprob              float64
}

// tokenLogprob records the vLLM output token id and its logprob at one position.
type tokenLogprob struct {
	TokenID     int                `json:"token_id"`
	Logprob     float64            `json:"logprob"`
	Rank        int                `json:"rank,omitempty"`
	TopLogprobs map[string]float64 `json:"top_logprobs,omitempty"`
}

// traceEnvelope is the local-defined trace/checkpoint payload written by Infer
// and read back by Verify.
type traceEnvelope struct {
	Generation            *nodewire.GenerationContext `json:"generation_context"`
	ModelID               string                      `json:"model_id,omitempty"`
	ProfileVersion        string                      `json:"profile_version,omitempty"`
	Output                string                      `json:"output"`
	InputTokenIDs         []int                       `json:"input_token_ids"`
	InputTokenIDsHash     string                      `json:"input_token_ids_hash,omitempty"`
	GeneratedTokenIDsHash string                      `json:"generated_token_ids_hash,omitempty"`
	GeneratedTokenCount   int                         `json:"generated_token_count,omitempty"`
	FinishReason          string                      `json:"finish_reason,omitempty"`
	StopReason            json.RawMessage             `json:"stop_reason,omitempty"`
	OutTokens             []tokenLogprob              `json:"out_tokens"`
}

// verificationValue records the verifier-side recomputation for one output
// token position.
type verificationValue struct {
	Position int      `json:"position"`
	TokenID  int      `json:"token_id"`
	Logprob  *float64 `json:"logprob,omitempty"`
	Rank     int      `json:"rank,omitempty"`
	Present  bool     `json:"present"`
}

type verificationEnvelope struct {
	Verdict        string                 `json:"verdict"`
	RawVerdict     string                 `json:"raw_verdict"`
	RejectReasons  []string               `json:"reject_reasons,omitempty"`
	Metrics        singleSampleMetrics    `json:"metrics"`
	Values         []verificationValue    `json:"values"`
	Policy         singleSampleThresholds `json:"policy"`
	MissingLogprob float64                `json:"missing_logprob"`
	VerifierID     string                 `json:"verifier_id"`
}

type singleSampleMetrics struct {
	FiniteCount          int      `json:"finite_count"`
	MissingSelectedCount int      `json:"missing_selected_count"`
	MeanAbsLogprobDiff   float64  `json:"mean_abs_logprob_diff"`
	AbsLogprobDiffP95    float64  `json:"abs_logprob_diff_p95"`
	AbsLogprobDiffP99    float64  `json:"abs_logprob_diff_p99"`
	RankDeltaNonzeroRate float64  `json:"rank_delta_nonzero_rate"`
	TopKJaccardMean      *float64 `json:"topk_jaccard_mean,omitempty"`
	UnionJSP99           *float64 `json:"union_js_p99,omitempty"`
	ComparedTopKCount    int      `json:"compared_topk_count"`
	ComparedRankCount    int      `json:"compared_rank_count"`
}

type singleSampleThresholds struct {
	PassMinFiniteCount          int     `json:"pass_min_finite_count"`
	PassMeanAbsLogprobDiffMax   float64 `json:"pass_mean_abs_logprob_diff_max"`
	PassAbsLogprobDiffP95Max    float64 `json:"pass_abs_logprob_diff_p95_max"`
	PassAbsLogprobDiffP99Max    float64 `json:"pass_abs_logprob_diff_p99_max"`
	PassRankMismatchRateMax     float64 `json:"pass_rank_mismatch_rate_max"`
	PassTopKJaccardMeanMin      float64 `json:"pass_topk_jaccard_mean_min"`
	PassUnionJSP99Max           float64 `json:"pass_union_js_p99_max"`
	RejectMeanAbsLogprobDiffMin float64 `json:"reject_mean_abs_logprob_diff_min"`
	RejectAbsLogprobDiffP95Min  float64 `json:"reject_abs_logprob_diff_p95_min"`
	RejectAbsLogprobDiffP99Min  float64 `json:"reject_abs_logprob_diff_p99_min"`
	RejectRankMismatchRateMin   float64 `json:"reject_rank_mismatch_rate_min"`
	RejectTopKJaccardMeanMax    float64 `json:"reject_topk_jaccard_mean_max"`
	RejectUnionJSP99Min         float64 `json:"reject_union_js_p99_min"`
}

func (s *LocalService) Health(ctx context.Context, req HealthRequest) (HealthResponse, error) {
	resp := HealthResponse{
		RequestID:      req.RequestID,
		ModelServiceID: s.serviceID,
	}
	serviceErr, err := s.checkVLLMHealth(ctx)
	if err != nil {
		return HealthResponse{}, err
	}
	if serviceErr != nil {
		resp.Error = serviceErr
		return resp, nil
	}
	resp.Healthy = true
	return resp, nil
}

func (s *LocalService) ListCapabilities(ctx context.Context, req ListCapabilitiesRequest) (ListCapabilitiesResponse, error) {
	models, err := s.listVLLMModels(ctx)
	if err != nil {
		return ListCapabilitiesResponse{}, err
	}
	occupied, err := s.occupiedSlots(ctx)
	if err != nil {
		return ListCapabilitiesResponse{}, err
	}
	modelIDs := s.capabilityModelIDs(models)
	capabilities := make([]ManagedModelCapability, 0, len(modelIDs))
	for _, modelID := range modelIDs {
		capabilities = append(capabilities, ManagedModelCapability{
			ModelID:            modelID,
			Capability:         CapabilityLLMTextV1,
			SupportsTrace:      true,
			SupportsCheckpoint: true,
			SupportsBatchLog:   true,
		})
	}
	return ListCapabilitiesResponse{
		RequestID:                  req.RequestID,
		ModelServiceID:             s.serviceID,
		ModelManagementAPIVersions: []string{"cortex.model_management.v1"},
		Capabilities:               capabilities,
		ResourceSnapshot: ResourceSnapshot{
			LoadedModels:   len(capabilities),
			MaxConcurrency: s.maxConcurrency,
			QueueDepth:     occupied,
		},
	}, nil
}

// occupiedSlots reports how many of maxConcurrency the backing vLLM is already
// using, read from its Prometheus endpoint. Requests in the running batch hold
// a slot just as waiting ones do, so both count.
//
// A capacity reading that cannot be taken is an error rather than zero: zero
// reads as "completely idle" and would make a saturated node handraise for work
// it cannot start.
func (s *LocalService) occupiedSlots(ctx context.Context) (uint32, error) {
	if s.maxConcurrency == 0 {
		return 0, fmt.Errorf("local model service max concurrency is not configured")
	}
	metrics, err := s.fetchVLLMMetrics(ctx)
	if err != nil {
		return 0, err
	}
	running, err := sumVLLMGauge(metrics, "vllm:num_requests_running")
	if err != nil {
		return 0, err
	}
	waiting, err := sumVLLMGauge(metrics, "vllm:num_requests_waiting")
	if err != nil {
		return 0, err
	}
	occupied := running + waiting
	if occupied > float64(s.maxConcurrency) {
		// vLLM admits more waiting requests than its batch size, so this is a
		// normal backlog rather than a fault. Report saturation.
		return s.maxConcurrency, nil
	}
	return uint32(occupied), nil
}

func (s *LocalService) fetchVLLMMetrics(ctx context.Context) (string, error) {
	ctx, cancel := s.withProbeTimeout(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/metrics", nil)
	if err != nil {
		return "", fmt.Errorf("create vLLM metrics request: %w", err)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("read vLLM metrics: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("vLLM metrics returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("read vLLM metrics body: %w", err)
	}
	return string(body), nil
}

// sumVLLMGauge totals every labelled series of a Prometheus gauge. vLLM emits
// one series per engine, so a multi-engine deployment reports several.
func sumVLLMGauge(metrics, name string) (float64, error) {
	total := 0.0
	found := false
	for _, line := range strings.Split(metrics, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.HasPrefix(line, name) {
			continue
		}
		// Skip a longer metric that merely shares this prefix, e.g.
		// vllm:num_requests_waiting_by_reason.
		rest := line[len(name):]
		if rest == "" || (rest[0] != ' ' && rest[0] != '{') {
			continue
		}
		// The sample value is the first field after the metric and optional
		// labels. A second field is an optional Prometheus timestamp and must
		// not be mistaken for the value.
		sample := rest
		if rest[0] == '{' {
			labelsEnd := strings.LastIndex(rest, "}")
			if labelsEnd < 0 {
				return 0, fmt.Errorf("parse vLLM gauge %s: unterminated labels", name)
			}
			sample = rest[labelsEnd+1:]
		}
		fields := strings.Fields(sample)
		if len(fields) == 0 {
			return 0, fmt.Errorf("parse vLLM gauge %s: sample value is missing", name)
		}
		value, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return 0, fmt.Errorf("parse vLLM gauge %s: %w", name, err)
		}
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || math.Trunc(value) != value {
			return 0, fmt.Errorf("parse vLLM gauge %s: invalid request count %q", name, fields[0])
		}
		total += value
		if math.IsInf(total, 0) || total > float64(^uint32(0)) {
			return 0, fmt.Errorf("parse vLLM gauge %s: total request count exceeds uint32", name)
		}
		found = true
	}
	if !found {
		return 0, fmt.Errorf("vLLM metrics do not report %s", name)
	}
	return total, nil
}

func (s *LocalService) GetModelDetails(_ context.Context, req GetModelDetailsRequest) (GetModelDetailsResponse, error) {
	return GetModelDetailsResponse{
		RequestID:      req.RequestID,
		ModelServiceID: s.serviceID,
		Error: &ServiceError{
			Code:    "UNIMPLEMENTED",
			Message: "local model details are not available until model profile resolution is wired",
		},
	}, nil
}

func (s *LocalService) capabilityModelIDs(servedModels []string) []string {
	s.rememberVLLMModelAliases(servedModels)
	served := normalizedServedModels(servedModels)
	configured := s.configuredModelIDSet()
	modelIDs := make([]string, 0, len(servedModels))
	seen := make(map[string]struct{}, len(servedModels))
	for _, model := range served {
		modelID := localHuggingFaceModelID(model)
		if modelID == "" {
			continue
		}
		if !modelIDAllowed(modelID, configured) {
			continue
		}
		if _, ok := seen[modelID]; ok {
			continue
		}
		seen[modelID] = struct{}{}
		modelIDs = append(modelIDs, modelID)
	}
	return modelIDs
}

func (s *LocalService) LoadModel(ctx context.Context, req LoadModelRequest) (LoadModelResponse, error) {
	if err := validateCapability(req.Capability, true, true); err != nil {
		return LoadModelResponse{}, err
	}
	servedModel, err := s.resolveServedModel(ctx, req.ModelID)
	if err != nil {
		return LoadModelResponse{}, err
	}
	s.mu.Lock()
	if strings.TrimSpace(req.ModelID) != "" {
		s.aliases[strings.TrimSpace(req.ModelID)] = servedModel
	}
	s.mu.Unlock()
	return LoadModelResponse{
		RequestID:      req.RequestID,
		ModelServiceID: s.serviceID,
		ModelID:        req.ModelID,
		Loaded:         true,
	}, nil
}

func (s *LocalService) Estimate(_ context.Context, req EstimateRequest) (EstimateResponse, error) {
	if err := validateCapability(req.Capability, true, true); err != nil {
		return EstimateResponse{}, err
	}
	return EstimateResponse{
		RequestID:      req.RequestID,
		ModelServiceID: s.serviceID,
		EstimatedMS:    100,
		EstimatedBytes: req.InputBytes + 64,
	}, nil
}

func (s *LocalService) resolveLocalProfile(ctx context.Context, modelID string, profileVersion string) (localModelProfile, error) {
	servedModel, err := s.resolveServedModel(ctx, modelID)
	if err != nil {
		return localModelProfile{}, err
	}
	profile := defaultQwenSingleSampleProfile(modelID, profileVersion, servedModel)
	resolver := s.localProfileResolver()
	if resolver == nil {
		return profile, nil
	}
	cacheKey := localProfileCacheKey(modelID, profileVersion)
	if cached, ok := s.cachedProfile(cacheKey); ok {
		return cached, nil
	}
	snapshot, err := resolver.ResolveLocalProfile(ctx, modelID, profileVersion)
	if err != nil {
		return localModelProfile{}, fmt.Errorf("modelservice local: resolve profile %s@%s: %w", modelID, profileVersion, err)
	}
	resolved, err := applyCurrentProfileSnapshot(profile, snapshot)
	if err != nil {
		return localModelProfile{}, err
	}
	s.rememberProfile(cacheKey, resolved)
	return resolved, nil
}

func defaultQwenSingleSampleProfile(modelID string, profileVersion string, servedModel string) localModelProfile {
	return localModelProfile{
		ModelID:        strings.TrimSpace(modelID),
		ProfileVersion: strings.TrimSpace(profileVersion),
		ServedModel:    strings.TrimSpace(servedModel),
		RuntimeClass:   defaultLocalRuntimeClass,
		RequiredTopK:   defaultTopK,
		Sampling: localSamplingProfile{
			Temperature:            0,
			TopP:                   defaultTopP,
			TopK:                   defaultTopKSample,
			Seed:                   defaultSeed,
			Logprobs:               defaultTopK,
			PromptLogprobs:         defaultTopK,
			SkipSpecialTokens:      false,
			ReturnTokenIDs:         true,
			ReturnTokensAsTokenIDs: true,
		},
		Verification: localVerificationProfile{
			ProfileID:                   1,
			JudgmentFunctionVersion:     defaultLocalJudgmentFunctionVersion,
			CanonicalEncodingVersion:    defaultLocalCanonicalEncoding,
			MetricAggregateProofVersion: defaultLocalMetricProofVersion,
			TraceMode:                   defaultLocalTraceMode,
			TokenScope:                  defaultLocalTokenScope,
			IncludeGeneratedSpecial:     true,
			IncludePromptTokens:         false,
			IncludePaddingTokens:        false,
			RequireOutputTokenIDs:       true,
			RequireFinishReason:         true,
			ComparedTopK:                defaultTopK,
			NumericScale:                defaultLocalNumericScale,
			MissingLogprob:              missingLogprob,
		},
		Thresholds: localSingleSampleThresholds(),
	}
}

func localProfileCacheKey(modelID string, profileVersion string) string {
	return strings.TrimSpace(modelID) + "@" + strings.TrimSpace(profileVersion)
}

func (s *LocalService) cachedProfile(key string) (localModelProfile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	profile, ok := s.profiles[key]
	return profile, ok
}

func (s *LocalService) rememberProfile(key string, profile localModelProfile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.profiles[key] = profile
}

func (s *LocalService) localProfileResolver() LocalProfileResolver {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.profileResolver
}

func applyCurrentProfileSnapshot(profile localModelProfile, snapshot chainclient.CurrentProfileSnapshot) (localModelProfile, error) {
	snapshotModelID := strings.TrimSpace(snapshot.ModelID)
	if snapshotModelID == "" {
		return localModelProfile{}, fmt.Errorf("resolved model profile is missing model_id")
	}
	if profile.ModelID != "" && snapshotModelID != profile.ModelID {
		return localModelProfile{}, fmt.Errorf("resolved model profile id %q does not match request model_id %q", snapshotModelID, profile.ModelID)
	}
	snapshotProfileVersion := strings.TrimSpace(snapshot.ProfileVersion.String())
	if snapshotProfileVersion == "" || snapshot.ProfileVersion.Uint32() == 0 {
		return localModelProfile{}, fmt.Errorf("resolved model profile is missing profile_version")
	}
	if profile.ProfileVersion != "" && snapshotProfileVersion != profile.ProfileVersion {
		return localModelProfile{}, fmt.Errorf("resolved profile version %q does not match request profile_version %q", snapshotProfileVersion, profile.ProfileVersion)
	}

	requiredTopK := snapshot.RequiredTopK
	comparedTopK := snapshot.VerificationProfile.Metrics.ComparedTopK
	switch {
	case requiredTopK == 0 && comparedTopK == 0:
		return localModelProfile{}, fmt.Errorf("resolved model profile is missing required_top_k")
	case requiredTopK == 0:
		requiredTopK = comparedTopK
	case comparedTopK == 0:
		comparedTopK = requiredTopK
	case requiredTopK != comparedTopK:
		return localModelProfile{}, fmt.Errorf("resolved model profile required_top_k %d does not match compared_top_k %d", requiredTopK, comparedTopK)
	}

	profile.ModelID = snapshotModelID
	profile.ProfileVersion = snapshotProfileVersion
	if runtimeClass := strings.TrimSpace(snapshot.RuntimeClass); runtimeClass != "" {
		profile.RuntimeClass = runtimeClass
	}
	profile.RequiredTopK = int(requiredTopK)
	profile.Sampling.Logprobs = int(requiredTopK)
	profile.Sampling.PromptLogprobs = int(requiredTopK)
	profile.Verification.ComparedTopK = int(comparedTopK)

	verification := snapshot.VerificationProfile
	if verification.VerificationProfileID != 0 {
		profile.Verification.ProfileID = int(verification.VerificationProfileID)
	}
	if value := strings.TrimSpace(verification.JudgmentFunctionVersion); value != "" {
		profile.Verification.JudgmentFunctionVersion = value
	}
	if value := strings.TrimSpace(verification.CanonicalEncodingVersion); value != "" {
		profile.Verification.CanonicalEncodingVersion = value
	}
	if value := strings.TrimSpace(verification.MetricAggregateProofVersion); value != "" {
		profile.Verification.MetricAggregateProofVersion = value
	}
	if value := normalizeCurrentProfileEnum(verification.TokenScope, "TOKEN_SCOPE_"); value != "" {
		profile.Verification.TokenScope = value
	}
	if value := normalizeCurrentProfileEnum(verification.Metrics.NumericScale, "NUMERIC_SCALE_"); value != "" {
		profile.Verification.NumericScale = value
	}
	profile.Verification.IncludeGeneratedSpecial = verification.IncludeGeneratedSpecialTokens
	profile.Verification.IncludePromptTokens = verification.IncludePromptTokens
	profile.Verification.IncludePaddingTokens = verification.IncludePaddingTokens
	profile.Verification.RequireOutputTokenIDs = verification.RequireOutputTokenIDs
	profile.Verification.RequireFinishReason = verification.RequireFinishReason

	if err := checkSupportedVerificationSpec(snapshot); err != nil {
		return localModelProfile{}, err
	}

	thresholds, ok, err := currentProfileThresholds(snapshot)
	if err != nil {
		return localModelProfile{}, err
	}
	if ok {
		profile.Thresholds = thresholds
	}
	return profile, nil
}

// checkSupportedVerificationSpec rejects a profile whose verification rules this
// implementation does not actually execute.
//
// The local pipeline implements exactly one combination: it computes and judges
// all four metrics, scores generated output tokens including generated special
// tokens, and treats any missing compared token as a reject. Those choices are
// currently hardcoded -- the corresponding profile fields were copied into the
// local profile but never consumed, so a legal profile selecting a different
// combination was silently executed under these rules instead.
//
// Diverging from the profile is worse than refusing it. A verifier recomputes
// against the profile the chain records, so a Worker that quietly applied
// different rules produces evidence that is judged inconsistent, and a Verifier
// that did so returns a verdict the network did not ask for. Until each field is
// implemented, fail closed and say which one is unsupported.
func checkSupportedVerificationSpec(snapshot chainclient.CurrentProfileSnapshot) error {
	verification := snapshot.VerificationProfile
	metrics := verification.Metrics
	for _, unsupported := range []struct {
		field string
		bad   bool
		want  string
	}{
		{"compare_logprob_diff", !metrics.CompareLogprobDiff, "true"},
		{"compare_rank_delta", !metrics.CompareRankDelta, "true"},
		{"compare_topk_jaccard", !metrics.CompareTopKJaccard, "true"},
		{"compare_union_js", !metrics.CompareUnionJS, "true"},
		{"include_generated_special_tokens", !verification.IncludeGeneratedSpecialTokens, "true"},
		{"include_prompt_tokens", verification.IncludePromptTokens, "false"},
		{"include_padding_tokens", verification.IncludePaddingTokens, "false"},
	} {
		if unsupported.bad {
			return fmt.Errorf("modelservice local: model profile %s is not implemented by the local verifier (only %s is executed)", unsupported.field, unsupported.want)
		}
	}
	if scope := normalizeCurrentProfileEnum(verification.TokenScope, "TOKEN_SCOPE_"); scope != "" && scope != defaultLocalTokenScope {
		return fmt.Errorf("modelservice local: model profile token_scope %q is not implemented by the local verifier (only %s is executed)", scope, defaultLocalTokenScope)
	}
	// The classifier rejects on any missing compared token and requires zero to
	// pass, so it cannot honour a non-zero allowance.
	if allowed := snapshot.VerificationThresholds.PassMaxMissingComparedCount; allowed != 0 {
		return fmt.Errorf("modelservice local: model profile pass_max_missing_compared_count %d is not implemented by the local verifier (only 0 is executed)", allowed)
	}
	return nil
}

func currentProfileThresholds(snapshot chainclient.CurrentProfileSnapshot) (singleSampleThresholds, bool, error) {
	thresholds := snapshot.VerificationThresholds
	if !currentProfileThresholdsPresent(thresholds) {
		return singleSampleThresholds{}, false, nil
	}
	scale, err := currentProfileNumericScale(snapshot.VerificationProfile.Metrics.NumericScale)
	if err != nil {
		return singleSampleThresholds{}, false, err
	}
	return singleSampleThresholds{
		PassMinFiniteCount:          int(thresholds.PassMinFiniteCount),
		PassMeanAbsLogprobDiffMax:   scale(thresholds.PassMeanAbsLogprobDiffMax),
		PassAbsLogprobDiffP95Max:    scale(thresholds.PassAbsLogprobDiffP95Max),
		PassAbsLogprobDiffP99Max:    scale(thresholds.PassAbsLogprobDiffP99Max),
		PassRankMismatchRateMax:     scale(thresholds.PassRankDeltaNonzeroRateMax),
		PassTopKJaccardMeanMin:      scale(thresholds.PassTopKJaccardMeanMin),
		PassUnionJSP99Max:           scale(thresholds.PassUnionJSP99Max),
		RejectMeanAbsLogprobDiffMin: scale(thresholds.RejectMeanAbsLogprobDiffMin),
		RejectAbsLogprobDiffP95Min:  scale(thresholds.RejectAbsLogprobDiffP95Min),
		RejectAbsLogprobDiffP99Min:  scale(thresholds.RejectAbsLogprobDiffP99Min),
		RejectRankMismatchRateMin:   scale(thresholds.RejectRankDeltaNonzeroRateMin),
		RejectTopKJaccardMeanMax:    scale(thresholds.RejectTopKJaccardMeanMax),
		RejectUnionJSP99Min:         scale(thresholds.RejectUnionJSP99Min),
	}, true, nil
}

func currentProfileThresholdsPresent(thresholds chainclient.CurrentVerificationThresholdsSnapshot) bool {
	return thresholds.PassMinFiniteCount != 0 ||
		thresholds.PassMaxMissingComparedCount != 0 ||
		thresholds.PassMeanAbsLogprobDiffMax != 0 ||
		thresholds.PassAbsLogprobDiffP95Max != 0 ||
		thresholds.PassAbsLogprobDiffP99Max != 0 ||
		thresholds.PassRankDeltaNonzeroRateMax != 0 ||
		thresholds.PassTopKJaccardMeanMin != 0 ||
		thresholds.PassUnionJSP99Max != 0 ||
		thresholds.RejectMeanAbsLogprobDiffMin != 0 ||
		thresholds.RejectAbsLogprobDiffP95Min != 0 ||
		thresholds.RejectAbsLogprobDiffP99Min != 0 ||
		thresholds.RejectRankDeltaNonzeroRateMin != 0 ||
		thresholds.RejectTopKJaccardMeanMax != 0 ||
		thresholds.RejectUnionJSP99Min != 0
}

func currentProfileNumericScale(raw string) (func(uint32) float64, error) {
	switch normalizeCurrentProfileEnum(raw, "NUMERIC_SCALE_") {
	case "", "FP_1E6":
		return func(value uint32) float64 {
			return float64(value) / 1_000_000
		}, nil
	default:
		return nil, fmt.Errorf("unsupported resolved profile numeric_scale %q", raw)
	}
}

func normalizeCurrentProfileEnum(value, prefix string) string {
	return strings.TrimPrefix(strings.TrimSpace(value), prefix)
}

// inferV0 is the original raw-text generation path: it sends req.Input verbatim
// as a /v1/completions prompt. It is retained for the legacy llm_text_v1 shape
// and is dispatched to by Infer (local_chat.go) when the input is not a chat
// payload.
func (s *LocalService) inferV0(ctx context.Context, req InferRequest) (InferResponse, error) {
	if err := validateCapability(req.Capability, true, true); err != nil {
		return InferResponse{}, err
	}
	if err := ValidateGenerationContext(req.Generation, req.GenerationParamsDigest, req.ModelID, req.ProfileVersion); err != nil {
		return InferResponse{}, err
	}
	generation := req.Generation.Clone()
	req.Generation = &generation
	req.GenerationParamsDigest = slices.Clone(req.GenerationParamsDigest)
	profile, err := s.resolveLocalProfile(ctx, req.ModelID, req.ProfileVersion)
	if err != nil {
		return InferResponse{}, err
	}
	streaming := s.streamInferenceEnabled()
	genReq, duration, err := localGenerationRequest(req, profile, streaming)
	if err != nil {
		return InferResponse{}, err
	}
	// The local bound begins before the engine call, so queue and network time
	// consume the budget. Expiry fails the call without publishing partial output.
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	if req.DeadlineMS > 0 {
		var deadlineCancel context.CancelFunc
		ctx, deadlineCancel = context.WithDeadline(ctx, time.UnixMilli(req.DeadlineMS))
		defer deadlineCancel()
	}
	ctx, inferCancel := s.withInferTimeout(ctx)
	defer inferCancel()
	var resp completionResponse
	{
		if streaming {
			ident := inferStreamIdentity{
				requestID: req.RequestID,
				jobID:     req.JobID,
				taskID:    req.TaskID,
				modelID:   profile.ModelID,
			}
			if err := s.postStreamingCompletion(ctx, "/v1/completions", genReq, &resp, ident); err != nil {
				return InferResponse{}, err
			}
		} else if err := s.post(ctx, "/v1/completions", genReq, &resp); err != nil {
			return InferResponse{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return InferResponse{}, err
	}
	return s.buildInferResultFromCompletion(ctx, req, profile, resp, nil, completionFinishResolver(req))
}

// finishReasonResolver derives the frozen FinishReasonV1 for one choice. The two
// generation paths resolve it differently, so the shared post-processing takes
// the policy as a parameter rather than choosing one for both.
type finishReasonResolver func(reason string, stop json.RawMessage, count uint64) (nodewire.FinishReasonV1, error)

// completionFinishResolver honours the chain-bound generation parameters: the
// raw-text path validates req.Generation, so it can cross-check the reported
// finish against max_output_tokens and the configured stop conditions (#370).
func completionFinishResolver(req InferRequest) finishReasonResolver {
	return func(reason string, stop json.RawMessage, count uint64) (nodewire.FinishReasonV1, error) {
		return localGenerationFinishReason(req.Generation, reason, stop, count)
	}
}

// chatFinishResolver serves the chat path, which does not validate req.Generation
// and may see vLLM's "tool_calls" finish. finishReasonV1FromString maps that to
// EOS and treats "stop" as EOS (the chat path sends no stop sequences).
func chatFinishResolver(reason string, _ json.RawMessage, _ uint64) (nodewire.FinishReasonV1, error) {
	return finishReasonV1FromString(reason, false)
}

// buildInferResultFromCompletion turns a decoded /v1/completions response (or a
// chat response projected onto the same shape) into the InferResponse plus the
// stored output/trace/checkpoint artifacts. It is shared by inferV0 and the chat
// path so both produce byte-identical trace/checkpoint envelopes and the Verifier
// sees one shape regardless of which endpoint generated the tokens.
//
// outputBytes is the artifact to commit and deliver as the output. Pass nil to
// commit the raw generated text (choice.Text) -- the inferV0 behaviour; the chat
// path passes a full OpenAI ChatCompletion object instead, which is why the output
// artifact and trace.Output are decoupled here: trace.Output stays the model's
// text while the delivered output can be a richer envelope.
//
// resolveFinish computes the frozen finish reason; each path supplies its own so
// the completions path can honour generation parameters while the chat path keeps
// its own mapping (see finishReasonResolver).
func (s *LocalService) buildInferResultFromCompletion(ctx context.Context, req InferRequest, profile localModelProfile, resp completionResponse, outputBytes []byte, resolveFinish finishReasonResolver) (InferResponse, error) {
	if len(resp.Choices) == 0 {
		return InferResponse{}, fmt.Errorf("modelservice local infer: empty choices")
	}
	choice := resp.Choices[0]
	if len(choice.TokenIDs) == 0 && choice.Text != "" {
		return InferResponse{}, fmt.Errorf("modelservice local infer: missing generated token ids")
	}
	if len(choice.PromptTokenIDs) == 0 && len(req.Input) > 0 {
		return InferResponse{}, fmt.Errorf("modelservice local infer: missing prompt token ids")
	}
	if choice.Logprobs == nil || len(choice.Logprobs.TokenLogprobs) != len(choice.TokenIDs) {
		return InferResponse{}, fmt.Errorf("modelservice local infer: generated token logprobs are incomplete")
	}
	finishReason, err := resolveFinish(choice.FinishReason, choice.StopReason, uint64(len(choice.TokenIDs)))
	if err != nil {
		return InferResponse{}, err
	}

	outTokens := make([]tokenLogprob, 0, len(choice.TokenIDs))
	generatedTokenIDs := make([]int, 0, len(choice.TokenIDs))
	for i, id := range choice.TokenIDs {
		generatedTokenIDs = append(generatedTokenIDs, id)
		topLogprobs := topLogprobsAt(choice.Logprobs.TopLogprobs, i)
		outTokens = append(outTokens, tokenLogprob{
			TokenID:     id,
			Logprob:     choice.Logprobs.TokenLogprobs[i],
			Rank:        rankForToken(id, topLogprobs),
			TopLogprobs: topLogprobs,
		})
	}

	trace := traceEnvelope{
		Generation:            req.Generation,
		ModelID:               profile.ModelID,
		ProfileVersion:        profile.ProfileVersion,
		Output:                choice.Text,
		InputTokenIDs:         choice.PromptTokenIDs,
		InputTokenIDsHash:     hashTokenIDs(choice.PromptTokenIDs),
		GeneratedTokenIDsHash: hashTokenIDs(generatedTokenIDs),
		GeneratedTokenCount:   len(generatedTokenIDs),
		FinishReason:          choice.FinishReason,
		StopReason:            choice.StopReason,
		OutTokens:             outTokens,
	}
	traceBytes, err := json.Marshal(trace)
	if err != nil {
		return InferResponse{}, fmt.Errorf("modelservice local infer: marshal trace: %w", err)
	}
	checkpointBytes, err := json.Marshal(traceEnvelope{
		Generation:            req.Generation,
		ModelID:               profile.ModelID,
		ProfileVersion:        profile.ProfileVersion,
		Output:                choice.Text,
		InputTokenIDs:         choice.PromptTokenIDs,
		InputTokenIDsHash:     hashTokenIDs(choice.PromptTokenIDs),
		GeneratedTokenIDsHash: hashTokenIDs(generatedTokenIDs),
		GeneratedTokenCount:   len(generatedTokenIDs),
		FinishReason:          choice.FinishReason,
		StopReason:            choice.StopReason,
	})
	if err != nil {
		return InferResponse{}, fmt.Errorf("modelservice local infer: marshal checkpoint: %w", err)
	}
	// The chain-bound generation contract is only validated for the completions
	// path, which carries and validates req.Generation. The chat path has no
	// generation context yet (its finish reason comes from chatFinishResolver), so
	// there is nothing to re-derive against here.
	if req.Generation != nil {
		if _, _, err := ValidateGenerationEvidence(req.Generation, req.GenerationParamsDigest, []byte(choice.Text), traceBytes, checkpointBytes); err != nil {
			return InferResponse{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return InferResponse{}, err
	}

	if outputBytes == nil {
		outputBytes = []byte(choice.Text)
	}
	outputRef := s.putArtifact(outputBytes)
	traceRef := s.putArtifact(traceBytes)
	checkpointRef := s.putArtifact(checkpointBytes)
	generatedTokenCount := uint64(trace.GeneratedTokenCount)

	return InferResponse{
		RequestID:              req.RequestID,
		ModelServiceID:         s.serviceID,
		JobID:                  req.JobID,
		TaskID:                 req.TaskID,
		ModelID:                req.ModelID,
		ProfileVersion:         req.ProfileVersion,
		RequestDigest:          req.RequestDigest,
		GenerationParamsDigest: slices.Clone(req.GenerationParamsDigest),
		OutputRef:              outputRef,
		TraceRef:               traceRef,
		CheckpointRef:          checkpointRef,
		GeneratedTokenCount:    generatedTokenCount,
		WorkUnit:               generatedTokenCount,
		FinishReason:           finishReason,
	}, nil
}

// Verify re-runs the committed token IDs as a prefill and scores them. One
// check data-plane-and-evidence-transfer.md §9.1 names is deliberately NOT here yet:
// `detokenize(token IDs) == text`. Everything it depends on is in place — the
// Verifier rebuilds the output MMR from `chunk_lengths[]` and binds the text to
// `output_hash` (internal/verifier/worker_commitment.go), and
// ValidateTokenIDArtifacts binds the raw token vectors to the authenticated
// trace and checkpoint — so what is missing is only the tokenizer call, and it
// is missing for a reason rather than by oversight: the engine does not render
// the stop-triggering token into the text (measured on vLLM 0.25.1 /
// Qwen/Qwen3-8B: the returned IDs end in 151645, the text does not, with
// skip_special_tokens=false), so a straight comparison fails every normal EOS
// completion. Dropping the final token to make it pass is what must not be
// done without first establishing that token's identity, and this deployment
// exposes no authority for it — `/tokenizer_info` answers 404, and the task's
// frozen generation params carry only the *configured* StopTokenIDs, never the
// model's own EOS. `TokenIDArtifacts` therefore proves the raw artifacts equal
// the trace, not that they mean the same text as the output; do not describe it
// as the §9.1 check. Landing that check needs an EOS-identity source decided
// first, not a looser comparison here.
func (s *LocalService) Verify(ctx context.Context, req VerifyRequest) (VerifyResponse, error) {
	if err := ValidateGenerationContext(req.Generation, req.GenerationParamsDigest, req.ModelID, req.ProfileVersion); err != nil {
		return VerifyResponse{}, err
	}
	generation := req.Generation.Clone()
	req.Generation = &generation
	req.GenerationParamsDigest = slices.Clone(req.GenerationParamsDigest)
	if req.DeadlineMS > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, time.UnixMilli(req.DeadlineMS))
		defer cancel()
	}
	item, err := validateVerifyRequest(req)
	if err != nil {
		return VerifyResponse{}, err
	}
	var env traceEnvelope
	if err := json.Unmarshal(item.Trace, &env); err != nil {
		return VerifyResponse{}, fmt.Errorf("modelservice local verify: unmarshal trace: %w", err)
	}
	if _, _, err := ValidateGenerationEvidence(req.Generation, req.GenerationParamsDigest, []byte(env.Output), item.Trace, item.Checkpoint); err != nil {
		return VerifyResponse{}, err
	}
	profile, err := s.resolveLocalProfile(ctx, req.ModelID, req.ProfileVersion)
	if err != nil {
		return VerifyResponse{}, err
	}
	if err := validateTraceProfile(req, profile, env); err != nil {
		return VerifyResponse{}, err
	}

	inputLen := len(env.InputTokenIDs)
	prompt := make([]int, 0, inputLen+len(env.OutTokens))
	prompt = append(prompt, env.InputTokenIDs...)
	for _, t := range env.OutTokens {
		prompt = append(prompt, t.TokenID)
	}

	topK := profile.Sampling.PromptLogprobs
	skipSpecial := profile.Sampling.SkipSpecialTokens
	seed := profile.Sampling.Seed
	verifyReq := completionRequest{
		Model:                  profile.ServedModel,
		Prompt:                 prompt,
		MaxTokens:              1, // next token is ignored; we only need prompt_logprobs
		RepetitionPenalty:      1,
		Temperature:            profile.Sampling.Temperature,
		TopP:                   profile.Sampling.TopP,
		TopK:                   profile.Sampling.TopK,
		Seed:                   &seed,
		PromptLogprobs:         &topK,
		Stream:                 false,
		ReturnTokenIDs:         profile.Sampling.ReturnTokenIDs,
		ReturnTokensAsTokenIDs: profile.Sampling.ReturnTokensAsTokenIDs,
		SkipSpecialTokens:      &skipSpecial,
	}
	var resp completionResponse
	ctx, cancel := s.withInferTimeout(ctx)
	defer cancel()
	if err := s.post(ctx, "/v1/completions", verifyReq, &resp); err != nil {
		return VerifyResponse{}, err
	}
	if err := ctx.Err(); err != nil {
		return VerifyResponse{}, err
	}
	if len(resp.Choices) == 0 {
		return VerifyResponse{}, fmt.Errorf("modelservice local verify: empty choices")
	}
	recomputed := resp.Choices[0].PromptLogprobs

	metrics, metricSamples, err := computeSingleSampleMetrics(
		env.OutTokens, inputLen, recomputed, profile.Verification.ComparedTopK, profile.Verification.MissingLogprob)
	if err != nil {
		return VerifyResponse{}, err
	}
	rawVerdict, rejectReasons := classifySingleSampleWithThresholds(metrics, profile.Thresholds)
	verdict := verdictPass
	mismatchCount := 0
	if rawVerdict == verdictReject {
		verdict = verdictReject
		mismatchCount = len(rejectReasons)
	}
	positions := outputTokenPositions(len(env.OutTokens))
	values := verificationSequence(env.OutTokens, inputLen, recomputed, profile.Verification.MissingLogprob)

	sequenceBytes, err := json.Marshal(verificationEnvelope{
		Verdict:        verdict,
		RawVerdict:     rawVerdict,
		RejectReasons:  rejectReasons,
		Metrics:        metrics,
		Values:         values,
		Policy:         profile.Thresholds,
		MissingLogprob: profile.Verification.MissingLogprob,
		VerifierID:     localVerifierID,
	})
	if err != nil {
		return VerifyResponse{}, fmt.Errorf("modelservice local verify: marshal sample sequence: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return VerifyResponse{}, err
	}
	sequenceRef := s.putArtifact(sequenceBytes)

	sampleDigest := codec.HashBytes(req.Sample)
	materialDigest := codec.HashWithDomain("CORTEX_LOCAL_VERIFY_MATERIAL_V1", req.Sample, item.Trace, item.Checkpoint)

	return VerifyResponse{
		RequestID:                      req.RequestID,
		ModelServiceID:                 s.serviceID,
		JobID:                          req.JobID,
		TaskID:                         req.TaskID,
		ModelID:                        req.ModelID,
		ProfileVersion:                 req.ProfileVersion,
		RequestDigest:                  req.RequestDigest,
		GenerationParamsDigest:         slices.Clone(req.GenerationParamsDigest),
		VerifierID:                     localVerifierID,
		MainMismatchCount:              mismatchCount,
		SelectedPositionsOrCheckpoints: positions,
		SampleValueSequenceRef:         sequenceRef,
		SampleDigest:                   sampleDigest[:],
		MaterialDigest:                 materialDigest[:],
		// The metric material: one sample per generated token position, plus the
		// aggregation the summary is narrowed from. Both are carried on the
		// response rather than only inside the sample-sequence artifact, because
		// the verifier must derive metric_root and MetricSummaryV1 from the same
		// run that produced the compact reveal - re-reading a JSON artifact would
		// be a second source that can disagree with the first.
		MetricSamples: metricSamples,
	}, nil
}

// compareOutputLogprobs compares the output token ids and logprobs captured at
// infer time against the verifier's recomputed prompt_logprobs, and reports how
// many positions are inconsistent.
func compareOutputLogprobs(trace []tokenLogprob, inputLen int, recomputed []map[string]logprobEntry) (mismatchCount int) {
	metrics, _, err := computeSingleSampleMetrics(trace, inputLen, recomputed, defaultTopK, missingLogprob)
	if err != nil {
		return 0
	}
	verdict, reasons := classifySingleSample(metrics)
	if verdict != verdictReject {
		return 0
	}
	return len(reasons)
}

func verificationSequence(trace []tokenLogprob, inputLen int, recomputed []map[string]logprobEntry, missingValue float64) []verificationValue {
	values := make([]verificationValue, 0, len(trace))
	for i, t := range trace {
		entry, ok := recomputedEntryFor(t.TokenID, inputLen+i, recomputed)
		value := verificationValue{
			Position: i,
			TokenID:  t.TokenID,
			Present:  ok,
		}
		if ok {
			lp := entry.Logprob
			value.Logprob = &lp
			value.Rank = entry.Rank
		} else {
			lp := missingValue
			value.Logprob = &lp
		}
		values = append(values, value)
	}
	return values
}

// computeSingleSampleMetrics compares the worker's captured trace against the
// verifier's recomputed prompt_logprobs and returns both halves of the result:
// the aggregates the local verdict is classified from, and one metric sample per
// generated token position.
//
// The samples exist because metric_root is a Merkle tree over per-position
// leaves (05-verification-algorithm §7) and the aggregates alone cannot reconstruct them. They
// are emitted from the SAME loop as the aggregates, not from a second pass:
// summary and leaves must describe one comparison, and two passes over
// floating-point data are exactly how they stop doing so.
//
// missingLogprob is the profile's stand-in for a position the verifier has no
// entry for. The leaf still carries it - the position happened, and dropping it
// would renumber every later output_position - beside missing_flag saying the
// value is a substitute rather than a measurement.
func computeSingleSampleMetrics(
	trace []tokenLogprob, inputLen int, recomputed []map[string]logprobEntry, comparedTopK int, missingLogprob float64,
) (singleSampleMetrics, []metric.Sample, error) {
	samples := make([]metric.Sample, 0, len(trace))

	for i, worker := range trace {
		entry, selectedPresent := recomputedEntryFor(worker.TokenID, inputLen+i, recomputed)
		position, err := leafUint32("output_position", i)
		if err != nil {
			return singleSampleMetrics{}, nil, err
		}
		tokenID, err := leafUint32("emitted_token_id", worker.TokenID)
		if err != nil {
			return singleSampleMetrics{}, nil, err
		}
		workerRank, err := leafUint32("worker_rank", worker.Rank)
		if err != nil {
			return singleSampleMetrics{}, nil, err
		}
		sample := metric.Sample{
			OutputPosition:  position,
			EmittedTokenID:  tokenID,
			WorkerLogprob:   worker.Logprob,
			VerifierLogprob: missingLogprob,
			WorkerRank:      workerRank,
			Missing:         !selectedPresent,
		}
		if selectedPresent {
			verifierRank, err := leafUint32("verifier_rank", entry.Rank)
			if err != nil {
				return singleSampleMetrics{}, nil, err
			}
			sample.VerifierLogprob = entry.Logprob
			sample.VerifierRank = verifierRank
			sample.Finite = finite(worker.Logprob) && finite(entry.Logprob)
		}
		workerTopK := limitTopLogprobs(worker.TopLogprobs, comparedTopK)
		verifierTopK := limitTopLogprobs(promptTopLogprobsAt(recomputed, inputLen+i), comparedTopK)
		if len(workerTopK) > 0 && len(verifierTopK) > 0 {
			sample.TopKJaccard = metric.PresentFP(topKJaccard(workerTopK, verifierTopK))
			if js, ok := unionJSDivergence(workerTopK, verifierTopK); ok {
				sample.UnionJS = metric.PresentFP(js)
			}
		}
		samples = append(samples, sample)
	}

	// The local verdict classifies from the SAME aggregation the submitted
	// summary is narrowed from. There is one aggregator (metric.AggregateFromSamples)
	// and this is a projection of it - a second pass here is exactly how the
	// number an operator reads and the number the Keeper judges start to differ.
	return localMetricsFromAggregates(metric.AggregateFromSamples(samples, uint32(comparedTopK))), samples, nil
}

// localMetricsFromAggregates projects the canonical aggregation into the local
// classifier's shape. It converts nothing: presence stays presence, and the
// counts are the same integers.
func localMetricsFromAggregates(aggregates metric.Aggregates) singleSampleMetrics {
	metrics := singleSampleMetrics{
		FiniteCount:          aggregates.FiniteCount,
		MissingSelectedCount: aggregates.MissingComparedCount,
		MeanAbsLogprobDiff:   aggregates.MeanAbsLogprobDiff,
		AbsLogprobDiffP95:    aggregates.AbsLogprobDiffP95,
		AbsLogprobDiffP99:    aggregates.AbsLogprobDiffP99,
		RankDeltaNonzeroRate: aggregates.RankDeltaNonzeroRate,
		ComparedTopKCount:    aggregates.ComparedTopKCount,
		ComparedRankCount:    aggregates.ComparedRankCount,
	}
	if aggregates.TopKJaccardMean.Present {
		value := aggregates.TopKJaccardMean.Value
		metrics.TopKJaccardMean = &value
	}
	if aggregates.UnionJSP99.Present {
		value := aggregates.UnionJSP99.Value
		metrics.UnionJSP99 = &value
	}
	return metrics
}

// leafUint32 narrows a model service int to the unsigned width the metric leaf
// frames, and REFUSES anything that does not fit.
//
// It used to clamp to zero. That was wrong in a way that only shows up much
// later: token id 0 is a legal token and rank 0 is the wire's "no rank
// reported" spelling, so a clamped transport fault becomes an ordinary-looking
// leaf. The leaf is then hashed into metric_root, signed, and put on chain -
// and the mismatch only surfaces at a VERIFIER_VALUE_OPENING that can never be
// satisfied, because the true value was destroyed at this line.
func leafUint32(name string, value int) (uint32, error) {
	if value < 0 || int64(value) > math.MaxUint32 {
		return 0, fmt.Errorf(
			"modelservice local verify: %s = %d does not fit the metric leaf's uint32 field; refusing rather "+
				"than clamping, because a clamped value hashes into metric_root as a plausible one", name, value)
	}
	return uint32(value), nil
}

func classifySingleSample(metrics singleSampleMetrics) (string, []string) {
	return classifySingleSampleWithThresholds(metrics, localSingleSampleThresholds())
}

func classifySingleSampleWithThresholds(metrics singleSampleMetrics, thresholds singleSampleThresholds) (string, []string) {
	var rejectReasons []string
	if metrics.MissingSelectedCount > 0 {
		rejectReasons = append(rejectReasons, "missing_selected_count")
	}
	if metrics.MeanAbsLogprobDiff >= thresholds.RejectMeanAbsLogprobDiffMin {
		rejectReasons = append(rejectReasons, "mean_abs_logprob_diff")
	}
	if metrics.AbsLogprobDiffP95 >= thresholds.RejectAbsLogprobDiffP95Min {
		rejectReasons = append(rejectReasons, "abs_logprob_diff_p95")
	}
	if metrics.AbsLogprobDiffP99 >= thresholds.RejectAbsLogprobDiffP99Min {
		rejectReasons = append(rejectReasons, "abs_logprob_diff_p99")
	}
	if metrics.RankDeltaNonzeroRate >= thresholds.RejectRankMismatchRateMin {
		rejectReasons = append(rejectReasons, "rank_delta_nonzero_rate")
	}
	if metrics.TopKJaccardMean != nil && *metrics.TopKJaccardMean <= thresholds.RejectTopKJaccardMeanMax {
		rejectReasons = append(rejectReasons, "topk_jaccard_mean")
	}
	if metrics.UnionJSP99 != nil && *metrics.UnionJSP99 >= thresholds.RejectUnionJSP99Min {
		rejectReasons = append(rejectReasons, "union_js_p99")
	}
	if len(rejectReasons) > 0 {
		return verdictReject, rejectReasons
	}

	// Pass thresholds are inclusive. There is no dead band: a sample either meets
	// every pass threshold, triggers a reject threshold, or is missing required
	// fields and is inconclusive. The reject boundaries are inclusive to match the
	// chain's JudgeMetricSample in x/task/types/metric_judgment.go.
	if metrics.FiniteCount >= thresholds.PassMinFiniteCount &&
		metrics.MissingSelectedCount == 0 &&
		metrics.ComparedRankCount == metrics.FiniteCount &&
		metrics.ComparedTopKCount == metrics.FiniteCount &&
		metrics.MeanAbsLogprobDiff <= thresholds.PassMeanAbsLogprobDiffMax &&
		metrics.AbsLogprobDiffP95 <= thresholds.PassAbsLogprobDiffP95Max &&
		metrics.AbsLogprobDiffP99 <= thresholds.PassAbsLogprobDiffP99Max &&
		metrics.RankDeltaNonzeroRate <= thresholds.PassRankMismatchRateMax &&
		metrics.TopKJaccardMean != nil && *metrics.TopKJaccardMean >= thresholds.PassTopKJaccardMeanMin &&
		metrics.UnionJSP99 != nil && *metrics.UnionJSP99 <= thresholds.PassUnionJSP99Max {
		return verdictPassStrict, nil
	}
	return verdictInconclusive, nil
}

func localSingleSampleThresholds() singleSampleThresholds {
	return singleSampleThresholds{
		PassMinFiniteCount:          passMinFiniteCount,
		PassMeanAbsLogprobDiffMax:   passMeanAbsLogprobDiffMax,
		PassAbsLogprobDiffP95Max:    passAbsLogprobDiffP95Max,
		PassAbsLogprobDiffP99Max:    passAbsLogprobDiffP99Max,
		PassRankMismatchRateMax:     passRankMismatchRateMax,
		PassTopKJaccardMeanMin:      passTopKJaccardMeanMin,
		PassUnionJSP99Max:           passUnionJSP99Max,
		RejectMeanAbsLogprobDiffMin: rejectMeanAbsLogprobDiffMin,
		RejectAbsLogprobDiffP95Min:  rejectAbsLogprobDiffP95Min,
		RejectAbsLogprobDiffP99Min:  rejectAbsLogprobDiffP99Min,
		RejectRankMismatchRateMin:   rejectRankMismatchRateMin,
		RejectTopKJaccardMeanMax:    rejectTopKJaccardMeanMax,
		RejectUnionJSP99Min:         rejectUnionJSP99Min,
	}
}

func validateCheckpoint(data []byte, trace traceEnvelope) error {
	var checkpoint traceEnvelope
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		return fmt.Errorf("modelservice local verify: unmarshal checkpoint: %w", err)
	}
	if checkpoint.Output != trace.Output || !slices.Equal(checkpoint.InputTokenIDs, trace.InputTokenIDs) || len(checkpoint.OutTokens) != 0 {
		return fmt.Errorf("modelservice local verify: checkpoint does not match trace")
	}
	if trace.Generation == nil {
		return fmt.Errorf("trace generation context is required")
	}
	digest, err := trace.Generation.Digest()
	if err != nil {
		return err
	}
	if err := ValidateGenerationContext(checkpoint.Generation, digest[:], trace.ModelID, trace.ProfileVersion); err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	if checkpoint.ModelID != trace.ModelID || checkpoint.ProfileVersion != trace.ProfileVersion || checkpoint.GeneratedTokenCount != trace.GeneratedTokenCount ||
		checkpoint.InputTokenIDsHash != trace.InputTokenIDsHash || checkpoint.GeneratedTokenIDsHash != trace.GeneratedTokenIDsHash ||
		checkpoint.FinishReason != trace.FinishReason || !bytes.Equal(checkpoint.StopReason, trace.StopReason) {
		return fmt.Errorf("modelservice local verify: checkpoint metadata does not match trace")
	}
	return nil
}

func validateTraceProfile(req VerifyRequest, profile localModelProfile, trace traceEnvelope) error {
	if trace.ModelID != "" && req.ModelID != "" && trace.ModelID != req.ModelID {
		return fmt.Errorf("modelservice local verify: trace model_id %q does not match request model_id %q", trace.ModelID, req.ModelID)
	}
	if trace.ProfileVersion != "" && req.ProfileVersion != "" && trace.ProfileVersion != req.ProfileVersion {
		return fmt.Errorf("modelservice local verify: trace profile_version %q does not match request profile_version %q", trace.ProfileVersion, req.ProfileVersion)
	}
	if profile.Verification.RequireFinishReason && strings.TrimSpace(trace.FinishReason) == "" {
		return fmt.Errorf("modelservice local verify: trace missing finish reason")
	}
	if profile.Verification.RequireOutputTokenIDs && len(trace.OutTokens) != trace.GeneratedTokenCount {
		return fmt.Errorf("modelservice local verify: generated token count does not match trace")
	}
	if trace.InputTokenIDsHash != "" && trace.InputTokenIDsHash != hashTokenIDs(trace.InputTokenIDs) {
		return fmt.Errorf("modelservice local verify: input token ids hash mismatch")
	}
	if trace.GeneratedTokenIDsHash != "" && trace.GeneratedTokenIDsHash != hashGeneratedTokenIDs(trace.OutTokens) {
		return fmt.Errorf("modelservice local verify: generated token ids hash mismatch")
	}
	return nil
}

func topLogprobsAt(rows []map[string]float64, position int) map[string]float64 {
	if position < 0 || position >= len(rows) {
		return nil
	}
	return normalizeTopLogprobs(rows[position])
}

func promptTopLogprobsAt(rows []map[string]logprobEntry, position int) map[string]float64 {
	if position < 0 || position >= len(rows) {
		return nil
	}
	out := make(map[string]float64, len(rows[position]))
	for key, entry := range rows[position] {
		if !finite(entry.Logprob) {
			continue
		}
		out[normalizeTokenKey(key)] = entry.Logprob
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func limitTopLogprobs(in map[string]float64, limit int) map[string]float64 {
	in = normalizeTopLogprobs(in)
	if len(in) == 0 || limit <= 0 || len(in) <= limit {
		return in
	}
	type tokenScore struct {
		token   string
		logprob float64
	}
	scores := make([]tokenScore, 0, len(in))
	for token, logprob := range in {
		scores = append(scores, tokenScore{token: normalizeTokenKey(token), logprob: logprob})
	}
	sort.Slice(scores, func(i, j int) bool {
		if scores[i].logprob == scores[j].logprob {
			return scores[i].token < scores[j].token
		}
		return scores[i].logprob > scores[j].logprob
	})
	out := make(map[string]float64, limit)
	for i := 0; i < limit && i < len(scores); i++ {
		out[scores[i].token] = scores[i].logprob
	}
	return out
}

func recomputedEntryFor(tokenID int, position int, recomputed []map[string]logprobEntry) (logprobEntry, bool) {
	if position < 0 || position >= len(recomputed) {
		return logprobEntry{}, false
	}
	for _, key := range tokenKeyCandidates(tokenID) {
		if entry, ok := recomputed[position][key]; ok {
			return entry, true
		}
	}
	want := strconv.Itoa(tokenID)
	for key, entry := range recomputed[position] {
		if normalizeTokenKey(key) == want {
			return entry, true
		}
	}
	return logprobEntry{}, false
}

func rankForToken(tokenID int, topLogprobs map[string]float64) int {
	if len(topLogprobs) == 0 {
		return 0
	}
	type tokenScore struct {
		token   string
		logprob float64
	}
	scores := make([]tokenScore, 0, len(topLogprobs))
	for token, logprob := range topLogprobs {
		if finite(logprob) {
			scores = append(scores, tokenScore{token: normalizeTokenKey(token), logprob: logprob})
		}
	}
	sort.Slice(scores, func(i, j int) bool {
		if scores[i].logprob == scores[j].logprob {
			return scores[i].token < scores[j].token
		}
		return scores[i].logprob > scores[j].logprob
	})
	want := strconv.Itoa(tokenID)
	for i, score := range scores {
		if score.token == want {
			return i + 1
		}
	}
	return 0
}

func normalizeTopLogprobs(in map[string]float64) map[string]float64 {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]float64, len(in))
	for key, value := range in {
		if finite(value) {
			out[normalizeTokenKey(key)] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeTokenKey(key string) string {
	key = strings.TrimSpace(key)
	for _, prefix := range []string{"token_id:", "token_id=", "id:", "id="} {
		key = strings.TrimPrefix(key, prefix)
	}
	return strings.TrimSpace(key)
}

func tokenKeyCandidates(tokenID int) []string {
	id := strconv.Itoa(tokenID)
	return []string{id, "token_id:" + id, "token_id=" + id, "id:" + id, "id=" + id}
}

func topKJaccard(a, b map[string]float64) float64 {
	a = normalizeTopLogprobs(a)
	b = normalizeTopLogprobs(b)
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	union := make(map[string]struct{}, len(a)+len(b))
	for key := range a {
		union[normalizeTokenKey(key)] = struct{}{}
	}
	for key := range b {
		union[normalizeTokenKey(key)] = struct{}{}
	}
	if len(union) == 0 {
		return 1
	}
	intersection := 0
	for key := range union {
		_, inA := a[key]
		_, inB := b[key]
		if inA && inB {
			intersection++
		}
	}
	return float64(intersection) / float64(len(union))
}

func unionJSDivergence(a, b map[string]float64) (float64, bool) {
	a = normalizeTopLogprobs(a)
	b = normalizeTopLogprobs(b)
	keys := make(map[string]struct{}, len(a)+len(b))
	for key := range a {
		keys[normalizeTokenKey(key)] = struct{}{}
	}
	for key := range b {
		keys[normalizeTokenKey(key)] = struct{}{}
	}
	if len(keys) == 0 {
		return 0, false
	}
	aProb, aOK := normalizedProbabilities(a, keys)
	bProb, bOK := normalizedProbabilities(b, keys)
	if !aOK || !bOK {
		return 0, false
	}
	js := 0.0
	for key := range keys {
		p := aProb[key]
		q := bProb[key]
		m := 0.5 * (p + q)
		if p > 0 {
			js += 0.5 * p * math.Log(p/m)
		}
		if q > 0 {
			js += 0.5 * q * math.Log(q/m)
		}
	}
	return js, finite(js)
}

func normalizedProbabilities(logprobs map[string]float64, keys map[string]struct{}) (map[string]float64, bool) {
	out := make(map[string]float64, len(keys))
	total := 0.0
	for key := range keys {
		if logprob, ok := logprobs[key]; ok && finite(logprob) {
			p := math.Exp(logprob)
			out[key] = p
			total += p
		}
	}
	if total <= 0 || !finite(total) {
		return nil, false
	}
	for key, value := range out {
		out[key] = value / total
	}
	return out, true
}

func finite(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}

func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	total := 0.0
	for _, value := range values {
		total += value
	}
	return total / float64(len(values))
}

func percentile(values []float64, q float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	if q <= 0 {
		return sorted[0]
	}
	if q >= 1 {
		return sorted[len(sorted)-1]
	}
	index := int(math.Ceil(q*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func outputTokenPositions(n int) []int {
	if n == 0 {
		return nil
	}
	positions := make([]int, n)
	for i := range positions {
		positions[i] = i
	}
	return positions
}

func hashGeneratedTokenIDs(tokens []tokenLogprob) string {
	ids := make([]int, 0, len(tokens))
	for _, token := range tokens {
		ids = append(ids, token.TokenID)
	}
	return hashTokenIDs(ids)
}

func hashTokenIDs(ids []int) string {
	payload, _ := json.Marshal(ids)
	sum := codec.HashBytes(payload)
	return fmt.Sprintf("%x", sum[:])
}

func (s *LocalService) FetchArtifact(_ context.Context, req FetchArtifactRequest) (Artifact, error) {
	ref, err := ParseArtifactRef(req.Ref)
	if err != nil {
		return Artifact{}, err
	}
	if ref.ServiceID != s.serviceID {
		return Artifact{}, fmt.Errorf("%w: service id %q", ErrInvalidArtifactRef, ref.ServiceID)
	}
	if req.ModelServiceID != "" && req.ModelServiceID != s.serviceID {
		return Artifact{}, fmt.Errorf("%w: request model_service_id %q", ErrInvalidArtifactRef, req.ModelServiceID)
	}
	s.mu.RLock()
	data, ok := s.artifacts[ref.ArtifactID]
	s.mu.RUnlock()
	if !ok {
		return Artifact{}, ErrArtifactNotFound
	}
	if req.SizeLimitBytes > 0 && uint64(len(data)) > req.SizeLimitBytes {
		return Artifact{}, fmt.Errorf("%w: kind=%s, bound=%d, observed=%d", ErrArtifactSizeExceeded, req.Kind, req.SizeLimitBytes, len(data))
	}
	if err := verifyArtifactBytes(ref, data, req.AllowEmpty); err != nil {
		return Artifact{}, err
	}
	return Artifact{Ref: ref.String(), MediaType: "application/octet-stream", Data: append([]byte(nil), data...)}, nil
}

// PutArtifactForTest stores data as an artifact and returns its ref. This is a
// test-only seam kept out of the Service interface; the ForTest suffix marks it
// so production code never reaches for it.
func (s *LocalService) PutArtifactForTest(data []byte) string {
	return s.putArtifact(data)
}

func (s *LocalService) putArtifact(data []byte) string {
	ref := NewArtifactRef(s.serviceID, data)
	s.mu.Lock()
	s.artifacts[ref.ArtifactID] = append([]byte(nil), data...)
	s.mu.Unlock()
	return ref.String()
}

func (s *LocalService) resolveServedModel(ctx context.Context, modelID string) (string, error) {
	modelID = strings.TrimSpace(modelID)
	if modelID == "" {
		return "", fmt.Errorf("modelservice local: model_id is required to resolve a vLLM served model")
	}
	s.mu.RLock()
	if servedModel := strings.TrimSpace(s.aliases[modelID]); servedModel != "" {
		s.mu.RUnlock()
		return servedModel, nil
	}
	s.mu.RUnlock()

	models, err := s.listVLLMModels(ctx)
	if err != nil {
		return "", err
	}
	if len(models) == 0 {
		return "", fmt.Errorf("modelservice local: vLLM returned no served models")
	}
	s.rememberVLLMModelAliases(models)
	if servedModel := s.servedModelForAlias(modelID); servedModel != "" {
		return servedModel, nil
	}
	// Name the served models and the derivation, so an operator can tell a
	// misconfigured model id from a model registered outside the HuggingFace
	// scheme this derivation covers.
	return "", fmt.Errorf("modelservice local: model_id %q is not mapped to a vLLM served model; "+
		"vLLM serves [%s] and chain ids are derived as \"hf-\"+sha256(\"huggingface:\"+repo_id)",
		modelID, strings.Join(models, ", "))
}

// localHuggingFaceModelID derives the chain model id for a vLLM served model
// name. It reproduces the Node's derivation for HuggingFace-sourced models:
// sha256("huggingface:" + repo_id), rendered as "hf-<hex>".
//
// This is a protocol assumption, not a local convention -- it is what lets a
// node advertise the id handraise matches on without being told the mapping.
// It only covers HuggingFace repo ids. A model registered from another source,
// or any change to the Node's derivation, will not be matched here, and the
// node will simply not advertise it (see resolveServedModel for the error an
// operator sees).
func localHuggingFaceModelID(repoID string) string {
	repoID = strings.TrimSpace(repoID)
	if repoID == "" {
		return ""
	}
	if strings.HasPrefix(repoID, huggingFaceModelIDPrefix) && len(strings.TrimPrefix(repoID, huggingFaceModelIDPrefix)) == sha256.Size*2 {
		if _, err := hex.DecodeString(strings.TrimPrefix(repoID, huggingFaceModelIDPrefix)); err == nil {
			return repoID
		}
	}
	sum := sha256.Sum256([]byte(huggingFaceModelIDDomain + repoID))
	return huggingFaceModelIDPrefix + hex.EncodeToString(sum[:])
}

func normalizedServedModels(servedModels []string) []string {
	out := make([]string, 0, len(servedModels))
	seen := make(map[string]struct{}, len(servedModels))
	for _, servedModel := range servedModels {
		servedModel = strings.TrimSpace(servedModel)
		if servedModel == "" {
			continue
		}
		if _, ok := seen[servedModel]; ok {
			continue
		}
		seen[servedModel] = struct{}{}
		out = append(out, servedModel)
	}
	return out
}

// modelIDAllowed filters derived chain model ids down to the ones this node
// declares support for.
//
// An empty set means "no filter", not "allow nothing": LocalService is also
// constructed without configured ids in tests and by callers that have no
// registration to filter against. Production safety comes from the caller --
// BuildDependencies always passes the configured profiles, and real-mode config
// validation requires them -- rather than from this default.
func modelIDAllowed(modelID string, configured map[string]struct{}) bool {
	if len(configured) == 0 {
		return true
	}
	_, ok := configured[modelID]
	return ok
}

func (s *LocalService) configuredModelIDSet() map[string]struct{} {
	if len(s.configuredModelIDs) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(s.configuredModelIDs))
	for _, modelID := range s.configuredModelIDs {
		set[modelID] = struct{}{}
	}
	return set
}

func (s *LocalService) rememberVLLMModelAliases(servedModels []string) {
	servedModels = normalizedServedModels(servedModels)
	configured := s.configuredModelIDSet()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, servedModel := range servedModels {
		modelID := localHuggingFaceModelID(servedModel)
		if modelID == "" {
			continue
		}
		if !modelIDAllowed(modelID, configured) {
			continue
		}
		s.aliases[modelID] = servedModel
	}
}

func (s *LocalService) servedModelForAlias(modelID string) string {
	modelID = strings.TrimSpace(modelID)
	if modelID == "" {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return strings.TrimSpace(s.aliases[modelID])
}

func normalizeLocalBaseURL(raw string) string {
	base := strings.TrimRight(strings.TrimSpace(raw), "/")
	if base == "" {
		return defaultVLLMBaseURL
	}
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	return strings.TrimRight(base, "/")
}

func (s *LocalService) checkVLLMHealth(ctx context.Context) (*ServiceError, error) {
	ctx, cancel := s.withProbeTimeout(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/health", nil)
	if err != nil {
		return nil, fmt.Errorf("modelservice local health: create request: %w", err)
	}
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return &ServiceError{
			Code:      "VLLM_HEALTH_UNAVAILABLE",
			Message:   err.Error(),
			Retryable: true,
		}, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil, nil
	}
	detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	message := strings.TrimSpace(string(detail))
	if message == "" {
		message = resp.Status
	}
	return &ServiceError{
		Code:      "VLLM_HEALTH_UNHEALTHY",
		Message:   message,
		Retryable: resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500,
	}, nil
}

func (s *LocalService) listVLLMModels(ctx context.Context) ([]string, error) {
	ctx, cancel := s.withProbeTimeout(ctx)
	defer cancel()
	var resp modelListResponse
	if err := s.getJSON(ctx, "/v1/models", &resp); err != nil {
		return nil, err
	}
	models := make([]string, 0, len(resp.Data))
	seen := make(map[string]struct{}, len(resp.Data))
	for _, model := range resp.Data {
		id := strings.TrimSpace(model.ID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		models = append(models, id)
	}
	return models, nil
}

func (s *LocalService) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("modelservice local: create request %s: %w", path, err)
	}
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return retryableError{err: fmt.Errorf("modelservice local: request %s: %w", path, err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		err := fmt.Errorf("modelservice local: %s returned status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(detail)))
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return retryableError{err: err}
		}
		return err
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("modelservice local: decode response %s: %w", path, err)
	}
	return nil
}

// doPost issues the JSON POST and returns the response on a 2xx. The caller owns
// resp.Body and must close it. Transport failures and non-2xx statuses are mapped
// to the same (retryable) errors post has always returned, with the body drained
// and closed before returning.
func (s *LocalService) doPost(ctx context.Context, path string, body any) (*http.Response, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("modelservice local: marshal request %s: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("modelservice local: create request %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, retryableError{err: fmt.Errorf("modelservice local: request %s: %w", path, err)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		err := fmt.Errorf("modelservice local: %s returned status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(detail)))
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return nil, retryableError{err: err}
		}
		return nil, err
	}
	return resp, nil
}

func (s *LocalService) post(ctx context.Context, path string, body any, out any) error {
	resp, err := s.doPost(ctx, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("modelservice local: decode response %s: %w", path, err)
	}
	return nil
}

// postStreamingCompletion issues a streaming /v1/completions request and
// reassembles the server-sent events into out. The result must be byte-for-byte
// what a non-streaming decode would yield for the same generation, so nothing
// downstream can tell which transport was used. If the server did not actually
// stream (Content-Type is not text/event-stream -- a stub, or a vLLM that ignored
// stream:true), it falls back to the plain JSON decode.
func (s *LocalService) postStreamingCompletion(ctx context.Context, path string, body any, out *completionResponse, ident inferStreamIdentity) error {
	resp, err := s.doPost(ctx, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if !isEventStream(resp.Header.Get("Content-Type")) {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("modelservice local: decode response %s: %w", path, err)
		}
		return nil
	}
	return s.reassembleCompletionStream(ctx, resp.Body, out, ident)
}

// isEventStream reports whether a Content-Type header names text/event-stream,
// ignoring any charset/boundary parameters and case.
func isEventStream(contentType string) bool {
	mediaType := contentType
	if i := strings.IndexByte(mediaType, ';'); i >= 0 {
		mediaType = mediaType[:i]
	}
	return strings.EqualFold(strings.TrimSpace(mediaType), "text/event-stream")
}

// reassembleCompletionStream folds the SSE `data:` frames of a streaming
// completion into out, and emits each frame's delta to the per-frame observer
// (best-effort). Frames are accumulated so that out matches a non-streaming
// response: text concatenated, generated-token slices appended in order,
// prompt_token_ids taken once, finish_reason taken from the frame that carries it.
func (s *LocalService) reassembleCompletionStream(ctx context.Context, r io.Reader, out *completionResponse, ident inferStreamIdentity) error {
	observer := s.observerForRequest(ctx)
	observerActive := observer != nil

	scanner := bufio.NewScanner(r)
	// vLLM emits one JSON object per SSE frame; with top-k logprobs a frame can be
	// large, so raise the line limit well above bufio's 64 KiB default.
	scanner.Buffer(make([]byte, 0, 1<<20), 8<<20)

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" || strings.HasPrefix(line, ":") {
			// Blank separator or SSE comment/keepalive.
			continue
		}
		payload, ok := strings.CutPrefix(line, "data:")
		if !ok {
			// Ignore other SSE fields (event:, id:, retry:).
			continue
		}
		payload = strings.TrimSpace(payload)
		if payload == "[DONE]" {
			break
		}
		var chunk completionResponse
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			return fmt.Errorf("modelservice local: decode stream frame: %w", err)
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		cc := chunk.Choices[0]
		// Only a terminal frame's explicit null identifies EOS. Intermediate
		// nulls must not fill in stop metadata omitted by the terminal frame.
		if cc.FinishReason == "" && bytes.Equal(bytes.TrimSpace(cc.StopReason), []byte("null")) {
			cc.StopReason = nil
		}
		if len(out.Choices) == 0 {
			// Adopt the first frame wholesale (Text, TokenIDs, PromptTokenIDs,
			// Logprobs, FinishReason); later frames append their deltas.
			out.Choices = append(out.Choices, cc)
		} else {
			dst := &out.Choices[0]
			if dst.FinishReason != "" && (cc.Text != "" || len(cc.TokenIDs) > 0 || cc.FinishReason != "" && cc.FinishReason != dst.FinishReason) {
				return fmt.Errorf("modelservice local: stream continued after terminal finish reason")
			}
			dst.Text += cc.Text
			dst.TokenIDs = append(dst.TokenIDs, cc.TokenIDs...)
			if len(dst.PromptTokenIDs) == 0 && len(cc.PromptTokenIDs) > 0 {
				dst.PromptTokenIDs = cc.PromptTokenIDs
			}
			if cc.FinishReason != "" {
				dst.FinishReason = cc.FinishReason
			}
			if len(cc.StopReason) != 0 {
				if len(dst.StopReason) != 0 && !bytes.Equal(dst.StopReason, cc.StopReason) {
					return fmt.Errorf("modelservice local: conflicting stream stop_reason")
				}
				dst.StopReason = slices.Clone(cc.StopReason)
			}
			if src := cc.Logprobs; src != nil {
				if dst.Logprobs == nil {
					dst.Logprobs = &completionLogprobs{}
				}
				dst.Logprobs.Tokens = append(dst.Logprobs.Tokens, src.Tokens...)
				dst.Logprobs.TokenLogprobs = append(dst.Logprobs.TokenLogprobs, src.TokenLogprobs...)
				dst.Logprobs.TopLogprobs = append(dst.Logprobs.TopLogprobs, src.TopLogprobs...)
			}
			if len(cc.PromptLogprobs) > 0 {
				dst.PromptLogprobs = append(dst.PromptLogprobs, cc.PromptLogprobs...)
			}
		}
		if observerActive {
			frame := InferStreamFrame{
				RequestID:    ident.requestID,
				JobID:        ident.jobID,
				TaskID:       ident.taskID,
				ModelID:      ident.modelID,
				TextDelta:    cc.Text,
				TokenIDs:     cc.TokenIDs,
				FinishReason: cc.FinishReason,
			}
			if cc.Logprobs != nil {
				frame.TokenLogprobs = cc.Logprobs.TokenLogprobs
				frame.TopLogprobs = cc.Logprobs.TopLogprobs
			}
			if err := observer.ObserveInferFrame(ctx, frame); err != nil {
				// Best-effort: a failed downstream must not fail the committed
				// inference. Stop delivering, keep reassembling.
				observerActive = false
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("modelservice local: read completion stream: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	if observerActive {
		finish := ""
		if len(out.Choices) > 0 {
			finish = out.Choices[0].FinishReason
		}
		_ = observer.ObserveInferFrame(ctx, InferStreamFrame{
			RequestID:    ident.requestID,
			JobID:        ident.jobID,
			TaskID:       ident.taskID,
			ModelID:      ident.modelID,
			FinishReason: finish,
			Done:         true,
		})
	}
	return nil
}

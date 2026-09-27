package modelservice

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/identity"
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
	localVerifierID                     = "local-vllm-verifier-v1"
	defaultLocalRuntimeClass            = "CAUSAL_LM_PREFILL_LOGPROBS_V1"
	defaultLocalJudgmentFunctionVersion = "PREFILL_GENERATED_TOKEN_METRICS_V1"
	defaultLocalCanonicalEncoding       = "CANONICAL_OUTPUT_TEXT_V1"
	defaultLocalMetricProofVersion      = "PREFILL_METRIC_AGGREGATE_PROOF_V1"
	defaultLocalTokenScope              = "ALL_GENERATED_OUTPUT_TOKENS"
	defaultLocalNumericScale            = "FP_1E6"
)

// LocalService is an in-process model service that fulfils Infer/Verify by
// calling a local vLLM OpenAI-compatible /v1/completions endpoint. Produced
// artifacts (output, token ids, position values, verify sample sequence) are kept in an
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

	mu        sync.RWMutex
	artifacts map[string][]byte
	// models binds each chain model id this node serves to the repository vLLM
	// serves it under. The binding comes from the chain (ModelState provider and
	// repo_id), set by BindModel at startup: a model id is a hash over the
	// proposer too, so it cannot be derived from the served name.
	models map[string]string
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

func NewLocalService(baseURL, serviceID string, maxConcurrency uint32, inferTimeout, probeTimeout time.Duration) *LocalService {
	serviceID = strings.TrimSpace(serviceID)
	if serviceID == "" {
		serviceID = defaultLocalSvcID
	}
	if inferTimeout <= 0 {
		inferTimeout = 60 * time.Second
	}
	if probeTimeout <= 0 {
		probeTimeout = 5 * time.Second
	}
	return &LocalService{
		baseURL:         normalizeLocalBaseURL(baseURL),
		apiKey:          defaultVLLMAPIKey,
		serviceID:       serviceID,
		maxConcurrency:  maxConcurrency,
		http:            &http.Client{},
		artifacts:       make(map[string][]byte),
		models:          make(map[string]string),
		profiles:        make(map[string]localModelProfile),
		inferTimeout:    inferTimeout,
		probeTimeout:    probeTimeout,
		streamInference: true,
	}
}

// LocalModelProvider is the only source provider the local adapter serves:
// vLLM loads and names its models by Hugging Face repo id.
const LocalModelProvider = identity.ModelProviderHuggingFace

// BindModel records that modelID is served by vLLM under repoID, the model's
// on-chain repo_id. provider is the model's on-chain source provider and must
// be LocalModelProvider. Only bound models are advertised or served.
func (s *LocalService) BindModel(modelID, provider, repoID string) error {
	if provider != LocalModelProvider {
		return fmt.Errorf("modelservice local: model %s has source provider %q; the local adapter serves only %s",
			modelID, provider, LocalModelProvider)
	}
	if strings.TrimSpace(modelID) != modelID || modelID == "" || strings.TrimSpace(repoID) != repoID || repoID == "" {
		return fmt.Errorf("modelservice local: model binding %q -> %q must be non-empty and trimmed", modelID, repoID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if bound, ok := s.models[modelID]; ok && bound != repoID {
		return fmt.Errorf("modelservice local: model %s is already bound to %s", modelID, bound)
	}
	s.models[modelID] = repoID
	return nil
}

// CheckServed reports whether vLLM currently serves the repository modelID is
// bound to. An unbound model or an unserved repository is an error.
func (s *LocalService) CheckServed(ctx context.Context, modelID string) error {
	ctx, cancel := s.withProbeTimeout(ctx)
	defer cancel()
	_, err := s.resolveServedModel(ctx, modelID)
	return err
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
	TopLogprobs   []TopLogprobRow
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
	Tokens        []string        `json:"tokens"`
	TokenLogprobs []float64       `json:"token_logprobs"`
	TopLogprobs   []TopLogprobRow `json:"top_logprobs"`
	// absent marks positions whose token_logprobs entry vLLM wrote as null.
	// Such a position has no value; nil means every entry was present.
	absent []bool
}

// UnmarshalJSON reads token_logprobs entries that may be null.
func (l *completionLogprobs) UnmarshalJSON(data []byte) error {
	var raw struct {
		Tokens        []string        `json:"tokens"`
		TokenLogprobs []*float64      `json:"token_logprobs"`
		TopLogprobs   []TopLogprobRow `json:"top_logprobs"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*l = completionLogprobs{Tokens: raw.Tokens, TopLogprobs: raw.TopLogprobs}
	if raw.TokenLogprobs != nil {
		l.TokenLogprobs = make([]float64, len(raw.TokenLogprobs))
	}
	for i, logprob := range raw.TokenLogprobs {
		if logprob == nil {
			if l.absent == nil {
				l.absent = make([]bool, len(raw.TokenLogprobs))
			}
			l.absent[i] = true
			continue
		}
		l.TokenLogprobs[i] = *logprob
	}
	return nil
}

// logprobAbsent reports whether position i's token logprob was null.
func (l *completionLogprobs) logprobAbsent(i int) bool {
	return i < len(l.absent) && l.absent[i]
}

// appendFrom appends one streamed chunk's logprobs, keeping the null marks
// aligned with token_logprobs.
func (l *completionLogprobs) appendFrom(src *completionLogprobs) {
	if src.absent != nil {
		for len(l.absent) < len(l.TokenLogprobs) {
			l.absent = append(l.absent, false)
		}
		l.absent = append(l.absent, src.absent...)
		for len(l.absent) < len(l.TokenLogprobs)+len(src.TokenLogprobs) {
			l.absent = append(l.absent, false)
		}
	}
	l.Tokens = append(l.Tokens, src.Tokens...)
	l.TokenLogprobs = append(l.TokenLogprobs, src.TokenLogprobs...)
	l.TopLogprobs = append(l.TopLogprobs, src.TopLogprobs...)
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
}

type localSamplingProfile struct {
	Temperature       float64
	TopP              float64
	TopK              int
	Seed              int
	Logprobs          int
	PromptLogprobs    int
	SkipSpecialTokens bool
}

type localVerificationProfile struct {
	ProfileID                   int
	JudgmentFunctionVersion     string
	CanonicalEncodingVersion    string
	MetricAggregateProofVersion string
	TokenScope                  string
	IncludeGeneratedSpecial     bool
	IncludePromptTokens         bool
	IncludePaddingTokens        bool
	RequireOutputTokenIDs       bool
	RequireFinishReason         bool
	ComparedTopK                int
	NumericScale                string
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
			ModelID:                modelID,
			Capability:             CapabilityLLMTextV1,
			SupportsTokenIDs:       true,
			SupportsPositionValues: true,
			SupportsBatchLog:       true,
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

// capabilityModelIDs lists the bound models whose repository vLLM serves.
func (s *LocalService) capabilityModelIDs(servedModels []string) []string {
	served := make(map[string]struct{}, len(servedModels))
	for _, model := range normalizedServedModels(servedModels) {
		served[model] = struct{}{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	modelIDs := make([]string, 0, len(s.models))
	for modelID, repoID := range s.models {
		if _, ok := served[repoID]; ok {
			modelIDs = append(modelIDs, modelID)
		}
	}
	slices.Sort(modelIDs)
	return modelIDs
}

func (s *LocalService) LoadModel(ctx context.Context, req LoadModelRequest) (LoadModelResponse, error) {
	if err := validateCapability(req.Capability); err != nil {
		return LoadModelResponse{}, err
	}
	if _, err := s.resolveServedModel(ctx, req.ModelID); err != nil {
		return LoadModelResponse{}, err
	}
	return LoadModelResponse{
		RequestID:      req.RequestID,
		ModelServiceID: s.serviceID,
		ModelID:        req.ModelID,
		Loaded:         true,
	}, nil
}

func (s *LocalService) Estimate(_ context.Context, req EstimateRequest) (EstimateResponse, error) {
	if err := validateCapability(req.Capability); err != nil {
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
			Temperature:       0,
			TopP:              defaultTopP,
			TopK:              defaultTopKSample,
			Seed:              defaultSeed,
			Logprobs:          defaultTopK,
			PromptLogprobs:    defaultTopK,
			SkipSpecialTokens: false,
		},
		Verification: localVerificationProfile{
			ProfileID:                   1,
			JudgmentFunctionVersion:     defaultLocalJudgmentFunctionVersion,
			CanonicalEncodingVersion:    defaultLocalCanonicalEncoding,
			MetricAggregateProofVersion: defaultLocalMetricProofVersion,
			TokenScope:                  defaultLocalTokenScope,
			IncludeGeneratedSpecial:     true,
			IncludePromptTokens:         false,
			IncludePaddingTokens:        false,
			RequireOutputTokenIDs:       true,
			RequireFinishReason:         true,
			ComparedTopK:                defaultTopK,
			NumericScale:                defaultLocalNumericScale,
		},
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

	// The chain judges the summary against these thresholds; Node cannot judge
	// an all-zero set, because its pass and reject bounds always overlap, so a
	// profile without them is refused rather than served.
	if !currentProfileThresholdsPresent(snapshot.VerificationThresholds) {
		return localModelProfile{}, fmt.Errorf("resolved model profile %s@%s has no verification_thresholds", profile.ModelID, profile.ProfileVersion)
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

func normalizeCurrentProfileEnum(value, prefix string) string {
	return strings.TrimPrefix(strings.TrimSpace(value), prefix)
}

// inferV0 is the original raw-text generation path: it sends req.Input verbatim
// as a /v1/completions prompt. It is retained for the legacy llm_text_v1 shape
// and is dispatched to by Infer (local_chat.go) when the input is not a chat
// payload.
func (s *LocalService) inferV0(ctx context.Context, req InferRequest) (InferResponse, error) {
	if err := validateCapability(req.Capability); err != nil {
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
	// max_output_duration is a generation budget, not a transport timeout, and
	// the two need different behaviour at expiry. The budget ends the generation
	// SUCCESSFULLY -- the tokens produced so far are committed and the finish
	// reason is max_output_duration, which the frozen set admits. A transport
	// timeout fails the call.
	//
	// They used to be one context deadline, so an over-budget run discarded
	// everything and MAX_OUTPUT_DURATION could never be produced at all, despite
	// being in the closed successful-termination set.
	//
	// The budget begins before the engine call, so queue and network time still
	// consume it. Only the streaming transport can honour it: a unary body
	// arrives whole or not at all.
	//
	// budgetGrace keeps a context deadline behind the budget so an engine that
	// has stopped sending is still a failure rather than a hang. Truncation is
	// checked between frames, so the clean stop wins whenever frames are still
	// arriving.
	budgetAt := time.Now().Add(duration)
	ctx, cancel := context.WithDeadline(ctx, budgetAt.Add(budgetGrace))
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
			if err := s.postStreamingCompletion(ctx, "/v1/completions", genReq, &resp, ident, budgetAt); err != nil {
				return InferResponse{}, err
			}
		} else if err := s.post(ctx, "/v1/completions", genReq, &resp); err != nil {
			return InferResponse{}, err
		}
	}
	if err := ctx.Err(); err != nil && !budgetStopped(&resp) {
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

// buildInferResultFromCompletion turns a decoded /v1/completions response (or a
// chat response projected onto the same shape) into the InferResponse plus the
// stored output, token-id and position-value artifacts. It is shared by inferV0
// and the chat path so both produce byte-identical material and the Verifier
// sees one shape regardless of which endpoint generated the tokens.
//
// outputBytes is the artifact to commit and deliver as the output. Pass nil to
// commit the raw generated text (choice.Text).
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
	// A generation stopped before its first token has no logprobs block.
	if len(choice.TokenIDs) > 0 && (choice.Logprobs == nil || len(choice.Logprobs.TokenLogprobs) != len(choice.TokenIDs)) {
		return InferResponse{}, fmt.Errorf("modelservice local infer: generated token logprobs are incomplete")
	}
	finishReason, err := resolveFinish(choice.FinishReason, choice.StopReason, uint64(len(choice.TokenIDs)))
	if err != nil {
		return InferResponse{}, err
	}

	inputIDs, err := tokenIDsUint32("prompt_token_ids", choice.PromptTokenIDs)
	if err != nil {
		return InferResponse{}, fmt.Errorf("modelservice local infer: %w", err)
	}
	generatedIDs, err := tokenIDsUint32("token_ids", choice.TokenIDs)
	if err != nil {
		return InferResponse{}, fmt.Errorf("modelservice local infer: %w", err)
	}
	values := make([]metric.PositionValue, len(generatedIDs))
	for i, id := range generatedIDs {
		var row TopLogprobRow
		if i < len(choice.Logprobs.TopLogprobs) {
			row = choice.Logprobs.TopLogprobs[i]
		}
		// A position the engine reported no logprob or no top-k for has no
		// value: it becomes a missing leaf rather than a refusal.
		if choice.Logprobs.logprobAbsent(i) || len(row) == 0 {
			values[i] = metric.PositionValue{TokenID: id, Missing: true}
			continue
		}
		topK, err := completionTopK(i, id, row, profile.RequiredTopK)
		if err != nil {
			return InferResponse{}, fmt.Errorf("modelservice local infer: %w", err)
		}
		values[i] = metric.PositionValue{TokenID: id, Logprob: choice.Logprobs.TokenLogprobs[i], Rank: rankIn(id, topK), TopK: topK}
	}
	ids := TokenIDs{Input: inputIDs, Generated: generatedIDs}
	// The chain-bound generation contract is re-derived here for both paths: the
	// raw-text path (inferV0) and the chat path (Infer) each carry and validate
	// req.Generation, so the material is checked against the frozen parameters
	// regardless of which endpoint generated the tokens.
	if req.Generation != nil {
		if _, err := ValidateGenerationMaterial(req.Generation, req.GenerationParamsDigest, ids, values); err != nil {
			return InferResponse{}, err
		}
	}
	tokenIDsBytes, err := EncodeTokenIDsArtifact(ids)
	if err != nil {
		return InferResponse{}, fmt.Errorf("modelservice local infer: encode token ids: %w", err)
	}
	positionValuesBytes, err := EncodePositionValuesArtifact(values)
	if err != nil {
		return InferResponse{}, fmt.Errorf("modelservice local infer: encode position values: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return InferResponse{}, err
	}

	if outputBytes == nil {
		outputBytes = []byte(choice.Text)
	}
	outputRef := s.putArtifact(outputBytes)
	tokenIDsRef := s.putArtifact(tokenIDsBytes)
	positionValuesRef := s.putArtifact(positionValuesBytes)
	generatedTokenCount := uint64(len(generatedIDs))

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
		TokenIDsRef:            tokenIDsRef,
		PositionValuesRef:      positionValuesRef,
		GeneratedTokenCount:    generatedTokenCount,
		WorkUnit:               generatedTokenCount,
		FinishReason:           finishReason,
	}, nil
}

// Verify re-runs the Worker's committed token IDs as a prefill and reports the
// verifier's own value at every generated position. It never sees the Worker's
// values: comparing the two, and everything derived from the comparison, is
// Cortex's job.
//
// One check data-plane-and-evidence-transfer.md §9.1 names is deliberately NOT
// here yet: `detokenize(token IDs) == text`. The Verifier binds the text to
// `output_hash` and the token vectors to the A-level commitment, so what is
// missing is only the tokenizer call, and it is missing for a reason rather
// than by oversight: the engine does not render the stop-triggering token into
// the text (measured on vLLM 0.25.1 / Qwen/Qwen3-8B: the returned IDs end in
// 151645, the text does not, with skip_special_tokens=false), so a straight
// comparison fails every normal EOS completion. Dropping the final token to
// make it pass is what must not be done without first establishing that
// token's identity, and this deployment exposes no authority for it --
// `/tokenizer_info` answers 404, and the task's frozen generation params carry
// only the *configured* StopTokenIDs, never the model's own EOS. Landing that
// check needs an EOS-identity source decided first, not a looser comparison.
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
	if err := validateVerifyRequest(req); err != nil {
		return VerifyResponse{}, err
	}
	if uint64(len(req.TokenIDs.Generated)) > req.Generation.Params.MaxOutputTokens {
		return VerifyResponse{}, Deterministic(FaultCodeTokenBudgetExceeded,
			fmt.Errorf("Worker generated token count exceeds the order's max_output_tokens"),
			FaultInt("generated_token_count", len(req.TokenIDs.Generated)), FaultUint("max_output_tokens", req.Generation.Params.MaxOutputTokens))
	}
	profile, err := s.resolveLocalProfile(ctx, req.ModelID, req.ProfileVersion)
	if err != nil {
		return VerifyResponse{}, err
	}

	inputLen := len(req.TokenIDs.Input)
	prompt := make([]int, 0, inputLen+len(req.TokenIDs.Generated))
	for _, id := range req.TokenIDs.Input {
		prompt = append(prompt, int(id))
	}
	for _, id := range req.TokenIDs.Generated {
		prompt = append(prompt, int(id))
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
		ReturnTokenIDs:         true,
		ReturnTokensAsTokenIDs: true,
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
	values := make([]metric.PositionValue, len(req.TokenIDs.Generated))
	for i, id := range req.TokenIDs.Generated {
		value := metric.PositionValue{TokenID: id, Missing: true}
		if row := inputLen + i; row < len(recomputed) {
			ordered, byID, err := promptTopK(row, recomputed[row])
			if err != nil {
				return VerifyResponse{}, fmt.Errorf("modelservice local verify: %w", err)
			}
			value.TopK = ordered
			if entry, ok := byID[id]; ok && entry.Rank >= 0 {
				value.Missing, value.Logprob, value.Rank = false, entry.Logprob, uint32(entry.Rank)
			}
		}
		values[i] = value
	}
	sequenceBytes, err := EncodePositionValuesArtifact(values)
	if err != nil {
		return VerifyResponse{}, fmt.Errorf("modelservice local verify: encode verifier values: %w", err)
	}
	sequenceRef := s.putArtifact(sequenceBytes)
	tokenMaterial, err := EncodeTokenIDsArtifact(req.TokenIDs)
	if err != nil {
		return VerifyResponse{}, err
	}
	sampleDigest := codec.HashBytes(req.Sample)
	materialDigest := codec.HashWithDomain("CORTEX_LOCAL_VERIFY_MATERIAL_V2", req.Sample, tokenMaterial)

	return VerifyResponse{
		RequestID:              req.RequestID,
		ModelServiceID:         s.serviceID,
		JobID:                  req.JobID,
		TaskID:                 req.TaskID,
		ModelID:                req.ModelID,
		ProfileVersion:         req.ProfileVersion,
		RequestDigest:          req.RequestDigest,
		GenerationParamsDigest: slices.Clone(req.GenerationParamsDigest),
		VerifierID:             localVerifierID,
		SampleValueSequenceRef: sequenceRef,
		SampleDigest:           sampleDigest[:],
		MaterialDigest:         materialDigest[:],
		VerifierValues:         values,
	}, nil
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
	repoID, bound := s.models[modelID]
	s.mu.RUnlock()
	if !bound {
		return "", fmt.Errorf("modelservice local: model_id %s is not bound to a repository; bind it from its chain ModelState first", modelID)
	}
	models, err := s.listVLLMModels(ctx)
	if err != nil {
		return "", err
	}
	if !slices.Contains(normalizedServedModels(models), repoID) {
		return "", fmt.Errorf("modelservice local: model %s is registered for %s, but vLLM serves [%s]", modelID, repoID, strings.Join(models, ", "))
	}
	return repoID, nil
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
func (s *LocalService) postStreamingCompletion(ctx context.Context, path string, body any, out *completionResponse, ident inferStreamIdentity, budget time.Time) error {
	resp, err := s.doPost(ctx, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if !isEventStream(resp.Header.Get("Content-Type")) {
		// A unary body arrives whole or not at all, so there is nothing to
		// truncate: the budget can only fail this call, which the caller's
		// context deadline already does.
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("modelservice local: decode response %s: %w", path, err)
		}
		return nil
	}
	return s.reassembleCompletionStream(ctx, resp.Body, out, ident, budget)
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

// budgetGrace is how long after max_output_duration the context deadline sits.
// It exists so an engine that has gone silent still fails instead of hanging,
// while leaving the clean between-frames truncation to win in every case where
// frames are still arriving. It is deliberately short: it is a backstop for a
// dead connection, not additional generation time.
const budgetGrace = 5 * time.Second

// finishReasonMaxOutputDuration is the finish_reason this node fills in when it
// stops a generation at max_output_duration. It is spelled the same way the
// gRPC model-service contract spells it (see finishReasonV1FromString) so one
// string means one thing across both transports; no engine ever sends it.
const finishReasonMaxOutputDuration = "max_output_duration"

// budgetStopped reports whether this node, rather than the engine, ended the
// generation.
func budgetStopped(out *completionResponse) bool {
	return len(out.Choices) > 0 && out.Choices[0].FinishReason == finishReasonMaxOutputDuration
}

// reassembleCompletionStream folds the SSE `data:` frames of a streaming
// completion into out, and emits each frame's delta to the per-frame observer
// (best-effort). Frames are accumulated so that out matches a non-streaming
// response: text concatenated, generated-token slices appended in order,
// prompt_token_ids taken once, finish_reason taken from the frame that carries it.
//
// budget, when non-zero, is the wall-clock deadline max_output_duration sets. It
// is checked between whole frames, so what it stops is always a complete token
// with its logprobs: the committed text is decoded from the token ids, and half
// a frame would leave those two disagreeing. Stopping this way is a SUCCESSFUL
// termination -- the reason is filled in as max_output_duration and the tokens
// collected so far are committed -- which is why it is the budget and not a
// context cancellation. The caller keeps a later context deadline as the
// backstop for an engine that has stopped sending at all; that one still fails.
func (s *LocalService) reassembleCompletionStream(ctx context.Context, r io.Reader, out *completionResponse, ident inferStreamIdentity, budget time.Time) error {
	observer := s.observerForRequest(ctx)
	observerActive := observer != nil
	overBudget := func() bool { return !budget.IsZero() && !time.Now().Before(budget) }

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
				dst.Logprobs.appendFrom(src)
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
		// Checked after the frame is folded in, never in the middle of one: the
		// budget truncates the generation, not a token.
		if overBudget() && out.Choices[0].FinishReason == "" {
			out.Choices[0].FinishReason = finishReasonMaxOutputDuration
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("modelservice local: read completion stream: %w", err)
	}
	// A budget stop is a result, so it must not be overwritten by the context
	// error that the abandoned response body produces as it is closed.
	if err := ctx.Err(); err != nil && !budgetStopped(out) {
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

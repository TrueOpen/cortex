package modelservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/metric"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

const (
	ArtifactScheme      = "cortex-artifact"
	CapabilityLLMTextV1 = "llm_text_v1"
)

var (
	ErrInvalidArtifactRef     = errors.New("invalid artifact ref")
	ErrArtifactNotFound       = errors.New("artifact not found")
	ErrArtifactDigestMismatch = errors.New("artifact digest mismatch")
	ErrArtifactSizeMismatch   = errors.New("artifact size mismatch")
	ErrArtifactSizeExceeded   = errors.New("artifact size limit exceeded")
	ErrEmptyArtifact          = errors.New("empty artifact")
	ErrUnsupportedCapability  = errors.New("unsupported capability")
)

type ArtifactRef struct {
	Scheme       string
	ServiceID    string
	ArtifactID   string
	DigestSHA256 string
	SizeBytes    int64
}

func NewArtifactRef(serviceID string, data []byte) ArtifactRef {
	digest := codec.HashBytes(data)
	return ArtifactRef{
		Scheme:       ArtifactScheme,
		ServiceID:    serviceID,
		ArtifactID:   hex.EncodeToString(digest[:]),
		DigestSHA256: hex.EncodeToString(digest[:]),
		SizeBytes:    int64(len(data)),
	}
}

func verifyArtifactBytes(ref ArtifactRef, data []byte, allowEmpty bool) error {
	if len(data) == 0 && !allowEmpty {
		return ErrEmptyArtifact
	}
	if int64(len(data)) != ref.SizeBytes {
		return ErrArtifactSizeMismatch
	}
	got := NewArtifactRef(ref.ServiceID, data)
	if got.DigestSHA256 != ref.DigestSHA256 {
		return ErrArtifactDigestMismatch
	}
	return nil
}

func ParseArtifactRef(raw string) (ArtifactRef, error) {
	if strings.TrimSpace(raw) == "" {
		return ArtifactRef{}, fmt.Errorf("%w: empty ref", ErrInvalidArtifactRef)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ArtifactRef{}, fmt.Errorf("%w: %v", ErrInvalidArtifactRef, err)
	}
	if u.Scheme != ArtifactScheme {
		return ArtifactRef{}, fmt.Errorf("%w: scheme %q", ErrInvalidArtifactRef, u.Scheme)
	}
	if u.Host == "" {
		return ArtifactRef{}, fmt.Errorf("%w: missing service id", ErrInvalidArtifactRef)
	}
	if u.Path == "" || u.Path == "/" {
		return ArtifactRef{}, fmt.Errorf("%w: missing artifact id", ErrInvalidArtifactRef)
	}
	if strings.Contains(u.Path, "..") || path.Clean(u.Path) != u.Path {
		return ArtifactRef{}, fmt.Errorf("%w: unsafe artifact path", ErrInvalidArtifactRef)
	}
	artifactID := strings.TrimPrefix(u.Path, "/")
	if strings.Contains(artifactID, "/") || strings.HasPrefix(artifactID, ".") {
		return ArtifactRef{}, fmt.Errorf("%w: unsafe artifact id", ErrInvalidArtifactRef)
	}
	digest := u.Query().Get("digest")
	if digest == "" {
		digest = artifactID
	}
	if len(digest) != sha256.Size*2 {
		return ArtifactRef{}, fmt.Errorf("%w: invalid digest length", ErrInvalidArtifactRef)
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return ArtifactRef{}, fmt.Errorf("%w: invalid digest", ErrInvalidArtifactRef)
	}
	size, err := strconv.ParseInt(u.Query().Get("size"), 10, 64)
	if err != nil || size < 0 {
		return ArtifactRef{}, fmt.Errorf("%w: invalid size", ErrInvalidArtifactRef)
	}
	return ArtifactRef{
		Scheme:       u.Scheme,
		ServiceID:    u.Host,
		ArtifactID:   artifactID,
		DigestSHA256: strings.ToLower(digest),
		SizeBytes:    size,
	}, nil
}

func (r ArtifactRef) String() string {
	q := url.Values{}
	q.Set("size", strconv.FormatInt(r.SizeBytes, 10))
	if r.DigestSHA256 != "" && r.DigestSHA256 != r.ArtifactID {
		q.Set("digest", r.DigestSHA256)
	}
	u := url.URL{
		Scheme:   r.Scheme,
		Host:     r.ServiceID,
		Path:     "/" + r.ArtifactID,
		RawQuery: q.Encode(),
	}
	return u.String()
}

type HealthRequest struct {
	RequestID      string
	ModelServiceID string
	DeadlineMS     int64
}

type HealthResponse struct {
	RequestID      string
	ModelServiceID string
	Healthy        bool
	Error          *ServiceError
}

type ListCapabilitiesRequest struct {
	RequestID       string
	ModelServiceID  string
	DeadlineMS      int64
	IncludeUnloaded bool
	RegistryFilter  string
	ReadinessLevel  string
}

type ListCapabilitiesResponse struct {
	RequestID                  string
	ModelServiceID             string
	ModelManagementAPIVersions []string
	Capabilities               []ManagedModelCapability
	ResourceSnapshot           ResourceSnapshot
	Error                      *ServiceError
}

type ManagedModelCapability struct {
	ModelID            string
	Capability         string
	SupportsTrace      bool
	SupportsCheckpoint bool
	SupportsBatchLog   bool
}

type GetModelDetailsRequest struct {
	RequestID      string
	ModelServiceID string
	DeadlineMS     int64
	ModelID        string
}

type GetModelDetailsResponse struct {
	RequestID      string
	ModelServiceID string
	Details        ModelDetails
	Error          *ServiceError
}

type ModelDetails struct {
	Artifacts          ModelArtifacts
	Derivation         ModelDerivation
	Identity           ModelIdentity
	Metadata           ModelMetadata
	ModelConfigSummary ModelConfigSummary
	ModelDir           string
	ModelRef           string
	Source             ModelSource
}

type ModelArtifacts struct {
	ChatTemplateHash     string
	FileManifestHash     string
	Files                []ModelArtifactFile
	GenerationConfigHash string
	ModelConfigHash      string
	ModelWeightDigest    string
	QuantConfigHash      string
	TokenizerConfigHash  string
	TokenizerHash        string
}

type ModelArtifactFile struct {
	Digest    string
	Path      string
	Role      string
	SizeBytes uint64
}

type ModelDerivation struct {
	ArtifactSources ModelArtifactSources
	Warnings        []string
}

type ModelArtifactSources struct {
	ChatTemplateSource   string
	ConfigPath           string
	GenerationConfigPath string
	QuantConfigSource    string
	TokenizerConfigPath  string
	TokenizerPaths       []string
	WeightPaths          []string
}

type ModelIdentity struct {
	DisplayName string
	ModelID     string
}

type ModelMetadata struct {
	LicenseFiles []string
	LicenseRef   string
}

type ModelConfigSummary struct {
	ActiveParams  uint64
	Architecture  string
	ContextLength uint64
	Modality      []string
	MOE           ModelMOESummary
	Quantization  ModelQuantizationSummary
	TotalParams   uint64
}

type ModelMOESummary struct {
	Enabled          bool
	NumExperts       uint64
	NumExpertsPerTok uint64
}

type ModelQuantizationSummary struct {
	Bits   uint64
	Method string
}

type ModelSource struct {
	Provider        string
	RepoID          string
	RepoType        string
	ResolverVersion string
	Revision        string
	SourceURI       string
}

type ResourceSnapshot struct {
	LoadedModels   int
	QueueDepth     uint32
	MaxConcurrency uint32
}

func (s ResourceSnapshot) AvailableSlots() (int, error) {
	if s.MaxConcurrency == 0 {
		return 0, fmt.Errorf("model service max concurrency is required")
	}
	if s.QueueDepth > s.MaxConcurrency {
		return 0, fmt.Errorf("model service queue depth exceeds max concurrency")
	}
	available := s.MaxConcurrency - s.QueueDepth
	if uint64(available) > uint64(^uint(0)>>1) {
		return 0, fmt.Errorf("model service available slots exceed platform int range")
	}
	return int(available), nil
}

type LoadModelRequest struct {
	RequestID      string
	ModelServiceID string
	DeadlineMS     int64
	ModelID        string
	Capability     string
}

type LoadModelResponse struct {
	RequestID      string
	ModelServiceID string
	ModelID        string
	Loaded         bool
	Error          *ServiceError
}

type EstimateRequest struct {
	RequestID      string
	ModelServiceID string
	DeadlineMS     int64
	ModelID        string
	Capability     string
	InputBytes     int64
}

type EstimateResponse struct {
	RequestID      string
	ModelServiceID string
	EstimatedMS    int64
	EstimatedBytes int64
	Error          *ServiceError
}

type InferRequest struct {
	RequestID              string
	ModelServiceID         string
	DeadlineMS             int64
	JobID                  string
	TaskID                 string
	ModelID                string
	ProfileVersion         string
	RequestDigest          []byte
	Capability             string
	Input                  []byte
	Generation             *nodewire.GenerationContext
	GenerationParamsDigest []byte
}

type InferResponse struct {
	RequestID              string
	ModelServiceID         string
	JobID                  string
	TaskID                 string
	ModelID                string
	ProfileVersion         string
	RequestDigest          []byte
	GenerationParamsDigest []byte
	OutputRef              string
	TraceRef               string
	CheckpointRef          string
	Error                  *ServiceError
	GeneratedTokenCount    uint64
	WorkUnit               uint64
	// FinishReason is the model service's completion finish reason, already
	// mapped to the nodewire.FinishReasonV1 enum.
	FinishReason nodewire.FinishReasonV1
}

// EvidenceKindWorkerValueOpening is the only evidence kind currently supported by
// the model service verification interface. It corresponds to the frozen enum
// value EVIDENCE_KIND_WORKER_VALUE_OPENING.
const EvidenceKindWorkerValueOpening = "EVIDENCE_KIND_WORKER_VALUE_OPENING"

type VerifyEvidence struct {
	Trace            []byte
	Checkpoint       []byte
	ExpectedRoot     []byte
	EncodedSizeBytes uint64
}

type EvidenceRequirement struct {
	Kind             string
	ExpectedRoot     []byte
	EncodedSizeBytes uint64
}

type VerifyRequest struct {
	RequestID              string
	ModelServiceID         string
	DeadlineMS             int64
	JobID                  string
	TaskID                 string
	ModelID                string
	ProfileVersion         string
	RequestDigest          []byte
	Capability             string
	Sample                 []byte
	Evidence               map[string]VerifyEvidence
	RequiredEvidence       []EvidenceRequirement
	Generation             *nodewire.GenerationContext
	GenerationParamsDigest []byte
}

type VerifyResponse struct {
	RequestID                      string
	ModelServiceID                 string
	JobID                          string
	TaskID                         string
	ModelID                        string
	ProfileVersion                 string
	RequestDigest                  []byte
	GenerationParamsDigest         []byte
	VerifierID                     string
	MainMismatchCount              int
	SelectedPositionsOrCheckpoints []int
	SampleValueSequenceRef         string
	SampleDigest                   []byte
	MaterialDigest                 []byte
	// MetricSamples is the verifier's prefill/teacher-forcing comparison at
	// every generated token position, in output_position order starting at zero.
	// It is the input to the metric Merkle tree whose root the frozen result
	// credential carries as metric_root.
	//
	// It carries no verdict, here or anywhere downstream: keeper §9.7 judgment
	// layer 2 recomputes PASS/REJECT on chain and "must not accept a verdict field
	// carried by the Verifier itself". MainMismatchCount stays what it has always
	// been - a local diagnostic that reaches no preimage.
	//
	// There is deliberately NO aggregate field beside it. MetricSummaryV1 is
	// derived from these samples by metric.AggregateFromSamples, so root and
	// summary provably describe the same data; a second channel carrying the
	// aggregation would let a model service hand over honest samples and a
	// summary about something else, and nothing downstream could catch it.
	MetricSamples []metric.Sample
	Error         *ServiceError
}

type FetchArtifactRequest struct {
	RequestID      string
	ModelServiceID string
	DeadlineMS     int64
	Ref            string
	AllowEmpty     bool
	// SizeLimitBytes, if non-zero, is the maximum bytes the caller is willing
	// to receive. The transport must abort as soon as the next chunk would
	// exceed this bound.
	SizeLimitBytes uint64
	// Kind is an optional caller label (e.g. the evidence kind) used in error
	// messages when SizeLimitBytes is exceeded.
	Kind string
}

type Artifact struct {
	Ref       string
	MediaType string
	Data      []byte
}

type ServiceError struct {
	Code      string
	Message   string
	Retryable bool
}

type Client interface {
	Health(context.Context, HealthRequest) (HealthResponse, error)
	ListCapabilities(context.Context, ListCapabilitiesRequest) (ListCapabilitiesResponse, error)
	GetModelDetails(context.Context, GetModelDetailsRequest) (GetModelDetailsResponse, error)
	LoadModel(context.Context, LoadModelRequest) (LoadModelResponse, error)
	Estimate(context.Context, EstimateRequest) (EstimateResponse, error)
	Infer(context.Context, InferRequest) (InferResponse, error)
	Verify(context.Context, VerifyRequest) (VerifyResponse, error)
	FetchArtifact(context.Context, FetchArtifactRequest) (Artifact, error)
}

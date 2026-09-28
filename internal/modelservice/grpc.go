package modelservice

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/tlstrust"
	cortexv1 "github.com/TrueOpen/cortex/proto/cortex/v1"

	"google.golang.org/grpc/status"
)

type retryableError struct {
	err error
}

func (e retryableError) Error() string {
	return e.err.Error()
}

func (e retryableError) Unwrap() error {
	return e.err
}

// IsRetryable is the transient half of the fault classification in errors.go.
// It is expressed through ClassOf rather than errors.As so that a fault marked
// Transient and a retryableError answer the same question the same way.
func IsRetryable(err error) bool {
	return ClassOf(err) == FaultTransient
}

type GRPCTransport struct {
	client cortexv1.ModelManagementServiceClient
	conn   *grpc.ClientConn
}

var (
	testDialersMu sync.RWMutex
	testDialers   = map[string]func(context.Context, string) (net.Conn, error){}
)

func RegisterGRPCTestDialer(endpoint string, dialer func(context.Context, string) (net.Conn, error)) func() {
	testDialersMu.Lock()
	testDialers[endpoint] = dialer
	testDialersMu.Unlock()
	return func() {
		testDialersMu.Lock()
		delete(testDialers, endpoint)
		testDialersMu.Unlock()
	}
}

// GRPCTLS is the encryption setting for the link to the model service (deployment
// security baseline): CAFile validates against the certificate chain, PubkeyHash
// (sha256(SubjectPublicKeyInfo), 64 lowercase hex chars) accepts that one public
// key and nothing else. Neither one given = plaintext.
type GRPCTLS struct {
	CAFile     string
	PubkeyHash string
}

// grpcTLSConfig turns GRPCTLS into a tls.Config; nil means dial in plaintext.
func grpcTLSConfig(cfg GRPCTLS) (*tls.Config, error) {
	return tlstrust.ClientConfig("model service tls", cfg.CAFile, cfg.PubkeyHash)
}

// NewGRPCTransportTLS dials according to tlsCfg: plaintext (the default) or TLS.
func NewGRPCTransportTLS(endpoint string, tlsCfg GRPCTLS) (*GRPCTransport, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("%w: grpc endpoint unavailable", ErrRuntimeTransportUnavailable)
	}
	tlsConfig, err := grpcTLSConfig(tlsCfg)
	if err != nil {
		return nil, err
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if tlsConfig != nil {
		opts = []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}
	}
	testDialersMu.RLock()
	dialer := testDialers[endpoint]
	testDialersMu.RUnlock()
	if dialer != nil {
		opts = append(opts, grpc.WithContextDialer(dialer))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, endpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: grpc endpoint %q unavailable: %v", ErrRuntimeTransportUnavailable, endpoint, err)
	}
	return &GRPCTransport{client: cortexv1.NewModelManagementServiceClient(conn), conn: conn}, nil
}

func NewGRPCTransportForClient(client cortexv1.ModelManagementServiceClient) Transport {
	return &GRPCTransport{client: client}
}

func (t *GRPCTransport) Close() error {
	if t == nil || t.conn == nil {
		return nil
	}
	return t.conn.Close()
}

func (t *GRPCTransport) Invoke(ctx context.Context, method string, req any, resp any) error {
	if t == nil || t.client == nil {
		return fmt.Errorf("grpc modelservice client is required")
	}
	method = strings.TrimPrefix(method, "/cortex.v1.ModelManagementService/")
	switch method {
	case "Health":
		r, err := t.client.Health(ctx, toProtoHealthRequest(req.(HealthRequest)))
		if err != nil {
			return mapGRPCError(err)
		}
		*(resp.(*HealthResponse)) = fromProtoHealthResponse(r)
	case "ListCapabilities":
		r, err := t.client.ListCapabilities(ctx, toProtoListCapabilitiesRequest(req.(ListCapabilitiesRequest)))
		if err != nil {
			return mapGRPCError(err)
		}
		*(resp.(*ListCapabilitiesResponse)) = fromProtoListCapabilitiesResponse(r)
	case "GetModelDetails":
		r, err := t.client.GetModelDetails(ctx, toProtoGetModelDetailsRequest(req.(GetModelDetailsRequest)))
		if err != nil {
			return mapGRPCError(err)
		}
		*(resp.(*GetModelDetailsResponse)) = fromProtoGetModelDetailsResponse(r)
	case "LoadModel":
		r, err := t.client.LoadModel(ctx, toProtoLoadModelRequest(req.(LoadModelRequest)))
		if err != nil {
			return mapGRPCError(err)
		}
		*(resp.(*LoadModelResponse)) = fromProtoLoadModelResponse(r)
	case "Estimate":
		r, err := t.client.Estimate(ctx, toProtoEstimateRequest(req.(EstimateRequest)))
		if err != nil {
			return mapGRPCError(err)
		}
		*(resp.(*EstimateResponse)) = fromProtoEstimateResponse(r)
	case "Infer":
		r, err := t.client.Infer(ctx, toProtoInferRequest(req.(InferRequest)))
		if err != nil {
			return mapGRPCError(err)
		}
		var inferResp InferResponse
		if inferResp, err = fromProtoInferResponse(r); err != nil {
			return err
		}
		*(resp.(*InferResponse)) = inferResp
	case "Verify":
		r, err := t.client.Verify(ctx, toProtoVerifyRequest(req.(VerifyRequest)))
		if err != nil {
			return mapGRPCError(err)
		}
		var verifyResp VerifyResponse
		if verifyResp, err = fromProtoVerifyResponse(r); err != nil {
			return err
		}
		*(resp.(*VerifyResponse)) = verifyResp
	case "FetchArtifact":
		r, err := t.fetchArtifact(ctx, req.(FetchArtifactRequest))
		if err != nil {
			return err
		}
		*(resp.(*Artifact)) = r
	default:
		return fmt.Errorf("unknown modelservice grpc method %q", method)
	}
	return nil
}

func (t *GRPCTransport) fetchArtifact(ctx context.Context, req FetchArtifactRequest) (Artifact, error) {
	if _, err := ParseArtifactRef(req.Ref); err != nil {
		return Artifact{}, err
	}
	stream, err := t.client.FetchArtifact(ctx, toProtoFetchArtifactRequest(req))
	if err != nil {
		return Artifact{}, mapGRPCError(err)
	}
	var data []byte
	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return Artifact{Ref: req.Ref, MediaType: "application/octet-stream", Data: data}, nil
		}
		if err != nil {
			return Artifact{}, mapGRPCError(err)
		}
		if req.SizeLimitBytes > 0 {
			observed := uint64(len(data)) + uint64(len(chunk.GetBytes()))
			if observed > req.SizeLimitBytes {
				return Artifact{}, fmt.Errorf("%w: kind=%s, bound=%d, observed=%d", ErrArtifactSizeExceeded, req.Kind, req.SizeLimitBytes, observed)
			}
		}
		data = append(data, chunk.GetBytes()...)
	}
}

func mapGRPCError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	if st.Code() == codes.DeadlineExceeded {
		return context.DeadlineExceeded
	}
	wrapped := fmt.Errorf("%s: %s", st.Code(), st.Message())
	switch st.Code() {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted:
		return retryableError{err: wrapped}
	default:
		return wrapped
	}
}

func serviceErrorFromProto(err *cortexv1.ModelServiceError) *ServiceError {
	if err == nil {
		return nil
	}
	return &ServiceError{Code: err.GetCode(), Message: err.GetMessage(), Retryable: err.GetRetryable()}
}

func toProtoHealthRequest(req HealthRequest) *cortexv1.HealthRequest {
	return &cortexv1.HealthRequest{RequestId: req.RequestID, ModelServiceId: req.ModelServiceID, DeadlineMs: req.DeadlineMS}
}

func fromProtoHealthResponse(resp *cortexv1.HealthResponse) HealthResponse {
	return HealthResponse{RequestID: resp.GetRequestId(), ModelServiceID: resp.GetModelServiceId(), Healthy: resp.GetHealthy(), Error: serviceErrorFromProto(resp.GetError())}
}

func toProtoListCapabilitiesRequest(req ListCapabilitiesRequest) *cortexv1.ListCapabilitiesRequest {
	return &cortexv1.ListCapabilitiesRequest{RequestId: req.RequestID, ModelServiceId: req.ModelServiceID, DeadlineMs: req.DeadlineMS, IncludeUnloaded: req.IncludeUnloaded, RegistryFilter: req.RegistryFilter, ReadinessLevel: req.ReadinessLevel}
}

func fromProtoListCapabilitiesResponse(resp *cortexv1.ListCapabilitiesResponse) ListCapabilitiesResponse {
	out := ListCapabilitiesResponse{
		RequestID:                  resp.GetRequestId(),
		ModelServiceID:             resp.GetModelServiceId(),
		ModelManagementAPIVersions: append([]string(nil), resp.GetModelManagementApiVersions()...),
		Error:                      serviceErrorFromProto(resp.GetError()),
	}
	for _, cap := range resp.GetCapabilities() {
		out.Capabilities = append(out.Capabilities, ManagedModelCapability{ModelID: modelIDFromProto(cap.GetModelId()), Capability: cap.GetCapability(), SupportsTokenIDs: cap.GetSupportsTokenIds(), SupportsPositionValues: cap.GetSupportsPositionValues(), SupportsBatchLog: cap.GetSupportsBatchLog()})
	}
	if snapshot := resp.GetResourceSnapshot(); snapshot != nil {
		out.ResourceSnapshot = ResourceSnapshot{
			LoadedModels:   int(snapshot.GetLoadedModels()),
			QueueDepth:     snapshot.GetQueueDepth(),
			MaxConcurrency: snapshot.GetMaxConcurrency(),
		}
	}
	return out
}

func toProtoGetModelDetailsRequest(req GetModelDetailsRequest) *cortexv1.GetModelDetailsRequest {
	return &cortexv1.GetModelDetailsRequest{
		RequestId:      req.RequestID,
		ModelServiceId: req.ModelServiceID,
		DeadlineMs:     req.DeadlineMS,
		ModelId:        modelIDToProto(req.ModelID),
	}
}

func fromProtoGetModelDetailsResponse(resp *cortexv1.GetModelDetailsResponse) GetModelDetailsResponse {
	out := GetModelDetailsResponse{
		RequestID:      resp.GetRequestId(),
		ModelServiceID: resp.GetModelServiceId(),
		Error:          serviceErrorFromProto(resp.GetError()),
	}
	if details := resp.GetDetails(); details != nil {
		out.Details = fromProtoModelDetails(details)
	}
	return out
}

func fromProtoModelDetails(details *cortexv1.ModelDetails) ModelDetails {
	return ModelDetails{
		Artifacts:          fromProtoModelArtifacts(details.GetArtifacts()),
		Derivation:         fromProtoModelDerivation(details.GetDerivation()),
		Identity:           fromProtoModelIdentity(details.GetIdentity()),
		Metadata:           fromProtoModelMetadata(details.GetMetadata()),
		ModelConfigSummary: fromProtoModelConfigSummary(details.GetModelConfigSummary()),
		ModelDir:           details.GetModelDir(),
		ModelRef:           details.GetModelRef(),
		Source:             fromProtoModelSource(details.GetSource()),
	}
}

func fromProtoModelArtifacts(artifacts *cortexv1.ModelArtifacts) ModelArtifacts {
	out := ModelArtifacts{Files: make([]ModelArtifactFile, 0)}
	if artifacts == nil {
		return out
	}
	out.ChatTemplateHash = artifacts.GetChatTemplateHash()
	out.FileManifestHash = artifacts.GetFileManifestHash()
	out.GenerationConfigHash = artifacts.GetGenerationConfigHash()
	out.ModelConfigHash = artifacts.GetModelConfigHash()
	out.ModelWeightDigest = artifacts.GetModelWeightDigest()
	out.QuantConfigHash = artifacts.GetQuantConfigHash()
	out.TokenizerConfigHash = artifacts.GetTokenizerConfigHash()
	out.TokenizerHash = artifacts.GetTokenizerHash()
	for _, file := range artifacts.GetFiles() {
		if file == nil {
			continue
		}
		out.Files = append(out.Files, ModelArtifactFile{
			Digest: file.GetDigest(), Path: file.GetPath(), Role: file.GetRole(), SizeBytes: file.GetSizeBytes(),
		})
	}
	return out
}

func fromProtoModelDerivation(derivation *cortexv1.ModelDerivation) ModelDerivation {
	out := ModelDerivation{
		ArtifactSources: fromProtoModelArtifactSources(nil),
		Warnings:        []string{},
	}
	if derivation == nil {
		return out
	}
	out.ArtifactSources = fromProtoModelArtifactSources(derivation.GetArtifactSources())
	out.Warnings = cloneStrings(derivation.GetWarnings())
	return out
}

func fromProtoModelArtifactSources(sources *cortexv1.ModelArtifactSources) ModelArtifactSources {
	out := ModelArtifactSources{TokenizerPaths: []string{}, WeightPaths: []string{}}
	if sources == nil {
		return out
	}
	out.ChatTemplateSource = sources.GetChatTemplateSource()
	out.ConfigPath = sources.GetConfigPath()
	out.GenerationConfigPath = sources.GetGenerationConfigPath()
	out.QuantConfigSource = sources.GetQuantConfigSource()
	out.TokenizerConfigPath = sources.GetTokenizerConfigPath()
	out.TokenizerPaths = cloneStrings(sources.GetTokenizerPaths())
	out.WeightPaths = cloneStrings(sources.GetWeightPaths())
	return out
}

func fromProtoModelIdentity(identity *cortexv1.ModelIdentity) ModelIdentity {
	if identity == nil {
		return ModelIdentity{}
	}
	return ModelIdentity{DisplayName: identity.GetDisplayName(), ModelID: modelIDFromProto(identity.GetModelId())}
}

func fromProtoModelMetadata(metadata *cortexv1.ModelMetadata) ModelMetadata {
	if metadata == nil {
		return ModelMetadata{LicenseFiles: []string{}}
	}
	return ModelMetadata{LicenseFiles: cloneStrings(metadata.GetLicenseFiles()), LicenseRef: metadata.GetLicenseRef()}
}

func fromProtoModelConfigSummary(summary *cortexv1.ModelConfigSummary) ModelConfigSummary {
	out := ModelConfigSummary{Modality: []string{}}
	if summary == nil {
		return out
	}
	out.ActiveParams = summary.GetActiveParams()
	out.Architecture = summary.GetArchitecture()
	out.ContextLength = summary.GetContextLength()
	out.Modality = cloneStrings(summary.GetModality())
	if moe := summary.GetMoe(); moe != nil {
		out.MOE = ModelMOESummary{Enabled: moe.GetEnabled(), NumExperts: moe.GetNumExperts(), NumExpertsPerTok: moe.GetNumExpertsPerTok()}
	}
	if quantization := summary.GetQuantization(); quantization != nil {
		out.Quantization = ModelQuantizationSummary{Bits: quantization.GetBits(), Method: quantization.GetMethod()}
	}
	out.TotalParams = summary.GetTotalParams()
	return out
}

func fromProtoModelSource(source *cortexv1.ModelSource) ModelSource {
	if source == nil {
		return ModelSource{}
	}
	return ModelSource{
		Provider: source.GetProvider(), RepoID: source.GetRepoId(), RepoType: source.GetRepoType(),
		ResolverVersion: source.GetResolverVersion(), Revision: source.GetRevision(), SourceURI: source.GetSourceUri(),
	}
}

func cloneStrings(values []string) []string {
	return append([]string{}, values...)
}

func toProtoLoadModelRequest(req LoadModelRequest) *cortexv1.LoadModelRequest {
	return &cortexv1.LoadModelRequest{RequestId: req.RequestID, ModelServiceId: req.ModelServiceID, DeadlineMs: req.DeadlineMS, ModelId: modelIDToProto(req.ModelID), Capability: req.Capability}
}

func fromProtoLoadModelResponse(resp *cortexv1.LoadModelResponse) LoadModelResponse {
	return LoadModelResponse{RequestID: resp.GetRequestId(), ModelServiceID: resp.GetModelServiceId(), ModelID: modelIDFromProto(resp.GetModelId()), Loaded: resp.GetLoaded(), Error: serviceErrorFromProto(resp.GetError())}
}

func toProtoEstimateRequest(req EstimateRequest) *cortexv1.EstimateRequest {
	return &cortexv1.EstimateRequest{RequestId: req.RequestID, ModelServiceId: req.ModelServiceID, DeadlineMs: req.DeadlineMS, ModelId: modelIDToProto(req.ModelID), Capability: req.Capability, InputBytes: req.InputBytes}
}

func fromProtoEstimateResponse(resp *cortexv1.EstimateResponse) EstimateResponse {
	return EstimateResponse{RequestID: resp.GetRequestId(), ModelServiceID: resp.GetModelServiceId(), EstimatedMS: resp.GetEstimatedMs(), EstimatedBytes: resp.GetEstimatedBytes(), Error: serviceErrorFromProto(resp.GetError())}
}

func toProtoInferRequest(req InferRequest) *cortexv1.InferRequest {
	return &cortexv1.InferRequest{RequestId: req.RequestID, ModelServiceId: req.ModelServiceID, DeadlineMs: req.DeadlineMS, JobId: req.JobID, TaskId: req.TaskID, ModelId: modelIDToProto(req.ModelID), ProfileVersion: req.ProfileVersion, RequestDigest: req.RequestDigest, Capability: req.Capability, Input: req.Input, Generation: generationContextProto(req.Generation), GenerationParamsDigest: append([]byte(nil), req.GenerationParamsDigest...)}
}

func fromProtoInferResponse(resp *cortexv1.InferResponse) (InferResponse, error) {
	if resp.GetError() != nil {
		return InferResponse{Error: serviceErrorFromProto(resp.GetError())}, nil
	}
	finishReason, err := finishReasonV1FromString(resp.GetFinishReason(), true)
	if err != nil {
		return InferResponse{}, err
	}
	return InferResponse{RequestID: resp.GetRequestId(), ModelServiceID: resp.GetModelServiceId(), JobID: resp.GetJobId(), TaskID: resp.GetTaskId(), ModelID: modelIDFromProto(resp.GetModelId()), ProfileVersion: resp.GetProfileVersion(), RequestDigest: resp.GetRequestDigest(), OutputRef: resp.GetOutputRef(), TokenIDsRef: resp.GetTokenIdsRef(), PositionValuesRef: resp.GetPositionValuesRef(), Error: serviceErrorFromProto(resp.GetError()), GeneratedTokenCount: resp.GetGeneratedTokenCount(), WorkUnit: resp.GetWorkUnit(), FinishReason: finishReason, GenerationParamsDigest: append([]byte(nil), resp.GetGenerationParamsDigest()...)}, nil
}

func toProtoVerifyRequest(req VerifyRequest) *cortexv1.VerifyRequest {
	evidence := []*cortexv1.VerifyEvidenceItem{{
		EvidenceKind: EvidenceKindWorkerTokenOpening,
		TokenIds:     &cortexv1.TokenIDsV1{InputTokenIds: req.TokenIDs.Input, GeneratedTokenIds: req.TokenIDs.Generated},
	}}
	return &cortexv1.VerifyRequest{RequestId: req.RequestID, ModelServiceId: req.ModelServiceID, DeadlineMs: req.DeadlineMS, JobId: req.JobID, TaskId: req.TaskID, ModelId: modelIDToProto(req.ModelID), ProfileVersion: req.ProfileVersion, RequestDigest: req.RequestDigest, Capability: req.Capability, Sample: req.Sample, Evidence: evidence, Generation: generationContextProto(req.Generation), GenerationParamsDigest: append([]byte(nil), req.GenerationParamsDigest...)}
}

func fromProtoVerifyResponse(resp *cortexv1.VerifyResponse) (VerifyResponse, error) {
	out := VerifyResponse{RequestID: resp.GetRequestId(), ModelServiceID: resp.GetModelServiceId(), JobID: resp.GetJobId(), TaskID: resp.GetTaskId(), ModelID: modelIDFromProto(resp.GetModelId()), ProfileVersion: resp.GetProfileVersion(), RequestDigest: resp.GetRequestDigest(), MainMismatchCount: int(resp.GetMainMismatchCount()), SampleValueSequenceRef: resp.GetSampleValueSequenceRef(), SampleDigest: resp.GetSampleValueDigest(), MaterialDigest: resp.GetResultCommitMaterialDigest(), Error: serviceErrorFromProto(resp.GetError())}
	for _, position := range resp.GetSelectedPositionsOrCheckpoints() {
		out.SelectedPositionsOrCheckpoints = append(out.SelectedPositionsOrCheckpoints, int(position))
	}
	out.GenerationParamsDigest = append([]byte(nil), resp.GetGenerationParamsDigest()...)
	if values := resp.GetVerifierValues(); values != nil {
		// Round-trip through the artifact codec so a remote service's values
		// meet exactly the shape checks a local one's do. Order is the
		// transport's and is not repaired: a service that emitted positions out
		// of order is refused, not corrected.
		raw, err := artifactMarshal.Marshal(values)
		if err != nil {
			return VerifyResponse{}, err
		}
		if out.VerifierValues, err = DecodePositionValuesArtifact(raw); err != nil {
			return VerifyResponse{}, fmt.Errorf("model service verifier values: %w", err)
		}
	}
	return out, nil
}

// modelIDToProto is the Hash32 a cortex.v1 model_id field carries. Cortex holds
// model ids as canonical hex and validates them before they reach a model
// service, so a malformed one here is sent empty and refused by the service.
func modelIDToProto(modelID string) []byte {
	raw, err := identity.ModelIDBytes(modelID)
	if err != nil {
		return nil
	}
	return raw
}

func modelIDFromProto(raw []byte) string {
	text, err := identity.ModelIDHex(raw)
	if err != nil {
		return ""
	}
	return text
}

func toProtoFetchArtifactRequest(req FetchArtifactRequest) *cortexv1.FetchArtifactRequest {
	return &cortexv1.FetchArtifactRequest{RequestId: req.RequestID, ModelServiceId: req.ModelServiceID, DeadlineMs: req.DeadlineMS, Ref: req.Ref, AllowEmpty: req.AllowEmpty}
}

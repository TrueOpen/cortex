package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/TrueOpen/cortex/internal/diagnostics"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/modelregistry"
)

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
)

var ErrInsecureSocketPermissions = errors.New("admin socket permissions are not owner-only")

type Format string

type ServiceConfig struct {
	ModelRegistry              *modelregistry.Registry
	TreasuryStatus             TreasuryStatus
	Capability                 Capability
	Diagnostics                diagnostics.Diagnostics
	DiagnosticsProvider        func(context.Context) diagnostics.Diagnostics
	EvidenceCleanupPlan        func(context.Context) (evidence.CleanupPlan, error)
	EvidenceCleanupExecute     func(context.Context, string) (evidence.CleanupResult, error)
	EvidenceCleanupDiagnostics func(context.Context) (evidence.CleanupDiagnosticsReport, error)
	TaskQueueRequeue           func(context.Context, TaskQueueRequeueRequest) (TaskQueueRequeueResponse, error)
	TaskQueueList              func(context.Context, TaskQueueListRequest) (TaskQueueListResponse, error)
	TaskSettlement             func(context.Context, TaskSettlementRequest) (TaskSettlementResponse, error)
}

type Service struct {
	modelRegistry              *modelregistry.Registry
	treasuryStatus             TreasuryStatus
	capability                 Capability
	diagnostics                diagnostics.Diagnostics
	diagnosticsProvider        func(context.Context) diagnostics.Diagnostics
	evidenceCleanupPlan        func(context.Context) (evidence.CleanupPlan, error)
	evidenceCleanupExecute     func(context.Context, string) (evidence.CleanupResult, error)
	evidenceCleanupDiagnostics func(context.Context) (evidence.CleanupDiagnosticsReport, error)
	taskQueueRequeue           func(context.Context, TaskQueueRequeueRequest) (TaskQueueRequeueResponse, error)
	taskQueueList              func(context.Context, TaskQueueListRequest) (TaskQueueListResponse, error)
	taskSettlement             func(context.Context, TaskSettlementRequest) (TaskSettlementResponse, error)
}

type TreasuryStatus struct {
	Destination string `json:"destination"`
	Denom       string `json:"denom"`
	Balance     uint64 `json:"balance"`
}

type Capability struct {
	ModelRegistry     bool `json:"model_registry"`
	ChallengeVerifier bool `json:"challenge_verifier"`
}

type TaskQueueRequeueRequest struct {
	QueueID      string `json:"queue_id"`
	Reason       string `json:"reason"`
	RetryDelayMS uint64 `json:"retry_delay_ms,omitempty"`
}

type TaskQueueRequeueResponse struct {
	QueueID    string `json:"queue_id"`
	TaskID     string `json:"task_id"`
	Status     string `json:"status"`
	RetryCount int    `json:"retry_count"`
	RetryAt    string `json:"retry_at,omitempty"`
	LastError  string `json:"last_error"`
}

type TaskQueueListRequest struct {
	// Status filters by queue status. "all" lists every row.
	Status string `json:"status,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

type TaskQueueListResponse struct {
	Rows []TaskQueueRow `json:"rows"`
}

// TaskQueueRow carries the fields that make a row's disposition legible. LastError
// is the one that distinguishes a row retrying for a good reason from a row that
// will never succeed.
type TaskQueueRow struct {
	QueueID    string `json:"queue_id"`
	TaskID     string `json:"task_id"`
	Role       string `json:"role"`
	Stage      string `json:"stage"`
	Status     string `json:"status"`
	RetryCount int    `json:"retry_count"`
	RetryAt    string `json:"retry_at,omitempty"`
	DueHeight  uint64 `json:"due_height,omitempty"`
	LastError  string `json:"last_error,omitempty"`
	// AutoHalted marks a row the scheduler deliberately stopped calling the
	// model for, with the fault code that decided it. A halted row and a row
	// that merely exhausted its retries both read "failed" in Status, and only
	// the first has an operator remedy (requeue), so the distinction has to be
	// on the wire and not only in LastError's prose.
	AutoHalted bool   `json:"auto_halted,omitempty"`
	HaltCode   string `json:"halt_code,omitempty"`
	HaltReason string `json:"halt_reason,omitempty"`
}

type ModelRegisterRequest struct {
	Manifest               modelregistry.Manifest `json:"manifest"`
	ModelRegistrationFee   uint64                 `json:"model_registration_fee"`
	ProfileRegistrationFee uint64                 `json:"profile_registration_fee"`
	DryRun                 bool                   `json:"dry_run"`
}

type ModelRegisterResponse struct {
	ManifestHash string                                `json:"manifest_hash"`
	Model        modelregistry.RegistrationStageResult `json:"model"`
	Profile      modelregistry.RegistrationStageResult `json:"profile"`
	DryRun       bool                                  `json:"dry_run"`
}

type modelRegisterWireRequest struct {
	ModelRegisterRequest
	Quote *modelregistry.FeeQuote  `json:"quote,omitempty"`
	Mode  modelregistry.SubmitMode `json:"mode,omitempty"`
	Wait  bool                     `json:"wait,omitempty"`
}

type modelRegisterWireResponse struct {
	ModelRegisterResponse
	TxID     string                              `json:"tx_id,omitempty"`
	OutboxID string                              `json:"outbox_id,omitempty"`
	Material *modelregistry.RegistrationMaterial `json:"material,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func New(config ServiceConfig) *Service {
	return &Service{
		modelRegistry:              config.ModelRegistry,
		treasuryStatus:             config.TreasuryStatus,
		capability:                 config.Capability,
		diagnostics:                config.Diagnostics,
		diagnosticsProvider:        config.DiagnosticsProvider,
		evidenceCleanupPlan:        config.EvidenceCleanupPlan,
		evidenceCleanupExecute:     config.EvidenceCleanupExecute,
		evidenceCleanupDiagnostics: config.EvidenceCleanupDiagnostics,
		taskQueueRequeue:           config.TaskQueueRequeue,
		taskQueueList:              config.TaskQueueList,
		taskSettlement:             config.TaskSettlement,
	}
}

type Server struct {
	path    string
	service *Service
	server  *http.Server
	ln      net.Listener
}

type Client struct {
	socketPath string
	httpClient *http.Client
}

func NewServer(path string, service *Service) *Server {
	return &Server{path: strings.TrimSpace(path), service: service}
}

func (s *Server) Start(ctx context.Context) error {
	if s.service == nil {
		return errors.New("admin service is required")
	}
	if s.path == "" {
		return errors.New("admin socket path is required")
	}
	if err := removeStaleSocket(s.path); err != nil {
		return err
	}
	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return err
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		_ = ln.Close()
		return err
	}
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	s.ln = ln
	s.server = &http.Server{
		Handler:  mux,
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
	}
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	go func() {
		err := s.server.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			// Serve errors are surfaced through client calls in this MVP.
			return
		}
	}()
	return nil
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%w: %s is not a unix socket", ErrInsecureSocketPermissions, path)
	}
	return os.Remove(path)
}

func (s *Server) Close() error {
	var err error
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		err = s.server.Shutdown(ctx)
	}
	if s.ln != nil {
		if closeErr := s.ln.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) && err == nil {
			err = closeErr
		}
	}
	if s.path != "" {
		if removeErr := os.Remove(s.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) && err == nil {
			err = removeErr
		}
	}
	return err
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/model/manifest/generate", s.handleCurrentModelManifestGenerate)
	mux.HandleFunc("/v1/model/manifest/validate", s.handleCurrentModelManifestValidate)
	mux.HandleFunc("/v1/model/manifest/legacy/generate", s.handleModelManifestGenerate)
	mux.HandleFunc("/v1/model/manifest/legacy/validate", s.handleModelManifestValidate)
	mux.HandleFunc("/v1/model/self-test", s.handleCurrentModelSelfTest)
	mux.HandleFunc("/v1/model/self-test-legacy", s.handleModelSelfTest)
	mux.HandleFunc("/v1/model/register", s.handleCurrentModelRegister)
	mux.HandleFunc("/v1/model/register-legacy", s.handleModelRegister)
	mux.HandleFunc("/v1/model/status", s.handleModelStatus)
	mux.HandleFunc("/v1/model/list", s.handleModelList)
	mux.HandleFunc("/v1/model/show", s.handleModelShow)
	mux.HandleFunc("/v1/model/status-projection", s.handleModelStatusProjection)
	mux.HandleFunc("/v1/model/list-projections", s.handleModelListProjections)
	mux.HandleFunc("/v1/model/show-projection", s.handleModelShowProjection)
	mux.HandleFunc("/v1/model/support", s.handleModelSupport)
	mux.HandleFunc("/v1/model/daily-support", s.handleModelDailySupport)
	mux.HandleFunc("/v1/treasury/status", s.handleTreasuryStatus)
	mux.HandleFunc("/v1/capability", s.handleCapability)
	mux.HandleFunc("/v1/diagnostics", s.handleDiagnostics)
	mux.HandleFunc("/v1/evidence/cleanup-plan", s.handleEvidenceCleanupPlan)
	mux.HandleFunc("/v1/evidence/cleanup-execute", s.handleEvidenceCleanupExecute)
	mux.HandleFunc("/v1/evidence/cleanup-diagnostics", s.handleEvidenceCleanupDiagnostics)
	mux.HandleFunc("/v1/task/requeue", s.handleTaskQueueRequeue)
	mux.HandleFunc("/v1/task/list", s.handleTaskQueueList)
	mux.HandleFunc("/v1/task/settle", s.handleTaskSettlement)
}

func (s *Service) ModelManifestGenerate(ctx context.Context, input modelregistry.ManifestInput) (modelregistry.Manifest, error) {
	if s.modelRegistry == nil {
		return modelregistry.GenerateManifest(input)
	}
	return s.modelRegistry.GenerateManifest(ctx, input)
}

func (s *Service) ModelManifestValidate(ctx context.Context, manifest modelregistry.Manifest) error {
	if s.modelRegistry == nil {
		return modelregistry.ValidateManifest(manifest)
	}
	return s.modelRegistry.ValidateManifest(ctx, manifest)
}

func (s *Service) CurrentModelManifestGenerate(_ context.Context, input modelregistry.CurrentManifestInput) (modelregistry.CurrentManifest, error) {
	return modelregistry.GenerateCurrentManifest(input)
}

func (s *Service) CurrentModelManifestValidate(_ context.Context, manifest modelregistry.CurrentManifest) error {
	return modelregistry.ValidateCurrentManifest(manifest)
}

func (s *Service) ModelSelfTest(ctx context.Context, manifest modelregistry.Manifest) (modelregistry.RegistrationMaterial, error) {
	registry, err := s.requireRegistry()
	if err != nil {
		return modelregistry.RegistrationMaterial{}, err
	}
	material, err := registry.SelfTest(ctx, manifest)
	if err != nil {
		return modelregistry.RegistrationMaterial{}, err
	}
	return *material, nil
}

func (s *Service) CurrentModelSelfTest(_ context.Context, manifest modelregistry.CurrentManifest) (modelregistry.CurrentSelfTestResult, error) {
	return modelregistry.SelfTestCurrentManifest(manifest)
}

func (s *Service) ModelRegister(ctx context.Context, req modelregistry.RegisterRequest) (modelregistry.RegisterResult, error) {
	registry, err := s.requireRegistry()
	if err != nil {
		return modelregistry.RegisterResult{}, err
	}
	return registry.Register(ctx, req)
}

func (s *Service) CurrentModelRegister(ctx context.Context, req modelregistry.CurrentRegisterRequest) (modelregistry.CurrentRegisterResult, error) {
	registry, err := s.requireRegistry()
	if err != nil {
		return modelregistry.CurrentRegisterResult{}, err
	}
	return registry.RegisterCurrent(ctx, req)
}

func (s *Service) ModelStatus(ctx context.Context, req modelregistry.StatusRequest) (modelregistry.ModelStatus, error) {
	registry, err := s.requireRegistry()
	if err != nil {
		return modelregistry.ModelStatus{}, err
	}
	return registry.Status(ctx, req)
}

func (s *Service) ModelList(ctx context.Context, req modelregistry.ListRequest) ([]modelregistry.ModelStatus, error) {
	registry, err := s.requireRegistry()
	if err != nil {
		return nil, err
	}
	return registry.List(ctx, req)
}

func (s *Service) ModelShow(ctx context.Context, req modelregistry.ShowRequest) (modelregistry.ModelDetails, error) {
	registry, err := s.requireRegistry()
	if err != nil {
		return modelregistry.ModelDetails{}, err
	}
	return registry.Show(ctx, req)
}

func (s *Service) ModelStatusProjection(ctx context.Context, req modelregistry.StatusRequest) (modelregistry.StatusProjection, error) {
	registry, err := s.requireRegistry()
	if err != nil {
		return modelregistry.StatusProjection{}, err
	}
	return registry.StatusProjection(ctx, req)
}

func (s *Service) ModelListProjections(ctx context.Context, req modelregistry.ListRequest) ([]modelregistry.StatusProjection, error) {
	registry, err := s.requireRegistry()
	if err != nil {
		return nil, err
	}
	return registry.ListProjections(ctx, req)
}

func (s *Service) ModelShowProjection(ctx context.Context, req modelregistry.ShowRequest) (modelregistry.StatusProjection, error) {
	registry, err := s.requireRegistry()
	if err != nil {
		return modelregistry.StatusProjection{}, err
	}
	return registry.ShowProjection(ctx, req)
}

func (s *Service) ModelSupport(ctx context.Context, req modelregistry.SupportRequest) (modelregistry.OperatorSupportIntent, error) {
	registry, err := s.requireRegistry()
	if err != nil {
		return modelregistry.OperatorSupportIntent{}, err
	}
	return registry.PrepareOperatorSupportIntent(ctx, req)
}

func (s *Service) ModelDailySupport(ctx context.Context, req modelregistry.DailySupportRequest) (modelregistry.ModelStatus, error) {
	registry, err := s.requireRegistry()
	if err != nil {
		return modelregistry.ModelStatus{}, err
	}
	return registry.DailySupport(ctx, req)
}

func (s *Service) TreasuryStatus(_ context.Context) TreasuryStatus {
	return s.treasuryStatus
}

func (s *Service) Capability(_ context.Context) Capability {
	return s.capability
}

func (s *Service) Diagnostics(ctx context.Context) diagnostics.Diagnostics {
	if s.diagnosticsProvider != nil {
		return s.diagnosticsProvider(ctx)
	}
	return s.diagnostics
}

func (s *Service) EvidenceCleanupPlan(ctx context.Context) (evidence.CleanupPlan, error) {
	if s.evidenceCleanupPlan == nil {
		return evidence.CleanupPlan{}, fmt.Errorf("evidence cleanup planner is unavailable")
	}
	return s.evidenceCleanupPlan(ctx)
}

func (s *Service) EvidenceCleanupExecute(ctx context.Context, digest string) (evidence.CleanupResult, error) {
	if s.evidenceCleanupExecute == nil {
		return evidence.CleanupResult{}, fmt.Errorf("evidence cleanup execution is unavailable")
	}
	return s.evidenceCleanupExecute(ctx, digest)
}

func (s *Service) EvidenceCleanupDiagnostics(ctx context.Context) (evidence.CleanupDiagnosticsReport, error) {
	if s.evidenceCleanupDiagnostics == nil {
		return evidence.CleanupDiagnosticsReport{}, fmt.Errorf("evidence cleanup diagnostics are unavailable")
	}
	return s.evidenceCleanupDiagnostics(ctx)
}

func (s *Service) TaskQueueRequeue(ctx context.Context, req TaskQueueRequeueRequest) (TaskQueueRequeueResponse, error) {
	if s.taskQueueRequeue == nil {
		return TaskQueueRequeueResponse{}, fmt.Errorf("task queue requeue is unavailable")
	}
	req.QueueID = strings.TrimSpace(req.QueueID)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.QueueID == "" {
		return TaskQueueRequeueResponse{}, fmt.Errorf("queue_id is required")
	}
	if req.Reason == "" {
		return TaskQueueRequeueResponse{}, fmt.Errorf("requeue reason is required")
	}
	const maxRetryDelayMS = uint64((7 * 24 * time.Hour) / time.Millisecond)
	if req.RetryDelayMS > maxRetryDelayMS {
		return TaskQueueRequeueResponse{}, fmt.Errorf("retry_delay_ms exceeds 7 days")
	}
	return s.taskQueueRequeue(ctx, req)
}

// taskQueueListMaxLimit bounds a response an operator reads in a terminal.
const taskQueueListMaxLimit = 500

func (s *Service) TaskQueueList(ctx context.Context, req TaskQueueListRequest) (TaskQueueListResponse, error) {
	if s.taskQueueList == nil {
		return TaskQueueListResponse{}, fmt.Errorf("task queue listing is unavailable")
	}
	req.Status = strings.TrimSpace(req.Status)
	if strings.EqualFold(req.Status, "all") {
		req.Status = ""
	}
	if req.Limit < 0 {
		return TaskQueueListResponse{}, fmt.Errorf("limit cannot be negative")
	}
	if req.Limit > taskQueueListMaxLimit {
		return TaskQueueListResponse{}, fmt.Errorf("limit exceeds %d", taskQueueListMaxLimit)
	}
	return s.taskQueueList(ctx, req)
}

func (s *Service) requireRegistry() (*modelregistry.Registry, error) {
	if s.modelRegistry == nil {
		return nil, errors.New("model registry is not configured")
	}
	return s.modelRegistry, nil
}

func (s *Server) handleModelManifestGenerate(w http.ResponseWriter, r *http.Request) {
	var req modelregistry.ManifestInput
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return s.service.ModelManifestGenerate(ctx, req)
	})
}

func (s *Server) handleCurrentModelManifestGenerate(w http.ResponseWriter, r *http.Request) {
	var req modelregistry.CurrentManifestInput
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return s.service.CurrentModelManifestGenerate(ctx, req)
	})
}

func (s *Server) handleModelManifestValidate(w http.ResponseWriter, r *http.Request) {
	var req modelregistry.Manifest
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return struct{}{}, s.service.ModelManifestValidate(ctx, req)
	})
}

func (s *Server) handleCurrentModelManifestValidate(w http.ResponseWriter, r *http.Request) {
	var req modelregistry.CurrentManifest
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return struct{}{}, s.service.CurrentModelManifestValidate(ctx, req)
	})
}

func (s *Server) handleModelSelfTest(w http.ResponseWriter, r *http.Request) {
	var req modelregistry.Manifest
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return s.service.ModelSelfTest(ctx, req)
	})
}

func (s *Server) handleCurrentModelSelfTest(w http.ResponseWriter, r *http.Request) {
	var req modelregistry.CurrentManifest
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return s.service.CurrentModelSelfTest(ctx, req)
	})
}

func (s *Server) handleModelRegister(w http.ResponseWriter, r *http.Request) {
	var req modelRegisterWireRequest
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		registryReq := modelregistry.RegisterRequest{
			Manifest:               req.Manifest,
			ModelRegistrationFee:   req.ModelRegistrationFee,
			ProfileRegistrationFee: req.ProfileRegistrationFee,
			DryRun:                 req.DryRun,
			Mode:                   req.Mode,
			Wait:                   req.Wait,
		}
		if req.Quote != nil {
			registryReq.Quote = *req.Quote
		}
		result, err := s.service.ModelRegister(ctx, registryReq)
		if err != nil {
			return nil, err
		}
		response := modelRegisterWireResponse{
			ModelRegisterResponse: ModelRegisterResponse{
				ManifestHash: result.ManifestHash,
				Model:        result.ModelStage,
				Profile:      result.ProfileStage,
				DryRun:       result.DryRun,
			},
			TxID:     result.TxID,
			OutboxID: result.OutboxID,
		}
		if req.Quote != nil {
			response.Material = &result.Material
		}
		return response, nil
	})
}

func (s *Server) handleCurrentModelRegister(w http.ResponseWriter, r *http.Request) {
	var req modelregistry.CurrentRegisterRequest
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return s.service.CurrentModelRegister(ctx, req)
	})
}

func (s *Server) handleModelStatus(w http.ResponseWriter, r *http.Request) {
	var req modelregistry.StatusRequest
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return s.service.ModelStatus(ctx, req)
	})
}

func (s *Server) handleModelList(w http.ResponseWriter, r *http.Request) {
	var req modelregistry.ListRequest
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return s.service.ModelList(ctx, req)
	})
}

func (s *Server) handleModelShow(w http.ResponseWriter, r *http.Request) {
	var req modelregistry.ShowRequest
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return s.service.ModelShow(ctx, req)
	})
}

func (s *Server) handleModelStatusProjection(w http.ResponseWriter, r *http.Request) {
	var req modelregistry.StatusRequest
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return s.service.ModelStatusProjection(ctx, req)
	})
}

func (s *Server) handleModelListProjections(w http.ResponseWriter, r *http.Request) {
	var req modelregistry.ListRequest
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return s.service.ModelListProjections(ctx, req)
	})
}

func (s *Server) handleModelShowProjection(w http.ResponseWriter, r *http.Request) {
	var req modelregistry.ShowRequest
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return s.service.ModelShowProjection(ctx, req)
	})
}

func (s *Server) handleModelSupport(w http.ResponseWriter, r *http.Request) {
	var req modelregistry.SupportRequest
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return s.service.ModelSupport(ctx, req)
	})
}

func (s *Server) handleModelDailySupport(w http.ResponseWriter, r *http.Request) {
	var req modelregistry.DailySupportRequest
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return s.service.ModelDailySupport(ctx, req)
	})
}

func (s *Server) handleTreasuryStatus(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, &struct{}{}, func(ctx context.Context) (any, error) {
		return s.service.TreasuryStatus(ctx), nil
	})
}

func (s *Server) handleCapability(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, &struct{}{}, func(ctx context.Context) (any, error) {
		return s.service.Capability(ctx), nil
	})
}

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, &struct{}{}, func(ctx context.Context) (any, error) {
		return s.service.Diagnostics(ctx), nil
	})
}

func (s *Server) handleEvidenceCleanupPlan(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, &struct{}{}, func(ctx context.Context) (any, error) {
		return s.service.EvidenceCleanupPlan(ctx)
	})
}

type evidenceCleanupExecuteRequest struct {
	Digest string `json:"digest"`
}

func (s *Server) handleEvidenceCleanupExecute(w http.ResponseWriter, r *http.Request) {
	var req evidenceCleanupExecuteRequest
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return s.service.EvidenceCleanupExecute(ctx, req.Digest)
	})
}

func (s *Server) handleEvidenceCleanupDiagnostics(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, &struct{}{}, func(ctx context.Context) (any, error) {
		return s.service.EvidenceCleanupDiagnostics(ctx)
	})
}

func (s *Server) handleTaskQueueRequeue(w http.ResponseWriter, r *http.Request) {
	var req TaskQueueRequeueRequest
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return s.service.TaskQueueRequeue(ctx, req)
	})
}

func (s *Server) handleTaskQueueList(w http.ResponseWriter, r *http.Request) {
	var req TaskQueueListRequest
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return s.service.TaskQueueList(ctx, req)
	})
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request, req any, call func(context.Context) (any, error)) {
	w.Header().Set("content-type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(errorResponse{Error: "method not allowed"})
		return
	}
	if req != nil {
		defer r.Body.Close()
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(errorResponse{Error: err.Error()})
			return
		}
	}
	out, err := call(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(errorResponse{Error: err.Error()})
		return
	}
	if out == nil {
		out = struct{}{}
	}
	_ = json.NewEncoder(w).Encode(out)
}

func EnsureOwnerOnlySocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink", ErrInsecureSocketPermissions, path)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%w: %s is not a unix socket", ErrInsecureSocketPermissions, path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %s", ErrInsecureSocketPermissions, path, info.Mode().Perm())
	}
	return nil
}

func NewClient(socketPath string) *Client {
	socketPath = strings.TrimSpace(socketPath)
	return &Client{
		socketPath: socketPath,
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					if err := EnsureOwnerOnlySocket(socketPath); err != nil {
						return nil, err
					}
					dialer := net.Dialer{}
					return dialer.DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

func (c *Client) ModelManifestGenerate(ctx context.Context, input modelregistry.ManifestInput) (modelregistry.Manifest, error) {
	var out modelregistry.Manifest
	err := c.post(ctx, "/v1/model/manifest/legacy/generate", input, &out)
	return out, err
}

func (c *Client) ModelManifestValidate(ctx context.Context, manifest modelregistry.Manifest) error {
	return c.post(ctx, "/v1/model/manifest/legacy/validate", manifest, &struct{}{})
}

func (c *Client) CurrentModelManifestGenerate(ctx context.Context, input modelregistry.CurrentManifestInput) (modelregistry.CurrentManifest, error) {
	var out modelregistry.CurrentManifest
	err := c.post(ctx, "/v1/model/manifest/generate", input, &out)
	return out, err
}

func (c *Client) CurrentModelManifestValidate(ctx context.Context, manifest modelregistry.CurrentManifest) error {
	return c.post(ctx, "/v1/model/manifest/validate", manifest, &struct{}{})
}

func (c *Client) ModelSelfTest(ctx context.Context, manifest modelregistry.Manifest) (modelregistry.RegistrationMaterial, error) {
	var out modelregistry.RegistrationMaterial
	err := c.post(ctx, "/v1/model/self-test-legacy", manifest, &out)
	return out, err
}

func (c *Client) CurrentModelSelfTest(ctx context.Context, manifest modelregistry.CurrentManifest) (modelregistry.CurrentSelfTestResult, error) {
	var out modelregistry.CurrentSelfTestResult
	err := c.post(ctx, "/v1/model/self-test", manifest, &out)
	return out, err
}

func (c *Client) ModelRegister(ctx context.Context, req modelregistry.RegisterRequest) (modelregistry.RegisterResult, error) {
	var quote *modelregistry.FeeQuote
	if req.Quote != (modelregistry.FeeQuote{}) {
		quote = &req.Quote
	}
	var out modelRegisterWireResponse
	err := c.post(ctx, "/v1/model/register-legacy", modelRegisterWireRequest{
		ModelRegisterRequest: ModelRegisterRequest{
			Manifest:               req.Manifest,
			ModelRegistrationFee:   req.ModelRegistrationFee,
			ProfileRegistrationFee: req.ProfileRegistrationFee,
			DryRun:                 req.DryRun,
		},
		Quote: quote,
		Mode:  req.Mode,
		Wait:  req.Wait,
	}, &out)
	result := modelregistry.RegisterResult{
		ManifestHash: out.ManifestHash,
		ModelStage:   out.Model,
		ProfileStage: out.Profile,
		DryRun:       out.DryRun,
		TxID:         out.TxID,
		OutboxID:     out.OutboxID,
	}
	if out.Material != nil {
		result.Material = *out.Material
	}
	return result, err
}

func (c *Client) CurrentModelRegister(ctx context.Context, req modelregistry.CurrentRegisterRequest) (modelregistry.CurrentRegisterResult, error) {
	var out modelregistry.CurrentRegisterResult
	err := c.post(ctx, "/v1/model/register", req, &out)
	return out, err
}

func (c *Client) ModelStatus(ctx context.Context, req modelregistry.StatusRequest) (modelregistry.ModelStatus, error) {
	var out modelregistry.ModelStatus
	err := c.post(ctx, "/v1/model/status", req, &out)
	return out, err
}

func (c *Client) ModelList(ctx context.Context, req modelregistry.ListRequest) ([]modelregistry.ModelStatus, error) {
	var out []modelregistry.ModelStatus
	err := c.post(ctx, "/v1/model/list", req, &out)
	return out, err
}

func (c *Client) ModelShow(ctx context.Context, req modelregistry.ShowRequest) (modelregistry.ModelDetails, error) {
	var out modelregistry.ModelDetails
	err := c.post(ctx, "/v1/model/show", req, &out)
	return out, err
}

func (c *Client) ModelStatusProjection(ctx context.Context, req modelregistry.StatusRequest) (modelregistry.StatusProjection, error) {
	var out modelregistry.StatusProjection
	err := c.post(ctx, "/v1/model/status-projection", req, &out)
	return out, err
}

func (c *Client) ModelListProjections(ctx context.Context, req modelregistry.ListRequest) ([]modelregistry.StatusProjection, error) {
	var out []modelregistry.StatusProjection
	err := c.post(ctx, "/v1/model/list-projections", req, &out)
	return out, err
}

func (c *Client) ModelShowProjection(ctx context.Context, req modelregistry.ShowRequest) (modelregistry.StatusProjection, error) {
	var out modelregistry.StatusProjection
	err := c.post(ctx, "/v1/model/show-projection", req, &out)
	return out, err
}

func (c *Client) ModelSupport(ctx context.Context, req modelregistry.SupportRequest) (modelregistry.OperatorSupportIntent, error) {
	var out modelregistry.OperatorSupportIntent
	err := c.post(ctx, "/v1/model/support", req, &out)
	return out, err
}

func (c *Client) ModelDailySupport(ctx context.Context, req modelregistry.DailySupportRequest) (modelregistry.ModelStatus, error) {
	var out modelregistry.ModelStatus
	err := c.post(ctx, "/v1/model/daily-support", req, &out)
	return out, err
}

func (c *Client) TreasuryStatus(ctx context.Context) (TreasuryStatus, error) {
	var out TreasuryStatus
	err := c.post(ctx, "/v1/treasury/status", struct{}{}, &out)
	return out, err
}

func (c *Client) Capability(ctx context.Context) (Capability, error) {
	var out Capability
	err := c.post(ctx, "/v1/capability", struct{}{}, &out)
	return out, err
}

func (c *Client) Diagnostics(ctx context.Context) (diagnostics.Diagnostics, error) {
	var out diagnostics.Diagnostics
	err := c.post(ctx, "/v1/diagnostics", struct{}{}, &out)
	return out, err
}

func (c *Client) EvidenceCleanupPlan(ctx context.Context) (evidence.CleanupPlan, error) {
	var out evidence.CleanupPlan
	err := c.post(ctx, "/v1/evidence/cleanup-plan", struct{}{}, &out)
	return out, err
}

func (c *Client) EvidenceCleanupExecute(ctx context.Context, digest string) (evidence.CleanupResult, error) {
	var out evidence.CleanupResult
	err := c.post(ctx, "/v1/evidence/cleanup-execute", evidenceCleanupExecuteRequest{Digest: digest}, &out)
	return out, err
}

func (c *Client) EvidenceCleanupDiagnostics(ctx context.Context) (evidence.CleanupDiagnosticsReport, error) {
	var out evidence.CleanupDiagnosticsReport
	err := c.post(ctx, "/v1/evidence/cleanup-diagnostics", struct{}{}, &out)
	return out, err
}

func (c *Client) TaskQueueRequeue(ctx context.Context, req TaskQueueRequeueRequest) (TaskQueueRequeueResponse, error) {
	var out TaskQueueRequeueResponse
	err := c.post(ctx, "/v1/task/requeue", req, &out)
	return out, err
}

func (c *Client) TaskQueueList(ctx context.Context, req TaskQueueListRequest) (TaskQueueListResponse, error) {
	var out TaskQueueListResponse
	err := c.post(ctx, "/v1/task/list", req, &out)
	return out, err
}

func (c *Client) post(ctx context.Context, path string, in any, out any) error {
	if c.socketPath == "" {
		return errors.New("admin socket path is required")
	}
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://cortexd"+path, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var failure errorResponse
		if err := json.NewDecoder(resp.Body).Decode(&failure); err == nil && failure.Error != "" {
			return errors.New(failure.Error)
		}
		return fmt.Errorf("admin API returned %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func FormatResponse(value any, format Format) (string, error) {
	switch format {
	case "", FormatTable:
		return formatTable(value), nil
	case FormatJSON:
		out, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return "", err
		}
		return string(out) + "\n", nil
	default:
		return "", fmt.Errorf("unknown format %q", format)
	}
}

func formatTable(value any) string {
	switch v := value.(type) {
	case modelregistry.ModelStatus:
		return modelStatusTable(v)
	case []modelregistry.ModelStatus:
		var b strings.Builder
		b.WriteString("model_id\tchain_state\tdisplay_visibility\tverification_label\treward_state\n")
		for _, status := range v {
			b.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n", status.ModelID, status.ChainState, status.DisplayVisibility, status.VerificationLabel, status.RewardState))
		}
		return b.String()
	case modelregistry.StatusProjection:
		return modelStatusProjectionTable(v)
	case []modelregistry.StatusProjection:
		var b strings.Builder
		b.WriteString(statusProjectionTableHeader())
		for _, status := range v {
			b.WriteString(statusProjectionTableRow(status))
		}
		return b.String()
	case modelregistry.ModelDetails:
		return modelStatusTable(v.Status)
	case TreasuryStatus:
		return fmt.Sprintf("destination\tdenom\tbalance\n%s\t%s\t%d\n", v.Destination, v.Denom, v.Balance)
	case Capability:
		return fmt.Sprintf("model_registry\tchallenge_verifier\n%t\t%t\n", v.ModelRegistry, v.ChallengeVerifier)
	case diagnostics.Diagnostics:
		return diagnosticsTable(v)
	case evidence.CleanupPlan:
		var b strings.Builder
		b.WriteString(fmt.Sprintf("current_height\tretention_policy_version\tminimum_retention_blocks\tplan_digest\titems\n%d\t%s\t%d\t%s\t%d\n", v.CurrentHeight, v.RetentionPolicyVersion, v.MinimumRetentionBlocks, v.Digest, len(v.Items)))
		if len(v.Items) > 0 {
			b.WriteString("task_hash\tdigest_sha256\tsize_bytes\tcleanup_height\tfinality_height\tterminal_or_settled\taction\n")
			for _, item := range v.Items {
				b.WriteString(fmt.Sprintf("%s\t%s\t%d\t%d\t%d\t%v\t%s\n", item.TaskHash, item.DigestSHA256, item.SizeBytes, item.CleanupHeight, item.FinalityHeight, item.TerminalOrSettled, item.Action))
			}
		}
		return b.String()
	case TaskQueueRequeueResponse:
		return fmt.Sprintf("queue_id\ttask_id\tstatus\tretry_count\tretry_at\tlast_error\n%s\t%s\t%s\t%d\t%s\t%s\n", v.QueueID, v.TaskID, v.Status, v.RetryCount, v.RetryAt, v.LastError)
	case TaskSettlementResponse:
		return fmt.Sprintf("task_id\tstatus\tsubmitted\tconfirmed\ttx_hash\tincluded_height\treject_reason\terror\n%s\t%s\t%t\t%t\t%s\t%d\t%s\t%s\n", v.TaskID, v.Status, v.Submitted, v.Confirmed, v.TxHash, v.IncludedHeight, truncateError(v.RejectReason), truncateError(v.Error))
	case TaskQueueListResponse:
		var b strings.Builder
		b.WriteString("queue_id\ttask_id\trole\tstage\tstatus\tretry_count\tretry_at\tdue_height\thalt_code\tlast_error\n")
		for _, row := range v.Rows {
			// halt_code is a column of its own rather than a prefix on
			// last_error: "which rows are halted" is the first question an
			// operator asks of this table and a grep must be able to answer it.
			halt := "-"
			if row.AutoHalted {
				halt = row.HaltCode
				if halt == "" {
					halt = "HALTED"
				}
			}
			b.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%d\t%s\t%d\t%s\t%s\n",
				row.QueueID, row.TaskID, row.Role, row.Stage, row.Status,
				row.RetryCount, row.RetryAt, row.DueHeight, halt, truncateError(row.LastError)))
		}
		return b.String()
	default:
		return fmt.Sprintf("%v\n", value)
	}
}

// truncateError keeps a table row on one terminal line. The JSON format carries
// the untruncated value, so nothing is lost where it matters.
func truncateError(message string) string {
	message = strings.ReplaceAll(strings.TrimSpace(message), "\n", " ")
	const limit = 80
	if len(message) <= limit {
		return message
	}
	return message[:limit-3] + "..."
}

func diagnosticsTable(report diagnostics.Diagnostics) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("mode\tmodel_transport\tkeeper_endpoint\tnexus_ingress\tnexus_nats\tnexus_envelope_auth_mode\tnexus_nats_identity\tsecurity_warnings\n%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n\n",
		report.Mode,
		report.ModelTransport,
		report.KeeperEndpoint,
		report.NexusIngress,
		report.NexusNATS,
		report.NexusEnvelopeAuthMode,
		formatNATSIdentityStatus(report.NexusNATSIdentity),
		strings.Join(report.SecurityWarnings, ","),
	))
	b.WriteString("name\tendpoint\tconfigured\tready\terror\n")
	for _, status := range report.Dependencies {
		b.WriteString(fmt.Sprintf("%s\t%s\t%t\t%t\t%s\n", status.Name, status.Endpoint, status.Configured, status.Ready, status.Error))
	}
	return b.String()
}

// formatNATSIdentityStatus renders the on-chain NATS identity binding for the
// table format: "(none)" when the node still connects with creds or a token,
// otherwise the generated public key, the on-chain nonce it was bound to, and
// the AUTH account whose sentinel JWT the CONNECT presents.
func formatNATSIdentityStatus(status *diagnostics.NATSIdentityStatus) string {
	if status == nil {
		return "(none)"
	}
	sentinel := status.SentinelAccount
	if sentinel == "" {
		sentinel = "(none)"
	}
	return fmt.Sprintf("%s nonce=%d sentinel_account=%s", status.UserPublicKey, status.BindingNonce, sentinel)
}

func modelStatusProjectionTable(status modelregistry.StatusProjection) string {
	return statusProjectionTableHeader() + statusProjectionTableRow(status)
}

func statusProjectionTableHeader() string {
	return "model_id\tprofile_version\tchain_state\tdisplay_visibility\tverification_label\treward_state\tsupport_state\tlast_p30_task_id\tp30_cutoff\ttop10_cutoff\tmark_gate_open\tlast_marked_task_id\tfailure_risk_count\tfailure_counts\ttreasury_denom\ttreasury_balance\tmaintenance_rate\tmax_reimbursement_per_task\thardware_tier\thardware_tier_proof_role\thardware_tier_proof_task_id\tbuilder_connected\tbuilder_missed_messages\tbuilder_faulted_messages\temergency_frozen\temergency_freeze_reason\tpending_task_fee\tclaimable_task_fee\ttask_finality_height\tclaimable_after_height\tclaim_responsibility\n"
}

func statusProjectionTableRow(status modelregistry.StatusProjection) string {
	return fmt.Sprintf(
		"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%t\t%s\t%d\t%s\t%s\t%d\t%d\t%d\t%s\t%s\t%s\t%t\t%d\t%d\t%t\t%s\t%d\t%d\t%d\t%d\t%s\n",
		status.ModelID,
		status.ProfileVersion,
		status.ChainState,
		status.DisplayVisibility,
		status.VerificationLabel,
		status.RewardState,
		status.Support.SupportState,
		status.Support.LastP30TaskID,
		status.MarkGate.P30Cutoff,
		status.MarkGate.Top10Cutoff,
		status.MarkGate.Open,
		status.MarkGate.LastMarkedTaskID,
		status.Risk.EmergencyFreezeRiskCount,
		formatRiskCounts(status.Risk.Counts),
		status.Treasury.Denom,
		status.Treasury.Balance,
		status.Treasury.MaintenanceRate,
		status.Treasury.MaxReimbursementPerTask,
		status.HardwareTierProof.HardwareTier,
		status.HardwareTierProof.Role,
		status.HardwareTierProof.TaskID,
		status.Builder.Connected,
		status.Builder.MissedMessages,
		status.Builder.FaultedMessages,
		status.EmergencyFreeze.Frozen,
		status.EmergencyFreeze.Reason,
		status.Earnings.PendingTaskFee,
		status.Earnings.ClaimableTaskFee,
		status.Earnings.TaskFinalityHeight,
		status.Earnings.ClaimableAfterHeight,
		status.Earnings.ClaimResponsibility,
	)
}

func formatRiskCounts(counts map[string]uint64) string {
	if len(counts) == 0 {
		return ""
	}
	classes := make([]string, 0, len(counts))
	for class := range counts {
		classes = append(classes, class)
	}
	sort.Strings(classes)
	parts := make([]string, 0, len(classes))
	for _, class := range classes {
		parts = append(parts, fmt.Sprintf("%s:%d", class, counts[class]))
	}
	return strings.Join(parts, ",")
}

func modelStatusTable(status modelregistry.ModelStatus) string {
	return fmt.Sprintf(
		"model_id\tchain_state\tdisplay_visibility\tverification_label\treward_state\n%s\t%s\t%s\t%s\t%s\n",
		status.ModelID,
		status.ChainState,
		status.DisplayVisibility,
		status.VerificationLabel,
		status.RewardState,
	)
}

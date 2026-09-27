package modelregistry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/keepercontract"
	"github.com/TrueOpen/cortex/internal/txclient"
)

const (
	FeeKindRegistration          = "registration"
	KeeperRegistrationFeeMin     = uint64(10_000_000)
	KeeperRegistrationFeeMax     = uint64(50_000_000)
	KeeperIntegrationRuleVersion = "DEBUG_KEEPER_INTEGRATION_V1"

	RegistrationStagePlanned   = "planned"
	RegistrationStageSubmitted = "submitted"
	RegistrationStageSkipped   = "skipped"
	RegistrationStageFailed    = "failed"

	SubmitDirect     SubmitMode = "direct"
	SubmitViaBuilder SubmitMode = "via-builder"
)

type SubmitMode string

type RegistryConfig struct {
	CurrentRegistrationReader    CurrentRegistrationReader
	CurrentRegistrationSubmitter CurrentRegistrationSubmitter
	CurrentRegistrationSigner    CurrentRegistrationSigner
	ChainID                      string
	ProposerAddress              string
	RegistrationReader           RegistrationReader
	RegistrationSponsor          string
	// NowHeight resolves the current chain height. It must report an error
	// when the height cannot be determined so callers fail closed instead of
	// treating an unknown height as zero.
	NowHeight                  func() (uint64, error)
	Treasury                   string
	FeeDenom                   string
	Submitter                  TxSubmitter
	Outbox                     BuilderOutbox
	SelfTester                 SelfTestFunc
	Signer                     Signer
	FeeGrant                   StaticFeeGrant
	MinGasGrant                uint64
	SupporterAddress           string
	InferenceCapability        bool
	VerificationCapability     bool
	SupportConfirmer           SupportConfirmer
	RequireSupportConfirmation bool
}

type Registry struct {
	currentRegistrationReader    CurrentRegistrationReader
	currentRegistrationSubmitter CurrentRegistrationSubmitter
	currentRegistrationSigner    CurrentRegistrationSigner
	chainID                      string
	proposerAddress              string
	mu                           sync.RWMutex
	registrationReader           RegistrationReader
	registrationSponsor          string
	nowHeight                    func() (uint64, error)
	treasury                     string
	feeDenom                     string
	submitter                    TxSubmitter
	outbox                       BuilderOutbox
	selfTester                   SelfTestFunc
	signer                       Signer
	feeGrant                     StaticFeeGrant
	minGasGrant                  uint64
	supporterAddress             string
	inferenceCapability          bool
	verificationCapability       bool
	supportConfirmer             SupportConfirmer
	requireSupportConfirmation   bool
	statuses                     map[string]ModelStatus
	projections                  map[string]StatusProjection
	manifests                    map[string]Manifest
}

type SelfTestFunc func(context.Context, Manifest) (SelfTestResult, error)

type Signer func(context.Context, RegistrationMaterial) (string, error)

type TxSubmitter interface {
	SubmitRegistration(context.Context, RegistrationMaterial) (string, error)
}

type RegistrationReader interface {
	Params(context.Context) (chainclient.ParamsSnapshot, error)
	Model(context.Context, string) (chainclient.ModelSnapshot, error)
	Profile(context.Context, string, string) (chainclient.ProfileSnapshot, error)
}

type BuilderOutbox interface {
	WriteRegistration(context.Context, OutboxMessage) (string, error)
}

type SupportConfirmer interface {
	ConfirmSupport(context.Context, SupportMaterial) (string, error)
}

type SelfTestResult struct {
	Passed               bool
	Error                string
	RegistrationMaterial *RegistrationMaterial
}

type RegistrationMaterial struct {
	ManifestHash          string                                     `json:"manifest_hash"`
	QuoteHeight           uint64                                     `json:"quote_height"`
	QuoteExpiresAtHeight  uint64                                     `json:"quote_expires_at_height"`
	FeeDenom              string                                     `json:"fee_denom"`
	TreasuryDestination   string                                     `json:"treasury_destination"`
	FeeKind               string                                     `json:"fee_kind"`
	SignedEnvelope        string                                     `json:"signed_envelope"`
	FeeAmount             uint64                                     `json:"fee_amount"`
	GasLimit              uint64                                     `json:"gas_limit"`
	AuthorizationGranter  string                                     `json:"authorization_granter,omitempty"`
	AuthorizationFeeGrant uint64                                     `json:"authorization_fee_grant,omitempty"`
	Message               txclient.LegacyRegisterModelProfileMessage `json:"-"`
}

const (
	SupportModeDeclared = "declared"
	SupportModeDaily    = "daily"
)

type SupportMaterial struct {
	ModelID                            string `json:"model_id"`
	ProfileVersion                     string `json:"profile_version"`
	SupporterAddress                   string `json:"supporter_address"`
	SupportMode                        string `json:"support_mode"`
	Supported                          bool   `json:"supported"`
	EpochIndex                         uint64 `json:"epoch_index"`
	SupportDigest                      string `json:"support_digest"`
	SignedEnvelope                     string `json:"signed_envelope"`
	CapabilityMetadataHash             string `json:"capability_metadata_hash"`
	VerificationCapabilityMetadataHash string `json:"verification_capability_metadata_hash"`
	InferenceCapability                bool   `json:"inference_capability"`
	VerificationCapability             bool   `json:"verification_capability"`
}

// OperatorSupportIntent is the exact MsgDeclareModelSupport body that an
// operator-controlled Cosmos wallet must sign and broadcast. cortexd never
// signs or submits this operator-only message.
type OperatorSupportIntent struct {
	TypeURL string                              `json:"type_url"`
	Message txclient.DeclareModelSupportMessage `json:"message"`
}

type FeeQuote struct {
	Height              uint64
	ExpiresAtHeight     uint64
	Denom               string
	TreasuryDestination string
	FeeKind             string
	Amount              uint64
	GasLimit            uint64
}

type StaticFeeGrant struct {
	Granter  string
	Amount   uint64
	GasLimit uint64
}

type RegisterRequest struct {
	Manifest               Manifest `json:"manifest"`
	ModelRegistrationFee   uint64   `json:"model_registration_fee"`
	ProfileRegistrationFee uint64   `json:"profile_registration_fee"`
	DryRun                 bool     `json:"dry_run"`

	// Legacy fields remain internal while older daemon paths are migrated.
	Quote FeeQuote   `json:"-"`
	Mode  SubmitMode `json:"-"`
	Wait  bool       `json:"-"`
}

type RegisterResult struct {
	ManifestHash string                  `json:"manifest_hash"`
	ModelStage   RegistrationStageResult `json:"model"`
	ProfileStage RegistrationStageResult `json:"profile"`
	TxID         string                  `json:"-"`
	OutboxID     string                  `json:"-"`
	DryRun       bool                    `json:"dry_run"`
	Material     RegistrationMaterial    `json:"-"`
}

type RegistrationStageResult struct {
	Status string `json:"status"`
	TxID   string `json:"tx_id,omitempty"`
}

type OutboxMessage struct {
	Material      RegistrationMaterial
	Authorization BuilderAuthorization
}

type BuilderAuthorization struct {
	Granter               string
	CoversRegistrationFee bool
	CoversGas             bool
	RegistrationFeeAmount uint64
	GasLimit              uint64
	TreasuryDestination   string
	RegistrationFeeDenom  string
	RegistrationFeeKind   string
	QuoteHeight           uint64
	QuoteExpiresAtHeight  uint64
	SignedEnvelope        string
}

func NewRegistry(config RegistryConfig) *Registry {
	nowHeight := config.NowHeight
	if nowHeight == nil {
		nowHeight = func() (uint64, error) {
			return 0, fmt.Errorf("chain height resolver is required")
		}
	}
	return &Registry{
		currentRegistrationReader:    config.CurrentRegistrationReader,
		currentRegistrationSubmitter: config.CurrentRegistrationSubmitter,
		currentRegistrationSigner:    config.CurrentRegistrationSigner,
		chainID:                      strings.TrimSpace(config.ChainID),
		proposerAddress:              strings.TrimSpace(config.ProposerAddress),
		registrationReader:           config.RegistrationReader,
		registrationSponsor:          strings.TrimSpace(config.RegistrationSponsor),
		nowHeight:                    nowHeight,
		treasury:                     strings.TrimSpace(config.Treasury),
		feeDenom:                     strings.TrimSpace(config.FeeDenom),
		submitter:                    config.Submitter,
		outbox:                       config.Outbox,
		selfTester:                   config.SelfTester,
		signer:                       config.Signer,
		feeGrant:                     config.FeeGrant,
		minGasGrant:                  config.MinGasGrant,
		supporterAddress:             strings.TrimSpace(config.SupporterAddress),
		inferenceCapability:          config.InferenceCapability,
		verificationCapability:       config.VerificationCapability,
		supportConfirmer:             config.SupportConfirmer,
		requireSupportConfirmation:   config.RequireSupportConfirmation,
		statuses:                     make(map[string]ModelStatus),
		projections:                  make(map[string]StatusProjection),
		manifests:                    make(map[string]Manifest),
	}
}

func (r *Registry) GenerateManifest(_ context.Context, input ManifestInput) (Manifest, error) {
	return GenerateManifest(input)
}

func (r *Registry) ValidateManifest(_ context.Context, manifest Manifest) error {
	return ValidateManifest(manifest)
}

func (r *Registry) SelfTest(ctx context.Context, manifest Manifest) (*RegistrationMaterial, error) {
	if err := ValidateManifest(manifest); err != nil {
		return nil, err
	}
	if r.selfTester == nil {
		return &RegistrationMaterial{ManifestHash: manifest.Hash}, nil
	}
	result, err := r.selfTester(ctx, manifest)
	if err != nil {
		return nil, err
	}
	if !result.Passed {
		if result.Error == "" {
			result.Error = "self-test failed"
		}
		return nil, errors.New(result.Error)
	}
	if result.RegistrationMaterial == nil {
		return &RegistrationMaterial{ManifestHash: manifest.Hash}, nil
	}
	material := *result.RegistrationMaterial
	if material.ManifestHash == "" {
		material.ManifestHash = manifest.Hash
	}
	return &material, nil
}

func (r *Registry) Register(ctx context.Context, req RegisterRequest) (RegisterResult, error) {
	if req.ModelRegistrationFee != 0 || req.ProfileRegistrationFee != 0 {
		return RegisterResult{}, ErrKeeperModelRegistrationUnavailable
	}
	if req.Mode == "" {
		req.Mode = SubmitDirect
	}
	material, err := r.SelfTest(ctx, req.Manifest)
	if err != nil {
		return RegisterResult{}, err
	}
	if err := r.validateQuote(req.Quote); err != nil {
		return RegisterResult{}, err
	}
	if err := r.validateFeeGrant(req.Quote); err != nil {
		return RegisterResult{}, err
	}
	r.bindRegistrationMaterial(material, req.Manifest, req.Quote)
	if r.signer == nil {
		return RegisterResult{}, fmt.Errorf("model registration signer is required")
	}
	// The signature travels as material.SignedEnvelope: the builder outbox frames
	// it into the published registration payload and into that payload's dedup
	// digest, and a dry run returns it for offline inspection. material.Message is
	// only the signing preimage - it is json:"-" and the signer clears
	// RegistrantSignature before hashing - so writing the signature back into it
	// would be work no reader can ever observe.
	signed, err := r.signer(ctx, *material)
	if err != nil {
		return RegisterResult{}, err
	}
	material.SignedEnvelope = signed
	result := RegisterResult{
		ManifestHash: material.ManifestHash,
		DryRun:       req.DryRun,
		Material:     *material,
	}
	if req.DryRun {
		return result, nil
	}
	switch req.Mode {
	case SubmitDirect:
		if r.submitter == nil {
			return RegisterResult{}, fmt.Errorf("tx submitter is required")
		}
		txID, err := r.submitter.SubmitRegistration(ctx, *material)
		if err != nil {
			return RegisterResult{}, err
		}
		result.TxID = txID
	case SubmitViaBuilder:
		if r.outbox == nil {
			return RegisterResult{}, fmt.Errorf("builder outbox is required")
		}
		outboxID, err := r.outbox.WriteRegistration(ctx, OutboxMessage{
			Material:      *material,
			Authorization: r.builderAuthorization(req.Quote, *material),
		})
		if err != nil {
			return RegisterResult{}, err
		}
		result.OutboxID = outboxID
	default:
		return RegisterResult{}, fmt.Errorf("unknown submit mode %q", req.Mode)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manifests[req.Manifest.Hash] = cloneManifest(req.Manifest)
	r.statuses[req.Manifest.ModelID] = ModelStatus{
		ModelID:             req.Manifest.ModelID,
		ManifestHash:        req.Manifest.Hash,
		ProfileVersion:      req.Manifest.Verification.ProfileVersion,
		ChainState:          "registration_submitted",
		DisplayVisibility:   "hidden",
		VerificationLabel:   "unverified",
		RewardState:         "pending",
		Supported:           false,
		DailySupportEnabled: false,
	}
	return result, nil
}

func (r *Registry) PrepareOperatorSupportIntent(_ context.Context, req SupportRequest) (OperatorSupportIntent, error) {
	if !req.Supported {
		return OperatorSupportIntent{}, fmt.Errorf("Keeper does not define an undeclare/disable support message")
	}
	modelID := strings.TrimSpace(req.ModelID)
	if modelID == "" {
		return OperatorSupportIntent{}, fmt.Errorf("model_id is required")
	}
	// Support is declared per model; no profile version is carried.
	message := txclient.DeclareModelSupportMessage{
		OperatorAddress:        r.supporterAddress,
		ModelID:                txclient.ProtoBytes32(modelID),
		InferenceCapability:    r.inferenceCapability,
		VerificationCapability: r.verificationCapability,
	}
	if _, err := txclient.MarshalMessage(txclient.MsgDeclareModelSupport, message); err != nil {
		return OperatorSupportIntent{}, err
	}
	return OperatorSupportIntent{TypeURL: txclient.MsgDeclareModelSupport.String(), Message: message}, nil
}

func (r *Registry) Support(_ context.Context, req SupportRequest) (ModelStatus, error) {
	if !req.DryRun {
		return ModelStatus{}, ErrOperatorModelSupportSignatureRequired
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	status, err := r.ensureStatusLocked(req.ModelID)
	if err != nil {
		return ModelStatus{}, err
	}
	status.Supported = req.Supported
	return status, nil
}

func (r *Registry) DailySupport(ctx context.Context, req DailySupportRequest) (ModelStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	status, err := r.ensureStatusLocked(req.ModelID)
	if err != nil {
		return ModelStatus{}, err
	}
	status.DailySupportEnabled = req.Enabled
	if req.DryRun {
		return status, nil
	}
	if err := r.confirmSupportLocked(ctx, status, SupportModeDaily, req.Enabled); err != nil {
		return ModelStatus{}, err
	}
	r.statuses[req.ModelID] = status
	return status, nil
}

func (r *Registry) confirmSupportLocked(ctx context.Context, status ModelStatus, mode string, enabled bool) error {
	if r.supportConfirmer == nil {
		if r.requireSupportConfirmation {
			return fmt.Errorf("support confirmation client is required")
		}
		return nil
	}
	profileVersion := status.ProfileVersion
	if profileVersion == "" {
		profileVersion = status.ManifestHash
	}
	currentHeight, err := r.currentHeight()
	if err != nil {
		return err
	}
	material := SupportMaterial{
		ModelID:          status.ModelID,
		ProfileVersion:   profileVersion,
		SupporterAddress: r.supporterAddress,
		SupportMode:      mode,
		Supported:        enabled,
		EpochIndex:       keepercontract.TaskEpoch(currentHeight),
	}
	if manifest, ok := r.manifests[status.ManifestHash]; ok {
		material.CapabilityMetadataHash = strings.TrimPrefix(manifest.MetadataHash, "sha256:")
		verificationProfile, _ := json.Marshal(manifest.Verification)
		verificationHash := sha256.Sum256(verificationProfile)
		material.VerificationCapabilityMetadataHash = hex.EncodeToString(verificationHash[:])
	}
	material.InferenceCapability = r.inferenceCapability
	material.VerificationCapability = r.verificationCapability
	material.SupportDigest = SupportDigest(material)
	_, signsInternally := r.supportConfirmer.(interface{ SignsSupportInternally() bool })
	if !signsInternally && r.signer != nil {
		signed, err := r.signer(ctx, RegistrationMaterial{ManifestHash: material.SupportDigest})
		if err != nil {
			return err
		}
		material.SignedEnvelope = signed
	} else if !signsInternally {
		material.SignedEnvelope = "unsigned-support:" + material.SupportDigest
	}
	if _, err := r.supportConfirmer.ConfirmSupport(ctx, material); err != nil {
		return err
	}
	return nil
}

func SupportDigest(material SupportMaterial) string {
	canonical := struct {
		ModelID                            string `json:"model_id"`
		ProfileVersion                     string `json:"profile_version"`
		SupporterAddress                   string `json:"supporter_address"`
		SupportMode                        string `json:"support_mode"`
		Supported                          bool   `json:"supported"`
		EpochIndex                         uint64 `json:"epoch_index"`
		CapabilityMetadataHash             string `json:"capability_metadata_hash"`
		VerificationCapabilityMetadataHash string `json:"verification_capability_metadata_hash"`
		InferenceCapability                bool   `json:"inference_capability"`
		VerificationCapability             bool   `json:"verification_capability"`
	}{
		ModelID: material.ModelID, ProfileVersion: material.ProfileVersion, SupporterAddress: material.SupporterAddress,
		SupportMode: material.SupportMode, Supported: material.Supported, EpochIndex: material.EpochIndex,
		CapabilityMetadataHash: material.CapabilityMetadataHash, VerificationCapabilityMetadataHash: material.VerificationCapabilityMetadataHash,
		InferenceCapability: material.InferenceCapability, VerificationCapability: material.VerificationCapability,
	}
	payload, _ := json.Marshal(canonical)
	digest := codec.HashWithDomain("CORTEX_MODEL_SUPPORT_V1", payload)
	return hex.EncodeToString(digest[:])
}

// currentHeight resolves the chain height and refuses to return an unusable
// value. An unknown height must not be silently treated as zero, because every
// height comparison would then pass.
func (r *Registry) currentHeight() (uint64, error) {
	height, err := r.nowHeight()
	if err != nil {
		return 0, fmt.Errorf("resolve current chain height: %w", err)
	}
	if height == 0 {
		return 0, fmt.Errorf("current chain height is unavailable")
	}
	return height, nil
}

func (r *Registry) validateQuote(quote FeeQuote) error {
	if quote.Height == 0 {
		return fmt.Errorf("fee quote height is required")
	}
	currentHeight, err := r.currentHeight()
	if err != nil {
		return err
	}
	if quote.ExpiresAtHeight <= currentHeight {
		return fmt.Errorf("fee quote expired")
	}
	if quote.Denom != r.feeDenom {
		return fmt.Errorf("fee quote denom %q does not match %q", quote.Denom, r.feeDenom)
	}
	if quote.TreasuryDestination != r.treasury {
		return fmt.Errorf("fee quote treasury %q does not match %q", quote.TreasuryDestination, r.treasury)
	}
	if quote.FeeKind != FeeKindRegistration {
		return fmt.Errorf("fee quote kind %q does not match %q", quote.FeeKind, FeeKindRegistration)
	}
	if quote.Amount == 0 {
		return fmt.Errorf("fee quote amount is required")
	}
	return nil
}

func (r *Registry) validateFeeGrant(quote FeeQuote) error {
	if r.feeGrant.Amount < quote.Amount {
		return fmt.Errorf("insufficient fee grant")
	}
	if r.feeGrant.GasLimit < r.minGasGrant {
		return fmt.Errorf("insufficient gas authorization")
	}
	if r.feeGrant.GasLimit < quote.GasLimit {
		return fmt.Errorf("gas authorization below quote gas limit")
	}
	return nil
}

func (r *Registry) bindRegistrationMaterial(material *RegistrationMaterial, manifest Manifest, quote FeeQuote) {
	material.QuoteHeight = quote.Height
	material.QuoteExpiresAtHeight = quote.ExpiresAtHeight
	material.FeeDenom = quote.Denom
	material.TreasuryDestination = quote.TreasuryDestination
	material.FeeKind = quote.FeeKind
	material.FeeAmount = quote.Amount
	material.GasLimit = quote.GasLimit
	material.AuthorizationGranter = r.feeGrant.Granter
	material.AuthorizationFeeGrant = r.feeGrant.Amount
	verificationProfile, _ := json.Marshal(manifest.Verification)
	pricingProfile, _ := json.Marshal(manifest.Pricing)
	material.Message = txclient.LegacyRegisterModelProfileMessage{
		ModelID: manifest.ModelID, ProfileVersion: manifest.Verification.ProfileVersion,
		ManifestHash: strings.TrimPrefix(manifest.Hash, "sha256:"), TokenizerHash: strings.TrimPrefix(manifest.TokenizerHash, "sha256:"),
		RuntimeVersion: manifest.RuntimeVersion, ResourceTier: fmt.Sprintf("%d", manifest.ResourceTier), MinStake: txclient.ProtoUint64(manifest.MinStake),
		ChallengeOpenWindowBlocks: txclient.ProtoUint64(manifest.ChallengeOpenWindowBlocks), VerificationProfile: string(verificationProfile),
		PricingProfile: string(pricingProfile), EpsilonParams: manifest.EpsilonParams, TimeoutBootstrapProfile: manifest.TimeoutBootstrapProfile,
		SchemaHash: strings.TrimPrefix(manifest.SchemaHash, "sha256:"), PreviousProfileVersion: manifest.PreviousProfileVersion,
		RegistrationFee: txclient.CoinMessage{Denom: quote.Denom, Amount: txclient.ProtoUint64(quote.Amount)},
		MetadataHash:    strings.TrimPrefix(manifest.MetadataHash, "sha256:"), OptionalDisplayTagHash: strings.TrimPrefix(manifest.DisplayTagHash, "sha256:"),
	}
}

func (r *Registry) builderAuthorization(quote FeeQuote, material RegistrationMaterial) BuilderAuthorization {
	return BuilderAuthorization{
		Granter:               r.feeGrant.Granter,
		CoversRegistrationFee: r.feeGrant.Amount >= quote.Amount,
		CoversGas:             r.feeGrant.GasLimit >= quote.GasLimit,
		RegistrationFeeAmount: quote.Amount,
		GasLimit:              quote.GasLimit,
		TreasuryDestination:   quote.TreasuryDestination,
		RegistrationFeeDenom:  quote.Denom,
		RegistrationFeeKind:   quote.FeeKind,
		QuoteHeight:           quote.Height,
		QuoteExpiresAtHeight:  quote.ExpiresAtHeight,
		SignedEnvelope:        material.SignedEnvelope,
	}
}

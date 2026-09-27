package modelregistry

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/keepercontract"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/txclient"
)

type txSubmitter struct {
	tx      txclient.Client
	options TxSubmitterOptions
}

var ErrKeeperModelRegistrationUnavailable = errors.New("Keeper does not register a model/profile creation message")

// ErrRegistrationPublishRequiresOperatorRetry reports that Cortex did not
// durably queue the registration. The operator may retry the complete request;
// the reconstructed payload, task ID, subject, and downstream dedup identity
// remain stable for identical signed material.
var ErrRegistrationPublishRequiresOperatorRetry = errors.New("registration publish requires operator retry")

// ErrOperatorModelSupportSignatureRequired is returned when a daemon path is
// asked to submit MsgDeclareModelSupport. Node requires the operator Cosmos
// account as the sole signer; the service key is valid only for daily support.
var ErrOperatorModelSupportSignatureRequired = errors.New("model support declaration requires an operator-signed Cosmos transaction; prepare an operator support intent instead")

func NewRegistrationDigestSigner(client signer.DigestSigner, keyRef string, address string) Signer {
	return func(ctx context.Context, material RegistrationMaterial) (string, error) {
		if client == nil {
			return "", fmt.Errorf("model registration digest signer is required")
		}
		message := material.Message
		message.RegistrantSignature = ""
		canonical, err := json.Marshal(message)
		if err != nil {
			return "", err
		}
		digest := codec.HashBytes(canonical)
		signature, err := client.SignDigest(ctx, signer.DigestRequest{KeyRef: keyRef, ExpectedSignerAddress: address, Digest: digest})
		if err != nil {
			return "", err
		}
		if len(signature) != 64 {
			return "", fmt.Errorf("model registration signer returned an invalid signature length")
		}
		return hex.EncodeToString(signature), nil
	}
}

func NewCurrentRegistrationDigestSigner(client signer.DigestSigner, keyRef string, address string) CurrentRegistrationSigner {
	return func(ctx context.Context, digest codec.Hash) (txclient.ProtoBytes, error) {
		if client == nil {
			return "", fmt.Errorf("model registration digest signer is required")
		}
		signature, err := client.SignDigest(ctx, signer.DigestRequest{KeyRef: keyRef, ExpectedSignerAddress: address, Digest: digest})
		if err != nil {
			return "", err
		}
		if len(signature) != 64 {
			return "", fmt.Errorf("model registration signer returned an invalid signature length")
		}
		return txclient.ProtoBytes(hex.EncodeToString(signature)), nil
	}
}

type TxSubmitterOptions struct {
	GasPayer string
	FeeCap   txclient.Coin
	FeeGrant string
	Memo     string
}

// NewCurrentRegistrationSubmitter builds the only registration submitter that
// targets a registered Keeper message: MsgRegisterModelProfile. There is
// deliberately no txclient-backed TxSubmitter any more - the Keeper registers no
// model/profile creation message for the legacy flat material, so such a
// submitter could only ever refuse, and every caller had to sign the material
// first to reach that refusal.
func NewCurrentRegistrationSubmitter(tx txclient.Client, options TxSubmitterOptions) CurrentRegistrationSubmitter {
	return txSubmitter{tx: tx, options: options}
}

func (s txSubmitter) SubmitModelProfile(ctx context.Context, message txclient.RegisterModelProfileMessage) (string, error) {
	taskID := "model-profile-registration:" + string(message.Profile.ModelID) + "/" + strconv.FormatUint(uint64(message.Profile.ProfileVersion), 10)
	return s.submitKeeperRegistration(ctx, taskID, txclient.MsgRegisterModelProfile, message)
}

func (s txSubmitter) submitKeeperRegistration(ctx context.Context, taskID string, kind txclient.Kind, message any) (string, error) {
	if s.tx == nil {
		return "", fmt.Errorf("tx client is required")
	}
	payload, err := txclient.MarshalMessage(kind, message)
	if err != nil {
		return "", err
	}
	digest := codec.HashWithDomain("CORTEX_KEEPER_MODEL_REGISTRATION_V2", []byte(kind), payload)
	observation, err := s.tx.Submit(ctx, txclient.Request{
		TaskID: taskID, Kind: kind, Payload: payload, GasPayer: s.options.GasPayer,
		FeeCap: s.options.FeeCap, FeeGrant: s.options.FeeGrant, Memo: s.options.Memo, MaterialDigest: digest,
	})
	if err != nil {
		return "", err
	}
	if observation.Rejected {
		return "", fmt.Errorf("Keeper rejected %s: %s", kind, observation.RejectReason)
	}
	if !observation.Accepted || observation.TxHash == "" {
		return "", fmt.Errorf("Keeper did not confirm %s", kind)
	}
	return observation.TxHash, nil
}

type builderRegistrationPublisher struct{ builder builderclient.Publisher }

// NewBuilderRegistrationPublisher reconstructs the complete registration
// frame from the authoritative operator request on every attempt. Its stable
// digest is also the downstream deduplication identity, so no KV outbox is
// needed.
func NewBuilderRegistrationPublisher(builder builderclient.Publisher) BuilderOutbox {
	return builderRegistrationPublisher{builder: builder}
}

func (o builderRegistrationPublisher) WriteRegistration(ctx context.Context, msg OutboxMessage) (string, error) {
	if o.builder == nil {
		return "", fmt.Errorf("builder client is required")
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}
	digestHash := codec.HashWithDomain(
		"CORTEX_MODEL_REGISTRATION_OUTBOX_V1",
		[]byte(msg.Material.ManifestHash),
		[]byte(msg.Material.SignedEnvelope),
		payload,
	)
	digest := hex.EncodeToString(digestHash[:])
	if err := o.builder.Publish(ctx, builderclient.PublishRequest{
		Subject: builderclient.NATSModelRegistrationSubject(digest),
		TaskID:  "model-registration-" + digest,
		Payload: payload,
	}); err != nil {
		return "", fmt.Errorf("%w: %w", ErrRegistrationPublishRequiresOperatorRetry, err)
	}
	return digest, nil
}

type TxSupportConfirmerOptions struct {
	ChainID         string
	OperatorAddress string
	Signer          signer.DigestSigner
	ServiceKeyRef   string
	ServiceAddress  string
	ServiceIdentity func(context.Context) (serviceAuthorizationNonce, committedHeight, epoch, expiryHeight uint64, err error)
	GasPayer        string
	FeeCap          txclient.Coin
	FeeGrant        string
	// SupportedModels is every model this node is configured to support
	// (the models of local_identity.supported_model_profiles), in any order.
	// Node keeps one daily support record per (epoch, operator), so each daily
	// confirmation carries this whole set rather than the one model it was
	// requested for.
	SupportedModels []string
}

type txSupportConfirmer struct {
	tx      txclient.Client
	options TxSupportConfirmerOptions
}

func NewTxSupportConfirmer(tx txclient.Client, options TxSupportConfirmerOptions) SupportConfirmer {
	return txSupportConfirmer{tx: tx, options: options}
}

func (txSupportConfirmer) SignsSupportInternally() bool { return true }

func (c txSupportConfirmer) ConfirmSupport(ctx context.Context, material SupportMaterial) (string, error) {
	if c.tx == nil || c.options.Signer == nil {
		return "", fmt.Errorf("tx client and support signer are required")
	}
	if !material.Supported {
		return "", fmt.Errorf("Keeper does not define an undeclare/disable support message")
	}
	switch material.SupportMode {
	case SupportModeDeclared:
		return "", ErrOperatorModelSupportSignatureRequired
	case SupportModeDaily:
		if c.options.ServiceIdentity == nil {
			return "", fmt.Errorf("current service identity reader is required")
		}
		models, err := c.dailySupportModels(material.ModelID)
		if err != nil {
			return "", err
		}
		nonce, committedHeight, epoch, expiryHeight, err := c.options.ServiceIdentity(ctx)
		if err != nil {
			return "", fmt.Errorf("read current service identity: %w", err)
		}
		if nonce == 0 || committedHeight == 0 || committedHeight == ^uint64(0) || expiryHeight < committedHeight {
			return "", fmt.Errorf("current service identity nonce, committed height, and expiry are required")
		}
		material.EpochIndex = epoch
		digest, err := keepercontract.DailySupportConfirmation(
			c.options.ChainID, c.options.OperatorAddress, material.EpochIndex, nonce, expiryHeight, models,
		)
		if err != nil {
			return "", err
		}
		signature, err := c.sign(ctx, digest)
		if err != nil {
			return "", err
		}
		supportedModels := make([]txclient.ProtoBytes32, len(models))
		for i, model := range models {
			supportedModels[i] = txclient.ProtoBytes32(model)
		}
		confirmations := []txclient.ModelSupportConfirmation{{
			OperatorAddress:           c.options.OperatorAddress,
			SupportedModels:           supportedModels,
			ServiceAuthorizationNonce: txclient.ProtoUint64(nonce), ExpiryHeight: txclient.ProtoUint64(expiryHeight),
			ServiceSignature: txclient.ProtoBytes(signature),
		}}
		message := txclient.BatchConfirmModelSupportMessage{SubmitterAddress: c.options.ServiceAddress, EpochIndex: txclient.ProtoUint64(material.EpochIndex), Confirmations: confirmations}
		material.SupportDigest = hex.EncodeToString(digest[:])
		material.SignedEnvelope = signature
		// The confirmation is one record per (epoch, operator), so that is the
		// identity the tx is tracked under, not the model it was requested for.
		taskID := "model-support-daily:" + c.options.OperatorAddress + ":" + strconv.FormatUint(material.EpochIndex, 10)
		return c.submitAndConfirm(ctx, material, taskID, txclient.MsgBatchConfirmModelSupport, message, digest)
	default:
		return "", fmt.Errorf("unsupported model support mode %q", material.SupportMode)
	}
}

func (c txSupportConfirmer) sign(ctx context.Context, digest codec.Hash) (string, error) {
	signature, err := c.options.Signer.SignDigest(ctx, signer.DigestRequest{KeyRef: c.options.ServiceKeyRef, ExpectedSignerAddress: c.options.ServiceAddress, Digest: digest})
	if err != nil {
		return "", err
	}
	if len(signature) != 64 {
		return "", fmt.Errorf("support signer returned an invalid signature length")
	}
	return hex.EncodeToString(signature), nil
}

// dailySupportModels returns the configured model set in Node's canonical
// order, after checking that the requested model belongs to it. Confirming a
// model outside the configured set would drop every configured one from the
// epoch's single record.
func (c txSupportConfirmer) dailySupportModels(requested string) ([]string, error) {
	if len(c.options.SupportedModels) == 0 {
		return nil, fmt.Errorf("daily support requires the configured local_identity.supported_model_profiles")
	}
	models, err := keepercontract.CanonicalModelIDs(c.options.SupportedModels)
	if err != nil {
		return nil, fmt.Errorf("configured supported models: %w", err)
	}
	if !slices.Contains(models, requested) {
		return nil, fmt.Errorf("model %s is not in local_identity.supported_model_profiles", requested)
	}
	return models, nil
}

func (c txSupportConfirmer) submitAndConfirm(ctx context.Context, material SupportMaterial, taskID string, kind txclient.Kind, message any, materialDigest codec.Hash) (string, error) {
	payload, err := txclient.MarshalMessage(kind, message)
	if err != nil {
		return "", err
	}
	obs, err := c.tx.Submit(ctx, txclient.Request{TaskID: taskID, Kind: kind, Payload: payload, GasPayer: c.options.GasPayer, FeeCap: c.options.FeeCap, FeeGrant: c.options.FeeGrant, MaterialDigest: materialDigest})
	if err != nil {
		return "", err
	}
	confirmationID := SupportConfirmationID(material)
	if obs.Rejected {
		return "", fmt.Errorf("model support tx rejected: %s", obs.RejectReason)
	}
	if !obs.Accepted {
		return "", fmt.Errorf("model support tx not Keeper-confirmed")
	}
	return confirmationID, nil
}

func SupportConfirmationID(material SupportMaterial) string {
	digest := codec.HashWithDomain(
		"CORTEX_MODEL_SUPPORT_CONFIRMATION_V1",
		[]byte(material.ModelID),
		[]byte(material.ProfileVersion),
		[]byte(material.SupporterAddress),
		[]byte(material.SupportMode),
		[]byte(material.SupportDigest),
	)
	return hex.EncodeToString(digest[:])
}

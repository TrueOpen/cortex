package modelregistry

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/keepercontract"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/txclient"
	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
)

type txSubmitter struct {
	tx      txclient.Client
	options TxSubmitterOptions
}

var ErrKeeperModelRegistrationUnavailable = errors.New("Keeper does not register a model/profile creation message")

// ErrOperatorModelSupportSignatureRequired is returned when a daemon path is
// asked to submit MsgDeclareModelSupport. Node requires the operator Cosmos
// account as the sole signer; the service key is valid only for daily support.
var ErrOperatorModelSupportSignatureRequired = errors.New("model support declaration requires an operator-signed Cosmos transaction; prepare an operator support intent instead")

type TxSubmitterOptions struct {
	GasPayer string
	FeeCap   txclient.Coin
	FeeGrant string
	Memo     string
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
	// Workload resolves the tx client and the Keeper-confirmed current service
	// address at call time. cortexd builds the confirmer at boot, before the
	// first Keeper poll activates the workload, so a client and address read
	// then are always nil and empty and renewal would never succeed. When set,
	// its answer replaces the constructor's tx client, ServiceAddress and
	// GasPayer.
	Workload func() (txclient.Client, string)
	// TxUnavailable says why there is no tx client, for the refusal; nil
	// means "the workload is not active yet".
	TxUnavailable func() string
	// Relay hands the daily confirmation to a Builder that batches it and pays
	// the fee (IngressAPI SubmitModelSupportConfirmation). It is used only when
	// this node cannot submit its own transaction, which is every node whose
	// signer is a file:// keystore. Nil leaves self-submission the only route.
	Relay SupportRelay
	// RelayServiceAddress is the Keeper-confirmed current service address the
	// relayed confirmation is signed as; empty until the workload activates.
	RelayServiceAddress func() string
}

// SupportRelay delivers one service-signed daily support confirmation (the
// protobuf binary of hub.v1.ModelSupportConfirmationV1) for the given epoch. A
// nil return is the relay's acceptance, not an on-chain refresh: the caller
// learns that from the chain's support rows.
type SupportRelay interface {
	RelaySupportConfirmation(ctx context.Context, epoch uint64, confirmation []byte, signingDigest codec.Hash) error
}

type txSupportConfirmer struct {
	tx      txclient.Client
	options TxSupportConfirmerOptions
	signed  *signedSupportMemo
}

func NewTxSupportConfirmer(tx txclient.Client, options TxSupportConfirmerOptions) SupportConfirmer {
	return txSupportConfirmer{tx: tx, options: options, signed: &signedSupportMemo{}}
}

// signedSupportMemo keeps the last daily confirmation signature. The renewer
// retries the same confirmation until the chain shows it, and a retry must
// resend the material already signed: the chain keeps one row per
// (operator, epoch) and a Builder refuses different material for an occupied
// one. A signer is not required to be deterministic, so it is not asked again.
type signedSupportMemo struct {
	mu        sync.Mutex
	digest    codec.Hash
	signature string
}

func (m *signedSupportMemo) lookup(digest codec.Hash) (string, bool) {
	if m == nil {
		return "", false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.signature, m.signature != "" && m.digest == digest
}

func (m *signedSupportMemo) store(digest codec.Hash, signature string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.digest, m.signature = digest, signature
}

func (txSupportConfirmer) SignsSupportInternally() bool { return true }

// resolve applies the Workload provider, if any, for one confirmation.
func (c txSupportConfirmer) resolve() (txSupportConfirmer, error) {
	if c.options.Workload != nil {
		tx, serviceAddress := c.options.Workload()
		c.tx = tx
		c.options.ServiceAddress, c.options.GasPayer = serviceAddress, serviceAddress
	}
	if c.tx == nil {
		reason := "the workload is not active yet: the Keeper has not confirmed this node's current service key"
		if c.options.TxUnavailable != nil {
			if r := c.options.TxUnavailable(); r != "" {
				reason = r
			}
		}
		return c, fmt.Errorf("model support confirmation needs this node's own transaction (no Builder relay is configured), and no workload tx client is available: %s", reason)
	}
	if c.options.Workload != nil && c.options.ServiceAddress == "" {
		return c, fmt.Errorf("model support confirmation requires the Keeper-confirmed current service address")
	}
	return c, nil
}

func (c txSupportConfirmer) ConfirmSupport(ctx context.Context, material SupportMaterial) (string, error) {
	if c.options.Signer == nil {
		return "", fmt.Errorf("support signer is required")
	}
	c, relayed, err := c.route(material)
	if err != nil {
		return "", err
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
		material.SupportDigest = hex.EncodeToString(digest[:])
		material.SignedEnvelope = signature
		if relayed {
			return c.relay(ctx, material, models, nonce, expiryHeight, digest, signature)
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
		// The confirmation is one record per (epoch, operator), so that is the
		// identity the tx is tracked under, not the model it was requested for.
		taskID := "model-support-daily:" + c.options.OperatorAddress + ":" + strconv.FormatUint(material.EpochIndex, 10)
		return c.submitAndConfirm(ctx, material, taskID, txclient.MsgBatchConfirmModelSupport, message, digest)
	default:
		return "", fmt.Errorf("unsupported model support mode %q", material.SupportMode)
	}
}

// route picks how a confirmation reaches the chain: this node's own
// transaction when it can submit one, otherwise the Builder relay for a daily
// confirmation. The refusal without either is the self-submission one, which
// names why there is no tx client.
func (c txSupportConfirmer) route(material SupportMaterial) (txSupportConfirmer, bool, error) {
	resolved, err := c.resolve()
	if err == nil {
		return resolved, false, nil
	}
	if c.options.Relay == nil || material.SupportMode != SupportModeDaily || !material.Supported {
		return c, false, err
	}
	address := ""
	if c.options.RelayServiceAddress != nil {
		address = c.options.RelayServiceAddress()
	}
	if address == "" {
		return c, false, fmt.Errorf("model support relay needs the Keeper-confirmed current service address: the workload is not active yet")
	}
	c.options.ServiceAddress = address
	return c, true, nil
}

// relay hands the signed confirmation to a Builder. Acceptance is reported as
// success, but it is only the Builder's queue: the renewer keeps reading the
// chain's freshness and retries this same material until it moves.
func (c txSupportConfirmer) relay(ctx context.Context, material SupportMaterial, models []string, nonce, expiryHeight uint64, digest codec.Hash, signature string) (string, error) {
	raw, err := hex.DecodeString(signature)
	if err != nil {
		return "", err
	}
	payload, err := supportConfirmationBytes(c.options.OperatorAddress, models, nonce, expiryHeight, raw)
	if err != nil {
		return "", err
	}
	if err := c.options.Relay.RelaySupportConfirmation(ctx, material.EpochIndex, payload, digest); err != nil {
		return "", fmt.Errorf("relay model support confirmation: %w", err)
	}
	return SupportConfirmationID(material), nil
}

// supportConfirmationBytes is the protobuf binary of one
// hub.v1.ModelSupportConfirmationV1, the relay's payload. models are 64-hex
// model IDs already in Node's canonical order.
func supportConfirmationBytes(operatorAddress string, models []string, nonce, expiryHeight uint64, signature []byte) ([]byte, error) {
	supported := make([][]byte, len(models))
	for i, model := range models {
		raw, err := hex.DecodeString(model)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("supported model %q is not a 32-byte hex model ID", model)
		}
		supported[i] = raw
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(&hubv1.ModelSupportConfirmationV1{
		OperatorAddress:           operatorAddress,
		SupportedModels:           supported,
		ServiceAuthorizationNonce: nonce,
		ExpiryHeight:              expiryHeight,
		ServiceSignature:          signature,
	})
}

func (c txSupportConfirmer) sign(ctx context.Context, digest codec.Hash) (string, error) {
	if signature, ok := c.signed.lookup(digest); ok {
		return signature, nil
	}
	signature, err := c.options.Signer.SignDigest(ctx, signer.DigestRequest{KeyRef: c.options.ServiceKeyRef, ExpectedSignerAddress: c.options.ServiceAddress, Digest: digest})
	if err != nil {
		return "", err
	}
	if len(signature) != 64 {
		return "", fmt.Errorf("support signer returned an invalid signature length")
	}
	text := hex.EncodeToString(signature)
	c.signed.store(digest, text)
	return text, nil
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

package taskdataauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/signer"
)

const requestNonceBytes = 32

// CurrentServiceKeyReader reads the service key Keeper considers current from the
// latest committed state, and reports the height that read was served at. One
// read backs both the key material and the height every check is bound to; there
// is deliberately no way to supply a height of one's own, because a height read
// from CometBFT's /status can be one block ahead of what the application will
// answer and the chain then refuses the query outright.
type CurrentServiceKeyReader interface {
	CommittedCurrentServiceKey(ctx context.Context, participantType, operatorAddress string) (chainclient.ServiceKeySnapshot, uint64, error)
}

type Config struct {
	ServiceKeys     CurrentServiceKeyReader
	Signer          signer.Signer
	ChainID         string
	OperatorAddress string
	ServiceAddress  string
	ServicePubkey   string
	ServiceKeyRef   string
	ExpiryBlocks    uint64
}

type Authenticator struct {
	cfg       Config
	publicKey []byte
}

func New(cfg Config) (*Authenticator, error) {
	switch {
	case cfg.ServiceKeys == nil:
		return nil, fmt.Errorf("task-data authenticator requires a current service-key reader")
	case cfg.Signer == nil:
		return nil, fmt.Errorf("task-data authenticator requires a signer")
	case cfg.ExpiryBlocks == 0:
		return nil, fmt.Errorf("task-data authenticator requires a positive block expiry")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "chain id", value: cfg.ChainID},
		{name: "operator address", value: cfg.OperatorAddress},
		{name: "service address", value: cfg.ServiceAddress},
		{name: "service public key", value: cfg.ServicePubkey},
		{name: "service key ref", value: cfg.ServiceKeyRef},
	} {
		if field.value == "" || strings.TrimSpace(field.value) != field.value || strings.ContainsRune(field.value, '\x00') {
			return nil, fmt.Errorf("task-data authenticator %s must be canonical", field.name)
		}
	}
	if cfg.ServicePubkey != strings.ToLower(cfg.ServicePubkey) {
		return nil, fmt.Errorf("task-data authenticator service public key must be lowercase compressed secp256k1 hex")
	}
	publicKey, err := hex.DecodeString(cfg.ServicePubkey)
	if err != nil || len(publicKey) != 33 || (publicKey[0] != 0x02 && publicKey[0] != 0x03) {
		return nil, fmt.Errorf("task-data authenticator service public key must be lowercase compressed secp256k1 hex")
	}
	hrp := bech32HRP(cfg.ServiceAddress)
	derivedAddress, err := signer.AddressFromCompressedPublicKey(hrp, publicKey)
	if err != nil {
		return nil, fmt.Errorf("derive task-data service identity: %w", err)
	}
	if derivedAddress != cfg.ServiceAddress {
		return nil, fmt.Errorf("task-data service public key derives %s, not runtime service address %s", derivedAddress, cfg.ServiceAddress)
	}
	return &Authenticator{cfg: cfg, publicKey: publicKey}, nil
}

// SignRequest authenticates one task-data unary request. BuilderAddress is
// explicit because it is signed responsibility material and is not derivable
// from TaskDataKey.
func (a *Authenticator) SignRequest(
	ctx context.Context,
	method string,
	key builderclient.TaskDataKey,
	builderOperator string,
	bodyDigest codec.Hash,
) (builderclient.TaskDataRequestAuth, error) {
	// A single committed lookup supplies both the authorization nonce and expiry.
	serviceNonce, _, expiry, err := a.committedIdentity(ctx)
	if err != nil {
		return builderclient.TaskDataRequestAuth{}, err
	}
	if builderclient.TaskDataProcedure(method) == builderclient.TaskDataProcedure("UploadTaskOutputStream") {
		expected, err := builderclient.TaskDataOutputStreamBodyDigest(key.TaskHash, key.SessionID, key.TaskID)
		if err != nil {
			return builderclient.TaskDataRequestAuth{}, err
		}
		if expected != bodyDigest || key.Kind != builderclient.DataKindOutput || key.EvidenceProducerKind != builderclient.EvidenceProducerUnspecified || key.VerifyRound != 0 || key.ProducerOperator != "" {
			return builderclient.TaskDataRequestAuth{}, fmt.Errorf("output stream authentication requires its fixed header projection")
		}
	} else if err := builderclient.ValidateTaskDataKey(key); err != nil {
		return builderclient.TaskDataRequestAuth{}, err
	}
	nonce, err := freshNonce()
	if err != nil {
		return builderclient.TaskDataRequestAuth{}, err
	}
	request := builderclient.TaskDataRequestAuth{
		SchemaVersion: 1, ChainID: a.cfg.ChainID, BuilderAddress: builderOperator,
		Method: builderclient.TaskDataProcedure(method), BodyDigest: bodyDigest,
		RequesterKind: builderclient.TaskDataRequesterCortexService, Requester: a.cfg.OperatorAddress,
		ServiceAuthorizationNonce: serviceNonce, RequestNonce: nonce, ExpiresAtHeight: expiry,
	}
	digest, err := builderclient.TaskDataRequestSigningHash(request)
	if err != nil {
		return builderclient.TaskDataRequestAuth{}, err
	}
	request.Signature, err = a.sign(ctx, digest)
	if err != nil {
		return builderclient.TaskDataRequestAuth{}, err
	}
	return request, nil
}

// SignFetch authenticates a fetch body with explicit optional range presence.
func (a *Authenticator) SignFetch(ctx context.Context, key builderclient.TaskDataKey, builderOperator string, bounds *builderclient.TaskDataRange) (builderclient.TaskDataRequestAuth, error) {
	digest, err := builderclient.TaskDataFetchBodyDigest(key, bounds)
	if err != nil {
		return builderclient.TaskDataRequestAuth{}, err
	}
	return a.SignRequest(ctx, "FetchTaskData", key, builderOperator, digest)
}

// currentIdentity re-reads the node's current service key and returns the expiry
// height that read licenses. Key material, expiry, and the revocation bound all
// come from one committed read: the height is the height Keeper served the binding
// at, so a binding revoked exactly there is refused and the expiry cannot be
// anchored to a block the chain has not committed.
func (a *Authenticator) currentIdentity(ctx context.Context) (uint64, error) {
	_, _, expiry, err := a.committedIdentity(ctx)
	return expiry, err
}

// CommittedBusEnvelopeIdentity returns the two values this node's own committed
// chain view supplies to every outbound frozen wire: the
// service_authorization_nonce Keeper currently holds for this Cortex node, and
// the height Keeper served that binding at.
//
// The nonce is the replay counter the frozen Task wires carry and the Keeper
// compares for equality against the node's own record, so it must come from a
// committed read rather than a local counter. It is also TRUEOPEN_BUS_ENVELOPE_V1
// field 7, which the receiver checks against the binding it resolves at
// verification time (interface-and-topic-list.md §5.2 field 7) - one value, one source,
// used by both wires.
//
// The height is bus envelope field 14, source_snapshot_height: the sender's own
// chain view (§5.2 field 14). §5.2 field 14 states outright that it is NOT used
// for historical key lookup, and §5.2 forbids a historical-key fallback outright,
// so do not pass it
// to a key, BuilderSet or binding query. It is provenance a receiver may log or
// bound freshness with, nothing more.
func (a *Authenticator) CommittedBusEnvelopeIdentity(ctx context.Context) (uint64, uint64, error) {
	if a == nil {
		return 0, 0, fmt.Errorf("task-data authenticator is required")
	}
	nonce, height, _, err := a.committedIdentity(ctx)
	if err != nil {
		return 0, 0, err
	}
	return nonce, height, nil
}

// committedIdentity performs the one committed read the request expiry, the
// receipt's replay counter and the bus envelope's chain-view fields are all bound
// to, and returns (service_authorization_nonce, committed height, request expiry
// height).
//
// The committed height is returned separately from the expiry because they answer
// different questions: the height is the block Keeper served the binding at (the
// sender's chain view), while the expiry is that height plus the configured
// request window.
func (a *Authenticator) committedIdentity(ctx context.Context) (uint64, uint64, uint64, error) {
	if a == nil {
		return 0, 0, 0, fmt.Errorf("task-data authenticator is required")
	}
	binding, height, err := a.cfg.ServiceKeys.CommittedCurrentServiceKey(ctx, chainclient.ParticipantTypeCortexNode, a.cfg.OperatorAddress)
	if err != nil {
		return 0, 0, 0, normalizeDependencyError(fmt.Errorf("query current Cortex service key for task-data authentication: %w", err), err)
	}
	if height == 0 {
		return 0, 0, 0, fmt.Errorf("task-data authentication requires a positive committed chain height")
	}
	if height > ^uint64(0)-a.cfg.ExpiryBlocks {
		return 0, 0, 0, fmt.Errorf("task-data request expiry overflows uint64 at height %d", height)
	}
	if err := binding.Validate(); err != nil {
		return 0, 0, 0, err
	}
	switch {
	case binding.ParticipantType != chainclient.ParticipantTypeCortexNode || binding.OperatorAddress != a.cfg.OperatorAddress:
		return 0, 0, 0, fmt.Errorf("Keeper current service key does not belong to Cortex node %s", a.cfg.OperatorAddress)
	case !strings.EqualFold(binding.Status, "ACTIVE"):
		return 0, 0, 0, fmt.Errorf("Keeper current Cortex service key status is %q", binding.Status)
	case binding.RevokedHeight.Uint64() != 0 && binding.RevokedHeight.Uint64() <= height:
		return 0, 0, 0, fmt.Errorf("Keeper current Cortex service key was revoked at height %d", binding.RevokedHeight.Uint64())
	case binding.ServiceAddress != a.cfg.ServiceAddress:
		return 0, 0, 0, fmt.Errorf("Keeper current service address %s does not match runtime service address %s", binding.ServiceAddress, a.cfg.ServiceAddress)
	case binding.ServicePubkey != a.cfg.ServicePubkey:
		return 0, 0, 0, fmt.Errorf("Keeper current service public key does not match runtime service public key")
	}
	return binding.AuthorizationNonce.Uint64(), height, height + a.cfg.ExpiryBlocks, nil
}

func (a *Authenticator) sign(ctx context.Context, digest codec.Hash) ([]byte, error) {
	signature, err := a.cfg.Signer.SignDigest(ctx, signer.DigestRequest{
		KeyRef:                a.cfg.ServiceKeyRef,
		ExpectedSignerAddress: a.cfg.ServiceAddress,
		Digest:                digest,
	})
	if err != nil {
		wrapped := fmt.Errorf("sign task-data request: %w", err)
		if errors.Is(err, signer.ErrRetryable) {
			return nil, builderclient.Retryable(wrapped)
		}
		return nil, wrapped
	}
	if err := signer.VerifyDigestSignature(a.cfg.ServicePubkey, digest, signature); err != nil {
		return nil, fmt.Errorf("task-data signature does not verify under the runtime service key: %w", err)
	}
	return signature, nil
}

func freshNonce() ([]byte, error) {
	nonce := make([]byte, requestNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate task-data request nonce: %w", err)
	}
	return nonce, nil
}

func normalizeDependencyError(wrapped, cause error) error {
	if chainclient.IsRetryable(cause) {
		return builderclient.Retryable(wrapped)
	}
	return wrapped
}

func bech32HRP(address string) string {
	if separator := strings.LastIndexByte(address, '1'); separator > 0 {
		return address[:separator]
	}
	return ""
}

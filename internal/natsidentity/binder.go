package natsidentity

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/TrueOpen/wire/bus"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/signer"
)

// ServiceKeyReader is the Binder's only dependency on the chain: it reads the
// service key Keeper considers current. chainclient.KeeperABCIClient already
// implements it, and it has the same shape as taskdataauth.CurrentServiceKeyReader.
type ServiceKeyReader interface {
	CommittedCurrentServiceKey(ctx context.Context, participantType, operatorAddress string) (chainclient.ServiceKeySnapshot, uint64, error)
}

type Config struct {
	ServiceKeys     ServiceKeyReader
	Signer          signer.Signer
	ChainID         string
	OperatorAddress string
	// ServiceKeyRef is the signer's reference to the service key;
	// ExpectedSignerAddress is the chain's current service address, and the signer
	// refuses a mismatch (CLAUDE.md, "two signing identities").
	ServiceKeyRef string
	UserKey       nkeys.KeyPair
	// Sentinel supplies the AUTH sentinel user JWT that CONNECT has to present (see
	// sentinel.go). An operator-mode server never even reaches the connection callback
	// without it, so it is required.
	Sentinel SentinelSource
	Now      func() time.Time
}

// Status is the binding status diagnostics displays.
type Status struct {
	UserPublicKey string `json:"user_public_key"`
	// SentinelAccount is the AUTH account public key the sentinel JWT belongs to; it
	// is set only once a sentinel has been fetched.
	SentinelAccount string `json:"sentinel_account,omitempty"`
	BindingNonce    uint64 `json:"binding_nonce,omitempty"`
	IssuedAtUnixMS  uint64 `json:"issued_at_unix_ms,omitempty"`
	LastError       string `json:"last_error,omitempty"`
}

type binding struct {
	nonce      uint64
	token      string
	issuedAtMS uint64
}

// Binder implements builderclient.ChainIdentityProvider: every Credential call
// re-reads the committed binding from the chain and reuses the already-signed token
// while the nonce is unchanged (the signer may be a remote KMS, and is not asked to
// sign once per reconnect); a changed nonce, a state other than ACTIVE, or an
// Invalidate call rebuilds it. The construction and verification rules all live in
// wire bus.
type Binder struct {
	cfg     Config
	userPub string

	// sem is a capacity-1 semaphore standing in for a mutex to serialise the
	// construction path: acquiring it can be cancelled by ctx, so a TokenHandler call
	// queued behind a slow chain read still honours its own timeout.
	sem chan struct{}

	// stateMu guards published state only and is never held across a chain read or a
	// signer call, so Status and Invalidate are not blocked by a slow chain read
	// (cortexctl diagnostics needs an answer precisely when the chain is slow).
	stateMu         sync.Mutex
	current         *binding
	sentinelAccount string
	lastError       string
}

func New(cfg Config) (*Binder, error) {
	switch {
	case cfg.ServiceKeys == nil:
		return nil, fmt.Errorf("nats identity requires a current service-key reader")
	case cfg.Signer == nil:
		return nil, fmt.Errorf("nats identity requires a signer")
	case cfg.UserKey == nil:
		return nil, fmt.Errorf("nats identity requires the local nats user key")
	case cfg.Sentinel == nil:
		return nil, fmt.Errorf("nats identity requires an auth sentinel source")
	case strings.TrimSpace(cfg.ChainID) == "":
		return nil, fmt.Errorf("nats identity requires chain id")
	case strings.TrimSpace(cfg.OperatorAddress) == "":
		return nil, fmt.Errorf("nats identity requires the operator address")
	case strings.TrimSpace(cfg.ServiceKeyRef) == "":
		return nil, fmt.Errorf("nats identity requires the service key ref")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	pub, err := cfg.UserKey.PublicKey()
	if err != nil {
		return nil, err
	}
	if err := bus.ValidateNATSUserPublicKey(pub); err != nil {
		return nil, err
	}
	return &Binder{cfg: cfg, userPub: pub, sem: make(chan struct{}, 1)}, nil
}

var _ builderclient.ChainIdentityProvider = (*Binder)(nil)

// Credential returns the three things that have to be presented right now
// (interface-and-topic-list §5.14.2).
//
// The construction path is serialised by the capacity-1 b.sem: the chain read and
// the signing both happen inside it, so concurrent Credential calls queue instead
// of each signing their own. The serialisation is deliberate (connection events are
// rare, and one reconnect should produce exactly one binding), but the queueing has
// to be abandonable - acquiring sem goes through select, and once the caller's ctx
// expires it returns ctx.Err() instead of waiting past its own timeout.
func (b *Binder) Credential(ctx context.Context) (builderclient.NATSChainCredential, error) {
	select {
	case b.sem <- struct{}{}:
	case <-ctx.Done():
		return builderclient.NATSChainCredential{}, ctx.Err()
	}
	defer func() { <-b.sem }()

	token, err := b.token(ctx)
	if err != nil {
		b.publishError(err)
		return builderclient.NATSChainCredential{}, err
	}
	// The sentinel and the binding are two different things: the binding comes from
	// the chain, the sentinel from a Builder's ingress. Missing either one means no
	// credential is presented - in operator mode a CONNECT without a sentinel is
	// refused by the server before the callback runs, and the only reason reported is
	// a bare Authorization Violation.
	sentinel, err := b.cfg.Sentinel.Sentinel(ctx)
	if err != nil {
		b.publishError(err)
		return builderclient.NATSChainCredential{}, err
	}
	b.publishSentinelAccount(sentinel.AuthAccountPublicKey)
	return builderclient.NATSChainCredential{
		UserPublicKey: b.userPub,
		SignNonce:     b.cfg.UserKey.Sign,
		Token:         token,
		SentinelJWT:   sentinel.JWT,
	}, nil
}

// Invalidate is called after an authentication failure: it drops the cache, so the
// next Credential call necessarily re-signs. It takes only stateMu, so it returns
// immediately even while a Credential call is stuck in a chain read.
//
// The sentinel is dropped as well: a rotated sentinel presents as the same
// Authorization Violation, the client cannot tell an expired binding from an
// expired sentinel, and only refetching both avoids getting stuck on stale material.
func (b *Binder) Invalidate() {
	b.stateMu.Lock()
	b.current = nil
	b.stateMu.Unlock()
	if invalidator, ok := b.cfg.Sentinel.(sentinelInvalidator); ok {
		invalidator.Invalidate()
	}
}

// Status reads published state only and never queues behind the construction path:
// diagnostics must answer immediately even when the chain is unavailable.
func (b *Binder) Status() Status {
	b.stateMu.Lock()
	defer b.stateMu.Unlock()
	status := Status{UserPublicKey: b.userPub, SentinelAccount: b.sentinelAccount, LastError: b.lastError}
	if b.current != nil {
		status.BindingNonce = b.current.nonce
		status.IssuedAtUnixMS = b.current.issuedAtMS
	}
	return status
}

// cached returns the currently cached binding; it returns false when the nonce
// differs or nothing is cached.
func (b *Binder) cached(nonce uint64) (string, bool) {
	b.stateMu.Lock()
	defer b.stateMu.Unlock()
	if b.current == nil || b.current.nonce != nonce {
		return "", false
	}
	return b.current.token, true
}

func (b *Binder) publish(current binding) {
	b.stateMu.Lock()
	b.current = &current
	b.lastError = ""
	b.stateMu.Unlock()
}

func (b *Binder) publishSentinelAccount(account string) {
	b.stateMu.Lock()
	b.sentinelAccount = account
	b.stateMu.Unlock()
}

func (b *Binder) publishError(err error) {
	b.stateMu.Lock()
	b.lastError = err.Error()
	b.stateMu.Unlock()
}

func (b *Binder) clearError() {
	b.stateMu.Lock()
	b.lastError = ""
	b.stateMu.Unlock()
}

// token re-reads the committed binding from the chain while holding b.sem and
// re-signs when needed.
func (b *Binder) token(ctx context.Context) (string, error) {
	snapshot, height, err := b.cfg.ServiceKeys.CommittedCurrentServiceKey(ctx, chainclient.ParticipantTypeCortexNode, b.cfg.OperatorAddress)
	if err != nil {
		return "", fmt.Errorf("read committed cortex service key: %w", err)
	}
	if height == 0 {
		return "", fmt.Errorf("nats user binding requires a positive committed chain height")
	}
	if err := snapshot.Validate(); err != nil {
		return "", err
	}
	switch {
	case snapshot.ParticipantType != chainclient.ParticipantTypeCortexNode || snapshot.OperatorAddress != b.cfg.OperatorAddress:
		return "", fmt.Errorf("committed service key does not belong to cortex node %s", b.cfg.OperatorAddress)
	case !strings.EqualFold(snapshot.Status, "ACTIVE"):
		return "", fmt.Errorf("committed cortex service key status is %q; a binding signed by it would be refused", snapshot.Status)
	// A non-zero revocation height that the height of this read has already caught up
	// with means the key is revoked on chain: the same test taskdataauth.committedIdentity
	// applies, where a revocation point exactly equal to the current height counts as
	// revoked.
	case snapshot.RevokedHeight.Uint64() != 0 && snapshot.RevokedHeight.Uint64() <= height:
		return "", fmt.Errorf("committed cortex service key was revoked at height %d", snapshot.RevokedHeight.Uint64())
	}
	nonce := snapshot.AuthorizationNonce.Uint64()
	if token, ok := b.cached(nonce); ok {
		b.clearError()
		return token, nil
	}

	fields := bus.BindingFields{
		SchemaVersion:             bus.BindingSchemaVersion,
		ChainID:                   b.cfg.ChainID,
		ParticipantType:           bus.ParticipantCortex,
		OperatorAddress:           b.cfg.OperatorAddress,
		ServiceAuthorizationNonce: nonce,
		NATSUserPubkey:            b.userPub,
		IssuedAtUnixMS:            uint64(b.cfg.Now().UnixMilli()),
	}
	digest, err := bus.BindingSigningDigest(fields)
	if err != nil {
		return "", fmt.Errorf("nats user binding projection: %w", err)
	}
	signature, err := b.cfg.Signer.SignDigest(ctx, signer.DigestRequest{
		KeyRef: b.cfg.ServiceKeyRef, ExpectedSignerAddress: snapshot.ServiceAddress, Digest: codec.Hash(digest),
	})
	if err != nil {
		return "", fmt.Errorf("sign nats user binding: %w", err)
	}
	// snapshot.Validate has already confirmed ServicePubkey is 33-byte lowercase
	// compressed secp256k1 hex, so this decode cannot fail any more.
	pubkey, _ := hex.DecodeString(snapshot.ServicePubkey)
	// Verify once against the on-chain public key: a signer that signed with the wrong
	// key stops here, rather than leaving us to guess after NATS refuses.
	if err := bus.VerifyBindingSignature(fields, signature, pubkey); err != nil {
		return "", fmt.Errorf("nats user binding does not verify under the committed service key: %w", err)
	}
	encoded, err := bus.EncodeBinding(fields, signature)
	if err != nil {
		return "", err
	}
	token := bus.EncodeBindingToken(encoded)
	b.publish(binding{nonce: nonce, token: token, issuedAtMS: fields.IssuedAtUnixMS})
	return token, nil
}

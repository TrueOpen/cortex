package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store/once"
)

// serviceKeyStatusActive is the only binding status that may authenticate or
// sign a bus envelope. A revoked or pending key is not a current binding.
const serviceKeyStatusActive = "ACTIVE"

// ErrBusEnvelopeReplay reports an envelope whose message id or nonce was already
// consumed. It is permanent: the sender must mint a new envelope.
var ErrBusEnvelopeReplay = errors.New("Nexus envelope was already processed")

// envelopeServiceKeyReader resolves the current service-key binding of a
// participant. Only the verification-time current binding is admissible: a
// historical key, a message-carried key, or a cached key from an earlier height
// would each let a rotated-out key keep authenticating.
type envelopeServiceKeyReader interface {
	CurrentServiceKey(ctx context.Context, participantType, operatorAddress string, snapshotHeight uint64) (chainclient.ServiceKeySnapshot, error)
}

// BusEnvelopeSignerConfig builds the outbound signer.
type BusEnvelopeSignerConfig struct {
	Signer signer.DigestSigner
	// KeyRef names the online service key.
	KeyRef string
	// ServiceAddress resolves the Keeper-confirmed service address that owns the
	// key. It is late bound because that address is only known once the chain
	// confirms this node's current binding: signing bus material before then
	// would assert an identity the chain has not agreed to, so an unresolved
	// address must fail rather than default to anything.
	ServiceAddress func() (string, error)
}

// NewBusEnvelopeSigner signs outbound envelopes with the node's online service
// key. It is the same key that signs task business material: the design forbids
// a separate envelope or relayer key.
func NewBusEnvelopeSigner(cfg BusEnvelopeSignerConfig) (builderclient.BusEnvelopeSigner, error) {
	if cfg.Signer == nil {
		return nil, fmt.Errorf("Nexus envelope signer requires a signing client")
	}
	keyRef := strings.TrimSpace(cfg.KeyRef)
	if keyRef == "" {
		return nil, fmt.Errorf("Nexus envelope signer requires signer.key_ref")
	}
	if cfg.ServiceAddress == nil {
		return nil, fmt.Errorf("Nexus envelope signer requires a service address resolver")
	}
	return builderclient.BusEnvelopeSignerFunc(func(envelope builderclient.BusEnvelope) ([]byte, error) {
		signerAddress, err := cfg.ServiceAddress()
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(signerAddress) == "" {
			return nil, fmt.Errorf("Nexus envelope signer has no Keeper-confirmed service address yet")
		}
		digest, err := builderclient.BusEnvelopeSignDigest(envelope)
		if err != nil {
			return nil, err
		}
		// The bus has no request context of its own; signing is a local
		// operation bounded by the signer's own deadline handling.
		signature, err := cfg.Signer.SignDigest(context.Background(), signer.DigestRequest{
			KeyRef:                keyRef,
			ExpectedSignerAddress: strings.TrimSpace(signerAddress),
			Digest:                digest,
		})
		if err != nil {
			return nil, fmt.Errorf("sign Nexus envelope with %s: %w", keyRef, err)
		}
		return signature, nil
	}), nil
}

// builderMembership answers whether the chain currently recognises a Builder. It
// is the authority for bus-sender authorization; configuration can narrow what
// this node accepts but must never widen it.
type builderMembership interface {
	HasBuilder(ctx context.Context, operatorAddress string) (bool, error)
}

// BusEnvelopeAuthenticatorConfig builds the inbound authenticator.
type BusEnvelopeAuthenticatorConfig struct {
	ChainID string
	Keeper  envelopeServiceKeyReader
	// Members is the active BuilderSet this node accepts Builder senders from.
	// It is required: a build that fell back to PeerOperatorAddress alone would
	// make a local file the authority over who may send, so a Builder the chain
	// has removed from the set would keep being accepted for as long as the file
	// still named it.
	//
	// It governs the BUILDER domain only. There is no chain query for the set of
	// Cortex nodes, so a CORTEX sender is authorized by its own current, ACTIVE
	// CORTEX_NODE service-key binding instead — see Authenticate.
	Members builderMembership
	// PeerOperatorAddress is an OPTIONAL narrowing filter over BUILDER senders.
	// When set, this node accepts Builder traffic only from that one Builder, on
	// top of the chain membership requirement; it never admits a sender the
	// chain does not currently recognise. When empty, every current BuilderSet
	// member is admissible.
	//
	// It does not apply to a CORTEX sender: it names a Builder, so applying it
	// to Cortex traffic would refuse all of it.
	PeerOperatorAddress string
	TTL                 time.Duration
	ClockSkew           time.Duration
	// KeeperTimeout bounds the current-key read. It defaults to the TTL, because
	// a read that outlives the envelope's own freshness window cannot produce a
	// usable verdict.
	KeeperTimeout time.Duration
	// OnDependencyOutcome reports whether this node's own inputs to
	// authentication are usable: it is called with the error when the chain view
	// is unreadable or the replay store is unwritable, and with nil once a frame
	// authenticates end to end, so readiness can withdraw and return. Peer
	// failures (missing, invalid, expired or replayed signatures) are never
	// reported here: they are the sender's fault, and withdrawing readiness for
	// them would let a peer take this node out of service.
	OnDependencyOutcome func(error)
	// Now is injectable for tests; it defaults to wall clock UTC.
	Now func() time.Time
	// StoreOnce persists replay and inbound dedup claims so they survive a
	// process restart. When nil, the authenticator falls back to an in-memory map
	// for callers that do not need durability (tests and fake mode).
	StoreOnce *once.Store
}

type busEnvelopeAuthenticator struct {
	cfg      BusEnvelopeAuthenticatorConfig
	replayMu sync.Mutex
	replay   map[string]time.Time
	claims   map[string][]string
	// lastPrune rate-limits the durable claim sweep. Without a sweep the once
	// store grows for the life of the node, which is why the expiry is persisted
	// at all; without the rate limit every frame would pay for it.
	lastPrune time.Time
}

// releaseClaims undoes the claims this pass wrote.
//
// The context is detached from cancellation on purpose. The commonest reason a
// later key fails is that the request context was cancelled, and Store.delete
// checks the context first - so rolling back with the caller's context would fail
// every delete precisely when rollback matters most. The orphaned key would then
// refuse the legitimate redelivery until it expired, because a.claims is only
// populated after all keys succeed and nothing else knows the key exists.
//
// Best-effort past that: a claim expires on its own, so a failed release costs a
// retryable window, not correctness.
func (a *busEnvelopeAuthenticator) releaseClaims(ctx context.Context, keys []string) {
	if a.cfg.StoreOnce == nil {
		return
	}
	release := context.WithoutCancel(ctx)
	for _, key := range keys {
		_ = a.cfg.StoreOnce.Release(release, key)
	}
}

const (
	onceStorePruneInterval = time.Minute
	onceStorePruneLimit    = 256
)

// pruneOnceStore drops expired claims at most once per interval. This mirrors what
// the in-memory branch below does to its map on every pass; the durable branch had
// no equivalent, so nothing ever removed a claim.
func (a *busEnvelopeAuthenticator) pruneOnceStore(ctx context.Context, now time.Time) {
	a.replayMu.Lock()
	due := now.Sub(a.lastPrune) >= onceStorePruneInterval
	if due {
		a.lastPrune = now
	}
	a.replayMu.Unlock()
	if !due {
		return
	}
	_, _ = a.cfg.StoreOnce.Prune(ctx, now, onceStorePruneLimit)
}

// NewBusEnvelopeAuthenticator authenticates inbound envelopes against the
// sender's current on-chain service key.
//
// Upstream reality worth stating plainly: the Nexus that ships today never
// populates BusEnvelope.signature (nexus internal/coordinator/taskfsm.go builds
// every envelope without one). This authenticator therefore refuses every
// message a current Nexus emits, which is the correct fail-closed behaviour and
// not a defect here - the design prohibits downgrading to unsigned after a
// verification failure. Deployments that need to run before Nexus signs must
// select the trusted_nats_dev transport-boundary mode explicitly.
func NewBusEnvelopeAuthenticator(cfg BusEnvelopeAuthenticatorConfig) (builderclient.BusEnvelopeAuthenticator, error) {
	if strings.TrimSpace(cfg.ChainID) == "" {
		return nil, fmt.Errorf("Nexus envelope authenticator requires chain_id")
	}
	if cfg.Keeper == nil {
		return nil, fmt.Errorf("Nexus envelope authenticator requires a Keeper client that can read service keys")
	}
	if cfg.Members == nil {
		return nil, fmt.Errorf("Nexus envelope authenticator requires chain BuilderSet membership")
	}
	if cfg.TTL <= 0 {
		return nil, fmt.Errorf("Nexus envelope authenticator requires a positive envelope TTL")
	}
	if cfg.KeeperTimeout <= 0 {
		cfg.KeeperTimeout = cfg.TTL
	}
	if cfg.ClockSkew < 0 {
		return nil, fmt.Errorf("Nexus envelope clock skew must not be negative")
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &busEnvelopeAuthenticator{cfg: cfg, replay: make(map[string]time.Time), claims: make(map[string][]string)}, nil
}

// Authenticate runs the fixed verification order the design freezes: structure,
// then identity and the delivery subject, then chain id and freshness, then the
// current binding, then the signature, and only then the durable replay claim.
// Nothing advances on any failure, and the replay record is claimed before the
// caller can act on the message.
//
// Exactly one call is admissible per frame received from the wire, because the
// claim is what makes a replay detectable. Re-authenticating a frame this node
// already admitted would report it as a replay of itself.
func (a *busEnvelopeAuthenticator) Authenticate(ctx context.Context, subject string, envelope builderclient.BusEnvelope) error {
	if a == nil {
		return builderclient.ErrBusEnvelopeAuthenticationUnavailable
	}
	// Everything a frame asserts about itself is checked before any of it is
	// believed: wire shape, the constants the spec fixes, the agreement between
	// kind/participant/role/stage/subject, and payload_digest against the
	// canonical payload. This has to happen here rather than only in
	// BusEnvelope.Validate, because Validate needs an expected kind and this
	// path has none - it accepts whatever the subject legitimately carries.
	//
	// The payload_digest recompute is the load-bearing one. BusEnvelopeSignBytes
	// signs a RECOMPUTED digest, not the transmitted field, so a signature says
	// nothing about the bytes that arrived in field 20. Without this, a validly
	// signed frame could carry any 32 bytes there and nothing would object.
	if err := envelope.ValidateEnvelopeIntrinsics(); err != nil {
		return err
	}
	sender := strings.TrimSpace(envelope.SenderOperatorAddress)
	if sender == "" {
		return fmt.Errorf("Nexus envelope carries no sender")
	}
	// The sender's domain selects the keyspace this node's current-key lookup
	// runs in, so it is never simply trusted. What bounds it is the frozen
	// subject table: ValidateEnvelopeIntrinsics above has already refused any
	// (kind, sender_participant_type) pair that is not a row of it, so by here
	// the domain is one the contract admits for this kind and no frame could
	// have widened that set. This mapping is total over the two domains Cortex
	// can verify and an error otherwise, which is what stops an unrecognised
	// domain from selecting a keyspace of its own.
	//
	// It used to be compared against ONE configured domain instead, hardwired
	// to BUILDER. trueopen.output-avail.* has two sender rows — Cortex publishes
	// the CORTEX one from its Worker — so that comparison made the only kind
	// Cortex both sends and receives structurally unauthenticable, and every
	// Verifier lost its OUTPUT_AVAILABLE wake-up.
	//
	// The V2 envelope has no sender_role axis; task duty travels inside the
	// signed payloads.
	senderDomain, err := queryDomainForBusParticipantType(envelope.SenderParticipantType)
	if err != nil {
		return err
	}
	// The subject is inside the signed set, so a frame signed for one subject
	// must not be accepted off another: that is how a captured WORKER_ASSIGNMENT_NOTIFY
	// would otherwise be replayed onto a different stage's subject.
	if delivered := strings.TrimSpace(subject); delivered != "" && delivered != strings.TrimSpace(envelope.Subject) {
		return fmt.Errorf("Nexus envelope subject %s was delivered on %s", envelope.Subject, delivered)
	}
	if strings.TrimSpace(envelope.ChainID) != strings.TrimSpace(a.cfg.ChainID) {
		return fmt.Errorf("Nexus envelope chain id %s does not match %s", envelope.ChainID, a.cfg.ChainID)
	}
	now := a.cfg.Now()
	if err := a.checkFreshness(envelope, now); err != nil {
		return err
	}

	if ctx == nil {
		ctx = context.Background()
	}
	// Who may send is decided per domain, because the two domains have
	// different authorities on chain.
	//
	// BUILDER: the active BuilderSet, plus the optional configured narrowing.
	// This runs before the key read because a sender the network does not
	// currently recognise has nothing to prove: it is the sender's failure, and
	// resolving its key first would let an unknown peer drive this node's chain
	// reads.
	//
	// CORTEX: there is no chain query for the set of Cortex nodes, so the
	// authority is the sender's own current, ACTIVE CORTEX_NODE service-key
	// binding, checked below — a key the chain has not currently bound to this
	// operator in this domain cannot produce an accepted signature. The
	// task-level binding (that the sender is the on-chain winning Worker of the
	// task the frame names) belongs to the consumer, which holds the task
	// snapshot: admitOutputAvailable.
	if senderDomain == chainclient.ParticipantTypeBuilder {
		// Configuration may narrow and never widen: the configured operator is
		// applied as a filter here, and the chain's own membership decision is
		// what actually authorizes the sender.
		if configured := strings.TrimSpace(a.cfg.PeerOperatorAddress); configured != "" && sender != configured {
			return fmt.Errorf("Nexus envelope sender %s is not the configured Builder operator %s",
				sender, configured)
		}
		member, err := a.cfg.Members.HasBuilder(ctx, sender)
		if err != nil {
			// An unreadable membership view is this node's failure, not the
			// sender's: reporting it as "not a member" would make a Keeper
			// outage indistinguishable from an unauthorized peer and would
			// discard a frame that is probably fine.
			return a.dependencyFailure(fmt.Errorf("read current BuilderSet membership of %s: %w", sender, err))
		}
		if !member {
			return fmt.Errorf("Nexus envelope sender %s is not in the current BuilderSet", sender)
		}
	}
	keeperCtx, cancel := context.WithTimeout(ctx, a.cfg.KeeperTimeout)
	defer cancel()
	binding, err := a.cfg.Keeper.CurrentServiceKey(keeperCtx, senderDomain, sender, 0)
	if err != nil {
		// A chain view this node cannot read is not a licence to accept the
		// message, but it is this node's failure rather than the sender's: it is
		// reported to readiness and marked retryable so the frame is redelivered
		// instead of being discarded as invalid.
		return a.dependencyFailure(fmt.Errorf("read current service key of %s: %w", sender, err))
	}
	if err := checkCurrentServiceBinding(binding, senderDomain, sender); err != nil {
		return err
	}
	// service_authorization_nonce must equal the nonce on the binding resolved at
	// verification time (interface-and-topic-list.md §5.2 field 7). The nonce is a signed
	// field, so this rejects a frame minted under a superseded binding before its
	// signature is even considered valuable - which is the point: §5.2 allows no
	// historical key fallback, so a frame carrying a stale nonce has nothing to fall
	// back to.
	if envelope.ServiceAuthorizationNonce != binding.AuthorizationNonce.Uint64() {
		return fmt.Errorf("Nexus envelope service_authorization_nonce %d is not the current binding nonce %d of %s",
			envelope.ServiceAuthorizationNonce, binding.AuthorizationNonce.Uint64(), sender)
	}
	if err := builderclient.VerifyBusEnvelopeSignature(envelope, binding.ServicePubkey); err != nil {
		return err
	}

	expiresAt := time.UnixMilli(envelope.ExpiresAtUnixMs).UTC().Add(a.cfg.ClockSkew)
	// Wire's dual replay keys: message_id and nonce, both scoped to the sender's
	// current authorization nonce. The retired payload dedup_id sniffing is gone
	// with the JSON payloads; transport dedup is the envelope's job.
	keys, err := builderclient.BusEnvelopeReplayKeys(envelope, binding.AuthorizationNonce.Uint64())
	if err != nil {
		return err
	}

	var replayed bool
	allKeys := append([]string(nil), keys...)
	if a.cfg.StoreOnce != nil {
		// Claims are taken one key at a time, so a frame refused on its second or
		// third key has already written the first. Releasing them is not tidiness:
		// a rejected frame would otherwise leave permanent rows, and worse, it
		// would consume a message id that a later legitimate frame needs.
		taken := make([]string, 0, len(allKeys))
		for _, key := range allKeys {
			claimed, err := a.cfg.StoreOnce.Claim(ctx, key, expiresAt)
			if err != nil {
				a.releaseClaims(ctx, taken)
				return a.dependencyFailure(fmt.Errorf("claim %s: %w", key, err))
			}
			if !claimed {
				replayed = true
				break
			}
			taken = append(taken, key)
		}
		if replayed {
			a.releaseClaims(ctx, taken)
			return fmt.Errorf("%w: %s", ErrBusEnvelopeReplay, envelope.MessageID)
		}
		a.pruneOnceStore(ctx, now)
		a.replayMu.Lock()
		a.claims[envelope.MessageID] = append([]string(nil), allKeys...)
		a.replayMu.Unlock()
	} else {
		a.replayMu.Lock()
		for key, expiry := range a.replay {
			if now.After(expiry) {
				delete(a.replay, key)
			}
		}
		for _, key := range keys {
			if _, exists := a.replay[key]; exists {
				replayed = true
				break
			}
		}
		if !replayed {
			for _, key := range keys {
				a.replay[key] = expiresAt
			}
			a.claims[envelope.MessageID] = append([]string(nil), keys...)
		}
		a.replayMu.Unlock()
		if replayed {
			return fmt.Errorf("%w: %s", ErrBusEnvelopeReplay, envelope.MessageID)
		}
	}
	if a.cfg.OnDependencyOutcome != nil {
		a.cfg.OnDependencyOutcome(nil)
	}
	return nil
}

// Release returns this authenticator's replay claim for a frame whose
// downstream handling failed retryably. JetStream then redelivers the exact
// signed bytes; retaining the claim would misclassify that redelivery as an
// attacker replay and ACK-discard an otherwise recoverable order.
func (a *busEnvelopeAuthenticator) Release(_ string, envelope builderclient.BusEnvelope) {
	if a == nil {
		return
	}
	a.replayMu.Lock()
	keys := a.claims[envelope.MessageID]
	delete(a.claims, envelope.MessageID)
	for _, key := range keys {
		delete(a.replay, key)
	}
	a.replayMu.Unlock()
	if a.cfg.StoreOnce != nil {
		for _, key := range keys {
			_ = a.cfg.StoreOnce.Release(context.Background(), key)
		}
	}
}

// dependencyFailure reports a failure of this node's own dependencies and marks
// it retryable, so the frame is redelivered rather than rejected as invalid.
func (a *busEnvelopeAuthenticator) dependencyFailure(err error) error {
	if a.cfg.OnDependencyOutcome != nil {
		a.cfg.OnDependencyOutcome(err)
	}
	return builderclient.Retryable(err)
}

// checkFreshness rejects an envelope that is expired, not yet issued, or claims
// a lifetime longer than this deployment admits. JetStream redelivery must not
// refresh the stamps, so a redelivered message that outlived its TTL is expired
// rather than renewed.
//
// It does NOT re-check that the stamps are present and ordered:
// ValidateEnvelopeIntrinsics has already refused issued_at_unix_ms <= 0 and
// expires_at_unix_ms <= issued_at_unix_ms before this runs, so those two
// comparisons could not fire here and are left with one owner instead of two.
// What remains below is everything that needs this node's clock and config,
// which the intrinsic check deliberately has neither of.
func (a *busEnvelopeAuthenticator) checkFreshness(envelope builderclient.BusEnvelope, now time.Time) error {
	issuedAt := time.UnixMilli(envelope.IssuedAtUnixMs).UTC()
	expiresAt := time.UnixMilli(envelope.ExpiresAtUnixMs).UTC()
	// Clock skew is a tolerance for comparing a remote stamp against the local
	// clock, not a licence to extend the sender's own internally consistent
	// lifetime, so the TTL bound is strict.
	if lifetime := expiresAt.Sub(issuedAt); lifetime > a.cfg.TTL {
		return fmt.Errorf("Nexus envelope lifetime %s exceeds the accepted TTL %s", lifetime, a.cfg.TTL)
	}
	if now.After(expiresAt.Add(a.cfg.ClockSkew)) {
		return fmt.Errorf("Nexus envelope expired at %s", expiresAt.Format(time.RFC3339))
	}
	if issuedAt.After(now.Add(a.cfg.ClockSkew)) {
		return fmt.Errorf("Nexus envelope was issued in the future at %s", issuedAt.Format(time.RFC3339))
	}
	return nil
}

// queryDomainForBusParticipantType maps a bus wire sender_participant_type
// (interface-and-topic-list.md §5.2 field 5) onto the Keeper query-side participant type
// whose keyspace holds that sender's service key.
//
// The two spellings differ - the envelope enum is CORTEX while the Keeper query
// namespace is CORTEX_NODE - so the mapping has to be explicit. It is a total
// function over the two domains Cortex can verify and an error otherwise:
// silently passing an unrecognised domain through would let a frame select a
// keyspace this node cannot reason about.
//
// It replaced the query-domain -> wire direction, which existed only to compare
// a frame against one configured domain. That comparison is gone: the
// admissible domains are the frozen subject table's own sender column.
func queryDomainForBusParticipantType(participant builderclient.BusParticipantType) (string, error) {
	switch participant {
	case builderclient.ParticipantBuilder:
		return chainclient.ParticipantTypeBuilder, nil
	case builderclient.ParticipantCortex:
		return chainclient.ParticipantTypeCortexNode, nil
	default:
		return "", fmt.Errorf("Nexus envelope sender_participant_type %q has no Keeper service-key domain", participant)
	}
}

// checkCurrentServiceBinding rejects any binding that is not the participant's
// live, active key.
func checkCurrentServiceBinding(binding chainclient.ServiceKeySnapshot, participantType, operatorAddress string) error {
	if !strings.EqualFold(strings.TrimSpace(binding.OperatorAddress), strings.TrimSpace(operatorAddress)) {
		return fmt.Errorf("current service key belongs to %s, not %s", binding.OperatorAddress, operatorAddress)
	}
	// A blank participant type is a rejection, not a pass: a partially decoded
	// snapshot must not authenticate a CORTEX_NODE key as a BUILDER one.
	if got := strings.TrimSpace(binding.ParticipantType); !strings.EqualFold(got, strings.TrimSpace(participantType)) {
		return fmt.Errorf("current service key participant type is %q, want %s", got, participantType)
	}
	if !strings.EqualFold(strings.TrimSpace(binding.Status), serviceKeyStatusActive) {
		return fmt.Errorf("current service key of %s has status %s, want %s",
			operatorAddress, binding.Status, serviceKeyStatusActive)
	}
	// Defensive: the chain refuses to return a non-ACTIVE binding at all, so this
	// only fires against a Keeper implementation that reports revoked bindings.
	if binding.RevokedHeight.Uint64() != 0 {
		return fmt.Errorf("current service key of %s was revoked at height %d",
			operatorAddress, binding.RevokedHeight.Uint64())
	}
	if strings.TrimSpace(binding.ServicePubkey) == "" {
		return fmt.Errorf("current service key of %s carries no public key", operatorAddress)
	}
	return nil
}

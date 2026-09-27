// Command testorder publishes one synthetic order onto the devnet Nexus bus.
//
// The Builder side does not yet publish task orders, so there is no way to
// exercise the Worker handraise path from real traffic. This injects a
// well-formed OrderBroadcast so that path can be observed end to end.
//
// Without -signer-uri the envelope carries no signature, so the receiving node
// must be running with nexus.envelope_auth_mode: trusted_nats_dev. With
// -signer-uri the frame is signed by the production signer through the
// production sign bytes, so a strict-mode node accepts it provided the key is
// the sender's current ACTIVE on-chain service key; the tool reads that binding
// first and refuses to publish a frame the node would reject.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/daemon"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/observability"
	"github.com/TrueOpen/cortex/internal/signer"
	busv1 "github.com/TrueOpen/cortex/proto/bus/v1"
	bussharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	bustaskv1 "github.com/TrueOpen/cortex/proto/task/v1"
	"github.com/TrueOpen/cortex/scripts/natsurl"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
)

// keeperReadTimeout bounds the one read-only Keeper query this tool makes. The
// tool never submits anything.
const keeperReadTimeout = 15 * time.Second

// orderSpec is everything the flags decide about the order and its envelope.
// It exists so the frame the tool publishes is built by one function that a
// test can call, rather than by main() alone.
type orderSpec struct {
	chainID                string
	evmChainID             uint64
	feeDenom               string
	modelID                string
	builderAddr            string
	builderSetID           string
	builderSetHash         []byte
	sessionAnchorBlockHash []byte
	profileVersion         uint32
	deadlineHeight         uint64
	snapshotHeight         uint64
	authorizationNonce     uint64
	ttl                    time.Duration
	// now anchors issued_at/expires_at and the session seed. Tests pin it; main
	// passes the wall clock.
	now time.Time
	// sessionSeed makes the session id reproducible. Empty means derive it from
	// now, so repeated smoke runs cannot collapse onto one input commitment.
	sessionSeed string
}

// orderFrame is the published frame plus the identifiers the operator needs to
// follow it through the node's logs.
type orderFrame struct {
	subject    string
	frame      []byte
	sessionID  string
	taskID     string
	taskHash   string
	payloadCID string
	payload    []byte
	expiresAt  time.Time
	signed     bool
}

// signerSpec locates the signing key. The flag names mirror cortexd's config
// keys so an operator can copy values across from a node's YAML.
type signerSpec struct {
	uri          string
	keyRef       string
	passwordFile string
	passwordEnv  string
	// serviceAddress is the Keeper-confirmed service address that owns the key,
	// i.e. the service_address of the sender's current binding. The signer must
	// sign as exactly that identity: the receiving node verifies against
	// binding.service_pubkey, so any other key produces a frame it refuses.
	serviceAddress string
	// hrp is the bech32 prefix used to derive a local key's address. It comes
	// from the sender address rather than being configured separately, the same
	// way cortexd derives it.
	hrp string
}

func main() {
	observability.SetDefaultLogger(os.Stderr)
	natsURL := flag.String("nats-url", "", "Nexus NATS URL, credentials may be in the userinfo")
	chainID := flag.String("chain-id", "trueopen-localnet-1", "chain id")
	evmChainID := flag.Uint64("evm-chain-id", 0, "authoritative EVM chain id for the EIP-712 order domain")
	feeDenom := flag.String("fee-denom", "", "authoritative fee denomination for the EIP-712 order")
	modelID := flag.String("model-id", "", "chain model id (64 lowercase hex)")
	profileVersion := flag.Uint("profile-version", 1, "chain profile version")
	builderAddr := flag.String("builder", "", "builder address to attribute the order to")
	deadlineHeight := flag.Uint64("deadline-height", 0, "order deadline height")
	// BuilderSet and session anchor facts belong to the signed order. The bus
	// envelope independently authenticates its Builder at the current nonce.
	builderSetID := flag.String("builder-set-id", "", "BuilderSet id the SignedOrder binds")
	builderSetHash := flag.String("builder-set-hash", "", "BuilderSet hash the SignedOrder binds, 64 lowercase hex")
	authorizationNonce := flag.Uint64("authorization-nonce", 0, "the Builder's current ServiceKey authorization nonce (envelope field 7)")
	snapshotHeight := flag.Uint64("snapshot-height", 0, "order anchor and earliest submission height; not used for key lookup")
	anchorBlockHash := flag.String("session-anchor-block-hash", "", "committed block hash at the order anchor height, 64 lowercase hex")
	ttl := flag.Duration("ttl", 2*time.Minute, "bus envelope lifetime relative to now; the order deadline is -deadline-height")
	// The signer flags mirror cortexd's signer.uri / local_identity.service_key_ref
	// / signer.password_file / signer.password_env, so the values an operator
	// already has in a node config work here unchanged.
	signerURI := flag.String("signer-uri", "", "signer uri holding the Builder's service key, e.g. file:///path/to/keystore; empty publishes an unsigned envelope")
	keyRef := flag.String("key-ref", "", "key reference inside the keystore, e.g. service.json (cortexd local_identity.service_key_ref)")
	passwordFile := flag.String("password-file", "", "file holding the keystore password (cortexd signer.password_file)")
	passwordEnv := flag.String("password-env", "", "environment variable holding the keystore password (cortexd signer.password_env)")
	keeperRPC := flag.String("keeper-rpc", "", "CometBFT RPC endpoint used for read-only Keeper queries")
	nonceFromChain := flag.Bool("authorization-nonce-from-chain", false, "read envelope field 7 from the sender's current ServiceKey binding instead of -authorization-nonce")
	flag.Parse()

	signing := strings.TrimSpace(*signerURI) != ""
	builderSetHashBytes, builderSetHashErr := hex.DecodeString(*builderSetHash)
	anchorBlockHashBytes, anchorHashErr := hex.DecodeString(*anchorBlockHash)
	if *natsURL == "" || *evmChainID == 0 || strings.TrimSpace(*feeDenom) == "" || *modelID == "" || *builderAddr == "" || *deadlineHeight == 0 ||
		*builderSetID == "" || builderSetHashErr != nil || len(builderSetHashBytes) != len(codec.Hash{}) ||
		(*authorizationNonce == 0 && !*nonceFromChain) || *snapshotHeight == 0 || anchorHashErr != nil || len(anchorBlockHashBytes) != 32 {
		printUsage()
		os.Exit(2)
	}
	if signing && strings.TrimSpace(*keyRef) == "" {
		slog.Error("testorder failed", slog.Any("error", errors.New("-signer-uri requires -key-ref: the keystore holds more than one key and signing must name the service key")))
		os.Exit(2)
	}
	// A signed frame is only useful if it is signed by the key the chain
	// currently binds to the sender, at that binding's nonce. Both come from the
	// same read-only Keeper query, so signing without one is guesswork that ends
	// in a refused frame.
	if (signing || *nonceFromChain) && strings.TrimSpace(*keeperRPC) == "" {
		slog.Error("testorder failed", slog.Any("error", errors.New("-keeper-rpc is required with -signer-uri or -authorization-nonce-from-chain: the sender's current ServiceKey binding decides which key and which nonce a node accepts")))
		os.Exit(2)
	}

	nonce := *authorizationNonce
	var envelopeSigner builderclient.BusEnvelopeSigner
	signerAddress := ""
	if signing || *nonceFromChain {
		binding, err := readCurrentBuilderBinding(*keeperRPC, *builderAddr)
		if err != nil {
			slog.Error("testorder failed", slog.Any("error", fmt.Errorf("read current service key: %w", err)))
			os.Exit(1)
		}
		chainNonce := binding.AuthorizationNonce.Uint64()
		if *nonceFromChain {
			if *authorizationNonce != 0 && *authorizationNonce != chainNonce {
				slog.Info("authorization nonce overridden from current ServiceKey binding",
					slog.Uint64("configured_nonce", *authorizationNonce), slog.Uint64("binding_nonce", chainNonce))
			}
			nonce = chainNonce
		} else if nonce != chainNonce {
			// Field 7 is compared against the binding resolved at verification
			// time, so this frame will be refused. Say so rather than let the
			// operator read it as a signature problem.
			slog.Info("authorization nonce does not match current ServiceKey binding; a node will refuse this frame",
				slog.Uint64("configured_nonce", nonce), slog.Uint64("binding_nonce", chainNonce), slog.String("builder", *builderAddr))
		}
		if signing {
			envelopeSigner, signerAddress, err = openEnvelopeSigner(signerSpec{
				uri: *signerURI, keyRef: *keyRef,
				passwordFile: *passwordFile, passwordEnv: *passwordEnv,
				serviceAddress: binding.ServiceAddress,
				hrp:            bech32HRP(*builderAddr),
			})
			if err != nil {
				slog.Error("testorder failed", slog.Any("error", fmt.Errorf("open signer: %w", err)))
				os.Exit(1)
			}
		}
	}

	built, err := buildOrderFrame(orderSpec{
		chainID: *chainID, modelID: *modelID, builderAddr: *builderAddr,
		evmChainID: *evmChainID, feeDenom: strings.TrimSpace(*feeDenom),
		builderSetID: *builderSetID, builderSetHash: builderSetHashBytes,
		sessionAnchorBlockHash: anchorBlockHashBytes,
		profileVersion:         uint32(*profileVersion), deadlineHeight: *deadlineHeight,
		snapshotHeight: *snapshotHeight, authorizationNonce: nonce,
		ttl: *ttl, now: time.Now().UTC(),
	}, envelopeSigner)
	if err != nil {
		slog.Error("testorder failed", slog.Any("error", fmt.Errorf("encode order: %w", err)))
		os.Exit(1)
	}

	publisher, err := builderclient.NewNATSPublisher(strings.TrimSpace(*natsURL), "")
	if err != nil {
		slog.Error("testorder failed", slog.Any("error", errors.New("connect nats: "+natsurl.Scrub(err.Error(), *natsURL))))
		os.Exit(1)
	}
	if err := publisher.Publish(context.Background(), builderclient.PublishRequest{
		Subject: built.subject, TaskID: built.taskID, Payload: built.frame,
	}); err != nil {
		slog.Error("testorder failed", slog.Any("error", errors.New("publish: "+natsurl.Scrub(err.Error(), *natsURL))))
		os.Exit(1)
	}
	// Core NATS publishes are buffered. A short-lived tool has to flush before
	// exiting or the frame never leaves the client.
	if prober, ok := publisher.(interface {
		Probe(context.Context) error
	}); ok {
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := prober.Probe(flushCtx); err != nil {
			slog.Error("testorder failed", slog.Any("error", errors.New("flush: "+natsurl.Scrub(err.Error(), *natsURL))))
			os.Exit(1)
		}
	}
	if closer, ok := publisher.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	fmt.Printf("published order\n  subject:        %s\n  session_id:     %s\n  task_id:        %s\n  task_hash:      %s\n  payload_cid:    %s\n  payload sha256 of %q\n  deadline_height: %d (deadline hint carries the same height)\n  envelope expires: %s\n",
		built.subject, built.sessionID, built.taskID, built.taskHash, built.payloadCID, built.payload, *deadlineHeight, built.expiresAt.Format(time.RFC3339))
	fmt.Printf("  authorization_nonce: %d (%s)\n", nonce, nonceSource(*nonceFromChain))
	if built.signed {
		// The address and the key ref are public identifiers. No password, key
		// material or NATS URL is ever printed.
		fmt.Printf("  envelope signature: signed as %s with key ref %s\n", signerAddress, *keyRef)
	} else {
		fmt.Printf("  envelope signature: none; the receiving node must run nexus.envelope_auth_mode: trusted_nats_dev\n")
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage: testorder -nats-url URL -model-id ID -builder ADDR -deadline-height N")
	fmt.Fprintln(os.Stderr, "       -evm-chain-id N -fee-denom DENOM")
	fmt.Fprintln(os.Stderr, "       -builder-set-id ID -builder-set-hash HEX64 -authorization-nonce N -snapshot-height N")
	fmt.Fprintln(os.Stderr, "       -session-anchor-block-hash HEX64")
	fmt.Fprintln(os.Stderr, "  to publish a signed envelope: -signer-uri URI -key-ref REF -keeper-rpc URL")
	fmt.Fprintln(os.Stderr, "       [-password-file PATH | -password-env NAME] [-authorization-nonce-from-chain]")
}

func nonceSource(fromChain bool) string {
	if fromChain {
		return "current ServiceKey binding"
	}
	return "-authorization-nonce"
}

// readCurrentBuilderBinding resolves the sender's current service-key binding.
// This is the only chain access the tool makes and it is read-only.
//
// The checks mirror the receiving node's own checkCurrentServiceBinding, so a
// binding this rejects is one no strict-mode node would accept either.
func readCurrentBuilderBinding(rpcURL, builderAddr string) (chainclient.ServiceKeySnapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), keeperReadTimeout)
	defer cancel()
	binding, err := chainclient.NewKeeperABCIClient(rpcURL).CurrentServiceKey(
		ctx, chainclient.ParticipantTypeBuilder, builderAddr, 0)
	if err != nil {
		return chainclient.ServiceKeySnapshot{}, err
	}
	if err := checkBuilderBinding(binding, builderAddr); err != nil {
		return chainclient.ServiceKeySnapshot{}, err
	}
	return binding, nil
}

func checkBuilderBinding(binding chainclient.ServiceKeySnapshot, builderAddr string) error {
	if !strings.EqualFold(strings.TrimSpace(binding.OperatorAddress), strings.TrimSpace(builderAddr)) {
		return fmt.Errorf("current service key belongs to %s, not the -builder address %s",
			binding.OperatorAddress, builderAddr)
	}
	if !strings.EqualFold(strings.TrimSpace(binding.ParticipantType), chainclient.ParticipantTypeBuilder) {
		return fmt.Errorf("current service key of %s has participant type %q, want %s",
			builderAddr, binding.ParticipantType, chainclient.ParticipantTypeBuilder)
	}
	if !strings.EqualFold(strings.TrimSpace(binding.Status), "ACTIVE") {
		return fmt.Errorf("current service key of %s has status %s, want ACTIVE", builderAddr, binding.Status)
	}
	if strings.TrimSpace(binding.ServiceAddress) == "" {
		return fmt.Errorf("current service key of %s carries no service address", builderAddr)
	}
	return nil
}

// openEnvelopeSigner opens the keystore the way cortexd does and wraps it in the
// production envelope signer. It returns the address the frames will be signed
// as, for reporting.
//
// A key that is not the one the chain binds to the sender produces a frame the
// receiving node refuses at the signature step, so the mismatch is refused here
// instead: publishing a frame guaranteed to be rejected is worse than not
// publishing at all.
func openEnvelopeSigner(spec signerSpec) (builderclient.BusEnvelopeSigner, string, error) {
	keyRef := strings.TrimSpace(spec.keyRef)
	signingClient, err := signer.Open(spec.uri, signer.OpenOptions{
		PasswordEnv:  spec.passwordEnv,
		PasswordFile: spec.passwordFile,
		HRP:          spec.hrp,
		KeyRefs:      []signer.KeyRef{{Ref: keyRef}},
	})
	if err != nil {
		return nil, "", err
	}
	// A local keystore knows the address it signs as, so the mismatch is caught
	// before anything is published. A remote signing service does not expose one
	// ahead of time; it is handed the expected address and rejects the request
	// itself if its key disagrees.
	serviceAddress := strings.TrimSpace(spec.serviceAddress)
	if local, ok := signingClient.(*signer.LocalSigner); ok {
		keyAddress, ok := local.AddressFor(keyRef)
		if !ok {
			return nil, "", fmt.Errorf("signer uri holds no key %s", keyRef)
		}
		if !strings.EqualFold(keyAddress, serviceAddress) {
			return nil, "", fmt.Errorf("key %s signs as %s, but the sender's current service key is %s: a frame signed by this key would be refused",
				keyRef, keyAddress, serviceAddress)
		}
	}
	envelopeSigner, err := daemon.NewBusEnvelopeSigner(daemon.BusEnvelopeSignerConfig{
		Signer: signingClient,
		KeyRef: keyRef,
		// The address is already resolved from the chain, so there is nothing to
		// bind late here the way the daemon has to.
		ServiceAddress: func() (string, error) { return serviceAddress, nil },
	})
	if err != nil {
		return nil, "", err
	}
	return envelopeSigner, serviceAddress, nil
}

// bech32HRP takes the bech32 prefix from an address, the same way cortexd
// derives it, so a local key file does not have to repeat it.
func bech32HRP(address string) string {
	trimmed := strings.TrimSpace(address)
	if cut := strings.LastIndex(trimmed, "1"); cut > 0 {
		return trimmed[:cut]
	}
	return trimmed
}

// buildOrderFrame builds the OrderBroadcast and its TRUEOPEN_BUS_ENVELOPE_V2 frame.
// A nil signer produces the unsigned frame this tool has always published; a
// non-nil one produces a frame signed through the production sign bytes.
func buildOrderFrame(spec orderSpec, envelopeSigner builderclient.BusEnvelopeSigner) (orderFrame, error) {
	if spec.evmChainID == 0 || strings.TrimSpace(spec.feeDenom) != spec.feeDenom || spec.feeDenom == "" {
		return orderFrame{}, fmt.Errorf("explicit EVM chain id and fee denomination are required")
	}
	// This diagnostic order has an ephemeral user identity. Only the Builder's
	// service key signs the bus envelope; the user key never leaves memory.
	userKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return orderFrame{}, fmt.Errorf("generate synthetic user key: %w", err)
	}
	defer userKey.Zero()
	hasher := sha3.NewLegacyKeccak256()
	_, _ = hasher.Write(userKey.PubKey().SerializeUncompressed()[1:])
	userAddress, err := nodewire.CanonicalOperatorAddressString(bech32HRP(spec.builderAddr), hasher.Sum(nil)[12:])
	if err != nil {
		return orderFrame{}, fmt.Errorf("encode synthetic user address: %w", err)
	}
	// Each invocation is a new user order. Fresh V1 session_id is a raw Hash32
	// rendered as lowercase hex; the payload also changes so repeated smoke runs
	// cannot collapse onto one input commitment.
	sessionSeed := spec.sessionSeed
	if sessionSeed == "" {
		sessionSeed = fmt.Sprintf("testorder-%d", spec.now.UnixNano())
	}
	sessionHash := sha256.Sum256([]byte(sessionSeed))
	sessionID := hex.EncodeToString(sessionHash[:])
	const orderSequence = uint64(1)
	taskID := identity.TaskIDString(sessionID, orderSequence)
	// The payload hash is what the chain would record; a fixture resolver
	// stores the matching bytes at <fixture_root>/inputs/<digest>.bin.
	payload := []byte("hello from cortex testorder " + sessionID)
	payloadDigest := codec.HashBytes(payload)
	modelID, err := identity.ModelIDBytes(spec.modelID)
	if err != nil {
		return orderFrame{}, fmt.Errorf("model id: %w", err)
	}
	orderValue := func(value string) *bussharedv1.Amount { return &bussharedv1.Amount{AtomicUnits: value} }
	signedOrder := &bustaskv1.SignedOrderV2{
		Order: &bustaskv1.TaskOrderV3{
			SchemaVersion: 3, ChainId: spec.chainID, UserAddress: userAddress,
			SessionId: sessionHash[:], OrderSequence: orderSequence,
			ModelId: modelID, ProfileVersion: spec.profileVersion, TaskType: bussharedv1.TaskType_TASK_TYPE_CHAT,
			InputHash: payloadDigest[:], InputSizeBytes: uint64(len(payload)),
			InputBucket: 1, OutputBudgetBucket: 1,
			GenerationParams: &bustaskv1.GenerationParamsV1{
				GenerationParamsSchemaVersion: 1, MaxOutputTokens: 128, MaxOutputDuration: 2000,
				DecodingParams: &bustaskv1.DecodingParamsV1{
					TopPPpm: 1_000_000, Seed: 1, RepetitionPenaltyPpm: 1_000_000,
					StopSequences: []string{}, StopTokenIds: []uint32{},
				},
			},
			PriceBid: orderValue("1"), MaxFee: orderValue("3000"),
			AssignmentPriorityFee: orderValue("0"), TxFeeReserve: orderValue("1000"),
			EarliestSubmitHeight: spec.snapshotHeight, OrderExpireHeight: spec.deadlineHeight,
			DeadlinePolicy:       &bustaskv1.DeadlinePolicyV1{LatencyClass: bustaskv1.DeadlineLatencyClass_DEADLINE_LATENCY_CLASS_STANDARD},
			TimeoutBucketVersion: 1, SessionAnchorHeight: spec.snapshotHeight,
			SessionAnchorBlockHash: spec.sessionAnchorBlockHash,
			BuilderSetId:           spec.builderSetID, BuilderSetHash: spec.builderSetHash,
			PayloadMode:        bustaskv1.PayloadModeV1_PAYLOAD_MODE_V1_PLAINTEXT,
			InputKeyCommitment: make([]byte, 32),
		},
		SignatureScheme: "eip712",
	}
	signingDigest, err := nodewire.TaskOrderSigningDigest(signedOrder.Order, spec.evmChainID, spec.feeDenom)
	if err != nil {
		return orderFrame{}, fmt.Errorf("derive EIP-712 order digest: %w", err)
	}
	compact := ecdsa.SignCompact(userKey, signingDigest[:], false)
	signedOrder.UserSignature = append(append([]byte(nil), compact[1:]...), compact[0])
	signedOrderBytes, err := proto.Marshal(signedOrder)
	if err != nil {
		return orderFrame{}, fmt.Errorf("encode SignedOrderV2: %w", err)
	}
	orderEnvelope := hex.EncodeToString(signedOrderBytes)
	taskHash, _, err := nodewire.TaskOrderHashAndFactsEnvelope(orderEnvelope)
	if err != nil {
		return orderFrame{}, fmt.Errorf("hash TaskOrderV3: %w", err)
	}
	now := spec.now

	// The V2 broadcast carries the typed SignedOrderV2 and nothing else; every
	// fact the old payload duplicated is read off the decoded order.
	broadcast := &busv1.OrderBroadcastV1{SignedOrder: signedOrder}

	subject := builderclient.NATSTaskOpenSubject(spec.modelID)
	input := builderclient.UnsignedEnvelopeInput{
		Kind: builderclient.KindOrderBroadcast, ChainID: spec.chainID, Subject: subject,
		SenderOperatorAddress: spec.builderAddr, SenderParticipantType: builderclient.ParticipantBuilder,
		ServiceAuthorizationNonce: spec.authorizationNonce,
		IssuedAt:                  now, ExpiresAt: now.Add(spec.ttl),
	}
	var frame []byte
	if envelopeSigner == nil {
		frame, err = builderclient.EncodeUnsignedBusMessage(input, broadcast, true)
	} else {
		frame, err = builderclient.EncodeAuthenticatedBusMessage(input, broadcast, envelopeSigner)
	}
	if err != nil {
		return orderFrame{}, err
	}
	return orderFrame{
		subject: subject, frame: frame,
		sessionID: sessionID, taskID: taskID,
		taskHash: hex.EncodeToString(taskHash[:]), payloadCID: "fixture://sha256/" + fmt.Sprintf("%x", payloadDigest[:]), payload: payload,
		expiresAt: now.Add(spec.ttl), signed: envelopeSigner != nil,
	}, nil
}

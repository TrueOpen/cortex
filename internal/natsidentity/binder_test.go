package natsidentity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nats-io/nkeys"

	"github.com/TrueOpen/wire/bus"

	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/signer"
	"github.com/SingaXYZ/cortex/internal/wirevectors"
)

type vectorFile struct {
	PrivateKey          string `json:"private_key"`
	PublicKeyCompressed string `json:"public_key_compressed"`
	NATSUserSeed        string `json:"nats_user_seed"`
	Cases               []struct {
		Fields struct {
			ChainID                   string `json:"chain_id"`
			OperatorAddress           string `json:"operator_address"`
			ServiceAuthorizationNonce string `json:"service_authorization_nonce"`
			IssuedAtUnixMS            string `json:"issued_at_unix_ms"`
		} `json:"fields"`
		Expected struct {
			Token string `json:"token"`
		} `json:"expected"`
	} `json:"cases"`
}

func loadVector(t *testing.T) vectorFile {
	t.Helper()
	raw, err := wirevectors.File("bus/nats_user_binding_v1_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file vectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("wire nats user binding vectors carry no case")
	}
	return file
}

// vectorSigner implements signer.Signer with the vector's test-only secp256k1
// private key; it signs digests only.
type vectorSigner struct {
	mu      sync.Mutex
	priv    *secp256k1.PrivateKey
	calls   int
	err     error
	lastReq signer.DigestRequest
}

func (s *vectorSigner) SignDigest(_ context.Context, req signer.DigestRequest) ([]byte, error) {
	s.mu.Lock()
	s.calls++
	s.lastReq = req
	priv, err := s.priv, s.err
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	digest := [32]byte(req.Digest)
	return bus.SignDigest(priv, digest), nil
}

func (s *vectorSigner) SignCosmosTx(context.Context, signer.CosmosTxRequest) ([]byte, error) {
	return nil, errors.New("not used")
}

func (s *vectorSigner) CanSignCosmosTx() bool { return false }

func (s *vectorSigner) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *vectorSigner) request() signer.DigestRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastReq
}

type fakeServiceKeys struct {
	mu       sync.Mutex
	snapshot chainclient.ServiceKeySnapshot
	height   uint64
	err      error
	calls    int
	// When gate is non-nil every chain read stops here until the test releases it:
	// used to pin one Credential call to the construction path.
	gate chan struct{}
	// queries records the arguments of every chain query: the Binder must ask for
	// CORTEX_NODE and the configured operator.
	queries [][2]string
}

func (f *fakeServiceKeys) CommittedCurrentServiceKey(_ context.Context, participantType, operatorAddress string) (chainclient.ServiceKeySnapshot, uint64, error) {
	f.mu.Lock()
	f.calls++
	f.queries = append(f.queries, [2]string{participantType, operatorAddress})
	snapshot, height, err, gate := f.snapshot, f.height, f.err, f.gate
	f.mu.Unlock()
	if gate != nil {
		<-gate
	}
	if err != nil {
		return chainclient.ServiceKeySnapshot{}, 0, err
	}
	return snapshot, height, nil
}

func (f *fakeServiceKeys) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeServiceKeys) queryArgs() [][2]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][2]string(nil), f.queries...)
}

const vectorServiceAddress = "trueopen1serviceaddress"

func newVectorBinder(t *testing.T, file vectorFile, nowMS int64) (*Binder, *fakeServiceKeys, *vectorSigner) {
	t.Helper()
	binder, keys, sig, _ := newVectorBinderWithSentinel(t, file, nowMS)
	return binder, keys, sig
}

func newVectorBinderWithSentinel(t *testing.T, file vectorFile, nowMS int64) (*Binder, *fakeServiceKeys, *vectorSigner, *fakeSentinelSource) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nats-user.nk")
	if err := os.WriteFile(path, []byte(file.NATSUserSeed), 0o600); err != nil {
		t.Fatal(err)
	}
	userKey, _, err := LoadOrCreateUserKey(path)
	if err != nil {
		t.Fatal(err)
	}
	privBytes, err := hex.DecodeString(file.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	sig := &vectorSigner{priv: secp256k1.PrivKeyFromBytes(privBytes)}
	c := file.Cases[0]
	keys := &fakeServiceKeys{height: 100, snapshot: chainclient.ServiceKeySnapshot{
		ParticipantType: chainclient.ParticipantTypeCortexNode, OperatorAddress: c.Fields.OperatorAddress,
		ServiceAddress: vectorServiceAddress, ServicePubkey: file.PublicKeyCompressed,
		AuthorizationNonce: chainclient.Uint64String(1), Status: "ACTIVE",
	}}
	sentinel := newFakeSentinel()
	binder, err := New(Config{
		ServiceKeys: keys, Signer: sig, ChainID: c.Fields.ChainID, OperatorAddress: c.Fields.OperatorAddress,
		ServiceKeyRef: "kms://cortex/service-key", UserKey: userKey, Sentinel: sentinel,
		Now: func() time.Time { return time.UnixMilli(nowMS) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return binder, keys, sig, sentinel
}

// The strongest one: the token the Binder produces is byte-for-byte the token of
// wire §7.5.4's minimal vector.
func TestBinderReproducesWireMinimumVectorToken(t *testing.T) {
	file := loadVector(t)
	binder, _, _, sentinel := newVectorBinderWithSentinel(t, file, 1)
	cred, err := binder.Credential(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cred.Token != file.Cases[0].Expected.Token {
		t.Fatalf("token differs from wire vector\n got %s\nwant %s", cred.Token, file.Cases[0].Expected.Token)
	}
	if cred.UserPublicKey != "UA5WUJ54Z23KILLCUOUNAKTPBVZWKMQVO4O6EQ5GHLAERIMLLHNCTYM5" {
		t.Fatalf("user pubkey = %s", cred.UserPublicKey)
	}
	sig, err := cred.SignNonce([]byte("nonce"))
	if err != nil || len(sig) != 64 {
		t.Fatalf("nonce signature: %v len=%d", err, len(sig))
	}
	// CONNECT must also carry the AUTH sentinel: without it an operator-mode server
	// never even reaches the connection callback.
	if cred.SentinelJWT != sentinel.sentinel.JWT {
		t.Fatalf("sentinel jwt = %q, want the one the Builder ingress served", cred.SentinelJWT)
	}
	if status := binder.Status(); status.SentinelAccount != sentinel.sentinel.AuthAccountPublicKey {
		t.Fatalf("status sentinel account = %q", status.SentinelAccount)
	}
}

// "Two signing identities": the binding must be signed by the service key, and the
// signing request must name the chain's current service address.
func TestBinderSignsWithTheCommittedServiceIdentity(t *testing.T) {
	file := loadVector(t)
	binder, _, sig := newVectorBinder(t, file, 1)
	if _, err := binder.Credential(context.Background()); err != nil {
		t.Fatal(err)
	}
	req := sig.request()
	if req.ExpectedSignerAddress != vectorServiceAddress {
		t.Fatalf("expected signer address = %q, want the committed service address %q", req.ExpectedSignerAddress, vectorServiceAddress)
	}
	if req.KeyRef != "kms://cortex/service-key" {
		t.Fatalf("key ref = %q", req.KeyRef)
	}
	if hex.EncodeToString(req.Digest[:]) != "114c75653efeb0b8f316f8078bd4a50abb3f7c018716cbd5adf08e3ceb4ce917" {
		t.Fatalf("signed digest = %s, want the wire vector signing digest", hex.EncodeToString(req.Digest[:]))
	}
}

func TestBinderCachesUntilChainNonceChanges(t *testing.T) {
	file := loadVector(t)
	binder, keys, sig := newVectorBinder(t, file, 1)
	first, err := binder.Credential(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := binder.Credential(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Token != second.Token || sig.callCount() != 1 {
		t.Fatalf("unchanged chain binding must reuse the signed token; signer called %d times", sig.callCount())
	}
	if keys.callCount() != 2 {
		t.Fatalf("every Credential re-reads the committed binding to notice rotation, got %d reads", keys.callCount())
	}
	operator := file.Cases[0].Fields.OperatorAddress
	for i, query := range keys.queryArgs() {
		if query[0] != chainclient.ParticipantTypeCortexNode || query[1] != operator {
			t.Fatalf("chain read %d asked for (%q, %q), want (%q, %q)", i, query[0], query[1], chainclient.ParticipantTypeCortexNode, operator)
		}
	}
	keys.mu.Lock()
	keys.snapshot.AuthorizationNonce = chainclient.Uint64String(2)
	keys.mu.Unlock()
	third, err := binder.Credential(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if third.Token == first.Token || sig.callCount() != 2 {
		t.Fatal("rotated nonce must produce a new binding")
	}
	if status := binder.Status(); status.BindingNonce != 2 || status.UserPublicKey == "" || status.LastError != "" {
		t.Fatalf("status = %+v", status)
	}
}

func TestBinderInvalidateForcesRebuild(t *testing.T) {
	file := loadVector(t)
	binder, _, sig, sentinel := newVectorBinderWithSentinel(t, file, 1)
	if _, err := binder.Credential(context.Background()); err != nil {
		t.Fatal(err)
	}
	binder.Invalidate()
	if _, err := binder.Credential(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sig.callCount() != 2 {
		t.Fatalf("invalidate must force a fresh signature, signer called %d times", sig.callCount())
	}
	// A rotated sentinel presents as the same authentication failure, so it has to be
	// invalidated along with the binding.
	if sentinel.invalidateCount() != 1 {
		t.Fatalf("invalidate must also drop the sentinel, got %d", sentinel.invalidateCount())
	}
	if status := binder.Status(); status.LastError != "" {
		t.Fatalf("a successful rebuild clears the error: %+v", status)
	}
}

// Concurrent reconnects must not each sign their own: Credential serialises, and
// 10 goroutines produce exactly one signature.
func TestBinderSignsOnceUnderConcurrentCredential(t *testing.T) {
	file := loadVector(t)
	binder, _, sig := newVectorBinder(t, file, 1)
	var wg sync.WaitGroup
	tokens := make([]string, 10)
	errs := make([]error, 10)
	for i := range tokens {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cred, err := binder.Credential(context.Background())
			tokens[i], errs[i] = cred.Token, err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
		if tokens[i] != tokens[0] {
			t.Fatalf("goroutine %d saw a different token", i)
		}
	}
	if sig.callCount() != 1 {
		t.Fatalf("concurrent Credential calls must share one signature, signer called %d times", sig.callCount())
	}
}

func TestBinderFailsClosedOnChainAndKeyProblems(t *testing.T) {
	file := loadVector(t)
	cases := []struct {
		name   string
		mutate func(*fakeServiceKeys, *vectorSigner)
	}{
		{"chain unavailable", func(k *fakeServiceKeys, _ *vectorSigner) { k.err = errors.New("connection refused") }},
		{"key revoked", func(k *fakeServiceKeys, _ *vectorSigner) { k.snapshot.Status = "REVOKED" }},
		{"revoked at or below the committed height", func(k *fakeServiceKeys, _ *vectorSigner) {
			k.snapshot.RevokedHeight = chainclient.Uint64String(100)
		}},
		{"wrong operator", func(k *fakeServiceKeys, _ *vectorSigner) { k.snapshot.OperatorAddress = "trueopen1other" }},
		{"wrong participant", func(k *fakeServiceKeys, _ *vectorSigner) { k.snapshot.ParticipantType = "BUILDER" }},
		{"incomplete snapshot", func(k *fakeServiceKeys, _ *vectorSigner) { k.snapshot.ServiceAddress = "" }},
		{"zero committed height", func(k *fakeServiceKeys, _ *vectorSigner) { k.height = 0 }},
		{"signer failure", func(_ *fakeServiceKeys, s *vectorSigner) { s.err = errors.New("kms down") }},
		{"signer wrong key", func(_ *fakeServiceKeys, s *vectorSigner) {
			other, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000002")
			s.priv = secp256k1.PrivKeyFromBytes(other)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			binder, keys, sig := newVectorBinder(t, file, 1)
			tc.mutate(keys, sig)
			_, err := binder.Credential(context.Background())
			if err == nil {
				t.Fatal("expected failure")
			}
			if status := binder.Status(); status.LastError == "" {
				t.Fatalf("status must record the failure: %+v", status)
			}
		})
	}
}

// No sentinel means no credential is presented: fail closed, and record the
// failure in Status so diagnostics can explain the reason.
func TestBinderFailsClosedWhenTheSentinelIsUnavailable(t *testing.T) {
	file := loadVector(t)
	binder, _, _, sentinel := newVectorBinderWithSentinel(t, file, 1)
	sentinel.err = errors.New("builder has no nats sentinel configured")
	if _, err := binder.Credential(context.Background()); err == nil {
		t.Fatal("a missing sentinel must fail the credential")
	}
	if status := binder.Status(); status.LastError == "" {
		t.Fatalf("status must record the sentinel failure: %+v", status)
	}
}

func TestBinderRejectsIncompleteConfig(t *testing.T) {
	file := loadVector(t)
	_, keys, sig := newVectorBinder(t, file, 1)
	userKey, _, err := LoadOrCreateUserKey(filepath.Join(t.TempDir(), "k.nk"))
	if err != nil {
		t.Fatal(err)
	}
	base := Config{ServiceKeys: keys, Signer: sig, ChainID: "c", OperatorAddress: "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man", ServiceKeyRef: "ref", UserKey: userKey, Sentinel: newFakeSentinel()}
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no service keys", func(c *Config) { c.ServiceKeys = nil }},
		{"no signer", func(c *Config) { c.Signer = nil }},
		{"no chain id", func(c *Config) { c.ChainID = "" }},
		{"no operator", func(c *Config) { c.OperatorAddress = "" }},
		{"no key ref", func(c *Config) { c.ServiceKeyRef = "" }},
		{"no user key", func(c *Config) { c.UserKey = nil }},
		{"no sentinel source", func(c *Config) { c.Sentinel = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if _, err := New(base); err != nil {
		t.Fatalf("a complete config must be accepted: %v", err)
	}
}

// nats_user_pubkey in the binding declaration must be a user-class nkey: an account
// key handed in here has to be stopped in New, not left for wire's validateBinding
// to report on every signature.
func TestBinderRejectsNonUserNATSKey(t *testing.T) {
	file := loadVector(t)
	_, keys, sig := newVectorBinder(t, file, 1)
	account, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Config{
		ServiceKeys: keys, Signer: sig, ChainID: "c",
		OperatorAddress: file.Cases[0].Fields.OperatorAddress, ServiceKeyRef: "ref", UserKey: account,
		Sentinel: newFakeSentinel(),
	})
	if err == nil {
		t.Fatal("New must refuse a key pair whose public key is not a nats user key")
	}
	if !errors.Is(err, bus.ErrBinding) {
		t.Fatalf("rejection should come from the wire binding validator, got %v", err)
	}
}

// blockInFlightCredential parks one Credential call inside the chain read and
// returns the closure that releases it plus its completion signal.
func blockInFlightCredential(t *testing.T, binder *Binder, keys *fakeServiceKeys) (release func(), done chan error) {
	t.Helper()
	gate := make(chan struct{})
	keys.mu.Lock()
	keys.gate = gate
	keys.mu.Unlock()
	done = make(chan error, 1)
	go func() {
		_, err := binder.Credential(context.Background())
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for keys.callCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the first Credential never reached the chain read")
		}
		time.Sleep(time.Millisecond)
	}
	return func() { close(gate) }, done
}

// Diagnostics matter most when the chain is at its slowest: Status must not share
// a lock with the construction path.
func TestStatusDoesNotWaitForAnInFlightCredential(t *testing.T) {
	file := loadVector(t)
	binder, keys, _ := newVectorBinder(t, file, 1)
	release, done := blockInFlightCredential(t, binder, keys)

	answered := make(chan Status, 1)
	go func() { answered <- binder.Status() }()
	select {
	case status := <-answered:
		if status.UserPublicKey == "" {
			t.Errorf("status = %+v, want the user public key even before the first binding", status)
		}
	case <-time.After(2 * time.Second):
		t.Error("Status blocked behind a Credential stuck in a slow chain read")
	}
	// Invalidate likewise only touches published state; a stuck chain read must not
	// block it too.
	invalidated := make(chan struct{})
	go func() { binder.Invalidate(); close(invalidated) }()
	select {
	case <-invalidated:
	case <-time.After(2 * time.Second):
		t.Error("Invalidate blocked behind a Credential stuck in a slow chain read")
	}

	release()
	if err := <-done; err != nil {
		t.Fatalf("the released Credential should still succeed: %v", err)
	}
}

// A call queued behind an in-flight construction has to honour its own ctx instead
// of waiting alongside the chain.
func TestCredentialQueuedBehindAnotherHonoursItsContext(t *testing.T) {
	file := loadVector(t)
	binder, keys, _ := newVectorBinder(t, file, 1)
	release, done := blockInFlightCredential(t, binder, keys)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	queued := make(chan error, 1)
	go func() {
		_, err := binder.Credential(ctx)
		queued <- err
	}()
	select {
	case err := <-queued:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("queued Credential error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a queued Credential with a cancelled context must not wait for the in-flight build")
	}

	release()
	if err := <-done; err != nil {
		t.Fatalf("the released Credential should still succeed: %v", err)
	}
}

package builderclient

import (
	"context"
	"errors"
	"strings"
	"testing"

	nats "github.com/nats-io/nats.go"
)

type fakeChainIdentity struct {
	cred        NATSChainCredential
	err         error
	calls       int
	invalidated int
}

func (f *fakeChainIdentity) Credential(context.Context) (NATSChainCredential, error) {
	f.calls++
	return f.cred, f.err
}

func (f *fakeChainIdentity) Invalidate() { f.invalidated++ }

func applyOptions(t *testing.T, opts []nats.Option) nats.Options {
	t.Helper()
	o := nats.GetDefaultOptions()
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			t.Fatal(err)
		}
	}
	return o
}

func TestNATSAuthOptionsUseSentinelJWTAndTokenHandlerForChainIdentity(t *testing.T) {
	provider := &fakeChainIdentity{cred: NATSChainCredential{
		UserPublicKey: "UA5WUJ54Z23KILLCUOUNAKTPBVZWKMQVO4O6EQ5GHLAERIMLLHNCTYM5",
		SignNonce:     func(nonce []byte) ([]byte, error) { return append([]byte("sig:"), nonce...), nil },
		Token:         "trueopen-nub1.abc",
		SentinelJWT:   "eyJ.sentinel.one",
	}}
	_, opts, err := natsConnectOptions(NATSAuth{URL: "tls://nats.example:4222", ChainIdentity: provider})
	if err != nil {
		t.Fatal(err)
	}
	o := applyOptions(t, opts)
	// An operator-mode CONNECT has to carry a jwt, and an nkey and a jwt cannot both be
	// present, so Nkey must be empty.
	if o.UserJWT == nil || o.Nkey != "" || o.SignatureCB == nil || o.TokenHandler == nil || !o.Secure {
		t.Fatalf("options = userJWT %v nkey %q sigCB %v tokenHandler %v secure %v", o.UserJWT != nil, o.Nkey, o.SignatureCB != nil, o.TokenHandler != nil, o.Secure)
	}
	if got, err := o.UserJWT(); err != nil || got != "eyJ.sentinel.one" {
		t.Fatalf("user jwt callback = %q, %v", got, err)
	}
	// After a sentinel rotation the next (re)connect presents the new one.
	provider.cred.SentinelJWT = "eyJ.sentinel.two"
	if got, _ := o.UserJWT(); got != "eyJ.sentinel.two" {
		t.Fatalf("user jwt callback must ask the provider each time, got %q", got)
	}
	if got, _ := o.SignatureCB([]byte("n")); string(got) != "sig:n" {
		t.Fatalf("signature callback not wired: %q", got)
	}
	if got := o.TokenHandler(); got != "trueopen-nub1.abc" {
		t.Fatalf("token handler returned %q", got)
	}
	// TokenHandler asks the provider once per connection and gets the current binding.
	provider.cred.Token = "trueopen-nub1.def"
	if got := o.TokenHandler(); got != "trueopen-nub1.def" {
		t.Fatalf("token handler must ask the provider each time, got %q", got)
	}
	if o.Token != "" {
		t.Fatal("static token must not be set alongside the handler")
	}
}

// The nkey and the signing function do not change during one connection's lifetime:
// the user key does not rotate with the binding, so the handshake uses the SignNonce
// obtained at the moment natsConnectOptions ran.
func TestNATSAuthOptionsSignatureCallbackStaysTheInitialSigner(t *testing.T) {
	provider := &fakeChainIdentity{cred: NATSChainCredential{
		UserPublicKey: "UA5WUJ54Z23KILLCUOUNAKTPBVZWKMQVO4O6EQ5GHLAERIMLLHNCTYM5",
		SignNonce:     func(nonce []byte) ([]byte, error) { return append([]byte("first:"), nonce...), nil },
		Token:         "trueopen-nub1.abc",
		SentinelJWT:   "eyJ.sentinel.one",
	}}
	_, opts, err := natsConnectOptions(NATSAuth{URL: "tls://nats.example:4222", ChainIdentity: provider})
	if err != nil {
		t.Fatal(err)
	}
	o := applyOptions(t, opts)
	provider.cred.SignNonce = func(nonce []byte) ([]byte, error) { return append([]byte("second:"), nonce...), nil }
	provider.cred.UserPublicKey = "UOTHER"
	if got, _ := o.SignatureCB([]byte("n")); string(got) != "first:n" {
		t.Fatalf("signature callback = %q, want the signer captured at option build time", got)
	}
	if o.Nkey != "" {
		t.Fatalf("nkey = %q, want none: nats.go refuses nkey together with a jwt", o.Nkey)
	}
}

// When the chain is briefly unreadable on a reconnect, reusing the previous token and
// being refused beats sending an empty one.
func TestNATSAuthOptionsTokenHandlerFallsBackToLastGoodToken(t *testing.T) {
	provider := &fakeChainIdentity{cred: NATSChainCredential{
		UserPublicKey: "U",
		SignNonce:     func([]byte) ([]byte, error) { return nil, nil },
		Token:         "trueopen-nub1.abc",
		SentinelJWT:   "eyJ.sentinel.one",
	}}
	_, opts, err := natsConnectOptions(NATSAuth{URL: "tls://x:4222", ChainIdentity: provider})
	if err != nil {
		t.Fatal(err)
	}
	o := applyOptions(t, opts)
	provider.err = errors.New("chain unavailable")
	provider.cred.Token = ""
	if got := o.TokenHandler(); got != "trueopen-nub1.abc" {
		t.Fatalf("token handler = %q, want the last good token", got)
	}
}

// When the chain is briefly unreadable on a reconnect the sentinel is reused too: it
// is public material and rotates rarely, so handshaking with the old one beats sending
// an empty jwt (nats.go refuses an empty jwt outright).
func TestNATSAuthOptionsUserJWTFallsBackToLastSentinel(t *testing.T) {
	provider := &fakeChainIdentity{cred: NATSChainCredential{
		UserPublicKey: "U",
		SignNonce:     func([]byte) ([]byte, error) { return nil, nil },
		Token:         "trueopen-nub1.abc",
		SentinelJWT:   "eyJ.sentinel.one",
	}}
	_, opts, err := natsConnectOptions(NATSAuth{URL: "tls://x:4222", ChainIdentity: provider})
	if err != nil {
		t.Fatal(err)
	}
	o := applyOptions(t, opts)
	provider.err = errors.New("builder ingress unavailable")
	provider.cred.SentinelJWT = ""
	if got, err := o.UserJWT(); err != nil || got != "eyJ.sentinel.one" {
		t.Fatalf("user jwt callback = %q, %v; want the last sentinel", got, err)
	}
}

// No sentinel even on the first attempt: fail closed, and the error has to say that
// the Builder served no sentinel.
func TestNATSAuthOptionsRefuseEmptySentinel(t *testing.T) {
	provider := &fakeChainIdentity{cred: NATSChainCredential{
		UserPublicKey: "U",
		SignNonce:     func([]byte) ([]byte, error) { return nil, nil },
		Token:         "trueopen-nub1.abc",
	}}
	_, _, err := natsConnectOptions(NATSAuth{URL: "tls://x:4222", ChainIdentity: provider})
	if err == nil || !strings.Contains(err.Error(), "sentinel") {
		t.Fatalf("empty sentinel must fail the connect and name the cause, got %v", err)
	}
}

func TestNATSAuthOptionsChainIdentityWinsOverCredsAndToken(t *testing.T) {
	provider := &fakeChainIdentity{cred: NATSChainCredential{UserPublicKey: "U", SignNonce: func([]byte) ([]byte, error) { return nil, nil }, Token: "t", SentinelJWT: "eyJ.sentinel.one"}}
	_, opts, err := natsConnectOptions(NATSAuth{URL: "tls://x:4222", ChainIdentity: provider, CredsFile: "/nonexistent.creds", Token: "legacy"})
	if err != nil {
		t.Fatalf("creds/token must be ignored when a chain identity is present: %v", err)
	}
	o := applyOptions(t, opts)
	// creds would put its own UserJWT in the same field, so what matters here is what the
	// callback returns: it must be the on-chain identity's sentinel, not the user JWT
	// from a creds file.
	if o.Token != "" {
		t.Fatal("legacy token leaked into options")
	}
	if got, err := o.UserJWT(); err != nil || got != "eyJ.sentinel.one" {
		t.Fatalf("user jwt = %q, %v; creds must be ignored when a chain identity is present", got, err)
	}
}

func TestNATSAuthOptionsPropagateProviderFailure(t *testing.T) {
	provider := &fakeChainIdentity{err: errors.New("chain unavailable")}
	if _, _, err := natsConnectOptions(NATSAuth{URL: "tls://x:4222", ChainIdentity: provider}); err == nil || !errors.Is(err, provider.err) {
		t.Fatalf("provider failure must fail the connect, got %v", err)
	}
}

func TestInvalidateOnAuthorizationError(t *testing.T) {
	provider := &fakeChainIdentity{}
	invalidateOnAuthError(NATSAuth{ChainIdentity: provider}, nats.ErrAuthorization)
	invalidateOnAuthError(NATSAuth{ChainIdentity: provider}, errors.New("dial tcp: refused"))
	if provider.invalidated != 1 {
		t.Fatalf("only an authorization error invalidates, got %d", provider.invalidated)
	}
}

func TestConcreteConnectorsInvalidateOnAuthorizationError(t *testing.T) {
	cred := NATSChainCredential{UserPublicKey: "U", SignNonce: func([]byte) ([]byte, error) { return nil, nil }, Token: "t", SentinelJWT: "eyJ.sentinel.one"}
	original := natsConnect
	natsConnect = func(string, ...nats.Option) (*nats.Conn, error) { return nil, nats.ErrAuthorization }
	t.Cleanup(func() { natsConnect = original })

	subProvider := &fakeChainIdentity{cred: cred}
	if _, err := connectConcreteNATSSubscriber(NATSAuth{URL: "tls://x:4222", ChainIdentity: subProvider}); !errors.Is(err, nats.ErrAuthorization) {
		t.Fatalf("subscriber connect error = %v", err)
	}
	if subProvider.invalidated != 1 {
		t.Fatalf("subscriber must invalidate the binding on an authorization error, got %d", subProvider.invalidated)
	}

	pubProvider := &fakeChainIdentity{cred: cred}
	if _, err := connectConcreteNATSPublishTransport(NATSAuth{URL: "tls://x:4222", ChainIdentity: pubProvider}); !errors.Is(err, nats.ErrAuthorization) {
		t.Fatalf("publish transport connect error = %v", err)
	}
	if pubProvider.invalidated != 1 {
		t.Fatalf("publish transport must invalidate the binding on an authorization error, got %d", pubProvider.invalidated)
	}
}

// An authentication failure at run time reaches the client only through the
// disconnect / async error callbacks, and must invalidate the binding as well.
func TestNATSAuthOptionsInvalidateOnRuntimeAuthErrors(t *testing.T) {
	provider := &fakeChainIdentity{cred: NATSChainCredential{
		UserPublicKey: "U",
		SignNonce:     func([]byte) ([]byte, error) { return nil, nil },
		Token:         "trueopen-nub1.abc",
		SentinelJWT:   "eyJ.sentinel.one",
	}}
	_, opts, err := natsConnectOptions(NATSAuth{URL: "tls://x:4222", ChainIdentity: provider})
	if err != nil {
		t.Fatal(err)
	}
	o := applyOptions(t, opts)
	if o.DisconnectedErrCB == nil || o.AsyncErrorCB == nil {
		t.Fatalf("handlers = disconnect %v asyncErr %v", o.DisconnectedErrCB != nil, o.AsyncErrorCB != nil)
	}
	o.DisconnectedErrCB(nil, nats.ErrAuthExpired)
	o.AsyncErrorCB(nil, nil, nats.ErrAuthorization)
	if provider.invalidated != 2 {
		t.Fatalf("runtime auth errors invalidated %d times, want 2", provider.invalidated)
	}
	o.DisconnectedErrCB(nil, errors.New("connection reset"))
	o.AsyncErrorCB(nil, nil, errors.New("slow consumer"))
	if provider.invalidated != 2 {
		t.Fatalf("non-auth errors must not invalidate, got %d", provider.invalidated)
	}
}

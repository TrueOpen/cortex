package builderclient

import (
	"context"
	"errors"

	nats "github.com/nats-io/nats.go"
)

// NATSChainCredential is what one connection has to present (interface-and-topic-list §5.14.2):
// CONNECT.jwt = SentinelJWT, CONNECT.sig = SignNonce(the server's nonce),
// CONNECT.auth_token = Token.
//
// Why CONNECT carries the sentinel JWT rather than the nkey: an operator-mode server
// requires CONNECT to carry a user JWT its own account can verify before it asks the
// auth callback (nats-server v2.10.22 server/auth.go:731-736), so sending only
// nkey+sig+auth_token earns an Authorization Violation before the callback ever runs.
// NATS's own answer is to present the AUTH account's sentinel user JWT (a bearer with
// no permissions, public material) and leave the real identity in auth_token for the
// callback to judge. UserPublicKey is still kept: it is the nats_user_pubkey in the
// binding declaration, which the callback verifies sig against.
type NATSChainCredential struct {
	UserPublicKey string
	SignNonce     func(nonce []byte) ([]byte, error)
	Token         string
	// SentinelJWT is the AUTH account sentinel user JWT fetched from a Builder ingress.
	SentinelJWT string
}

// ChainIdentityProvider is implemented by natsidentity.Binder. Credential is called
// before every (re)connect and returns the current binding; Invalidate is called after
// an authentication failure, so the next Credential re-reads the chain and rebuilds it.
type ChainIdentityProvider interface {
	Credential(ctx context.Context) (NATSChainCredential, error)
	Invalidate()
}

// invalidateOnAuthError drops the binding for authentication failures only: NATS does
// not pass the callback's error code to the client, so all a client can tell apart is
// "authentication refused" and "cannot connect".
func invalidateOnAuthError(auth NATSAuth, err error) {
	if auth.ChainIdentity == nil || err == nil {
		return
	}
	if errors.Is(err, nats.ErrAuthorization) || errors.Is(err, nats.ErrAuthExpired) || errors.Is(err, nats.ErrAuthRevoked) {
		auth.ChainIdentity.Invalidate()
	}
}

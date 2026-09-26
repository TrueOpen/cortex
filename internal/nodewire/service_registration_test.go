package nodewire

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The published wire vector for TRUEOPEN_SERVICE_REGISTRATION_V1
// (testdata/v1/hub/hub_domains_v1.json, §10.0c step 1). It is the Cortex case:
// participant_type 1 is PARTICIPANT_TYPE_CORTEX.
//
// Pinned literally rather than read from the vector file, because this test's
// job is to fail when this implementation drifts from the published contract --
// including when the vector file is updated for a reason nobody checked against
// this code. internal/wirevectors separately proves the file itself is the one
// wire published.
const (
	vectorChainID       = "trueopen-fixture-1"
	vectorOperatorHex   = "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4"
	vectorServicePubHex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	vectorPreimageHex   = "0000000000000020545255454f50454e5f534552564943455f524547495354524154494f4e5f56310000000000000012747275656f70656e2d666978747572652d310000000000000004000000010000000000000014a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4000000000000002102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee500000000000000080000000000000001"
	vectorDigestHex     = "9ab3141d52a2b3d3f2800405ec33b6f1d210d490c33de422fb6643723b4b98dc"
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode %q: %v", value, err)
	}
	return raw
}

// TestServiceRegistrationMatchesThePublishedVector is the only thing standing
// between this digest and a proof the chain silently refuses. The Hub Keeper
// recomputes it with its own helpers; agreeing with the published vector is how
// this implementation shows it agrees with those.
func TestServiceRegistrationMatchesThePublishedVector(t *testing.T) {
	preimage, err := ServiceRegistrationPreimage(vectorChainID, ParticipantTypeCortexV1,
		mustHex(t, vectorOperatorHex), mustHex(t, vectorServicePubHex), InitialServiceAuthorizationNonce)
	if err != nil {
		t.Fatalf("ServiceRegistrationPreimage: %v", err)
	}
	if got := hex.EncodeToString(preimage); got != vectorPreimageHex {
		t.Fatalf("preimage =\n%s\nwant\n%s", got, vectorPreimageHex)
	}
	digest, err := ServiceRegistrationDigest(vectorChainID, ParticipantTypeCortexV1,
		mustHex(t, vectorOperatorHex), mustHex(t, vectorServicePubHex), InitialServiceAuthorizationNonce)
	if err != nil {
		t.Fatalf("ServiceRegistrationDigest: %v", err)
	}
	if digest.String() != vectorDigestHex {
		t.Fatalf("digest = %s, want %s", digest, vectorDigestHex)
	}
}

// TestServiceRegistrationSeparatesParticipantTypes pins the reason
// participant_type sits where it does. The vector's own note says the domain
// "separates Cortex and Builder identity proofs and makes cross_participant_type
// replay testable" -- so a Builder proof must not be reusable as a Cortex one
// over otherwise identical material.
func TestServiceRegistrationSeparatesParticipantTypes(t *testing.T) {
	cortex, err := ServiceRegistrationDigest(vectorChainID, ParticipantTypeCortexV1,
		mustHex(t, vectorOperatorHex), mustHex(t, vectorServicePubHex), InitialServiceAuthorizationNonce)
	if err != nil {
		t.Fatal(err)
	}
	builder, err := ServiceRegistrationDigest(vectorChainID, ParticipantTypeBuilderV1,
		mustHex(t, vectorOperatorHex), mustHex(t, vectorServicePubHex), InitialServiceAuthorizationNonce)
	if err != nil {
		t.Fatal(err)
	}
	if cortex == builder {
		t.Fatal("Cortex and Builder registration digests are equal; cross-participant replay would succeed")
	}
}

// TestServiceRegistrationRejectsMalformedFields covers the inputs that would
// otherwise produce a well-formed digest the chain refuses, with nothing
// pointing at the cause. The bech32 case is the one that actually happens: the
// operator address is bech32 text everywhere else in the config and in every
// log line, and framing that text instead of the 20 raw bytes still compiles,
// still hashes, and still signs.
func TestServiceRegistrationRejectsMalformedFields(t *testing.T) {
	operator := mustHex(t, vectorOperatorHex)
	pubkey := mustHex(t, vectorServicePubHex)

	for _, test := range []struct {
		name string
		call func() error
		want string
	}{
		{
			name: "bech32 operator text instead of raw bytes",
			call: func() error {
				_, err := ServiceRegistrationDigest(vectorChainID, ParticipantTypeCortexV1,
					[]byte("trueopen15x328f9956n632d24wk2mt40kzcm9va5vw5e0a"), pubkey, InitialServiceAuthorizationNonce)
				return err
			},
			want: "20 raw address bytes",
		},
		{
			name: "uncompressed service pubkey",
			call: func() error {
				_, err := ServiceRegistrationDigest(vectorChainID, ParticipantTypeCortexV1,
					operator, make([]byte, 65), InitialServiceAuthorizationNonce)
				return err
			},
			want: "33-byte compressed",
		},
		{
			name: "unspecified participant type",
			call: func() error {
				_, err := ServiceRegistrationDigest(vectorChainID, 0, operator, pubkey, InitialServiceAuthorizationNonce)
				return err
			},
			want: "registerable identity domain",
		},
		{
			name: "zero nonce",
			call: func() error {
				_, err := ServiceRegistrationDigest(vectorChainID, ParticipantTypeCortexV1, operator, pubkey, 0)
				return err
			},
			want: "must not be zero",
		},
		{
			name: "empty chain id",
			call: func() error {
				_, err := ServiceRegistrationDigest("", ParticipantTypeCortexV1, operator, pubkey, InitialServiceAuthorizationNonce)
				return err
			},
			want: "chain_id",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want one mentioning %q", err, test.want)
			}
		})
	}
}

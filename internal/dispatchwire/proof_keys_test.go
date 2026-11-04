package dispatchwire

import (
	"encoding/json"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/wirevectors"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// previousKeyHex is a second test key standing in for a retired generation.
const previousKeyHex = "0202020202020202020202020202020202020202020202020202020202020202"

// currentKeys is a binding with one current ACTIVE generation, nonce 1.
func currentKeys(operator string, pub []byte) BuilderKeys {
	return BuilderKeys{Operator: operator, Current: pub, CurrentNonce: 1, CurrentActive: true}
}

// vectorKeys is the fixture Builder's binding as wire b30fba8 signs every
// dispatch_v1.json row: one current ACTIVE generation, nonce 1.
func vectorKeys(t *testing.T) BuilderKeys {
	t.Helper()
	row := vectorByName(t, "task_v1_dispatchticketv1")
	tk := vectorMessage(t, row).(*taskv1.DispatchTicketV1)
	return currentKeys(tk.BuilderAddress, mustHex(t, row.PublicKeyHex))
}

// The published ticket, root, revoke, input response and record notice are
// all signed by generation 1, and the three ticket-bound rows name the
// published ticket by its digest: each must verify byte for byte.
func TestProofsVerifyPublishedVectors(t *testing.T) {
	keys := vectorKeys(t)
	ticketRow := vectorByName(t, "task_v1_dispatchticketv1")
	ticket := mustHex(t, ticketRow.ProtobufHex)
	chain := vectorMessage(t, ticketRow).(*taskv1.DispatchTicketV1).ChainId
	if err := VerifyTicketProof(chain, ticket, keys, 1); err != nil {
		t.Fatalf("ticket: %v", err)
	}
	if err := VerifyRootProof(chain, mustHex(t, vectorByName(t, "task_v1_signedhandraiserootv1").ProtobufHex), keys); err != nil {
		t.Fatalf("root: %v", err)
	}
	for _, name := range []string{"nexus_v1_dispatchrevokev1", "nexus_v1_dispatchinputresponsev1", "nexus_v1_recordresultnoticev1"} {
		row := vectorByName(t, name)
		raw := mustHex(t, row.ProtobufHex)
		if err := VerifyTicketBoundProof(chain, row.MessageName, raw, ticket, keys, 1); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if nonce, has, err := SignedBuilderNonce(row.MessageName, raw); err != nil || !has || nonce != 1 {
			t.Fatalf("%s: SignedBuilderNonce = %d, %v, %v", name, nonce, has, err)
		}
		if err := VerifyTicketBoundProof("other-chain", row.MessageName, raw, ticket, keys, 1); err == nil {
			t.Fatalf("%s verified on another chain", name)
		}
	}
	ov := vectorByName(t, "nexus_v1_openverifyv1")
	want := vectorMessage(t, ov).(*nexusv1.OpenVerifyV1).GetBinding().GetServiceAuthorizationNonce()
	if nonce, has, err := SignedBuilderNonce(ov.MessageName, mustHex(t, ov.ProtobufHex)); err != nil || !has || nonce != want || want == 0 {
		t.Fatalf("OpenVerifyV1 binding nonce = %d, %v, %v; want %d", nonce, has, err, want)
	}
	if _, has, err := SignedBuilderNonce("nexus.v1.DispatchOfferV1", nil); err != nil || has {
		t.Fatalf("DispatchOfferV1 names a generation: %v, %v", has, err)
	}
}

type retainedCase struct {
	Name                  string `json:"name"`
	SignedNonce           uint64 `json:"signed_nonce"`
	TicketNonce           uint64 `json:"ticket_nonce"`
	CurrentNonce          uint64 `json:"current_nonce"`
	CurrentStatus         string `json:"current_status"`
	PreviousNonce         uint64 `json:"previous_nonce"`
	EarliestSubmitHeight  uint64 `json:"earliest_submit_height"`
	BoundChangeHeight     uint64 `json:"bound_change_height"`
	PreviousRetiredHeight uint64 `json:"previous_retired_height"`
	RevokedHeight         uint64 `json:"revoked_height"`
	Allowed               bool   `json:"allowed"`
}

type rootCase struct {
	Name         string `json:"name"`
	RootHeight   uint64 `json:"root_height"`
	CutoffHeight uint64 `json:"cutoff_height"`
	Allowed      bool   `json:"allowed"`
}

func loadRotationCases(t *testing.T) (retained []retainedCase, roots []rootCase) {
	t.Helper()
	raw, err := wirevectors.File("shared/service_key_rotation_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Retained []retainedCase `json:"retained_message_cases"`
		Roots    []rootCase     `json:"root_proof_cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Retained) == 0 || len(f.Roots) == 0 {
		t.Fatal("wire publishes no retained-message or root proof cases")
	}
	return f.Retained, f.Roots
}

// wire's retained_message_cases, replayed through this node's verifiers with
// real signatures: each generation signs with its own key, exactly as the
// Builder does before and after a cutover.
func TestRetainedMessageGenerationsFollowWireCases(t *testing.T) {
	retained, _ := loadRotationCases(t)
	base := vectorKeys(t)
	for _, c := range retained {
		t.Run(c.Name, func(t *testing.T) {
			keys := BuilderKeys{Operator: base.Operator, Current: pubKey(t, fixtureKeyHex), CurrentNonce: c.CurrentNonce,
				CurrentActive: c.CurrentStatus == "ACTIVE", RevokedHeight: c.RevokedHeight,
				Previous: pubKey(t, previousKeyHex), PreviousNonce: c.PreviousNonce, PreviousRetiredHeight: c.PreviousRetiredHeight}
			keyOf := map[uint64]string{c.CurrentNonce: fixtureKeyHex, c.PreviousNonce: previousKeyHex}
			signer := func(nonce uint64) string {
				if k, ok := keyOf[nonce]; ok {
					return k
				}
				return fixtureKeyHex // an unknown generation still signs with something
			}
			tk := vectorMessage(t, vectorByName(t, "task_v1_dispatchticketv1")).(*taskv1.DispatchTicketV1)
			tk.ServiceAuthorizationNonce, tk.BoundChangeHeight, tk.BuilderServiceSignature = c.TicketNonce, c.BoundChangeHeight, nil
			tk.BuilderServiceSignature = signDigest(t, tk, signer(c.TicketNonce))
			ticket, err := Raw(tk)
			if err != nil {
				t.Fatal(err)
			}
			th, err := Digest(tk)
			if err != nil {
				t.Fatal(err)
			}
			rv := vectorMessage(t, vectorByName(t, "nexus_v1_dispatchrevokev1")).(*nexusv1.DispatchRevokeV1)
			rv.DispatchTicketHash, rv.ServiceAuthorizationNonce, rv.BuilderServiceSignature = th[:], c.SignedNonce, nil
			rv.BuilderServiceSignature = signDigest(t, rv, signer(c.SignedNonce))
			raw, err := Raw(rv)
			if err != nil {
				t.Fatal(err)
			}
			err = VerifyTicketBoundProof(tk.ChainId, "nexus.v1.DispatchRevokeV1", raw, ticket, keys, c.EarliestSubmitHeight)
			if c.Allowed != (err == nil) {
				t.Fatalf("allowed = %v, err = %v", c.Allowed, err)
			}
			if err != nil && !errors.Is(err, ErrBuilderKeyGeneration) && !errors.Is(err, ErrBuilderSignature) {
				t.Fatalf("err = %v, want a named rejection", err)
			}
		})
	}
}

// wire's root_proof_cases: a previous-generation root proves only below its
// retirement height, by its own root_height whatever any order says.
func TestRootProofsFollowWireCases(t *testing.T) {
	_, roots := loadRotationCases(t)
	base := vectorKeys(t)
	for _, c := range roots {
		t.Run(c.Name, func(t *testing.T) {
			keys := BuilderKeys{Operator: base.Operator, Current: pubKey(t, fixtureKeyHex), CurrentNonce: 2, CurrentActive: true,
				Previous: pubKey(t, previousKeyHex), PreviousNonce: 1, PreviousRetiredHeight: c.CutoffHeight}
			root := vectorMessage(t, vectorByName(t, "task_v1_signedhandraiserootv1")).(*taskv1.SignedHandraiseRootV1)
			root.RootHeight, root.ServiceAuthorizationNonce, root.BuilderServiceSignature = c.RootHeight, 1, nil
			root.BuilderServiceSignature = signDigest(t, root, previousKeyHex)
			raw, err := Raw(root)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyRootProof(root.ChainId, raw, keys); c.Allowed != (err == nil) {
				t.Fatalf("allowed = %v, err = %v", c.Allowed, err)
			}
		})
	}
}

func TestBuilderKeysResolveOnlyKnownGenerations(t *testing.T) {
	keys := BuilderKeys{Operator: "b", Current: []byte{2}, CurrentNonce: 5, Previous: []byte{3}, PreviousNonce: 4}
	for nonce, want := range map[uint64]byte{0: 2, 5: 2, 4: 3} {
		if k, err := keys.Key(nonce); err != nil || k[0] != want {
			t.Fatalf("Key(%d) = %v, %v", nonce, k, err)
		}
	}
	for _, nonce := range []uint64{3, 6} {
		if _, err := keys.Key(nonce); !errors.Is(err, ErrBuilderKeyGeneration) {
			t.Fatalf("Key(%d) err = %v, want ErrBuilderKeyGeneration", nonce, err)
		}
	}
	keys.Previous = nil
	if _, err := keys.Key(4); !errors.Is(err, ErrBuilderKeyGeneration) {
		t.Fatalf("Key(4) without a previous generation: err = %v", err)
	}
}

func signDigest(t *testing.T, msg proto.Message, keyHex string) []byte {
	t.Helper()
	d, err := Digest(msg)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := localSigner(keyHex)(t.Context(), d)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

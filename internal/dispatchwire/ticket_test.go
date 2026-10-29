package dispatchwire

import (
	"context"
	"errors"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/wirevectors"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// otherOperator is a valid address that is not the fixture target.
const otherOperator = "trueopen13f2wj4cc90la25k5dljj4ktukp7chremmddxqv"

type epochSection struct {
	Length       uint64 `json:"epoch_length_blocks"`
	Height       uint64 `json:"earliest_submit_height"`
	Epoch        uint64 `json:"epoch"`
	Start        uint64 `json:"epoch_start_height"`
	BeaconHeight uint64 `json:"beacon_height"`
	Verified     bool   `json:"beacon_verified"`
	BeaconHex    string `json:"beacon_randomness_hex"`
	AlphaVector  string `json:"alpha_vector"`
	AlphaHex     string `json:"alpha_hex"`
	ProofHex     string `json:"vrf_proof_hex"`
}

type vrfSection struct {
	PublicKeyHex  string `json:"public_key_hex"`
	RandomnessHex string `json:"randomness_hex"`
	AlphaHex      string `json:"alpha_hex"`
}

func resignTicket(t *testing.T, tk *taskv1.DispatchTicketV1) {
	t.Helper()
	tk.BuilderServiceSignature = nil
	d, err := Digest(tk)
	if err != nil {
		t.Fatal(err)
	}
	if tk.BuilderServiceSignature, err = localSigner(fixtureKeyHex)(context.Background(), d); err != nil {
		t.Fatal(err)
	}
}

// loadTicketVector builds a ticket that is legitimate under the fixture's VRF
// and epoch sections. wire's published task_v1_dispatchticketv1 row is a
// signing-projection vector only (reference_height 1, a 4-byte placeholder
// vrf_proof), so its VRF/epoch fields are replaced by the epoch_seed_derivation
// and vrf sections -- which share its chain_id, session_id and order_sequence
// through task_v1_dispatchvrfinputv1 -- and it is re-signed with the published
// fixture Builder key.
func loadTicketVector(t *testing.T) (*taskv1.DispatchTicketV1, TicketContext) {
	t.Helper()
	var ep epochSection
	if err := wirevectors.DispatchSection("epoch_seed_derivation", &ep); err != nil {
		t.Fatal(err)
	}
	var vrf vrfSection
	if err := wirevectors.DispatchSection("vrf", &vrf); err != nil {
		t.Fatal(err)
	}
	if vrf.AlphaHex != ep.AlphaHex {
		t.Fatal("fixture vrf and epoch sections disagree on alpha")
	}
	ticketRow := vectorByName(t, "task_v1_dispatchticketv1")
	tk := vectorMessage(t, ticketRow).(*taskv1.DispatchTicketV1)
	alphaIn := vectorMessage(t, vectorByName(t, ep.AlphaVector)).(*taskv1.DispatchVrfInputV1)
	if alphaIn.ChainId != tk.ChainId || string(alphaIn.SessionId) != string(tk.SessionId) || alphaIn.OrderSequence != tk.OrderSequence {
		t.Fatal("fixture VRF input does not belong to the fixture ticket")
	}
	tk.VrfEpoch = ep.Epoch
	tk.ReferenceHeight = ep.Start
	tk.VrfProof = mustHex(t, ep.ProofHex)
	tk.VrfOutput = mustHex(t, vrf.RandomnessHex)
	resignTicket(t, tk)

	rootDigest := to32(t, vectorByName(t, "task_v1_signedhandraiserootv1").DigestHex)
	return tk, TicketContext{
		ChainID:              tk.ChainId,
		SelfOperator:         tk.Target.OperatorAddress,
		BuilderServicePubKey: mustHex(t, ticketRow.PublicKeyHex),
		BuilderVRFPubKey:     mustHex(t, vrf.PublicKeyHex),
		EpochLengthBlocks:    ep.Length,
		EarliestSubmitHeight: ep.Height,
		Beacon:               EpochBeacon{Height: ep.BeaconHeight, Randomness: mustHex(t, ep.BeaconHex), Verified: ep.Verified},
		HeldRootDigests:      map[[32]byte]bool{rootDigest: true},
	}
}

func TestPublishedTicketIsOnlyAProjectionVector(t *testing.T) {
	_, ctx := loadTicketVector(t)
	published := vectorMessage(t, vectorByName(t, "task_v1_dispatchticketv1")).(*taskv1.DispatchTicketV1)
	if err := CheckTicket(published, ctx); err == nil {
		t.Fatal("published projection ticket passed legitimacy checks; the fixture changed, revisit loadTicketVector")
	}
}

func TestCheckTicketAgainstWireVector(t *testing.T) {
	tk, ctx := loadTicketVector(t)
	if err := CheckTicket(tk, ctx); err != nil {
		t.Fatalf("vector ticket rejected: %v", err)
	}
	if _, err := dispatch.AddressBytes(otherOperator); err != nil {
		t.Fatalf("otherOperator is not a valid address: %v", err)
	}
	mutations := map[string]struct {
		mutate func(*taskv1.DispatchTicketV1)
		want   error
	}{
		"vrf":       {func(x *taskv1.DispatchTicketV1) { x.VrfOutput[0] ^= 1 }, ErrTicketVRF},
		"proof":     {func(x *taskv1.DispatchTicketV1) { x.VrfProof[0] ^= 1 }, ErrTicketVRF},
		"session":   {func(x *taskv1.DispatchTicketV1) { x.SessionId[0] ^= 1 }, ErrTicketVRF},
		"reference": {func(x *taskv1.DispatchTicketV1) { x.ReferenceHeight++ }, ErrTicketReferenceHeight},
		"target":    {func(x *taskv1.DispatchTicketV1) { x.Target.OperatorAddress = otherOperator }, ErrTicketTarget},
		"epoch":     {func(x *taskv1.DispatchTicketV1) { x.VrfEpoch++ }, ErrTicketEpoch},
		"root":      {func(x *taskv1.DispatchTicketV1) { x.HandraiseRootDigest[0] ^= 1 }, ErrTicketRoot},
		"roster":    {func(x *taskv1.DispatchTicketV1) { x.RosterHash = nil }, ErrTicketRoster},
		"scheme": {func(x *taskv1.DispatchTicketV1) {
			x.RandomnessScheme = taskv1.DispatchRandomnessSchemeV1_DISPATCH_RANDOMNESS_SCHEME_V1_UNSPECIFIED
		}, ErrTicketVRF},
	}
	for name, m := range mutations {
		// Unsigned tamper: the Builder signature catches it first.
		bad := proto.Clone(tk).(*taskv1.DispatchTicketV1)
		m.mutate(bad)
		if err := CheckTicket(bad, ctx); !errors.Is(err, ErrTicketSignature) && !errors.Is(err, m.want) {
			t.Fatalf("%s (unsigned): err = %v", name, err)
		} else if err == nil {
			t.Fatalf("%s mutation accepted", name)
		}
		// A Builder that signs the bad ticket: the named check must catch it.
		resigned := proto.Clone(tk).(*taskv1.DispatchTicketV1)
		m.mutate(resigned)
		resigned.BuilderServiceSignature = nil
		if _, err := Digest(resigned); err != nil {
			// wire's strict projection itself refuses the value, so no
			// Builder can produce a signed ticket carrying it.
			continue
		}
		resignTicket(t, resigned)
		if err := CheckTicket(resigned, ctx); !errors.Is(err, m.want) {
			t.Fatalf("%s (re-signed): err = %v, want %v", name, err, m.want)
		}
	}

	wrongChain := ctx
	wrongChain.ChainID = "other-chain"
	if err := CheckTicket(tk, wrongChain); !errors.Is(err, ErrTicketChain) {
		t.Fatalf("chain: %v", err)
	}
	unverified := ctx
	unverified.Beacon.Verified = false
	if err := CheckTicket(tk, unverified); !errors.Is(err, ErrTicketEpoch) {
		t.Fatalf("unverified beacon: %v", err)
	}
	wrongBuilder := ctx
	wrongBuilder.BuilderServicePubKey = pubKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
	if err := CheckTicket(tk, wrongBuilder); !errors.Is(err, ErrTicketSignature) {
		t.Fatalf("builder key: %v", err)
	}
	notHeld := ctx
	notHeld.HeldRootDigests = nil
	if err := CheckTicket(tk, notHeld); !errors.Is(err, ErrTicketRoot) {
		t.Fatalf("root not held: %v", err)
	}
	otherSelf := ctx
	otherSelf.SelfOperator = otherOperator
	if err := CheckTicket(tk, otherSelf); !errors.Is(err, ErrTicketTarget) {
		t.Fatalf("self operator: %v", err)
	}
}

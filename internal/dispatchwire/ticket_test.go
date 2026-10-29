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

// otherOperator is a valid address that is not the fixture Builder or target.
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

func loadEpochSection(t *testing.T) epochSection {
	t.Helper()
	var ep epochSection
	if err := wirevectors.DispatchSection("epoch_seed_derivation", &ep); err != nil {
		t.Fatal(err)
	}
	if !ep.Verified {
		t.Fatal("fixture beacon is not marked verified")
	}
	return ep
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
	ep := loadEpochSection(t)
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
		BuilderOperator:      tk.BuilderAddress,
		SelfOperator:         tk.Target.OperatorAddress,
		BuilderServicePubKey: mustHex(t, ticketRow.PublicKeyHex),
		BuilderVRFPubKey:     mustHex(t, vrf.PublicKeyHex),
		EpochLengthBlocks:    ep.Length,
		EarliestSubmitHeight: ep.Height,
		Beacon:               NewVerifiedBeacon(ep.BeaconHeight, mustHex(t, ep.BeaconHex)),
		HeldRootDigests:      map[[32]byte]bool{rootDigest: true},
	}
}

func TestPublishedTicketIsOnlyAProjectionVector(t *testing.T) {
	_, ctx := loadTicketVector(t)
	published := vectorMessage(t, vectorByName(t, "task_v1_dispatchticketv1")).(*taskv1.DispatchTicketV1)
	if err := CheckTicket(published, ctx); !errors.Is(err, ErrTicketReferenceHeight) {
		t.Fatalf("published ticket err = %v, want ErrTicketReferenceHeight; the fixture changed, revisit loadTicketVector", err)
	}
	// With only the reference height corrected, the placeholder VRF proof is
	// what fails next.
	patched := proto.Clone(published).(*taskv1.DispatchTicketV1)
	patched.ReferenceHeight = loadEpochSection(t).Start
	resignTicket(t, patched)
	if err := CheckTicket(patched, ctx); !errors.Is(err, ErrTicketVRF) {
		t.Fatalf("reference-patched ticket err = %v, want ErrTicketVRF", err)
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
		// projectionRejects: wire's signing projection refuses the mutated
		// value, so no Builder can sign it at all.
		projectionRejects bool
	}{
		"vrf":       {mutate: func(x *taskv1.DispatchTicketV1) { x.VrfOutput[0] ^= 1 }, want: ErrTicketVRF},
		"proof":     {mutate: func(x *taskv1.DispatchTicketV1) { x.VrfProof[0] ^= 1 }, want: ErrTicketVRF},
		"session":   {mutate: func(x *taskv1.DispatchTicketV1) { x.SessionId[0] ^= 1 }, want: ErrTicketVRF},
		"reference": {mutate: func(x *taskv1.DispatchTicketV1) { x.ReferenceHeight++ }, want: ErrTicketReferenceHeight},
		"target":    {mutate: func(x *taskv1.DispatchTicketV1) { x.Target.OperatorAddress = otherOperator }, want: ErrTicketTarget},
		"epoch":     {mutate: func(x *taskv1.DispatchTicketV1) { x.VrfEpoch++ }, want: ErrTicketEpoch},
		"root":      {mutate: func(x *taskv1.DispatchTicketV1) { x.HandraiseRootDigest[0] ^= 1 }, want: ErrTicketRoot},
		"scheme": {mutate: func(x *taskv1.DispatchTicketV1) {
			x.RandomnessScheme = taskv1.DispatchRandomnessSchemeV1_DISPATCH_RANDOMNESS_SCHEME_V1_UNSPECIFIED
		}, want: ErrTicketVRF},
		"short root": {mutate: func(x *taskv1.DispatchTicketV1) {
			x.HandraiseRootDigest = x.HandraiseRootDigest[:31]
		}, projectionRejects: true},
	}
	for name, m := range mutations {
		t.Run(name, func(t *testing.T) {
			// Unsigned tamper: the Builder signature catches it.
			bad := proto.Clone(tk).(*taskv1.DispatchTicketV1)
			m.mutate(bad)
			if err := CheckTicket(bad, ctx); !errors.Is(err, ErrTicketSignature) {
				t.Fatalf("unsigned: err = %v, want ErrTicketSignature", err)
			}
			// A Builder that signs the bad ticket: the named check must catch it.
			resigned := proto.Clone(tk).(*taskv1.DispatchTicketV1)
			m.mutate(resigned)
			resigned.BuilderServiceSignature = nil
			_, err := Digest(resigned)
			if m.projectionRejects {
				if !errors.Is(err, dispatch.ErrDecode) {
					t.Fatalf("projection err = %v, want dispatch.ErrDecode", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("projection refused the mutation: %v", err)
			}
			resignTicket(t, resigned)
			if err := CheckTicket(resigned, ctx); !errors.Is(err, m.want) {
				t.Fatalf("re-signed: err = %v, want %v", err, m.want)
			}
		})
	}
}

// A ticket without a raw32 roster_hash cannot be signed: wire's projection
// refuses it, and CheckTicket reports that as a signature failure.
func TestCheckTicketMissingRosterIsUnsignable(t *testing.T) {
	tk, ctx := loadTicketVector(t)
	tk.RosterHash = nil
	err := CheckTicket(tk, ctx)
	if !errors.Is(err, ErrTicketSignature) || !errors.Is(err, dispatch.ErrDecode) {
		t.Fatalf("err = %v, want ErrTicketSignature wrapping dispatch.ErrDecode", err)
	}
}

// The ticket must name the stream's Builder; a Builder signing a ticket in
// another Builder's name is caught whether or not it re-signs.
func TestCheckTicketBindsStreamBuilder(t *testing.T) {
	tk, ctx := loadTicketVector(t)
	foreign := proto.Clone(tk).(*taskv1.DispatchTicketV1)
	foreign.BuilderAddress = otherOperator
	if err := CheckTicket(foreign, ctx); !errors.Is(err, ErrTicketBuilder) {
		t.Fatalf("unsigned: err = %v, want ErrTicketBuilder", err)
	}
	resignTicket(t, foreign)
	if err := CheckTicket(foreign, ctx); !errors.Is(err, ErrTicketBuilder) {
		t.Fatalf("re-signed: err = %v, want ErrTicketBuilder", err)
	}
	otherStream := ctx
	otherStream.BuilderOperator = otherOperator
	if err := CheckTicket(tk, otherStream); !errors.Is(err, ErrTicketBuilder) {
		t.Fatalf("other stream Builder: err = %v", err)
	}
}

func TestCheckTicketContextMismatches(t *testing.T) {
	tk, ctx := loadTicketVector(t)
	for name, c := range map[string]struct {
		edit func(*TicketContext)
		want error
	}{
		"chain":      {func(c *TicketContext) { c.ChainID = "other-chain" }, ErrTicketChain},
		"unverified": {func(c *TicketContext) { c.Beacon = EpochBeacon{} }, ErrTicketEpoch},
		"builder key": {func(c *TicketContext) {
			c.BuilderServicePubKey = pubKey(t, "1111111111111111111111111111111111111111111111111111111111111111")
		}, ErrTicketSignature},
		"root not held": {func(c *TicketContext) { c.HeldRootDigests = nil }, ErrTicketRoot},
		"self operator": {func(c *TicketContext) { c.SelfOperator = otherOperator }, ErrTicketTarget},
		"vrf key":       {func(c *TicketContext) { c.BuilderVRFPubKey = make([]byte, 32) }, ErrTicketVRF},
	} {
		t.Run(name, func(t *testing.T) {
			edited := ctx
			c.edit(&edited)
			if err := CheckTicket(tk, edited); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

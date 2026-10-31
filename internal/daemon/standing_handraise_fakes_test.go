package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/dispatchstream"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/signer"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// Addresses are real bech32 strings from wire's p1 vectors, so wire's strict
// decoder accepts every message built from them.
const (
	hrChainID    = "trueopen-phase1-test-1"
	hrCortex     = "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"
	hrBuilderA   = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"
	hrBuilderB   = "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man"
	hrCortexKey  = "1111111111111111111111111111111111111111111111111111111111111111"
	hrBuilderKey = "2222222222222222222222222222222222222222222222222222222222222222"
)

var (
	hrModelAB = strings.Repeat("ab", 32)
	hrModelCD = strings.Repeat("cd", 32)
)

func hrPub(t testing.TB, keyHex string) []byte {
	t.Helper()
	k, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	return secp256k1.PrivKeyFromBytes(k).PubKey().SerializeCompressed()
}

func hrSigner(keyHex string) dispatchwire.DigestSigner {
	return func(_ context.Context, d [32]byte) ([]byte, error) {
		return signer.SignDigestWithPrivateKeyHex(keyHex, codec.Hash(d))
	}
}

func hrProfile(modelHex string, version uint32) HandraiseProfile {
	var p HandraiseProfile
	raw, _ := hex.DecodeString(modelHex)
	copy(p.ModelID[:], raw)
	p.Version = version
	return p
}

// hrProfileRefs is deliberately unsorted.
func hrProfileRefs() []config.ModelProfileRef {
	return []config.ModelProfileRef{
		{ModelID: hrModelCD, ProfileVersion: 1, Capability: "c"},
		{ModelID: hrModelAB, ProfileVersion: 2, Capability: "c"},
		{ModelID: hrModelAB, ProfileVersion: 1, Capability: "c"},
	}
}

func hrBids() map[string]uint64 {
	return map[string]uint64{
		config.MinPriceBidKey(hrModelAB, 1): 5,
		config.MinPriceBidKey(hrModelAB, 2): 5,
		config.MinPriceBidKey(hrModelCD, 1): 5,
	}
}

func freshScope(modelHex string, version uint32) chainclient.CommittedModelSupportScope {
	return chainclient.CommittedModelSupportScope{
		Height: 1_000, EpochLengthBlocks: 100, SupportWindowEpochs: 3,
		Profile: chainclient.CurrentModelProfileSnapshot{
			Model: chainclient.CurrentModelSnapshot{ModelID: modelHex, Status: "ACTIVE"},
			Profile: chainclient.CurrentProfileSnapshot{
				ModelID: modelHex, ProfileVersion: chainclient.ProfileVersion(strconv.FormatUint(uint64(version), 10)),
				Status: "ACTIVE", MinStake: 100,
			},
		},
		Capability: chainclient.ModelCapabilitySnapshot{OperatorAddress: hrCortex, ModelID: modelHex, InferenceCapability: true, CapabilityVersion: 1},
		Support: chainclient.ModelSupportSnapshot{
			OperatorAddress: hrCortex, ModelID: modelHex, DeclaredSupport: true, SupportActive: true,
			SupportFreshUntilEpoch: 20, SupportVersion: 1,
		},
	}
}

type fakeHandraiseChain struct {
	mu            sync.Mutex
	height        uint64
	node          chainclient.CortexNodeSnapshot
	nodeErr       error
	bond          chainclient.ServiceBondSnapshot
	cortexKey     chainclient.ServiceKeySnapshot
	cortexKeyErr  error
	builderKeys   map[string]chainclient.ServiceKeySnapshot
	builderKeyErr error
	member        chainclient.CandidateMemberRefSnapshot
	scopes        map[string]chainclient.CommittedModelSupportScope
	scopeErr      error
	scopeErrFor   map[string]error // by MinPriceBidKey
	vrfErr        map[string]error
	// gateCalls counts the gate's chain reads (everything but
	// CommittedHeight and the root path's Builder key); readHeights records
	// the heights the pinned ones were issued at.
	gateCalls   int
	readHeights map[uint64]bool
	unpinned    int // gate reads not pinned to a height
	// hangHeight makes CommittedHeight block until its context ends.
	hangHeight bool
}

func newFakeHandraiseChain(t testing.TB) *fakeHandraiseChain {
	keys := map[string]chainclient.ServiceKeySnapshot{}
	for _, b := range []string{hrBuilderA, hrBuilderB} {
		keys[b] = chainclient.ServiceKeySnapshot{
			ParticipantType: chainclient.ParticipantTypeBuilder, OperatorAddress: b,
			ServicePubkey: hex.EncodeToString(hrPub(t, hrBuilderKey)), AuthorizationNonce: 1, Status: "ACTIVE",
		}
	}
	return &fakeHandraiseChain{
		height: 100,
		node:   chainclient.CortexNodeSnapshot{OperatorAddress: hrCortex, Status: "ACTIVE"},
		bond:   chainclient.ServiceBondSnapshot{OperatorAddress: hrCortex, Status: "ACTIVE", ActiveBond: 1_000, BondVersion: 1},
		cortexKey: chainclient.ServiceKeySnapshot{
			ParticipantType: chainclient.ParticipantTypeCortexNode, OperatorAddress: hrCortex,
			ServicePubkey: hex.EncodeToString(hrPub(t, hrCortexKey)), AuthorizationNonce: 7, Status: "ACTIVE",
		},
		builderKeys: keys,
		member: chainclient.CandidateMemberRefSnapshot{
			CandidatePoolSnapshotID: chainclient.ProtoBytes32(bytes.Repeat([]byte{0x5a}, 32)),
			Slot:                    4, SlotVersion: 2, OperatorAddress: hrCortex,
		},
		scopes: map[string]chainclient.CommittedModelSupportScope{
			config.MinPriceBidKey(hrModelAB, 1): freshScope(hrModelAB, 1),
			config.MinPriceBidKey(hrModelAB, 2): freshScope(hrModelAB, 2),
			config.MinPriceBidKey(hrModelCD, 1): freshScope(hrModelCD, 1),
		},
		scopeErrFor: map[string]error{}, vrfErr: map[string]error{}, readHeights: map[uint64]bool{},
	}
}

// gateRead counts one gate read; the caller holds f.mu.
func (f *fakeHandraiseChain) gateRead(height uint64) {
	f.gateCalls++
	if height == 0 {
		f.unpinned++
		return
	}
	f.readHeights[height] = true
}

func (f *fakeHandraiseChain) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gateCalls
}

func (f *fakeHandraiseChain) with(fn func(*fakeHandraiseChain)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeHandraiseChain) CommittedHeight(ctx context.Context) (uint64, error) {
	f.mu.Lock()
	hang, height := f.hangHeight, f.height
	f.mu.Unlock()
	if hang {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	return height, nil
}

func (f *fakeHandraiseChain) CortexNodeAt(_ context.Context, _ string, height uint64) (chainclient.CortexNodeSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gateRead(height)
	return f.node, f.nodeErr
}

func (f *fakeHandraiseChain) ServiceBondAt(_ context.Context, _ string, height uint64) (chainclient.ServiceBondSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gateRead(height)
	return f.bond, nil
}

func (f *fakeHandraiseChain) CurrentServiceKey(_ context.Context, participant, _ string, height uint64) (chainclient.ServiceKeySnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gateRead(height)
	if participant != chainclient.ParticipantTypeCortexNode {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("gate read a %s key", participant)
	}
	return f.cortexKey, f.cortexKeyErr
}

// CommittedCurrentServiceKey serves the root path's Builder key reads.
func (f *fakeHandraiseChain) CommittedCurrentServiceKey(_ context.Context, participant, operator string) (chainclient.ServiceKeySnapshot, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if participant != chainclient.ParticipantTypeBuilder {
		return chainclient.ServiceKeySnapshot{}, 0, fmt.Errorf("root path read a %s key", participant)
	}
	if f.builderKeyErr != nil {
		return chainclient.ServiceKeySnapshot{}, 0, f.builderKeyErr
	}
	k, ok := f.builderKeys[operator]
	if !ok {
		return chainclient.ServiceKeySnapshot{}, 0, fmt.Errorf("no Builder %s", operator)
	}
	return k, f.height, nil
}

func (f *fakeHandraiseChain) CurrentCandidateMemberAt(_ context.Context, _ string, height uint64) (chainclient.CandidateMemberRefSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gateRead(height)
	return f.member, nil
}

func (f *fakeHandraiseChain) ModelSupportScopeAt(_ context.Context, _, modelID, version string, height uint64) (chainclient.CommittedModelSupportScope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gateRead(height)
	if f.scopeErr != nil {
		return chainclient.CommittedModelSupportScope{}, f.scopeErr
	}
	v, err := strconv.ParseUint(version, 10, 32)
	if err != nil {
		return chainclient.CommittedModelSupportScope{}, err
	}
	key := config.MinPriceBidKey(modelID, uint32(v))
	if err := f.scopeErrFor[key]; err != nil {
		return chainclient.CommittedModelSupportScope{}, err
	}
	s, ok := f.scopes[key]
	if !ok {
		return chainclient.CommittedModelSupportScope{}, fmt.Errorf("no support scope for %s@%s: %w", modelID, version, chainclient.ErrNotFound)
	}
	return s, nil
}

func (f *fakeHandraiseChain) BuilderVrfKeyAt(_ context.Context, builder string, height uint64) (chainclient.VrfKeySnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gateRead(height)
	if err := f.vrfErr[builder]; err != nil {
		return chainclient.VrfKeySnapshot{}, err
	}
	return chainclient.VrfKeySnapshot{ActivePubkey: bytes.Repeat([]byte{9}, 32)}, nil
}

type fakeHandraiseLocal struct {
	mu            sync.Mutex
	ready         bool
	drain         bool
	drainProfiles map[HandraiseProfile]bool
	free          uint32
	freeOK        bool
}

func (l *fakeHandraiseLocal) with(fn func(*fakeHandraiseLocal)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fn(l)
}

func (l *fakeHandraiseLocal) WorkloadReady(context.Context) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ready
}

func (l *fakeHandraiseLocal) Draining() (bool, map[HandraiseProfile]bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.drain, maps.Clone(l.drainProfiles)
}

func (l *fakeHandraiseLocal) FreeSlots(context.Context) (uint32, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.free, l.freeOK
}

// fakeEnqueuer stands in for dispatchstream.Session; it applies wire's strict
// decoder the way Session.Enqueue does.
type fakeEnqueuer struct {
	mu    sync.Mutex
	sent  []dispatchstream.Outgoing
	fail  error
	tries int
	// during runs inside Enqueue, before it returns; optional.
	during func()
}

func (f *fakeEnqueuer) Enqueue(_ context.Context, p dispatchstream.Outgoing) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tries++
	if f.during != nil {
		f.during()
	}
	if f.fail != nil {
		return 0, f.fail
	}
	raw, err := dispatchwire.Raw(p.Message)
	if err != nil {
		return 0, err
	}
	if err := dispatch.ValidateMessage(dispatchwire.Name(p.Message), raw); err != nil {
		return 0, err
	}
	f.sent = append(f.sent, p)
	return uint64(len(f.sent)), nil
}

func (f *fakeEnqueuer) setFail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = err
}

func (f *fakeEnqueuer) handraises() []*taskv1.StandingHandraiseV1 {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*taskv1.StandingHandraiseV1
	for _, p := range f.sent {
		out = append(out, p.Message.(*taskv1.StandingHandraiseV1))
	}
	return out
}

func (f *fakeEnqueuer) outgoing(i int) dispatchstream.Outgoing {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sent[i]
}

func hrEventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

package daemon

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/txclient"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

func (x *omFixture) setHeight(h uint64) {
	x.chain.mu.Lock()
	x.chain.height = h
	x.chain.mu.Unlock()
}

func (x *omFixture) putChallenge(id [32]byte, s chainclient.DispatchChallengeSnapshot) {
	x.chain.mu.Lock()
	defer x.chain.mu.Unlock()
	s.ChallengeID, s.TaskID = id[:], omTask[:]
	if s.Challenger == "" {
		s.Challenger = omService
	}
	x.chain.challenges[id] = s
}

func (x *omFixture) setRoster(builder string, r *nexusv1.GetDispatchRosterResponse) {
	x.rosters.mu.Lock()
	defer x.rosters.mu.Unlock()
	if r == nil {
		delete(x.rosters.resp, builder)
		return
	}
	x.rosters.resp[builder] = r
}

func omissionID(t *testing.T, round uint32) [32]byte {
	t.Helper()
	id, err := dispatchwire.OmissionChallengeID(dpChainID, omTask, round, hrCortex, omService)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSignerOutageIsNeverARosterMiss(t *testing.T) {
	x := newOmission(t, omLeaf(2, 250, "m"))
	cfg := x.w.cfg
	cfg.Sign = func(context.Context, [32]byte) ([]byte, error) { return nil, errors.New("signer unavailable") }
	w, err := NewOmissionWatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	x.w = w
	x.observe()
	for h := uint64(201); h <= 215; h++ {
		x.setHeight(h)
		if err := x.w.Sweep(context.Background()); err == nil {
			t.Fatal("a signer outage is reported as an error")
		}
	}
	if c := x.state(); c.RosterMissSince != 0 || c.State != layout.OmissionPending || len(x.tx.requests()) != 0 || len(x.rosters.askedBuilders()) != 0 {
		t.Fatalf("a signer outage is never a roster miss and never a report: %+v", c)
	}
}

func TestDismissedReportThenAnOmittingRosterIsChallenged(t *testing.T) {
	ctx := context.Background()
	x := newOmission(t, omLeaf(2, 250, "m"))
	resp := x.rosters.resp[hrBuilderA]
	x.setRoster(hrBuilderA, nil)
	x.tx.setLand(nil)
	x.observe()
	x.sweepAt(201)
	x.sweepAt(205)
	report, _ := dispatchwire.RosterUnavailableChallengeID(dpChainID, omTask, 0, omService)
	if c := x.state(); c.State != layout.OmissionReported {
		t.Fatalf("case = %+v", c)
	}
	dismissed := taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_DISMISSED
	x.putChallenge(report, chainclient.DispatchChallengeSnapshot{Status: dismissed})
	if err := x.w.ObserveDispatchEvent(ctx, DispatchEventFact{Type: chainclient.KeeperEventDispatchChallengeResolved, Height: 206, TaskID: omTask,
		ChallengeID: layout.StoredHash(report), Kind: sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_ROSTER_UNAVAILABLE}); err != nil {
		t.Fatal(err)
	}
	if c := x.state(); c.State != layout.OmissionReported || c.ReportOutcome != int32(dismissed) {
		t.Fatalf("a dismissed report keeps the case open: %+v", c)
	}
	x.setRoster(hrBuilderA, resp) // the Builder answered with a roster that leaves this node out
	x.sweepAt(207)
	reqs := x.tx.requests()
	if len(reqs) != 2 || reqs[1].Kind != txclient.MsgChallengeDispatchOmission {
		t.Fatalf("requests = %+v", reqs)
	}
	if c := x.state(); c.State != layout.OmissionChallenged || c.ChallengeID != layout.StoredHash(omissionID(t, 0)) {
		t.Fatalf("case = %+v", c)
	}

	y := newOmission(t, omLeaf(2, 250, "m"))
	y.setRoster(hrBuilderA, nil)
	y.tx.setLand(nil)
	y.observe()
	y.sweepAt(201)
	y.sweepAt(205)
	y.putChallenge(report, chainclient.DispatchChallengeSnapshot{Status: dismissed})
	y.sweepAt(206)
	if c := y.state(); c.State != layout.OmissionReported || c.ReportOutcome != int32(dismissed) {
		t.Fatalf("the sweep reads the dismissal too: %+v", c)
	}
	y.sweepAt(227)
	if c := y.state(); c.State != layout.OmissionResolved || c.Outcome != int32(dismissed) || len(y.tx.requests()) != 1 {
		t.Fatalf("no roster before the window closed: resolved with the report's outcome, reported once: %+v", c)
	}
}

func TestStuckCasesDoNotStarveANewOne(t *testing.T) {
	ctx := context.Background()
	x := newOmission(t, omLeaf(2, 250, "m"))
	x.chain.records = map[[32]byte]chainclient.DispatchRecordSnapshot{}
	var stuck []layout.StoredHash
	for i := range 9 { // older than omTask; no Builder ever serves their roster
		task, session := layout.StoredHash(bytes.Repeat([]byte{byte(0x10 + i)}, 32)), layout.StoredHash(bytes.Repeat([]byte{byte(0x40 + i)}, 32))
		rec := x.chain.record
		rec.TaskID, rec.RecordedHeight = task[:], 190+uint64(i)
		rec.Rounds = []chainclient.DispatchRoundSnapshot{{Round: 0, HandraiseRootDigest: rec.Rounds[0].HandraiseRootDigest, RosterHash: bytes.Repeat([]byte{0xee}, 32)}}
		x.chain.records[session] = rec
		if _, err := layout.PutOmissionCase(ctx, x.st, layout.OmissionCase{TaskID: task, SessionID: session, OrderSequence: 7, Builder: hrBuilderA,
			RecordHash: omRecordHash, RecordedHeight: rec.RecordedHeight}); err != nil {
			t.Fatal(err)
		}
		stuck = append(stuck, task)
	}
	x.observe()
	x.sweepAt(201)
	examined := 0
	for _, task := range stuck {
		c, err := layout.GetOmissionCase(ctx, x.st, task)
		if err != nil {
			t.Fatal(err)
		}
		if c.RosterMissSince != 0 {
			examined++
		}
	}
	if examined != 8 || len(x.tx.requests()) != 0 {
		t.Fatalf("ChecksPerSweep caps a sweep at 8: %d examined, %d requests", examined, len(x.tx.requests()))
	}
	x.sweepAt(202)
	if reqs := x.tx.requests(); len(reqs) != 1 || reqs[0].Kind != txclient.MsgChallengeDispatchOmission || x.state().State != layout.OmissionResolved {
		t.Fatalf("the stuck cases back off and the new case is examined: %+v", reqs)
	}
}

func TestEvidenceSlotFromTheDrawnPool(t *testing.T) {
	leaf := omLeaf(2, 250, "m")
	leaf.Handraise.Member.CandidatePoolSnapshotId = bytes.Repeat([]byte{0x55}, 32) // signed against another pool snapshot
	x := newOmission(t, leaf)
	x.chain.pool = map[string]chainclient.CandidateMemberRefSnapshot{strings.Repeat("66", 32): {Slot: 5, SlotVersion: 1, OperatorAddress: hrCortex}}
	x.observe()
	x.sweepAt(201)
	reqs := x.tx.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %+v", reqs)
	}
	if p := omChallenge(t, reqs[0]).GetNonInclusionProof(); p.GetPredecessor().GetSlot() != 1 || p.GetSuccessor().GetSlot() != 7 {
		t.Fatalf("proof around the drawn pool's slot 5: %v", p)
	}

	y := newOmission(t, proto.Clone(leaf).(*taskv1.HandraiseRootLeafV1))
	y.observe()
	y.sweepAt(201)
	if c := y.state(); c.State != layout.OmissionClear || len(y.tx.requests()) != 0 {
		t.Fatalf("not in the pool the draw used: clear, %+v", c)
	}
}

func TestMismatchingRostersFallBackToTheNextBuilder(t *testing.T) {
	for name, spoil := range map[string]func(x *omFixture, r *nexusv1.DispatchRosterRoundV1){
		"roster hash": func(_ *omFixture, r *nexusv1.DispatchRosterRoundV1) { r.Roster.Members = r.Roster.Members[:1] },
		"bound root": func(x *omFixture, r *nexusv1.DispatchRosterRoundV1) {
			_, other := omRoot(x.t, 181, 1, omLeaf(2, 250, "m"))
			r.HandraiseRoot = other
		},
	} {
		x := newOmission(t, omLeaf(2, 250, "m"))
		good := x.rosters.resp[hrBuilderA]
		bad := proto.Clone(good).(*nexusv1.GetDispatchRosterResponse)
		spoil(x, bad.Rounds[0])
		x.setRoster(hrBuilderA, bad)
		x.setRoster(hrBuilderB, good)
		x.observe()
		x.sweepAt(201)
		reqs := x.tx.requests()
		if asked := x.rosters.askedBuilders(); len(asked) != 2 || asked[0] != hrBuilderA || asked[1] != hrBuilderB || len(reqs) != 1 {
			t.Fatalf("%s: asked %v, requests %d", name, asked, len(reqs))
		}
		if m := omChallenge(t, reqs[0]); !proto.Equal(m.GetRoster(), x.roster) || !proto.Equal(m.GetHandraiseRoot(), x.bound) {
			t.Fatalf("%s: the challenge carries the roster that matches the record", name)
		}
	}
}

func TestChallengeLandedButLostIsTakenUpOnResubmit(t *testing.T) {
	ctx := context.Background()
	x := newOmission(t, omLeaf(2, 250, "m"))
	awaiting := taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_AWAITING_PROOF
	x.tx.setLand(func(r txclient.Request) {
		x.putChallenge([32]byte(r.MaterialDigest), chainclient.DispatchChallengeSnapshot{Status: awaiting})
	})
	x.tx.mu.Lock()
	x.tx.lost = true
	x.tx.mu.Unlock()
	x.observe()
	x.setHeight(201)
	if err := x.w.Sweep(ctx); err == nil {
		t.Fatal("a lost Tx result is an error")
	}
	if c := x.state(); c.State != layout.OmissionPending {
		t.Fatalf("the case was not updated: %+v", c)
	}
	x.tx.mu.Lock()
	x.tx.lost, x.tx.land, x.tx.reject = false, nil, "ERR_CHALLENGE_DUPLICATE"
	x.tx.mu.Unlock()
	x.sweepAt(202)
	id := omissionID(t, 0)
	if c := x.state(); c.State != layout.OmissionChallenged || c.ChallengeID != layout.StoredHash(id) || len(x.tx.requests()) != 2 {
		t.Fatalf("the resubmit finds its own landed challenge: %+v", c)
	}
	x.putChallenge(id, chainclient.DispatchChallengeSnapshot{Status: omUpheld})
	if err := x.w.ObserveDispatchEvent(ctx, DispatchEventFact{Type: chainclient.KeeperEventDispatchChallengeResolved, Height: 203, TaskID: omTask,
		ChallengeID: layout.StoredHash(id), Kind: sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_OMISSION}); err != nil {
		t.Fatal(err)
	}
	if c := x.state(); c.State != layout.OmissionResolved || c.Outcome != int32(omUpheld) {
		t.Fatalf("case = %+v", c)
	}
}

func TestChallengeConflictIsAbandoned(t *testing.T) {
	x := newOmission(t, omLeaf(2, 250, "m"))
	x.tx.setLand(func(r txclient.Request) {
		x.putChallenge([32]byte(r.MaterialDigest), chainclient.DispatchChallengeSnapshot{Status: omUpheld, Challenger: omLow})
	})
	x.observe()
	x.sweepAt(201)
	if c := x.state(); c.State != layout.OmissionAbandoned || !strings.Contains(c.Reason, "ChainObservationConflict") {
		t.Fatalf("case = %+v", c)
	}
}

func TestProofDeadlineBoundsTheChallenge(t *testing.T) {
	x := newOmission(t, omLeaf(2, 250, "m"))
	awaiting := taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_AWAITING_PROOF
	x.tx.setLand(func(r txclient.Request) {
		x.putChallenge([32]byte(r.MaterialDigest), chainclient.DispatchChallengeSnapshot{Status: awaiting, ProofDeadlineHeight: 210})
	})
	x.observe()
	x.sweepAt(201)
	x.sweepAt(211)
	if c := x.state(); c.State != layout.OmissionChallenged {
		t.Fatalf("followed until proof deadline + RecheckBlocks: %+v", c)
	}
	x.sweepAt(221)
	if c := x.state(); c.State != layout.OmissionAbandoned {
		t.Fatalf("case = %+v", c)
	}
}

func TestRecordLagBacksOffWithoutASweepError(t *testing.T) {
	x := newOmission(t, omLeaf(2, 250, "m"))
	x.chain.recordErr = chainclient.ErrNotFound
	x.observe()
	x.sweepAt(201)
	if c := x.state(); c.NextCheckHeight != 203 || c.State != layout.OmissionPending {
		t.Fatalf("case = %+v", c)
	}
	x.chain.mu.Lock()
	x.chain.recordErr = nil
	x.chain.mu.Unlock()
	x.sweepAt(202)
	if len(x.tx.requests()) != 0 {
		t.Fatal("backed off")
	}
	x.sweepAt(203)
	if len(x.tx.requests()) != 1 {
		t.Fatal("examined once the chain shows the record")
	}
}

func TestAnotherOperatorsLeafIsNotEvidence(t *testing.T) {
	leaf := omLeaf(2, 250, "m")
	leaf.Handraise.Member.OperatorAddress = omLow
	x := newOmission(t, leaf)
	x.observe()
	if _, err := layout.GetOmissionCase(context.Background(), x.st, omTask); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("only this node's own leaf opens a case")
	}
}

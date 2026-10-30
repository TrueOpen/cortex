package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/txclient"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
)

func TestRosterUnavailableIsReportedThenResolved(t *testing.T) {
	ctx := context.Background()
	x := newOmission(t, omLeaf(2, 250, "m"))
	delete(x.rosters.resp, hrBuilderA)
	x.tx.setLand(nil) // a report opens AWAITING_ROSTER; the test resolves it
	x.observe()
	x.sweepAt(201)
	x.sweepAt(204)
	if len(x.tx.requests()) != 0 || x.state().RosterMissSince != 201 {
		t.Fatalf("within RosterGraceBlocks nothing is reported: %+v", x.state())
	}
	if asked := x.rosters.askedBuilders(); len(asked) < 2 || asked[0] != hrBuilderA || asked[1] != hrBuilderB {
		t.Fatalf("asked %v: dispatching Builder first, then the others", asked)
	}
	x.sweepAt(205)
	reqs := x.tx.requests()
	if len(reqs) != 1 || reqs[0].Kind != txclient.MsgReportDispatchRosterUnavailable || reqs[0].DeadlineHeight != 230 {
		t.Fatalf("requests = %+v", reqs)
	}
	id, _ := dispatchwire.RosterUnavailableChallengeID(dpChainID, omTask, 0, omService)
	if c := x.state(); c.State != layout.OmissionReported || c.ReportID != layout.StoredHash(id) || reqs[0].MaterialDigest != [32]byte(id) {
		t.Fatalf("case = %+v", c)
	}
	x.sweepAt(206)
	if n := len(x.tx.requests()); n != 1 {
		t.Fatalf("reported once: %d requests", n)
	}
	x.chain.mu.Lock()
	x.chain.challenges[id] = chainclient.DispatchChallengeSnapshot{ChallengeID: id[:], TaskID: omTask[:], Challenger: omService, Status: omUpheld}
	x.chain.mu.Unlock()
	f := DispatchEventFact{Type: chainclient.KeeperEventDispatchChallengeResolved, Height: 230, TaskID: omTask, ChallengeID: layout.StoredHash(id),
		Kind: sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_ROSTER_UNAVAILABLE}
	if err := x.w.ObserveDispatchEvent(ctx, f); err != nil {
		t.Fatal(err)
	}
	if err := x.w.ObserveDispatchEvent(ctx, f); err != nil {
		t.Fatal("a redelivered event is a no-op")
	}
	until := x.state().RetainUntil
	if c := x.state(); c.State != layout.OmissionResolved || until != 230+5+40 {
		t.Fatalf("case = %+v", c)
	}
	x.sweepAt(until - 1)
	if _, err := layout.GetOmissionCase(ctx, x.st, omTask); err != nil {
		t.Fatal("kept until RetainUntil")
	}
	x.sweepAt(until)
	if _, err := layout.GetOmissionCase(ctx, x.st, omTask); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("collected")
	}
}

func TestOmissionFoundAfterTheReportIsStillChallenged(t *testing.T) {
	x := newOmission(t, omLeaf(2, 250, "m"))
	resp := x.rosters.resp[hrBuilderA]
	delete(x.rosters.resp, hrBuilderA)
	x.tx.setLand(nil)
	x.observe()
	x.sweepAt(201)
	x.sweepAt(205)
	if c := x.state(); c.State != layout.OmissionReported {
		t.Fatalf("case = %+v", c)
	}
	x.rosters.mu.Lock()
	x.rosters.resp[hrBuilderB] = resp // another configured Builder serves the roster
	x.rosters.mu.Unlock()
	x.sweepAt(206)
	reqs := x.tx.requests()
	if len(reqs) != 2 || reqs[1].Kind != txclient.MsgChallengeDispatchOmission {
		t.Fatalf("requests = %+v", reqs)
	}
	if c := x.state(); c.State != layout.OmissionChallenged || c.ChallengeID.IsZero() || c.ReportID.IsZero() {
		t.Fatalf("case = %+v", c)
	}
	x.sweepAt(235) // window 230 + response 5: the challenge was never seen resolved
	if c := x.state(); c.State != layout.OmissionAbandoned {
		t.Fatalf("an unresolved challenge is not followed forever: %+v", c)
	}
}

func TestChallengeEventsForOtherChallengesAreIgnored(t *testing.T) {
	x := newOmission(t, omLeaf(2, 250, "m"))
	x.tx.setLand(nil)
	x.observe()
	x.sweepAt(201)
	f := DispatchEventFact{Type: chainclient.KeeperEventDispatchChallengeOpened, Height: 202, TaskID: omTask, ChallengeID: layout.StoredHash{9},
		Kind: sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_OMISSION}
	if err := x.w.ObserveDispatchEvent(context.Background(), f); err != nil || x.state().State != layout.OmissionChallenged {
		t.Fatalf("another challenge of the task: %v, %+v", err, x.state())
	}
	f.TaskID = layout.StoredHash{8}
	if err := x.w.ObserveDispatchEvent(context.Background(), f); err != nil {
		t.Fatal("a task without a case is ignored")
	}
}

type fanoutEvents struct {
	events  []DispatchEventFact
	records []DispatchRecordedFact
	err     error
}

func (o *fanoutEvents) ObserveDispatchEvent(_ context.Context, f DispatchEventFact) error {
	o.events = append(o.events, f)
	return o.err
}

func (o *fanoutEvents) ObserveDispatchRecorded(_ context.Context, f DispatchRecordedFact) error {
	o.records = append(o.records, f)
	return o.err
}

func TestEventFanOutJoinsRetryability(t *testing.T) {
	ctx := context.Background()
	lag := &fanoutEvents{err: builderclient.Retryable(errors.New("lag"))}
	ok := &fanoutEvents{}
	if err := (DispatchEventObservers{lag, ok}).ObserveDispatchEvent(ctx, DispatchEventFact{}); !builderclient.IsRetryable(err) || len(ok.events) != 1 {
		t.Fatalf("every observer sees the event; any lag retries: %v", err)
	}
	if err := (DispatchRecordObservers{lag, ok}).ObserveDispatchRecorded(ctx, DispatchRecordedFact{}); !builderclient.IsRetryable(err) || len(ok.records) != 1 {
		t.Fatalf("every observer sees the record; any lag retries: %v", err)
	}
	bad := &fanoutEvents{err: errors.New("refused")}
	if err := (DispatchRecordObservers{bad, ok}).ObserveDispatchRecorded(ctx, DispatchRecordedFact{}); err == nil || builderclient.IsRetryable(err) {
		t.Fatalf("a permanent refusal stays permanent: %v", err)
	}
	if err := (DispatchEventObservers{ok, ok}).ObserveDispatchEvent(ctx, DispatchEventFact{}); err != nil {
		t.Fatal(err)
	}
}

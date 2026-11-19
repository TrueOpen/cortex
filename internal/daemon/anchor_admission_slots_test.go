package daemon

import (
	"context"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/store/layout"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// The slot protocol of the anchor admission signal: "slots" is how many
// tasks beyond those in "seen" this node may have in flight; the node takes a
// slot with the lease and holds it until the sidecar lists the task as seen.

// slotSignal is a slot signal written at the unix second at.
func slotSignal(at int64, slots int, seen ...layout.StoredHash) string {
	keys := make([]string, len(seen))
	for i, id := range seen {
		keys[i] = fmt.Sprintf("%q", anchorAdmissionKey(id))
	}
	return fmt.Sprintf(`{"accept":%v,"reason":"backlog","slots":%d,"seen":[%s],"updated":%d}`, slots > 0, slots, strings.Join(keys, ","), at)
}

// slotID is a distinct 32-byte id.
func slotID(kind byte, i int) layout.StoredHash {
	var h layout.StoredHash
	h[0], h[1], h[2], h[3] = kind, byte(i>>8), byte(i), 0x5a
	h[31] = 1
	return h
}

func slotTicket(i int) layout.StoredHash { return slotID(0x71, i) }
func slotTask(i int) layout.StoredHash   { return slotID(0x7a, i) }

func TestAnchorAdmissionSlotsAreTakenAtReserve(t *testing.T) {
	at := admissionAt.Unix()
	a, path, _ := newTestAdmission(t, slotSignal(at, 2))
	take := func(i int) (bool, error) { return a.Reserve(slotTicket(i), slotTask(i)) }
	if taken, err := take(1); err != nil || !taken {
		t.Fatalf("first slot: taken=%v err=%v", taken, err)
	}
	if taken, err := take(1); err != nil || taken {
		t.Fatalf("a ticket that holds a slot takes no second one: taken=%v err=%v", taken, err)
	}
	if err := a.RefusalForTask(slotTask(1)); err != nil {
		t.Fatalf("an offer of a task that holds a slot is not refused: %v", err)
	}
	if taken, err := take(2); err != nil || !taken {
		t.Fatalf("second slot: taken=%v err=%v", taken, err)
	}
	// The signal has not changed and still says accept: the boolean gate
	// would take a third task here, and a fourth, and a fifth.
	if _, err := take(3); err == nil || !strings.Contains(err.Error(), "2 audit slots and 2 tasks") {
		t.Fatalf("a third task against two slots: %v", err)
	}
	if err := a.Refusal(); err == nil {
		t.Fatal("Refusal() admits with every slot held")
	}
	if free, limited, refusal := a.Capacity(); free != 0 || !limited || refusal != nil {
		t.Fatalf("Capacity() = %d, %v, %v, want 0 free of a slot signal that is not closed", free, limited, refusal)
	}
	if st, _ := a.Status(); st.Accepting || !st.Limited || st.Slots != 2 || st.Reserved != 2 || st.Free != 0 {
		t.Fatalf("status %+v", st)
	}
	// The sidecar has seen task 1 and computed again: one slot beyond what
	// it sees. Task 2 is still in flight and fills it.
	writeAdmission(t, path, slotSignal(at, 1, slotTask(1)))
	if _, err := take(3); err == nil {
		t.Fatal("task 2 still holds the one slot")
	}
	if st, _ := a.Status(); st.Reserved != 1 || st.Slots != 1 {
		t.Fatalf("after task 1 was seen: %+v", st)
	}
	a.Release(slotTicket(2))
	if taken, err := take(3); err != nil || !taken {
		t.Fatalf("after the release: taken=%v err=%v", taken, err)
	}
	// A task the sidecar already accounts for needs no slot, even at zero.
	writeAdmission(t, path, slotSignal(at, 0, slotTask(1), slotTask(3)))
	if _, err := take(4); err == nil {
		t.Fatal("zero slots admitted a new task")
	}
	if taken, err := a.Reserve(slotTicket(31), slotTask(3)); err != nil || taken {
		t.Fatalf("another ticket of a task already seen: taken=%v err=%v, want admitted without a slot", taken, err)
	}
	a.ReleaseTask(slotTask(4)) // nothing held: a no-op
	if st, _ := a.Status(); st.Reserved != 0 || st.Accepting {
		t.Fatalf("status at zero slots: %+v", st)
	}
}

// A slot signal is read by its slots, not by "accept": the sidecar keeps
// computing "accept" its old way for a service that does not know slots.
func TestAnchorAdmissionSlotSignalIgnoresAccept(t *testing.T) {
	a, _, _ := newTestAdmission(t, fmt.Sprintf(`{"accept":false,"slots":1,"seen":[],"updated":%d}`, admissionAt.Unix()))
	if taken, err := a.Reserve(slotTicket(1), slotTask(1)); err != nil || !taken {
		t.Fatalf("one slot with accept false: taken=%v err=%v", taken, err)
	}
	b, _, _ := newTestAdmission(t, fmt.Sprintf(`{"accept":true,"slots":0,"seen":[],"updated":%d}`, admissionAt.Unix()))
	if _, err := b.Reserve(slotTicket(1), slotTask(1)); err == nil {
		t.Fatal("zero slots with accept true admitted")
	}
	c, _, _ := newTestAdmission(t, fmt.Sprintf(`{"accept":true,"slots":-3,"seen":[],"updated":%d}`, admissionAt.Unix()))
	if free, limited, _ := c.Capacity(); free != 0 || !limited {
		t.Fatalf("negative slots: %d free, limited %v, want none", free, limited)
	}
}

// Without "slots" the signal is the boolean gate it was: nothing is
// reserved, and any number of tasks is admitted while it says accept.
func TestAnchorAdmissionWithoutSlotsIsTheBooleanGate(t *testing.T) {
	a, path, _ := newTestAdmission(t, fmt.Sprintf(`{"accept":true,"updated":%d}`, admissionAt.Unix()))
	for i := range 50 {
		if taken, err := a.Reserve(slotTicket(i), slotTask(i)); err != nil || taken {
			t.Fatalf("task %d: taken=%v err=%v", i, taken, err)
		}
	}
	if free, limited, refusal := a.Capacity(); limited || refusal != nil || free != 0 {
		t.Fatalf("Capacity() = %d, %v, %v, want an unlimited open gate", free, limited, refusal)
	}
	if st, _ := a.Status(); !st.Accepting || st.Limited || st.Reserved != 0 {
		t.Fatalf("status %+v", st)
	}
	writeAdmission(t, path, fmt.Sprintf(`{"accept":false,"reason":"full","updated":%d}`, admissionAt.Unix()))
	if _, err := a.Reserve(slotTicket(99), slotTask(99)); err == nil || !strings.Contains(err.Error(), "full") {
		t.Fatalf("a boolean no: %v", err)
	}
}

// A slot the sidecar never confirms goes back at the TTL, so a path that
// forgot to give one back cannot close the gate for good; a stale slot signal
// refuses like a stale boolean one.
func TestAnchorAdmissionSlotTTLAndStaleSignal(t *testing.T) {
	now := admissionAt
	path := filepath.Join(t.TempDir(), "a.json")
	write := func(slots int) { writeAdmission(t, path, slotSignal(now.Unix(), slots)) }
	write(1)
	a := NewAnchorAdmission(config.AnchorAdmissionConfig{File: path, ReserveTTLS: 600}, func() time.Time { return now }, nil)
	if taken, err := a.Reserve(slotTicket(1), slotTask(1)); err != nil || !taken {
		t.Fatal(taken, err)
	}
	now = now.Add(46 * time.Second)
	if _, err := a.Reserve(slotTicket(2), slotTask(2)); err == nil || !strings.Contains(err.Error(), "old") {
		t.Fatalf("a stale slot signal: %v", err)
	}
	if free, limited, refusal := a.Capacity(); refusal == nil || free != 0 || limited {
		t.Fatalf("Capacity() of a stale signal = %d, %v, %v, want a refusal", free, limited, refusal)
	}
	write(1)
	if _, err := a.Reserve(slotTicket(2), slotTask(2)); err == nil {
		t.Fatal("task 1 is inside its TTL and holds the slot")
	}
	now = now.Add(10 * time.Minute)
	write(1)
	if taken, err := a.Reserve(slotTicket(2), slotTask(2)); err != nil || !taken {
		t.Fatalf("after the TTL of task 1: taken=%v err=%v", taken, err)
	}
	if st, _ := a.Status(); st.Reserved != 1 {
		t.Fatalf("status %+v, want only task 2 holding a slot", st)
	}
	if got := (config.AnchorAdmissionConfig{}).ReserveTTL(); got != config.DefaultAnchorAdmissionReserveTTLS*time.Second {
		t.Fatalf("default TTL %s", got)
	}
}

// A sidecar may list a task by its full id, with or without 0x, in either
// case: each is read by its first 16 hex characters. An entry that is not
// such an id releases nothing and is logged, once a minute at most.
func TestAnchorAdmissionSeenEntryForms(t *testing.T) {
	at := admissionAt.Unix()
	a, path, logs := newTestAdmission(t, slotSignal(at, 3))
	for i := 1; i <= 3; i++ {
		if taken, err := a.Reserve(slotTicket(i), slotTask(i)); err != nil || !taken {
			t.Fatal(i, taken, err)
		}
	}
	full := func(id layout.StoredHash) string { return hex.EncodeToString(id[:]) }
	task3 := anchorAdmissionKey(slotTask(3))
	writeAdmission(t, path, fmt.Sprintf(`{"accept":true,"slots":3,"seen":[%q,%q,%q,%q,%q,"",%q],"updated":%d}`,
		"0x"+full(slotTask(1)), strings.ToUpper(full(slotTask(2))),
		"0x"+task3[:15], task3[:15], "zz"+task3[2:], " not hex at all ", at))
	for range 2 {
		if st, _ := a.Status(); st.Reserved != 1 {
			t.Fatalf("%d slots held, want task 3's alone: the full ids release theirs, the malformed entries nothing", st.Reserved)
		}
	}
	if n := strings.Count(logs.String(), "malformed"); n != 1 {
		t.Fatalf("%d warnings about malformed seen entries, want one:\n%s", n, logs)
	}
}

// Many offers at once against one signal: the slots taken never outnumber
// the slots granted, whatever the interleaving.
func TestAnchorAdmissionParallelReservesNeverExceedTheSlots(t *testing.T) {
	const slots, offers = 5, 200
	a, _, _ := newTestAdmission(t, slotSignal(admissionAt.Unix(), slots))
	var taken, refused atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range offers {
		wg.Go(func() {
			<-start
			ok, err := a.Reserve(slotTicket(i), slotTask(i))
			switch {
			case err == nil && ok:
				taken.Add(1)
			case err != nil:
				refused.Add(1)
			}
			if st, _ := a.Status(); st.Reserved > slots {
				t.Errorf("%d slots held of %d", st.Reserved, slots)
			}
		})
	}
	close(start)
	wg.Wait()
	if taken.Load() != slots || refused.Load() != offers-slots {
		t.Fatalf("%d taken and %d refused of %d offers against %d slots", taken.Load(), refused.Load(), offers, slots)
	}
	// Releases and reserves interleaved: still never above the slots.
	for i := range offers {
		wg.Go(func() {
			a.Release(slotTicket(i))
			_, _ = a.Reserve(slotTicket(offers+i), slotTask(offers+i))
			if st, _ := a.Status(); st.Reserved > slots {
				t.Errorf("%d slots held of %d", st.Reserved, slots)
			}
		})
	}
	wg.Wait()
	if st, _ := a.Status(); st.Reserved != slots {
		t.Fatalf("%d slots held after the churn, want all %d", st.Reserved, slots)
	}
}

// slotHandraise is a standing handraise of a node whose Profiles all require
// kind 5 (or, with others, only hrModelCD@1), over a slot signal read at the
// harness clock. The engine has three free slots; MinChange is two seconds.
type slotHandraise struct {
	*hrHarness
	path string
	gate *AnchorAdmission
}

func newSlotHandraise(t *testing.T, mixed bool) *slotHandraise {
	t.Helper()
	s := &slotHandraise{path: filepath.Join(t.TempDir(), "admission.json")}
	s.hrHarness = newHRHarness(t, func(c *StandingHandraiseConfig) {
		if s.gate == nil {
			s.gate = NewAnchorAdmission(config.AnchorAdmissionConfig{File: s.path}, func() time.Time { return s.now }, nil)
		}
		c.Anchor, c.AnchorAdmission = &fakeAnchorProbe{}, s.gate
	})
	keys := []string{config.MinPriceBidKey(hrModelCD, 1)}
	if !mixed {
		keys = append(keys, config.MinPriceBidKey(hrModelAB, 1), config.MinPriceBidKey(hrModelAB, 2))
	}
	s.chain.with(func(f *fakeHandraiseChain) {
		for _, key := range keys {
			f.scopes[key] = requireAnchor(f.scopes[key])
		}
	})
	return s
}

func (s *slotHandraise) slots(n int, seen ...layout.StoredHash) {
	s.t.Helper()
	writeAdmission(s.t, s.path, slotSignal(s.now.Unix(), n, seen...))
}

// sent is the free_slot_count and Profile count of every handraise sent to
// Builder A, in order.
func (s *slotHandraise) sent() (out [][2]int) {
	for _, m := range s.a.handraises() {
		out = append(out, [2]int{int(m.GetFreeSlotCount()), len(m.GetProfiles())})
	}
	return out
}

// On a node whose Profiles all require kind 5 the standing handraise
// advertises min(free engine slots, free audit slots). It is ordinary
// capacity: a lower count is signed at once, a higher one waits for the
// minimum change interval, zero is advertised as zero (not withdrawn), and a
// slot count that moves above the engine's does not cause a send at all.
func TestStandingHandraiseAdvertisesTheFreeAuditSlots(t *testing.T) {
	x := newSlotHandraise(t, false)
	x.slots(2)
	x.warm()
	want := [][2]int{{2, 3}}
	check := func(what string) {
		t.Helper()
		if got := x.sent(); !slices.Equal(got, want) {
			t.Fatalf("%s: handraises (free, profiles) %v, want %v", what, got, want)
		}
	}
	check("two audit slots, three engine slots")

	// An offer is accepted: one slot is held.
	if taken, err := x.gate.Reserve(slotTicket(1), slotTask(1)); err != nil || !taken {
		t.Fatal(taken, err)
	}
	x.slots(2)
	x.step(100*time.Millisecond, 101)
	want = append(want, [2]int{1, 3})
	check("a slot was taken: the lower count is signed at once")

	// The second slot goes too: zero, with the Profiles still listed.
	if taken, err := x.gate.Reserve(slotTicket(2), slotTask(2)); err != nil || !taken {
		t.Fatal(taken, err)
	}
	x.slots(2)
	x.step(100*time.Millisecond, 101)
	want = append(want, [2]int{0, 3})
	check("no audit slot left: zero is advertised, nothing is withdrawn")
	if cur, _ := x.h.Current(hrBuilderA); cur.Withdrawn {
		t.Fatal("the handraise was withdrawn at zero audit slots")
	}

	// The sidecar has seen task 1: a slot is back. It is growth of a live
	// offer, so it waits for the minimum change interval, and it needs no
	// height, Notify or Rebound.
	x.slots(2, slotTask(1))
	x.step(100*time.Millisecond, 101)
	check("a slot came back 100 ms after the last send: held")
	x.slots(2, slotTask(1))
	x.step(time.Second, 101)
	check("1.1 s after the last send: still held")
	x.slots(2, slotTask(1))
	x.step(time.Second, 101)
	want = append(want, [2]int{1, 3})
	check("2.1 s after the last send: re-advertised")

	// Both tickets are gone and the sidecar grants more slots than the engine
	// has free, a different number at every write: the count grows once to
	// the engine's three, after the interval, and is not re-signed again.
	x.gate.Release(slotTicket(2))
	for _, n := range []int{5, 6, 4, 7, 5, 6} {
		x.slots(n, slotTask(1))
		x.step(time.Second, 101)
	}
	want = append(want, [2]int{3, 3})
	check("audit slots moving between 4 and 7 above three engine slots")
}

// A node that also offers Profiles without kind 5 cannot say "no slot for
// these Profiles" with one free_slot_count: the gated Profile is left out
// while no audit slot is free, and the engine's count is advertised as it is.
func TestStandingHandraiseMixedNodeDropsGatedProfilesAtZeroSlots(t *testing.T) {
	ab1, ab2, cd1 := hrProfile(hrModelAB, 1), hrProfile(hrModelAB, 2), hrProfile(hrModelCD, 1)
	x := newSlotHandraise(t, true)
	x.slots(1)
	x.warm()
	if cur, _ := x.h.Current(hrBuilderA); cur.State.FreeSlots != 3 || !slices.Equal(cur.State.Profiles, []HandraiseProfile{ab1, ab2, cd1}) {
		t.Fatalf("one audit slot: %+v, want the engine's three slots and every Profile", cur.State)
	}
	if taken, err := x.gate.Reserve(slotTicket(1), slotTask(1)); err != nil || !taken {
		t.Fatal(taken, err)
	}
	x.slots(1)
	x.step(100*time.Millisecond, 101)
	if cur, _ := x.h.Current(hrBuilderA); cur.Withdrawn || cur.State.FreeSlots != 3 || !slices.Equal(cur.State.Profiles, []HandraiseProfile{ab1, ab2}) {
		t.Fatalf("no audit slot: %+v, want the gated Profile left out at once and three slots", cur.State)
	}
	x.slots(1, slotTask(1))
	x.step(100*time.Millisecond, 101)
	if len(x.a.handraises()) != 2 {
		t.Fatal("the Profile came back inside the minimum change interval")
	}
	x.slots(1, slotTask(1))
	x.step(2*time.Second, 101)
	if cur, _ := x.h.Current(hrBuilderA); !slices.Equal(cur.State.Profiles, []HandraiseProfile{ab1, ab2, cd1}) {
		t.Fatalf("a slot is back: %+v", cur.State)
	}
}

// slotOffer is gatedOfferHarness over a slot signal: the engine has four
// slots, the offer is for a kind 5 Profile.
func slotOffer(t *testing.T, slots int) (*dispatchHarness, *AnchorAdmission, string) {
	t.Helper()
	a, path, _ := newTestAdmission(t, slotSignal(admissionAt.Unix(), slots))
	x, _ := gatedOfferHarness(t, a, false)
	x.capacity = 4
	x.open()
	return x, a, path
}

func reservedSlots(a *AnchorAdmission) int {
	st, _ := a.Status()
	return st.Reserved
}

// The slot is taken when the offer is accepted, with the lease, and given
// back on every way out that leaves no signed receipt.
func TestDispatchOfferTakesAndReturnsTheAuditSlot(t *testing.T) {
	ctx := context.Background()
	accept := func(t *testing.T, x *dispatchHarness, a *AnchorAdmission) {
		t.Helper()
		if err := x.handle(ctx); err != nil {
			t.Fatal(err)
		}
		if _, ok := x.a.messages()[0].(*taskv1.DispatchAcceptV1); !ok {
			t.Fatalf("answered %T, want an accept", x.a.messages()[0])
		}
		if !x.leaseHeld(t) || reservedSlots(a) != 1 {
			t.Fatalf("after the accept: lease held %v, %d slots held, want one of each", x.leaseHeld(t), reservedSlots(a))
		}
	}
	t.Run("accepted and redelivered", func(t *testing.T) {
		x, a, _ := slotOffer(t, 1)
		accept(t, x, a)
		if err := x.handle(ctx); err != nil {
			t.Fatal(err)
		}
		if reservedSlots(a) != 1 {
			t.Fatalf("%d slots held after the redelivery, want still one", reservedSlots(a))
		}
	})
	t.Run("revoked", func(t *testing.T) {
		x, a, _ := slotOffer(t, 1)
		accept(t, x, a)
		if err := x.d.HandleRevoke(ctx, hrBuilderA, dpRevoke(t, x, nexusv1.DispatchRevokeReasonV1_DISPATCH_REVOKE_REASON_V1_RBF)); err != nil {
			t.Fatal(err)
		}
		if x.leaseHeld(t) || reservedSlots(a) != 0 {
			t.Fatalf("after the revoke: lease held %v, %d slots held", x.leaseHeld(t), reservedSlots(a))
		}
	})
	t.Run("superseded by the next round", func(t *testing.T) {
		x, a, _ := slotOffer(t, 1)
		accept(t, x, a)
		x.nextOffer(1)
		if err := x.handle(ctx); err != nil {
			t.Fatal(err)
		}
		if reservedSlots(a) != 1 || x.leaseCount(t) != 1 {
			t.Fatalf("after round 1 replaced round 0: %d slots, %d leases, want the one slot moved to the new ticket", reservedSlots(a), x.leaseCount(t))
		}
		x.lastIsAccept(t)
	})
	t.Run("task ended without a receipt", func(t *testing.T) {
		x, a, _ := slotOffer(t, 1)
		accept(t, x, a)
		rec := x.record(t)
		if err := x.d.ReleaseTaskLease(ctx, rec.TaskID); err != nil {
			t.Fatal(err)
		}
		if reservedSlots(a) != 0 {
			t.Fatalf("%d slots held after the task ended with no receipt", reservedSlots(a))
		}
	})
	t.Run("task ended with a signed receipt keeps the slot until seen", func(t *testing.T) {
		x, a, path := slotOffer(t, 1)
		accept(t, x, a)
		rec := x.record(t)
		if _, err := layout.UpdateDispatch(ctx, x.st, rec.TicketHash, func(r *layout.DispatchRecord) error {
			// A receipt is only signed for a recorded ticket.
			r.State, r.RecordedHeight, r.InferDeadlineHeight, r.WinnerTicketHash = layout.DispatchRecorded, 120, 300, r.TicketHash
			r.Receipt = []byte(`{"signed":"receipt"}`)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := x.d.ReleaseTaskLease(ctx, rec.TaskID); err != nil {
			t.Fatal(err)
		}
		if reservedSlots(a) != 1 {
			t.Fatalf("%d slots held: the commitment is on its way and the sidecar has not seen it", reservedSlots(a))
		}
		writeAdmission(t, path, slotSignal(admissionAt.Unix(), 1, rec.TaskID))
		if reservedSlots(a) != 0 {
			t.Fatalf("%d slots held after the sidecar listed the task as seen", reservedSlots(a))
		}
	})
	t.Run("no engine slot: the audit slot goes straight back", func(t *testing.T) {
		x, a, _ := slotOffer(t, 2)
		for i := range 4 {
			if ok, err := x.leases.Acquire(ctx, layout.WorkerLease{TicketHash: slotTicket(900 + i), TaskID: slotTask(900 + i), Builder: hrBuilderB, ExpiryHeight: 999}); err != nil || !ok {
				t.Fatalf("occupy: %v %v", ok, err)
			}
		}
		if err := x.handle(ctx); err != nil {
			t.Fatal(err)
		}
		if rec := x.record(t); rec.RejectClass != classNoFreeSlot {
			t.Fatalf("reject class %q, want %q", rec.RejectClass, classNoFreeSlot)
		}
		if reservedSlots(a) != 0 {
			t.Fatalf("%d audit slots held by an offer that got no lease", reservedSlots(a))
		}
	})
	t.Run("restart rebuilds the table from the records", func(t *testing.T) {
		x, a, _ := slotOffer(t, 1)
		accept(t, x, a)
		a.Release(layout.StoredHash(x.fx.ticketHash())) // the table is in memory: a restart loses it
		if reservedSlots(a) != 0 {
			t.Fatal("setup")
		}
		x.open()
		if reservedSlots(a) != 1 {
			t.Fatalf("%d slots held after the restart, want the accepted ticket's", reservedSlots(a))
		}
	})
	// recordIt moves the accepted ticket to Recorded the way the order does:
	// the lease to its task key, then the state, with a receipt if signed.
	recordIt := func(t *testing.T, x *dispatchHarness, signed bool) layout.DispatchRecord {
		t.Helper()
		rec := x.record(t)
		if _, err := x.d.cfg.Leases.Rebind(ctx, rec.TicketHash, rec.TaskID); err != nil {
			t.Fatal(err)
		}
		rec, err := layout.UpdateDispatch(ctx, x.st, rec.TicketHash, func(r *layout.DispatchRecord) error {
			r.State, r.RecordedHeight, r.InferDeadlineHeight, r.WinnerTicketHash = layout.DispatchRecorded, 120, 300, r.TicketHash
			if signed {
				r.Receipt = []byte(`{"signed":"receipt"}`)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	t.Run("restart keeps the slot of a recorded task still running", func(t *testing.T) {
		x, a, _ := slotOffer(t, 1)
		accept(t, x, a)
		recordIt(t, x, false)
		a.Release(layout.StoredHash(x.fx.ticketHash()))
		x.open()
		if reservedSlots(a) != 1 {
			t.Fatalf("%d slots held after the restart, want the running task's", reservedSlots(a))
		}
	})
	t.Run("restart does not revive the slot of a task that ended without a receipt", func(t *testing.T) {
		x, a, _ := slotOffer(t, 1)
		accept(t, x, a)
		rec := recordIt(t, x, false)
		if err := x.d.ReleaseTaskLease(ctx, rec.TaskID); err != nil {
			t.Fatal(err)
		}
		if reservedSlots(a) != 0 {
			t.Fatal("setup")
		}
		x.open()
		if reservedSlots(a) != 0 {
			t.Fatalf("%d slots held after the restart by a task that ended with no receipt", reservedSlots(a))
		}
	})
	t.Run("restart keeps the slot of a signed receipt the sidecar has not seen", func(t *testing.T) {
		x, a, _ := slotOffer(t, 1)
		accept(t, x, a)
		rec := recordIt(t, x, true)
		if err := x.d.ReleaseTaskLease(ctx, rec.TaskID); err != nil {
			t.Fatal(err)
		}
		a.Release(rec.TicketHash) // the table is in memory: a restart loses it
		x.open()
		if reservedSlots(a) != 1 {
			t.Fatalf("%d slots held after the restart, want the slot of the receipt on its way", reservedSlots(a))
		}
	})
}

// With every slot held, an offer is refused NO_CAPACITY, after the handraise
// has been re-signed, without a lease and without a slot; the reject is not
// a reject-rate sample. One more slot and the same offer is accepted.
func TestDispatchOfferBeyondTheAuditSlotsIsRefused(t *testing.T) {
	ctx := context.Background()
	x, a, path := slotOffer(t, 2)
	for i := range 2 {
		if taken, err := a.Reserve(slotTicket(i), slotTask(i)); err != nil || !taken {
			t.Fatal(taken, err)
		}
	}
	const offers = 40
	for round := uint32(1); round <= offers; round++ {
		x.nextOffer(round)
		if err := x.handle(ctx); err != nil {
			t.Fatalf("offer %d: %v", round, err)
		}
	}
	events := x.log.all()
	rejects, counted := rejectRateSamples(events, 2)
	if rejects != offers || counted != 0 {
		t.Fatalf("%d rejects, %d of them reject-rate samples; want %d and 0", rejects, counted, offers)
	}
	if got, want := events[:3], []string{"handraise:refresh", "handraise:withdraw", rejectEvent}; !slices.Equal(got, want) {
		t.Fatalf("events %v, want %v first: the handraise is re-signed before the first reject", events[:min(len(events), 5)], want)
	}
	if rec := x.record(t); rec.RejectClass != classAnchorAdmission ||
		rec.RejectReason != int32(taskv1.DispatchRejectReasonV1_DISPATCH_REJECT_REASON_V1_NO_CAPACITY) {
		t.Fatalf("record class %q reason %d", rec.RejectClass, rec.RejectReason)
	}
	if x.leaseCount(t) != 0 || reservedSlots(a) != 2 {
		t.Fatalf("%d leases and %d slots held after %d refused offers, want none and the two taken before", x.leaseCount(t), reservedSlots(a), offers)
	}
	if st, _ := a.Status(); st.RefusedOffers != offers {
		t.Fatalf("refused offers %d, want %d", st.RefusedOffers, offers)
	}
	// The sidecar grants a third slot: the next round is accepted and holds it.
	writeAdmission(t, path, slotSignal(admissionAt.Unix(), 3))
	x.hr.mu.Lock()
	c := x.hr.current[hrBuilderA]
	c.Withdrawn, c.State.FreeSlots, c.State.Profiles = false, 2, []HandraiseProfile{hrProfile(hrModelAB, 1)}
	x.hr.current[hrBuilderA] = c
	x.hr.mu.Unlock()
	x.nextOffer(offers + 1)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	x.lastIsAccept(t)
	if x.leaseCount(t) != 1 || reservedSlots(a) != 3 {
		t.Fatalf("%d leases and %d slots held after the accept", x.leaseCount(t), reservedSlots(a))
	}
}

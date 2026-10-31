package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/dispatchstream/streamtest"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/txclient"
	"github.com/TrueOpen/cortex/internal/txclient/txclienttest"
	"github.com/TrueOpen/cortex/internal/worker"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

const e2eServiceAddress = "trueopen1n76x6eelp8s6nx737vnmp29rdme7peaypql50k"

type e2eEndpoints struct{ url, pin string }

func (e e2eEndpoints) ResolveBuilderEndpoint(_ context.Context, op string) (BuilderEndpoint, error) {
	return BuilderEndpoint{OperatorAddress: op, Endpoint: e.url, TLSPubkeyHash: e.pin, Source: BuilderEndpointSourceDescriptor}, nil
}

// e2eKeys serves the stream's two committed key reads from the handraise
// fake: the Builder keys as it does, and this node's own key (the binding's
// service_authorization_nonce), which the fake's root path refuses.
type e2eKeys struct{ hc *fakeHandraiseChain }

func (k e2eKeys) CommittedCurrentServiceKey(ctx context.Context, participant, operator string) (chainclient.ServiceKeySnapshot, uint64, error) {
	if participant != chainclient.ParticipantTypeCortexNode {
		return k.hc.CommittedCurrentServiceKey(ctx, participant, operator)
	}
	k.hc.mu.Lock()
	defer k.hc.mu.Unlock()
	return k.hc.cortexKey, k.hc.height, k.hc.cortexKeyErr
}

// e2eTx serializes the fake broadcaster: the Dispatcher submits from its
// own loop while the test reads the requests.
type e2eTx struct {
	mu sync.Mutex
	f  *txclienttest.Fake
}

func (t *e2eTx) Submit(ctx context.Context, req txclient.Request) (txclient.Observation, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.f.Submit(ctx, req)
}

func (t *e2eTx) Requests() []txclient.Request {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.f.Requests()
}

type e2eChainStatus struct{}

func (e2eChainStatus) ChainStatus(context.Context) (uint64, string, error) {
	return 150, dpChainID, nil
}

// e2eInfer stands in for the model and the Worker (Q2): it requires the
// Dispatcher's committed input, waits on the delivery gate like the Worker
// does (S5 W6), and only then issues the receipt.
type e2eInfer struct {
	st       *store.Store
	mu       sync.Mutex
	receipts []builderclient.SignedInferReceipt
}

func (e *e2eInfer) RunInfer(ctx context.Context, taskHash codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
	rec, err := layout.GetDispatchRecord(ctx, e.st, layout.StoredHash(task.DispatchTicketHash))
	if err != nil || !rec.InputCommitted {
		return task, false, fmt.Errorf("input of ticket %s is not committed: %v", task.DispatchTicketHash, err)
	}
	gate := dispatchGate{st: e.st}
	s, err := gate.DeliveryState(ctx, task.DispatchTicketHash)
	if err != nil {
		return task, false, err
	}
	if s.Paused || s.RecordedHeight == 0 {
		return task, false, builderclient.Retryable(fmt.Errorf("%w: %w", errChainStateWaiting, worker.ErrAwaitingDispatchRecord))
	}
	receipt := builderclient.SignedInferReceipt{TaskID: task.TaskID, DispatchTicketHash: task.DispatchTicketHash.String()}
	if err := gate.ReceiptSigned(ctx, task.DispatchTicketHash, receipt); err != nil {
		return task, false, err
	}
	e.mu.Lock()
	e.receipts = append(e.receipts, receipt)
	e.mu.Unlock()
	task.Stage = "succeeded"
	return task, true, nil
}

func (e *e2eInfer) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.receipts)
}

type planeE2E struct {
	t       *testing.T
	fx      *offerFixture
	hc      *fakeHandraiseChain
	dc      *fakeDispatchChain
	st      *store.Store
	srv     *streamtest.Server
	tx      *e2eTx
	infer   *e2eInfer
	runner  *TaskRunner
	streams *DispatchStreams
	plane   *DispatchPlane
}

func newPlaneE2E(t *testing.T) *planeE2E {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evidence.NewStore(t.TempDir(), st)
	if err != nil {
		t.Fatal(err)
	}
	x := &planeE2E{t: t, fx: newOfferFixture(t), hc: newFakeHandraiseChain(t), st: st, srv: streamtest.Start(t),
		tx: &e2eTx{f: txclienttest.NewFake()}, infer: &e2eInfer{st: st}}
	x.dc = newFakeDispatchChain(t, x.fx)
	x.dc.with(func(f *fakeDispatchChain) { f.params.CompensationClaimWindowBlocks = 20 })
	x.hc.with(func(f *fakeHandraiseChain) { f.height = 140 })
	x.streams, err = NewDispatchStreams(DispatchStreamsConfig{
		ChainID: dpChainID, Operator: hrCortex, Builders: []string{hrBuilderA, hrBuilderB},
		Stream:    config.DispatchStreamConfig{KeepaliveMS: 3_600_000, MaxMissed: 3, ReconnectMinMS: 10, ReconnectMaxMS: 50},
		Endpoints: e2eEndpoints{url: x.srv.URL(), pin: x.srv.Pin()}, HTTP: builderclient.NewDispatchStreamHTTPClient(),
		Keys: e2eKeys{x.hc}, Sign: hrSigner(hrCortexKey), Height: func() uint64 { return 150 }, Store: st,
	})
	if err != nil {
		t.Fatal(err)
	}
	link := NewDispatchLink()
	x.runner = NewTaskRunner(TaskRunnerConfig{Store: st, Evidence: ev, InferExecutor: x.infer, ChainStatus: e2eChainStatus{},
		VerifierSender: x.streams.Fanout(), VerifyNotices: x.streams.Fanout(),
		DispatchRecords: link, DispatchEvents: link, ReleaseDispatchLease: link.ReleaseTaskLease,
		PollInterval: 10 * time.Millisecond, DispatchWaitInterval: 10 * time.Millisecond, LocalWorkerAddress: hrCortex, ChainID: dpChainID})
	x.plane, err = NewDispatchPlane(ctx, DispatchPlaneConfig{
		Streams: x.streams, Runner: x.runner, Evidence: ev, Store: st,
		ChainID: dpChainID, Operator: hrCortex, FeeDenom: dpFeeDenom, Profiles: hrProfileRefs(),
		Dispatch: config.DispatchConfig{EvidenceRetentionBlocks: 1_000, MinPriceBid: hrBids(), ReceiptRescueMarginBlocks: 2,
			Handraise: config.HandraiseConfig{HeartbeatMS: 10_000, TTLMS: 60_000, MinChangeIntervalMS: 500}},
		Capacity: 2, Local: &fakeHandraiseLocal{ready: true, freeOK: true}, Sign: hrSigner(hrCortexKey),
		Submitter:      func() (txclient.Client, string) { return x.tx, e2eServiceAddress },
		HandraiseChain: x.hc, DispatchChain: x.dc, VerifierChain: x.hc,
		EvalEvery: 10 * time.Millisecond, SweepEvery: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	link.Bind(x.plane)
	var wg sync.WaitGroup
	for _, run := range append(x.plane.Runners(), x.runner.Run) {
		wg.Add(1)
		go func() { defer wg.Done(); _ = run(ctx) }()
	}
	t.Cleanup(func() { cancel(); wg.Wait(); _ = st.Close() })
	return x
}

// handraise advances the handraise chain until the standing handraise to the
// Builder of conn arrives: the block interval needs two heights.
func (x *planeE2E) handraise(conn *streamtest.Conn) *taskv1.StandingHandraiseV1 {
	x.t.Helper()
	for h := uint64(141); h < 200; h++ {
		x.hc.with(func(f *fakeHandraiseChain) { f.height = h })
		if f, ok := conn.TryRecv(50 * time.Millisecond); ok && f.GetHandraise() != nil {
			return f.GetHandraise()
		}
	}
	x.t.Fatalf("no standing handraise to %s", conn.Builder)
	return nil
}

// rootFor proves h in a root signed by Builder A on the plane's chain.
func (x *planeE2E) rootFor(h *taskv1.StandingHandraiseV1) *nexusv1.HandraiseRootNoticeV1 {
	x.t.Helper()
	n := hrRootNotice(x.t, hrBuilderA, hrBuilderKey, h.GetIssuedHeight(), 0, admittedLeaf(h))
	n.Root.ChainId, n.Root.BuilderServiceSignature = dpChainID, nil
	d, err := dispatchwire.Digest(n.Root)
	if err != nil {
		x.t.Fatal(err)
	}
	if n.Root.BuilderServiceSignature, err = signer.SignDigestWithPrivateKeyHex(hrBuilderKey, codec.Hash(d)); err != nil {
		x.t.Fatal(err)
	}
	return n
}

// accepted drives Builder A from handraise to a committed input and returns
// the ticket hash.
func (x *planeE2E) accepted(conn *streamtest.Conn) [32]byte {
	x.t.Helper()
	n := x.rootFor(x.handraise(conn))
	conn.WaitAcked(x.t, conn.Push(x.t, n))
	hrEventually(x.t, "root admitted", func() bool { r, ok := x.plane.handraiser.lastAdmission(hrBuilderA); return ok && r.Admitted })
	d, err := dispatchwire.Digest(n.Root)
	if err != nil {
		x.t.Fatal(err)
	}
	x.fx.ticket.HandraiseRootDigest = d[:]
	x.fx.signTicket(hrBuilderKey)
	th := x.fx.ticketHash()
	conn.Push(x.t, x.fx.offer())
	acc := conn.RecvUntil(x.t, "accept", func(f *nexusv1.DispatchStreamFrameV1) bool { return f.GetAccept() != nil })
	if !bytes.Equal(acc.GetAccept().GetDispatchTicketHash(), th[:]) {
		x.t.Fatalf("accept for %x", acc.GetAccept().GetDispatchTicketHash())
	}
	conn.RecvUntil(x.t, "input request", func(f *nexusv1.DispatchStreamFrameV1) bool { return f.GetInputRequest() != nil })
	conn.Push(x.t, x.fx.inputResponse(0, 1, x.fx.input))
	hrEventually(x.t, "inference admitted", func() bool {
		infer, _ := x.runner.ActiveTasks()
		for _, task := range infer {
			if task.DispatchTicketHash == codec.Hash(th) {
				return true
			}
		}
		return false
	})
	return th
}

func (x *planeE2E) notice(th [32]byte, status taskv1.DispatchRecordStatusV1) *nexusv1.RecordResultNoticeV1 {
	x.t.Helper()
	n := &nexusv1.RecordResultNoticeV1{DispatchTicketHash: th[:], Status: status, RecordedHeight: 120}
	if status == taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_REJECTED {
		n.RecordedHeight, n.RejectCode = 0, taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_RECORD_LATE
	}
	d, err := dispatchwire.Digest(n)
	if err != nil {
		x.t.Fatal(err)
	}
	if n.BuilderServiceSignature, err = signer.SignDigestWithPrivateKeyHex(hrBuilderKey, codec.Hash(d)); err != nil {
		x.t.Fatal(err)
	}
	return n
}

// Flow 1: handraise → root → offer → accept → input → infer → record → receipt.
func TestDispatchPlaneE2EHandraiseToReceipt(t *testing.T) {
	x := newPlaneE2E(t)
	connA, connB := x.srv.Next(t, hrBuilderA), x.srv.Next(t, hrBuilderB)
	th := x.accepted(connA)
	if h := x.handraise(connB); h.GetBuilderAddress() != hrBuilderB {
		t.Fatal("each Builder gets its own standing handraise")
	}
	time.Sleep(100 * time.Millisecond)
	if x.infer.count() != 0 {
		t.Fatal("no receipt before the record (S5 W6)")
	}
	digest := dpGenerationDigest(t, x.fx)
	x.dc.with(func(f *fakeDispatchChain) {
		f.record = chainclient.DispatchRecordSnapshot{Height: f.height, TaskID: bytes.Clone(x.fx.ticket.TaskId), RecordHash: bytes.Repeat([]byte{0x77}, 32),
			TicketHash: bytes.Clone(th[:]), Builder: hrBuilderA, Winner: hrCortex, WinnerRound: 1, RecordedHeight: 120}
		f.assignment = chainclient.DispatchAssignmentSnapshot{Height: f.height, TaskID: bytes.Clone(x.fx.ticket.TaskId),
			AcceptedTaskHash: bytes.Clone(x.fx.ticket.TaskHash), GenerationParamsDigest: bytes.Clone(digest[:]),
			RecordHeight: 120, InferDeadlineHeight: 150, DispatchTicketHash: bytes.Clone(th[:]), WinnerWorker: hrCortex}
	})
	connA.WaitAcked(t, connA.Push(t, x.notice(th, taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_RECORDED)))
	fact := DispatchRecordedFact{Height: 120, TaskID: layout.StoredHash(x.fx.ticket.TaskId), SessionID: layout.StoredHash(x.fx.ticket.SessionId),
		OrderSequence: x.fx.ticket.OrderSequence, Builder: hrBuilderA, Winner: hrCortex, TicketHash: layout.StoredHash(th),
		RecordHash: layout.StoredHash(bytes.Repeat([]byte{0x77}, 32)), InferDeadline: 150}
	if err := x.runner.ApplyReconcilerEffects(context.Background(), []ReconcilerEffect{{Type: ReconcilerEffectDispatchRecorded,
		TaskID: hex.EncodeToString(x.fx.ticket.TaskId), Dispatch: fact}}); err != nil {
		t.Fatalf("the chain record reaches the Dispatcher through the link: %v", err)
	}
	hrEventually(t, "receipt after the record", func() bool { return x.infer.count() == 1 })
	if rec, err := layout.GetDispatchRecord(context.Background(), x.st, layout.StoredHash(th)); err != nil || rec.State != layout.DispatchRecorded {
		t.Fatalf("record = %v, %v", rec.State, err)
	}
}

// Flow 2: REJECTED notice → pending-claim → D_ticket, no record → claim.
func TestDispatchPlaneE2ERejectedToCompensationClaim(t *testing.T) {
	x := newPlaneE2E(t)
	conn := x.srv.Next(t, hrBuilderA)
	th := x.accepted(conn)
	conn.WaitAcked(t, conn.Push(t, x.notice(th, taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_REJECTED)))
	ctx := context.Background()
	hrEventually(t, "pending claim", func() bool {
		rec, err := layout.GetDispatchRecord(ctx, x.st, layout.StoredHash(th))
		return err == nil && rec.State == layout.DispatchPendingClaim
	})
	rec, _ := layout.GetDispatchRecord(ctx, x.st, layout.StoredHash(th))
	x.dc.with(func(f *fakeDispatchChain) { f.height = rec.ClaimFromHeight })
	hrEventually(t, "compensation claim broadcast", func() bool {
		for _, r := range x.tx.Requests() {
			if r.Kind == txclient.MsgClaimDispatchCompensation {
				return true
			}
		}
		return false
	})
	for _, r := range x.tx.Requests() {
		if r.Kind != txclient.MsgClaimDispatchCompensation {
			continue
		}
		var m taskv1.MsgClaimDispatchCompensation
		if err := protojson.Unmarshal(r.Payload, &m); err != nil || m.GetSubmitterAddress() != e2eServiceAddress {
			t.Fatalf("claim submitter = %q, %v: the broadcaster's own address (S6)", m.GetSubmitterAddress(), err)
		}
	}
}

// Flow 3: the stream legs of Verifier A → commit → B → reveal (Q2).
func TestDispatchPlaneE2EVerifierLegsReachEveryStream(t *testing.T) {
	x := newPlaneE2E(t)
	ctx := context.Background()
	conns := []*streamtest.Conn{x.srv.Next(t, hrBuilderA), x.srv.Next(t, hrBuilderB)}
	for _, c := range conns {
		m := vsOpenVerify(c.Builder)
		m.Binding.ChainId, m.WorkerOperatorAddress = dpChainID, e2eServiceAddress
		d, err := dispatchwire.Digest(m)
		if err != nil {
			t.Fatal(err)
		}
		if m.BuilderServiceSignature, err = signer.SignDigestWithPrivateKeyHex(hrBuilderKey, codec.Hash(d)); err != nil {
			t.Fatal(err)
		}
		c.WaitAcked(t, c.Push(t, m))
	}
	hrEventually(t, "one inbox entry naming both Builders", func() bool {
		e, ok, err := verifierInbox{st: x.st}.load(ctx, vsTaskID, 1)
		return err == nil && ok && len(e.Builders) == 2
	})
	if err := x.streams.Fanout().SendVerifierHandraise(ctx, vsHandraise(t, 1_000)); err != nil {
		t.Fatal(err)
	}
	for _, c := range conns {
		c.RecvUntil(t, "verifier handraise", func(f *nexusv1.DispatchStreamFrameV1) bool { return f.GetVerifierHandraise() != nil })
	}
	for _, key := range []byte{0x01, 0x02} { // the commit notice (V12), then the result notice (V15)
		n := &nexusv1.VerifyResultSubmittedNoticeV1{TaskId: bytes.Repeat([]byte{0x11}, 32), TaskHash: bytes.Repeat([]byte{0x22}, 32),
			VerifyRound: 1, CommitKey: bytes.Repeat([]byte{key}, 32), OperatorAddress: hrCortex, ServiceAuthorizationNonce: 7}
		if err := dispatchwire.SignVerifyResultSubmitted(ctx, n, hrSigner(hrCortexKey)); err != nil {
			t.Fatal(err)
		}
		if err := x.streams.Fanout().SendVerifyResultSubmitted(ctx, n, 1_000); err != nil {
			t.Fatal(err)
		}
		for _, c := range conns {
			f := c.RecvUntil(t, "result notice", func(f *nexusv1.DispatchStreamFrameV1) bool { return f.GetVerifyResultSubmitted() != nil })
			if f.GetVerifyResultSubmitted().GetCommitKey()[0] != key {
				t.Fatalf("%s got the notices out of order", c.Builder)
			}
		}
	}
	for _, row := range x.streams.Statuses() {
		if !row.Ready {
			t.Fatalf("%s not ready while both streams are bound: %s", row.Name, row.Error)
		}
	}
}

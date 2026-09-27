package builderclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"runtime"

	"strings"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
)

type fakeNATSTransport struct {
	published []NATSMessage
	err       error
	probeErr  error
	probes    int
}

type closableFakeNATSTransport struct {
	fakeNATSTransport
	closed chan struct{}
}

func (f *closableFakeNATSTransport) Close() error {
	close(f.closed)
	return nil
}

func (f *fakeNATSTransport) Publish(_ context.Context, msg NATSMessage) error {
	if f.err != nil {
		return f.err
	}
	f.published = append(f.published, NATSMessage{
		Subject:   msg.Subject,
		Header:    msg.Header.Clone(),
		Data:      append([]byte(nil), msg.Data...),
		JetStream: msg.JetStream,
	})
	return nil
}

func (f *fakeNATSTransport) Probe(context.Context) error {
	f.probes++
	return f.probeErr
}

func TestNATSPublisherProbeConnectsWithoutPublishing(t *testing.T) {
	fake := &fakeNATSTransport{}
	restore := replaceNATSConnectorForTest(t, func(string, string) (natsPublishTransport, error) {
		return fake, nil
	})
	defer restore()

	publisher, err := NewNATSPublisher("nats://127.0.0.1:4222", "")
	if err != nil {
		t.Fatalf("NewNATSPublisher() error = %v", err)
	}
	probe := publisher.(interface{ Probe(context.Context) error })
	if err := probe.Probe(context.Background()); err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if fake.probes != 1 || len(fake.published) != 0 {
		t.Fatalf("probes = %d published = %d, want one probe and no publish", fake.probes, len(fake.published))
	}
}

func TestNATSPublisherProbeReportsTransportFailure(t *testing.T) {
	want := errors.New("flush failed")
	publisher := natsPublisher{transport: &fakeNATSTransport{probeErr: want}}
	if err := publisher.Probe(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Probe() error = %v, want %v", err, want)
	}
}

func TestNATSSubscriberProbeHonorsCanceledContext(t *testing.T) {
	release := make(chan struct{})
	restore := replaceNATSSubscriberConnectorForTest(t, func(string, string) (*nats.Conn, error) {
		<-release
		return nil, errors.New("late connect failure")
	})
	defer restore()
	subscriber, err := NewNATSSubscriber("nats://127.0.0.1:4222", "", "TRUEOPEN_TASK")
	if err != nil {
		t.Fatalf("NewNATSSubscriber() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probe := subscriber.(interface{ Probe(context.Context) error })
	if err := probe.Probe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Probe() error = %v, want context.Canceled", err)
	}
	close(release)
}

func TestNewNATSPublisherPublishesThroughInjectedTransport(t *testing.T) {
	fake := &fakeNATSTransport{}
	restore := replaceNATSPublisherConnectorForTest(t, func(_ string, _ string) (natsPublishTransport, error) {
		return fake, nil
	})
	defer restore()

	publisher, err := NewNATSPublisher("nats://127.0.0.1:4222", "token-1")
	if err != nil {
		t.Fatalf("NewNATSPublisher() error = %v", err)
	}

	payload := []byte("payload")
	if err := publisher.Publish(context.Background(), PublishRequest{
		Subject: "trueopen.output-avail.task-1",
		TaskID:  "task-1",
		Payload: payload,
	}); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	if len(fake.published) != 1 {
		t.Fatalf("published count = %d, want 1", len(fake.published))
	}
	got := fake.published[0]
	if got.Subject != "trueopen.output-avail.task-1" {
		t.Fatalf("subject = %q, want trueopen.output-avail.task-1", got.Subject)
	}
	if !bytes.Equal(got.Data, payload) {
		t.Fatalf("payload = %q, want %q", got.Data, payload)
	}
	if got.Header.Get(natsDedupHeader) == "" {
		t.Fatalf("dedup header %q missing", natsDedupHeader)
	}
}

func TestNATSPublisherRejectsInvalidPublishRequests(t *testing.T) {
	publisher := natsPublisher{transport: &fakeNATSTransport{}}
	for name, req := range map[string]PublishRequest{
		"empty subject": {TaskID: "task-1", Payload: []byte("payload")},
		"empty task id": {Subject: "trueopen.output-avail.task-1", Payload: []byte("payload")},
		"empty payload": {Subject: "trueopen.output-avail.task-1", TaskID: "task-1"},
	} {
		t.Run(name, func(t *testing.T) {
			err := publisher.Publish(context.Background(), req)
			if err == nil {
				t.Fatalf("Publish() error = nil, want validation error")
			}
			if IsRetryable(err) {
				t.Fatalf("Publish() error = %v, want non-retryable validation error", err)
			}
		})
	}
}

func TestLazyNATSPublisherConnectionHonorsCanceledContext(t *testing.T) {
	release := make(chan struct{})
	transport := &closableFakeNATSTransport{closed: make(chan struct{})}
	restore := replaceNATSConnectorForTest(t, func(string, string) (natsPublishTransport, error) {
		<-release
		return transport, nil
	})
	defer restore()

	lazy, err := newLazyNATSPublishTransport(NATSAuth{URL: "nats://127.0.0.1:4222", Token: ""})
	if err != nil {
		t.Fatalf("newLazyNATSPublishTransport error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := lazy.Publish(ctx, NATSMessage{Subject: "trueopen.output-avail.task-1", Data: []byte("payload"), JetStream: true}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Publish error = %v, want context.Canceled", err)
	}
	close(release)
	select {
	case <-transport.closed:
	case <-time.After(time.Second):
		t.Fatal("late NATS connection was not closed")
	}
}

func TestNATSPublisherAppliesDeterministicDedupIDs(t *testing.T) {
	payload := []byte("payload")
	first := NATSDedupID(PublishRequest{Subject: "trueopen.output-avail.task-1", TaskID: "task-1", Payload: payload})
	second := NATSDedupID(PublishRequest{Subject: "trueopen.output-avail.task-1", TaskID: "task-1", Payload: append([]byte(nil), payload...)})
	if first == "" {
		t.Fatalf("dedup id is empty")
	}
	if first != second {
		t.Fatalf("dedup id = %q then %q, want deterministic", first, second)
	}

	if first == NATSDedupID(PublishRequest{Subject: "trueopen.output-avail.task-2", TaskID: "task-1", Payload: payload}) {
		t.Fatalf("dedup id did not change when subject changed")
	}
	if first == NATSDedupID(PublishRequest{Subject: "trueopen.output-avail.task-1", TaskID: "task-2", Payload: payload}) {
		t.Fatalf("dedup id did not change when task id changed")
	}
	if first == NATSDedupID(PublishRequest{Subject: "trueopen.output-avail.task-1", TaskID: "task-1", Payload: []byte("other")}) {
		t.Fatalf("dedup id did not change when payload changed")
	}
}

func TestNATSPublisherClassifiesConnectionFailuresAsRetryable(t *testing.T) {
	restore := replaceNATSConnectorForTest(t, func(_ string, _ string) (natsPublishTransport, error) {
		return nil, errors.New("connect failed")
	})
	defer restore()

	publisher, err := NewNATSPublisher("nats://127.0.0.1:4222", "token-1")
	if err != nil {
		t.Fatalf("NewNATSPublisher() error = %v", err)
	}
	err = publisher.Publish(context.Background(), PublishRequest{
		Subject: "trueopen.output-avail.task-1",
		TaskID:  "task-1",
		Payload: []byte("payload"),
	})
	if err == nil || !IsRetryable(err) {
		t.Fatalf("Publish() error = %v, want retryable connection error", err)
	}
}

func TestNATSPublisherClassifiesAckFailuresAsRetryable(t *testing.T) {
	publisher := natsPublisher{transport: &fakeNATSTransport{err: errors.New("ack failed")}}
	err := publisher.Publish(context.Background(), PublishRequest{
		Subject: "trueopen.output-avail.task-1",
		TaskID:  "task-1",
		Payload: []byte("payload"),
	})
	if err == nil || !IsRetryable(err) {
		t.Fatalf("Publish() error = %v, want retryable ack error", err)
	}
}

func TestNATSSubscriberSubjects(t *testing.T) {
	for name, tc := range map[string]struct {
		got  string
		want string
	}{
		"task open":           {NATSTaskOpenSubject("model-1"), "trueopen.task.open.model-1"},
		"worker raise":        {NATSWorkerHandraiseSubject("task-1"), "trueopen.handraise.worker.task-1"},
		"verify open":         {NATSVerifyOpenSubject("task-1"), "trueopen.verify.open.task-1"},
		"verifier raise":      {NATSVerifierHandraiseSubject("task-1"), "trueopen.handraise.verifier.task-1"},
		"worker assignment":   {NATSWorkerAssignmentSubject("task-1"), "trueopen.worker-assignment.task-1"},
		"output ready":        {NATSOutputAvailableSubject("task-1"), "trueopen.output-avail.task-1"},
		"verifier assignment": {NATSVerifierAssignmentSubject("task-1"), "trueopen.verifier-assignment.task-1"},
		"verify result":       {NATSVerifyResultSubject("task-1"), "trueopen.verify-result.task-1"},
		"model registration":  {NATSModelRegistrationSubject("reg-1"), "trueopen.model-registration.reg-1"},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("subject = %q, want %q", tc.got, tc.want)
			}
			if err := ValidateNATSSubscribeSubject(tc.got); err != nil {
				t.Fatalf("ValidateNATSSubscribeSubject(%q) error = %v", tc.got, err)
			}
		})
	}

	for _, subject := range []string{"", "trueopen.task.open.", "trueopen.worker-assignment."} {
		t.Run("reject "+subject, func(t *testing.T) {
			if err := ValidateNATSSubscribeSubject(subject); err == nil {
				t.Fatalf("ValidateNATSSubscribeSubject(%q) error = nil, want error", subject)
			}
		})
	}
}

func TestNATSPublisherSelectsProtocolDeliveryTier(t *testing.T) {
	fake := &fakeNATSTransport{}
	publisher := natsPublisher{transport: fake}

	for _, tc := range []struct {
		subject   string
		jetStream bool
	}{
		{NATSWorkerHandraiseSubject("task-1"), false},
		{NATSVerifierHandraiseSubject("task-1"), false},
		{NATSOutputAvailableSubject("task-1"), true},
		{NATSVerifyResultSubject("task-1"), true},
	} {
		if err := publisher.Publish(context.Background(), PublishRequest{Subject: tc.subject, TaskID: "task-1", Payload: []byte("payload")}); err != nil {
			t.Fatalf("Publish(%s) error = %v", tc.subject, err)
		}
		got := fake.published[len(fake.published)-1]
		if got.JetStream != tc.jetStream {
			t.Fatalf("Publish(%s) JetStream = %v, want %v", tc.subject, got.JetStream, tc.jetStream)
		}
		if !tc.jetStream && got.Header.Get(natsDedupHeader) != "" {
			t.Fatalf("core Publish(%s) unexpectedly set dedup header", tc.subject)
		}
	}
}

func TestNATSDurableNameIsStableAndSafe(t *testing.T) {
	first := NATSDurableName("trueopen1node/VERIFIER", "trueopen.output-avail.*")
	second := NATSDurableName("trueopen1node/VERIFIER", "trueopen.output-avail.*")
	if first == "" || first != second {
		t.Fatalf("durable names = %q and %q, want stable non-empty value", first, second)
	}
	if strings.ContainsAny(first, ".*>/\\ ") {
		t.Fatalf("durable name %q contains NATS-unsafe characters", first)
	}
	if first == NATSDurableName("trueopen1other/VERIFIER", "trueopen.output-avail.*") {
		t.Fatalf("durable name did not bind node identity")
	}
}

func TestJetStreamSubscribeBindsToACortexOwnedConsumer(t *testing.T) {
	// nats.Bind is the whole fix: a consumer nats.go created itself is deleted
	// on Unsubscribe (nats.go@v1.37.0 js.go:1858-1861), so nats.Durable here
	// would destroy the ack position on every readiness blip.
	kinds := subOptKinds(t, jetStreamSubscribeOptions("TRUEOPEN_TASK", "existing-durable"))
	if !kinds["Bind"] || !kinds["ManualAck"] {
		t.Fatalf("subscribe options = %v, want Bind and ManualAck", kinds)
	}
	if kinds["Durable"] {
		t.Fatal("subscribe options still ask nats.go to create the durable, which makes it delete the consumer on Unsubscribe")
	}
	// Every field named through a SubOpt is compared against the server's
	// consumer at bind time, so anything extra is a new rolling-upgrade failure
	// mode. Adding one requires an upgrade-compatibility review.
	if len(kinds) != 2 {
		t.Fatalf("subscribe options = %v, want exactly Bind and ManualAck", kinds)
	}
	if jetStreamNakDelay <= 0 {
		t.Fatalf("jetStreamNakDelay = %s, want positive backoff", jetStreamNakDelay)
	}
}

func TestJetStreamConsumerConfigMatchesWhatExistingDurablesHold(t *testing.T) {
	cfg := jetStreamConsumerConfig("cortex_trueopen1node_beef", "trueopen.output-avail.*")
	// AddConsumer runs on every restart and nats.go rejects a stated field that
	// differs from the server's consumer, so this must describe exactly what a
	// durable created by the old subscribe path already holds.
	if cfg.Durable != "cortex_trueopen1node_beef" || cfg.FilterSubject != "trueopen.output-avail.*" {
		t.Fatalf("consumer config identity = %q/%q", cfg.Durable, cfg.FilterSubject)
	}
	if cfg.DeliverPolicy != nats.DeliverAllPolicy || cfg.AckPolicy != nats.AckExplicitPolicy {
		t.Fatalf("consumer config policies = %v/%v, want DeliverAll and AckExplicit", cfg.DeliverPolicy, cfg.AckPolicy)
	}
	// A push subscribe refuses a consumer without a deliver subject
	// (js.go processConsInfo returns ErrPullSubscribeRequired).
	if cfg.DeliverSubject == "" {
		t.Fatal("consumer config has no deliver subject, so the created consumer would be a pull consumer")
	}
	if cfg.MaxDeliver != 0 {
		t.Fatalf("consumer config MaxDeliver = %d, want unset: existing consumers hold the server default and a different value makes nats.go reject the bind", cfg.MaxDeliver)
	}
}

// A readiness blip stops the workload, which unsubscribes every subscription.
// The durable's ack position has to survive that: it is the only thing that
// keeps the next start from replaying the stream's whole retention window.
func TestJetStreamStopPreservesDurableAckPosition(t *testing.T) {
	const subject = "trueopen.output-avail.*"
	js := newFakeJetStream(t, "TRUEOPEN_TASK", "trueopen1node")
	subscriber := newTestJetStreamSubscriber(t, js)

	first, err := subscriber.Subscribe(context.Background(), subject, func(context.Context, NATSMessage) error { return nil })
	if err != nil {
		t.Fatalf("first Subscribe() error = %v", err)
	}
	if got := js.deliverFrom(subject); got != 1 {
		t.Fatalf("first start delivers from sequence %d, want 1 for a new consumer", got)
	}
	// The node worked through the retention window and acked it.
	js.ackThrough(subject, 42)

	if err := first.Unsubscribe(); err != nil {
		t.Fatalf("Unsubscribe() error = %v", err)
	}
	if _, ok := js.consumers[js.durableFor(subject)]; !ok {
		t.Fatal("Unsubscribe deleted the durable consumer, so the ack position is gone")
	}

	if _, err := subscriber.Subscribe(context.Background(), subject, func(context.Context, NATSMessage) error { return nil }); err != nil {
		t.Fatalf("second Subscribe() error = %v", err)
	}
	if got := js.deliverFrom(subject); got != 43 {
		t.Fatalf("second start delivers from sequence %d, want 43: the stop must not reset the durable's ack position", got)
	}
}

// AddConsumer runs on every node restart, so an existing consumer whose
// configuration matches has to be accepted without disturbing its position.
func TestJetStreamConsumerCreationIsIdempotentAcrossRestarts(t *testing.T) {
	const subject = "trueopen.worker-assignment.*"
	js := newFakeJetStream(t, "TRUEOPEN_TASK", "trueopen1node")
	subscriber := newTestJetStreamSubscriber(t, js)

	for restart := range 3 {
		sub, err := subscriber.Subscribe(context.Background(), subject, func(context.Context, NATSMessage) error { return nil })
		if err != nil {
			t.Fatalf("Subscribe() on restart %d error = %v", restart, err)
		}
		if err := sub.Unsubscribe(); err != nil {
			t.Fatalf("Unsubscribe() on restart %d error = %v", restart, err)
		}
	}
	if js.addCalls != 3 {
		t.Fatalf("AddConsumer calls = %d, want one per start", js.addCalls)
	}
	if len(js.consumers) != 1 {
		t.Fatalf("consumers = %d, want the same durable reused across restarts", len(js.consumers))
	}
}

// A node that was hard-killed leaves behind the durable the OLD build's
// library-created subscribe made — same name, a configuration Cortex never
// authored, and a live ack position. The first start of this build must adopt
// it, not fail closed on it: failing closed would need an operator to delete
// the consumer, and deleting it is exactly what loses the ack position.
func TestJetStreamAdoptsADurableLeftByTheLibraryCreatedSubscribe(t *testing.T) {
	const subject = "trueopen.output-avail.*"
	js := newFakeJetStream(t, "TRUEOPEN_TASK", "trueopen1node")
	durable := js.durableFor(subject)
	// Exactly what nats.go@v1.37.0 creates from the previous option set
	// (Durable, ManualAck, AckExplicit, DeliverAll): the sentinels normalized at
	// js.go:1720-1730, its own random inbox, and server defaults for everything
	// the options never named.
	js.consumers[durable] = &fakeJetStreamConsumer{
		name: durable,
		cfg: nats.ConsumerConfig{
			Durable:        durable,
			FilterSubject:  subject,
			DeliverSubject: "_INBOX.libraryCreated.1",
			DeliverPolicy:  nats.DeliverAllPolicy,
			AckPolicy:      nats.AckExplicitPolicy,
			ReplayPolicy:   nats.ReplayInstantPolicy,
			MaxDeliver:     -1,
			AckWait:        30 * time.Second,
			MaxAckPending:  1000,
		},
		ackFloor: 517,
	}
	subscriber := newTestJetStreamSubscriber(t, js)

	if _, err := subscriber.Subscribe(context.Background(), subject, func(context.Context, NATSMessage) error { return nil }); err != nil {
		t.Fatalf("Subscribe() error = %v, want the surviving durable to be adopted with no operator step", err)
	}
	if got := js.deliverFrom(subject); got != 518 {
		t.Fatalf("delivery resumed at sequence %d, want 518: adopting the durable must keep its ack position", got)
	}
	if js.consumers[durable].cfg.DeliverSubject != "_INBOX.libraryCreated.1" {
		t.Fatal("AddConsumer rewrote the surviving consumer instead of returning it")
	}
}

// A durable this node cannot bind must name the operator action. Recreating it
// silently would drop the ack position this path exists to preserve.
func TestJetStreamConflictingConsumerConfigIsActionable(t *testing.T) {
	const subject = "trueopen.verify-result.*"
	js := newFakeJetStream(t, "TRUEOPEN_TASK", "trueopen1node")
	durable := js.durableFor(subject)
	js.consumers[durable] = &fakeJetStreamConsumer{
		name: durable,
		cfg: nats.ConsumerConfig{
			Durable:       durable,
			FilterSubject: subject,
			DeliverPolicy: nats.DeliverAllPolicy,
			AckPolicy:     nats.AckNonePolicy,
		},
	}
	subscriber := newTestJetStreamSubscriber(t, js)

	_, err := subscriber.Subscribe(context.Background(), subject, func(context.Context, NATSMessage) error { return nil })
	if err == nil {
		t.Fatal("Subscribe() succeeded against a conflicting durable")
	}
	if IsRetryable(err) {
		t.Fatalf("Subscribe() error = %v, want a permanent configuration error", err)
	}
	for _, want := range []string{durable, "TRUEOPEN_TASK", "conflicting configuration", "nats consumer info"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Subscribe() error = %v, want it to mention %q", err, want)
		}
	}
}

func TestJetStreamMissingStreamNamesTheConfigKey(t *testing.T) {
	js := newFakeJetStream(t, "SOME_OTHER_STREAM", "trueopen1node")
	subscriber := newTestJetStreamSubscriber(t, js)

	_, err := subscriber.Subscribe(context.Background(), "trueopen.worker-assignment.*", func(context.Context, NATSMessage) error { return nil })
	if err == nil || IsRetryable(err) {
		t.Fatalf("Subscribe() error = %v, want a permanent missing-stream error", err)
	}
	if !strings.Contains(err.Error(), "nexus.jetstream_stream") {
		t.Fatalf("Subscribe() error = %v, want it to name the config key to fix", err)
	}
}

// Binding needs the stream by name and nothing resolves it from a subject any
// more, so a subscriber without one must not exist at all.
func TestNewNATSSubscriberRequiresJetStreamStream(t *testing.T) {
	for _, stream := range []string{"", "   "} {
		if _, err := NewNATSSubscriber("nats://127.0.0.1:4222", "", stream); err == nil {
			t.Fatalf("NewNATSSubscriber(stream=%q) succeeded, want a fail-closed error", stream)
		} else if !strings.Contains(err.Error(), "nexus.jetstream_stream") {
			t.Fatalf("NewNATSSubscriber(stream=%q) error = %v, want it to name the config key", stream, err)
		}
	}
}

func newTestJetStreamSubscriber(t *testing.T, js jetStreamContext) Subscriber {
	t.Helper()
	restoreConn := replaceNATSSubscriberConnectorForTest(t, func(string, string) (*nats.Conn, error) {
		// An opaque handle: jetStreamContextFor below never looks at it.
		return &nats.Conn{}, nil
	})
	t.Cleanup(restoreConn)
	previous := jetStreamContextFor
	jetStreamContextFor = func(*nats.Conn) (jetStreamContext, error) { return js, nil }
	t.Cleanup(func() { jetStreamContextFor = previous })

	subscriber, err := NewNATSSubscriber("nats://127.0.0.1:4222", "", "TRUEOPEN_TASK", "trueopen1node")
	if err != nil {
		t.Fatalf("NewNATSSubscriber() error = %v", err)
	}
	return subscriber
}

// subOptKinds names the nats.SubOpt constructors a subscribe call carried.
// nats.Bind and nats.Durable are indistinguishable by type — both are closures
// over the same unexported function type — so identify them by the constructor
// they were built from. An option that resolves to no known constructor fails
// the test rather than quietly reporting "no Bind".
func subOptKinds(t *testing.T, opts []nats.SubOpt) map[string]bool {
	t.Helper()
	kinds := make(map[string]bool, len(opts))
	for i, opt := range opts {
		symbol := runtime.FuncForPC(reflect.ValueOf(opt).Pointer()).Name()
		matched := ""
		for _, kind := range []string{"BindStream", "Bind", "Durable", "ManualAck", "AckExplicit", "AckAll", "AckNone", "DeliverAll", "DeliverNew", "DeliverLast", "MaxDeliver", "MaxAckPending", "AckWait", "SkipConsumerLookup"} {
			if strings.Contains(symbol, "."+kind+".") {
				matched = kind
				break
			}
		}
		if matched == "" {
			t.Fatalf("sub option %d resolved to symbol %q, which matches no known nats.SubOpt constructor", i, symbol)
		}
		kinds[matched] = true
	}
	return kinds
}

// fakeJetStream models the pinned nats.go@v1.37.0 push-subscribe semantics this
// change depends on, so a stop/start cycle is exercisable without a broker:
//
//   - AddConsumer returns the existing consumer when the stated configuration
//     matches and ErrConsumerNameAlreadyInUse when it does not (jsm.go:432-460).
//   - A subscribe that only names a durable creates the consumer when it is
//     absent (js.go:1701-1704) and records that the library owns it
//     (js.go:1858-1861), so Unsubscribe deletes it (js.go:2131).
//   - A subscribe that binds never creates: a missing consumer is an error
//     (js.go:1682-1687) and Unsubscribe only unbinds.
type fakeJetStream struct {
	t             *testing.T
	stream        string
	durablePrefix string
	consumers     map[string]*fakeJetStreamConsumer
	addCalls      int
}

type fakeJetStreamConsumer struct {
	name     string
	cfg      nats.ConsumerConfig
	ackFloor uint64
	// owned mirrors nats.go's jsi.dc: a consumer the library created is deleted
	// server-side when the subscription goes away.
	owned         bool
	bound         bool
	deliveredFrom uint64
}

func newFakeJetStream(t *testing.T, stream string, durablePrefix string) *fakeJetStream {
	t.Helper()
	return &fakeJetStream{t: t, stream: stream, durablePrefix: durablePrefix, consumers: map[string]*fakeJetStreamConsumer{}}
}

func (f *fakeJetStream) durableFor(subject string) string {
	return NATSDurableName(f.durablePrefix, subject)
}

func (f *fakeJetStream) AddConsumer(stream string, cfg *nats.ConsumerConfig) (*nats.ConsumerInfo, error) {
	f.t.Helper()
	if stream != f.stream {
		return nil, nats.ErrStreamNotFound
	}
	f.addCalls++
	existing, ok := f.consumers[cfg.Durable]
	if !ok {
		f.consumers[cfg.Durable] = &fakeJetStreamConsumer{name: cfg.Durable, cfg: *cfg}
		return &nats.ConsumerInfo{Stream: stream, Name: cfg.Durable, Config: *cfg}, nil
	}
	if field := fakeConsumerConflict(existing.cfg, *cfg); field != "" {
		return nil, fmt.Errorf("%w: %s differs on consumer %q", nats.ErrConsumerNameAlreadyInUse, field, cfg.Durable)
	}
	return &nats.ConsumerInfo{Stream: stream, Name: existing.name, Config: existing.cfg}, nil
}

func (f *fakeJetStream) Subscribe(subject string, _ nats.MsgHandler, opts ...nats.SubOpt) (Subscription, error) {
	f.t.Helper()
	kinds := subOptKinds(f.t, opts)
	name := f.durableFor(subject)
	consumer := f.consumers[name]
	switch {
	case kinds["Bind"]:
		if consumer == nil {
			return nil, nats.ErrConsumerNotFound
		}
	case kinds["Durable"]:
		if consumer == nil {
			consumer = &fakeJetStreamConsumer{
				name:  name,
				cfg:   nats.ConsumerConfig{Durable: name, FilterSubject: subject, DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy},
				owned: true,
			}
			f.consumers[name] = consumer
		}
	default:
		return nil, fmt.Errorf("subscribe on %q named neither a durable nor a bound consumer", subject)
	}
	if consumer.bound {
		return nil, fmt.Errorf("consumer is already bound to a subscription")
	}
	consumer.bound = true
	consumer.deliveredFrom = consumer.ackFloor + 1
	return fakeJetStreamSubscription{js: f, name: name}, nil
}

// deliverFrom is the stream sequence the consumer's current binding started
// from: ackFloor+1 for a surviving durable, 1 for one that had to be recreated.
func (f *fakeJetStream) deliverFrom(subject string) uint64 {
	f.t.Helper()
	consumer, ok := f.consumers[f.durableFor(subject)]
	if !ok {
		f.t.Fatalf("no consumer exists for %q", subject)
	}
	return consumer.deliveredFrom
}

func (f *fakeJetStream) ackThrough(subject string, sequence uint64) {
	f.t.Helper()
	consumer, ok := f.consumers[f.durableFor(subject)]
	if !ok {
		f.t.Fatalf("no consumer exists for %q", subject)
	}
	consumer.ackFloor = sequence
}

// fakeConsumerConflict mirrors nats.go checkConfig (js.go:1466-1524) over the
// fields Cortex states. An unset field is not compared, which is exactly why
// leaving MaxDeliver alone keeps a rolling upgrade working.
func fakeConsumerConflict(server nats.ConsumerConfig, requested nats.ConsumerConfig) string {
	switch {
	case requested.Durable != "" && requested.Durable != server.Durable:
		return "durable"
	case requested.DeliverPolicy != server.DeliverPolicy:
		return "deliver policy"
	case requested.AckPolicy != server.AckPolicy:
		return "ack policy"
	case requested.ReplayPolicy != server.ReplayPolicy:
		return "replay policy"
	case requested.AckWait > 0 && requested.AckWait != server.AckWait:
		return "ack wait"
	case requested.MaxDeliver > 0 && requested.MaxDeliver != server.MaxDeliver:
		return "max deliver"
	case requested.MaxAckPending > 0 && requested.MaxAckPending != server.MaxAckPending:
		return "max ack pending"
	}
	return ""
}

type fakeJetStreamSubscription struct {
	js   *fakeJetStream
	name string
}

func (s fakeJetStreamSubscription) Unsubscribe() error {
	consumer, ok := s.js.consumers[s.name]
	if !ok {
		return nil
	}
	consumer.bound = false
	if consumer.owned {
		delete(s.js.consumers, s.name)
	}
	return nil
}

func TestNATSSubscriberReportsHandlerErrors(t *testing.T) {
	subscriber := &natsSubscriber{errCh: make(chan error, 1)}
	handlerErr := errors.New("db failed")

	subscriber.handleMessage(context.Background(), "trueopen.worker-assignment.task-1", func(context.Context, NATSMessage) error {
		return handlerErr
	}, &nats.Msg{Subject: "trueopen.worker-assignment.task-1", Data: []byte("payload")})

	select {
	case err := <-subscriber.Errors():
		if !errors.Is(err, handlerErr) {
			t.Fatalf("reported error = %v, want %v", err, handlerErr)
		}
	case <-time.After(time.Second):
		t.Fatalf("handler error was not reported")
	}
}

func replaceNATSPublisherConnectorForTest(t *testing.T, connector func(string, string) (natsPublishTransport, error)) func() {
	t.Helper()
	old := newNATSPublishTransport
	newNATSPublishTransport = func(auth NATSAuth) (natsPublishTransport, error) { return connector(auth.URL, auth.Token) }
	return func() {
		newNATSPublishTransport = old
	}
}

func replaceNATSConnectorForTest(t *testing.T, connector func(string, string) (natsPublishTransport, error)) func() {
	t.Helper()
	old := connectNATSPublishTransport
	connectNATSPublishTransport = func(auth NATSAuth) (natsPublishTransport, error) { return connector(auth.URL, auth.Token) }
	return func() {
		connectNATSPublishTransport = old
	}
}

func replaceNATSSubscriberConnectorForTest(t *testing.T, connector func(string, string) (*nats.Conn, error)) func() {
	t.Helper()
	old := connectNATSSubscriber
	connectNATSSubscriber = func(auth NATSAuth) (*nats.Conn, error) { return connector(auth.URL, auth.Token) }
	return func() {
		connectNATSSubscriber = old
	}
}

// A full error buffer used to discard reports silently, so a burst of handler
// failures looked like no failures at all. The loss must itself be reported.
func TestNATSSubscriberReportsDroppedErrorCount(t *testing.T) {
	subscriber := &natsSubscriber{}
	errs := subscriber.Errors()

	// Fill the 16-slot buffer, then overflow it.
	for i := 0; i < cap(subscriber.errCh); i++ {
		subscriber.reportError(fmt.Errorf("buffered %d", i))
	}
	for i := 0; i < 5; i++ {
		subscriber.reportError(fmt.Errorf("dropped %d", i))
	}

	// Draining a buffered error is enough for the consumer to discover the
	// summary; no later producer callback is required.
	<-errs
	if dropped := subscriber.TakeDroppedErrors(); dropped != 5 {
		t.Fatalf("TakeDroppedErrors() = %d, want 5 without a later report", dropped)
	}
}

func TestNATSDedupIDPrefersCallerSuppliedDedupID(t *testing.T) {
	withDedupID := NATSDedupID(PublishRequest{
		Subject: "trueopen.output-avail.task-1",
		TaskID:  "task-1",
		Payload: []byte("payload"),
		DedupID: "output-available:task-1:output-hash-1",
	})
	withSameDedupID := NATSDedupID(PublishRequest{
		Subject: "trueopen.output-avail.task-1",
		TaskID:  "task-1",
		Payload: []byte("different-payload"),
		DedupID: "output-available:task-1:output-hash-1",
	})
	if withDedupID != withSameDedupID {
		t.Fatalf("dedup id changed when only payload changed: %q vs %q", withDedupID, withSameDedupID)
	}

	withDifferentDedupID := NATSDedupID(PublishRequest{
		Subject: "trueopen.output-avail.task-1",
		TaskID:  "task-1",
		Payload: []byte("payload"),
		DedupID: "output-available:task-1:output-hash-2",
	})
	if withDedupID == withDifferentDedupID {
		t.Fatal("dedup id did not change when DedupID changed")
	}
}

func TestStableDedupIDHelpers(t *testing.T) {
	a := OutputAvailableDedupID("task-1", "output-1")
	b := OutputAvailableDedupID("task-1", "output-1")
	if a != b {
		t.Fatalf("OutputAvailableDedupID not stable: %q vs %q", a, b)
	}
	if a == OutputAvailableDedupID("task-1", "output-2") {
		t.Fatal("OutputAvailableDedupID did not change when output hash changed")
	}

	wh := WorkerHandraiseDedupID("task-1", "digest-1")
	wh2 := WorkerHandraiseDedupID("task-1", "digest-1")
	if wh != wh2 {
		t.Fatalf("WorkerHandraiseDedupID not stable: %q vs %q", wh, wh2)
	}

	vh := VerifierHandraiseDedupID("task-1", 3, "digest-1")
	vh2 := VerifierHandraiseDedupID("task-1", 3, "digest-1")
	if vh != vh2 {
		t.Fatalf("VerifierHandraiseDedupID not stable: %q vs %q", vh, vh2)
	}
	if vh == VerifierHandraiseDedupID("task-1", 4, "digest-1") {
		t.Fatal("VerifierHandraiseDedupID did not change when round changed")
	}
}

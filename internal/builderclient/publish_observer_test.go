package builderclient

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/TrueOpen/wire/bus"

	"google.golang.org/protobuf/proto"
)

type failingPublisher struct {
	err      error
	received PublishRequest
}

func (p *failingPublisher) Publish(_ context.Context, req PublishRequest) error {
	p.received = req
	return p.err
}

func handraiseEnvelopeBytes(t *testing.T, taskID string, messageID string) []byte {
	t.Helper()
	payload, err := proto.Marshal(testWorkerHandraisePayload(taskID))
	if err != nil {
		t.Fatal(err)
	}
	digest := bus.PayloadDigest(payload)
	nonce := bytes.Repeat([]byte{0x01}, 32)
	encoded, err := EncodeBusEnvelope(BusEnvelope{
		SchemaVersion: 1, ChainID: "chain-1", Subject: NATSWorkerHandraiseSubject(taskID),
		Kind: KindWorkerHandraise, SenderParticipantType: ParticipantCortex,
		SenderOperatorAddress: "worker-1", ServiceAuthorizationNonce: 23,
		MessageID: messageID, Nonce: nonce,
		IssuedAtUnixMs: 1_700_000_000_000, ExpiresAtUnixMs: 1_700_000_030_000,
		PayloadDigest: digest[:], Payload: payload, Signature: bytes.Repeat([]byte{0x02}, 64),
	})
	if err != nil {
		t.Fatalf("EncodeBusEnvelope: %v", err)
	}
	return encoded
}

// TestObservedPublisherReportsTheCorrelationFieldsOfADeliveredMessage pins the
// outbound counterpart of the inbox completion record: a successful publish is
// otherwise silent, so "did this node send the handraise" can only be answered
// by elimination.
func TestObservedPublisherReportsTheCorrelationFieldsOfADeliveredMessage(t *testing.T) {
	inner := &recordingPublisher{}
	var completions []PublishCompletion
	publisher := NewObservedPublisher(inner, func(completion PublishCompletion) {
		completions = append(completions, completion)
	})
	payload := handraiseEnvelopeBytes(t, "task-1", "01a01a8e-6a23-76d7-a839-0a1b6c7d4e5f")

	if err := publisher.Publish(context.Background(), PublishRequest{
		Subject: NATSWorkerHandraiseSubject("task-1"), TaskID: "task-1",
		Payload: payload, DedupID: "dedup-1",
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if !bytes.Equal(inner.payload, payload) {
		t.Fatal("the observed publisher did not forward the exact payload")
	}
	if len(completions) != 1 {
		t.Fatalf("completions = %d, want 1", len(completions))
	}
	completion := completions[0]
	switch {
	case completion.Subject != NATSWorkerHandraiseSubject("task-1"):
		t.Fatalf("subject = %q", completion.Subject)
	case completion.TaskID != "task-1":
		t.Fatalf("task = %q", completion.TaskID)
	case completion.Kind != KindWorkerHandraise:
		t.Fatalf("kind = %q, want %q", completion.Kind, KindWorkerHandraise)
	case completion.MessageID != "01a01a8e-6a23-76d7-a839-0a1b6c7d4e5f":
		t.Fatalf("message_id = %q; without it a published frame cannot be matched to the peer's log", completion.MessageID)
	case completion.DedupID != "dedup-1":
		t.Fatalf("dedup_id = %q", completion.DedupID)
	case completion.SizeBytes != len(payload):
		t.Fatalf("bytes = %d, want %d", completion.SizeBytes, len(payload))
	case completion.JetStream:
		t.Fatal("jetstream = true for a Core-tier handraise subject")
	case completion.Result != PublishResultPublished:
		t.Fatalf("result = %q, want %q", completion.Result, PublishResultPublished)
	case completion.Err != nil:
		t.Fatalf("err = %v on a delivered message", completion.Err)
	}
}

// TestObservedPublisherReportsAFailedPublishWithoutSwallowingIt keeps the
// decorator out of the error path: the caller's retry classification is what
// decides whether the inbox acknowledges, so it must reach the caller unchanged.
func TestObservedPublisherReportsAFailedPublishWithoutSwallowingIt(t *testing.T) {
	cause := errors.New("nats: no responders")
	inner := &failingPublisher{err: Retryable(cause)}
	var completions []PublishCompletion
	publisher := NewObservedPublisher(inner, func(completion PublishCompletion) {
		completions = append(completions, completion)
	})

	err := publisher.Publish(context.Background(), PublishRequest{
		Subject: NATSWorkerHandraiseSubject("task-1"), TaskID: "task-1",
		Payload: handraiseEnvelopeBytes(t, "task-1", "message-1"), DedupID: "dedup-1",
	})

	if !errors.Is(err, cause) {
		t.Fatalf("Publish error = %v, want the inner cause", err)
	}
	if !IsRetryable(err) {
		t.Fatal("the observed publisher dropped the retryable classification")
	}
	if len(completions) != 1 {
		t.Fatalf("completions = %d, want 1", len(completions))
	}
	if completions[0].Result != PublishResultFailed {
		t.Fatalf("result = %q, want %q", completions[0].Result, PublishResultFailed)
	}
	if !errors.Is(completions[0].Err, cause) {
		t.Fatalf("completion err = %v, want the inner cause", completions[0].Err)
	}
}

// TestObservedPublisherFallsBackToTheSubjectTableForAnUndecodableFrame keeps the
// record useful for the payloads that are not §5.2 envelopes at all, such as the
// model-registration frames Cortex publishes off-contract.
func TestObservedPublisherFallsBackToTheSubjectTableForAnUndecodableFrame(t *testing.T) {
	inner := &recordingPublisher{}
	var completion PublishCompletion
	publisher := NewObservedPublisher(inner, func(reported PublishCompletion) { completion = reported })

	if err := publisher.Publish(context.Background(), PublishRequest{
		Subject: NATSVerifyResultSubject("task-1"), TaskID: "task-1",
		Payload: []byte("not an envelope"), DedupID: "dedup-1",
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if completion.Kind != KindVerifyResult {
		t.Fatalf("kind = %q, want the subject table's %q", completion.Kind, KindVerifyResult)
	}
	if completion.TaskID != "task-1" {
		t.Fatalf("task = %q, want the request's task", completion.TaskID)
	}
	if !completion.JetStream {
		t.Fatal("jetstream = false for a JetStream-tier verify-result subject")
	}
	if completion.MessageID != "" {
		t.Fatalf("message_id = %q invented for a frame that carries none", completion.MessageID)
	}
}

// TestNewObservedPublisherWithoutAnObserverReturnsThePublisherUnchanged keeps the
// readiness probe and the Close path reachable: both are optional interfaces
// type-asserted on the publisher value, and a decorator would hide them.
func TestNewObservedPublisherWithoutAnObserverReturnsThePublisherUnchanged(t *testing.T) {
	inner := &recordingPublisher{}
	if got := NewObservedPublisher(inner, nil); got != Publisher(inner) {
		t.Fatalf("NewObservedPublisher(inner, nil) = %T, want the inner publisher itself", got)
	}
	if got := NewObservedPublisher(nil, func(PublishCompletion) {}); got != nil {
		t.Fatalf("NewObservedPublisher(nil, observer) = %T, want nil so the missing-publisher refusal survives", got)
	}
}

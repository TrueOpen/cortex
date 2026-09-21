package outbox

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	busv1 "github.com/SingaXYZ/cortex/proto/bus/v1"
	bustaskv1 "github.com/SingaXYZ/cortex/proto/task/v1"
	"github.com/TrueOpen/wire/bus"
)

// orderBroadcastFrame mints a shape-valid V2 ORDER_BROADCAST frame. The inbox
// only decodes for the completion record; authentication belongs to the
// processor, so the signature bytes are placeholders.
func orderBroadcastFrame(t *testing.T, modelID, messageID string) []byte {
	t.Helper()
	payload, err := proto.Marshal(&busv1.OrderBroadcastV1{
		SignedOrder: &bustaskv1.SignedOrderV2{
			Order:           &bustaskv1.TaskOrderV2{SchemaVersion: 2, ChainId: "chain-1", ModelId: modelID},
			SignatureScheme: "eip712",
			UserSignature:   append(bytes.Repeat([]byte{0x01}, 64), 27),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := bus.PayloadDigest(payload)
	frame, err := builderclient.EncodeBusEnvelope(builderclient.BusEnvelope{
		SchemaVersion: builderclient.BusEnvelopeSchemaVersion, ChainID: "chain-1",
		Subject:                   builderclient.NATSTaskOpenSubject(modelID),
		Kind:                      builderclient.KindOrderBroadcast,
		SenderParticipantType:     builderclient.ParticipantBuilder,
		SenderOperatorAddress:     "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc",
		ServiceAuthorizationNonce: 1, MessageID: messageID,
		Nonce:          bytes.Repeat([]byte{0x02}, 32),
		IssuedAtUnixMs: 1_700_000_000_000, ExpiresAtUnixMs: 4_102_444_800_000,
		Payload: payload, PayloadDigest: digest[:],
		Signature: bytes.Repeat([]byte{0x03}, 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

type fakeSubscriber struct {
	subjects []string
	handlers []builderclient.MessageHandler
}

func (s *fakeSubscriber) Subscribe(_ context.Context, subject string, handler builderclient.MessageHandler) (builderclient.Subscription, error) {
	s.subjects = append(s.subjects, subject)
	s.handlers = append(s.handlers, handler)
	return fakeSubscription{}, nil
}

type fakeSubscription struct{}

func (fakeSubscription) Unsubscribe() error { return nil }

func TestInboxRunnerProcessesBeforeAcknowledgingAndDeduplicatesSuccess(t *testing.T) {
	sub := &fakeSubscriber{}
	calls := 0
	r := NewInboxRunner(sub, InboxRunnerConfig{ModelIDs: []string{"model"}, Process: func(context.Context, builderclient.NATSMessage) error { calls++; return nil }})
	if _, err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	msg := builderclient.NATSMessage{Subject: builderclient.NATSTaskOpenSubject("model"), Data: []byte("frame"), JetStream: true}
	if err := sub.handlers[0](context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if err := sub.handlers[0](context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d, want 1", calls)
	}
}

func TestInboxRunnerReportsSuccessfulMessageCompletion(t *testing.T) {
	sub := &fakeSubscriber{}
	var completions []InboxMessageCompletion
	r := NewInboxRunner(sub, InboxRunnerConfig{
		ModelIDs: []string{"model"},
		Process:  func(context.Context, builderclient.NATSMessage) error { return nil },
		OnCompletion: func(completion InboxMessageCompletion) {
			completions = append(completions, completion)
		},
	})
	if _, err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A V2 wire frame: the completion record is derived at decode, so this frame
	// doubles as a check that the decoder reads the fields the log reports.
	data := orderBroadcastFrame(t, "model", "message-1")
	msg := builderclient.NATSMessage{Subject: builderclient.NATSTaskOpenSubject("model"), Data: data, JetStream: true}
	if err := sub.handlers[0](context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if len(completions) != 1 {
		t.Fatalf("completions = %#v, want one successful completion", completions)
	}
	got := completions[0]
	if got.Subject != "trueopen.task.open.model" || got.Kind != builderclient.KindOrderBroadcast || got.MessageID != "message-1" {
		t.Fatalf("completion identity = %#v", got)
	}
	if !got.JetStream || got.SizeBytes != len(data) || got.Result != InboxMessageResultProcessed || got.Duration <= 0 {
		t.Fatalf("completion delivery = %#v", got)
	}
}

func TestInboxRunnerReportsDeduplicatedMessageCompletion(t *testing.T) {
	sub := &fakeSubscriber{}
	processCalls := 0
	var completions []InboxMessageCompletion
	r := NewInboxRunner(sub, InboxRunnerConfig{
		ModelIDs: []string{"model"},
		Process: func(context.Context, builderclient.NATSMessage) error {
			processCalls++
			return nil
		},
		OnCompletion: func(completion InboxMessageCompletion) {
			completions = append(completions, completion)
		},
	})
	if _, err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A v1 wire body: 0x hex for every byte string, plain integers, the OPEN_TASK
	// kind (interface-and-topic-list.md §5.1/§5.2). The completion record is derived at
	// decode, so this frame doubles as a check that the decoder reads the fields
	// the log reports.
	data := []byte(`{"schema_version":1,"chain_id":"chain-1","subject":"trueopen.task.open.model","kind":"OPEN_TASK","sender_participant_type":"BUILDER","sender_operator_address":"builder-1","service_authorization_nonce":1,"sender_role":"BUILDER","session_id":"session-1","task_id":"task-1","builder_set_id":"1","builder_set_hash":"0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a","stage":"OPEN_TASK","source_snapshot_height":1,"message_id":"message-1","nonce":"0x01","issued_at_unix_ms":1700000000000,"expires_at_unix_ms":4102444800000,"payload_codec":"trueopen-cjson-v1","payload_digest":"0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a","payload":{},"signature":"0x01"}`)
	msg := builderclient.NATSMessage{Subject: builderclient.NATSTaskOpenSubject("model"), Data: data}
	if err := sub.handlers[0](context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	completions = nil
	if err := sub.handlers[0](context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if processCalls != 1 {
		t.Fatalf("process calls = %d, want the duplicate skipped", processCalls)
	}
	if len(completions) != 1 || completions[0].Result != InboxMessageResultDeduplicated {
		t.Fatalf("duplicate completions = %#v", completions)
	}
}

func TestInboxRunnerRetryableFailureUsesSourceRedelivery(t *testing.T) {
	sub := &fakeSubscriber{}
	calls := 0
	transient := errors.New("builder unavailable")
	r := NewInboxRunner(sub, InboxRunnerConfig{TaskIDs: []string{"task"}, Process: func(context.Context, builderclient.NATSMessage) error {
		calls++
		if calls == 1 {
			return builderclient.Retryable(transient)
		}
		return nil
	}})
	_, _ = r.Start(context.Background())
	msg := builderclient.NATSMessage{Subject: builderclient.NATSWorkerAssignmentSubject("task"), Data: []byte("frame"), JetStream: true}
	if err := sub.handlers[0](context.Background(), msg); !errors.Is(err, transient) {
		t.Fatalf("first error=%v", err)
	}
	if err := sub.handlers[0](context.Background(), msg); err != nil {
		t.Fatalf("redelivery error=%v", err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d, want 2", calls)
	}
}

func TestInboxRunnerPermanentRefusalIsMemoryOnlyAndAcknowledged(t *testing.T) {
	sub := &fakeSubscriber{}
	calls := 0
	perm := errors.New("invalid signature")
	var refused error
	var completions []InboxMessageCompletion
	r := NewInboxRunner(sub, InboxRunnerConfig{
		TaskIDs: []string{"task"},
		Process: func(context.Context, builderclient.NATSMessage) error {
			calls++
			return perm
		},
		Refuse:       func(err error) { refused = err },
		OnCompletion: func(completion InboxMessageCompletion) { completions = append(completions, completion) },
	})
	_, _ = r.Start(context.Background())
	msg := builderclient.NATSMessage{Subject: builderclient.NATSWorkerAssignmentSubject("task"), Data: []byte("bad")}
	if err := sub.handlers[0](context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if refused == nil || !errors.Is(refused, perm) {
		t.Fatalf("reported %v, want the permanent refusal wrapped so the ack is not silent", refused)
	}
	if !strings.Contains(refused.Error(), msg.Subject) {
		t.Fatalf("reported %q, want the subject so the log is greppable", refused)
	}
	if err := sub.handlers[0](context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d, want 1", calls)
	}
	if len(completions) != 0 {
		t.Fatalf("completions = %#v, want a permanently refused frame to stay out of successful completion logs", completions)
	}
}

func TestInboxRunnerNeverAcknowledgesMissingAuthenticatorOrRecognizedVerifierFailure(t *testing.T) {
	for _, testCase := range []struct {
		name, subject string
		err           error
	}{
		{name: "missing authenticator", subject: builderclient.NATSTaskOpenSubject("model"), err: builderclient.ErrBusEnvelopeAuthenticationUnavailable},
		{name: "output available", subject: builderclient.NATSOutputAvailableSubject("task"), err: errors.New("verifier admission unavailable")},
		{name: "verify select", subject: builderclient.NATSVerifierAssignmentSubject("task"), err: errors.New("verifier checkpoint unavailable")},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			sub := &fakeSubscriber{}
			r := NewInboxRunner(sub, InboxRunnerConfig{ModelIDs: []string{"model"}, TaskIDs: []string{"task"}, Process: func(context.Context, builderclient.NATSMessage) error { return testCase.err }})
			_, _ = r.Start(context.Background())
			for i, subject := range sub.subjects {
				if subject != testCase.subject {
					continue
				}
				if err := sub.handlers[i](context.Background(), builderclient.NATSMessage{Subject: subject, Data: []byte("frame"), JetStream: true}); !errors.Is(err, testCase.err) {
					t.Fatalf("handler error = %v, want %v so JetStream NAKs", err, testCase.err)
				}
				return
			}
			t.Fatalf("subject %q was not subscribed: %v", testCase.subject, sub.subjects)
		})
	}
}

// The sibling test above fixes that an *unmarked* verifier failure NAKs, because
// a verifier frame commonly races ahead of the chain state it needs. A refusal
// that can never succeed is the opposite case: redelivering it is not caution,
// it is a loop, so an asserted permanent verdict has to outrank the subject.
func TestInboxAcknowledgesAssertedPermanentRefusalOnVerifierFrames(t *testing.T) {
	for _, subject := range []string{
		builderclient.NATSOutputAvailableSubject("task"),
		builderclient.NATSVerifierAssignmentSubject("task"),
	} {
		t.Run(subject, func(t *testing.T) {
			conflict := errors.New("record conflict: verify.OutputCID")
			calls := 0
			var refused error
			sub := &fakeSubscriber{}
			r := NewInboxRunner(sub, InboxRunnerConfig{
				ModelIDs: []string{"model"}, TaskIDs: []string{"task"},
				Process: func(context.Context, builderclient.NATSMessage) error {
					calls++
					return builderclient.Permanent(conflict)
				},
				Refuse: func(err error) { refused = err },
			})
			_, _ = r.Start(context.Background())
			for i, subscribed := range sub.subjects {
				if subscribed != subject {
					continue
				}
				msg := builderclient.NATSMessage{Subject: subject, Data: []byte("frame"), JetStream: true}
				if err := sub.handlers[i](context.Background(), msg); err != nil {
					t.Fatalf("handler error = %v, want nil so JetStream acks instead of redelivering forever", err)
				}
				if refused == nil || !errors.Is(refused, conflict) {
					t.Fatalf("reported %v, want the conflict reported so the ack is not silent", refused)
				}
				if err := sub.handlers[i](context.Background(), msg); err != nil {
					t.Fatal(err)
				}
				if calls != 1 {
					t.Fatalf("calls = %d, want the refused frame remembered rather than reprocessed", calls)
				}
				return
			}
			t.Fatalf("subject %q was not subscribed: %v", subject, sub.subjects)
		})
	}
}

// Duty selection is retired, so the subject set is no longer conditional. This
// is the regression that stranded a devnet: two nodes configured
// duties: [WORKER] subscribed only to trueopen.worker-assignment.*, so the
// trueopen.output-avail.* and trueopen.verify.open.* frames that trigger a Verifier
// handraise reached nobody, the handraise window expired, and the chain swept
// every task as TASK_FAILURE_CLASS_INSUFFICIENT_VERIFIER.
func TestInboxSubjectsCoverBothResponsibilitiesForEveryNode(t *testing.T) {
	subjects := InboxSubjects(InboxRunnerConfig{ModelIDs: []string{"model"}, TaskIDs: []string{"task"}})

	for _, want := range []string{
		builderclient.NATSTaskOpenSubject("model"),
		builderclient.NATSWorkerAssignmentSubject("task"),
		builderclient.NATSOutputAvailableSubject("task"),
		builderclient.NATSVerifyOpenSubject("task"),
		builderclient.NATSVerifierAssignmentSubject("task"),
	} {
		if !slices.Contains(subjects, want) {
			t.Fatalf("subjects = %v, missing %q", subjects, want)
		}
	}
}

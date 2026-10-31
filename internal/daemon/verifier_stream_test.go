package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/store"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

// stubBuilderKeys serves Builder current service keys by operator.
type stubBuilderKeys struct {
	mu   sync.Mutex
	keys map[string]chainclient.ServiceKeySnapshot
	err  error
}

func newStubBuilderKeys(builders ...string) *stubBuilderKeys {
	keys := map[string]chainclient.ServiceKeySnapshot{}
	for _, b := range builders {
		keys[b] = chainclient.ServiceKeySnapshot{ParticipantType: chainclient.ParticipantTypeBuilder, OperatorAddress: b, AuthorizationNonce: 1, Status: "ACTIVE"}
	}
	return &stubBuilderKeys{keys: keys}
}

func (s *stubBuilderKeys) CommittedCurrentServiceKey(_ context.Context, participant, operator string) (chainclient.ServiceKeySnapshot, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if participant != chainclient.ParticipantTypeBuilder {
		return chainclient.ServiceKeySnapshot{}, 0, fmt.Errorf("binding check read a %s key", participant)
	}
	if s.err != nil {
		return chainclient.ServiceKeySnapshot{}, 0, s.err
	}
	k, ok := s.keys[operator]
	if !ok {
		return chainclient.ServiceKeySnapshot{}, 0, chainclient.ErrNotFound
	}
	return k, 100, nil
}

func vsStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func vsOpenVerify(builder string) *nexusv1.OpenVerifyV1 {
	return &nexusv1.OpenVerifyV1{
		TaskId: bytes.Repeat([]byte{0x11}, 32), TaskHash: bytes.Repeat([]byte{0x22}, 32), ModelId: bytes.Repeat([]byte{0x01}, 32),
		ProfileVersion: 1, InferReceiptHash: bytes.Repeat([]byte{0x33}, 32), OutputHash: bytes.Repeat([]byte{0x44}, 32),
		WorkerOperatorAddress: "worker-1", VerifyRound: 1,
		Binding: &nexusv1.BuilderMessageBindingV1{ChainId: "chain", BuilderAddress: builder, ServiceAuthorizationNonce: 1},
	}
}

func openVerifyFrame(m *nexusv1.OpenVerifyV1) *nexusv1.DispatchStreamFrameV1 {
	return &nexusv1.DispatchStreamFrameV1{Cursor: 1, Message: &nexusv1.DispatchStreamFrameV1_OpenVerify{OpenVerify: m}}
}

func assignmentFrame(m *nexusv1.VerifierAssignmentNotifyV1) *nexusv1.DispatchStreamFrameV1 {
	return &nexusv1.DispatchStreamFrameV1{Cursor: 1, Message: &nexusv1.DispatchStreamFrameV1_VerifierAssignment{VerifierAssignment: m}}
}

type vsHarness struct {
	stream    *VerifierStream
	keys      *stubBuilderKeys
	inbox     verifierInbox
	wakes     atomic.Int32
	applied   atomic.Int32
	assignErr error
}

func newVSHarness(t *testing.T) *vsHarness {
	t.Helper()
	h := &vsHarness{keys: newStubBuilderKeys("builder-1", "builder-2")}
	db := vsStore(t)
	h.inbox = verifierInbox{st: db}
	stream, err := NewVerifierStream(VerifierStreamConfig{
		ChainID: "chain", Chain: h.keys, Store: db,
		Assignment: func(context.Context, *nexusv1.VerifierAssignmentNotifyV1) error {
			h.applied.Add(1)
			return h.assignErr
		},
		Wake: func() { h.wakes.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	h.stream = stream
	return h
}

var vsTaskID = hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32))

func TestVerifierStreamChecksTheBuilderMessageBinding(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate    func(*nexusv1.OpenVerifyV1, *stubBuilderKeys)
		retryable bool
	}{
		"missing binding": {func(m *nexusv1.OpenVerifyV1, _ *stubBuilderKeys) { m.Binding = nil }, false},
		"other chain":     {func(m *nexusv1.OpenVerifyV1, _ *stubBuilderKeys) { m.Binding.ChainId = "other" }, false},
		"other Builder":   {func(m *nexusv1.OpenVerifyV1, _ *stubBuilderKeys) { m.Binding.BuilderAddress = "builder-2" }, false},
		"stale nonce":     {func(m *nexusv1.OpenVerifyV1, _ *stubBuilderKeys) { m.Binding.ServiceAuthorizationNonce = 2 }, false},
		"unknown Builder": {func(_ *nexusv1.OpenVerifyV1, k *stubBuilderKeys) { delete(k.keys, "builder-1") }, false},
		"revoked key": {func(_ *nexusv1.OpenVerifyV1, k *stubBuilderKeys) {
			key := k.keys["builder-1"]
			key.Status = "REVOKED"
			k.keys["builder-1"] = key
		}, false},
		"chain unreadable": {func(_ *nexusv1.OpenVerifyV1, k *stubBuilderKeys) { k.err = errors.New("rpc down") }, true},
	} {
		t.Run(name, func(t *testing.T) {
			h := newVSHarness(t)
			m := vsOpenVerify("builder-1")
			tc.mutate(m, h.keys)
			err := h.stream.HandleFrame(context.Background(), "builder-1", openVerifyFrame(m))
			if err == nil || builderclient.IsRetryable(err) != tc.retryable {
				t.Fatalf("error = %v, want retryable=%v", err, tc.retryable)
			}
			if !tc.retryable && !errors.Is(err, ErrBuilderMessageBinding) {
				t.Fatalf("error = %v, want ErrBuilderMessageBinding", err)
			}
			if _, ok, _ := h.inbox.load(context.Background(), vsTaskID, 1); ok || h.wakes.Load() != 0 {
				t.Fatal("a frame failing the binding check reached the inbox")
			}
		})
	}
}

// CD §6.2 V1: the same (task_id, verify_round) from several Builders is applied once.
func TestVerifierStreamAppliesOpenVerifyOncePerTaskRound(t *testing.T) {
	h := newVSHarness(t)
	ctx := context.Background()
	for _, delivery := range []string{"builder-1", "builder-2", "builder-1"} {
		if err := h.stream.HandleFrame(ctx, delivery, openVerifyFrame(vsOpenVerify(delivery))); err != nil {
			t.Fatalf("delivery from %s: %v", delivery, err)
		}
	}
	if h.wakes.Load() != 1 {
		t.Fatalf("wakes = %d, want one for the first delivery only", h.wakes.Load())
	}
	entry, ok, err := h.inbox.load(ctx, vsTaskID, 1)
	if err != nil || !ok {
		t.Fatalf("inbox entry = %v, %v", ok, err)
	}
	if entry.State != inboxPending || len(entry.Builders) != 2 || entry.Builders[0] != "builder-1" || entry.Builders[1] != "builder-2" {
		t.Fatalf("entry = %+v, want one pending trigger seen from both Builders in arrival order", entry)
	}
	if entry.Trigger.DataReadyBuilderOperator != "builder-1" {
		t.Fatalf("trigger = %+v, want the first Builder as the data-ready one", entry.Trigger)
	}
}

// A shape-invalid OPEN_VERIFY is a permanent refusal and is never recorded.
func TestVerifierStreamRefusesAMalformedOpenVerify(t *testing.T) {
	h := newVSHarness(t)
	m := vsOpenVerify("builder-1")
	m.VerifyRound = 2
	err := h.stream.HandleFrame(context.Background(), "builder-1", openVerifyFrame(m))
	if err == nil || builderclient.IsRetryable(err) {
		t.Fatalf("error = %v, want a permanent refusal", err)
	}
	if _, ok, _ := h.inbox.load(context.Background(), vsTaskID, 2); ok {
		t.Fatal("a malformed OPEN_VERIFY reached the inbox")
	}
}

func TestVerifierStreamAppliesAnAssignmentNoticeOnceAndNeverHoldsTheStream(t *testing.T) {
	h := newVSHarness(t)
	ctx := context.Background()
	notice := &nexusv1.VerifierAssignmentNotifyV1{
		TaskId: bytes.Repeat([]byte{0x11}, 32), VerifyRound: 1,
		Binding: &nexusv1.BuilderMessageBindingV1{ChainId: "chain", BuilderAddress: "builder-1", ServiceAuthorizationNonce: 1},
	}
	h.assignErr = builderclient.Retryable(errors.New("local verify record not there yet"))
	if err := h.stream.HandleFrame(ctx, "builder-1", assignmentFrame(notice)); err != nil {
		t.Fatalf("a retryable hint returned %v, want it acked: the Keeper effect is the authority", err)
	}
	h.assignErr = nil
	for range 2 {
		if err := h.stream.HandleFrame(ctx, "builder-1", assignmentFrame(notice)); err != nil {
			t.Fatal(err)
		}
	}
	if h.applied.Load() != 2 {
		t.Fatalf("applications = %d, want the failed one plus exactly one success", h.applied.Load())
	}
}

func TestVerifierStreamRefusesOtherVariants(t *testing.T) {
	h := newVSHarness(t)
	frame := &nexusv1.DispatchStreamFrameV1{Cursor: 1, Message: &nexusv1.DispatchStreamFrameV1_Revoke{Revoke: &nexusv1.DispatchRevokeV1{}}}
	if err := h.stream.HandleFrame(context.Background(), "builder-1", frame); err == nil || builderclient.IsRetryable(err) {
		t.Fatalf("error = %v, want a permanent refusal", err)
	}
}

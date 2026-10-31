package dispatchstream

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/TrueOpen/cortex/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestOutboxReplaysUnackedUnexpiredInOrderWithIdenticalBytes(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ob := newOutbox(st, "trueopen1builder", slog.Default())
	a := pending{Variant: variantAccept, Payload: []byte{1}, ExpiresAtUnixMilli: 2_000}
	b := pending{Variant: variantHandraise, Payload: []byte{2}, ExpiryHeight: 50}
	c := pending{Variant: variantVerifierHandraise, Payload: []byte{3}, ExpiryHeight: 500}
	var seqs []uint64
	for _, p := range []pending{a, b, c} {
		seq, err := ob.put(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, seq)
	}
	if !(seqs[0] < seqs[1] && seqs[1] < seqs[2]) {
		t.Fatalf("seqs must increase: %v", seqs)
	}
	got, err := ob.replayable(ctx, 1_500 /*nowMs*/, 60 /*height*/, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !bytes.Equal(got[0].Payload, []byte{1}) || !bytes.Equal(got[1].Payload, []byte{3}) {
		t.Fatalf("want a then c (b expired by height), got %+v", got)
	}
	if got[0].Variant != variantAccept || got[1].Variant != variantVerifierHandraise || got[1].ExpiryHeight != 500 {
		t.Fatalf("record fields not preserved: %+v", got)
	}
	if err := ob.done(ctx, got[0].Seq); err != nil {
		t.Fatal(err)
	}
	got, err = ob.replayable(ctx, 1_500, 60, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Seq != seqs[2] || !bytes.Equal(got[0].Payload, []byte{3}) {
		t.Fatalf("after done(a) only c remains, got %+v", got)
	}
	// Wall-clock expiry: a is gone already; c survives any time.
	if got, _ := ob.replayable(ctx, 1_000_000, 60, 0); len(got) != 1 {
		t.Fatalf("height-bound c must ignore the clock, got %+v", got)
	}
}

func TestOutboxIsScopedPerBuilderAndSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	one, two := newOutbox(st, "trueopen1b", slog.Default()), newOutbox(st, "trueopen1bb", slog.Default())
	if _, err := one.put(ctx, pending{Variant: variantAccept, Payload: []byte{1}, ExpiryHeight: 9}); err != nil {
		t.Fatal(err)
	}
	if _, err := two.put(ctx, pending{Variant: variantAccept, Payload: []byte{2}, ExpiryHeight: 9}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	one = newOutbox(st, "trueopen1b", slog.Default())
	got, err := one.replayable(ctx, 0, 1, 0)
	if err != nil || len(got) != 1 || !bytes.Equal(got[0].Payload, []byte{1}) {
		t.Fatalf("builder scoping or durability broken: %+v %v", got, err)
	}
	seq, err := one.put(ctx, pending{Variant: variantAccept, Payload: []byte{3}, ExpiryHeight: 9})
	if err != nil || seq <= got[0].Seq {
		t.Fatalf("seq must keep increasing across reopen: %d after %d (%v)", seq, got[0].Seq, err)
	}
}

func TestOutboxRefusesAmbiguousExpiry(t *testing.T) {
	ob := newOutbox(newTestStore(t), "trueopen1builder", slog.Default())
	for _, p := range []pending{
		{Variant: variantAccept, Payload: []byte{1}},
		{Variant: variantAccept, Payload: []byte{1}, ExpiryHeight: 1, ExpiresAtUnixMilli: 1},
	} {
		if _, err := ob.put(context.Background(), p); err == nil {
			t.Fatalf("exactly one expiry bound is required: %+v", p)
		}
	}
}

func TestOutboxPruneDropsOnlyExpired(t *testing.T) {
	ctx := context.Background()
	ob := newOutbox(newTestStore(t), "trueopen1builder", slog.Default())
	for _, p := range []pending{
		{Variant: variantAccept, Payload: []byte{1}, ExpiresAtUnixMilli: 10},
		{Variant: variantAccept, Payload: []byte{2}, ExpiryHeight: 5},
		{Variant: variantAccept, Payload: []byte{3}, ExpiryHeight: 7},
	} {
		if _, err := ob.put(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := ob.prune(ctx, 10, 6); err != nil {
		t.Fatal(err)
	}
	var left [][]byte
	_ = ob.st.ScanPrefix(ctx, ob.prefix, func(_, v []byte) error { left = append(left, v); return nil })
	if len(left) != 1 || !bytes.Contains(left[0], []byte(`"expiry_height":7`)) {
		t.Fatalf("only the height-7 message survives height 6, got %q", left)
	}
}

func TestOutboxQuarantinesCorruptRecord(t *testing.T) {
	ctx := context.Background()
	ob := newOutbox(newTestStore(t), "trueopen1builder", slog.Default())
	for i := byte(1); i <= 3; i++ {
		if _, err := ob.put(ctx, pending{Variant: variantAccept, Payload: []byte{i}, ExpiryHeight: 9}); err != nil {
			t.Fatal(err)
		}
	}
	if err := ob.st.PutRaw(ctx, ob.key(2), []byte("{corrupt")); err != nil {
		t.Fatal(err)
	}
	got, err := ob.replayable(ctx, 0, 1, 0)
	if err != nil || len(got) != 2 || got[0].Seq != 1 || got[1].Seq != 3 {
		t.Fatalf("corrupt record must be skipped, not fatal: %+v %v", got, err)
	}
	if countPrefix(t, ob.st, outboxBadPrefix+"trueopen1builder/") != 1 {
		t.Fatal("corrupt record not quarantined")
	}
	if _, err := ob.st.GetRaw(ctx, ob.key(2)); err == nil {
		t.Fatal("corrupt record left in the live outbox")
	}
}

func TestOutboxReplayableResumesAfterSeq(t *testing.T) {
	ctx := context.Background()
	ob := newOutbox(newTestStore(t), "trueopen1builder", slog.Default())
	for i := byte(1); i <= 3; i++ {
		if _, err := ob.put(ctx, pending{Variant: variantAccept, Payload: []byte{i}, ExpiryHeight: 9}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ob.replayable(ctx, 0, 1, 2)
	if err != nil || len(got) != 1 || got[0].Seq != 3 {
		t.Fatalf("want only seq 3, got %+v %v", got, err)
	}
}

func TestOutboxPruneIsBatched(t *testing.T) {
	ctx := context.Background()
	ob := newOutbox(newTestStore(t), "trueopen1builder", slog.Default())
	ob.batch = 2
	for i := byte(1); i <= 5; i++ {
		if _, err := ob.put(ctx, pending{Variant: variantAccept, Payload: []byte{i}, ExpiryHeight: uint64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := ob.prune(ctx, 0, 4); err != nil {
		t.Fatal(err)
	}
	got, _ := ob.replayable(ctx, 0, 0, 0)
	if len(got) != 2 || got[0].ExpiryHeight != 4 || got[1].ExpiryHeight != 5 {
		t.Fatalf("want heights 4 and 5 left, got %+v", got)
	}
}

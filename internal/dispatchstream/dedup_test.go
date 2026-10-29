package dispatchstream

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

type testClock struct{ ms atomic.Int64 }

func (c *testClock) now() time.Time          { return time.UnixMilli(c.ms.Load()) }
func (c *testClock) advance(d time.Duration) { c.ms.Add(d.Milliseconds()) }

func newTestDedup(t *testing.T, builder string, clk *testClock) *dedup {
	t.Helper()
	return newDedup(newTestStore(t), builder, time.Hour, clk.now, slog.Default())
}

// A corrupt record is overwritten by mark without its old index entry being
// found; when that stale index entry expires, prune must drop only the index
// entry and leave the live record alone.
func TestDedupPruneKeepsLiveRecordBehindStaleIndex(t *testing.T) {
	ctx := context.Background()
	clk := &testClock{}
	clk.ms.Store(1_000_000)
	d := newTestDedup(t, "trueopen1b", clk)
	key := d.key(variantRevoke, [32]byte{1})
	stale := clk.now().UnixMilli() + 10
	if err := d.st.PutRaw(ctx, key, []byte("{corrupt")); err != nil {
		t.Fatal(err)
	}
	if err := d.st.PutRaw(ctx, d.expiryKey(stale, key), nil); err != nil {
		t.Fatal(err)
	}
	if err := d.mark(ctx, key, stateDone); err != nil {
		t.Fatal(err)
	}
	clk.advance(time.Second) // past the stale stamp, well before the live one
	if err := d.prune(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, err := d.delivered(ctx, key); err != nil || !ok {
		t.Fatalf("the live done record was pruned through a stale index entry (%v %v)", ok, err)
	}
	if n := countPrefix(t, d.st, string(d.indexPrefix)); n != 1 {
		t.Fatalf("want only the live index entry left, got %d", n)
	}
}

func TestDedupCorruptRecordIsNotDone(t *testing.T) {
	ctx := context.Background()
	clk := &testClock{}
	d := newTestDedup(t, "trueopen1b", clk)
	key := d.key(variantRevoke, [32]byte{2})
	if err := d.st.PutRaw(ctx, key, []byte("{corrupt")); err != nil {
		t.Fatal(err)
	}
	if ok, err := d.delivered(ctx, key); err != nil || ok {
		t.Fatalf("a corrupt record must redeliver: %v %v", ok, err)
	}
}

func TestDedupPruneIsPerBuilderAndBatched(t *testing.T) {
	ctx := context.Background()
	clk := &testClock{}
	clk.ms.Store(1_000_000)
	st := newTestStore(t)
	a := newDedup(st, "trueopen1a", time.Hour, clk.now, slog.Default())
	b := newDedup(st, "trueopen1ab", time.Hour, clk.now, slog.Default())
	a.batch = 2
	for i := byte(0); i < 5; i++ {
		if err := a.mark(ctx, a.key(variantRevoke, [32]byte{i}), stateDone); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.mark(ctx, b.key(variantRevoke, [32]byte{9}), stateDone); err != nil {
		t.Fatal(err)
	}
	clk.advance(2 * time.Hour)
	if err := a.prune(ctx); err != nil {
		t.Fatal(err)
	}
	if n := countPrefix(t, st, dedupPrefix+"trueopen1a/"); n != 0 {
		t.Fatalf("batched prune left %d of builder a's records", n)
	}
	if n := countPrefix(t, st, dedupPrefix+"trueopen1ab/"); n != 1 {
		t.Fatalf("builder a's prune touched builder ab's records (%d left)", n)
	}
}

package daemon

import (
	"context"
	"testing"

	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

func TestDispatchLeasesBoundCapacityAndAnswerFreeSlots(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	l, err := NewDispatchLeases(ctx, st, 2)
	if err != nil {
		t.Fatal(err)
	}
	lease := func(b byte) layout.WorkerLease {
		return layout.WorkerLease{TicketHash: layout.StoredHash{b}, TaskID: layout.StoredHash{b}, Builder: hrBuilderA, ExpiryHeight: 9}
	}
	free := func(l *DispatchLeases, want uint32) {
		t.Helper()
		if n, ok := l.FreeSlots(); !ok || n != want {
			t.Fatalf("free = %d %v, want %d", n, ok, want)
		}
	}
	free(l, 2)
	for _, b := range []byte{1, 1} {
		if ok, err := l.Acquire(ctx, lease(b)); err != nil || !ok {
			t.Fatalf("acquire %d = %v, %v", b, ok, err)
		}
	}
	free(l, 1)
	if ok, err := l.Acquire(ctx, lease(2)); err != nil || !ok {
		t.Fatal("second ticket fits")
	}
	free(l, 0)
	if ok, err := l.Acquire(ctx, lease(3)); err != nil || ok {
		t.Fatal("capacity is 2")
	}
	reopened, err := NewDispatchLeases(ctx, st, 2)
	if err != nil {
		t.Fatal(err)
	}
	free(reopened, 0)
	if released, err := reopened.Release(ctx, layout.StoredHash{1}); err != nil || !released {
		t.Fatal("release 1")
	}
	free(reopened, 1)
	if released, err := reopened.Release(ctx, layout.StoredHash{1}); err != nil || released {
		t.Fatal("a second release is a no-op")
	}
	local := &fakeHandraiseLocal{ready: true, free: 9, freeOK: true}
	wrapped := WithLeaseSlots(local, reopened)
	if n, ok := wrapped.FreeSlots(ctx); !ok || n != 1 {
		t.Fatalf("wrapped free = %d %v, want the ledger's 1", n, ok)
	}
	local.with(func(f *fakeHandraiseLocal) { f.freeOK = false })
	if _, ok := wrapped.FreeSlots(ctx); ok {
		t.Fatal("a runtime that is not ready offers no slot (H3)")
	}
	if _, err := NewDispatchLeases(ctx, st, 0); err == nil {
		t.Fatal("capacity 0 is refused")
	}
}

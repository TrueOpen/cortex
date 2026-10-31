package daemon

import (
	"context"
	"testing"

	"github.com/TrueOpen/cortex/internal/store"
)

func TestHeldRootsByDigestAndHeight(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	db := handraiseStore{st: st}
	for i, hv := range [][2]uint64{{180, 1}, {185, 1}, {185, 2}, {195, 1}} {
		r := HeldRoot{Builder: hrBuilderA, RootDigest: [32]byte{byte(i + 1)}, RootHeight: hv[0], RootVersion: hv[1], ReceivedHeight: hv[0], Notice: []byte("n")}
		if _, _, err := db.putRoot(ctx, r, 1000); err != nil {
			t.Fatal(err)
		}
	}
	h := &StandingHandraiser{db: db}
	roots, err := h.RootsUpTo(ctx, hrBuilderA, 190, 10)
	if err != nil || len(roots) != 3 || roots[0].RootHeight != 185 || roots[0].RootVersion != 2 || roots[2].RootHeight != 180 {
		t.Fatalf("roots = %+v, %v: newest first, none above 190", roots, err)
	}
	if roots, _ := h.RootsUpTo(ctx, hrBuilderA, 190, 2); len(roots) != 2 || roots[1].RootVersion != 1 || roots[1].RootHeight != 185 {
		t.Fatalf("limit: %+v", roots)
	}
	if r, ok, err := h.RootByDigest(ctx, hrBuilderA, [32]byte{4}); err != nil || !ok || r.RootHeight != 195 {
		t.Fatalf("by digest = %+v, %v, %v", r, ok, err)
	}
	if _, ok, _ := h.RootByDigest(ctx, hrBuilderB, [32]byte{4}); ok {
		t.Fatal("per Builder")
	}
	if roots, _ := h.RootsUpTo(ctx, hrBuilderB, 190, 10); len(roots) != 0 {
		t.Fatal("per Builder")
	}
}

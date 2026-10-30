package daemon

import (
	"bytes"
	"context"
	"testing"

	"github.com/TrueOpen/cortex/internal/store"
)

func openHandraiseTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestHandraiseStoreSendLog(t *testing.T) {
	ctx := context.Background()
	s := handraiseStore{st: openHandraiseTestStore(t)}
	if cur, err := s.loadCurrent(ctx, "b1"); err != nil || cur != nil {
		t.Fatalf("empty store: %v %v", cur, err)
	}
	cur := CurrentHandraise{IssuedHeight: 100, Nonce: 2, ExpiryHeight: 115, Digest: [32]byte{1}, SentAtUnixMs: 5}
	if err := s.recordSend(ctx, "b1", cur, sentHandraise{IssuedHeight: 100, ExpiryHeight: 115, Nonce: 2, Raw: []byte{9}}, 10); err != nil {
		t.Fatal(err)
	}
	got, err := s.loadCurrent(ctx, "b1")
	if err != nil || got == nil || got.Nonce != 2 || got.Digest != cur.Digest {
		t.Fatalf("loadCurrent = %+v %v", got, err)
	}
	for _, c := range []struct {
		builder string
		digest  [32]byte
		want    bool
	}{{"b1", [32]byte{1}, true}, {"b2", [32]byte{1}, false}, {"b1", [32]byte{2}, false}} {
		if ok, err := s.hasSent(ctx, c.builder, c.digest); err != nil || ok != c.want {
			t.Fatalf("hasSent(%s, %x) = %v %v", c.builder, c.digest[0], ok, err)
		}
	}
	// Kept through expiry_height + retention = 125, gone after.
	if err := pruneAll(ctx, s, 125); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.hasSent(ctx, "b1", [32]byte{1}); !ok {
		t.Fatal("pruned before its retention ended")
	}
	if err := pruneAll(ctx, s, 126); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.hasSent(ctx, "b1", [32]byte{1}); ok {
		t.Fatal("kept past retention")
	}
}

func TestHandraiseStoreRoots(t *testing.T) {
	ctx := context.Background()
	s := handraiseStore{st: openHandraiseTestStore(t)}
	root := func(h, v uint64, tag byte) HeldRoot {
		return HeldRoot{Builder: "b1", RootDigest: [32]byte{tag}, RootHeight: h, RootVersion: v, ReceivedHeight: 100}
	}
	put := func(r HeldRoot) (bool, bool) {
		t.Helper()
		held, stored, err := s.putRoot(ctx, r, 10)
		if err != nil {
			t.Fatal(err)
		}
		return stored, held.Equivocal
	}
	if stored, eq := put(root(200, 0, 1)); !stored || eq {
		t.Fatal("first root must be stored")
	}
	if stored, _ := put(root(200, 0, 1)); stored {
		t.Fatal("a duplicate digest must not be stored twice")
	}
	put(root(200, 1, 2))
	put(root(199, 9, 3))
	put(root(201, 0, 4))
	if stored, eq := put(root(201, 0, 5)); !stored || !eq {
		t.Fatal("a second digest at the same (root_height, root_version) is equivocation and is kept")
	}
	latest, err := s.latestRootDigests(ctx, "b1", 3)
	if err != nil {
		t.Fatal(err)
	}
	var tags []byte
	for _, d := range latest {
		tags = append(tags, d[0])
	}
	if newest, err := s.latestRoots(ctx, "b1", 1); err != nil || len(newest) != 1 || newest[0].RootDigest[0] != 4 {
		t.Fatalf("latestRoots(1) = %v %v", newest, err)
	}
	if !bytes.Equal(tags, []byte{4, 5, 2}) {
		t.Fatalf("newest-first roots %v, want [4 5 2]", tags)
	}
	if ok, _ := s.holdsRoot(ctx, "b1", [32]byte{3}); !ok {
		t.Fatal("an older retained root is still held")
	}
	if ok, _ := s.holdsRoot(ctx, "b2", [32]byte{3}); ok {
		t.Fatal("roots are per Builder")
	}
	if err := pruneAll(ctx, s, 111); err != nil { // received 100 + retention 10
		t.Fatal(err)
	}
	for tag := byte(1); tag <= 5; tag++ {
		if ok, _ := s.holdsRoot(ctx, "b1", [32]byte{tag}); ok {
			t.Fatalf("root %d kept past retention", tag)
		}
	}
	if latest, _ := s.latestRootDigests(ctx, "b1", 10); len(latest) != 0 {
		t.Fatal("the order index must be pruned with its roots")
	}
}

func TestHandraiseStorePruneDropsAMalformedIndexKey(t *testing.T) {
	ctx := context.Background()
	st := openHandraiseTestStore(t)
	s := handraiseStore{st: st}
	for _, k := range []string{hrExpiryPrefix + "garbage", hrExpiryPrefix + "00000000000000000001/x/b1/zz"} {
		if err := st.PutRaw(ctx, []byte(k), []byte{}); err != nil {
			t.Fatal(err)
		}
	}
	cur := CurrentHandraise{IssuedHeight: 1, ExpiryHeight: 2, Digest: [32]byte{1}}
	if err := s.recordSend(ctx, "b1", cur, sentHandraise{IssuedHeight: 1, ExpiryHeight: 2}, 1); err != nil {
		t.Fatal(err)
	}
	if err := pruneAll(ctx, s, 100); err != nil {
		t.Fatalf("a malformed index key must not wedge pruning: %v", err)
	}
	if ok, _ := s.hasSent(ctx, "b1", [32]byte{1}); ok {
		t.Fatal("a due send record survived next to a malformed index key")
	}
	n := 0
	if err := st.ScanPrefix(ctx, []byte(hrExpiryPrefix), func(_, _ []byte) error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d index keys left, want 0", n)
	}
}

// pruneAll runs prune batches until none is left, as successive Run ticks do.
func pruneAll(ctx context.Context, s handraiseStore, height uint64) error {
	var from []byte
	for {
		next, err := s.pruneBatch(ctx, height, from)
		if err != nil || next == nil {
			return err
		}
		from = next
	}
}

func TestHandraiseStorePrunesOneBatchPerCall(t *testing.T) {
	ctx := context.Background()
	s := handraiseStore{st: openHandraiseTestStore(t), batch: 2}
	for i := range byte(5) {
		cur := CurrentHandraise{IssuedHeight: 1, ExpiryHeight: 2, Digest: [32]byte{i + 1}}
		if err := s.recordSend(ctx, "b1", cur, sentHandraise{IssuedHeight: 1, ExpiryHeight: 2}, 1); err != nil {
			t.Fatal(err)
		}
	}
	left := func() int { return sentLogSizeOf(t, s, "b1") }
	next, err := s.pruneBatch(ctx, 100, nil)
	if err != nil || next == nil || left() != 3 {
		t.Fatalf("first batch: next=%q err=%v left=%d, want 3 left and a resume key", next, err, left())
	}
	next, _ = s.pruneBatch(ctx, 100, next)
	if next == nil || left() != 1 {
		t.Fatalf("second batch left %d", left())
	}
	if next, _ = s.pruneBatch(ctx, 100, next); next != nil || left() != 0 {
		t.Fatalf("last batch: next=%q left=%d", next, left())
	}
}

func sentLogSizeOf(t *testing.T, s handraiseStore, builder string) int {
	t.Helper()
	n := 0
	if err := s.st.ScanPrefix(context.Background(), []byte(hrSentPrefix+builder+"/"), func(_, _ []byte) error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	return n
}

// A root received late keeps the handraise it proves at least as long as
// itself.
func TestHandraiseStoreRootExtendsTheProvedHandraiseRetention(t *testing.T) {
	ctx := context.Background()
	s := handraiseStore{st: openHandraiseTestStore(t)}
	standing := [32]byte{7}
	if err := s.recordSend(ctx, "b1", CurrentHandraise{ExpiryHeight: 115, Digest: standing}, sentHandraise{ExpiryHeight: 115}, 10); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.putRoot(ctx, HeldRoot{Builder: "b1", RootDigest: [32]byte{1}, StandingDigest: standing, RootHeight: 5, ReceivedHeight: 200}, 10); err != nil {
		t.Fatal(err)
	}
	if err := pruneAll(ctx, s, 150); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.hasSent(ctx, "b1", standing); !ok {
		t.Fatal("the proved handraise was pruned before the root that proves it")
	}
	if err := pruneAll(ctx, s, 211); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.hasSent(ctx, "b1", standing); ok {
		t.Fatal("kept past the root's retention")
	}
}

func TestHandraiseStorePruneRemovesTheOrderKeyOfACorruptRoot(t *testing.T) {
	ctx := context.Background()
	s := handraiseStore{st: openHandraiseTestStore(t)}
	r := HeldRoot{Builder: "b1", RootDigest: [32]byte{1}, RootHeight: 9, RootVersion: 3, ReceivedHeight: 100}
	if _, _, err := s.putRoot(ctx, r, 10); err != nil {
		t.Fatal(err)
	}
	if err := s.st.PutRaw(ctx, hrRootKey("b1", hrDigestHex(r.RootDigest)), []byte("{corrupt")); err != nil {
		t.Fatal(err)
	}
	if err := pruneAll(ctx, s, 111); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.latestRootDigests(ctx, "b1", 10); len(d) != 0 {
		t.Fatal("the order key of a corrupt root was orphaned")
	}
}

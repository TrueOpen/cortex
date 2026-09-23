package once

import (
	"context"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(context.Background(), t.TempDir()+"/once-test")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	})
	return db
}

func TestClaimAcceptsFirstCaller(t *testing.T) {
	db := newTestStore(t)
	s := New(db)
	ctx := context.Background()
	expires := time.Now().UTC().Add(time.Minute)
	claimed, err := s.Claim(ctx, "dedup:subject:1", expires)
	if err != nil || !claimed {
		t.Fatalf("Claim() = %v, %v; want true, nil", claimed, err)
	}
	claimed, err = s.Claim(ctx, "dedup:subject:1", expires.Add(time.Hour))
	if err != nil || claimed {
		t.Fatalf("second Claim() = %v, %v; want false, nil", claimed, err)
	}
}

func TestClaimAllowsExpiredKey(t *testing.T) {
	db := newTestStore(t)
	s := New(db)
	ctx := context.Background()
	key := "dedup:subject:2"
	expires := time.Now().UTC().Add(-time.Millisecond)
	if _, err := s.Claim(ctx, key, expires); err != nil {
		t.Fatalf("initial claim: %v", err)
	}
	claimed, err := s.Claim(ctx, key, time.Now().UTC().Add(time.Minute))
	if err != nil || !claimed {
		t.Fatalf("expired re-Claim() = %v, %v; want true, nil", claimed, err)
	}
}

func TestReleaseAllowsRedelivery(t *testing.T) {
	db := newTestStore(t)
	s := New(db)
	ctx := context.Background()
	key := "dedup:subject:3"
	expires := time.Now().UTC().Add(time.Minute)
	if _, err := s.Claim(ctx, key, expires); err != nil {
		t.Fatalf("initial claim: %v", err)
	}
	if err := s.Release(ctx, key); err != nil {
		t.Fatalf("Release: %v", err)
	}
	claimed, err := s.Claim(ctx, key, expires.Add(time.Hour))
	if err != nil || !claimed {
		t.Fatalf("Claim after release = %v, %v; want true, nil", claimed, err)
	}
}

func TestNewWithNilStore(t *testing.T) {
	ctx := context.Background()
	var s *Store
	if _, err := s.Claim(ctx, "x", time.Now()); err == nil {
		t.Fatal("Claim with nil store should fail")
	}
}

// The expiry is persisted so the store can be pruned. Without a sweep every
// message id, nonce and dedup id a node ever saw stays in Pebble for the life of
// the node, and normal traffic alone makes it grow without bound.
func TestPruneRemovesOnlyExpiredClaims(t *testing.T) {
	ctx := context.Background()
	s := New(newTestStore(t))
	now := time.Now().UTC()

	if claimed, err := s.Claim(ctx, "expired", now.Add(-time.Minute)); err != nil || !claimed {
		t.Fatalf("claim expired key = %v, %v", claimed, err)
	}
	if claimed, err := s.Claim(ctx, "live", now.Add(time.Hour)); err != nil || !claimed {
		t.Fatalf("claim live key = %v, %v", claimed, err)
	}

	removed, err := s.Prune(ctx, now, 256)
	if err != nil {
		t.Fatalf("Prune returned error: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want only the expired claim", removed)
	}
	// The live claim must still refuse a replay.
	if claimed, err := s.Claim(ctx, "live", now.Add(time.Hour)); err != nil || claimed {
		t.Fatalf("live claim after prune = %v, %v; want it still held", claimed, err)
	}
}

// The whole point of a Pebble-backed claim is that a restart does not re-accept a
// replayed envelope. That is a property of reopening the database, so it has to be
// tested by reopening the database.
func TestClaimSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir() + "/once-reopen"
	expiry := time.Now().UTC().Add(time.Hour)

	db, err := store.Open(ctx, dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if claimed, err := New(db).Claim(ctx, "message-1", expiry); err != nil || !claimed {
		t.Fatalf("first claim = %v, %v", claimed, err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	reopened, err := store.Open(ctx, dir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if claimed, err := New(reopened).Claim(ctx, "message-1", expiry); err != nil || claimed {
		t.Fatalf("claim after reopen = %v, %v; want the replay refused", claimed, err)
	}
}

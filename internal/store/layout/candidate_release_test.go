package layout

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/SingaXYZ/cortex/internal/store"
)

// TestReleaseCandidateAdmissionRemovesBothRowsOfALostOrder pins the missing
// half of the candidate lifecycle.
//
// A Worker writes candidate/<taskHash> plus the candidate-current locator
// before it publishes a handraise, because a restart mid-handraise must not
// lose the signed document. Once the chain finalizes the assignment to someone
// else, that obligation is over - and nothing removed the rows. The store's key
// space is restart obligations only (CLAUDE.md), so a row for a task this node
// will never work is a leak that grows with every order it bids on and loses.
func TestReleaseCandidateAdmissionRemovesBothRowsOfALostOrder(t *testing.T) {
	ctx := context.Background()
	db := openCandidateTestStore(t)
	taskHash := StoredHash{0x11}
	admission := CandidateAdmission{
		SchemaVersion: CandidateAdmissionSchemaVersion,
		SignedOrder:   []byte("order"), HandraisePayload: []byte("handraise"), PublishTS: 5,
	}
	if err := AdmissionBatch(ctx, db, "session-1", 1, taskHash, admission); err != nil {
		t.Fatalf("AdmissionBatch() error = %v", err)
	}

	if err := ReleaseCandidateAdmission(ctx, db, "session-1", 1, taskHash); err != nil {
		t.Fatalf("ReleaseCandidateAdmission() error = %v", err)
	}
	if _, err := GetCandidateAdmission(ctx, db, taskHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetCandidateAdmission() error = %v, want the admission row gone", err)
	}
	if _, err := db.GetRaw(ctx, CandidateCurrentKey("session-1", 1)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("locator read error = %v, want the locator gone with its row", err)
	}
	// Releasing twice is how a redelivered notify behaves; it must be a no-op
	// rather than an error, or the second delivery fails on cleanup alone.
	if err := ReleaseCandidateAdmission(ctx, db, "session-1", 1, taskHash); err != nil {
		t.Fatalf("second ReleaseCandidateAdmission() error = %v, want idempotent", err)
	}
}

// The locator is keyed by (session, order) and the row by task hash, so a
// release must not take the locator out from under a NEWER candidate that
// already replaced this one at the same locator - that would orphan a live
// obligation.
func TestReleaseCandidateAdmissionKeepsALocatorThatMovedOn(t *testing.T) {
	ctx := context.Background()
	db := openCandidateTestStore(t)
	first := StoredHash{0x21}
	second := StoredHash{0x22}
	base := CandidateAdmission{SchemaVersion: CandidateAdmissionSchemaVersion, SignedOrder: []byte("order")}

	firstAdmission := base
	firstAdmission.PublishTS = 5
	if err := AdmissionBatch(ctx, db, "session-1", 1, first, firstAdmission); err != nil {
		t.Fatalf("first AdmissionBatch() error = %v", err)
	}
	secondAdmission := base
	secondAdmission.PublishTS = 9
	if err := AdmissionBatch(ctx, db, "session-1", 1, second, secondAdmission); err != nil {
		t.Fatalf("second AdmissionBatch() error = %v", err)
	}

	if err := ReleaseCandidateAdmission(ctx, db, "session-1", 1, first); err != nil {
		t.Fatalf("ReleaseCandidateAdmission() error = %v", err)
	}
	if _, err := GetCandidateAdmission(ctx, db, second); err != nil {
		t.Fatalf("GetCandidateAdmission(second) error = %v, want the live candidate untouched", err)
	}
	locator, err := db.GetRaw(ctx, CandidateCurrentKey("session-1", 1))
	if err != nil {
		t.Fatalf("locator read error = %v, want the locator of the live candidate kept", err)
	}
	if StoredHash(locator) != second {
		t.Fatalf("locator = %x, want it still pointing at the live candidate %x", locator, second)
	}
}

func openCandidateTestStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

package daemon

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/store"
)

// OPEN_VERIFY is the Verifier's discovery entry point and has to work even when the
// node holds no record of the task at all.
//
// A pure Verifier node has had no contact with the Task before this message arrives:
// trueopen.task.open.<model_id> goes only to Worker candidates, and no chain event
// creates a local record for a verification candidate. Requiring "a local verify
// record must exist" would require the node to be selected first, and being selected
// requires raising a hand first - a deadlock in which the node can never reach the
// verification stage.
//
// Keeper's QueryTask needs only the task_id and its response carries the session_id
// and the accepted task_hash, so querying the chain by task_id is enough and the
// message need not carry a session_id; the task_hash in OPEN_VERIFY's fixed fields is
// still cross-checked against the query result as a restated value.
func TestOpenVerifyHandraisesWithoutAnyLocalRecord(t *testing.T) {
	fixture := newVerifierOnlyFixture(t)

	call := fixture.openVerifyCall()
	taskHash := codec.HashBytes([]byte("accepted-task-hash"))
	call.TaskHash = append([]byte(nil), taskHash[:]...)

	if err := fixture.deliverOpenVerify(t, call); err != nil {
		t.Fatalf("a pure Verifier node was refused: %v", err)
	}
	fixture.assertHandraised(t)
}

// The task_hash in the frame is a restatement and the chain is the authority: a
// mismatch must be refused, and the frame's value must not be used as a storage key.
func TestOpenVerifyWithMismatchedTaskHashIsRefused(t *testing.T) {
	fixture := newVerifierOnlyFixture(t)

	call := fixture.openVerifyCall()
	wrong := codec.HashBytes([]byte("some-other-task-hash"))
	call.TaskHash = append([]byte(nil), wrong[:]...)
	if err := fixture.deliverOpenVerify(t, call); err == nil {
		t.Fatal("a task_hash that disagrees with the chain's accepted value must not be accepted")
	}
}

// newVerifierOnlyFixture is newOutputAvailableFixture without the local task record:
// a node that holds only the VERIFIER duty and has never seen this task.
func newVerifierOnlyFixture(t *testing.T) *outputAvailableFixture {
	t.Helper()
	fixture := newOutputAvailableFixture(t)
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "verifier-only.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	fixture.runner.cfg.Store = db
	return fixture
}

var _ = hex.EncodeToString
var _ = builderclient.KindOpenVerify

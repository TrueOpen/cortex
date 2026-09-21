package daemon

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/evidence"
	"github.com/SingaXYZ/cortex/internal/store"
	"github.com/SingaXYZ/cortex/internal/store/layout"
	"github.com/SingaXYZ/cortex/internal/worker"
)

// TestInferInputReopenWithoutCloseRecoversData uses a subprocess to open a
// Pebble database, persist an task input, and exit without closing the database.
// The parent process then reopens the same path and verifies the input is
// recoverable, exercising Pebble WAL recovery rather than assuming a clean
// shutdown.
func TestInferInputReopenWithoutCloseRecoversData(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(t.TempDir(), "cortex.kv")

	input := []byte("persisted task input")
	if err := runInferInputWriterSubprocess(t, root, path, input); err != nil {
		t.Fatalf("subprocess writer: %v", err)
	}

	idx, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen store.Open() error = %v", err)
	}
	defer idx.Close()
	evStore, err := evidence.NewStore(root, idx)
	if err != nil {
		t.Fatalf("reopen NewStore() error = %v", err)
	}
	p := &evidenceWorkerPersistence{
		taskHash: codec.HashBytes([]byte("taskhash")),
		task:     &store.InferTask{TaskID: "task-1", SessionID: "session-1"},
		evidence: evStore,
		persist:  func(_ context.Context, _ codec.Hash, _ store.InferTask, _ layout.Evidence) error { return nil },
	}
	got, err := p.InferInput(ctx, "task-1")
	if err != nil {
		t.Fatalf("InferInput after reopen: %v", err)
	}
	if !bytes.Equal(got.Payload, input) {
		t.Fatalf("InferInput() payload = %q, want %q", got.Payload, input)
	}
}

func runInferInputWriterSubprocess(t *testing.T, root, path string, input []byte) error {
	cmd := exec.Command(os.Args[0], "-test.run", "TestInferInputWriterSubprocess", "-test.v")
	cmd.Env = append(os.Environ(),
		"CORTEX_CRASH_REOPEN_ROOT="+root,
		"CORTEX_CRASH_REOPEN_PATH="+path,
		"CORTEX_CRASH_REOPEN_INPUT="+string(input),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess output:\n%s", string(out))
	}
	return nil
}

// TestInferInputWriterSubprocess is invoked by the parent test as a subprocess.
// It opens the store, persists the input, and exits without closing.
func TestInferInputWriterSubprocess(t *testing.T) {
	root := os.Getenv("CORTEX_CRASH_REOPEN_ROOT")
	path := os.Getenv("CORTEX_CRASH_REOPEN_PATH")
	input := os.Getenv("CORTEX_CRASH_REOPEN_INPUT")
	if root == "" || path == "" || input == "" {
		t.Skip("subprocess helper, run via TestInferInputReopenWithoutCloseRecoversData")
	}
	ctx := context.Background()
	idx, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	evStore, err := evidence.NewStore(root, idx)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	p := &evidenceWorkerPersistence{
		taskHash: codec.HashBytes([]byte("taskhash")),
		task:     &store.InferTask{TaskID: "task-1", SessionID: "session-1"},
		evidence: evStore,
		persist:  func(_ context.Context, _ codec.Hash, _ store.InferTask, _ layout.Evidence) error { return nil },
	}
	if err := p.CheckpointInferInput(ctx, worker.InferInputCheckpoint{TaskID: "task-1", Payload: []byte(input)}); err != nil {
		t.Fatalf("CheckpointInferInput() error = %v", err)
	}
	// Intentionally leak idx and evStore: exit without closing.
	os.Exit(0)
}

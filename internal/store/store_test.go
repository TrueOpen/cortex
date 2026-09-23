package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/cockroachdb/pebble/v2"
)

func TestBindChainIdentityFailsClosedOnAnotherChain(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cortex.kv")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.BindChainIdentity(ctx, "trueopen-localnet-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.BindChainIdentity(ctx, "trueopen-localnet-1"); err != nil {
		t.Fatalf("same-chain rebind: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	err = reopened.BindChainIdentity(ctx, "trueopen-devnet-1")
	var mismatch *ChainIdentityMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("BindChainIdentity error = %v, want ChainIdentityMismatchError", err)
	}
	if mismatch.StorePath != path || mismatch.Recorded != "trueopen-localnet-1" || mismatch.Configured != "trueopen-devnet-1" {
		t.Fatalf("mismatch = %#v", mismatch)
	}
	for _, want := range []string{path, "trueopen-localnet-1", "trueopen-devnet-1", "node.rpc_endpoint", "keep config.yaml, keystore/, secrets/ and data/evidence/"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}
	if got, err := reopened.ChainIdentity(ctx); err != nil || got != "trueopen-localnet-1" {
		t.Fatalf("ChainIdentity = %q, %v", got, err)
	}
}

func TestKeeperLastProcessedHeightOnlyAdvances(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if got, err := s.KeeperLastProcessedHeight(ctx); err != nil || got != 0 {
		t.Fatalf("initial height = (%d, %v), want (0, nil)", got, err)
	}
	if advanced, err := s.AdvanceKeeperLastProcessedHeight(ctx, 42); err != nil || !advanced {
		t.Fatalf("advance to 42 = (%v, %v), want (true, nil)", advanced, err)
	}
	for _, height := range []uint64{42, 10} {
		if advanced, err := s.AdvanceKeeperLastProcessedHeight(ctx, height); err != nil || advanced {
			t.Fatalf("advance to %d = (%v, %v), want (false, nil)", height, advanced, err)
		}
	}
	if got, err := s.KeeperLastProcessedHeight(ctx); err != nil || got != 42 {
		t.Fatalf("final height = (%d, %v), want (42, nil)", got, err)
	}
}

func TestPhysicalLayoutUsesPrefixesAndStorePathIsDirectory(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cortex.kv")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.AdvanceKeeperLastProcessedHeight(ctx, 5); err != nil {
		t.Fatalf("AdvanceKeeperLastProcessedHeight: %v", err)
	}

	iter, err := s.db.NewIter(&pebble.IterOptions{LowerBound: runtimePrefix, UpperBound: prefixUpperBound(runtimePrefix)})
	if err != nil {
		t.Fatalf("create Pebble iterator: %v", err)
	}
	defer iter.Close()
	if !iter.First() {
		t.Fatalf("expected at least one key under runtime prefix")
	}
	if !bytes.HasPrefix(iter.Key(), runtimePrefix) {
		t.Fatalf("key %x does not start with runtime prefix %x", iter.Key(), runtimePrefix)
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		t.Fatalf("store path is not a directory: (%v, %v)", info, err)
	}
}

func TestAllPublicOperationsReturnErrClosed(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	operations := []struct {
		name string
		run  func() error
	}{
		{"Ping", func() error { return s.Ping(ctx) }},
		{"KeeperLastProcessedHeight", func() error { _, err := s.KeeperLastProcessedHeight(ctx); return err }},
		{"AdvanceKeeperLastProcessedHeight", func() error { _, err := s.AdvanceKeeperLastProcessedHeight(ctx, 1); return err }},
		{"Checkpoint", func() error { return s.Checkpoint(ctx, filepath.Join(t.TempDir(), "checkpoint")) }},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.run(); !errors.Is(err, ErrClosed) {
				t.Fatalf("error = %v, want ErrClosed", err)
			}
		})
	}
}

func TestConcurrentCloseAndOperationsDoNotPanic(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	start := make(chan struct{})
	errs := make(chan error, 64)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if i%2 == 0 {
				_, err := s.KeeperLastProcessedHeight(ctx)
				errs <- err
				return
			}
			_, err := s.AdvanceKeeperLastProcessedHeight(ctx, uint64(i))
			errs <- err
		}(i)
	}
	close(start)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil && !errors.Is(err, ErrClosed) {
			t.Fatalf("operation error = %v, want nil or ErrClosed", err)
		}
	}
}

func TestConcurrentKeeperHeightRemainsMonotonic(t *testing.T) {
	s := openTestStore(t)
	var wg sync.WaitGroup
	for height := uint64(1); height <= 64; height++ {
		wg.Add(1)
		go func(height uint64) {
			defer wg.Done()
			if _, err := s.AdvanceKeeperLastProcessedHeight(context.Background(), height); err != nil {
				t.Errorf("advance: %v", err)
			}
		}(height)
	}
	wg.Wait()
	if got, err := s.KeeperLastProcessedHeight(context.Background()); err != nil || got != 64 {
		t.Fatalf("height = (%d, %v), want 64", got, err)
	}
}

func TestCloseReopenDurabilityAndNoSQLSidecars(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "cortex.kv")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.AdvanceKeeperLastProcessedHeight(ctx, 19); err != nil {
		t.Fatalf("AdvanceKeeperLastProcessedHeight: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	gotHeight, heightErr := reopened.KeeperLastProcessedHeight(ctx)
	if heightErr != nil || gotHeight != 19 {
		t.Fatalf("KeeperLastProcessedHeight after reopen = (%d, %v), want (19, nil)", gotHeight, heightErr)
	}
	if err := reopened.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("SQL sidecar %q exists or stat failed: %v", path+suffix, err)
		}
	}
}

func TestCheckpointRestoreIncludesFlushedWAL(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	s, err := Open(ctx, filepath.Join(root, "live"))
	if err != nil {
		t.Fatal(err)
	}
	hash := codec.HashBytes([]byte("checkpoint"))
	encoded, err := json.Marshal(map[string]interface{}{"schema_version": 1, "digest": codec.HashBytes([]byte("evidence-durable"))})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutRaw(ctx, []byte("evidence_"+string(hash[:])), encoded); err != nil {
		t.Fatal(err)
	}
	checkpoint := filepath.Join(root, "backup")
	if err := s.Checkpoint(ctx, checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(ctx, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	got, err := restored.GetRaw(ctx, []byte("evidence_"+string(hash[:])))
	if err != nil {
		t.Fatalf("checkpoint raw read: %v", err)
	}
	if !bytes.Equal(got, encoded) {
		t.Fatalf("checkpoint raw = %x, want %x", got, encoded)
	}
	// suppress unused
	_ = encoded
}

func TestOpenRejectsExistingSQLiteDatabaseWithCutoverGuidance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacyHeader := append([]byte("SQLite format 3\x00"), bytes.Repeat([]byte{0}, 128)...)
	if err := os.WriteFile(path, legacyHeader, 0o600); err != nil {
		t.Fatalf("write SQLite fixture: %v", err)
	}

	_, err := Open(context.Background(), path)
	if err == nil {
		t.Fatal("Open() error = nil, want explicit SQLite cutover error")
	}
	for _, want := range []string{"SQLite", "drain", "migration", "store.path", "rollback"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Open() error = %q, want cutover guidance containing %q", err, want)
		}
	}
}

func TestOpenRejectsExistingBboltDatabaseWithCutoverGuidance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.kv")
	header := make([]byte, 20)
	binary.LittleEndian.PutUint32(header[16:20], 0xED0CDAED)
	if err := os.WriteFile(path, header, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(context.Background(), path)
	if err == nil {
		t.Fatal("Open() error = nil")
	}
	for _, want := range []string{"bbolt", "drain", "store.path", "Pebble", "rollback"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Open() error = %q, want %q", err, want)
		}
	}
}

func TestOpenRejectsGenericFileAsNonDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-store")
	if err := os.WriteFile(path, []byte("plain file"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(context.Background(), path)
	if err == nil {
		t.Fatal("Open() error = nil")
	}
	for _, want := range []string{"unrecognized non-directory file", "not a Pebble directory", "store.path"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Open() error = %q, want %q", err, want)
		}
	}
}

func TestStoreBuildsWithCGODisabled(t *testing.T) {
	cmd := exec.Command("go", "test", "./internal/store", "-run=^$", "-count=1")
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("CGO_ENABLED=0 store build failed: %v\n%s", err, output)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

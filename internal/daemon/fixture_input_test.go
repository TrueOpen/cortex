package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
)

func TestFixtureTaskInputResolverReadsContentAddressedInput(t *testing.T) {
	root := t.TempDir()
	input := []byte("fixture input")
	hash := chainclient.HexHash(codec.HashBytes(input))
	if err := os.MkdirAll(filepath.Join(root, "inputs"), 0o700); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "inputs", hash.String()+".bin"), input, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	resolver, err := NewFixtureTaskInputResolver(root)
	if err != nil {
		t.Fatalf("NewFixtureTaskInputResolver error = %v", err)
	}
	got, err := resolver.ResolveTaskInput(context.Background(), TaskInputRef{
		SessionID: "session-1", TaskID: "task-1", PayloadCID: "fixture://sha256/" + hash.String(), PayloadHash: hash,
	})
	if err != nil {
		t.Fatalf("ResolveTaskInput error = %v", err)
	}
	if string(got) != string(input) {
		t.Fatalf("ResolveTaskInput = %q, want %q", got, input)
	}
}

func TestFixtureTaskInputResolverRejectsUnsafeOrMismatchedRefs(t *testing.T) {
	root := t.TempDir()
	resolver, err := NewFixtureTaskInputResolver(root)
	if err != nil {
		t.Fatalf("NewFixtureTaskInputResolver error = %v", err)
	}
	wantHash := chainclient.HexHash(codec.HashBytes([]byte("expected")))

	for name, cid := range map[string]string{
		"wrong scheme": "file:///tmp/input",
		"traversal":    "fixture://sha256/../input",
		"uppercase":    "fixture://sha256/" + strings.ToUpper(wantHash.String()),
		"wrong hash":   "fixture://sha256/" + chainclient.HexHash(codec.HashBytes([]byte("other"))).String(),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := resolver.ResolveTaskInput(context.Background(), TaskInputRef{PayloadCID: cid, PayloadHash: wantHash})
			if err == nil {
				t.Fatalf("ResolveTaskInput(%q) succeeded", cid)
			}
		})
	}
}

func TestFixtureTaskInputResolverRetriesMissingFixture(t *testing.T) {
	resolver, err := NewFixtureTaskInputResolver(t.TempDir())
	if err != nil {
		t.Fatalf("NewFixtureTaskInputResolver error = %v", err)
	}
	hash := chainclient.HexHash(codec.HashBytes([]byte("missing")))
	_, err = resolver.ResolveTaskInput(context.Background(), TaskInputRef{PayloadCID: "fixture://sha256/" + hash.String(), PayloadHash: hash})
	if err == nil || !builderclient.IsRetryable(err) {
		t.Fatalf("ResolveTaskInput missing error = %v, want retryable", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ResolveTaskInput missing error = %v, want os.ErrNotExist", err)
	}
}

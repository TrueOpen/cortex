package evidence

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
)

func TestDropNamespaceRetiresOneNamespace(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s, err := NewStore(t.TempDir(), st)
	if err != nil {
		t.Fatal(err)
	}
	keep, drop := codec.Hash{1}, codec.Hash{2}
	for _, k := range []codec.Hash{keep, drop} {
		if _, err := s.Write(ctx, WriteRequest{TaskHash: k, TaskID: "t", Kind: "worker-output-fin", Data: []byte("fin")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DropNamespace(ctx, drop); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadTaskKind(ctx, drop, "worker-output-fin"); err == nil {
		t.Fatal("the dropped namespace is gone")
	}
	if got, err := s.ReadTaskKind(ctx, keep, "worker-output-fin"); err != nil || string(got) != "fin" {
		t.Fatalf("the other namespace stays: %q, %v", got, err)
	}
	if err := s.DropNamespace(ctx, drop); err != nil {
		t.Fatal("idempotent")
	}
}

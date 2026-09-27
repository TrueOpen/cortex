package builderclient

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
)

func TestFixtureOutputPackageStoreSharesCanonicalPackage(t *testing.T) {
	root := t.TempDir()
	producer, err := NewFixtureOutputPackageStore(root)
	if err != nil {
		t.Fatalf("NewFixtureOutputPackageStore producer error = %v", err)
	}
	consumer, err := NewFixtureOutputPackageStore(root)
	if err != nil {
		t.Fatalf("NewFixtureOutputPackageStore consumer error = %v", err)
	}
	pkg := OutputPackage{
		SessionID: "session-1", TaskID: "task-1", ModelID: "model-1", ProfileVersion: "llm_text_v1",
		OutputRef: "cortex-artifact://model/output?size=1", TokenIDsRef: "cortex-artifact://model/trace?size=1", PositionValuesRef: "cortex-artifact://model/checkpoint?size=1",
		OutputHash: codec.HashWithDomain("OUTPUT", []byte("output")), ReceiptHash: codec.HashWithDomain("RECEIPT", []byte("receipt")),
		ReceiptPayload: []byte("receipt-payload"), WorkerSignature: []byte("worker-signature"),
	}
	written, cid, err := producer.SaveOutputPackage(context.Background(), pkg)
	if err != nil {
		t.Fatalf("SaveOutputPackage error = %v", err)
	}
	if !strings.HasPrefix(cid, "fixture://sha256/") || written.PackageHash == (codec.Hash{}) {
		t.Fatalf("written package = %#v cid=%q", written, cid)
	}
	loaded, err := consumer.LoadOutputPackage(context.Background(), cid, written.PackageHash)
	if err != nil {
		t.Fatalf("LoadOutputPackage error = %v", err)
	}
	if loaded.TaskID != pkg.TaskID || loaded.SessionID != pkg.SessionID || loaded.OutputHash != pkg.OutputHash || string(loaded.ReceiptPayload) != string(pkg.ReceiptPayload) || string(loaded.WorkerSignature) != string(pkg.WorkerSignature) {
		t.Fatalf("loaded package = %#v, want %#v", loaded, pkg)
	}

	path := filepath.Join(root, "output-packages", hex.EncodeToString(written.PackageHash[:])+".bin")
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("corrupt package: %v", err)
	}
	if _, err := consumer.LoadOutputPackage(context.Background(), cid, written.PackageHash); !errors.Is(err, ErrOutputPackageDigestMismatch) {
		t.Fatalf("LoadOutputPackage corrupted error = %v, want ErrOutputPackageDigestMismatch", err)
	}
}

func TestFixtureOutputPackageStoreRejectsUnsafeCID(t *testing.T) {
	store, err := NewFixtureOutputPackageStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFixtureOutputPackageStore error = %v", err)
	}
	for _, cid := range []string{"file:///tmp/package", "fixture://sha256/../package", "fixture://sha256/ABC"} {
		if _, err := store.LoadOutputPackage(context.Background(), cid, codec.HashWithDomain("PACKAGE", []byte("package"))); err == nil {
			t.Fatalf("LoadOutputPackage(%q) succeeded", cid)
		}
	}
}

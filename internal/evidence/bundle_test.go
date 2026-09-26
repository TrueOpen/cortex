package evidence

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

func newBundleStore(t *testing.T) (*Store, string) {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	return store, store.root
}

func testOperator(t *testing.T, fill byte) string {
	t.Helper()
	address, err := nodewire.CanonicalOperatorAddressString("trueopen", bytes.Repeat([]byte{fill}, 20))
	if err != nil {
		t.Fatal(err)
	}
	return address
}

func verifierBundle(t *testing.T, taskHash codec.Hash, round uint32, operator string) BundleID {
	t.Helper()
	id, err := VerifierBundle(taskHash, round, operator)
	if err != nil {
		t.Fatalf("VerifierBundle() error = %v", err)
	}
	return id
}

func bundleRequest(id BundleID, manifest string, artifacts ...string) BundleRequest {
	req := BundleRequest{ID: id, Manifest: []byte(manifest)}
	for _, artifact := range artifacts {
		req.Artifacts = append(req.Artifacts, []byte(artifact))
	}
	return req
}

func TestPublishBundleLaysOutEveryBundleIndependently(t *testing.T) {
	store, root := newBundleStore(t)
	ctx := context.Background()
	taskHash := codec.HashBytes([]byte("bundle-layout"))
	operatorA, operatorB := testOperator(t, 0x2b), testOperator(t, 0x3c)
	bundles := []BundleRequest{
		bundleRequest(WorkerTokenBundle(taskHash), `{"kind":"token"}`, "input-ids", "generated-ids"),
		bundleRequest(WorkerValueBundle(taskHash), `{"kind":"value"}`, "worker-values"),
		bundleRequest(verifierBundle(t, taskHash, 1, operatorA), `{"kind":"verifier","round":1}`, "verifier-values"),
		bundleRequest(verifierBundle(t, taskHash, 2, operatorA), `{"kind":"verifier","round":2}`, "verifier-values"),
		bundleRequest(verifierBundle(t, taskHash, 1, operatorB), `{"kind":"verifier","round":1,"b":1}`, "verifier-values-b"),
	}
	taskDir := filepath.Join(root, taskRelDir(taskHash))
	wantDirs := []string{
		"evidence/worker/token",
		"evidence/worker/value",
		"evidence/verifier/1/" + hexDigest(bytes.Repeat([]byte{0x2b}, 20)),
		"evidence/verifier/2/" + hexDigest(bytes.Repeat([]byte{0x2b}, 20)),
		"evidence/verifier/1/" + hexDigest(bytes.Repeat([]byte{0x3c}, 20)),
	}
	for i, req := range bundles {
		ref, err := store.PublishBundle(ctx, req)
		if err != nil {
			t.Fatalf("PublishBundle(%s) error = %v", req.ID, err)
		}
		if want := filepath.Join(taskDir, filepath.FromSlash(wantDirs[i])); ref.Path != want {
			t.Fatalf("bundle %s path = %s, want %s", req.ID, ref.Path, want)
		}
		if ref.ManifestHash != evidencebundle.Hash(req.Manifest) || ref.ManifestSizeBytes != int64(len(req.Manifest)) {
			t.Fatalf("bundle %s ref = %+v", req.ID, ref)
		}
	}
	// A legacy flat artifact of the same task coexists with the bundles.
	if _, err := store.Write(ctx, WriteRequest{TaskHash: taskHash, Kind: "worker-token-ids-material", Data: []byte("trace")}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	for _, req := range bundles {
		manifest, hash, err := store.ReadBundleManifest(req.ID)
		if err != nil || !bytes.Equal(manifest, req.Manifest) || hash != evidencebundle.Hash(req.Manifest) {
			t.Fatalf("ReadBundleManifest(%s) = %q, %v", req.ID, manifest, err)
		}
		for _, artifact := range req.Artifacts {
			got, err := store.ReadBundleArtifact(req.ID, codec.HashBytes(artifact), int64(len(artifact)))
			if err != nil || !bytes.Equal(got, artifact) {
				t.Fatalf("ReadBundleArtifact(%s) = %q, %v", req.ID, got, err)
			}
		}
	}
	// Artifacts are named by content hash and nothing is left staged.
	entries, err := os.ReadDir(filepath.Join(taskDir, "evidence", "worker", "token", artifactsName))
	if err != nil || len(entries) != 2 {
		t.Fatalf("token artifacts = %v, %v", entries, err)
	}
	for _, entry := range entries {
		if !validSHA256Hex(entry.Name()) {
			t.Fatalf("artifact file %q is not a content hash", entry.Name())
		}
	}
	if leftovers := stagedFiles(t, filepath.Join(taskDir, stagingName, evidenceName)); len(leftovers) != 0 {
		t.Fatalf("staging still holds %v", leftovers)
	}
}

func TestPublishBundleIsWriteOnce(t *testing.T) {
	store, _ := newBundleStore(t)
	ctx := context.Background()
	taskHash := codec.HashBytes([]byte("bundle-write-once"))
	req := bundleRequest(WorkerValueBundle(taskHash), `{"v":1}`, "worker-values")
	first, err := store.PublishBundle(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	again, err := store.PublishBundle(ctx, req)
	if err != nil || again.ManifestHash != first.ManifestHash {
		t.Fatalf("identical republish = %+v, %v; want idempotent success", again, err)
	}
	for name, conflicting := range map[string]BundleRequest{
		"different manifest":          bundleRequest(req.ID, `{"v":2}`, "worker-values"),
		"same manifest, new artifact": bundleRequest(req.ID, `{"v":1}`, "other-values"),
	} {
		if _, err := store.PublishBundle(ctx, conflicting); !errors.Is(err, ErrLocalArtifactConflict) {
			t.Fatalf("%s: PublishBundle() error = %v, want ErrLocalArtifactConflict", name, err)
		}
	}
	manifest, _, err := store.ReadBundleManifest(req.ID)
	if err != nil || string(manifest) != `{"v":1}` {
		t.Fatalf("published manifest changed to %q, %v", manifest, err)
	}
	// The other Worker bundle of the same task is independent.
	if _, err := store.PublishBundle(ctx, bundleRequest(WorkerTokenBundle(taskHash), `{"v":2}`, "ids")); err != nil {
		t.Fatalf("token bundle refused beside the value bundle: %v", err)
	}
}

func TestPublishBundleCrashBeforeRenameLeavesNothingVisible(t *testing.T) {
	store, root := newBundleStore(t)
	ctx := context.Background()
	taskHash := codec.HashBytes([]byte("bundle-crash"))
	req := bundleRequest(WorkerTokenBundle(taskHash), `{"m":1}`, "input-ids", "generated-ids")
	crash := errors.New("crash before rename")
	store.beforeBundleRename = func(BundleID) error { return crash }
	if _, err := store.PublishBundle(ctx, req); !errors.Is(err, crash) {
		t.Fatalf("PublishBundle() error = %v, want the injected crash", err)
	}
	if _, _, err := store.ReadBundleManifest(req.ID); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("ReadBundleManifest() after crash = %v, want ErrBundleNotFound", err)
	}
	stagingDir := filepath.Join(root, req.ID.stagingRelDir())
	if len(stagedFiles(t, stagingDir)) == 0 {
		t.Fatal("the crash left no staged bundle, so recovery is not being exercised")
	}
	// A stray file from the crashed attempt must not be published by the retry.
	if err := os.WriteFile(filepath.Join(stagingDir, artifactsName, "stray"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	store.beforeBundleRename = nil
	ref, err := store.PublishBundle(ctx, req)
	if err != nil {
		t.Fatalf("retry after crash: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(ref.Path, artifactsName))
	if err != nil || len(entries) != 2 {
		t.Fatalf("published artifacts = %v, %v; want exactly the two requested", entries, err)
	}
	if _, err := os.Lstat(stagingDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging bundle survived a successful publish: %v", err)
	}
}

func TestPublishBundleCrashAfterRenameIsIdempotent(t *testing.T) {
	store, root := newBundleStore(t)
	ctx := context.Background()
	taskHash := codec.HashBytes([]byte("bundle-crash-after"))
	req := bundleRequest(WorkerValueBundle(taskHash), `{"m":1}`, "worker-values")
	if _, err := store.PublishBundle(ctx, req); err != nil {
		t.Fatal(err)
	}
	// A crash after the rename but before the caller recorded success leaves the
	// formal bundle and, possibly, a fresh partial staging directory.
	stagingDir := filepath.Join(root, req.ID.stagingRelDir(), artifactsName)
	if err := os.MkdirAll(stagingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stagingDir, ".part-1"), []byte("half"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PublishBundle(ctx, req); err != nil {
		t.Fatalf("republish after crash: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, req.ID.stagingRelDir())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("idempotent publish kept the staged leftovers: %v", err)
	}
}

func TestDiscardStagedBundleLeavesPublishedBundlesAlone(t *testing.T) {
	store, root := newBundleStore(t)
	ctx := context.Background()
	taskHash := codec.HashBytes([]byte("bundle-discard"))
	published := bundleRequest(WorkerTokenBundle(taskHash), `{"t":1}`, "ids")
	if _, err := store.PublishBundle(ctx, published); err != nil {
		t.Fatal(err)
	}
	abandoned := WorkerValueBundle(taskHash)
	staged := filepath.Join(root, abandoned.stagingRelDir(), artifactsName)
	if err := os.MkdirAll(staged, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.DiscardStagedBundle(abandoned); err != nil {
		t.Fatalf("DiscardStagedBundle() error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, abandoned.stagingRelDir())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged bundle survived discard: %v", err)
	}
	if err := store.DiscardStagedBundle(published.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ReadBundleManifest(published.ID); err != nil {
		t.Fatalf("discard touched a published bundle: %v", err)
	}
}

func TestBundleIDsRefuseUnsafeInput(t *testing.T) {
	taskHash := codec.HashBytes([]byte("bundle-ids"))
	for name, tc := range map[string]struct {
		round    uint32
		operator string
	}{
		"round 0":            {0, testOperator(t, 1)},
		"round 3":            {3, testOperator(t, 1)},
		"path traversal":     {1, "../../etc"},
		"absolute path":      {1, "/tmp/x"},
		"non-canonical case": {1, "TRUEOPEN1" + testOperator(t, 1)[len("trueopen1"):]},
		"empty operator":     {1, ""},
	} {
		if _, err := VerifierBundle(taskHash, tc.round, tc.operator); !errors.Is(err, ErrInvalidBundle) {
			t.Errorf("%s: VerifierBundle() error = %v, want ErrInvalidBundle", name, err)
		}
	}
	store, _ := newBundleStore(t)
	ctx := context.Background()
	for name, req := range map[string]BundleRequest{
		"zero bundle id": {Manifest: []byte("{}")},
		"zero task hash": bundleRequest(WorkerTokenBundle(codec.Hash{}), "{}", "a"),
		"empty manifest": bundleRequest(WorkerTokenBundle(taskHash), "", "a"),
		"empty artifact": bundleRequest(WorkerTokenBundle(taskHash), "{}", ""),
	} {
		if _, err := store.PublishBundle(ctx, req); err == nil {
			t.Errorf("%s: PublishBundle() error = nil", name)
		}
	}
}

func TestPublishBundleRefusesSymlinks(t *testing.T) {
	ctx := context.Background()
	taskHash := codec.HashBytes([]byte("bundle-symlink"))
	req := bundleRequest(WorkerTokenBundle(taskHash), `{"t":1}`, "ids")

	t.Run("symlinked producer directory", func(t *testing.T) {
		store, root := newBundleStore(t)
		outside := t.TempDir()
		evidenceDir := filepath.Join(root, taskRelDir(taskHash), evidenceName)
		if err := os.MkdirAll(evidenceDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(evidenceDir, workerProducerName)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PublishBundle(ctx, req); !errors.Is(err, ErrEvidenceEscape) {
			t.Fatalf("PublishBundle() error = %v, want ErrEvidenceEscape", err)
		}
		if entries, _ := os.ReadDir(outside); len(entries) != 0 {
			t.Fatalf("bundle escaped the root into %v", entries)
		}
	})

	t.Run("symlinked formal bundle", func(t *testing.T) {
		store, root := newBundleStore(t)
		outside := t.TempDir()
		workerDir := filepath.Join(root, taskRelDir(taskHash), evidenceName, workerProducerName)
		if err := os.MkdirAll(workerDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(workerDir, "token")); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PublishBundle(ctx, req); !errors.Is(err, ErrEvidenceEscape) {
			t.Fatalf("PublishBundle() error = %v, want ErrEvidenceEscape", err)
		}
		if _, _, err := store.ReadBundleManifest(req.ID); !errors.Is(err, ErrEvidenceEscape) {
			t.Fatalf("ReadBundleManifest() error = %v, want ErrEvidenceEscape", err)
		}
	})

	t.Run("symlinked staging", func(t *testing.T) {
		store, root := newBundleStore(t)
		outside := t.TempDir()
		stagingWorker := filepath.Join(root, taskRelDir(taskHash), stagingName, evidenceName, workerProducerName)
		if err := os.MkdirAll(stagingWorker, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(stagingWorker, "token")); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PublishBundle(ctx, req); !errors.Is(err, ErrEvidenceEscape) {
			t.Fatalf("PublishBundle() error = %v, want ErrEvidenceEscape", err)
		}
	})
}

func TestBundleReadsRefuseHardlinksAndTampering(t *testing.T) {
	store, _ := newBundleStore(t)
	ctx := context.Background()
	taskHash := codec.HashBytes([]byte("bundle-hardlink"))
	artifact := []byte("worker-values")
	req := BundleRequest{ID: WorkerValueBundle(taskHash), Manifest: []byte(`{"v":1}`), Artifacts: [][]byte{artifact}}
	ref, err := store.PublishBundle(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(ref.Path, bundleManifestName)
	link := filepath.Join(t.TempDir(), "manifest-link")
	if err := os.Link(manifestPath, link); err != nil {
		t.Skipf("hardlink across temp dirs unsupported here: %v", err)
	}
	if _, _, err := store.ReadBundleManifest(req.ID); !errors.Is(err, ErrEvidenceEscape) {
		t.Fatalf("ReadBundleManifest() on a hardlinked manifest = %v, want ErrEvidenceEscape", err)
	}
	if _, err := store.PublishBundle(ctx, req); !errors.Is(err, ErrLocalArtifactConflict) {
		t.Fatalf("republish over a hardlinked manifest = %v, want ErrLocalArtifactConflict", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}

	digest := codec.HashBytes(artifact)
	if _, err := store.ReadBundleArtifact(req.ID, digest, int64(len(artifact))+1); !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("ReadBundleArtifact() with a wrong size = %v, want ErrSizeMismatch", err)
	}
	if err := os.WriteFile(filepath.Join(ref.Path, artifactsName, hexDigest(digest[:])), []byte("tampered-vals"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadBundleArtifact(req.ID, digest, int64(len(artifact))); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("ReadBundleArtifact() on tampered bytes = %v, want ErrDigestMismatch", err)
	}
	if _, err := store.ReadBundleArtifact(req.ID, codec.HashBytes([]byte("absent")), 6); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("ReadBundleArtifact() for an absent artifact = %v, want ErrArtifactNotFound", err)
	}
}

// stagedFiles lists every regular file under dir, or nothing if dir is absent.
func stagedFiles(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if errors.Is(err, os.ErrNotExist) {
			return filepath.SkipDir
		}
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return files
}

package evidence

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

func wrapTestIndex(idx *store.Store) *LayoutStoreIndex { return &LayoutStoreIndex{Store: idx} }

// taskObjectPath is the path a test expects an object to occupy, derived from
// the layout rather than from the store's own return value.
func taskObjectPath(t *testing.T, root string, taskHash codec.Hash, kind string, digest codec.Hash) string {
	t.Helper()
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q) returned error: %v", root, err)
	}
	return filepath.Join(realRoot, objectRelPath(taskHash, kind, digest))
}

func TestStoreWritePersistsTaskHashMetadataAfterDurableFile(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	index := &recordingEvidenceIndex{root: root}
	evidenceStore, err := NewStore(root, index)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("task-1"))
	data := []byte("one complete evidence package")

	ref, err := evidenceStore.Write(ctx, WriteRequest{
		TaskHash: taskHash, Kind: "output-package", Data: data,
		FinalityHeight: 100, CleanupHeight: 120,
	})
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if !index.fileWasValidAtPut {
		t.Fatal("metadata was written before the digest-valid file was durable")
	}
	wantDigest := codec.HashBytes(data)
	if index.taskHash != taskHash {
		t.Fatalf("metadata task hash = %x, want %x", index.taskHash, taskHash)
	}
	if len(index.evidence.Artifacts) != 1 || codec.Hash(index.evidence.Artifacts[0].Digest) != wantDigest || index.evidence.Size != uint64(len(data)) ||
		index.evidence.FinalityHeight != 100 || index.evidence.CleanupHeight != 120 ||
		index.evidence.TerminalOrSettled {
		t.Fatalf("metadata = %#v, want digest/size/heights/active", index.evidence)
	}
	if ref.DigestSHA256 != hexDigest(wantDigest[:]) {
		t.Fatalf("ref digest = %q, want %x", ref.DigestSHA256, wantDigest)
	}
}

func TestStoreWriteAggregatesMultipleArtifactsUnderCanonicalTaskHash(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	idx, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	index := wrapTestIndex(idx)
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	t.Cleanup(func() { _ = index.Store.Close() })
	evidenceStore, err := NewStore(root, index)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("single-package-task"))
	first := []byte("infer receipt")
	second := []byte("settlement material")
	if _, err := evidenceStore.Write(ctx, WriteRequest{TaskHash: taskHash, Kind: "infer-receipt", Data: first}); err != nil {
		t.Fatalf("first Write returned error: %v", err)
	}
	if _, err := evidenceStore.Write(ctx, WriteRequest{TaskHash: taskHash, Kind: "settlement", Data: second}); err != nil {
		t.Fatalf("second Write returned error: %v", err)
	}
	metadata, err := index.Evidence(ctx, taskHash)
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}
	if len(metadata.Artifacts) != 2 || metadata.Artifacts[0].Kind != "infer-receipt" || metadata.Artifacts[1].Kind != "settlement" {
		t.Fatalf("stored artifacts = %#v, want both kinds in deterministic order", metadata.Artifacts)
	}
	if codec.Hash(metadata.Digest) == codec.HashBytes(first) || codec.Hash(metadata.Digest) == codec.HashBytes(second) {
		t.Fatalf("package digest = %x, want aggregate manifest digest", metadata.Digest)
	}
	entries, err := index.ListEvidence(ctx)
	if err != nil || len(entries) != 1 || entries[0].TaskHash != taskHash {
		t.Fatalf("ListEvidence = (%#v, %v), want exactly one canonical task entry", entries, err)
	}
}

func TestStoreWriteDoesNotRegressRetentionMetadata(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	idx, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	index := wrapTestIndex(idx)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = index.Store.Close() })
	evidenceStore, err := NewStore(root, index)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	taskHash := codec.HashBytes([]byte("retention-idempotency"))
	data := []byte("stable-package")
	if _, err := evidenceStore.Write(ctx, WriteRequest{
		TaskHash: taskHash, Kind: "receipt", Data: data, FinalityHeight: 50, CleanupHeight: 80,
	}); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if _, err := evidenceStore.Write(ctx, WriteRequest{
		TaskHash: taskHash, Kind: "receipt", Data: data, FinalityHeight: 20, CleanupHeight: 30,
	}); err != nil {
		t.Fatalf("idempotent Write: %v", err)
	}
	metadata, err := index.Evidence(ctx, taskHash)
	if err != nil || metadata.FinalityHeight != 50 || metadata.CleanupHeight != 80 {
		t.Fatalf("metadata after idempotent write = (%#v, %v)", metadata, err)
	}
}

func TestConcurrentWriteAndLifecycleUpdatesPreserveArtifactAndRetention(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	idx, err := store.Open(ctx, filepath.Join(t.TempDir(), "index"))
	index := wrapTestIndex(idx)
	if err != nil {
		t.Fatal(err)
	}
	defer index.Store.Close()
	taskHash := codec.HashBytes([]byte("concurrent-write-lifecycle"))
	initialStore, err := NewStore(root, index)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initialStore.Write(ctx, WriteRequest{
		TaskHash: taskHash, Kind: "receipt", Data: []byte("receipt"), FinalityHeight: 10, CleanupHeight: 20,
	}); err != nil {
		t.Fatal(err)
	}

	gate := &mergeGateIndex{MetadataStore: index, started: make(chan struct{}), release: make(chan struct{})}
	concurrentStore, err := NewStore(root, gate)
	if err != nil {
		t.Fatal(err)
	}
	writeErr := make(chan error, 1)
	go func() {
		_, err := concurrentStore.Write(ctx, WriteRequest{
			TaskHash: taskHash, Kind: "trace", Data: []byte("trace"), FinalityHeight: 70, CleanupHeight: 90,
		})
		writeErr <- err
	}()
	<-gate.started // The artifact file is durable; the final metadata merge has not started.
	if err := index.SetEvidenceChallenge(ctx, taskHash, "challenge-1", true); err != nil {
		t.Fatal(err)
	}
	if err := index.SetEvidenceTerminal(ctx, taskHash); err != nil {
		t.Fatal(err)
	}
	if advanced, err := index.AdvanceEvidenceRetention(ctx, taskHash, 100, 120); err != nil || !advanced {
		t.Fatalf("AdvanceEvidenceRetention = (%t, %v)", advanced, err)
	}
	close(gate.release)
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}

	metadata, err := index.Evidence(ctx, taskHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.Artifacts) != 2 || !metadata.TerminalOrSettled || metadata.FinalityHeight != 100 || metadata.CleanupHeight != 120 {
		t.Fatalf("merged evidence = %#v", metadata)
	}
}

type mergeGateIndex struct {
	MetadataStore
	started chan struct{}
	release chan struct{}
}

func (i *mergeGateIndex) MergeEvidence(ctx context.Context, taskHash codec.Hash, mutate func(layout.Evidence, bool) (layout.Evidence, error)) (layout.Evidence, error) {
	close(i.started)
	<-i.release
	return i.MetadataStore.MergeEvidence(ctx, taskHash, mutate)
}

type recordingEvidenceIndex struct {
	root              string
	taskHash          codec.Hash
	evidence          layout.Evidence
	fileWasValidAtPut bool
}

func (i *recordingEvidenceIndex) PutEvidence(_ context.Context, taskHash codec.Hash, evidence layout.Evidence) error {
	i.taskHash = taskHash
	i.evidence = evidence
	artifact := evidence.Artifacts[0]
	path := filepath.Join(i.root, objectRelPath(taskHash, string(artifact.Kind), codec.Hash(artifact.Digest)))
	i.fileWasValidAtPut = verifyFile(path, codec.Hash(artifact.Digest), int64(artifact.Size)) == nil
	return nil
}

func (*recordingEvidenceIndex) Evidence(context.Context, codec.Hash) (layout.Evidence, error) {
	return layout.Evidence{}, store.ErrNotFound
}

func (i *recordingEvidenceIndex) MergeEvidence(_ context.Context, taskHash codec.Hash, mutate func(layout.Evidence, bool) (layout.Evidence, error)) (layout.Evidence, error) {
	evidence, err := mutate(layout.Evidence{}, false)
	if err != nil {
		return layout.Evidence{}, err
	}
	return evidence, i.PutEvidence(context.Background(), taskHash, evidence)
}

func (*recordingEvidenceIndex) CleanupEvidence(context.Context, codec.Hash) error { return nil }
func (*recordingEvidenceIndex) ListEvidenceChallenges(context.Context, codec.Hash) ([]string, error) {
	return nil, nil
}
func (*recordingEvidenceIndex) WithArtifactLock(fn func() error) error           { return fn() }
func (*recordingEvidenceIndex) DeleteEvidence(context.Context, codec.Hash) error { return nil }

// The locator is the whole point of the layout: a task's bytes live under that
// task's own directory, and the class - input, output, evidence artifact - is
// derived from the kind, never from anything a peer supplies.
func TestStoreWritePublishesEachClassUnderTheTaskDirectory(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	evidenceStore, err := NewStore(root)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("class-layout"))
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("EvalSymlinks returned error: %v", err)
	}
	taskDir := filepath.Join(realRoot, "tasks", hexDigest(taskHash[:])[:2], hexDigest(taskHash[:]))

	for _, testCase := range []struct {
		kind    string
		data    []byte
		wantDir string
	}{
		{kind: string(layout.ArtifactTaskInput), data: []byte("the input"), wantDir: filepath.Join(taskDir, "input")},
		{kind: string(layout.ArtifactWorkerOutput), data: []byte("the output"), wantDir: filepath.Join(taskDir, "output")},
		{kind: string(layout.ArtifactWorkerTokenIDsMaterial), data: []byte("the trace"), wantDir: filepath.Join(taskDir, "evidence", "artifacts")},
	} {
		ref, err := evidenceStore.Write(ctx, WriteRequest{TaskHash: taskHash, Kind: testCase.kind, Data: testCase.data})
		if err != nil {
			t.Fatalf("Write %s returned error: %v", testCase.kind, err)
		}
		digest := codec.HashBytes(testCase.data)
		wantPath := filepath.Join(testCase.wantDir, hexDigest(digest[:]))
		if ref.Path != wantPath {
			t.Fatalf("%s path = %q, want %q", testCase.kind, ref.Path, wantPath)
		}
		if !isWithin(realRoot, ref.Path) {
			t.Fatalf("%s path = %q escapes root %q", testCase.kind, ref.Path, realRoot)
		}
		got, err := os.ReadFile(ref.Path)
		if err != nil {
			t.Fatalf("ReadFile %s returned error: %v", testCase.kind, err)
		}
		if !bytes.Equal(got, testCase.data) {
			t.Fatalf("%s stored data = %q, want %q", testCase.kind, got, testCase.data)
		}
		if ref.SizeBytes != int64(len(testCase.data)) {
			t.Fatalf("%s size = %d, want %d", testCase.kind, ref.SizeBytes, len(testCase.data))
		}
	}
}

// The task hash is a path component now, not merely an index key, so a write
// without one has nowhere to go and is refused whether or not an index is
// wired. Silently writing such bytes to a task-agnostic location is exactly
// what the layout retires.
func TestStoreWriteRequiresATaskHashAndAKind(t *testing.T) {
	ctx := context.Background()
	evidenceStore, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	if _, err := evidenceStore.Write(ctx, WriteRequest{Kind: "worker-token-ids-material", Data: []byte("orphan")}); !errors.Is(err, ErrTaskHashRequired) {
		t.Fatalf("Write without a task hash error = %v, want %v", err, ErrTaskHashRequired)
	}
	if _, err := evidenceStore.Write(ctx, WriteRequest{TaskHash: codec.HashBytes([]byte("t")), Data: []byte("kindless")}); !errors.Is(err, ErrKindRequired) {
		t.Fatalf("Write without a kind error = %v, want %v", err, ErrKindRequired)
	}
}

func TestStoreWriteIsIdempotentForIdenticalBytesAtTheSameLocator(t *testing.T) {
	ctx := context.Background()
	evidenceStore, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("idempotent"))
	data := []byte("same evidence payload")

	for _, kind := range []string{string(layout.ArtifactWorkerOutput), string(layout.ArtifactWorkerTokenIDsMaterial)} {
		first, err := evidenceStore.Write(ctx, WriteRequest{TaskHash: taskHash, Kind: kind, Data: data})
		if err != nil {
			t.Fatalf("first Write %s returned error: %v", kind, err)
		}
		second, err := evidenceStore.Write(ctx, WriteRequest{TaskHash: taskHash, Kind: kind, Data: data})
		if err != nil {
			t.Fatalf("second Write %s returned error: %v", kind, err)
		}
		if second.Path != first.Path || second.DigestSHA256 != first.DigestSHA256 {
			t.Fatalf("%s second ref = %#v, want %#v", kind, second, first)
		}
	}
}

// Write-once, stated as the failure it prevents: a second, different output for
// a task that already published one is never an overwrite. input/ and output/
// hold exactly one object in V1, so the class directory is the locator and its
// content decides between idempotent success and conflict.
func TestStoreWriteRefusesDifferentBytesForAnAlreadyPublishedSingletonClass(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	evidenceStore, err := NewStore(root)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("write-once-output"))
	published := []byte("the output that was committed")
	if _, err := evidenceStore.Write(ctx, WriteRequest{TaskHash: taskHash, Kind: string(layout.ArtifactWorkerOutput), Data: published}); err != nil {
		t.Fatalf("first Write returned error: %v", err)
	}

	if _, err := evidenceStore.Write(ctx, WriteRequest{
		TaskHash: taskHash, Kind: string(layout.ArtifactWorkerOutput), Data: []byte("a different output"),
	}); !errors.Is(err, ErrLocalArtifactConflict) {
		t.Fatalf("conflicting Write error = %v, want %v", err, ErrLocalArtifactConflict)
	}

	// The committed bytes are untouched: a refused write must not have replaced
	// or truncated what was already published.
	digest := codec.HashBytes(published)
	got, err := os.ReadFile(taskObjectPath(t, root, taskHash, string(layout.ArtifactWorkerOutput), digest))
	if err != nil {
		t.Fatalf("ReadFile published output returned error: %v", err)
	}
	if !bytes.Equal(got, published) {
		t.Fatalf("published output = %q, want %q", got, published)
	}
}

// An evidence artifact is located by its kind in the index, and the file name is
// its content hash, so a second digest under one kind is the same "locator
// already bound to different content" case as the singleton classes.
func TestStoreWriteRefusesASecondDigestUnderOneEvidenceKind(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	idx, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	index := wrapTestIndex(idx)
	t.Cleanup(func() { _ = index.Store.Close() })
	evidenceStore, err := NewStore(root, index)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("write-once-trace"))
	if _, err := evidenceStore.Write(ctx, WriteRequest{
		TaskHash: taskHash, Kind: string(layout.ArtifactWorkerTokenIDsMaterial), Data: []byte("the trace"),
	}); err != nil {
		t.Fatalf("first Write returned error: %v", err)
	}
	if _, err := evidenceStore.Write(ctx, WriteRequest{
		TaskHash: taskHash, Kind: string(layout.ArtifactWorkerTokenIDsMaterial), Data: []byte("another trace"),
	}); !errors.Is(err, ErrLocalArtifactConflict) {
		t.Fatalf("conflicting Write error = %v, want %v", err, ErrLocalArtifactConflict)
	}
	metadata, err := index.Evidence(ctx, taskHash)
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}
	if len(metadata.Artifacts) != 1 || codec.Hash(metadata.Artifacts[0].Digest) != codec.HashBytes([]byte("the trace")) {
		t.Fatalf("artifacts after a refused write = %#v, want only the committed trace", metadata.Artifacts)
	}
}

// A crash between staging and publication leaves bytes in .staging/. The
// staged class directory is renamed *whole*, so anything left behind would be
// published along with this write - which is how a partially written object
// from a previous attempt would become a formal one.
func TestStoreWriteDiscardsBytesLeftInStagingByAnEarlierCrash(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	evidenceStore, err := NewStore(root)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("crashed-staging"))
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("EvalSymlinks returned error: %v", err)
	}
	staging := filepath.Join(realRoot, stagingRelDir(taskHash, classInput))
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatalf("MkdirAll staging returned error: %v", err)
	}
	orphan := []byte("half of a previous attempt")
	orphanDigest := codec.HashBytes(orphan)
	if err := os.WriteFile(filepath.Join(staging, hexDigest(orphanDigest[:])), orphan, 0o600); err != nil {
		t.Fatalf("WriteFile staged orphan returned error: %v", err)
	}

	data := []byte("the input that is actually resolved")
	if _, err := evidenceStore.Write(ctx, WriteRequest{TaskHash: taskHash, Kind: string(layout.ArtifactTaskInput), Data: data}); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	digest := codec.HashBytes(data)
	entries, err := os.ReadDir(filepath.Join(realRoot, classRelDir(taskHash, classInput)))
	if err != nil {
		t.Fatalf("ReadDir input returned error: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != hexDigest(digest[:]) {
		t.Fatalf("published input directory = %v, want only %s", entries, hexDigest(digest[:]))
	}
}

// Nothing published is left staged, in either class. A staged copy that
// survived publication is a second, unaccounted-for copy of task bytes that
// cleanup does not know about.
func TestStoreWriteLeavesNothingStaged(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	evidenceStore, err := NewStore(root)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("staging-drained"))
	for _, kind := range []string{string(layout.ArtifactTaskInput), string(layout.ArtifactWorkerOutput), string(layout.ArtifactWorkerTokenIDsMaterial)} {
		if _, err := evidenceStore.Write(ctx, WriteRequest{TaskHash: taskHash, Kind: kind, Data: []byte("payload for " + kind)}); err != nil {
			t.Fatalf("Write %s returned error: %v", kind, err)
		}
		// A repeated write takes the idempotent branch, which has its own
		// staging teardown.
		if _, err := evidenceStore.Write(ctx, WriteRequest{TaskHash: taskHash, Kind: kind, Data: []byte("payload for " + kind)}); err != nil {
			t.Fatalf("idempotent Write %s returned error: %v", kind, err)
		}
	}

	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("EvalSymlinks returned error: %v", err)
	}
	stagingRoot := filepath.Join(realRoot, taskRelDir(taskHash), stagingName)
	var leftover []string
	err = filepath.Walk(stagingRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if !info.IsDir() {
			leftover = append(leftover, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk staging returned error: %v", err)
	}
	if len(leftover) != 0 {
		t.Fatalf("staged files left after publication: %v", leftover)
	}
}

// The deliberate cost of the layout, asserted rather than assumed: two tasks
// carrying identical bytes get two files. Sharing one physical file is what
// forced cleanup to reference-count digests across tasks, and the task
// directory can only be the retention boundary if nothing crosses it.
func TestTwoTasksWithIdenticalBytesDoNotShareAFile(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	evidenceStore, err := NewStore(root)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	data := []byte("the very same input")
	first := codec.HashBytes([]byte("task-a"))
	second := codec.HashBytes([]byte("task-b"))
	for _, taskHash := range []codec.Hash{first, second} {
		if _, err := evidenceStore.Write(ctx, WriteRequest{TaskHash: taskHash, Kind: string(layout.ArtifactTaskInput), Data: data}); err != nil {
			t.Fatalf("Write returned error: %v", err)
		}
	}
	digest := codec.HashBytes(data)
	firstPath := taskObjectPath(t, root, first, string(layout.ArtifactTaskInput), digest)
	secondPath := taskObjectPath(t, root, second, string(layout.ArtifactTaskInput), digest)
	if firstPath == secondPath {
		t.Fatalf("both tasks resolved to %q", firstPath)
	}
	for _, path := range []string{firstPath, secondPath} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("Lstat %q returned error: %v", path, err)
		}
		if links := hardlinkCount(info); links != 1 {
			t.Fatalf("%q has %d links, want an unshared file", path, links)
		}
	}
}

func TestStoreWriteRejectsEmptyUnlessAllowed(t *testing.T) {
	ctx := context.Background()
	evidenceStore, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("empty"))

	if _, err := evidenceStore.Write(ctx, WriteRequest{TaskHash: taskHash, Kind: "empty", Data: nil}); !errors.Is(err, ErrEmptyEvidence) {
		t.Fatalf("Write empty error = %v, want %v", err, ErrEmptyEvidence)
	}

	ref, err := evidenceStore.Write(ctx, WriteRequest{TaskHash: taskHash, Kind: "empty", Data: nil, AllowEmpty: true})
	if err != nil {
		t.Fatalf("Write empty with AllowEmpty returned error: %v", err)
	}
	if ref.SizeBytes != 0 {
		t.Fatalf("size = %d, want 0", ref.SizeBytes)
	}
}

func TestStoreRejectsSymlinkEscape(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	evidenceStore, err := NewStore(root)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("symlinked-object"))
	data := []byte("escape")
	digest := codec.HashBytes(data)
	finalPath := taskObjectPath(t, root, taskHash, string(layout.ArtifactWorkerTokenIDsMaterial), digest)
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("WriteFile outside returned error: %v", err)
	}
	if err := os.Symlink(outside, finalPath); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}

	if _, err := evidenceStore.Write(ctx, WriteRequest{TaskHash: taskHash, Kind: string(layout.ArtifactWorkerTokenIDsMaterial), Data: data}); !errors.Is(err, ErrEvidenceEscape) {
		t.Fatalf("Write symlink escape error = %v, want %v", err, ErrEvidenceEscape)
	}
}

func TestStoreRejectsSymlinkedTaskShardEscape(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	evidenceStore, err := NewStore(root)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("symlinked-shard"))
	shardDir := filepath.Dir(filepath.Join(root, taskRelDir(taskHash)))
	if err := os.MkdirAll(filepath.Dir(shardDir), 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.Symlink(t.TempDir(), shardDir); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}

	if _, err := evidenceStore.Write(ctx, WriteRequest{
		TaskHash: taskHash, Kind: string(layout.ArtifactWorkerTokenIDsMaterial), Data: []byte("escape"),
	}); !errors.Is(err, ErrEvidenceEscape) {
		t.Fatalf("Write parent symlink escape error = %v, want %v", err, ErrEvidenceEscape)
	}
}

// Planting a *valid* object behind the symlinked parent is what makes the
// ordering matter: Lstat on the final path follows a symlinked parent and
// reports the file present, so a guard that checks the file before the parent
// chain adopts an object from outside the root as this task's own.
func TestStoreRejectsSymlinkedClassDirectoryAlreadyHoldingAValidObject(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	evidenceStore, err := NewStore(root)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("symlinked-class-dir"))
	data := []byte("class-symlink-with-valid-object")
	digest := codec.HashBytes(data)
	digestHex := hexDigest(digest[:])

	// A correct object, by name and by content, outside the root.
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, digestHex), data, 0o600); err != nil {
		t.Fatalf("WriteFile outside returned error: %v", err)
	}
	classDir := filepath.Join(root, classRelDir(taskHash, classEvidence))
	if err := os.MkdirAll(filepath.Dir(classDir), 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.Symlink(outside, classDir); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}

	if _, err := evidenceStore.Write(ctx, WriteRequest{TaskHash: taskHash, Kind: string(layout.ArtifactWorkerTokenIDsMaterial), Data: data}); !errors.Is(err, ErrEvidenceEscape) {
		t.Fatalf("Write error = %v, want %v: an outside object was adopted as this task's artifact", err, ErrEvidenceEscape)
	}
}

// A root reached through a symlink is an ordinary deployment: a data volume
// mounted elsewhere and linked into place. Refusing it stopped such a node from
// starting at all, which is why the root is resolved once and the resolved path
// - not the configured one - is the boundary every child is checked against.
func TestNewStoreAcceptsASymlinkedRoot(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	volume := filepath.Join(base, "real-volume")
	if err := os.MkdirAll(volume, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	link := filepath.Join(base, "evidence")
	if err := os.Symlink(volume, link); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}

	evidenceStore, err := NewStore(link)
	if err != nil {
		t.Fatalf("NewStore through a symlinked root returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("symlinked-root"))
	data := []byte("payload")
	ref, err := evidenceStore.Write(ctx, WriteRequest{TaskHash: taskHash, Kind: string(layout.ArtifactWorkerOutput), Data: data})
	if err != nil {
		t.Fatalf("Write through a symlinked root returned error: %v", err)
	}
	if ref.DigestSHA256 == "" {
		t.Fatalf("Write returned no digest: %#v", ref)
	}
	got, err := evidenceStore.readTaskObject(taskHash, string(layout.ArtifactWorkerOutput), codec.HashBytes(data))
	if err != nil {
		t.Fatalf("readTaskObject through a symlinked root returned error: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("readTaskObject = %q, want %q", got, data)
	}
}

func TestStoreRejectsHardlinkEscape(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	evidenceStore, err := NewStore(root)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("hardlinked-object"))
	data := []byte("hardlink")
	digest := codec.HashBytes(data)
	finalPath := taskObjectPath(t, root, taskHash, string(layout.ArtifactWorkerTokenIDsMaterial), digest)
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("WriteFile outside returned error: %v", err)
	}
	if err := os.Link(outside, finalPath); err != nil {
		t.Fatalf("Link returned error: %v", err)
	}

	if _, err := evidenceStore.Write(ctx, WriteRequest{TaskHash: taskHash, Kind: string(layout.ArtifactWorkerTokenIDsMaterial), Data: data}); !errors.Is(err, ErrEvidenceEscape) {
		t.Fatalf("Write hardlink escape error = %v, want %v", err, ErrEvidenceEscape)
	}
}

func TestReadTaskKindRoundTrip(t *testing.T) {
	ctx := context.Background()
	idx, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	index := wrapTestIndex(idx)
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = index.Store.Close() })
	path := t.TempDir()
	evidenceStore, err := NewStore(path, index)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	data := []byte("hello task input")
	taskHash := codec.HashBytes([]byte("task-hash"))
	if _, err := evidenceStore.Write(ctx, WriteRequest{
		TaskHash: taskHash, SessionID: "session-1", TaskID: "task-1",
		Kind: string(layout.ArtifactTaskInput), Data: data,
	}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	got, err := evidenceStore.ReadTaskKind(ctx, taskHash, string(layout.ArtifactTaskInput))
	if err != nil {
		t.Fatalf("ReadTaskKind() error = %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("ReadTaskKind() = %q, want %q", got, data)
	}
}

func TestReadTaskKindRejectsASymlinkedTaskDirectory(t *testing.T) {
	ctx := context.Background()
	idx, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	index := wrapTestIndex(idx)
	t.Cleanup(func() { _ = index.Store.Close() })
	root := t.TempDir()
	evidenceStore, err := NewStore(root, index)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("symlinked-task-dir"))
	data := []byte("symlinked-root")
	if _, err := evidenceStore.Write(ctx, WriteRequest{
		TaskHash: taskHash, Kind: string(layout.ArtifactWorkerTokenIDsMaterial), Data: data,
	}); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	taskDir := filepath.Join(root, taskRelDir(taskHash))
	if err := os.RemoveAll(taskDir); err != nil {
		t.Fatalf("RemoveAll task directory returned error: %v", err)
	}
	if err := os.Symlink(t.TempDir(), taskDir); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}

	if _, err := evidenceStore.ReadTaskKind(ctx, taskHash, string(layout.ArtifactWorkerTokenIDsMaterial)); !errors.Is(err, ErrEvidenceEscape) {
		t.Fatalf("ReadTaskKind error = %v, want %v", err, ErrEvidenceEscape)
	}
}

func TestReadTaskKindNotFound(t *testing.T) {
	ctx := context.Background()
	idx, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	index := wrapTestIndex(idx)
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = index.Store.Close() })
	path := t.TempDir()
	evidenceStore, err := NewStore(path, index)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	_, err = evidenceStore.ReadTaskKind(ctx, codec.HashBytes([]byte("task-hash")), "worker-input")
	if err == nil {
		t.Fatalf("ReadTaskKind() error = nil, want not found")
	}
}

// Crash recovery, the case that must not be papered over: the index says the
// bytes are committed and they are gone. The signed material naming them has
// already been produced, so redoing the work would sign different bytes for the
// same task. The store reports it instead, and the caller stops.
func TestVerifyTaskObjectsReportsCommittedBytesThatAreGone(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	idx, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	index := wrapTestIndex(idx)
	t.Cleanup(func() { _ = index.Store.Close() })
	evidenceStore, err := NewStore(root, index)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("lost-bytes"))
	data := []byte("committed evidence")
	if _, err := evidenceStore.Write(ctx, WriteRequest{
		TaskHash: taskHash, Kind: string(layout.ArtifactWorkerTokenIDsMaterial), Data: data,
	}); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if err := evidenceStore.VerifyTaskObjects(ctx, taskHash); err != nil {
		t.Fatalf("VerifyTaskObjects on an intact task returned error: %v", err)
	}

	if err := os.Remove(taskObjectPath(t, root, taskHash, string(layout.ArtifactWorkerTokenIDsMaterial), codec.HashBytes(data))); err != nil {
		t.Fatalf("Remove committed object returned error: %v", err)
	}
	if err := evidenceStore.VerifyTaskObjects(ctx, taskHash); !errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatalf("VerifyTaskObjects error = %v, want %v", err, ErrEvidenceUnavailable)
	}
}

// Corrupt is not the same as absent, and both are unavailable. A truncated or
// rewritten file whose digest no longer matches must never be handed to a
// caller as the committed bytes.
func TestVerifyTaskObjectsReportsCorruptedCommittedBytes(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	idx, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	index := wrapTestIndex(idx)
	t.Cleanup(func() { _ = index.Store.Close() })
	evidenceStore, err := NewStore(root, index)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("corrupt-bytes"))
	data := []byte("committed evidence")
	if _, err := evidenceStore.Write(ctx, WriteRequest{
		TaskHash: taskHash, Kind: string(layout.ArtifactWorkerTokenIDsMaterial), Data: data,
	}); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	path := taskObjectPath(t, root, taskHash, string(layout.ArtifactWorkerTokenIDsMaterial), codec.HashBytes(data))
	if err := os.WriteFile(path, []byte("not the committed evidence"), 0o600); err != nil {
		t.Fatalf("WriteFile corrupted object returned error: %v", err)
	}
	if err := evidenceStore.VerifyTaskObjects(ctx, taskHash); !errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatalf("VerifyTaskObjects error = %v, want %v", err, ErrEvidenceUnavailable)
	}
}

// Retired on schedule is not the same as lost. A task whose directory cleanup
// already moved to trash reports ErrCleanupPending, so a caller can tell the
// two apart instead of treating a completed retention as data loss.
func TestVerifyTaskObjectsDistinguishesATrashedTaskFromALostOne(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	idx, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	index := wrapTestIndex(idx)
	t.Cleanup(func() { _ = index.Store.Close() })
	evidenceStore, err := NewStore(root, index)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("trashed-task"))
	if _, err := evidenceStore.Write(ctx, WriteRequest{
		TaskHash: taskHash, Kind: string(layout.ArtifactWorkerTokenIDsMaterial), Data: []byte("retired evidence"),
	}); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if moved, err := trashTaskDirectory(root, taskHash); err != nil || !moved {
		t.Fatalf("trashTaskDirectory = (%t, %v), want the directory moved", moved, err)
	}

	err = evidenceStore.VerifyTaskObjects(ctx, taskHash)
	if !errors.Is(err, ErrCleanupPending) {
		t.Fatalf("VerifyTaskObjects error = %v, want %v", err, ErrCleanupPending)
	}
	if errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatalf("VerifyTaskObjects error = %v, want a retired task not to be reported as lost", err)
	}
}

// Nothing committed means nothing can be missing: a task the store has never
// written must not look like data loss at startup.
func TestVerifyTaskObjectsAcceptsATaskWithNoIndexRow(t *testing.T) {
	ctx := context.Background()
	idx, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	index := wrapTestIndex(idx)
	t.Cleanup(func() { _ = index.Store.Close() })
	evidenceStore, err := NewStore(t.TempDir(), index)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	if err := evidenceStore.VerifyTaskObjects(ctx, codec.HashBytes([]byte("never-written"))); err != nil {
		t.Fatalf("VerifyTaskObjects on an unknown task returned error: %v", err)
	}
}

// The retired global content-addressed tree is reported, not migrated in place.
// Ignoring it would leak every byte in it forever and leave index rows pointing
// at paths this store can no longer resolve, so the node refuses to start and
// names the drain.
func TestNewStoreRefusesTheRetiredGlobalLayout(t *testing.T) {
	root := t.TempDir()
	legacyShard := filepath.Join(root, "sha256", "ab")
	if err := os.MkdirAll(legacyShard, 0o700); err != nil {
		t.Fatalf("MkdirAll legacy shard returned error: %v", err)
	}
	legacyObject := codec.HashBytes([]byte("legacy object"))
	if err := os.WriteFile(filepath.Join(legacyShard, hexDigest(legacyObject[:])), []byte("legacy object"), 0o600); err != nil {
		t.Fatalf("WriteFile legacy object returned error: %v", err)
	}

	_, err := NewStore(root)
	if !errors.Is(err, ErrLegacyEvidenceLayout) {
		t.Fatalf("NewStore error = %v, want %v", err, ErrLegacyEvidenceLayout)
	}
	if got := err.Error(); !strings.Contains(got, "docs/operations/evidence-retention.md") {
		t.Fatalf("NewStore error = %q, want it to name the operator runbook", got)
	}
}

// An empty leftover sha256/ directory is not a populated legacy tree: a node
// that already drained must still start.
func TestNewStoreAcceptsAnEmptyLegacyDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sha256"), 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if _, err := NewStore(root); err != nil {
		t.Fatalf("NewStore with a drained legacy directory returned error: %v", err)
	}
}

// The symlink guards in this package are pathname prechecks: a component is
// validated, then the operation re-resolves the same path. That rests on no other
// local user being able to plant a symlink in the tree, and this is the check that
// turns the assumption into a precondition instead of a comment.
func TestNewStoreRefusesAnUntrustedAncestor(t *testing.T) {
	base := t.TempDir()
	// A world-writable ancestor with no sticky bit: any local user can replace
	// entries inside it, including the resolved root itself.
	exposed := filepath.Join(base, "exposed")
	if err := os.MkdirAll(filepath.Join(exposed, "evidence"), 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.Chmod(exposed, 0o777); err != nil {
		t.Fatalf("Chmod returned error: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(exposed, 0o700) })

	if _, err := NewStore(filepath.Join(exposed, "evidence")); !errors.Is(err, ErrEvidenceRootUntrusted) {
		t.Fatalf("NewStore error = %v, want %v", err, ErrEvidenceRootUntrusted)
	}
}

// The sticky exemption is load-bearing, not a loophole. configs/dev.yaml puts the
// evidence root under /tmp, and on Linux t.TempDir() does too, so a check that
// refused every world-writable ancestor would refuse dev mode and CI. Sticky is
// exactly the rule that stops one user replacing another's entry, which is the
// attack being guarded, so it is the right line to draw.
func TestNewStoreAcceptsAStickyWorldWritableAncestor(t *testing.T) {
	base := t.TempDir()
	shared := filepath.Join(base, "shared")
	if err := os.MkdirAll(filepath.Join(shared, "evidence"), 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.Chmod(shared, 0o777|os.ModeSticky); err != nil {
		t.Fatalf("Chmod returned error: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(shared, 0o700) })

	evidenceStore, err := NewStore(filepath.Join(shared, "evidence"))
	if err != nil {
		t.Fatalf("NewStore through a sticky ancestor returned error: %v", err)
	}
	if _, err := evidenceStore.Write(context.Background(), WriteRequest{
		TaskHash: codec.HashBytes([]byte("sticky")), Kind: "output-package", Data: []byte("payload"),
	}); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
}

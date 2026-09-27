// Package evidence implements the task-scoped local artifact store. The name
// "evidence" reflects its origin as the keeper of protocol evidence openings,
// but the store now holds all task artifacts: model material (worker-token-ids-material,
// worker-position-values-material, worker-reveal-opening, verifier-v-values,
// verifier-full-result-reveal-state, settlement-*), OUTPUT payload
// (worker-output), local-only signed material (worker-handshake,
// worker-infer-receipt, verifier-handshake, verifier-result-commit), and
// resolved task input. Evidence, in the strict protocol sense of an opening
// commitment, is only one category of tenant.
//
// Bytes live under tasks/<taskHash[0:2]>/<taskHash>/ (see paths.go), are staged
// inside that task's own .staging/ and published write-once, and are retired by
// moving the whole task directory to trash/. Nothing is shared between tasks,
// so the task directory is the retention boundary and cleanup never needs a
// cross-task reference count. The store groups index entries per task hash and
// retires them on the task's chain-driven retention schedule.
//
// A local path is never an RPC field, a signing field or an on-chain locator.
// The on-chain evidence commitments are computed from the bytes in memory
// (internal/worker), so this layout is free to change without moving a single
// signed digest.
package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

var (
	// ErrArtifactNotFound means no artifact of this kind is recorded in the index.
	// It never denotes missing or unreadable bytes for an indexed artifact.
	ErrArtifactNotFound = errors.New("evidence artifact is not indexed")
	ErrEmptyEvidence    = errors.New("empty evidence")
	ErrEvidenceEscape   = errors.New("evidence path escapes root")
	// ErrEvidenceRootUntrusted reports a CAS root whose ownership or permissions
	// would let another local user replace a path component between a symlink
	// check and the operation that uses it.
	ErrEvidenceRootUntrusted = errors.New("evidence root is not trusted")
	ErrDigestMismatch        = errors.New("evidence digest mismatch")
	ErrSizeMismatch          = errors.New("evidence size mismatch")
	ErrTaskHashRequired      = errors.New("task hash is required: the local layout is task-scoped")
	ErrKindRequired          = errors.New("artifact kind is required")
	ErrEvidenceConflict      = errors.New("task hash already owns a different evidence package")
	ErrCleanupPending        = errors.New("evidence cleanup is pending")
	// ErrLocalArtifactConflict reports a formal locator that is already bound to
	// different content. Formal objects are write-once: identical bytes are an
	// idempotent success, different bytes are never an overwrite.
	ErrLocalArtifactConflict = errors.New("local artifact conflict")
	// ErrEvidenceUnavailable reports an object the index claims is committed but
	// whose bytes are missing or corrupt on disk. A caller that sees this must
	// stop signing new responsibility material for the task rather than redo the
	// work behind the already-committed state.
	ErrEvidenceUnavailable = errors.New("committed evidence object is unavailable")
	// ErrLegacyEvidenceLayout reports a root that still holds the retired global
	// content-addressed tree.
	ErrLegacyEvidenceLayout = errors.New("evidence root holds the retired global content-addressed layout")
)

type Store struct {
	root  string
	index MetadataStore

	// publishLocks serializes publication per (task hash, class). Directory
	// publication is a check-then-rename, so two responsibilities of the same
	// task writing the same class concurrently must not interleave.
	publishLocks sync.Map // string -> *sync.Mutex

	// beforeBundleRename, when set by a test, runs after a bundle is fully
	// staged and before its directory rename, to stand in for a crash there.
	beforeBundleRename func(BundleID) error
}

type MetadataStore interface {
	PutEvidence(context.Context, codec.Hash, layout.Evidence) error
	Evidence(context.Context, codec.Hash) (layout.Evidence, error)
	MergeEvidence(context.Context, codec.Hash, func(layout.Evidence, bool) (layout.Evidence, error)) (layout.Evidence, error)
	DeleteEvidence(context.Context, codec.Hash) error
	CleanupEvidence(context.Context, codec.Hash) error
	WithArtifactLock(func() error) error
	ListEvidenceChallenges(context.Context, codec.Hash) ([]string, error)
}

type MetadataEnumerator interface {
	ListEvidence(context.Context) ([]layout.EvidenceEntry, error)
}

type WriteRequest struct {
	TaskHash       codec.Hash
	SessionID      string
	TaskID         string
	Kind           string
	Data           []byte
	AllowEmpty     bool
	FinalityHeight uint64
	CleanupHeight  uint64
}

type Ref struct {
	Scheme       string
	Kind         string
	DigestSHA256 string
	SizeBytes    int64
	Path         string
}

func (r Ref) String() string {
	if r.Scheme == "" || r.DigestSHA256 == "" {
		return ""
	}
	return fmt.Sprintf("%s://sha256/%s?kind=%s&size=%d", r.Scheme, r.DigestSHA256, r.Kind, r.SizeBytes)
}

func NewStore(root string, indexes ...any) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("evidence root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, err
	}
	// The configured root may legitimately be reached through a symlink: a
	// symlinked data volume is an ordinary deployment shape, and refusing it
	// stopped such a node from starting at all. Resolve it once here and treat
	// the resolved path as the boundary. What must never be a symlink is a path
	// component *inside* the root, and every access checks that against realRoot.
	realRoot, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	rootInfo, err := os.Stat(realRoot)
	if err != nil {
		return nil, err
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("evidence root is not a directory: %s", realRoot)
	}
	if err := verifyRootTrust(realRoot); err != nil {
		return nil, err
	}
	if err := refuseLegacyLayout(realRoot); err != nil {
		return nil, err
	}
	if len(indexes) > 1 {
		return nil, fmt.Errorf("at most one evidence metadata store is allowed")
	}
	var index MetadataStore
	if len(indexes) == 1 {
		if indexes[0] == nil {
			return nil, fmt.Errorf("evidence metadata store is required")
		}
		switch idx := indexes[0].(type) {
		case MetadataStore:
			index = idx
		case *store.Store:
			index = &LayoutStoreIndex{Store: idx}
		default:
			return nil, fmt.Errorf("unsupported evidence index type %T", indexes[0])
		}
	}
	return &Store{root: realRoot, index: index}, nil
}

// Write publishes one task object and records it in the local index. The
// publication is write-once: identical bytes at the same locator are an
// idempotent success, different bytes are ErrLocalArtifactConflict, and no
// formal file is ever overwritten in place.
func (s *Store) Write(ctx context.Context, req WriteRequest) (Ref, error) {
	if err := ctx.Err(); err != nil {
		return Ref{}, err
	}
	if len(req.Data) == 0 && !req.AllowEmpty {
		return Ref{}, ErrEmptyEvidence
	}
	// The task hash is a path component now, not just an index key, so it is
	// required whether or not an index is wired.
	if req.TaskHash == (codec.Hash{}) {
		return Ref{}, ErrTaskHashRequired
	}
	if strings.TrimSpace(req.Kind) == "" {
		return Ref{}, ErrKindRequired
	}

	digest := codec.HashBytes(req.Data)
	digestHex := hexDigest(digest[:])
	class := classForKind(req.Kind)
	size := int64(len(req.Data))

	finalPath := filepath.Join(s.root, classRelDir(req.TaskHash, class), digestHex)
	if !isWithin(s.root, finalPath) {
		return Ref{}, ErrEvidenceEscape
	}
	ref := Ref{
		Scheme:       "cortex-evidence",
		Kind:         req.Kind,
		DigestSHA256: digestHex,
		SizeBytes:    size,
		Path:         finalPath,
	}

	unlock := s.lockPublication(req.TaskHash, class)
	defer unlock()

	publish := func() error {
		if class == classEvidence {
			return s.publishArtifact(req.TaskHash, digest, size, req.Data)
		}
		return s.publishSingletonClass(req.TaskHash, class, digest, size, req.Data)
	}

	if s.index == nil {
		if err := publish(); err != nil {
			return Ref{}, err
		}
		return ref, nil
	}

	// Object before index, as the target design requires: an index row that
	// names bytes which were never published would make a restart report
	// ErrEvidenceUnavailable for work that simply had not happened yet.
	artifact := layout.EvidenceArtifact{Kind: layout.ArtifactKind(req.Kind), Digest: layout.StoredHash(digest), Size: uint64(size)}
	err := s.index.WithArtifactLock(func() error {
		if err := publish(); err != nil {
			return err
		}
		_, err := s.index.MergeEvidence(ctx, req.TaskHash, func(existing layout.Evidence, exists bool) (layout.Evidence, error) {
			metadata := existing
			metadata.SessionID = firstNonEmptyEvidence(req.SessionID, metadata.SessionID)
			metadata.TaskID = firstNonEmptyEvidence(req.TaskID, metadata.TaskID)
			metadata.FinalityHeight = max(req.FinalityHeight, metadata.FinalityHeight)
			metadata.CleanupHeight = max(req.CleanupHeight, metadata.CleanupHeight)
			metadata.Artifacts = append([]layout.EvidenceArtifact(nil), metadata.Artifacts...)
			if len(metadata.Artifacts) == 0 && metadata.Digest != (layout.StoredHash{}) {
				metadata.Artifacts = append(metadata.Artifacts, layout.EvidenceArtifact{Digest: metadata.Digest, Size: metadata.Size})
			}
			found := false
			for _, existingArtifact := range metadata.Artifacts {
				if string(existingArtifact.Kind) == req.Kind && codec.Hash(existingArtifact.Digest) == digest && existingArtifact.Size == uint64(size) {
					found = true
				}
			}
			if !found {
				metadata.Artifacts = append(metadata.Artifacts, artifact)
			}
			seen := make(map[string]struct{})
			for _, a := range metadata.Artifacts {
				if _, ok := seen[string(a.Kind)]; ok {
					// The kind is the locator of an evidence artifact - the
					// file name is its content hash, so a second digest under
					// the same kind is exactly the "locator already bound to
					// different content" case.
					return layout.Evidence{}, fmt.Errorf("%w: task %s kind %q is already bound to different content", ErrLocalArtifactConflict, hexDigest(req.TaskHash[:]), a.Kind)
				}
				seen[string(a.Kind)] = struct{}{}
			}
			sort.Slice(metadata.Artifacts, func(i, j int) bool {
				if metadata.Artifacts[i].Kind != metadata.Artifacts[j].Kind {
					return metadata.Artifacts[i].Kind < metadata.Artifacts[j].Kind
				}
				return strings.Compare(hexDigest(metadata.Artifacts[i].Digest[:]), hexDigest(metadata.Artifacts[j].Digest[:])) < 0
			})
			metadata.Size = 0
			parts := make([][]byte, 0, len(metadata.Artifacts)*3)
			for _, item := range metadata.Artifacts {
				metadata.Size += item.Size
				parts = append(parts, []byte(item.Kind), item.Digest[:], codec.Uint64Bytes(item.Size))
			}
			if len(metadata.Artifacts) == 1 {
				metadata.Digest = metadata.Artifacts[0].Digest
			} else {
				metadata.Digest = layout.StoredHash(codec.HashWithDomain("CORTEX_TASK_EVIDENCE_PACKAGE_V1", parts...))
			}
			return metadata, nil
		})
		return err
	})
	if err != nil {
		if errors.Is(err, ErrLocalArtifactConflict) {
			return Ref{}, err
		}
		return Ref{}, fmt.Errorf("persist evidence metadata: %w", err)
	}

	return ref, nil
}

// lockPublication serializes publication of one class of one task.
func (s *Store) lockPublication(taskHash codec.Hash, class objectClass) func() {
	key := hexDigest(taskHash[:]) + "/" + string(class)
	value, _ := s.publishLocks.LoadOrStore(key, &sync.Mutex{})
	mutex := value.(*sync.Mutex)
	mutex.Lock()
	return mutex.Unlock
}

// publishSingletonClass publishes input/ or output/ by renaming the task's
// staged class directory onto the formal one. The class holds exactly one
// object in V1, but the unit of publication is the directory, so a later
// sharded or derived layout commits the same way.
func (s *Store) publishSingletonClass(taskHash codec.Hash, class objectClass, digest codec.Hash, size int64, data []byte) error {
	taskDir := filepath.Join(s.root, taskRelDir(taskHash))
	if err := s.ensureSafeDir(taskDir); err != nil {
		return err
	}
	finalDir := filepath.Join(s.root, classRelDir(taskHash, class))
	digestHex := hexDigest(digest[:])

	// No-replace publication. This package never creates a formal class
	// directory by any route other than the rename below, so a destination that
	// exists is always a complete previous publication: verify it and report an
	// idempotent success or a conflict, and never rename onto it. The residual
	// window between this Lstat and the rename is the same pathname-precheck
	// window every guard in this package has, narrowed by verifyRootTrust and
	// by lockPublication; plain POSIX rename also refuses a non-empty
	// destination with ENOTEMPTY, so the only thing a lost race could replace
	// is an empty directory that this code never produces.
	info, err := os.Lstat(finalDir)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return ErrEvidenceEscape
		}
		if err := verifySingletonClassDir(finalDir, digest, size); err != nil {
			return err
		}
		// Idempotent success: drop the staged copy of work already published.
		return s.removeStagingDir(filepath.Join(s.root, stagingRelDir(taskHash, class)))
	case !errors.Is(err, os.ErrNotExist):
		return err
	}

	stagingDir := filepath.Join(s.root, stagingRelDir(taskHash, class))
	// The staged directory is renamed whole, so anything a previous crash left
	// in it would be published too. Start from an empty one.
	if err := s.removeStagingDir(stagingDir); err != nil {
		return err
	}
	if err := s.ensureSafeDir(stagingDir); err != nil {
		return err
	}
	if err := writeStagedObject(stagingDir, digestHex, data, digest, size); err != nil {
		return err
	}
	if err := fsyncDir(stagingDir); err != nil {
		return err
	}
	if err := os.Rename(stagingDir, finalDir); err != nil {
		return err
	}
	if err := fsyncDir(taskDir); err != nil {
		return err
	}
	if err := fsyncDir(filepath.Dir(stagingDir)); err != nil {
		return err
	}
	return verifyFile(filepath.Join(finalDir, digestHex), digest, size)
}

// publishArtifact publishes one evidence artifact into evidence/artifacts/.
//
// The target design commits the whole evidence/ directory in one rename, which
// presupposes knowing the bundle's closure up front - that closure is named by
// evidence/manifest.json, which this store deliberately does not write yet.
// Cortex's artifacts also arrive across several responsibilities rather than in
// one batch. So publication is per artifact: staged, verified, then renamed
// under its content hash. Write-once, no half-written formal file, and
// idempotent on identical bytes; only bundle-level atomicity waits for the
// manifest.
func (s *Store) publishArtifact(taskHash codec.Hash, digest codec.Hash, size int64, data []byte) error {
	taskDir := filepath.Join(s.root, taskRelDir(taskHash))
	if err := s.ensureSafeDir(taskDir); err != nil {
		return err
	}
	finalDir := filepath.Join(s.root, classRelDir(taskHash, classEvidence))
	// Validate the parent chain before consulting the final entry. Lstat on the
	// final path follows a symlinked parent, so checking the file first accepted
	// an object outside the root whenever a parent directory had been replaced
	// by a symlink to a tree that already held a file of the right name and
	// bytes: ensureSafeDir never ran in that case, because it only ran when the
	// file was reported absent.
	if err := s.ensureSafeDir(finalDir); err != nil {
		return err
	}
	digestHex := hexDigest(digest[:])
	finalPath := filepath.Join(finalDir, digestHex)
	exists, err := existingSafeFile(finalPath, digest, size)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	stagingDir := filepath.Join(s.root, stagingRelDir(taskHash, classEvidence))
	if err := s.ensureSafeDir(stagingDir); err != nil {
		return err
	}
	stagedPath := filepath.Join(stagingDir, digestHex)
	if err := writeStagedObject(stagingDir, digestHex, data, digest, size); err != nil {
		return err
	}
	if err := os.Rename(stagedPath, finalPath); err != nil {
		return err
	}
	if err := fsyncDir(finalDir); err != nil {
		return err
	}
	return verifyFile(finalPath, digest, size)
}

// writeStagedObject writes data to an operation-scoped .part file inside the
// staging directory, fsyncs it, verifies the bytes actually on disk, and only
// then renames it to its content-addressed staged name. The operation id is
// generated here and never derived from an external string.
func writeStagedObject(stagingDir, name string, data []byte, digest codec.Hash, size int64) error {
	part, err := os.CreateTemp(stagingDir, ".part-*")
	if err != nil {
		return err
	}
	partPath := part.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(partPath)
		}
	}()
	if _, err := part.Write(data); err != nil {
		_ = part.Close()
		return err
	}
	if err := part.Sync(); err != nil {
		_ = part.Close()
		return err
	}
	if err := part.Close(); err != nil {
		return err
	}
	if err := verifyFile(partPath, digest, size); err != nil {
		return err
	}
	if err := os.Rename(partPath, filepath.Join(stagingDir, name)); err != nil {
		return err
	}
	committed = true
	return nil
}

// verifySingletonClassDir decides between an idempotent success and a conflict
// for an already-published input/ or output/ directory. V1 locks each class to
// exactly one object, so any other content is a locator bound to something
// else.
func verifySingletonClassDir(dir string, digest codec.Hash, size int64) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	digestHex := hexDigest(digest[:])
	if len(entries) != 1 || entries[0].Name() != digestHex {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		sort.Strings(names)
		return fmt.Errorf("%w: %s is already bound to %v, not %s", ErrLocalArtifactConflict, dir, names, digestHex)
	}
	return verifyFile(filepath.Join(dir, digestHex), digest, size)
}

// removeStagingDir drops a staging directory and everything under it. It
// refuses anything that is not a plain directory inside the root: a staging
// path replaced by a symlink must never turn a cleanup into a delete somewhere
// else.
func (s *Store) removeStagingDir(dir string) error {
	if !isWithin(s.root, dir) {
		return ErrEvidenceEscape
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrEvidenceEscape
	}
	return os.RemoveAll(dir)
}

// VerifyTaskObjects checks that every object the index records for a task is
// present and intact. A committed index row whose bytes are gone is
// ErrEvidenceUnavailable: the work behind it must not be redone, because the
// signed material that names those bytes has already been produced, so the only
// safe response is to stop signing new responsibility material for the task.
//
// A task with no index row yet is not an error - nothing has been committed, so
// there is nothing to be missing. Neither is a task whose directory has already
// been moved to trash/ by cleanup, which is reported as ErrCleanupPending
// instead so a caller can tell "retired on schedule" from "lost".
func (s *Store) VerifyTaskObjects(ctx context.Context, taskHash codec.Hash) error {
	if s.index == nil {
		return nil
	}
	metadata, err := s.index.Evidence(ctx, taskHash)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, artifact := range metadata.Artifacts {
		if artifact.Digest == (layout.StoredHash{}) {
			continue
		}
		rel := objectRelPath(taskHash, string(artifact.Kind), codec.Hash(artifact.Digest))
		path, err := resolveEvidencePath(s.root, rel)
		if errors.Is(err, os.ErrNotExist) {
			if trashed, terr := s.taskIsTrashed(taskHash); terr == nil && trashed {
				return fmt.Errorf("%w: task %s objects were moved to trash by cleanup", ErrCleanupPending, hexDigest(taskHash[:]))
			}
			return fmt.Errorf("%w: task %s kind %q digest %s is missing from %s", ErrEvidenceUnavailable,
				hexDigest(taskHash[:]), artifact.Kind, hexDigest(artifact.Digest[:]), filepath.Dir(rel))
		}
		if err != nil {
			return err
		}
		if err := verifyFile(path, codec.Hash(artifact.Digest), int64(artifact.Size)); err != nil {
			return fmt.Errorf("%w: task %s kind %q digest %s: %v", ErrEvidenceUnavailable,
				hexDigest(taskHash[:]), artifact.Kind, hexDigest(artifact.Digest[:]), err)
		}
	}
	return nil
}

func (s *Store) taskIsTrashed(taskHash codec.Hash) (bool, error) {
	info, err := os.Lstat(filepath.Join(s.root, trashRelDir(taskHash)))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

// readTaskObject reads one object of a task by its kind and content hash.
func (s *Store) readTaskObject(taskHash codec.Hash, kind string, digest codec.Hash) ([]byte, error) {
	path, err := resolveEvidencePath(s.root, objectRelPath(taskHash, kind, digest))
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := verifyFile(path, digest, int64(len(data))); err != nil {
		return nil, err
	}
	return data, nil
}

// ReadTaskKind returns the artifact data of the given kind for a task, looking
// its content hash up in the local index and reading it from the task
// directory.
func (s *Store) ReadTaskKind(ctx context.Context, taskHash codec.Hash, kind string) ([]byte, error) {
	if s.index == nil {
		return nil, fmt.Errorf("evidence metadata store is required")
	}
	ev, err := s.index.Evidence(ctx, taskHash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%w: task %s kind %q", ErrArtifactNotFound, hexDigest(taskHash[:]), kind)
	}
	if err != nil {
		return nil, err
	}
	for _, artifact := range ev.Artifacts {
		if string(artifact.Kind) == kind {
			return s.readTaskObject(taskHash, kind, codec.Hash(artifact.Digest))
		}
	}

	return nil, fmt.Errorf("%w: evidence kind %q not found for task %s", ErrArtifactNotFound, kind, hexDigest(taskHash[:]))
}

// TaskArtifacts returns the evidence manifest artifacts for a task. It is a
// convenience wrapper over the metadata store for callers that need to list
// artifacts rather than read a single kind.
func (s *Store) TaskArtifacts(ctx context.Context, taskHash codec.Hash) ([]layout.EvidenceArtifact, error) {
	if s.index == nil {
		return nil, fmt.Errorf("evidence metadata store is required")
	}
	ev, err := s.index.Evidence(ctx, taskHash)
	if err != nil {
		return nil, err
	}
	return ev.Artifacts, nil
}

func firstNonEmptyEvidence(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func verifyFile(path string, digest codec.Hash, size int64) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrEvidenceEscape
	}
	if hardlinkCount(info) > 1 {
		return ErrEvidenceEscape
	}
	if info.Size() != size {
		return ErrSizeMismatch
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	got := sha256.Sum256(data)
	if got != digest {
		return ErrDigestMismatch
	}
	return nil
}

func (s *Store) ensureSafeDir(dir string) error {
	if !isWithin(s.root, dir) {
		return ErrEvidenceEscape
	}
	rel, err := filepath.Rel(s.root, dir)
	if err != nil {
		return err
	}
	current := s.root
	if rel == "." {
		return ensureDirNoSymlink(current)
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return ErrEvidenceEscape
		}
		current = filepath.Join(current, part)
		if err := ensureDirNoSymlink(current); err != nil {
			return err
		}
	}
	return nil
}

func ensureDirNoSymlink(dir string) error {
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err = os.Lstat(dir)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrEvidenceEscape
	}
	if !info.IsDir() {
		return ErrEvidenceEscape
	}
	return nil
}

func existingSafeFile(finalPath string, digest codec.Hash, size int64) (bool, error) {
	info, err := os.Lstat(finalPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, ErrEvidenceEscape
	}
	if hardlinkCount(info) > 1 {
		return false, ErrEvidenceEscape
	}
	if err := verifyFile(finalPath, digest, size); err != nil {
		return false, err
	}
	return true, nil
}

func hardlinkCount(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 1
	}
	return uint64(stat.Nlink)
}

// verifyRootTrust refuses a CAS root that another local user could tamper with.
//
// Every symlink guard in this package is a pathname precheck: a component is
// validated with Lstat, then the operation re-resolves the same path. Closing that
// window needs openat-style traversal on a retained descriptor, which the standard
// library does not expose portably - os.Root arrives in Go 1.24 and the toolchain
// is pinned to 1.23 for the protobuf runtime. So the guards rest on an assumption:
// that no other user can plant a symlink inside the tree. This turns that
// assumption into a checked precondition rather than a comment nobody verifies.
//
// A component is trusted when it is owned by this process or by root, and is not
// writable by group or other. A world-writable directory is still trusted if it is
// sticky, because the sticky bit is precisely the rule that stops one user
// replacing another user's entry - which is the attack in question. That exemption
// is load-bearing, not a loophole: configs/dev.yaml puts the evidence root under
// /tmp, and CI's t.TempDir() does the same on Linux.
func verifyRootTrust(realRoot string) error {
	euid := os.Geteuid()
	for path := realRoot; ; {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect evidence root component %s: %w", path, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("evidence root component %s: ownership is unreadable on this platform", path)
		}
		if owner := int(stat.Uid); owner != euid && owner != 0 {
			return fmt.Errorf("%w: component %s is owned by uid %d, not this process (uid %d) or root, so that user could replace a path component between a symlink check and its use",
				ErrEvidenceRootUntrusted, path, owner, euid)
		}
		if perm := info.Mode().Perm(); perm&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("%w: component %s is mode %#o, group- or world-writable without the sticky bit, so another user could replace a path component between a symlink check and its use",
				ErrEvidenceRootUntrusted, path, perm)
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

func fsyncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// resolveEvidencePath resolves a relative path under the evidence root by walking
// each component and verifying that no component is a symlink and that the
// resolved path stays within root. It returns the absolute filesystem path.
//
// The guarantee is a pathname precheck, not a handle. Every caller re-resolves by
// path afterwards (os.ReadFile, os.ReadDir, os.Remove, os.Rename), so a component
// validated here can in principle be swapped for a symlink before it is used.
// Closing that window needs openat-style traversal on a retained directory
// descriptor, which the standard library does not offer portably - os.Root arrives
// in Go 1.24 and the toolchain is pinned to 1.23 for the protobuf runtime.
//
// What makes that residual window narrow rather than open is verifyRootTrust,
// which NewStore and Sweep both run: every component from the resolved root up to
// / must be owned by this process or by root and must not be group- or
// world-writable unless sticky. So the swap requires this process's own uid or
// root, and the precheck defeats a symlink planted by anyone else. That is a
// checked precondition, not an assumption - which is what it used to be.
func resolveEvidencePath(root, rel string) (string, error) {
	if filepath.IsAbs(rel) {
		return "", ErrEvidenceEscape
	}
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", ErrEvidenceEscape
	}
	current := root
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", ErrEvidenceEscape
		}
	}
	if !isWithin(root, current) {
		return "", ErrEvidenceEscape
	}
	return current, nil
}

func hexDigest(data []byte) string {
	return hex.EncodeToString(data)
}

func isWithin(root, candidate string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(rootAbs, candidateAbs)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." && !filepath.IsAbs(rel))
}

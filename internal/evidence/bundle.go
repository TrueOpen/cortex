package evidence

// Bundle-scoped publication of the Worker's two wire v0.3.0 evidence bundles.
// The Worker publishes both here and reads them back on recovery; the
// Verifier's own bundle is built and uploaded from its persisted reveal record
// and has no local bundle.
//
//	tasks/<taskHash[0:2]>/<taskHash>/
//	├── evidence/
//	│   └── worker/{token,value}/{manifest.json,artifacts/<artifactHash>}
//	└── .staging/evidence/<same bundle path>/
//
// A bundle is the unit of publication. Its artifacts and manifest.json are
// completed in the task's .staging/ and the whole bundle directory is renamed
// onto its formal path, so a formal bundle either does not exist or holds its
// final manifest and every artifact. The Worker token and value bundles publish
// independently and never overwrite one another.
//
// The manifest is opaque here. Its canonical content, and the rule that a
// bundle holds exactly the artifacts its manifest references, belong to the
// caller that builds it; this store only makes the bytes durable and atomic.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
)

const (
	bundleManifestName    = "manifest.json"
	bundleManifestTmpName = "manifest.tmp"
	workerProducerName    = "worker"
)

var (
	ErrBundleNotFound     = errors.New("evidence bundle is not published")
	ErrInvalidBundle      = errors.New("invalid evidence bundle")
	ErrBundleManifestSize = errors.New("evidence bundle manifest is empty")
)

// BundleID names one evidence bundle of a task. Build it with WorkerTokenBundle
// or WorkerValueBundle; every directory segment it produces is a fixed literal,
// never an external string.
type BundleID struct {
	taskHash codec.Hash
	segments []string // path below evidence/, e.g. worker/token
}

// WorkerTokenBundle is the A-level WORKER_TOKEN_OPENING bundle of a task.
func WorkerTokenBundle(taskHash codec.Hash) BundleID {
	return BundleID{taskHash: taskHash, segments: []string{workerProducerName, "token"}}
}

// WorkerValueBundle is the B-level WORKER_VALUE_OPENING bundle of a task.
func WorkerValueBundle(taskHash codec.Hash) BundleID {
	return BundleID{taskHash: taskHash, segments: []string{workerProducerName, "value"}}
}

func (id BundleID) valid() error {
	if id.taskHash == (codec.Hash{}) {
		return ErrTaskHashRequired
	}
	if len(id.segments) == 0 {
		return fmt.Errorf("%w: bundle id is not built by a constructor", ErrInvalidBundle)
	}
	return nil
}

func (id BundleID) String() string {
	return hexDigest(id.taskHash[:]) + "/" + filepath.ToSlash(filepath.Join(id.segments...))
}

// class is the bundle's publication lock key, distinct from the flat
// evidence class so bundle and legacy artifact publication never contend.
func (id BundleID) class() objectClass {
	return objectClass(filepath.Join(append([]string{evidenceName}, id.segments...)...))
}

func (id BundleID) formalRelDir() string {
	return filepath.Join(append([]string{taskRelDir(id.taskHash), evidenceName}, id.segments...)...)
}

func (id BundleID) stagingRelDir() string {
	return filepath.Join(append([]string{taskRelDir(id.taskHash), stagingName, evidenceName}, id.segments...)...)
}

// BundleArtifact is one artifact of a published bundle, named by content hash.
type BundleArtifact struct {
	Digest    codec.Hash
	SizeBytes int64
}

// BundleRef describes a published bundle. ManifestHash is evidence_bundle_hash,
// H_V1 over the exact manifest.json bytes (evidencebundle.Hash).
type BundleRef struct {
	ID                BundleID
	ManifestHash      codec.Hash
	ManifestSizeBytes int64
	Artifacts         []BundleArtifact
	Path              string
}

// BundleRequest is everything one bundle holds. Artifacts are stored under
// their content hash; the order and any repeats are irrelevant to the layout.
type BundleRequest struct {
	ID        BundleID
	Artifacts [][]byte
	Manifest  []byte
}

// PublishBundle publishes one bundle write-once.
//
// A bundle already published with the same manifest hash, and holding every
// requested artifact intact, is an idempotent success and the staged copy is
// dropped. One published under a different manifest is ErrLocalArtifactConflict.
// Otherwise every artifact and then the manifest are staged, fsynced and
// verified, and the staged bundle directory is renamed onto the formal one.
// Anything a previous crash left in the staging directory is discarded first,
// so a retry after a crash simply publishes again.
func (s *Store) PublishBundle(ctx context.Context, req BundleRequest) (BundleRef, error) {
	if err := ctx.Err(); err != nil {
		return BundleRef{}, err
	}
	if err := req.ID.valid(); err != nil {
		return BundleRef{}, err
	}
	if len(req.Manifest) == 0 {
		return BundleRef{}, ErrBundleManifestSize
	}
	artifacts := make(map[codec.Hash][]byte, len(req.Artifacts))
	for _, data := range req.Artifacts {
		if len(data) == 0 {
			return BundleRef{}, fmt.Errorf("%w: bundle %s", ErrEmptyEvidence, req.ID)
		}
		artifacts[codec.HashBytes(data)] = data
	}
	ref := BundleRef{
		ID:                req.ID,
		ManifestHash:      evidencebundle.Hash(req.Manifest),
		ManifestSizeBytes: int64(len(req.Manifest)),
		Path:              filepath.Join(s.root, req.ID.formalRelDir()),
	}
	for digest, data := range artifacts {
		ref.Artifacts = append(ref.Artifacts, BundleArtifact{Digest: digest, SizeBytes: int64(len(data))})
	}
	sortBundleArtifacts(ref.Artifacts)

	unlock := s.lockPublication(req.ID.taskHash, req.ID.class())
	defer unlock()

	taskDir := filepath.Join(s.root, taskRelDir(req.ID.taskHash))
	finalDir := ref.Path
	stagingDir := filepath.Join(s.root, req.ID.stagingRelDir())
	if err := s.ensureSafeDir(taskDir); err != nil {
		return BundleRef{}, err
	}
	// The formal parent must be a safe directory before the final entry is
	// consulted, for the same reason publishArtifact checks it first: Lstat on
	// the final path follows a symlinked parent.
	if err := s.ensureSafeDir(filepath.Dir(finalDir)); err != nil {
		return BundleRef{}, err
	}

	// No-replace publication: this package creates a formal bundle directory
	// only by the rename below, so an existing one is a complete earlier
	// publication. Decide between idempotent success and conflict; never
	// rename onto it.
	info, err := os.Lstat(finalDir)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return BundleRef{}, ErrEvidenceEscape
		}
		if err := verifyPublishedBundle(finalDir, ref); err != nil {
			return BundleRef{}, err
		}
		return ref, s.removeStagingDir(stagingDir)
	case !errors.Is(err, os.ErrNotExist):
		return BundleRef{}, err
	}

	if err := s.removeStagingDir(stagingDir); err != nil {
		return BundleRef{}, err
	}
	stagedArtifacts := filepath.Join(stagingDir, artifactsName)
	if err := s.ensureSafeDir(stagedArtifacts); err != nil {
		return BundleRef{}, err
	}
	for _, artifact := range ref.Artifacts {
		if err := ctx.Err(); err != nil {
			return BundleRef{}, err
		}
		if err := writeStagedObject(stagedArtifacts, hexDigest(artifact.Digest[:]), artifacts[artifact.Digest], artifact.Digest, artifact.SizeBytes); err != nil {
			return BundleRef{}, err
		}
	}
	if err := writeStagedManifest(stagingDir, req.Manifest); err != nil {
		return BundleRef{}, err
	}
	if err := fsyncDir(stagedArtifacts); err != nil {
		return BundleRef{}, err
	}
	if err := fsyncDir(stagingDir); err != nil {
		return BundleRef{}, err
	}
	if s.beforeBundleRename != nil {
		if err := s.beforeBundleRename(req.ID); err != nil {
			return BundleRef{}, err
		}
	}
	if err := os.Rename(stagingDir, finalDir); err != nil {
		return BundleRef{}, err
	}
	if err := fsyncDir(filepath.Dir(finalDir)); err != nil {
		return BundleRef{}, err
	}
	if err := fsyncDir(taskDir); err != nil {
		return BundleRef{}, err
	}
	if err := fsyncDir(filepath.Dir(stagingDir)); err != nil {
		return BundleRef{}, err
	}
	return ref, verifyPublishedBundle(finalDir, ref)
}

// ReadBundleManifest returns the exact manifest.json bytes of a published
// bundle and their evidence_bundle_hash.
func (s *Store) ReadBundleManifest(id BundleID) ([]byte, codec.Hash, error) {
	dir, err := s.publishedBundleDir(id)
	if err != nil {
		return nil, codec.Hash{}, err
	}
	manifest, err := readSafeFile(filepath.Join(dir, bundleManifestName))
	if err != nil {
		return nil, codec.Hash{}, err
	}
	return manifest, evidencebundle.Hash(manifest), nil
}

// ReadBundleArtifact returns one artifact of a published bundle, verified
// against the content hash and size the caller took from the manifest.
func (s *Store) ReadBundleArtifact(id BundleID, digest codec.Hash, size int64) ([]byte, error) {
	dir, err := s.publishedBundleDir(id)
	if err != nil {
		return nil, err
	}
	data, err := readSafeFile(filepath.Join(dir, artifactsName, hexDigest(digest[:])))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: bundle %s has no artifact %s", ErrArtifactNotFound, id, hexDigest(digest[:]))
	}
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != size {
		return nil, ErrSizeMismatch
	}
	if codec.HashBytes(data) != digest {
		return nil, ErrDigestMismatch
	}
	return data, nil
}

// DiscardStagedBundle drops whatever a crashed or abandoned publication left in
// the bundle's staging directory. It never touches a published bundle; the task
// directory's retirement by Cleanup removes those with the rest of the task.
func (s *Store) DiscardStagedBundle(id BundleID) error {
	if err := id.valid(); err != nil {
		return err
	}
	unlock := s.lockPublication(id.taskHash, id.class())
	defer unlock()
	return s.removeStagingDir(filepath.Join(s.root, id.stagingRelDir()))
}

func (s *Store) publishedBundleDir(id BundleID) (string, error) {
	if err := id.valid(); err != nil {
		return "", err
	}
	dir, err := resolveEvidencePath(s.root, id.formalRelDir())
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("%w: %s", ErrBundleNotFound, id)
	}
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", ErrEvidenceEscape
	}
	return dir, nil
}

// writeStagedManifest writes manifest.tmp, fsyncs and re-reads it, and only then
// renames it to manifest.json inside the staging bundle.
func writeStagedManifest(stagingDir string, manifest []byte) error {
	tmpPath := filepath.Join(stagingDir, bundleManifestTmpName)
	file, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := file.Write(manifest); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := verifyFile(tmpPath, codec.HashBytes(manifest), int64(len(manifest))); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, filepath.Join(stagingDir, bundleManifestName)); err != nil {
		return err
	}
	committed = true
	return nil
}

// verifyPublishedBundle checks a formal bundle against the one being
// published: the same manifest hash, and every requested artifact present and
// intact. A different manifest is a formal locator bound to other content.
func verifyPublishedBundle(dir string, want BundleRef) error {
	manifest, err := readSafeFile(filepath.Join(dir, bundleManifestName))
	if err != nil {
		return fmt.Errorf("%w: bundle %s manifest: %v", ErrLocalArtifactConflict, want.ID, err)
	}
	if got := evidencebundle.Hash(manifest); got != want.ManifestHash {
		return fmt.Errorf("%w: bundle %s is already published under manifest hash %s, not %s",
			ErrLocalArtifactConflict, want.ID, hexDigest(got[:]), hexDigest(want.ManifestHash[:]))
	}
	for _, artifact := range want.Artifacts {
		if err := verifyFile(filepath.Join(dir, artifactsName, hexDigest(artifact.Digest[:])), artifact.Digest, artifact.SizeBytes); err != nil {
			return fmt.Errorf("%w: bundle %s artifact %s: %v", ErrLocalArtifactConflict, want.ID, hexDigest(artifact.Digest[:]), err)
		}
	}
	return nil
}

// readSafeFile reads a file that must be neither a symlink nor hardlinked.
func readSafeFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || hardlinkCount(info) > 1 {
		return nil, ErrEvidenceEscape
	}
	return os.ReadFile(path)
}

func sortBundleArtifacts(artifacts []BundleArtifact) {
	sort.Slice(artifacts, func(i, j int) bool {
		return bytes.Compare(artifacts[i].Digest[:], artifacts[j].Digest[:]) < 0
	})
}

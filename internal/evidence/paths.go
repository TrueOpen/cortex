package evidence

// The task-scoped local layout.
//
//	<root>/
//	├── tasks/<taskHash[0:2]>/<taskHash>/
//	│   ├── input/<inputHash>
//	│   ├── output/<outputHash>
//	│   ├── evidence/artifacts/<artifactHash>
//	│   └── .staging/{input,output,evidence/artifacts}/
//	└── trash/<taskHash[0:2]>/<taskHash>/
//
// Every path component is a canonical lowercase hex hash or a fixed literal, so
// no externally supplied string ever becomes a directory segment.
//
// The Task directory is the retention and cleanup boundary: two tasks never
// share a physical file. That is the whole point of the layout and it is what
// retires the previous global content-addressed store, where cleanup had to
// reference-count digests across tasks and reclaim orphans with a full sweep.
// The cost is deliberate: identical bytes submitted for two tasks are stored
// twice.
//
// Two parts of the target design are *not* here, because they are the half that
// is still blocked upstream: evidence/manifest.json and the
// evidence_bundle_hash derived from its bytes, and therefore also the
// whole-bundle atomic publication of evidence/. Artifacts are published one
// file at a time into evidence/artifacts/ instead, which is the strongest
// invariant available while the bundle's closure is still named by the local
// index rather than by a manifest. input/ and output/ are published by
// directory rename exactly as specified, because their closure is one file.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/store/layout"
)

// objectClass is the local publication unit for one task object. It is derived
// from the artifact kind, never transmitted, and never taken from a peer.
type objectClass string

const (
	classInput    objectClass = "input"
	classOutput   objectClass = "output"
	classEvidence objectClass = "evidence"
)

const (
	tasksRoot     = "tasks"
	trashRoot     = "trash"
	stagingName   = ".staging"
	evidenceName  = "evidence"
	artifactsName = "artifacts"
	// legacyCASName is the shard root of the retired global content-addressed
	// store. NewStore refuses a root that still holds it rather than migrating
	// it in place.
	legacyCASName = "sha256"
)

// classForKind maps an artifact kind onto its publication class. INPUT and
// OUTPUT are the two singleton classes the protocol names; every other kind
// Cortex keeps locally - evidence openings, signed responsibility material,
// settlement material, outbox payloads - is an evidence artifact.
func classForKind(kind string) objectClass {
	switch kind {
	case string(layout.ArtifactTaskInput), "worker-input":
		return classInput
	case string(layout.ArtifactWorkerOutput):
		return classOutput
	default:
		return classEvidence
	}
}

func taskRelDir(taskHash codec.Hash) string {
	hexHash := hex.EncodeToString(taskHash[:])
	return filepath.Join(tasksRoot, hexHash[:2], hexHash)
}

func trashRelDir(taskHash codec.Hash) string {
	hexHash := hex.EncodeToString(taskHash[:])
	return filepath.Join(trashRoot, hexHash[:2], hexHash)
}

// classRelDir is the formal directory of a class, relative to the root.
func classRelDir(taskHash codec.Hash, class objectClass) string {
	base := taskRelDir(taskHash)
	if class == classEvidence {
		return filepath.Join(base, evidenceName, artifactsName)
	}
	return filepath.Join(base, string(class))
}

// stagingRelDir is the staging directory of a class, relative to the root. Each
// task has exactly one .staging/, inside the task directory and beside the
// formal class directories - never a global staging area, so a staged byte can
// never be attributed to the wrong task.
func stagingRelDir(taskHash codec.Hash, class objectClass) string {
	base := filepath.Join(taskRelDir(taskHash), stagingName)
	if class == classEvidence {
		return filepath.Join(base, evidenceName, artifactsName)
	}
	return filepath.Join(base, string(class))
}

func objectRelPath(taskHash codec.Hash, kind string, digest codec.Hash) string {
	return filepath.Join(classRelDir(taskHash, classForKind(kind)), hex.EncodeToString(digest[:]))
}

// refuseLegacyLayout reports the retired global CAS tree instead of migrating
// it. The target design requires an explicit drain or a one-shot migration
// tool; silently ignoring the old tree would leak every byte in it forever and
// leave the evidence index pointing at paths this store can no longer resolve.
func refuseLegacyLayout(root string) error {
	legacy := filepath.Join(root, legacyCASName)
	entries, err := os.ReadDir(legacy)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s still holds %d shard(s) written by the pre-task-scoped store, and this store cannot resolve them. "+
		"Cortex does not migrate the tree in place: drain the node (let in-flight tasks finish, then stop cortexd), delete %s and the evidence index rows that point into it, and restart. "+
		"See docs/operations/evidence-retention.md",
		ErrLegacyEvidenceLayout, legacy, len(entries), legacy)
}

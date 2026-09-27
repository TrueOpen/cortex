package modelservice

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ManifestSource hands back the profile manifest bytes for one registered
// profile, verbatim as they were distributed.
//
// Nothing here has to be trusted. The bytes are checked against the manifest
// hash the chain holds for that profile before any field is read, so a source
// can be a local file, an operator copy or anything else: a wrong document is
// rejected by the digest rather than by trusting where it came from.
type ManifestSource interface {
	ProfileManifest(ctx context.Context, modelID, profileVersion string) ([]byte, error)
}

// ManifestSourceFunc adapts a plain function to ManifestSource.
type ManifestSourceFunc func(ctx context.Context, modelID, profileVersion string) ([]byte, error)

func (f ManifestSourceFunc) ProfileManifest(ctx context.Context, modelID, profileVersion string) ([]byte, error) {
	return f(ctx, modelID, profileVersion)
}

// DirManifestSource reads manifests from one directory, named
// "<model_id>@<profile_version>.json" -- the same key the resolved-profile
// cache uses, so an operator placing a file can read the pairing off the
// node's own configuration instead of inventing one.
type DirManifestSource struct {
	dir string
}

func NewDirManifestSource(dir string) *DirManifestSource {
	return &DirManifestSource{dir: strings.TrimSpace(dir)}
}

func (d *DirManifestSource) ProfileManifest(_ context.Context, modelID, profileVersion string) ([]byte, error) {
	if d == nil || d.dir == "" {
		return nil, fmt.Errorf("no model manifest directory is configured")
	}
	name, err := manifestFileName(modelID, profileVersion)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(d.dir, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		// Name the path. The operator's next step is to put a file there, and
		// an error that only says "not found" makes them guess the convention.
		return nil, fmt.Errorf("read model manifest %s: %w", path, err)
	}
	return raw, nil
}

// manifestFileName refuses anything that could leave the directory. The model
// id reaches here from the chain, so it is not operator input, but it is also
// not this process's own string: a separator or a parent reference in it would
// turn a manifest lookup into an arbitrary file read.
func manifestFileName(modelID, profileVersion string) (string, error) {
	modelID = strings.TrimSpace(modelID)
	profileVersion = strings.TrimSpace(profileVersion)
	if modelID == "" || profileVersion == "" {
		return "", fmt.Errorf("model manifest lookup needs both model_id and profile_version, got %q@%q", modelID, profileVersion)
	}
	for _, part := range []string{modelID, profileVersion} {
		if strings.ContainsAny(part, `/\`) || part == "." || part == ".." {
			return "", fmt.Errorf("model manifest lookup rejects path characters in %q", part)
		}
	}
	return modelID + "@" + profileVersion + ".json", nil
}

// Package wirevectors serves github.com/TrueOpen/wire's published cross-language
// vectors to the tests that check this repository's digests against them.
//
// It exists because those vectors are consumed from more than one package --
// internal/keepercontract derives three Hub domains and internal/chainclient
// derives a fourth -- and a copy per package would be 80 KB of duplicated
// fixture whose two halves could silently drift apart. The bytes are embedded
// rather than read from disk so a caller's working directory cannot change
// which file is checked.
//
// The vectors are wire v0.2.0's files copied byte for byte, plus a small
// pre-release set copied from an untagged wire commit (see
// PrereleaseWireCommit) for encoders written ahead of the next release. VerifyProvenance
// checks the embedded bytes against wire's own release manifest, which is what
// makes them evidence rather than transcription: without it a fixture could be
// edited to agree with whatever this repository happens to compute, which is
// precisely the failure a cross-implementation vector exists to catch.
//
// This package holds no production code. Nothing outside a _test.go file may
// import it.
package wirevectors

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// WireVersion is the wire release the embedded files were copied from. Raising
// the go.mod dependency without recopying these is a drift this constant makes
// visible in a diff.
const WireVersion = "v0.2.0"

//go:embed testdata/v020
var released embed.FS

// PrereleaseWireCommit is the unreleased wire commit the v030rc files were
// copied from: TrueOpen/wire#14, which carries the v0.3.0 contract but is not
// tagged yet. These vectors let the v0.3.0 encoders be written and checked
// before the dependency can be raised. When v0.3.0 is tagged, the released
// files replace this set and this constant goes away.
const PrereleaseWireCommit = "cf6402f"

//go:embed testdata/v030rc
var prerelease embed.FS

// vectorSet is one embedded copy of wire's testdata and the checksum of the
// manifest it was copied with.
type vectorSet struct {
	fs          embed.FS
	dir         string
	version     string
	manifestSum string
}

var (
	releasedSet = vectorSet{
		fs: released, dir: "testdata/v020", version: WireVersion,
		manifestSum: "cc378b636c088ad4a2b165bc25b6549c9c7df20046eb8d5e4883c06199102a3f",
	}
	prereleaseSet = vectorSet{
		fs: prerelease, dir: "testdata/v030rc", version: PrereleaseWireCommit,
		manifestSum: "d272b9e95b7cfb4b2ca56a269201ab7b4fce0abce2a85e7be322fab69cb7cf66",
	}
)

// File returns exact released fixture bytes after checking their provenance.
func File(path string) ([]byte, error) {
	return releasedSet.file(path)
}

// PrereleaseFile returns exact fixture bytes from PrereleaseWireCommit after
// checking them against that commit's own manifest. Only files this repository
// already derives are copied, so an unregistered or uncopied path is an error.
func PrereleaseFile(path string) ([]byte, error) {
	return prereleaseSet.file(path)
}

func (set vectorSet) file(path string) ([]byte, error) {
	manifestBytes, err := set.fs.ReadFile(set.dir + "/manifest.json")
	if err != nil {
		return nil, err
	}
	if path == "manifest.json" {
		return manifestBytes, nil
	}
	if sum := sha256.Sum256(manifestBytes); hex.EncodeToString(sum[:]) != set.manifestSum {
		return nil, fmt.Errorf("wire %s fixture manifest checksum mismatch", set.version)
	}
	var manifest releaseManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, err
	}
	for _, item := range manifest.Files {
		if item.Path != path {
			continue
		}
		data, err := set.fs.ReadFile(set.dir + "/" + path)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != item.SHA256 {
			return nil, fmt.Errorf("wire %s fixture %s hash mismatch", set.version, path)
		}
		return data, nil
	}
	return nil, fmt.Errorf("wire %s fixture %s is not registered", set.version, path)
}

// hubDomainsManifestPath is the path this file has inside wire's release
// manifest, which is where its expected digest is recorded.
const hubDomainsManifestPath = "hub/hub_domains_v1.json"

// HubDomainVector is one published H_FIELDS_V1 vector: the domain, the exact
// preimage bytes and the digest a conforming implementation must produce.
type HubDomainVector struct {
	Name        string `json:"name"`
	Domain      string `json:"domain"`
	Framing     string `json:"framing"`
	Producer    string `json:"producer"`
	PreimageHex string `json:"preimage_hex"`
	DigestHex   string `json:"digest_hex"`
}

type hubDomainsFile struct {
	Schema  string            `json:"schema"`
	Vectors []HubDomainVector `json:"vectors"`
}

type releaseManifest struct {
	Files []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"files"`
}

// VerifyProvenance reports whether the embedded hub vectors are still wire's
// published bytes, by hashing them against wire's own release manifest.
func VerifyProvenance() error {
	_, err := File(hubDomainsManifestPath)
	return err
}

// HubDomain returns the published vector for one domain. A missing domain is an
// error rather than a zero value: a test that silently skipped its vector would
// report a pass for a check that never ran.
func HubDomain(domain string) (HubDomainVector, error) {
	data, err := File(hubDomainsManifestPath)
	if err != nil {
		return HubDomainVector{}, err
	}
	var file hubDomainsFile
	if err := json.Unmarshal(data, &file); err != nil {
		return HubDomainVector{}, fmt.Errorf("decode wire hub domain vectors: %w", err)
	}
	for _, vector := range file.Vectors {
		if vector.Domain == domain {
			if vector.DigestHex == "" {
				return HubDomainVector{}, fmt.Errorf("wire vector for %s publishes no digest", domain)
			}
			return vector, nil
		}
	}
	return HubDomainVector{}, fmt.Errorf("wire %s publishes no vector for %s", WireVersion, domain)
}

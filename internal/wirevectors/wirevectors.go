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
// The vectors are wire's testdata/v1 at WireVersion copied byte for byte.
// VerifyProvenance checks the embedded bytes against that release's own
// fixture manifest, which is what
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

// WireVersion names the wire version the embedded files were copied from. It
// is the go.mod pseudo-version of the Phase 1 candidate contract, which is not
// a release yet.
// Raising the go.mod dependency without recopying these is a drift this
// constant makes visible in a diff.
const WireVersion = "v0.5.2-0.20261029083751-916e3936355c"

// WireCommit is the wire commit the embedded files were copied from.
const WireCommit = "916e3936355cb787f6e82509619f55c6b5aad7e2"

//go:embed testdata/p1-916e393
var released embed.FS

// vectorSet is one embedded copy of wire's testdata and the checksum of the
// manifest it was copied with.
type vectorSet struct {
	fs          embed.FS
	dir         string
	version     string
	manifestSum string
}

var releasedSet = vectorSet{
	fs: released, dir: "testdata/p1-916e393", version: WireVersion,
	manifestSum: "e2a53f71d2080479e3e2e79f675ffdb3438a0e91cbfd57072d762128367d8c27",
}

// File returns exact released fixture bytes after checking their provenance.
func File(path string) ([]byte, error) {
	return releasedSet.file(path)
}

func (set vectorSet) file(path string) ([]byte, error) {
	manifestBytes, err := set.fs.ReadFile(set.dir + "/manifest.json")
	if err != nil {
		return nil, err
	}
	// The manifest itself is served only once its pinned checksum matches.
	if sum := sha256.Sum256(manifestBytes); hex.EncodeToString(sum[:]) != set.manifestSum {
		return nil, fmt.Errorf("wire %s fixture manifest checksum mismatch", set.version)
	}
	if path == "manifest.json" {
		return manifestBytes, nil
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

// dispatchManifestPath is the Phase 1 dispatch signing table inside wire's
// release manifest.
const dispatchManifestPath = "task/dispatch_v1.json"

// DispatchVector is one row of wire's task/dispatch_v1.json signing table.
type DispatchVector struct {
	Name         string `json:"name"`
	MessageName  string `json:"message_name"`
	Domain       string `json:"domain"`
	ProtobufHex  string `json:"protobuf_hex"`
	PreimageHex  string `json:"preimage_hex"`
	DigestHex    string `json:"digest_hex"`
	SignatureHex string `json:"signature_hex"`
	PublicKeyHex string `json:"public_key_hex"`
}

// DispatchVectors returns the rows of task/dispatch_v1.json that carry a
// protobuf message, after the provenance check File performs. Rows that only
// publish a derived digest (entry, roster, challenge and evidence digests) have
// no message to convert and are left to the tests of their own producers.
func DispatchVectors() ([]DispatchVector, error) {
	data, err := File(dispatchManifestPath)
	if err != nil {
		return nil, err
	}
	var file struct {
		Vectors []DispatchVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("decode wire dispatch vectors: %w", err)
	}
	var out []DispatchVector
	for _, v := range file.Vectors {
		if v.MessageName != "" && v.ProtobufHex != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("wire %s publishes no dispatch message vectors", WireVersion)
	}
	return out, nil
}

// DispatchVectorByName returns one message row of task/dispatch_v1.json. A
// missing row is an error, never a zero value.
func DispatchVectorByName(name string) (DispatchVector, error) {
	rows, err := DispatchVectors()
	if err != nil {
		return DispatchVector{}, err
	}
	for _, row := range rows {
		if row.Name == name {
			return row, nil
		}
	}
	return DispatchVector{}, fmt.Errorf("wire %s publishes no dispatch vector %s", WireVersion, name)
}

// DispatchSection decodes one top-level section of task/dispatch_v1.json
// (for example "vrf", "handraise_merkle" or "epoch_seed_derivation") into
// target. A missing section is an error.
func DispatchSection(section string, target any) error {
	data, err := File(dispatchManifestPath)
	if err != nil {
		return err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("decode wire dispatch vectors: %w", err)
	}
	raw, ok := doc[section]
	if !ok {
		return fmt.Errorf("wire %s dispatch vectors have no %s section", WireVersion, section)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("decode wire dispatch section %s: %w", section, err)
	}
	return nil
}

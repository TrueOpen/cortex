package modelmanifest

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// FetcherConfig names where a manifest may come from besides its
// manifest_uri. Every field is optional.
type FetcherConfig struct {
	// CacheDir holds verified manifests as <manifest_hash hex>.json.
	CacheDir string
	// IPFSGateway is the operator's gateway for ipfs:// manifest URIs, as an
	// https URL or an http URL on a loopback host. Without it ipfs:// URIs
	// are not fetched; there is no default public gateway.
	IPFSGateway string
	// Mirrors are https base URLs of services that serve a manifest by its
	// hash, at <mirror>/<manifest_hash hex>.
	Mirrors []string
}

// Fetcher obtains a registered profile's manifest and returns it only after
// Verify has accepted it against the chain.
type Fetcher struct {
	cfg        FetcherConfig
	downloader *Downloader
}

func NewFetcher(cfg FetcherConfig, downloader *Downloader) (*Fetcher, error) {
	if downloader == nil {
		downloader = NewDownloader(DownloaderConfig{})
	}
	if cfg.IPFSGateway != "" {
		gateway, err := url.Parse(cfg.IPFSGateway)
		if err != nil || gateway.Host == "" || gateway.User != nil || gateway.RawQuery != "" || gateway.Fragment != "" ||
			!(gateway.Scheme == "https" || gateway.Scheme == "http" && isLoopbackHost(gateway.Hostname())) {
			return nil, fmt.Errorf("ipfs gateway %q must be an https URL, or http on a loopback host, without userinfo, query or fragment", cfg.IPFSGateway)
		}
		cfg.IPFSGateway = strings.TrimSuffix(cfg.IPFSGateway, "/")
	}
	mirrors := make([]string, len(cfg.Mirrors))
	for index, mirror := range cfg.Mirrors {
		parsed, err := ParseURI(mirror, NoLengthCap)
		if err != nil || parsed.Scheme != "https" || strings.Contains(parsed.Rest, "?") {
			return nil, fmt.Errorf("manifest mirror %q must be an https URL without query or fragment", mirror)
		}
		mirrors[index] = strings.TrimSuffix(mirror, "/")
	}
	cfg.Mirrors = mirrors
	return &Fetcher{cfg: cfg, downloader: downloader}, nil
}

// Fetched is a verified manifest and where it came from.
type Fetched struct {
	Manifest *Manifest
	Bytes    []byte
	Source   string
}

// Fetch tries the local cache, then the profile's manifest_uri, then each
// mirror, and re-checks the hash at each. A source whose bytes do not hash to
// the chain's manifest_hash is skipped. Bytes that do hash to it but fail
// verification end the search, since every copy of those bytes is equally
// invalid.
func (f *Fetcher) Fetch(ctx context.Context, chain chainclient.CurrentModelProfileSnapshot) (Fetched, error) {
	return f.fetch(ctx, chain.Profile, func(body []byte) (*Manifest, error) { return Verify(body, chain) })
}

// OutputDecoding returns the output_decoding block of a registered profile's
// manifest. It searches the same sources in the same order as Fetch and
// shares its cache, but accepts any bytes that hash to the chain's
// manifest_hash and carry a valid output_decoding block (VerifyOutputDecoding):
// the rest of the manifest does not have to pass the full schema.
func (f *Fetcher) OutputDecoding(ctx context.Context, profile chainclient.CurrentProfileSnapshot) (OutputDecoding, error) {
	var decoding OutputDecoding
	_, err := f.fetch(ctx, profile, func(body []byte) (*Manifest, error) {
		var err error
		decoding, err = VerifyOutputDecoding(body, profile.ManifestHash)
		return nil, err
	})
	if err != nil {
		return OutputDecoding{}, err
	}
	return decoding, nil
}

// DecodeVectors returns the DECODE_VECTORS conformance cases of a registered
// profile's manifest, or nil when the manifest declares none
// (decode_vectors_path ""). The manifest is obtained like OutputDecoding --
// hash-authenticated, through the shared cache and sources -- and names the
// vectors file and its sha256. The file's bytes are then read from the cache
// as <sha256 hex>.decode_vectors.json (where an operator may also place them
// by hand, like their own manifests) or fetched from each mirror at
// <mirror>/<sha256 hex>, and accepted only when they hash to that digest.
func (f *Fetcher) DecodeVectors(ctx context.Context, profile chainclient.CurrentProfileSnapshot) ([]DecodeVector, error) {
	var ref DecodeVectorsRef
	if _, err := f.fetch(ctx, profile, func(body []byte) (*Manifest, error) {
		var err error
		ref, err = VerifyDecodeVectorsRef(body, profile.ManifestHash)
		return nil, err
	}); err != nil {
		return nil, err
	}
	if !ref.IsDeclared() {
		return nil, nil
	}
	digestHex := hex.EncodeToString(ref.SHA256[:])
	var failures []string
	// try mirrors fetch's source handling: a source whose bytes do not hash to
	// the committed digest is skipped, committed bytes that do not parse end
	// the search, since every copy of them is equally invalid.
	try := func(source string, body []byte, err error) ([]DecodeVector, bool, error) {
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", source, err))
			return nil, false, nil
		}
		vectors, err := ref.Verify(body)
		if errors.Is(err, ErrInvalid) {
			return nil, true, fmt.Errorf("decode vectors sha256:%s from %s: %w", digestHex, source, err)
		}
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", source, err))
			return nil, false, nil
		}
		return vectors, true, nil
	}
	cachePath := ""
	if f.cfg.CacheDir != "" {
		cachePath = filepath.Join(f.cfg.CacheDir, digestHex+".decode_vectors.json")
		body, err := readCacheFile(cachePath)
		if errors.Is(err, os.ErrNotExist) {
			failures = append(failures, fmt.Sprintf("cache: no %s.decode_vectors.json", digestHex))
		} else {
			vectors, done, verifyErr := try("cache", body, err)
			if done {
				return vectors, verifyErr
			}
			// A cached copy that no longer verifies is dropped.
			_ = os.Remove(cachePath)
		}
	}
	for _, mirror := range f.cfg.Mirrors {
		location := mirror + "/" + digestHex
		body, err := f.downloader.Get(ctx, location)
		vectors, done, verifyErr := try("mirror "+location, body, err)
		if done {
			if verifyErr == nil && cachePath != "" {
				// A cache write failure does not fail the fetch.
				_ = writeCacheFile(f.cfg.CacheDir, cachePath, body)
			}
			return vectors, verifyErr
		}
	}
	if len(failures) == 0 {
		return nil, fmt.Errorf("decode vectors sha256:%s: no cache or mirror is configured", digestHex)
	}
	return nil, fmt.Errorf("decode vectors sha256:%s not obtained: %s", digestHex, strings.Join(failures, "; "))
}

// fetch runs the source search for one profile. verify must return an error
// wrapping ErrHashMismatch for bytes that are not the committed manifest, and
// one wrapping ErrInvalid for committed bytes that cannot be used.
func (f *Fetcher) fetch(ctx context.Context, profile chainclient.CurrentProfileSnapshot, verify func([]byte) (*Manifest, error)) (Fetched, error) {
	manifestURI := profile.ManifestURI
	if !profile.ManifestHash.IsSet() {
		return Fetched{}, errors.New("chain profile has no manifest_hash")
	}
	hashHex := profile.ManifestHash.Hex()
	var failures []string
	try := func(source string, body []byte, err error) (Fetched, bool, error) {
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", source, err))
			return Fetched{}, false, nil
		}
		manifest, err := verify(body)
		if errors.Is(err, ErrInvalid) {
			return Fetched{}, true, fmt.Errorf("manifest %s from %s: %w", hashHex, source, err)
		}
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", source, err))
			return Fetched{}, false, nil
		}
		return Fetched{Manifest: manifest, Bytes: body, Source: source}, true, nil
	}

	if f.cfg.CacheDir != "" {
		body, err := readCacheFile(f.cachePath(hashHex))
		if !errors.Is(err, os.ErrNotExist) {
			fetched, done, verifyErr := try("cache", body, err)
			if done {
				return fetched, verifyErr
			}
			// A cached copy that no longer verifies is dropped.
			_ = os.Remove(f.cachePath(hashHex))
		}
	}
	if manifestURI != "" {
		body, err := f.fetchURI(ctx, manifestURI)
		fetched, done, verifyErr := try("manifest_uri "+manifestURI, body, err)
		if done {
			return f.store(fetched, verifyErr)
		}
	}
	for _, mirror := range f.cfg.Mirrors {
		location := mirror + "/" + hashHex
		body, err := f.downloader.Get(ctx, location)
		fetched, done, verifyErr := try("mirror "+location, body, err)
		if done {
			return f.store(fetched, verifyErr)
		}
	}
	if len(failures) == 0 {
		return Fetched{}, fmt.Errorf("manifest %s: no cache, manifest_uri or mirror is configured", hashHex)
	}
	return Fetched{}, fmt.Errorf("manifest %s not obtained: %s", hashHex, strings.Join(failures, "; "))
}

func (f *Fetcher) fetchURI(ctx context.Context, raw string) ([]byte, error) {
	// The chain already enforced max_manifest_uri_bytes on this value.
	parsed, err := ParseURI(raw, NoLengthCap)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme == "https" {
		return f.downloader.Get(ctx, raw)
	}
	if f.cfg.IPFSGateway == "" {
		return nil, errors.New("ipfs:// needs an operator-configured IPFS gateway")
	}
	return f.downloader.getTrusted(ctx, f.cfg.IPFSGateway+"/ipfs/"+parsed.CID+parsed.Rest)
}

func (f *Fetcher) cachePath(hashHex string) string {
	return filepath.Join(f.cfg.CacheDir, hashHex+".json")
}

// store writes a verified manifest to the cache. A cache write failure does
// not fail the fetch.
func (f *Fetcher) store(fetched Fetched, err error) (Fetched, error) {
	if err != nil || f.cfg.CacheDir == "" {
		return fetched, err
	}
	digest := Hash(fetched.Bytes)
	_ = writeCacheFile(f.cfg.CacheDir, f.cachePath(digest.String()), fetched.Bytes)
	return fetched, nil
}

func readCacheFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, MaxManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxManifestBytes {
		return nil, fmt.Errorf("cached file is above max_manifest_bytes %d", MaxManifestBytes)
	}
	return body, nil
}

func writeCacheFile(dir, path string, body []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".manifest-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(body); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

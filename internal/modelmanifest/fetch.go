package modelmanifest

import (
	"context"
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
	manifestURI := chain.Profile.ManifestURI
	if !chain.Profile.ManifestHash.IsSet() {
		return Fetched{}, errors.New("chain profile has no manifest_hash")
	}
	hashHex := chain.Profile.ManifestHash.Hex()
	var failures []string
	try := func(source string, body []byte, err error) (Fetched, bool, error) {
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", source, err))
			return Fetched{}, false, nil
		}
		manifest, err := Verify(body, chain)
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

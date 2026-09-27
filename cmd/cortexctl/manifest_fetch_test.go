package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

type fakeProfileReader struct {
	snapshot  chainclient.CurrentModelProfileSnapshot
	err       error
	requested []string
}

func (f *fakeProfileReader) CurrentModelProfile(_ context.Context, modelID, profileVersion string) (chainclient.CurrentModelProfileSnapshot, error) {
	f.requested = append(f.requested, modelID+"@"+profileVersion)
	return f.snapshot, f.err
}

func runManifestFetch(t *testing.T, reader *fakeProfileReader, args ...string) (string, error) {
	t.Helper()
	var stdout bytes.Buffer
	cmd := newModelManifestFetchCommand(&stdout, func(string) currentProfileReader { return reader }, nil)
	cmd.SetArgs(args)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	err := cmd.ExecuteContext(context.Background())
	return stdout.String(), err
}

func TestManifestFetchRequiresTheChainAndProfile(t *testing.T) {
	modelID := strings.Repeat("ab", 32)
	for _, args := range [][]string{
		{modelID, "--profile-version", "1"},
		{modelID, "--rpc", "http://127.0.0.1:26657"},
	} {
		if _, err := runManifestFetch(t, &fakeProfileReader{}, args...); err == nil || !strings.Contains(err.Error(), "--rpc and --profile-version") {
			t.Fatalf("%v: %v", args, err)
		}
	}
}

func TestManifestFetchRefusesAnHTTPMirror(t *testing.T) {
	reader := &fakeProfileReader{}
	_, err := runManifestFetch(t, reader, strings.Repeat("ab", 32), "--rpc", "http://127.0.0.1:26657", "--profile-version", "1", "--mirror", "http://mirror.example/m")
	if err == nil || !strings.Contains(err.Error(), "must be an https URL") || len(reader.requested) != 0 {
		t.Fatalf("http mirror: %v, chain reads %v", err, reader.requested)
	}
}

func TestManifestFetchReportsChainErrors(t *testing.T) {
	reader := &fakeProfileReader{err: chainclient.ErrNotFound}
	modelID := strings.Repeat("ab", 32)
	_, err := runManifestFetch(t, reader, modelID, "--rpc", "http://127.0.0.1:26657", "--profile-version", "2")
	if !errors.Is(err, chainclient.ErrNotFound) || len(reader.requested) != 1 || reader.requested[0] != modelID+"@2" {
		t.Fatalf("err %v, requested %v", err, reader.requested)
	}
}

// A cached file that does not hash to the chain's manifest_hash is never
// used, and the failure names the source that was tried.
func TestManifestFetchVerifiesTheCacheAgainstTheChain(t *testing.T) {
	hash := bytes.Repeat([]byte{0x6f}, 32)
	reader := &fakeProfileReader{snapshot: chainclient.CurrentModelProfileSnapshot{
		Profile: chainclient.CurrentProfileSnapshot{ModelID: strings.Repeat("ab", 32), ManifestHash: hash},
	}}
	cache := t.TempDir()
	cached := filepath.Join(cache, chainclient.ProtoBytes32(hash).Hex()+".json")
	if err := os.WriteFile(cached, []byte(`{"manifest_version":4}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runManifestFetch(t, reader, strings.Repeat("ab", 32), "--rpc", "http://127.0.0.1:26657", "--profile-version", "1", "--cache-dir", cache)
	if err == nil || !strings.Contains(err.Error(), "cache: manifest bytes do not hash") {
		t.Fatalf("unverified cache was accepted: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(cached); !os.IsNotExist(statErr) {
		t.Fatalf("stale cache entry was kept: %v", statErr)
	}
}

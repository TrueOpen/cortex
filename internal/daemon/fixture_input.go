package daemon

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/codec"
)

type FixtureTaskInputResolver struct {
	root string
}

func NewFixtureTaskInputResolver(fixtureRoot string) (*FixtureTaskInputResolver, error) {
	fixtureRoot = strings.TrimSpace(fixtureRoot)
	if fixtureRoot == "" {
		return nil, fmt.Errorf("fixture root is required")
	}
	root, err := filepath.Abs(fixtureRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve fixture root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "inputs"), 0o700); err != nil {
		return nil, fmt.Errorf("create fixture input directory: %w", err)
	}
	return &FixtureTaskInputResolver{root: root}, nil
}

func (r *FixtureTaskInputResolver) ResolveTaskInput(ctx context.Context, ref TaskInputRef) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest, err := fixturePayloadDigest(ref.PayloadCID)
	if err != nil {
		return nil, err
	}
	if ref.PayloadHash.IsZero() || digest != ref.PayloadHash.String() {
		return nil, fmt.Errorf("fixture payload cid does not match expected payload hash")
	}
	data, err := os.ReadFile(filepath.Join(r.root, "inputs", digest+".bin"))
	if err != nil {
		return nil, builderclient.Retryable(fmt.Errorf("read fixture task input: %w", err))
	}
	if got := chainclient.HexHash(codec.HashBytes(data)).String(); got != digest {
		return nil, fmt.Errorf("fixture task input digest %s does not match cid %s", got, digest)
	}
	return data, nil
}

func fixturePayloadDigest(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse fixture payload cid: %w", err)
	}
	if u.Scheme != "fixture" || u.Host != "sha256" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("fixture payload cid must use fixture://sha256/<hash>")
	}
	digest := strings.TrimPrefix(u.EscapedPath(), "/")
	if strings.Contains(digest, "/") || digest != strings.TrimPrefix(u.Path, "/") || len(digest) != 64 || digest != strings.ToLower(digest) {
		return "", fmt.Errorf("fixture payload cid contains an invalid sha256 digest")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", fmt.Errorf("fixture payload cid contains an invalid sha256 digest")
	}
	return digest, nil
}

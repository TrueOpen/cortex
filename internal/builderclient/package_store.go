package builderclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/SingaXYZ/cortex/internal/codec"
)

const outputPackageVersion = "CORTEX_FAKE_OUTPUT_PACKAGE_V1"

var ErrOutputPackageDigestMismatch = errors.New("output package digest mismatch")

type FixtureOutputPackageStore struct {
	root string
}

func CanonicalOutputPackageHash(pkg OutputPackage) (codec.Hash, error) {
	payload, err := encodeCanonicalOutputPackage(pkg)
	if err != nil {
		return codec.Hash{}, err
	}
	return codec.HashBytes(payload), nil
}

// FixtureOutputPackageRef is the address of a canonical output package inside
// the fixture package store the two nodes share. It is deliberately not a Nexus
// locator: the task-data contract returns none (nexus/v1 §2.3), so the
// only way to name a package without trusting a bus hint is to re-encode the
// chain-committed canonical package hash in this store's own scheme. The store
// re-verifies that the bytes behind the address hash back to the same value.
func FixtureOutputPackageRef(packageHash codec.Hash) string {
	return "fixture://sha256/" + hex.EncodeToString(packageHash[:])
}

func NewFixtureOutputPackageStore(fixtureRoot string) (*FixtureOutputPackageStore, error) {
	fixtureRoot = strings.TrimSpace(fixtureRoot)
	if fixtureRoot == "" {
		return nil, fmt.Errorf("fixture output package root is required")
	}
	root, err := filepath.Abs(fixtureRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve fixture output package root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "output-packages"), 0o700); err != nil {
		return nil, fmt.Errorf("create fixture output package directory: %w", err)
	}
	return &FixtureOutputPackageStore{root: root}, nil
}

func (s *FixtureOutputPackageStore) SaveOutputPackage(ctx context.Context, pkg OutputPackage) (OutputPackage, string, error) {
	if err := ctx.Err(); err != nil {
		return OutputPackage{}, "", err
	}
	payload, err := encodeCanonicalOutputPackage(pkg)
	if err != nil {
		return OutputPackage{}, "", err
	}
	hash := codec.HashBytes(payload)
	if pkg.PackageHash != (codec.Hash{}) && pkg.PackageHash != hash {
		return OutputPackage{}, "", fmt.Errorf("%w: supplied hash does not match canonical bytes", ErrOutputPackageDigestMismatch)
	}
	pkg.PackageHash = hash
	digest := hex.EncodeToString(hash[:])
	if err := writePackageFileAtomically(s.packagePath(digest), payload); err != nil {
		return OutputPackage{}, "", err
	}
	sidecar, err := json.Marshal(struct {
		ReceiptHash     string `json:"receipt_hash"`
		ReceiptPayload  []byte `json:"receipt_payload"`
		WorkerSignature []byte `json:"worker_signature"`
	}{hex.EncodeToString(pkg.ReceiptHash[:]), pkg.ReceiptPayload, pkg.WorkerSignature})
	if err != nil {
		return OutputPackage{}, "", err
	}
	if err := writePackageFileAtomically(s.receiptPath(digest), sidecar); err != nil {
		return OutputPackage{}, "", err
	}
	return pkg, FixtureOutputPackageRef(hash), nil
}

func (s *FixtureOutputPackageStore) LoadOutputPackage(ctx context.Context, cid string, expected codec.Hash) (OutputPackage, error) {
	if err := ctx.Err(); err != nil {
		return OutputPackage{}, err
	}
	digest, err := parseFixturePackageCID(cid)
	if err != nil {
		return OutputPackage{}, err
	}
	if expected == (codec.Hash{}) || digest != hex.EncodeToString(expected[:]) {
		return OutputPackage{}, fmt.Errorf("%w: cid does not match expected hash", ErrOutputPackageDigestMismatch)
	}
	payload, err := os.ReadFile(s.packagePath(digest))
	if err != nil {
		return OutputPackage{}, fmt.Errorf("read fixture output package: %w", err)
	}
	if got := codec.HashBytes(payload); got != expected {
		return OutputPackage{}, fmt.Errorf("%w: package bytes do not match cid", ErrOutputPackageDigestMismatch)
	}
	pkg, err := decodeCanonicalOutputPackage(payload)
	if err != nil {
		return OutputPackage{}, err
	}
	pkg.PackageHash = expected
	sidecar, err := os.ReadFile(s.receiptPath(digest))
	if err != nil {
		return OutputPackage{}, fmt.Errorf("read fixture output package receipt: %w", err)
	}
	var receipt struct {
		ReceiptHash     string `json:"receipt_hash"`
		ReceiptPayload  []byte `json:"receipt_payload"`
		WorkerSignature []byte `json:"worker_signature"`
	}
	if err := json.Unmarshal(sidecar, &receipt); err != nil {
		return OutputPackage{}, fmt.Errorf("decode fixture output package receipt: %w", err)
	}
	receiptHash, err := parseLowerHexHash(receipt.ReceiptHash, "receipt_hash")
	if err != nil {
		return OutputPackage{}, err
	}
	pkg.ReceiptHash = receiptHash
	pkg.ReceiptPayload = receipt.ReceiptPayload
	pkg.WorkerSignature = receipt.WorkerSignature
	return pkg, nil
}

func encodeCanonicalOutputPackage(pkg OutputPackage) ([]byte, error) {
	if pkg.SessionID == "" || pkg.TaskID == "" || pkg.ModelID == "" || pkg.ProfileVersion == "" || pkg.OutputRef == "" || pkg.TraceRef == "" || pkg.CheckpointRef == "" || pkg.OutputHash == (codec.Hash{}) {
		return nil, fmt.Errorf("canonical output package missing required fields")
	}
	var buf bytes.Buffer
	buf.WriteString(outputPackageVersion)
	for _, field := range [][]byte{
		[]byte(pkg.SessionID), []byte(pkg.TaskID), []byte(pkg.ModelID), []byte(pkg.ProfileVersion),
		[]byte(pkg.OutputRef), []byte(pkg.TraceRef), []byte(pkg.CheckpointRef), pkg.OutputHash[:],
	} {
		writeCanonicalField(&buf, field)
	}
	return buf.Bytes(), nil
}

func decodeCanonicalOutputPackage(payload []byte) (OutputPackage, error) {
	if !bytes.HasPrefix(payload, []byte(outputPackageVersion)) {
		return OutputPackage{}, fmt.Errorf("unsupported canonical output package version")
	}
	rest := payload[len(outputPackageVersion):]
	fields := make([][]byte, 0, 8)
	for range 8 {
		field, remaining, err := readCanonicalField(rest)
		if err != nil {
			return OutputPackage{}, fmt.Errorf("decode canonical output package: %w", err)
		}
		fields = append(fields, append([]byte(nil), field...))
		rest = remaining
	}
	if len(rest) != 0 || len(fields[7]) != len(codec.Hash{}) {
		return OutputPackage{}, fmt.Errorf("canonical output package has invalid trailing or hash bytes")
	}
	var outputHash codec.Hash
	copy(outputHash[:], fields[7])
	return OutputPackage{
		SessionID: string(fields[0]), TaskID: string(fields[1]), ModelID: string(fields[2]), ProfileVersion: string(fields[3]),
		OutputRef: string(fields[4]), TraceRef: string(fields[5]), CheckpointRef: string(fields[6]), OutputHash: outputHash,
	}, nil
}

func parseFixturePackageCID(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse fixture output package cid: %w", err)
	}
	if u.Scheme != "fixture" || u.Host != "sha256" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("output package cid must use fixture://sha256/<hash>")
	}
	digest := strings.TrimPrefix(u.EscapedPath(), "/")
	if len(digest) != 64 || digest != strings.ToLower(digest) || strings.Contains(digest, "/") || digest != strings.TrimPrefix(u.Path, "/") {
		return "", fmt.Errorf("output package cid contains an invalid sha256 digest")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", fmt.Errorf("output package cid contains an invalid sha256 digest")
	}
	return digest, nil
}

func (s *FixtureOutputPackageStore) packagePath(digest string) string {
	return filepath.Join(s.root, "output-packages", digest+".bin")
}

func (s *FixtureOutputPackageStore) receiptPath(digest string) string {
	return filepath.Join(s.root, "output-packages", digest+".receipt.json")
}

func writePackageFileAtomically(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".package-*")
	if err != nil {
		return fmt.Errorf("create output package temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("commit output package file: %w", err)
	}
	return nil
}

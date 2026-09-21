package store

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/cockroachdb/pebble/v2"
)

const (
	SchemaVersion uint16 = 1
	dbVersion     uint32 = 1
)

var (
	ErrNotFound      = errors.New("store record not found")
	ErrClosed        = errors.New("store is closed")
	metaPrefix       = []byte("meta/")
	runtimePrefix    = []byte("runtime/")
	schemaVersionKey = prefixedKey(metaPrefix, []byte("schema_version"))
	keeperHeightKey  = prefixedKey(runtimePrefix, []byte("keeper_last_processed_height"))
	chainIdentityKey = prefixedKey(metaPrefix, []byte("chain_identity"))
)

type Store struct {
	db           *pebble.DB
	mu           sync.Mutex
	closed       bool
	readOnly     bool
	path         string
	artifactLock sync.Mutex
}

type InferTask struct {
	TaskID           string     `json:"task_id"`
	SessionID        string     `json:"session_id"`
	OrderSequence    uint64     `json:"order_sequence"`
	AssignmentDigest codec.Hash `json:"assignment_digest"`
	OrderDigest      codec.Hash `json:"order_digest"`
	ModelID          string     `json:"model_id"`
	ProfileVersion   uint32     `json:"profile_version"`
	Capability       string     `json:"capability"`
	DeadlineHeight   uint64     `json:"deadline_height"`
	InputCID         string     `json:"input_cid"`
	InputDigest      codec.Hash `json:"input_digest"`
	Stage            string     `json:"stage"`
	RetryCount       uint32     `json:"retry_count"`
	RetryAtHeight    uint64     `json:"retry_at_height"`
	RetryAtUnixMilli int64      `json:"retry_at_unix_milli"`
	LastError        string     `json:"last_error"`
	// AutoHalted, HaltCode and HaltReason mirror layout.AutoHalt: the local
	// scheduler must not re-enter the executor for this responsibility. See the
	// AutoHalt doc comment for why it is neither task-terminal nor
	// cleanup-eligible.
	AutoHalted             bool       `json:"auto_halted,omitempty"`
	HaltCode               string     `json:"halt_code,omitempty"`
	HaltReason             string     `json:"halt_reason,omitempty"`
	OutputCID              string     `json:"output_cid"`
	OutputDigest           codec.Hash `json:"output_digest"`
	ReceiptCID             string     `json:"receipt_cid"`
	ReceiptDigest          codec.Hash `json:"receipt_digest"`
	WorkerAddress          string     `json:"worker_address"`
	WinnerConfirmHeight    uint64     `json:"winner_confirm_height"`
	BuilderOperatorAddress string     `json:"builder_operator_address"`
	// InputSizeBytes is the user-signed input size from the accepted TaskOrderV1.
	// Zero means unknown and forces a metadata round trip before fetching.
	InputSizeBytes uint64 `json:"input_size_bytes,omitempty"`
	// BuilderSetID and BuilderSetHash are TRUEOPEN_BUS_ENVELOPE_V1 fields 11 and 12
	// for this task (interface-and-topic-list.md §5.2 fields 11-12). After the first proposal is
	// accepted the authority is the Task's locked BuilderSet reference, which is
	// Task state on the chain and not something Cortex derives; the runner copies
	// it out of the authenticated WORKER_ASSIGNMENT_NOTIFY frame that named this node the
	// winner. Absent until such a frame arrives, and absent is a refusal at
	// publish time rather than an empty envelope field: §5.2 forbids an empty
	// builder_set_id on a task-control message.
	//
	// The hash is []byte rather than codec.Hash so absent stays distinguishable
	// from 32 zero bytes.
	BuilderSetID   string `json:"builder_set_id,omitempty"`
	BuilderSetHash []byte `json:"builder_set_hash,omitempty"`
}

type ActiveInferTasks struct {
	SchemaVersion uint16                   `json:"schema_version"`
	Tasks         map[codec.Hash]InferTask `json:"-"`
}

type VerifyTask struct {
	TaskID           string     `json:"task_id"`
	SessionID        string     `json:"session_id"`
	OrderSequence    uint64     `json:"order_sequence"`
	AssignmentDigest codec.Hash `json:"assignment_digest"`
	ModelID          string     `json:"model_id"`
	ProfileVersion   uint32     `json:"profile_version"`
	Capability       string     `json:"capability"`
	DeadlineHeight   uint64     `json:"deadline_height"`
	OutputCID        string     `json:"output_cid"`
	OutputDigest     codec.Hash `json:"output_digest"`
	PackageCID       string     `json:"package_cid"`
	PackageDigest    codec.Hash `json:"package_digest"`
	Stage            string     `json:"stage"`
	RetryCount       uint32     `json:"retry_count"`
	RetryAtHeight    uint64     `json:"retry_at_height"`
	RetryAtUnixMilli int64      `json:"retry_at_unix_milli"`
	LastError        string     `json:"last_error"`
	// See store.InferTask for what these three mean.
	AutoHalted                 bool       `json:"auto_halted,omitempty"`
	HaltCode                   string     `json:"halt_code,omitempty"`
	HaltReason                 string     `json:"halt_reason,omitempty"`
	ReceiptCID                 string     `json:"receipt_cid"`
	ReceiptDigest              codec.Hash `json:"receipt_digest"`
	WorkerAddress              string     `json:"worker_address"`
	BuilderOperatorAddress     string     `json:"builder_operator_address"`
	OrderDigest                codec.Hash `json:"order_digest"`
	VerifyRound                uint64     `json:"verify_round"`
	OpenVerifyHeight           uint64     `json:"open_verify_height"`
	CurrentHeight              uint64     `json:"current_height"`
	CommitDeadlineHeight       uint64     `json:"commit_deadline_height"`
	WorkerRevealDeadlineHeight uint64     `json:"worker_reveal_deadline_height"`
	RevealDeadlineHeight       uint64     `json:"reveal_deadline_height"`
	AssignedVerifiers          []string   `json:"assigned_verifiers,omitempty"`
	VerificationSampleSeed     codec.Hash `json:"verification_sample_seed"`
	InferReceiptDigest         codec.Hash `json:"infer_receipt_digest,omitempty"`
	KeeperReceiptJSON          []byte     `json:"keeper_receipt_json,omitempty"`
	OutputRef                  string     `json:"output_ref"`
	TraceRef                   string     `json:"trace_ref"`
	CheckpointRef              string     `json:"checkpoint_ref"`
	// BuilderSetID and BuilderSetHash are TRUEOPEN_BUS_ENVELOPE_V1 fields 11 and 12
	// for this task (interface-and-topic-list.md §5.2 fields 11-12). A verify
	// responsibility exists only after the first proposal was accepted, so the
	// authority is always the Task's locked BuilderSet reference (§5.2 field 12);
	// the runner copies it out of the authenticated VERIFIER_ASSIGNMENT_NOTIFY
	// frame. Absent is a refusal at publish time, never an
	// empty envelope field (§5.2).
	BuilderSetID   string `json:"builder_set_id,omitempty"`
	BuilderSetHash []byte `json:"builder_set_hash,omitempty"`
}

type ActiveVerifyTasks struct {
	SchemaVersion uint16                    `json:"schema_version"`
	Tasks         map[codec.Hash]VerifyTask `json:"-"`
}

func Open(ctx context.Context, path string) (*Store, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if path == "" {
		return nil, fmt.Errorf("store path is required")
	}
	legacy, err := legacyStoreKind(path)
	if err != nil {
		return nil, err
	}
	if legacy != "" {
		return nil, fmt.Errorf("store path %q is %s; automatic migration is not supported: drain active responsibilities, preserve the old file as a rollback backup, and configure store.path to a new Pebble directory", path, legacy)
	}
	db, err := pebble.Open(path, &pebble.Options{DisableWAL: false, WALBytesPerSync: 0})
	if err != nil {
		return nil, fmt.Errorf("open Pebble store: %w", err)
	}
	s := &Store{db: db, path: path}
	if err := s.initialize(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// ChainIdentityMismatchError reports that the compact store contains durable
// state for a different chain than the configured endpoint.
type ChainIdentityMismatchError struct {
	StorePath  string
	Recorded   string
	Configured string
}

func (e *ChainIdentityMismatchError) Error() string {
	return fmt.Sprintf(
		"local store %s was populated against chain %q but this node is configured for chain %q: either correct chain_id and node.rpc_endpoint to point back at chain %q, or stop the node and move %s aside (keep config.yaml, keystore/, secrets/ and data/evidence/) so it replays from height 0",
		e.StorePath, e.Recorded, e.Configured, e.Recorded, e.StorePath)
}

// BindChainIdentity adopts the configured chain for an unbound store and then
// enforces that identity on every subsequent boot.
func (s *Store) BindChainIdentity(ctx context.Context, chainID string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store is not open")
	}
	chainID = strings.TrimSpace(chainID)
	if chainID == "" {
		return fmt.Errorf("chain id is required to bind the local store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	stored, err := s.getLocked(chainIdentityKey)
	if errors.Is(err, ErrNotFound) {
		if err := s.db.Set(chainIdentityKey, []byte(chainID), pebble.Sync); err != nil {
			return fmt.Errorf("bind store chain identity: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read store chain identity: %w", err)
	}
	recorded := string(stored)
	if recorded != chainID {
		return &ChainIdentityMismatchError{StorePath: s.path, Recorded: recorded, Configured: chainID}
	}
	return nil
}

// ChainIdentity returns the chain recorded for this store.
func (s *Store) ChainIdentity(ctx context.Context) (string, error) {
	value, err := s.getContext(ctx, chainIdentityKey)
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func legacyStoreKind(path string) (string, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect store path: %w", err)
	}
	if info.IsDir() {
		return "", nil
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("inspect store path: %w", err)
	}
	defer file.Close()

	header := make([]byte, 20)
	if _, err := io.ReadFull(file, header); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return "an unrecognized non-directory file, not a Pebble directory", nil
		}
		return "", fmt.Errorf("inspect store header: %w", err)
	}
	if string(header[:16]) == "SQLite format 3\x00" {
		return "a legacy SQLite database", nil
	}
	// bbolt's meta page begins with a 16-byte page header followed by this magic.
	if binary.LittleEndian.Uint32(header[16:20]) == 0xED0CDAED {
		return "a legacy bbolt database", nil
	}
	return "an unrecognized non-directory file, not a Pebble directory", nil
}

func (s *Store) initialize(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	batch := s.db.NewBatch()
	defer batch.Close()
	{
		var version [4]byte
		binary.BigEndian.PutUint32(version[:], dbVersion)
		stored, err := s.getLocked(schemaVersionKey)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err == nil && (len(stored) != len(version) || binary.BigEndian.Uint32(stored) != dbVersion) {
			return fmt.Errorf("unsupported store schema version")
		}
		if errors.Is(err, ErrNotFound) {
			if err := batch.Set(schemaVersionKey, version[:], nil); err != nil {
				return fmt.Errorf("write schema version: %w", err)
			}
		}
		return batch.Commit(pebble.Sync)
	}
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}

func (s *Store) Ping(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.getLocked(schemaVersionKey)
	return err
}

func (s *Store) KeeperLastProcessedHeight(ctx context.Context) (uint64, error) {
	var height uint64
	value, err := s.getContext(ctx, keeperHeightKey)
	if errors.Is(err, ErrNotFound) {
		return 0, nil
	}
	if err == nil {
		if len(value) != 8 {
			err = fmt.Errorf("invalid keeper height length %d", len(value))
		} else {
			height = binary.BigEndian.Uint64(value)
		}
	}
	if err != nil {
		return 0, fmt.Errorf("get keeper last processed height: %w", err)
	}
	return height, nil
}

func (s *Store) AdvanceKeeperLastProcessedHeight(ctx context.Context, height uint64) (bool, error) {
	return s.setKeeperLastProcessedHeight(ctx, height, true)
}

// SetKeeperLastProcessedHeight overwrites the last processed height without
// requiring it to advance. It is used when the local cursor is found to be
// ahead of the authoritative chain tip and must be regressed to the current
// tip.
func (s *Store) SetKeeperLastProcessedHeight(ctx context.Context, height uint64) error {
	_, err := s.setKeeperLastProcessedHeight(ctx, height, false)
	return err
}

func (s *Store) setKeeperLastProcessedHeight(ctx context.Context, height uint64, requireAdvance bool) (bool, error) {
	advanced := false
	s.mu.Lock()
	defer s.mu.Unlock()
	err := contextError(ctx)
	if err == nil {
		if requireAdvance {
			stored, getErr := s.getLocked(keeperHeightKey)
			if getErr == nil {
				if len(stored) != 8 {
					err = fmt.Errorf("invalid keeper height length %d", len(stored))
				} else if height <= binary.BigEndian.Uint64(stored) {
					return false, nil
				}
			} else if !errors.Is(getErr, ErrNotFound) {
				err = getErr
			}
		}
		if err == nil {
			var value [8]byte
			binary.BigEndian.PutUint64(value[:], height)
			err = s.db.Set(keeperHeightKey, value[:], pebble.Sync)
			advanced = err == nil
		}
	}
	if err != nil {
		return false, fmt.Errorf("advance keeper last processed height: %w", err)
	}
	return advanced, nil
}

// ProbeWrite verifies the store is writable by writing a temporary probe key
// and immediately deleting it. A failure means readiness should fail closed.
func (s *Store) ProbeWrite(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.readOnly {
		return fmt.Errorf("store is read-only")
	}
	probeKey := []byte("__cortex_store_write_probe__")
	if err := s.db.Set(probeKey, []byte{1}, pebble.Sync); err != nil {
		return fmt.Errorf("write store probe: %w", err)
	}
	if err := s.db.Delete(probeKey, pebble.Sync); err != nil {
		return fmt.Errorf("delete store probe: %w", err)
	}
	return nil
}

// SetReadOnlyForTests marks the store as read-only. It is intended for tests
// that verify readiness fails closed when the backing database cannot be written.
func (s *Store) SetReadOnlyForTests() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readOnly = true
}

func (s *Store) getContext(ctx context.Context, key []byte) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getLocked(key)
}

func (s *Store) getLocked(key []byte) ([]byte, error) {
	if s.closed {
		return nil, ErrClosed
	}
	value, closer, err := s.db.Get(key)
	if errors.Is(err, pebble.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	return append([]byte(nil), value...), nil
}

func (s *Store) put(ctx context.Context, key, value []byte, label string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	err := s.db.Set(key, value, pebble.Sync)
	if err != nil {
		return fmt.Errorf("put %s: %w", label, err)
	}
	return nil
}

func (s *Store) delete(ctx context.Context, key []byte, label string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	err := s.db.Delete(key, pebble.Sync)
	if err != nil {
		return fmt.Errorf("delete %s: %w", label, err)
	}
	return nil
}

// WithArtifactLock serializes the supplied callback with the artifact-wide lock.
func (s *Store) WithArtifactLock(fn func() error) error {
	s.artifactLock.Lock()
	defer s.artifactLock.Unlock()
	return fn()
}

// Checkpoint creates a consistent Pebble backup and flushes the WAL first.
func (s *Store) Checkpoint(ctx context.Context, destination string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if destination == "" {
		return fmt.Errorf("checkpoint destination is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("create checkpoint parent: %w", err)
	}
	if err := s.db.Checkpoint(destination, pebble.WithFlushedWAL()); err != nil {
		return fmt.Errorf("create Pebble checkpoint: %w", err)
	}
	return nil
}

// Batch groups multiple Pebble operations into one atomic synced write. It is
// used by the new task storage layout (internal/store/layout) to commit the
// atomic admission, assignment, terminal and cleanup batches.
type Batch struct {
	batch *pebble.Batch
	s     *Store
}

// Get returns the current value for key, reading from the batch first and then
// the underlying database. The returned slice is a copy and is safe to retain.
func (b *Batch) Get(key []byte) ([]byte, error) {
	value, closer, err := b.batch.Get(key)
	if errors.Is(err, pebble.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	return append([]byte(nil), value...), nil
}

// Set writes key -> value into the batch. The write is not durable until the
// batch is committed.
func (b *Batch) Set(key, value []byte) error {
	return b.batch.Set(key, value, nil)
}

// Delete marks a key for deletion in the batch. The deletion is not durable
// until the batch is committed.
func (b *Batch) Delete(key []byte) error {
	return b.batch.Delete(key, nil)
}

// NewIter returns an iterator over the batch plus the underlying database for
// the given prefix. The iterator must be closed by the caller.
func (b *Batch) NewIter(prefix []byte) (BatchIterator, error) {
	iter, err := b.batch.NewIter(&pebble.IterOptions{
		LowerBound: prefix,
		UpperBound: prefixUpperBound(prefix),
	})
	if err != nil {
		return nil, err
	}
	return &batchIterator{iter: iter}, nil
}

// BatchIterator is a bounded iterator over a batch.
type BatchIterator interface {
	First() bool
	Valid() bool
	Next() bool
	Key() []byte
	Value() []byte
	Close() error
}

type batchIterator struct {
	iter *pebble.Iterator
}

func (i *batchIterator) First() bool { return i.iter.First() }
func (i *batchIterator) Valid() bool { return i.iter.Valid() }
func (i *batchIterator) Next() bool  { return i.iter.Next() }
func (i *batchIterator) Key() []byte { return i.iter.Key() }
func (i *batchIterator) Value() []byte {
	if !i.iter.Valid() {
		return nil
	}
	return i.iter.Value()
}
func (i *batchIterator) Close() error { return i.iter.Close() }

// ApplyBatch runs fn with a new Batch and commits it atomically. The Store lock
// is held for the duration of fn and the commit, so fn must not call back into
// the Store.
func (s *Store) ApplyBatch(ctx context.Context, fn func(*Batch) error) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	b := &Batch{batch: s.db.NewIndexedBatch(), s: s}
	defer b.batch.Close()
	if err := fn(b); err != nil {
		return err
	}
	if err := b.batch.Commit(pebble.Sync); err != nil {
		return fmt.Errorf("commit batch: %w", err)
	}
	return nil
}

// GetRaw returns the raw value stored under key.
func (s *Store) GetRaw(ctx context.Context, key []byte) ([]byte, error) {
	return s.getContext(ctx, key)
}

// PutRaw writes a raw value under key.
func (s *Store) PutRaw(ctx context.Context, key, value []byte) error {
	return s.put(ctx, key, value, "raw")
}

// DeleteRaw deletes the value stored under key.
func (s *Store) DeleteRaw(ctx context.Context, key []byte) error {
	return s.delete(ctx, key, "raw")
}

// ScanPrefix iterates over every key-value pair whose key begins with prefix
// and calls fn for each. If fn returns an error, iteration stops and that
// error is returned.
func (s *Store) ScanPrefix(ctx context.Context, prefix []byte, fn func(key, value []byte) error) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	iter, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: prefix,
		UpperBound: prefixUpperBound(prefix),
	})
	if err != nil {
		return err
	}
	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()
		value := iter.Value()
		if err := fn(append([]byte(nil), key...), append([]byte(nil), value...)); err != nil {
			iter.Close()
			return err
		}
	}
	return iter.Close()
}

func prefixedKey(prefix, suffix []byte) []byte {
	key := make([]byte, 0, len(prefix)+len(suffix))
	key = append(key, prefix...)
	return append(key, suffix...)
}

func prefixUpperBound(prefix []byte) []byte {
	upper := append([]byte(nil), prefix...)
	for i := len(upper) - 1; i >= 0; i-- {
		if upper[i] != 0xff {
			upper[i]++
			return upper[:i+1]
		}
	}
	return nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	return ctx.Err()
}

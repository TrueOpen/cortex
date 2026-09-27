package nodewire

// Worker and Verifier value leaves and trees of wire v0.3.0 (TrueOpen/wire#14,
// task/worker_value_leaf_v1.json and task/verifier_value_leaf_v1.json).
//
// Values arrive here already in fixed point. Converting the model service's
// real-valued logprobs to fp_1e6 is the caller's job and happens once, before
// any of these encoders runs.

import (
	"encoding/binary"
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

const (
	DomainWorkerValueLeafV1   = "TRUEOPEN_PREFILL_WORKER_VALUE_LEAF_V1"
	DomainWorkerValueRootV1   = "TRUEOPEN_PREFILL_WORKER_VALUE_ROOT_V1"
	DomainVerifierTopKV1      = "TRUEOPEN_PREFILL_VERIFIER_TOPK_V1"
	DomainVerifierValueLeafV1 = "TRUEOPEN_PREFILL_VERIFIER_VALUE_LEAF_V1"
	DomainVerifierValueRootV1 = "TRUEOPEN_PREFILL_VERIFIER_VALUE_ROOT_V1"
)

// ValueLeafVersionV1 is the leaf_version both value leaves frame first.
const ValueLeafVersionV1 uint32 = 1

// TopKEntryV1 is one (token, logprob) pair of a position's top-k list.
type TopKEntryV1 struct {
	TokenID      uint32
	LogprobFP1e6 int64
}

// PositionValueV1 is one side's fixed-point value at one generated position.
//
// The three legal states are: normal (Missing false, Finite true), missing
// (Missing true, Finite false) and non-finite (both false). Missing and
// non-finite carry zero logprob and rank and an empty top-k list; Missing and
// Finite together is illegal.
type PositionValueV1 struct {
	Position     uint32
	TokenID      uint32
	LogprobFP1e6 int64
	Rank         uint32 // 0 = not in the required top-k
	TopK         []TopKEntryV1
	Missing      bool
	Finite       bool
}

// WorkerValueBindingV1 is the per-task context every Worker leaf repeats.
type WorkerValueBindingV1 struct {
	ChainID               string
	TaskID                []byte // Hash32
	AcceptedTaskHash      []byte // Hash32
	WorkerOperatorAddress string // canonical Bech32; framed as address bytes
	RequiredTopK          uint32 // the locked profile's required_top_k
}

// VerifierValueBindingV1 is the per-round context every Verifier leaf repeats.
type VerifierValueBindingV1 struct {
	ChainID                 string
	TaskID                  []byte // Hash32
	TaskHash                []byte // Hash32
	VerifyRound             uint32
	VerifierOperatorAddress string // canonical Bech32; framed as address bytes
	RequiredTopK            uint32
}

// WorkerValueLeafBytes returns worker_value_leaf_bytes: the inner FRAME_V1 of
// one leaf, which is also exactly what the worker_values artifact stores.
func WorkerValueLeafBytes(binding WorkerValueBindingV1, value PositionValueV1) ([]byte, error) {
	fields, err := workerValueLeafFields(binding, value)
	if err != nil {
		return nil, err
	}
	return hfields.FrameBytes(fields...)
}

// WorkerValueLeafHash returns the leaf hash the Worker value tree is built from.
func WorkerValueLeafHash(binding WorkerValueBindingV1, value PositionValueV1) (codec.Hash, error) {
	fields, err := workerValueLeafFields(binding, value)
	if err != nil {
		return codec.Hash{}, err
	}
	return hfields.Digest(DomainWorkerValueLeafV1, hfields.Uint32(ValueLeafVersionV1), hfields.Frame(fields...))
}

// WorkerValueRoot returns worker_value_root over values, which must hold one
// value per generated position, in position order starting at 0.
func WorkerValueRoot(binding WorkerValueBindingV1, values []PositionValueV1) (codec.Hash, error) {
	if err := checkContiguousPositions(values); err != nil {
		return codec.Hash{}, err
	}
	leaves := make([]codec.Hash, len(values))
	for i, value := range values {
		leaf, err := WorkerValueLeafHash(binding, value)
		if err != nil {
			return codec.Hash{}, fmt.Errorf("worker value at position %d: %w", i, err)
		}
		leaves[i] = leaf
	}
	return codec.MerkleRootV1(DomainWorkerValueRootV1, leaves)
}

// EncodeWorkerValues returns the worker_values artifact:
// u32_be(leaf_count) followed by every worker_value_leaf_bytes in position
// order. Its length is worker_values_encoded_size_bytes.
func EncodeWorkerValues(binding WorkerValueBindingV1, values []PositionValueV1) ([]byte, error) {
	if len(values) > MaxTokenIDCountV1 {
		return nil, fmt.Errorf("worker value count %d exceeds %d", len(values), MaxTokenIDCountV1)
	}
	if err := checkContiguousPositions(values); err != nil {
		return nil, err
	}
	raw := binary.BigEndian.AppendUint32(nil, uint32(len(values)))
	for i, value := range values {
		leaf, err := WorkerValueLeafBytes(binding, value)
		if err != nil {
			return nil, fmt.Errorf("worker value at position %d: %w", i, err)
		}
		raw = append(raw, leaf...)
	}
	return raw, nil
}

// DecodeWorkerValues parses a worker_values artifact bound to binding. It is
// strict: the result must re-encode to exactly raw, so a leaf carrying another
// task's binding, a non-canonical frame, trailing bytes or an illegal value
// state are all refused.
func DecodeWorkerValues(binding WorkerValueBindingV1, raw []byte) ([]PositionValueV1, error) {
	if len(raw) < 4 {
		return nil, fmt.Errorf("worker_values artifact lacks its uint32 leaf count")
	}
	count := binary.BigEndian.Uint32(raw)
	if count > MaxTokenIDCountV1 {
		return nil, fmt.Errorf("worker value count %d exceeds %d", count, MaxTokenIDCountV1)
	}
	reader := frameReader{buf: raw, off: 4}
	values := make([]PositionValueV1, 0, min(int(count), len(raw)/workerValueLeafMinBytes))
	for i := uint32(0); i < count; i++ {
		value, err := reader.workerValueLeaf()
		if err != nil {
			return nil, fmt.Errorf("worker value leaf %d: %w", i, err)
		}
		values = append(values, value)
	}
	if reader.off != len(raw) {
		return nil, fmt.Errorf("worker_values artifact has %d trailing bytes", len(raw)-reader.off)
	}
	encoded, err := EncodeWorkerValues(binding, values)
	if err != nil {
		return nil, err
	}
	if string(encoded) != string(raw) {
		return nil, fmt.Errorf("worker_values artifact is not the canonical encoding for this task")
	}
	return values, nil
}

// VerifierTopKSetHash returns verifier_topk_set_hash for one position's top-k
// list, in rank order.
func VerifierTopKSetHash(topK []TopKEntryV1) (codec.Hash, error) {
	return hfields.Digest(DomainVerifierTopKV1, topKFrame(topK))
}

// VerifierValueLeafHash returns the leaf hash the Verifier value tree is built
// from. The Verifier's top-k enters the leaf as its set hash, not inline.
func VerifierValueLeafHash(binding VerifierValueBindingV1, value PositionValueV1) (codec.Hash, error) {
	if binding.ChainID == "" {
		return codec.Hash{}, fmt.Errorf("chain_id must be non-empty")
	}
	chainID, err := canonicalUTF8Field("chain_id", binding.ChainID)
	if err != nil {
		return codec.Hash{}, err
	}
	for _, hash := range [...]struct {
		name  string
		value []byte
	}{{"task_id", binding.TaskID}, {"task_hash", binding.TaskHash}} {
		if _, err := canonicalHash32(hash.name, hash.value); err != nil {
			return codec.Hash{}, err
		}
	}
	if binding.VerifyRound == 0 {
		return codec.Hash{}, fmt.Errorf("verify_round must be positive")
	}
	verifier, err := CanonicalOperatorAddressBytes("verifier_operator_address", binding.VerifierOperatorAddress)
	if err != nil {
		return codec.Hash{}, err
	}
	if err := checkValueState(value, binding.RequiredTopK); err != nil {
		return codec.Hash{}, err
	}
	topKSetHash, err := VerifierTopKSetHash(value.TopK)
	if err != nil {
		return codec.Hash{}, err
	}
	return hfields.Digest(DomainVerifierValueLeafV1, hfields.Uint32(ValueLeafVersionV1), hfields.Frame(
		hfields.String(chainID),
		hfields.Bytes(binding.TaskID),
		hfields.Bytes(binding.TaskHash),
		hfields.Uint32(binding.VerifyRound),
		hfields.Bytes(verifier),
		hfields.Uint32(value.Position),
		hfields.Uint32(value.TokenID),
		hfields.Int64(value.LogprobFP1e6),
		hfields.Uint32(value.Rank),
		hfields.Hash(topKSetHash),
		hfields.Bool(value.Missing),
		hfields.Bool(value.Finite),
	))
}

// VerifierValueRoot returns verifier_value_root over values, one per generated
// position, in output_position order starting at 0.
func VerifierValueRoot(binding VerifierValueBindingV1, values []PositionValueV1) (codec.Hash, error) {
	if err := checkContiguousPositions(values); err != nil {
		return codec.Hash{}, err
	}
	leaves := make([]codec.Hash, len(values))
	for i, value := range values {
		leaf, err := VerifierValueLeafHash(binding, value)
		if err != nil {
			return codec.Hash{}, fmt.Errorf("verifier value at position %d: %w", i, err)
		}
		leaves[i] = leaf
	}
	return codec.MerkleRootV1(DomainVerifierValueRootV1, leaves)
}

func workerValueLeafFields(binding WorkerValueBindingV1, value PositionValueV1) ([]hfields.Field, error) {
	if binding.ChainID == "" {
		return nil, fmt.Errorf("chain_id must be non-empty")
	}
	chainID, err := canonicalUTF8Field("chain_id", binding.ChainID)
	if err != nil {
		return nil, err
	}
	for _, hash := range [...]struct {
		name  string
		value []byte
	}{{"task_id", binding.TaskID}, {"accepted_task_hash", binding.AcceptedTaskHash}} {
		if _, err := canonicalHash32(hash.name, hash.value); err != nil {
			return nil, err
		}
	}
	worker, err := CanonicalOperatorAddressBytes("worker_operator_address", binding.WorkerOperatorAddress)
	if err != nil {
		return nil, err
	}
	if err := checkValueState(value, binding.RequiredTopK); err != nil {
		return nil, err
	}
	return []hfields.Field{
		hfields.String(chainID),
		hfields.Bytes(binding.TaskID),
		hfields.Bytes(binding.AcceptedTaskHash),
		hfields.Bytes(worker),
		hfields.Uint32(value.Position),
		hfields.Uint32(value.TokenID),
		hfields.Int64(value.LogprobFP1e6),
		hfields.Uint32(value.Rank),
		topKFrame(value.TopK),
		hfields.Bool(value.Missing),
		hfields.Bool(value.Finite),
	}, nil
}

// topKFrame is REPEATED_V1 of NESTED_V1(u32_be(token_id), i64_be(logprob)),
// kept in the order given: the list is the engine's rank order, not a set.
func topKFrame(topK []TopKEntryV1) hfields.Field {
	fields := make([]hfields.Field, 0, 1+len(topK))
	fields = append(fields, hfields.Uint32(uint32(len(topK))))
	for _, entry := range topK {
		fields = append(fields, hfields.Frame(hfields.Uint32(entry.TokenID), hfields.Int64(entry.LogprobFP1e6)))
	}
	return hfields.Frame(fields...)
}

// checkValueState enforces the leaf rules shared by both sides: the three
// legal flag states, zero values outside the normal state, and a normal top-k
// of exactly requiredTopK distinct tokens with a rank inside it.
func checkValueState(value PositionValueV1, requiredTopK uint32) error {
	if requiredTopK == 0 {
		return fmt.Errorf("required_top_k must be positive")
	}
	if value.Missing && value.Finite {
		return fmt.Errorf("missing_flag and finite_flag cannot both be set")
	}
	if !value.Finite {
		if value.LogprobFP1e6 != 0 || value.Rank != 0 || len(value.TopK) != 0 {
			return fmt.Errorf("a missing or non-finite value must carry zero logprob, zero rank and no top-k")
		}
		return nil
	}
	if value.Rank > requiredTopK {
		return fmt.Errorf("rank %d exceeds required_top_k %d", value.Rank, requiredTopK)
	}
	if uint64(len(value.TopK)) != uint64(requiredTopK) {
		return fmt.Errorf("top-k has %d entries, want exactly %d", len(value.TopK), requiredTopK)
	}
	seen := make(map[uint32]struct{}, len(value.TopK))
	for _, entry := range value.TopK {
		if _, dup := seen[entry.TokenID]; dup {
			return fmt.Errorf("top-k repeats token %d", entry.TokenID)
		}
		seen[entry.TokenID] = struct{}{}
	}
	return nil
}

func checkContiguousPositions(values []PositionValueV1) error {
	for i, value := range values {
		if uint64(value.Position) != uint64(i) {
			return fmt.Errorf("value %d has position %d; positions must run 0..n-1 in order", i, value.Position)
		}
	}
	return nil
}

// workerValueLeafMinBytes is the smallest possible leaf: eleven length
// prefixes, an empty chain id, two hashes, a 20-byte address, the fixed-width
// fields and an empty top-k frame. It bounds the preallocation in
// DecodeWorkerValues so a forged count cannot force a large allocation.
const workerValueLeafMinBytes = 11*8 + 32 + 32 + 20 + 4 + 4 + 8 + 4 + (8 + 4) + 1 + 1

// frameReader walks FRAME_V1 fields. Every read is bounds-checked; canonical
// form is left to the re-encode comparison in DecodeWorkerValues.
type frameReader struct {
	buf []byte
	off int
}

func (r *frameReader) field() ([]byte, error) {
	if len(r.buf)-r.off < 8 {
		return nil, fmt.Errorf("truncated field length at offset %d", r.off)
	}
	length := binary.BigEndian.Uint64(r.buf[r.off:])
	r.off += 8
	if length > uint64(len(r.buf)-r.off) {
		return nil, fmt.Errorf("field of %d bytes overruns the artifact at offset %d", length, r.off)
	}
	value := r.buf[r.off : r.off+int(length)]
	r.off += int(length)
	return value, nil
}

func (r *frameReader) fixed(width int) ([]byte, error) {
	value, err := r.field()
	if err != nil {
		return nil, err
	}
	if len(value) != width {
		return nil, fmt.Errorf("field is %d bytes, want %d", len(value), width)
	}
	return value, nil
}

// workerValueLeaf reads the eleven fields of one leaf and returns its value
// part. The binding fields are skipped here and checked by re-encoding.
func (r *frameReader) workerValueLeaf() (PositionValueV1, error) {
	var value PositionValueV1
	for range 4 { // chain_id, task_id, accepted_task_hash, worker address
		if _, err := r.field(); err != nil {
			return value, err
		}
	}
	u32 := func() (uint32, error) {
		raw, err := r.fixed(4)
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint32(raw), nil
	}
	var err error
	if value.Position, err = u32(); err != nil {
		return value, err
	}
	if value.TokenID, err = u32(); err != nil {
		return value, err
	}
	logprob, err := r.fixed(8)
	if err != nil {
		return value, err
	}
	value.LogprobFP1e6 = int64(binary.BigEndian.Uint64(logprob))
	if value.Rank, err = u32(); err != nil {
		return value, err
	}
	topKRaw, err := r.field()
	if err != nil {
		return value, err
	}
	if value.TopK, err = decodeTopK(topKRaw); err != nil {
		return value, err
	}
	for _, flag := range []*bool{&value.Missing, &value.Finite} {
		raw, err := r.fixed(1)
		if err != nil {
			return value, err
		}
		*flag = raw[0] == 1
	}
	return value, nil
}

func decodeTopK(raw []byte) ([]TopKEntryV1, error) {
	reader := frameReader{buf: raw}
	countRaw, err := reader.fixed(4)
	if err != nil {
		return nil, fmt.Errorf("top-k count: %w", err)
	}
	count := binary.BigEndian.Uint32(countRaw)
	// Each entry takes 36 bytes (a framed pair of 4- and 8-byte fields), which
	// bounds count by the bytes actually present.
	if uint64(count)*36 != uint64(len(raw)-reader.off) {
		return nil, fmt.Errorf("top-k count %d does not match its %d bytes", count, len(raw)-reader.off)
	}
	topK := make([]TopKEntryV1, count)
	for i := range topK {
		entryRaw, err := reader.field()
		if err != nil {
			return nil, err
		}
		entry := frameReader{buf: entryRaw}
		tokenID, err := entry.fixed(4)
		if err != nil {
			return nil, err
		}
		logprob, err := entry.fixed(8)
		if err != nil {
			return nil, err
		}
		topK[i] = TopKEntryV1{TokenID: binary.BigEndian.Uint32(tokenID), LogprobFP1e6: int64(binary.BigEndian.Uint64(logprob))}
	}
	return topK, nil
}

// WorkerValuesTopK reports the top-k length of the first normal leaf in a
// worker_values artifact, or 1 when every leaf is missing or non-finite (their
// top-k is empty under any K). It exists for a consumer that must strictly
// decode the artifact without a Profile read to take required_top_k from; a
// Profile-reading consumer uses the Profile's value instead.
func WorkerValuesTopK(raw []byte) (uint32, error) {
	if len(raw) < 4 {
		return 0, fmt.Errorf("worker_values artifact lacks its uint32 leaf count")
	}
	count := binary.BigEndian.Uint32(raw)
	reader := frameReader{buf: raw, off: 4}
	for i := uint32(0); i < count; i++ {
		value, err := reader.workerValueLeaf()
		if err != nil {
			return 0, fmt.Errorf("worker value leaf %d: %w", i, err)
		}
		if value.Finite {
			return uint32(len(value.TopK)), nil
		}
	}
	return 1, nil
}

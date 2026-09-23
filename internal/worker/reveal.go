package worker

// Worker reveal phase: opening the sampled value set after a verifier trigger.
//
// Reveal is the last thing a Worker does for a Task and it happens long after the
// prepared output has been relayed, driven by a verifier-issued trigger rather than
// by the assignment. The canonical encodings here are the reveal wire format the
// Keeper and verifiers verify byte-for-byte, so this file changes when that protocol
// changes -- not when the prepared-output checkpoint on disk does (see recovery.go).

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/keepercontract"
)

func (w *Worker) HandleWorkerRevealTrigger(ctx context.Context, trigger WorkerRevealTrigger) (WorkerRevealResult, error) {
	if result, ok := w.reveals[trigger.TaskID]; ok {
		return result, nil
	}
	if w.cfg.Builder == nil {
		return WorkerRevealResult{}, fmt.Errorf("Builder client is required for normal worker reveal delivery")
	}
	if err := validateWorkerRevealTrigger(trigger); err != nil {
		return WorkerRevealResult{}, err
	}
	valueHash, err := canonicalSampledValueSetHash(trigger)
	if err != nil {
		return WorkerRevealResult{}, err
	}
	positions := canonicalSelectedPositions(trigger.SelectedPositions)
	signatureHash := keepercontract.WorkerReveal(
		w.cfg.ChainID,
		trigger.TaskID,
		trigger.VerifyRound,
		fmt.Sprintf("%x", trigger.VerificationSampleSeed[:]),
		fmt.Sprintf("%x", valueHash[:]),
		trigger.EvidenceSchemaVersion,
	)
	signature, err := w.signDigest(ctx, signatureHash)
	if err != nil {
		return WorkerRevealResult{}, err
	}
	receipt := WorkerRevealReceipt{
		TaskID:                 trigger.TaskID,
		VerifyRound:            trigger.VerifyRound,
		WorkerAddress:          w.cfg.WorkerAddress,
		InferReceiptHash:       trigger.InferReceiptHash,
		VerificationSampleSeed: trigger.VerificationSampleSeed,
		SelectedPositions:      positions,
		SampledValueSetHash:    valueHash,
		SampleEncodingProfile:  trigger.SampleEncodingProfile,
		SourceRootKind:         trigger.SourceRootKind,
		EvidenceSchemaVersion:  trigger.EvidenceSchemaVersion,
		WorkerSignature:        signature,
	}
	payload, err := encodeWorkerRevealReceipt(receipt)
	if err != nil {
		return WorkerRevealResult{}, err
	}
	if err := w.persistWorkerRevealOpening(ctx, trigger.TaskID, trigger.OpeningMaterial); err != nil {
		return WorkerRevealResult{}, err
	}
	subject := "trueopen.worker-reveal." + trigger.TaskID
	if err := w.cfg.Builder.Publish(ctx, builderclient.PublishRequest{
		Subject: subject,
		TaskID:  trigger.TaskID,
		Payload: payload,
	}); err != nil {
		return WorkerRevealResult{}, err
	}
	result := WorkerRevealResult{Receipt: receipt, Payload: payload}
	w.reveals[trigger.TaskID] = result
	return result, nil
}

func validateWorkerRevealTrigger(trigger WorkerRevealTrigger) error {
	if trigger.SessionID == "" || trigger.TaskID == "" {
		return fmt.Errorf("worker reveal session and task id are required")
	}
	if trigger.InferReceiptHash == (codec.Hash{}) {
		return fmt.Errorf("worker reveal infer receipt hash is required")
	}
	if trigger.VerificationSampleSeed == (codec.Hash{}) {
		return fmt.Errorf("worker reveal sample seed is required")
	}
	if len(trigger.SelectedPositions) == 0 {
		return fmt.Errorf("worker reveal selected positions are required")
	}
	if len(trigger.SampledValueSet) == 0 {
		return fmt.Errorf("worker reveal sampled values are required")
	}
	if len(trigger.SampledValueSet) != len(trigger.SelectedPositions) {
		return fmt.Errorf("worker reveal sampled values must match selected positions")
	}
	if len(trigger.OpeningMaterial) == 0 {
		return fmt.Errorf("worker reveal opening material is required")
	}
	if trigger.SampleEncodingProfile == "" || trigger.SourceRootKind == "" || trigger.EvidenceSchemaVersion == "" {
		return fmt.Errorf("worker reveal schema binding fields are required")
	}
	return nil
}

func canonicalSampledValueSetHash(trigger WorkerRevealTrigger) (codec.Hash, error) {
	if len(trigger.SelectedPositions) != len(trigger.SampledValueSet) {
		return codec.Hash{}, fmt.Errorf("worker reveal sampled values must match selected positions")
	}
	pairs := make([]sampledValuePair, len(trigger.SelectedPositions))
	for i, pos := range trigger.SelectedPositions {
		pairs[i] = sampledValuePair{position: pos, value: append([]byte(nil), trigger.SampledValueSet[i]...)}
	}
	slices.SortFunc(pairs, func(a, b sampledValuePair) int {
		switch {
		case a.position < b.position:
			return -1
		case a.position > b.position:
			return 1
		default:
			return bytes.Compare(a.value, b.value)
		}
	})
	var buf bytes.Buffer
	buf.WriteString(trigger.TaskID)
	buf.Write(codec.Uint64Bytes(trigger.VerifyRound))
	buf.Write(trigger.InferReceiptHash[:])
	buf.Write(trigger.VerificationSampleSeed[:])
	for _, pair := range pairs {
		buf.Write(codec.Uint64Bytes(pair.position))
		writeCanonicalBytes(&buf, pair.value)
	}
	writeCanonicalBytes(&buf, []byte(trigger.SampleEncodingProfile))
	writeCanonicalBytes(&buf, []byte(trigger.SourceRootKind))
	writeCanonicalBytes(&buf, []byte(trigger.EvidenceSchemaVersion))
	return codec.HashWithDomain("TRUEOPEN_WORKER_SAMPLED_VALUE_SET_V1", buf.Bytes()), nil
}

type sampledValuePair struct {
	position uint64
	value    []byte
}

func canonicalSelectedPositions(positions []uint64) []uint64 {
	out := append([]uint64(nil), positions...)
	slices.Sort(out)
	return out
}

func encodeWorkerRevealReceipt(receipt WorkerRevealReceipt) ([]byte, error) {
	if receipt.TaskID == "" || receipt.WorkerAddress == "" || receipt.SampledValueSetHash == (codec.Hash{}) {
		return nil, fmt.Errorf("worker reveal receipt missing required fields")
	}
	var buf bytes.Buffer
	buf.WriteString("CORTEX_WORKER_REVEAL_RECEIPT_V1")
	writeCanonicalBytes(&buf, []byte(receipt.TaskID))
	buf.Write(codec.Uint64Bytes(receipt.VerifyRound))
	writeCanonicalBytes(&buf, []byte(receipt.WorkerAddress))
	buf.Write(receipt.InferReceiptHash[:])
	buf.Write(receipt.VerificationSampleSeed[:])
	buf.Write(codec.Uint64Bytes(uint64(len(receipt.SelectedPositions))))
	for _, pos := range receipt.SelectedPositions {
		buf.Write(codec.Uint64Bytes(pos))
	}
	buf.Write(receipt.SampledValueSetHash[:])
	writeCanonicalBytes(&buf, []byte(receipt.SampleEncodingProfile))
	writeCanonicalBytes(&buf, []byte(receipt.SourceRootKind))
	writeCanonicalBytes(&buf, []byte(receipt.EvidenceSchemaVersion))
	writeCanonicalBytes(&buf, receipt.WorkerSignature)
	return buf.Bytes(), nil
}

func writeCanonicalBytes(buf *bytes.Buffer, value []byte) {
	buf.Write(codec.Uint64Bytes(uint64(len(value))))
	buf.Write(value)
}

func (w *Worker) persistWorkerRevealOpening(ctx context.Context, taskID string, opening []byte) error {
	if w.cfg.Persistence == nil {
		return nil
	}
	openingHash := codec.HashBytes(opening)
	return w.cfg.Persistence.WriteEvidence(ctx, EvidenceRecord{
		TaskID: taskID,
		Kind:   "worker-reveal-opening",
		Data:   append([]byte(nil), opening...),
		Ref:    "sha256:" + fmt.Sprintf("%x", openingHash[:]),
	})
}

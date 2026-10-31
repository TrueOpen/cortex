package verifier

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/txclient"
)

// DataLevel is the ADR-0023 evidence level a report is about.
type DataLevel uint8

const (
	DataLevelA DataLevel = 1 // input/output/WORKER_TOKEN_OPENING, before the commit deadline
	DataLevelB DataLevel = 2 // WORKER_VALUE_OPENING, in REVEALING before the reveal deadline
)

// UnavailableBuilderBitmap marks the unavailable Builders in the frozen Task
// Builder order: bit i in byte i/8 at mask 1<<(i%8), length ceil(n/8)
// (fixed by wire data_unavailable_bitmap_v1).
func UnavailableBuilderBitmap(selected []string, unavailable map[string]bool) ([]byte, error) {
	if len(selected) == 0 {
		return nil, fmt.Errorf("the task has no fixed Task Builders to report")
	}
	index := make(map[string]int, len(selected))
	for i, builder := range selected {
		if _, dup := index[builder]; dup {
			return nil, fmt.Errorf("Task Builder %s appears twice in the frozen selection", builder)
		}
		index[builder] = i
	}
	bitmap := make([]byte, (len(selected)+7)/8)
	marked := 0
	for builder, down := range unavailable {
		if !down {
			continue
		}
		i, ok := index[builder]
		if !ok {
			return nil, fmt.Errorf("Builder %s is not one of the task's fixed Task Builders", builder)
		}
		bitmap[i/8] |= 1 << (i % 8)
		marked++
	}
	if marked == 0 {
		return nil, fmt.Errorf("a data unavailable report must mark at least one Task Builder")
	}
	return bitmap, nil
}

// DataUnavailableReport is one MsgReportDataUnavailable.
type DataUnavailableReport struct {
	SessionID, TaskID string
	VerifyRound       uint32
	Level             DataLevel
	Invalid           bool // WORKER_EVIDENCE_INVALID, else BUILDER_UNAVAILABLE
	Bitmap            []byte
	DeadlineHeight    uint64 // commit deadline (A) or reveal deadline (B); the tx timeout
}

// ReportDataUnavailable self-submits the report (CD §6.2 V7b/V14b). No relay
// exists for it; the outer signer is this operator's current service address.
func (m *SettlementManager) ReportDataUnavailable(ctx context.Context, r DataUnavailableReport) (SettlementObservation, error) {
	if r.DeadlineHeight == 0 {
		return SettlementObservation{}, fmt.Errorf("a data unavailable report needs its window's deadline height")
	}
	kind := txclient.EvidenceKindUnspecified
	switch r.Level {
	case DataLevelA:
	case DataLevelB:
		kind = txclient.EvidenceKindWorkerValueOpening
	default:
		return SettlementObservation{}, fmt.Errorf("unknown data level %d", r.Level)
	}
	reason := txclient.DataUnavailableReasonBuilderUnavailable
	if r.Invalid {
		reason = txclient.DataUnavailableReasonWorkerEvidenceInvalid
	}
	message := txclient.ReportDataUnavailableMessage{
		TaskID: txclient.ProtoBytes32(r.TaskID), VerifyRound: txclient.ProtoUint32(r.VerifyRound),
		UnavailableTaskBuilderBitmap: txclient.ProtoBytes(hex.EncodeToString(r.Bitmap)),
		SubmitterAddress:             m.cfg.SubmitterAddress, EvidenceKind: kind, Reason: reason,
	}
	payload, err := txclient.MarshalMessage(txclient.MsgReportDataUnavailable, message)
	if err != nil {
		return SettlementObservation{}, err
	}
	tx, err := m.submit(ctx, txclient.Request{
		TaskID: r.TaskID, SessionID: r.SessionID, Kind: txclient.MsgReportDataUnavailable, Payload: payload,
		DeadlineHeight: r.DeadlineHeight,
		MaterialDigest: codec.HashWithDomain("TRUEOPEN_VERIFIER_DATA_UNAVAILABLE_MATERIAL_V1", []byte(r.TaskID), payload),
		FeeCap:         m.cfg.CommitFeeCap,
	})
	if err != nil {
		return SettlementObservation{}, err
	}
	observation := SettlementObservation{Submitted: true, Tx: tx}
	switch {
	case tx.Rejected:
		return observation, fmt.Errorf("data unavailable report for task %s was rejected (tx %s): %s", r.TaskID, tx.TxHash, tx.RejectReason)
	case !tx.Accepted:
		return observation, fmt.Errorf("data unavailable report for task %s reached %q but not Keeper confirmation (tx %s)", r.TaskID, tx.Status, tx.TxHash)
	}
	return observation, nil
}

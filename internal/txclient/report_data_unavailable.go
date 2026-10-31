package txclient

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// MsgReportDataUnavailable is a selected Verifier's availability report
// (CD §6.2 V7b/V14b). The Cosmos signer is its current service address.
const MsgReportDataUnavailable Kind = "/task.v1.MsgReportDataUnavailable"

// The ProtoJSON enum names MsgReportDataUnavailable carries beside
// EvidenceKindWorkerValueOpening. UNSPECIFIED is written by this report only:
// it is the A-level kind (input/output/WORKER_TOKEN_OPENING are not
// separately addressable by the report).
const (
	EvidenceKindUnspecified                    = "EVIDENCE_KIND_UNSPECIFIED"
	DataUnavailableReasonBuilderUnavailable    = "DATA_UNAVAILABLE_REASON_V1_BUILDER_UNAVAILABLE"
	DataUnavailableReasonWorkerEvidenceInvalid = "DATA_UNAVAILABLE_REASON_V1_WORKER_EVIDENCE_INVALID"
)

// ReportDataUnavailableMessage mirrors task.v1.MsgReportDataUnavailable.
// The bitmap follows TaskBuilderSelectionState order, bit i in byte i/8 at
// mask 1<<(i%8), length ceil(count/8).
type ReportDataUnavailableMessage struct {
	TaskID                       ProtoBytes32 `json:"task_id"`
	VerifyRound                  ProtoUint32  `json:"verify_round"`
	UnavailableTaskBuilderBitmap ProtoBytes   `json:"unavailable_task_builder_bitmap"`
	SubmitterAddress             string       `json:"submitter_address"`
	EvidenceKind                 string       `json:"evidence_kind"`
	Reason                       string       `json:"reason"`
}

func validateReportDataUnavailable(m ReportDataUnavailableMessage) error {
	if err := requireStrings(m.SubmitterAddress); err != nil {
		return err
	}
	if err := validateHashHex(m.TaskID.Hex()); err != nil {
		return fmt.Errorf("data unavailable report task_id: %w", err)
	}
	if m.VerifyRound < 1 {
		return fmt.Errorf("data unavailable report verify_round must be at least 1")
	}
	bitmap, err := hex.DecodeString(m.UnavailableTaskBuilderBitmap.Hex())
	if err != nil || len(bitmap) == 0 || bytes.Equal(bitmap, make([]byte, len(bitmap))) {
		return fmt.Errorf("data unavailable report bitmap must mark at least one Task Builder")
	}
	switch m.EvidenceKind {
	case EvidenceKindUnspecified, EvidenceKindWorkerValueOpening:
	default:
		return fmt.Errorf("data unavailable report evidence_kind %q is neither the A-level UNSPECIFIED nor WORKER_VALUE_OPENING", m.EvidenceKind)
	}
	switch m.Reason {
	case DataUnavailableReasonBuilderUnavailable, DataUnavailableReasonWorkerEvidenceInvalid:
	default:
		return fmt.Errorf("data unavailable report reason %q is not BUILDER_UNAVAILABLE or WORKER_EVIDENCE_INVALID", m.Reason)
	}
	return nil
}

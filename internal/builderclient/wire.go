package builderclient

import (
	"encoding/hex"
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
	bussharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	bustaskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

const WorkerHandraiseSchemaV1 = uint32(1)

// This file is the bridge between the two frozen authorities Cortex speaks:
//
//   - internal/nodewire owns the H_FIELDS_V1 signing digests of the chain-bound
//     materials (handraises, result receipts). Digests are computed there and
//     only there.
//   - proto/bus/gen owns the protobuf wire encoding those materials travel
//     in on the NATS bus (and, byte for byte, in the chain Msgs the Builder
//     relays). Payload bytes are marshalled from the proto forms and only
//     from them.
//
// The retired trueopen-cjson-v1 payload structs and the Nexus-local legacy
// VerifyResult shape are gone: what a Cortex signs is the frozen task.v1
// message, and the bytes it signs over are the bytes the Builder submits on
// chain, with no JSON copy in between.

func dutyProto(duty nodewire.Duty) (bussharedv1.Duty, error) {
	switch duty {
	case nodewire.DutyWorker:
		return bussharedv1.Duty_DUTY_WORKER, nil
	case nodewire.DutyVerifier:
		return bussharedv1.Duty_DUTY_VERIFIER, nil
	default:
		return bussharedv1.Duty_DUTY_UNSPECIFIED, fmt.Errorf("duty %d is not a frozen wire duty", duty)
	}
}

func candidateMemberProto(member nodewire.CandidateMemberRefV1) *bustaskv1.CandidateMemberRefV1 {
	return &bustaskv1.CandidateMemberRefV1{
		CandidatePoolSnapshotId: append([]byte(nil), member.CandidatePoolSnapshotID...),
		Slot:                    member.Slot,
		SlotVersion:             member.SlotVersion,
		OperatorAddress:         member.OperatorAddress,
	}
}

// WorkerHandraiseProto projects the digest-authority struct onto the frozen
// wire message. The signature must already be over
// nodewire.WorkerHandraiseSigningDigest of the same value.
func WorkerHandraiseProto(handraise nodewire.WorkerHandraiseV1) (*bustaskv1.WorkerHandraiseV1, error) {
	duty, err := dutyProto(handraise.Duty)
	if err != nil {
		return nil, fmt.Errorf("worker handraise: %w", err)
	}
	if len(handraise.ServiceSignature) != 64 {
		return nil, fmt.Errorf("worker handraise service_signature must be 64 bytes, got %d", len(handraise.ServiceSignature))
	}
	return &bustaskv1.WorkerHandraiseV1{
		SchemaVersion:             handraise.SchemaVersion,
		ChainId:                   handraise.ChainID,
		TaskId:                    append([]byte(nil), handraise.TaskID...),
		TaskHash:                  append([]byte(nil), handraise.TaskHash...),
		ModelId:                   handraise.ModelID,
		ProfileVersion:            handraise.ProfileVersion,
		Member:                    candidateMemberProto(handraise.Member),
		Duty:                      duty,
		ServiceAuthorizationNonce: handraise.ServiceAuthorizationNonce,
		ExpiryHeight:              handraise.ExpiryHeight,
		ServiceSignature:          append([]byte(nil), handraise.ServiceSignature...),
	}, nil
}

// WorkerHandraiseFromProto rebuilds the digest-authority struct from the wire
// message, so a receiver (or this node's own persisted copy) can recompute the
// frozen digest against the carried signature.
func WorkerHandraiseFromProto(message *bustaskv1.WorkerHandraiseV1) (nodewire.WorkerHandraiseV1, error) {
	if message == nil {
		return nodewire.WorkerHandraiseV1{}, fmt.Errorf("worker handraise message is required")
	}
	member := message.GetMember()
	if member == nil {
		return nodewire.WorkerHandraiseV1{}, fmt.Errorf("worker handraise member is required")
	}
	return nodewire.WorkerHandraiseV1{
		SchemaVersion:  message.GetSchemaVersion(),
		ChainID:        message.GetChainId(),
		TaskID:         append([]byte(nil), message.GetTaskId()...),
		TaskHash:       append([]byte(nil), message.GetTaskHash()...),
		ModelID:        message.GetModelId(),
		ProfileVersion: message.GetProfileVersion(),
		Member: nodewire.CandidateMemberRefV1{
			CandidatePoolSnapshotID: append([]byte(nil), member.GetCandidatePoolSnapshotId()...),
			Slot:                    member.GetSlot(),
			SlotVersion:             member.GetSlotVersion(),
			OperatorAddress:         member.GetOperatorAddress(),
		},
		Duty:                      nodewire.Duty(message.GetDuty()),
		ServiceAuthorizationNonce: message.GetServiceAuthorizationNonce(),
		ExpiryHeight:              message.GetExpiryHeight(),
		ServiceSignature:          append([]byte(nil), message.GetServiceSignature()...),
	}, nil
}

// VerifierHandraiseProto projects the digest-authority struct onto the frozen
// wire message.
func VerifierHandraiseProto(handraise nodewire.VerifierHandraiseV1) (*bustaskv1.VerifierHandraiseV1, error) {
	duty, err := dutyProto(handraise.Duty)
	if err != nil {
		return nil, fmt.Errorf("verifier handraise: %w", err)
	}
	if len(handraise.ServiceSignature) != 64 {
		return nil, fmt.Errorf("verifier handraise service_signature must be 64 bytes, got %d", len(handraise.ServiceSignature))
	}
	return &bustaskv1.VerifierHandraiseV1{
		SchemaVersion:             handraise.SchemaVersion,
		ChainId:                   handraise.ChainID,
		TaskId:                    append([]byte(nil), handraise.TaskID...),
		VerifyRound:               handraise.VerifyRound,
		InferReceiptHash:          append([]byte(nil), handraise.InferReceiptHash...),
		OutputHash:                append([]byte(nil), handraise.OutputHash...),
		ModelId:                   handraise.ModelID,
		ProfileVersion:            handraise.ProfileVersion,
		Member:                    candidateMemberProto(handraise.Member),
		Duty:                      duty,
		ServiceAuthorizationNonce: handraise.ServiceAuthorizationNonce,
		ExpiryHeight:              handraise.ExpiryHeight,
		ServiceSignature:          append([]byte(nil), handraise.ServiceSignature...),
	}, nil
}

// ResultReceiptProto projects the signed digest-authority result receipt onto
// the frozen wire message. The optional MetricSummaryV1 members map presence
// exactly: an absent OptionalUint32 stays absent on the wire.
func ResultReceiptProto(receipt nodewire.ResultReceiptV2) (*bustaskv1.ResultReceiptV2, error) {
	if err := validateCompactSignature(receipt.ServiceSignature); err != nil {
		return nil, err
	}
	if _, err := nodewire.ResultReceiptSigningDigest(receipt); err != nil {
		return nil, err
	}
	summary := &bustaskv1.MetricSummaryV1{
		FiniteCount:                receipt.MetricSummary.FiniteCount,
		MissingComparedCount:       receipt.MetricSummary.MissingComparedCount,
		MeanAbsLogprobDiffFp_1E6:   receipt.MetricSummary.MeanAbsLogprobDiffFP1e6,
		AbsLogprobDiffP95Fp_1E6:    receipt.MetricSummary.AbsLogprobDiffP95FP1e6,
		AbsLogprobDiffP99Fp_1E6:    receipt.MetricSummary.AbsLogprobDiffP99FP1e6,
		RankDeltaNonzeroRateFp_1E6: receipt.MetricSummary.RankDeltaNonzeroRateFP1e6,
		ComparedTopkCount:          receipt.MetricSummary.ComparedTopkCount,
		ComparedRankCount:          receipt.MetricSummary.ComparedRankCount,
	}
	if receipt.MetricSummary.TopkJaccardMeanFP1e6.Present {
		value := receipt.MetricSummary.TopkJaccardMeanFP1e6.Value
		summary.TopkJaccardMeanFp_1E6 = &value
	}
	if receipt.MetricSummary.UnionJSP99FP1e6.Present {
		value := receipt.MetricSummary.UnionJSP99FP1e6.Value
		summary.UnionJsP99Fp_1E6 = &value
	}
	return &bustaskv1.ResultReceiptV2{
		SchemaVersion:                     receipt.SchemaVersion,
		ChainId:                           receipt.ChainID,
		TaskId:                            append([]byte(nil), receipt.TaskID...),
		VerifyRound:                       receipt.VerifyRound,
		VerifierOperatorAddress:           receipt.VerifierOperatorAddress,
		ServiceAuthorizationNonce:         receipt.ServiceAuthorizationNonce,
		GenerationParamsDigest:            append([]byte(nil), receipt.GenerationParamsDigest...),
		MetricRoot:                        append([]byte(nil), receipt.MetricRoot...),
		MetricSummary:                     summary,
		AggregateProofHash:                append([]byte(nil), receipt.AggregateProofHash...),
		VerifierEvidenceBundleHash:        append([]byte(nil), receipt.VerifierEvidenceBundleHash...),
		VerifierEvidenceManifestSizeBytes: receipt.VerifierEvidenceManifestSizeBytes,
		Salt:                              append([]byte(nil), receipt.Salt...),
		ExpiryHeight:                      receipt.ExpiryHeight,
		ServiceSignature:                  append([]byte(nil), receipt.ServiceSignature...),
	}, nil
}

// DecodePersistedWorkerHandraise decodes a handraise payload this binary wrote
// (the exact proto bytes carried inside the persisted envelope frame) and
// checks the frozen digest fields are decodable.
func DecodePersistedWorkerHandraise(payload []byte, dst *bustaskv1.WorkerHandraiseV1) error {
	envelope := BusEnvelope{Kind: KindWorkerHandraise, Payload: payload}
	if err := envelope.DecodePayload(dst); err != nil {
		return err
	}
	if _, err := WorkerHandraiseFromProto(dst); err != nil {
		return fmt.Errorf("decode persisted worker handraise: %w", err)
	}
	return nil
}

// CandidateMemberRefMessage is the task-plane carrier of the Keeper candidate
// locator, with the snapshot id in canonical Hash32 hex exactly as the chain
// queries serve it. It is not a wire shape: the bus and the chain both carry
// the bytes form, reached through Nodewire().
type CandidateMemberRefMessage struct {
	CandidatePoolSnapshotID string
	Slot                    uint32
	SlotVersion             uint64
	OperatorAddress         string
}

// Nodewire converts the hex carrier into the digest-authority bytes form.
func (m CandidateMemberRefMessage) Nodewire() (nodewire.CandidateMemberRefV1, error) {
	snapshotID, err := canonicalWireHash(m.CandidatePoolSnapshotID, "member.candidate_pool_snapshot_id")
	if err != nil {
		return nodewire.CandidateMemberRefV1{}, err
	}
	return nodewire.CandidateMemberRefV1{
		CandidatePoolSnapshotID: snapshotID[:],
		Slot:                    m.Slot,
		SlotVersion:             m.SlotVersion,
		OperatorAddress:         m.OperatorAddress,
	}, nil
}

func canonicalWireHash(value, field string) (codec.Hash, error) {
	if len(value) != hex.EncodedLen(len(codec.Hash{})) {
		return codec.Hash{}, fmt.Errorf("%s must be canonical lowercase Hash32 hex", field)
	}
	raw, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(raw) != value {
		return codec.Hash{}, fmt.Errorf("%s must be canonical lowercase Hash32 hex", field)
	}
	var hash codec.Hash
	copy(hash[:], raw)
	return hash, nil
}

// CanonicalWireHash exposes the canonical Hash32 hex decoder for consumers
// that project task-plane hex identities into frozen bytes fields.
func CanonicalWireHash(value, field string) (codec.Hash, error) {
	return canonicalWireHash(value, field)
}

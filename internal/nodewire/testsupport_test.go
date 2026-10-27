package nodewire

import (
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

// Declarations only tests use, kept out of the production binary.

func TaskOrderHashJSON(value string) (codec.Hash, error) {
	digest, _, err := TaskOrderHashAndFactsJSON(value)
	return digest, err
}

// SettlementBillPreimage returns the settlement bill preimage:
//
//	H_FIELDS_V1("TRUEOPEN_SETTLEMENT_BILL_V1",
//	  worker_operator_address, infer_receipt_ref, fee_rule_version,
//	  generated_token_count, work_unit)
//
// The five fields carry no schema_version.
func SettlementBillPreimage(leaf SettlementBillV1) ([]byte, error) {
	worker, err := CanonicalOperatorAddressBytes("worker_operator_address", leaf.WorkerOperatorAddress)
	if err != nil {
		return nil, err
	}
	inferReceiptRef, err := canonicalHash32("infer_receipt_ref", leaf.InferReceiptRef)
	if err != nil {
		return nil, err
	}
	return hfields.Preimage(
		DomainSettlementBillV1,
		hfields.Bytes(worker),
		hfields.Bytes(inferReceiptRef),
		hfields.Uint64(leaf.FeeRuleVersion),
		hfields.Uint64(leaf.GeneratedTokenCount),
		hfields.Uint64(leaf.WorkUnit),
	)
}

// SettlementBillHash is the settlement bill digest a round settlement carries
// as settlement_bill_hash.
func SettlementBillHash(leaf SettlementBillV1) (codec.Hash, error) {
	return digestOf(SettlementBillPreimage(leaf))
}

// WorkerTokenCommitmentPreimage frames all sixteen fields in schema order.
func WorkerTokenCommitmentPreimage(value WorkerTokenCommitmentV1) ([]byte, error) {
	fields, _, err := workerTokenCommitmentFields(value)
	if err != nil {
		return nil, err
	}
	return hfields.Preimage(DomainWorkerTokenCommitmentV1, fields...)
}

// WorkerValueCommitmentV3Preimage frames all eight fields in schema order.
func WorkerValueCommitmentV3Preimage(value WorkerValueCommitmentV3) ([]byte, error) {
	fields, err := workerValueCommitmentV3Fields(value)
	if err != nil {
		return nil, err
	}
	return hfields.Preimage(DomainWorkerValueCommitmentV3, fields...)
}

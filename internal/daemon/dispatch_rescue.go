package daemon

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/txclient"
)

// rescueReceipts self-submits MsgSubmitInferReceipt for a recorded ticket
// whose signed receipt the chain has not accepted once infer_deadline_height
// is within ReceiptRescueMarginBlocks (CD §5.2 W13, §8.2). The receipt goes
// out exactly as signed; only the outer Tx signer differs (CD §8.3). One
// rescue per receipt. The caller holds the work lock.
func (d *Dispatcher) rescueReceipts(ctx context.Context, height uint64) error {
	if d.cfg.Tx == nil {
		return nil
	}
	recs, err := layout.ReceiptRescueCandidates(ctx, d.cfg.Store)
	if err != nil {
		return fmt.Errorf("dispatcher: rescue candidates: %w", err)
	}
	var errs []error
	for _, rec := range recs {
		if rec.RescueTxHash != "" || height > rec.InferDeadlineHeight || height+d.cfg.ReceiptRescueMarginBlocks < rec.InferDeadlineHeight {
			continue
		}
		a, err := d.cfg.Chain.DispatchAssignment(ctx, rec.TaskID[:])
		if err != nil {
			errs = append(errs, fmt.Errorf("ticket %s: %w", rec.TicketHash, err))
			continue
		}
		if a.ReceiptAccepted {
			if _, err := layout.UpdateDispatch(ctx, d.cfg.Store, rec.TicketHash, func(r *layout.DispatchRecord) error {
				r.ReceiptAccepted = true
				return nil
			}); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		obs, err := d.submitRescue(ctx, rec)
		if err != nil {
			errs = append(errs, fmt.Errorf("ticket %s rescue: %w", rec.TicketHash, err))
			continue
		}
		hash := obs.TxHash
		if hash == "" {
			hash = "submitted"
		}
		if _, err := layout.UpdateDispatch(ctx, d.cfg.Store, rec.TicketHash, func(r *layout.DispatchRecord) error {
			r.RescueTxHash = hash
			return nil
		}); err != nil {
			errs = append(errs, err)
		}
		d.cfg.Logger.Warn("infer receipt self-rescued", "alert", "infer_receipt_self_rescue", "ticket", rec.TicketHash.String(),
			"height", height, "infer_deadline_height", rec.InferDeadlineHeight, "tx", hash)
	}
	return errors.Join(errs...)
}

func (d *Dispatcher) submitRescue(ctx context.Context, rec layout.DispatchRecord) (txclient.Observation, error) {
	var receipt builderclient.SignedInferReceipt
	if err := json.Unmarshal(rec.Receipt, &receipt); err != nil {
		return txclient.Observation{}, fmt.Errorf("stored receipt: %w", err)
	}
	msg, err := inferReceiptRescueMessage(receipt, d.cfg.ServiceAddress)
	if err != nil {
		return txclient.Observation{}, err
	}
	payload, err := txclient.MarshalMessage(txclient.MsgSubmitInferReceipt, msg)
	if err != nil {
		return txclient.Observation{}, err
	}
	taskID := hex.EncodeToString(rec.TaskID[:])
	return d.cfg.Tx.Submit(ctx, txclient.Request{
		TaskID: taskID, SessionID: hex.EncodeToString(rec.SessionID[:]), Kind: txclient.MsgSubmitInferReceipt, Payload: payload,
		DeadlineHeight: rec.InferDeadlineHeight,
		MaterialDigest: codec.HashWithDomain("TRUEOPEN_INFER_RECEIPT_SELF_RESCUE_V1", []byte(taskID), payload),
	})
}

// inferReceiptRescueMessage maps the signed receipt onto task.v1
// MsgSubmitInferReceipt without touching a signed field.
func inferReceiptRescueMessage(r builderclient.SignedInferReceipt, submitter string) (txclient.SubmitInferReceiptMessage, error) {
	kinds := map[nodewire.EvidenceKind]string{
		nodewire.EvidenceKindWorkerValueOpening: txclient.EvidenceKindWorkerValueOpening,
		nodewire.EvidenceKindWorkerTokenOpening: txclient.EvidenceKindWorkerTokenOpening,
	}
	commitments := make([]txclient.EvidenceCommitmentMessage, len(r.RequiredEvidenceCommitments))
	for i, c := range r.RequiredEvidenceCommitments {
		kind, ok := kinds[c.EvidenceKind]
		if !ok {
			return txclient.SubmitInferReceiptMessage{}, fmt.Errorf("receipt commitment %d has evidence kind %d", i, c.EvidenceKind)
		}
		commitments[i] = txclient.EvidenceCommitmentMessage{EvidenceKind: kind, EvidenceHashOrRoot: txclient.ProtoBytes32(c.EvidenceHashOrRoot.String()), EncodedSizeBytes: txclient.ProtoUint64(c.EncodedSizeBytes)}
	}
	zero := txclient.ProtoBytes32(strings.Repeat("00", 32))
	return txclient.SubmitInferReceiptMessage{SubmitterAddress: submitter, Receipt: txclient.InferReceiptMessage{
		SchemaVersion: txclient.ProtoUint32(r.SchemaVersion), ChainID: r.ChainID,
		TaskID: txclient.ProtoBytes32(r.TaskID), TaskHash: txclient.ProtoBytes32(r.TaskHash),
		WorkerOperatorAddress: r.WorkerOperatorAddress, ServiceAuthorizationNonce: txclient.ProtoUint64(r.ServiceAuthorizationNonce),
		GenerationParamsDigest: txclient.ProtoBytes32(r.GenerationParamsDigest), OutputHash: txclient.ProtoBytes32(r.OutputHash),
		OutputSizeBytes: txclient.ProtoUint64(r.OutputSizeBytes), RequiredEvidenceCommitments: commitments,
		ExpiryHeight: txclient.ProtoUint64(r.ExpiryHeight), ServiceSignature: txclient.ProtoBytes(r.ServiceSignature),
		GeneratedTokenCount: txclient.ProtoUint64(r.GeneratedTokenCount), OutputLeafCount: txclient.ProtoUint64(r.OutputLeafCount),
		OutputKeyCommitment: zero, WorkerTokenKeyCommitment: zero, WorkerValueKeyCommitment: zero, CiphertextOutputRoot: zero,
		DispatchTicketHash: txclient.ProtoBytes32(r.DispatchTicketHash),
	}}, nil
}

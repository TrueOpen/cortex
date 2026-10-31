package verifier

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/tasktrace"
	"github.com/TrueOpen/cortex/internal/txclient"
)

// ErrResultExitUnavailable: a real-mode reveal has no way to put its signed
// result on chain, so it is refused before anything is signed.
var ErrResultExitUnavailable = errors.New("verify result has no submission exit")

// verifierResultDeliveryEvidenceKind records that the chain confirmed this
// round's result, so a repeated reveal does not pay for a second submission.
const verifierResultDeliveryEvidenceKind = "verifier-result-delivery"

// ResultSubmitter self-submits MsgSubmitVerifyResult (outer signer: this
// operator's current Cortex service address). The Task Builder result relay is
// deferred (S7 Q7), so this is the only exit.
type ResultSubmitter interface {
	SubmitVerifyResultDirect(context.Context, DirectResultInput) (SettlementObservation, error)
}

// DirectResultInput is one result self-submission; DeadlineHeight becomes the
// tx timeout_height and equals the receipt's expiry_height (reveal deadline).
type DirectResultInput struct {
	SessionID      string
	TaskID         string
	DeadlineHeight uint64
	Message        txclient.SubmitVerifyResultMessage
}

// ResultDelivery is what happened to the signed result.
type ResultDelivery struct {
	Submitted      bool   `json:"submitted"`
	Duplicate      bool   `json:"-"`
	ChainAccepted  bool   `json:"chain_accepted"`
	TxHash         string `json:"tx_hash"`
	IncludedHeight uint64 `json:"included_height"`
}

// deliverResult self-submits the signed result once. A chain-confirmed
// delivery is recorded, and a later reveal of the same round reports it as a
// duplicate instead of submitting again.
func (v *Verifier) deliverResult(ctx context.Context, state TaskState, receipt nodewire.ResultReceiptV3) (ResultDelivery, error) {
	if reader, ok := v.cfg.Persistence.(verifierEvidenceReader); ok {
		data, err := reader.ReadVerifierEvidence(ctx, verifierResultDeliveryEvidenceKind)
		switch {
		case err == nil:
			var previous ResultDelivery
			if json.Unmarshal(data, &previous) == nil {
				previous.Duplicate = true
				return previous, nil
			}
		case !errors.Is(err, evidence.ErrArtifactNotFound):
			return ResultDelivery{}, fmt.Errorf("read persisted result delivery: %w", err)
		}
	}
	if v.cfg.ResultSubmitter == nil {
		// FakeOutput only: a real-mode reveal was refused before signing.
		return ResultDelivery{}, nil
	}
	message, err := resultMessage(v.cfg, receipt)
	if err != nil {
		return ResultDelivery{}, err
	}
	observation, err := v.cfg.ResultSubmitter.SubmitVerifyResultDirect(ctx, DirectResultInput{
		SessionID: state.SessionID, TaskID: state.TaskID, DeadlineHeight: receipt.ExpiryHeight, Message: message,
	})
	if err != nil {
		return ResultDelivery{}, err
	}
	delivery := ResultDelivery{Submitted: true, ChainAccepted: observation.Tx.Accepted, TxHash: observation.Tx.TxHash, IncludedHeight: observation.Tx.IncludedHeight}
	switch {
	case observation.Tx.Rejected:
		return delivery, fmt.Errorf("verify result for task %s was rejected on chain (tx %s): %s", state.TaskID, observation.Tx.TxHash, observation.Tx.RejectReason)
	case !observation.Tx.Accepted:
		return delivery, fmt.Errorf("verify result for task %s reached %q but not Keeper confirmation (tx %s)", state.TaskID, observation.Tx.Status, observation.Tx.TxHash)
	}
	if v.cfg.Persistence != nil {
		data, _ := json.Marshal(delivery)
		if err := v.cfg.Persistence.WriteEvidence(ctx, EvidenceRecord{TaskID: state.TaskID, Kind: verifierResultDeliveryEvidenceKind, Data: data, Ref: evidenceRef(data)}); err != nil {
			// The result is on chain; losing the dedup record costs at most one
			// duplicate submission the Keeper refuses.
			v.cfg.Trace.ErrorEvent("verify_result_delivery_record_failed", tasktrace.Str("task", state.TaskID), tasktrace.Err("error", err))
		}
	}
	return delivery, nil
}

// resultMessage marshals the exact signed body: nothing is re-read.
func resultMessage(cfg Config, r nodewire.ResultReceiptV3) (txclient.SubmitVerifyResultMessage, error) {
	if len(r.ServiceSignature) == 0 {
		return txclient.SubmitVerifyResultMessage{}, fmt.Errorf("verify result service_signature is missing: the body was never signed")
	}
	optional := func(o nodewire.OptionalUint32) *txclient.ProtoUint32 {
		if !o.Present {
			return nil
		}
		value := txclient.ProtoUint32(o.Value)
		return &value
	}
	key := r.VerifierEvidenceKeyCommitment
	if len(key) == 0 {
		key = make([]byte, 32)
	}
	h := func(b []byte) txclient.ProtoBytes32 { return txclient.ProtoBytes32(hex.EncodeToString(b)) }
	s := r.MetricSummary
	return txclient.SubmitVerifyResultMessage{
		Receipt: txclient.ResultReceiptMessage{
			SchemaVersion: txclient.ProtoUint32(r.SchemaVersion), ChainID: r.ChainID, TaskID: h(r.TaskID),
			VerifyRound: txclient.ProtoUint32(r.VerifyRound), VerifierOperatorAddress: r.VerifierOperatorAddress,
			ServiceAuthorizationNonce: txclient.ProtoUint64(r.ServiceAuthorizationNonce),
			GenerationParamsDigest:    h(r.GenerationParamsDigest), MetricRoot: h(r.MetricRoot),
			MetricSummary: txclient.MetricSummaryMessage{
				FiniteCount: txclient.ProtoUint32(s.FiniteCount), MissingComparedCount: txclient.ProtoUint32(s.MissingComparedCount),
				MeanAbsLogprobDiffFP1e6: txclient.ProtoUint32(s.MeanAbsLogprobDiffFP1e6), AbsLogprobDiffP95FP1e6: txclient.ProtoUint32(s.AbsLogprobDiffP95FP1e6),
				AbsLogprobDiffP99FP1e6: txclient.ProtoUint32(s.AbsLogprobDiffP99FP1e6), RankDeltaNonzeroRateFP1e6: txclient.ProtoUint32(s.RankDeltaNonzeroRateFP1e6),
				TopkJaccardMeanFP1e6: optional(s.TopkJaccardMeanFP1e6), UnionJSP99FP1e6: optional(s.UnionJSP99FP1e6),
				ComparedTopkCount: txclient.ProtoUint32(s.ComparedTopkCount), ComparedRankCount: txclient.ProtoUint32(s.ComparedRankCount),
			},
			AggregateProofHash: h(r.AggregateProofHash), VerifierEvidenceBundleHash: h(r.VerifierEvidenceBundleHash),
			VerifierEvidenceManifestSizeBytes: txclient.ProtoUint64(r.VerifierEvidenceManifestSizeBytes),
			Salt:                              h(r.Salt), ExpiryHeight: txclient.ProtoUint64(r.ExpiryHeight),
			ServiceSignature:              txclient.ProtoBytes(hex.EncodeToString(r.ServiceSignature)),
			VerifierValueRoot:             h(r.VerifierValueRoot),
			MetricLeafCount:               txclient.ProtoUint32(r.MetricLeafCount),
			VerifierEvidenceKeyCommitment: h(key),
		},
		SubmitterAddress: cfg.SignerAddress,
	}, nil
}

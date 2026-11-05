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

// ResultRelay hands the signed ResultReceiptV3 to the receiving Task Builder,
// which submits MsgSubmitVerifyResult as its own transaction (nexus ingress
// SubmitVerifyResult). It is the result's first exit, in the same order and
// with the same refusal contract as CommitRelay: a deterministic refusal
// (ErrResultRelayNotOffered) sends the result to the ResultSubmitter, anything
// else is retried. A nil relay means this round has no relay channel; a nil
// ResultSubmitter beside a live relay is the file:// keystore node, which
// cannot assemble a Cosmos transaction. What is refused is having neither.
type ResultRelay interface {
	RelayVerifyResult(context.Context, ResultRelayRequest) error
}

// ResultRelayRequest is the exact signed body plus the routing context.
type ResultRelayRequest struct {
	SessionID   string
	TaskID      string
	VerifyRound uint64
	Receipt     nodewire.ResultReceiptV3
}

// ErrResultRelayNotOffered is the result relay's deterministic refusal: take
// the self-submission exit instead of asking again.
var ErrResultRelayNotOffered = errors.New("verify result relay is not offered for this round")

// ResultRelayNotOffered reports whether a relay error is the deterministic
// refusal. Like CommitRelayNotOffered it also matches the frozen nexus code,
// and treats everything else as transient so a relay that may still carry the
// result is not raced by a self-submission.
func ResultRelayNotOffered(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrResultRelayNotOffered) || CommitRelayNotOffered(err)
}

// ResultSubmitter self-submits MsgSubmitVerifyResult (outer signer: this
// operator's current Cortex service address). It is the second exit, taken when
// no ResultRelay is wired or the relay refused deterministically.
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
	// Relayed: the receiving Builder accepted the result for relay. That is
	// not chain acceptance (nexus contract §7), so a relayed delivery is never
	// recorded as the round's dedup record.
	Relayed        bool   `json:"relayed,omitempty"`
	Submitted      bool   `json:"submitted"`
	Duplicate      bool   `json:"-"`
	ChainAccepted  bool   `json:"chain_accepted"`
	TxHash         string `json:"tx_hash"`
	IncludedHeight uint64 `json:"included_height"`
}

// deliverResult takes the result exit: the Builder relay first whenever one is
// wired, self-submission only when there is no relay or it refused
// deterministically (the deliverCommit order). A chain-confirmed
// self-submission is recorded, and a later reveal of the same round reports it
// as a duplicate instead of submitting again.
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
	reason := CommitExitRelayChannelAbsent
	if v.cfg.ResultRelay != nil {
		relayErr := v.cfg.ResultRelay.RelayVerifyResult(ctx, ResultRelayRequest{
			SessionID: state.SessionID, TaskID: state.TaskID, VerifyRound: state.VerifyRound, Receipt: receipt,
		})
		switch {
		case relayErr == nil:
			// Not memoised: relay acceptance is not chain acceptance.
			return ResultDelivery{Relayed: true}, nil
		case !ResultRelayNotOffered(relayErr):
			return ResultDelivery{}, fmt.Errorf("relay verify result for task %s: %w", state.TaskID, relayErr)
		}
		reason = CommitExitRelayNotOffered
	}
	if v.cfg.ResultSubmitter == nil {
		if v.cfg.ResultRelay == nil {
			// FakeOutput only: a real-mode reveal was refused before signing.
			return ResultDelivery{}, nil
		}
		return ResultDelivery{}, fmt.Errorf(
			"%w: the relay cannot carry this result (%s) and no direct result submitter is wired, so the signed "+
				"result for task %s would stay local", ErrResultExitUnavailable, reason, state.TaskID)
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

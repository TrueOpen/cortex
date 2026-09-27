package daemon

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/policy"
	"github.com/TrueOpen/cortex/internal/txclient"
	busv1 "github.com/TrueOpen/cortex/proto/bus/v1"
	"google.golang.org/protobuf/proto"
)

func outputPackageSummary(pkg builderclient.OutputPackage) policy.OutputPackageSummary {
	return policy.OutputPackageSummary{
		TaskID: pkg.TaskID, OutputRef: pkg.OutputRef, TokenIDsRef: pkg.TokenIDsRef, PositionValuesRef: pkg.PositionValuesRef,
		OutputHash: pkg.OutputHash, PackageHash: pkg.PackageHash,
		FromTaskData: pkg.Provenance == builderclient.OutputPackageFromTaskData,
	}
}

// confirmedOutputSummary is the V3 shape of the same summary. Its two inputs are
// the OPEN_VERIFY envelope's task and the Keeper-committed output hash, because
// those are the only two facts §6 of data-plane-and-evidence-transfer.md leaves a candidate: the
// metadata it may act on arrives on the control message, never from a data-plane
// query. The locator refs are absent for the same reason they are absent from a
// task-data package -- no wire carries them -- and there is no package hash to
// carry, so FromTaskData is what tells the precheck not to look for either.
func confirmedOutputSummary(taskID string, outputHash codec.Hash) policy.OutputPackageSummary {
	return policy.OutputPackageSummary{TaskID: taskID, OutputHash: outputHash, FromTaskData: true}
}

// validateNexusOrderBroadcast checks an ORDER_BROADCAST payload. The signed
// order it carries is the only authority in the frame: the user signed that
// order, and every fact (session, sequence, model, deadline, builder set) is
// read off the decoded TaskOrderV1 rather than off payload copies, which the
// V2 payload no longer has.
//
// It returns the derived task_hash, the decoded order facts and the exact
// SignedOrderV1 bytes (re-marshalled from the received message; task identity
// is field-derived, so re-marshalling cannot change it).
func validateNexusOrderBroadcast(order *busv1.OrderBroadcastV1, envelope builderclient.BusEnvelope, verifyTaskOrder bool) (codec.Hash, nodewire.TaskOrderFacts, []byte, error) {
	signed := order.GetSignedOrder()
	if signed == nil {
		return codec.Hash{}, nodewire.TaskOrderFacts{}, nil, fmt.Errorf("OrderBroadcast signed_order is required")
	}
	signedOrderBytes, err := proto.Marshal(signed)
	if err != nil {
		return codec.Hash{}, nodewire.TaskOrderFacts{}, nil, fmt.Errorf("marshal OrderBroadcast signed_order: %w", err)
	}
	taskHash, facts, err := nodewire.TaskOrderHashAndFactsEnvelope(hex.EncodeToString(signedOrderBytes))
	if err != nil {
		return codec.Hash{}, nodewire.TaskOrderFacts{}, nil, fmt.Errorf("OrderBroadcast signed_order is not a canonical TaskOrderV1 carrier: %w", err)
	}
	if taskHash == (codec.Hash{}) {
		return codec.Hash{}, nodewire.TaskOrderFacts{}, nil, fmt.Errorf("OrderBroadcast task_hash must not be zero")
	}
	if verifyTaskOrder {
		if facts.ChainID != envelope.ChainID {
			return codec.Hash{}, nodewire.TaskOrderFacts{}, nil, fmt.Errorf("OrderBroadcast order chain_id %q does not match envelope %q", facts.ChainID, envelope.ChainID)
		}
		// order_sequence is NOT checked for zero (#324): zero is the first order
		// of every session, not an unset field. Keeper creates StreamState without
		// assigning NextExpectedSequence and requires each order to equal it
		// exactly, so 0 is the only legal opening value. Nothing is lost by
		// dropping the check: task_id is derived from (session_id, order_sequence),
		// so an order claiming a different sequence fails the task identity check
		// the caller runs against the subject placeholder.
		if facts.SessionID == "" || facts.ModelID == "" || facts.ProfileVersion == 0 || facts.OrderExpireHeight == 0 {
			return codec.Hash{}, nodewire.TaskOrderFacts{}, nil, fmt.Errorf("OrderBroadcast signed order lacks authoritative fields")
		}
		if facts.SignatureScheme == "" || facts.UserSignature == "" {
			return codec.Hash{}, nodewire.TaskOrderFacts{}, nil, fmt.Errorf("OrderBroadcast signed order lacks the user signature")
		}
	}
	return taskHash, facts, signedOrderBytes, nil
}

// decodeHash32Hex reads a 32-byte commitment in the lowercase hex spelling the
// bus payloads use for them (§5.6 infer_receipt_hash). Uppercase is refused
// rather than folded: the same value must have one spelling, or two frames that
// differ only in case would both be accepted while canonicalising differently.
func decodeHash32Hex(value string) (codec.Hash, error) {
	if len(value) != hex.EncodedLen(len(codec.Hash{})) || value != strings.ToLower(value) {
		return codec.Hash{}, fmt.Errorf("must be 32-byte lowercase hex")
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return codec.Hash{}, fmt.Errorf("must be 32-byte lowercase hex")
	}
	var hash codec.Hash
	copy(hash[:], raw)
	if hash == (codec.Hash{}) {
		return codec.Hash{}, fmt.Errorf("must not be zero")
	}
	return hash, nil
}

type chainTip struct {
	height     uint64
	readable   bool
	configured bool
}

func (r *TaskRunner) currentChainTip(ctx context.Context) chainTip {
	if r.cfg.ChainStatus == nil {
		return chainTip{}
	}
	h, id, err := r.cfg.ChainStatus.ChainStatus(ctx)
	if err != nil || h == 0 || (strings.TrimSpace(r.cfg.ChainID) != "" && strings.TrimSpace(id) != strings.TrimSpace(r.cfg.ChainID)) {
		return chainTip{configured: true}
	}
	return chainTip{height: h, readable: true, configured: true}
}

func resolveSigningIdentity(cfg TaskRunnerConfig, fallback string) (string, string) {
	if cfg.ServiceIdentity != nil {
		return cfg.ServiceIdentity()
	}
	return firstNonEmpty(cfg.SignerAddress, fallback), cfg.SignerPubkey
}

// resolveWorkloadTx answers the same question resolveSigningIdentity does, for
// the tx client instead of the signer address: the value captured in the config
// was read before workload activation, so a provider is preferred whenever one
// is wired.
func resolveWorkloadTx(cfg TaskRunnerConfig) txclient.Client {
	if cfg.TxProvider != nil {
		if client := cfg.TxProvider(); client != nil {
			return client
		}
	}
	return cfg.Tx
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

package worker

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// The seam is the only place per-task Builder authority is read, so swapping the
// provider must move relay, upload and confirmation verification to the Builder
// it names, without any Worker change. This is what TrueOpen/node#92 will do for
// real when selected_task_builders replaces the assignment field.
func TestReceivingBuilderProviderRedirectsRelayUploadAndConfirmation(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	otherPrivate := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x53}, 32))
	otherPubkey := hex.EncodeToString(otherPrivate.PubKey().SerializeCompressed())
	// The alternative Builder holds the task under the same identity, and signs
	// its own storage confirmation.
	h.taskData.builderPrivate = otherPrivate
	var seen []ReceivingBuilderRef
	h.worker.cfg.ReceivingBuilder = ReceivingBuilderFunc(func(_ context.Context, task ReceivingBuilderRef) (BuilderEndpoint, error) {
		seen = append(seen, task)
		return BuilderEndpoint{
			OperatorAddress: "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe", Endpoint: "https://other-builder.example",
			ServicePubkey: otherPubkey, CurrentHeight: 100, AuthorizationNonce: 1,
		}, nil
	})
	// prepareOutput still cannot populate the frozen receipt - the locked
	// Profile's evidence_schema_hash has no reader - so the relay path is reached
	// through the durable prepared-output checkpoint a previous process would have
	// left behind.
	h.seedPreparedOutput(t, event)

	if _, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatalf("HandleAssignmentFinalized: %v", err)
	}

	if len(seen) == 0 {
		t.Fatalf("the receiving-Builder provider was never asked")
	}
	for _, task := range seen {
		if task.TaskID != event.TaskID || task.SessionID != event.SessionID ||
			task.AssignedBuilderOperator != event.BuilderOperatorAddress {
			t.Fatalf("provider ref = %+v, want the finalized task identity", task)
		}
	}
	// One receipt relay, five object uploads, and one finalization per bundle.
	if len(h.taskData.endpoints) != 8 {
		t.Fatalf("task-data endpoints = %v, want relay, five uploads and two finalizes", h.taskData.endpoints)
	}
	for _, endpoint := range h.taskData.endpoints {
		if endpoint != "https://other-builder.example" {
			t.Fatalf("task-data endpoint = %q, want the provider's endpoint", endpoint)
		}
	}
	if len(h.taskData.relays) != 1 || h.taskData.FinalizedTaskResults[0].Auth.BuilderAddress != "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe" {
		t.Fatalf("relay auth Builder = %+v, want the provider's Builder", h.taskData.relays)
	}
	if len(h.taskData.uploads) != 5 {
		t.Fatalf("uploads = %+v, want the OUTPUT object and both evidence artifacts", h.taskData.uploads)
	}
	for _, upload := range h.taskData.uploads {
		if upload.Auth.BuilderAddress != "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe" {
			t.Fatalf("upload auth Builder = %+v, want the provider's Builder", h.taskData.uploads)
		}
	}
	if len(h.persistence.confirmations) != 3 {
		t.Fatalf("confirmations = %#v, want one verified confirmation per uploaded object", h.persistence.confirmations)
	}
	confirmation := h.persistence.confirmations[0]
	if confirmation.BuilderOperator != "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe" || confirmation.BuilderServicePubkey != otherPubkey {
		t.Fatalf("confirmation = %+v, want it verified against the provider's Builder key", confirmation)
	}
}

// Whatever names the receiving Builder, the Worker refuses to relay against an
// identity it cannot use: no endpoint, no service key, or no pinned height.
func TestWorkerFailsClosedOnIncompleteResolvedBuilderIdentity(t *testing.T) {
	complete := BuilderEndpoint{
		OperatorAddress: "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut", Endpoint: "https://builder.example",
		ServicePubkey: "02" + strings.Repeat("ab", 32), CurrentHeight: 100, AuthorizationNonce: 1,
	}
	for name, mutate := range map[string]func(*BuilderEndpoint){
		"no operator":       func(e *BuilderEndpoint) { e.OperatorAddress = "" },
		"padded operator":   func(e *BuilderEndpoint) { e.OperatorAddress = " trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut " },
		"no endpoint":       func(e *BuilderEndpoint) { e.Endpoint = "" },
		"no service pubkey": func(e *BuilderEndpoint) { e.ServicePubkey = "" },
		"unpinned height":   func(e *BuilderEndpoint) { e.CurrentHeight = 0 },
		"nothing at all":    func(e *BuilderEndpoint) { *e = BuilderEndpoint{} },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			event := finalizedTask()
			h.seedPreparedOutput(t, event)
			endpoint := complete
			mutate(&endpoint)
			h.worker.cfg.ReceivingBuilder = ReceivingBuilderFunc(func(context.Context, ReceivingBuilderRef) (BuilderEndpoint, error) {
				return endpoint, nil
			})

			_, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event)
			if err == nil || !strings.Contains(err.Error(), "resolved receiving Builder identity is incomplete or mismatched") {
				t.Fatalf("err = %v, want a fail-closed receiving Builder identity", err)
			}
			if len(h.taskData.relays) != 0 || len(h.taskData.uploads) != 0 {
				t.Fatalf("relays=%d uploads=%d, want no task-data RPC on an unusable Builder identity",
					len(h.taskData.relays), len(h.taskData.uploads))
			}
		})
	}
}

// A provider failure is a relay failure: a Builder whose descriptor is missing or
// unverifiable never receives task material.
func TestWorkerFailsClosedWhenTheProviderRefuses(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	h.seedPreparedOutput(t, event)
	h.worker.cfg.ReceivingBuilder = ReceivingBuilderFunc(func(context.Context, ReceivingBuilderRef) (BuilderEndpoint, error) {
		return BuilderEndpoint{}, errors.New("no service descriptor and no configured bootstrap endpoint")
	})

	_, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event)
	if err == nil || !strings.Contains(err.Error(), "no service descriptor") {
		t.Fatalf("err = %v, want the provider failure to stop the relay", err)
	}
	if len(h.taskData.relays) != 0 || len(h.taskData.uploads) != 0 {
		t.Fatalf("relays=%d uploads=%d, want no task-data RPC without a resolved Builder",
			len(h.taskData.relays), len(h.taskData.uploads))
	}
}

func TestWorkerRequiresAReceivingBuilderProvider(t *testing.T) {
	h := newHarness(t)
	h.worker.cfg.ReceivingBuilder = nil

	_, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), finalizedTask())
	if err == nil || !strings.Contains(err.Error(), "receiving Builder provider is required") {
		t.Fatalf("err = %v, want a missing provider to fail closed", err)
	}
}

// The durable-recovery pass skips prepareOutput's precheck, so the seam carries
// its own guard: a resumed task with no provider must fail before any RPC rather
// than dereference a missing dependency.
func TestResumedWorkerRequiresAReceivingBuilderProvider(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	h.seedPreparedOutput(t, event)
	// Verify the durable artifacts are present.
	if _, err := h.persistence.ReadArtifact(context.Background(), event.TaskID, "worker-output"); err != nil {
		t.Fatalf("prepared output was not persisted: %v", err)
	}
	relays, uploads := len(h.taskData.relays), len(h.taskData.uploads)

	resumed := New(h.worker.cfg)
	resumed.cfg.ReceivingBuilder = nil
	_, err := resumed.HandleAssignmentFinalized(context.Background(), event)
	if err == nil || !strings.Contains(err.Error(), "receiving Builder provider is required") {
		t.Fatalf("resumed error = %v, want a missing provider to fail closed", err)
	}
	if len(h.taskData.relays) != relays || len(h.taskData.uploads) != uploads {
		t.Fatalf("relays=%d uploads=%d, want no task-data RPC without a provider",
			len(h.taskData.relays), len(h.taskData.uploads))
	}
}

// refreshingProvider simulates the daemon-side resolver: Resolve gives the cached
// fingerprint, Refresh the latest on-chain one.
type refreshingProvider struct {
	cached, fresh BuilderEndpoint
	refreshes     int
}

func (p *refreshingProvider) ResolveReceivingBuilder(context.Context, ReceivingBuilderRef) (BuilderEndpoint, error) {
	return p.cached, nil
}

func (p *refreshingProvider) ResolveReceivingBuilders(context.Context, ReceivingBuilderRef) ([]BuilderEndpoint, error) {
	return []BuilderEndpoint{p.cached}, nil
}

func (p *refreshingProvider) RefreshReceivingBuilder(context.Context, ReceivingBuilderRef) (BuilderEndpoint, error) {
	p.refreshes++
	p.cached = p.fresh
	return p.fresh, nil
}

// The Builder changed certificates and the locally cached fingerprint is stale: the
// relay reports a fingerprint mismatch -> re-read the descriptor -> resend once with
// the new fingerprint; the upload uses the new fingerprint directly.
func TestRelayRetriesOnceWithTheRefreshedTLSPin(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	// The harness's default Builder identity (its service public key has to verify the
	// storage confirmation's signature), with only the fingerprint changed.
	base, err := h.worker.cfg.ReceivingBuilder.ResolveReceivingBuilder(context.Background(), ReceivingBuilderRef{})
	if err != nil {
		t.Fatalf("default receiving Builder: %v", err)
	}
	stale, fresh := base, base
	stale.TLSPubkeyHash = strings.Repeat("aa", 32)
	fresh.TLSPubkeyHash = strings.Repeat("bb", 32)
	provider := &refreshingProvider{cached: stale, fresh: fresh}
	h.worker.cfg.ReceivingBuilder = provider
	h.taskData.relayErrors = []error{fmt.Errorf("dial: %w", builderclient.ErrTLSPubkeyMismatch)}
	h.seedPreparedOutput(t, event)

	if _, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatalf("HandleAssignmentFinalized: %v", err)
	}
	if provider.refreshes != 1 {
		t.Fatalf("refreshes = %d, want 1", provider.refreshes)
	}
	// relay(stale), relay(fresh), then all object uploads and finalize on the fresh pin.
	want := []string{
		stale.TLSPubkeyHash, fresh.TLSPubkeyHash,
		fresh.TLSPubkeyHash, fresh.TLSPubkeyHash, fresh.TLSPubkeyHash,
		fresh.TLSPubkeyHash, fresh.TLSPubkeyHash,
		fresh.TLSPubkeyHash, fresh.TLSPubkeyHash,
	}
	if len(h.taskData.pins) != len(want) {
		t.Fatalf("pins = %v, want stale relay then fresh relay, five uploads and two finalizes", h.taskData.pins)
	}
	for i := range want {
		if h.taskData.pins[i] != want[i] {
			t.Fatalf("pins = %v, want %v", h.taskData.pins, want)
		}
	}
}

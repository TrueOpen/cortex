package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
)

type staticKeeperIdentityReader struct {
	params     chainclient.ParamsSnapshot
	node       chainclient.CortexNodeSnapshot
	bond       chainclient.ServiceBondSnapshot
	key        chainclient.ServiceKeySnapshot
	capability chainclient.ModelCapabilitySnapshot
	support    chainclient.ModelSupportSnapshot
}

func (r staticKeeperIdentityReader) Params(context.Context) (chainclient.ParamsSnapshot, error) {
	return r.params, nil
}

func (r staticKeeperIdentityReader) CortexNode(context.Context, string) (chainclient.CortexNodeSnapshot, error) {
	return r.node, nil
}

func (r staticKeeperIdentityReader) ServiceBond(context.Context, string) (chainclient.ServiceBondSnapshot, error) {
	return r.bond, nil
}

func (r staticKeeperIdentityReader) CurrentServiceKey(context.Context, string, string, uint64) (chainclient.ServiceKeySnapshot, error) {
	return r.key, nil
}

// staticKeeperIdentityServedHeight is the height the fake application has
// committed, so committed reads are served from it.
const staticKeeperIdentityServedHeight = uint64(200)

func (r staticKeeperIdentityReader) CommittedCurrentServiceKey(context.Context, string, string) (chainclient.ServiceKeySnapshot, uint64, error) {
	return r.key, staticKeeperIdentityServedHeight, nil
}

func (r staticKeeperIdentityReader) ModelCapability(_ context.Context, nodeID, modelID, profile string) (chainclient.ModelCapabilitySnapshot, error) {
	result := r.capability
	result.OperatorAddress = nodeID
	result.ModelID = modelID
	result.ProfileVersion = chainclient.NewProfileVersion(1)
	return result, nil
}

func (r staticKeeperIdentityReader) ModelSupport(_ context.Context, nodeID, modelID, profile string) (chainclient.ModelSupportSnapshot, error) {
	result := r.support
	result.OperatorAddress = nodeID
	result.ModelID = modelID
	result.ProfileVersion = chainclient.NewProfileVersion(1)
	return result, nil
}

// ChainHeight answers the Keeper liveness probe only; it is never a query height.
func (r staticKeeperIdentityReader) ChainHeight(context.Context) (uint64, error) {
	return staticKeeperIdentityServedHeight, nil
}

func (r staticKeeperIdentityReader) Task(context.Context, string, string) (chainclient.TaskSnapshot, error) {
	return chainclient.TaskSnapshot{}, nil
}

type staticChainStatusReader struct {
	height  uint64
	chainID string
}

func (r staticChainStatusReader) ChainStatus(context.Context) (uint64, string, error) {
	return r.height, r.chainID, nil
}

func TestCheckKeeperIdentityAcceptsActiveStableNodeAndDutySupport(t *testing.T) {
	identity := readyLocalIdentity()
	reader := readyKeeperIdentityReader()

	if _, err := checkKeeperIdentity(context.Background(), identity, reader, 200); err != nil {
		t.Fatalf("checkKeeperIdentity() error = %v", err)
	}
}

func TestCheckKeeperCoreIdentityDoesNotRequireModelSupport(t *testing.T) {
	reader := readyKeeperIdentityReader()
	reader.support.DeclaredSupport = false

	serviceAddress, err := checkKeeperCoreIdentity(context.Background(), readyLocalIdentity(), reader, 200)
	if err != nil {
		t.Fatalf("checkKeeperCoreIdentity() error = %v", err)
	}
	if serviceAddress != reader.key.ServiceAddress {
		t.Fatalf("service address = %q, want %q", serviceAddress, reader.key.ServiceAddress)
	}
}

func TestCheckKeeperModelReadinessIsIndependentFromCoreIdentity(t *testing.T) {
	reader := readyKeeperIdentityReader()
	reader.node.Status = "JAILED"

	if err := checkKeeperModelReadiness(context.Background(), readyLocalIdentity(), reader); err != nil {
		t.Fatalf("checkKeeperModelReadiness() error = %v", err)
	}
}

func TestCheckKeeperModelReadinessQueriesEachProfileOnceAcrossDuties(t *testing.T) {
	reader := &countingKeeperIdentityReader{staticKeeperIdentityReader: readyKeeperIdentityReader()}

	if err := checkKeeperModelReadiness(context.Background(), readyLocalIdentity(), reader); err != nil {
		t.Fatalf("checkKeeperModelReadiness() error = %v", err)
	}
	if reader.capabilityQueries != 1 || reader.supportQueries != 1 {
		t.Fatalf("model readiness queries = capability %d support %d, want one each", reader.capabilityQueries, reader.supportQueries)
	}
}

// Duty selection is retired, so a node declares support for a profile as both a
// Worker and a Verifier. Either capability missing from the Keeper record now
// describes a declaration this binary cannot make, and readiness refuses -- the
// checks are no longer conditional on anything in the config.
func TestCheckKeeperModelReadinessRequiresBothCapabilities(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*chainclient.ModelCapabilitySnapshot)
		wantText string
	}{
		{name: "inference required", mutate: func(c *chainclient.ModelCapabilitySnapshot) { c.InferenceCapability = false }, wantText: "WORKER inference"},
		{name: "verification required", mutate: func(c *chainclient.ModelCapabilitySnapshot) { c.VerificationCapability = false }, wantText: "VERIFIER verification"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := readyKeeperIdentityReader()
			tt.mutate(&reader.capability)
			if err := checkKeeperModelReadiness(context.Background(), readyLocalIdentity(), reader); err == nil || !strings.Contains(err.Error(), tt.wantText) {
				t.Fatalf("checkKeeperModelReadiness() error = %v, want %q", err, tt.wantText)
			}
		})
	}
}

type countingKeeperIdentityReader struct {
	staticKeeperIdentityReader
	capabilityQueries int
	supportQueries    int
}

func (r *countingKeeperIdentityReader) ModelCapability(ctx context.Context, nodeID, modelID, profile string) (chainclient.ModelCapabilitySnapshot, error) {
	r.capabilityQueries++
	return r.staticKeeperIdentityReader.ModelCapability(ctx, nodeID, modelID, profile)
}

func (r *countingKeeperIdentityReader) ModelSupport(ctx context.Context, nodeID, modelID, profile string) (chainclient.ModelSupportSnapshot, error) {
	r.supportQueries++
	return r.staticKeeperIdentityReader.ModelSupport(ctx, nodeID, modelID, profile)
}

func TestCheckKeeperIdentityRejectsMismatches(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*staticKeeperIdentityReader)
		want string
	}{
		{name: "params", mut: func(r *staticKeeperIdentityReader) { r.params.ServiceUnbondingPeriodBlocks = 0 }, want: "params"},
		{name: "daily support window", mut: func(r *staticKeeperIdentityReader) { r.params.DailySupportWindowBlocks = 0 }, want: "params"},
		{name: "operator", mut: func(r *staticKeeperIdentityReader) { r.node.OperatorAddress = "trueopen1other" }, want: "operator"},
		{name: "node status", mut: func(r *staticKeeperIdentityReader) { r.node.Status = "JAILED" }, want: "node status"},
		{name: "retired node status", mut: func(r *staticKeeperIdentityReader) { r.node.Status = "REGISTERED" }, want: "node status"},
		{name: "key descriptor version", mut: func(r *staticKeeperIdentityReader) { r.key.CurrentDescriptorVersion = 1 }, want: "binding disagree"},
		{name: "bond status", mut: func(r *staticKeeperIdentityReader) { r.bond.Status = "UNBONDING" }, want: "bond status"},
		{name: "pending key", mut: func(r *staticKeeperIdentityReader) { r.key.Status = "PENDING" }, want: "key status"},
		{name: "invalid key", mut: func(r *staticKeeperIdentityReader) { r.key.ServicePubkey = "02AA" }, want: "public key"},
		{name: "missing key nonce", mut: func(r *staticKeeperIdentityReader) { r.key.AuthorizationNonce = 0 }, want: "authorization nonce"},
		{name: "revoked key", mut: func(r *staticKeeperIdentityReader) { r.key.RevokedHeight = chainclient.Uint64String(199) }, want: "revoked"},
		{name: "binding mismatch", mut: func(r *staticKeeperIdentityReader) { r.node.CurrentServiceAddress = "trueopen1other" }, want: "binding disagree"},
		{name: "capability version", mut: func(r *staticKeeperIdentityReader) { r.capability.CapabilityVersion = 0 }, want: "capability version"},
		{name: "model support declaration", mut: func(r *staticKeeperIdentityReader) { r.support.DeclaredSupport = false }, want: "model support"},
		{name: "model support version", mut: func(r *staticKeeperIdentityReader) { r.support.SupportVersion = 0 }, want: "support version"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := readyKeeperIdentityReader()
			tt.mut(&reader)
			_, err := checkKeeperIdentity(context.Background(), readyLocalIdentity(), reader, 200)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("checkKeeperIdentity() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestCheckKeeperIdentityAllowsDeclaredColdStartSupport(t *testing.T) {
	reader := readyKeeperIdentityReader()
	reader.node.Status = "ACTIVE"
	reader.support.SupportActive = false

	serviceAddress, err := checkKeeperIdentity(context.Background(), readyLocalIdentity(), reader, 200)
	if err != nil {
		t.Fatalf("checkKeeperIdentity() error = %v, want cold-start declared support accepted", err)
	}
	if serviceAddress != reader.key.ServiceAddress {
		t.Fatalf("service address = %q, want %q", serviceAddress, reader.key.ServiceAddress)
	}
}

func readyLocalIdentity() config.LocalIdentityConfig {
	return config.LocalIdentityConfig{
		OperatorAddress:        "trueopen1operator",
		ServiceKeyRef:          "kms://cortex/service-key",
		SupportedModelProfiles: []string{"llama-dev@1=llm_text_v1"},
		ModelServiceID:         "model-service",
	}
}

// Matched public pair from Node 6779581's Ethereum localnet seed. Runtime
// construction verifies that the key derives its published service address.
const (
	readyServicePubkey  = "0298c2da175fd3063bd2e8156303b98a0f77df43c5ca078eaa08dc2533e829f507"
	readyServiceAddress = "trueopen1j5me037hs26kmqz7xy6s5f0y224trsphlqjfd2"
)

func readyKeeperIdentityReader() staticKeeperIdentityReader {
	return staticKeeperIdentityReader{
		params: chainclient.ParamsSnapshot{ServiceUnbondingPeriodBlocks: 100, DailySupportWindowBlocks: 30},
		node: chainclient.CortexNodeSnapshot{
			OperatorAddress:       "trueopen1operator",
			CurrentServiceAddress: readyServiceAddress,
			CurrentServicePubkey:  readyServicePubkey,
			AuthorizationNonce:    chainclient.Uint64String(1),
			Status:                "ACTIVE",
		},
		bond: chainclient.ServiceBondSnapshot{
			OperatorAddress: "trueopen1operator",
			ActiveBond:      chainclient.Uint64String(500000),
			BondVersion:     chainclient.Uint64String(1),
			Status:          "ACTIVE",
		},
		key: chainclient.ServiceKeySnapshot{
			ParticipantType:    "CORTEX_NODE",
			OperatorAddress:    "trueopen1operator",
			ServiceAddress:     readyServiceAddress,
			ServicePubkey:      readyServicePubkey,
			AuthorizationNonce: chainclient.Uint64String(1),
			Status:             "ACTIVE",
		},
		capability: chainclient.ModelCapabilitySnapshot{
			InferenceCapability: true, VerificationCapability: true, CapabilityVersion: chainclient.Uint64String(1),
		},
		support: chainclient.ModelSupportSnapshot{
			DeclaredSupport: true,
			SupportActive:   true,
			SupportVersion:  chainclient.Uint64String(1),
		},
	}
}

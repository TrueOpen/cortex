package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/identity"
	"github.com/SingaXYZ/cortex/internal/modelservice"
	"github.com/SingaXYZ/cortex/internal/policy"
)

func TestKeeperHandraiseEligibilityUsesAuthoritativeSingleNodeFacts(t *testing.T) {
	keeper := activeHandraiseKeeper()
	model := handraiseCapacityModel{
		Client:   modelservice.NewFakeService(),
		snapshot: modelservice.ResourceSnapshot{LoadedModels: 1, QueueDepth: 2, MaxConcurrency: 4},
	}
	resolver := NewKeeperHandraiseEligibility(KeeperHandraiseEligibilityConfig{
		ChainStatus: handraiseChainStatus{height: 120, chainID: "chain-A"}, Keeper: keeper, Model: model,
		ChainID: "chain-A", OperatorAddress: "cortex-node-1", ModelServiceID: "fake-model-service",
		VerifyDeadlineDelta: 30, SelfRescueGasBudget: 10,
	})

	workerInput, expires, err := resolver.Worker(context.Background(), WorkerHandraiseCandidate{
		TaskID: identity.TaskIDString("84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", 1), SessionID: "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", OrderSequence: 1, ModelID: "fake-llm-text",
		ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1, DeadlineHeight: 140,
	})
	if err != nil {
		t.Fatalf("Worker eligibility error = %v", err)
	}
	if !policy.EvaluateWorkerPrecheck(workerInput).Accepted || workerInput.CurrentHeight != 120 || workerInput.SupportFreshnessWindow != 30 || workerInput.AvailableSlots != 2 || expires != 140 ||
		!strings.Contains(workerInput.CapacitySnapshotRef, "queue:2:max:4:available:2") {
		t.Fatalf("Worker eligibility = %#v expires=%d", workerInput, expires)
	}

	verifierInput, err := resolver.Verifier(context.Background(), VerifierHandraiseCandidate{
		TaskID: "task-2", SessionID: "session-2", ModelID: "fake-llm-text", ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1, WorkerAddress: "remote-node", OpenHeight: 115,
	})
	if err != nil {
		t.Fatalf("Verifier eligibility error = %v", err)
	}
	if verifierInput.CurrentHeight != 120 || verifierInput.SupportFreshnessWindow != 30 || verifierInput.VerifyDeadlineHeight != 145 || verifierInput.AvailableSlots != 2 {
		t.Fatalf("Verifier eligibility = %#v", verifierInput)
	}
}

func TestKeeperHandraiseEligibilityRejectsMissingOrExhaustedModelCapacity(t *testing.T) {
	for _, test := range []struct {
		name     string
		snapshot modelservice.ResourceSnapshot
	}{
		{name: "missing max concurrency", snapshot: modelservice.ResourceSnapshot{LoadedModels: 1}},
		{name: "exhausted", snapshot: modelservice.ResourceSnapshot{LoadedModels: 1, QueueDepth: 2, MaxConcurrency: 2}},
		{name: "queue exceeds max", snapshot: modelservice.ResourceSnapshot{LoadedModels: 1, QueueDepth: 3, MaxConcurrency: 2}},
	} {
		t.Run(test.name, func(t *testing.T) {
			model := handraiseCapacityModel{Client: modelservice.NewFakeService(), snapshot: test.snapshot}
			resolver := NewKeeperHandraiseEligibility(KeeperHandraiseEligibilityConfig{
				ChainStatus: handraiseChainStatus{height: 120, chainID: "chain-A"},
				Keeper:      activeHandraiseKeeper(),
				Model:       model, ChainID: "chain-A", OperatorAddress: "cortex-node-1", ModelServiceID: "fake-model-service",
				SelfRescueGasBudget: 10,
			})
			if _, _, err := resolver.Worker(context.Background(), WorkerHandraiseCandidate{
				TaskID: identity.TaskIDString("84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", 1), SessionID: "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", OrderSequence: 1,
				ModelID: "fake-llm-text", ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1, DeadlineHeight: 140,
			}); err == nil {
				t.Fatal("Worker eligibility accepted unavailable model capacity")
			}
			if _, err := resolver.Verifier(context.Background(), VerifierHandraiseCandidate{
				TaskID: "task-2", SessionID: "session-2", ModelID: "fake-llm-text", ProfileVersion: 1,
				Capability: modelservice.CapabilityLLMTextV1, WorkerAddress: "remote-node", OpenHeight: 115,
			}); err == nil {
				t.Fatal("Verifier eligibility accepted unavailable model capacity")
			}
		})
	}
}

type handraiseCapacityModel struct {
	modelservice.Client
	snapshot modelservice.ResourceSnapshot
}

func (m handraiseCapacityModel) ListCapabilities(ctx context.Context, req modelservice.ListCapabilitiesRequest) (modelservice.ListCapabilitiesResponse, error) {
	response, err := m.Client.ListCapabilities(ctx, req)
	response.ResourceSnapshot = m.snapshot
	return response, err
}

func TestKeeperHandraiseEligibilityRejectsInactiveSupport(t *testing.T) {
	support := activeHandraiseSupport()
	support.SupportActive = false
	support.DeclaredSupport = false
	keeper := activeHandraiseKeeper()
	keeper.support = support
	resolver := NewKeeperHandraiseEligibility(KeeperHandraiseEligibilityConfig{
		ChainStatus: handraiseChainStatus{height: 120, chainID: "chain-A"}, Keeper: keeper, Model: modelservice.NewFakeService(),
		ChainID: "chain-A", OperatorAddress: "cortex-node-1", ModelServiceID: "fake-model-service", SelfRescueGasBudget: 10,
	})
	if _, _, err := resolver.Worker(context.Background(), WorkerHandraiseCandidate{TaskID: identity.TaskIDString("84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", 1), SessionID: "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", OrderSequence: 1, ModelID: "fake-llm-text", ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1, DeadlineHeight: 140}); err == nil {
		t.Fatal("Worker eligibility accepted inactive Keeper support")
	}
}

func TestKeeperHandraiseEligibilityUsesAuthoritativeSupportFreshness(t *testing.T) {
	worker := WorkerHandraiseCandidate{
		TaskID: identity.TaskIDString("84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", 1), SessionID: "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", OrderSequence: 1,
		ModelID: "fake-llm-text", ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1, DeadlineHeight: 140,
	}
	verifier := VerifierHandraiseCandidate{
		TaskID: "task-2", SessionID: "session-2", ModelID: "fake-llm-text", ProfileVersion: 1,
		Capability: modelservice.CapabilityLLMTextV1, WorkerAddress: "remote-node", OpenHeight: 115,
	}

	for _, test := range []struct {
		name   string
		keeper handraiseKeeper
		wantOK bool
	}{
		{name: "inclusive boundary", keeper: func() handraiseKeeper {
			keeper := activeHandraiseKeeper()
			keeper.support.LastRefreshHeight = chainclient.NewUint64String(90)
			return keeper
		}(), wantOK: true},
		{name: "missing window", keeper: func() handraiseKeeper {
			keeper := activeHandraiseKeeper()
			keeper.params.DailySupportWindowBlocks = chainclient.NewUint64String(0)
			return keeper
		}()},
		{name: "missing refresh height", keeper: func() handraiseKeeper {
			keeper := activeHandraiseKeeper()
			keeper.support.LastRefreshHeight = chainclient.NewUint64String(0)
			return keeper
		}()},
		{name: "future refresh height", keeper: func() handraiseKeeper {
			keeper := activeHandraiseKeeper()
			keeper.support.LastRefreshHeight = chainclient.NewUint64String(121)
			return keeper
		}()},
		{name: "stale refresh height", keeper: func() handraiseKeeper {
			keeper := activeHandraiseKeeper()
			keeper.support.LastRefreshHeight = chainclient.NewUint64String(89)
			return keeper
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := NewKeeperHandraiseEligibility(KeeperHandraiseEligibilityConfig{
				ChainStatus: handraiseChainStatus{height: 120, chainID: "chain-A"}, Keeper: test.keeper, Model: modelservice.NewFakeService(),
				ChainID: "chain-A", OperatorAddress: "cortex-node-1", ModelServiceID: "fake-model-service", SelfRescueGasBudget: 10,
			})
			workerInput, _, workerErr := resolver.Worker(context.Background(), worker)
			verifierInput, verifierErr := resolver.Verifier(context.Background(), verifier)
			if test.wantOK {
				if workerErr != nil || verifierErr != nil || workerInput.SupportFreshnessWindow != 30 || verifierInput.SupportFreshnessWindow != 30 {
					t.Fatalf("boundary worker = %#v err=%v, verifier = %#v err=%v", workerInput, workerErr, verifierInput, verifierErr)
				}
				return
			}
			if workerErr == nil || verifierErr == nil {
				t.Fatalf("stale facts accepted: worker err=%v verifier err=%v", workerErr, verifierErr)
			}
		})
	}
}

func TestKeeperHandraiseEligibilityAllowsCurrentNodeColdStart(t *testing.T) {
	keeper := activeHandraiseKeeper()
	keeper.projection.Model.Status = "REGISTERED"
	keeper.projection.Profile.Status = "REGISTERED"
	keeper.support.SupportActive = false
	keeper.support.ActiveSupportStakeSnapshot = chainclient.NewUint64String(0)
	resolver := NewKeeperHandraiseEligibility(KeeperHandraiseEligibilityConfig{
		ChainStatus: handraiseChainStatus{height: 120, chainID: "chain-A"}, Keeper: keeper, Model: modelservice.NewFakeService(),
		ChainID: "chain-A", OperatorAddress: "cortex-node-1", ModelServiceID: "fake-model-service", SelfRescueGasBudget: 10,
	})
	workerInput, _, workerErr := resolver.Worker(context.Background(), WorkerHandraiseCandidate{
		TaskID: identity.TaskIDString("84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", 1), SessionID: "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", OrderSequence: 1,
		ModelID: "fake-llm-text", ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1, DeadlineHeight: 140,
	})
	verifierInput, verifierErr := resolver.Verifier(context.Background(), VerifierHandraiseCandidate{
		TaskID: "task-2", SessionID: "session-2", ModelID: "fake-llm-text", ProfileVersion: 1,
		Capability: modelservice.CapabilityLLMTextV1, WorkerAddress: "remote-node", OpenHeight: 115,
	})
	if workerErr != nil || verifierErr != nil || workerInput.SupportState != policy.SupportDeclaredBootstrap || !workerInput.P30ColdStartCandidate || !workerInput.RewardEligible || verifierInput.SupportState != policy.SupportDeclaredBootstrap {
		t.Fatalf("cold-start worker = %#v err=%v, verifier = %#v err=%v", workerInput, workerErr, verifierInput, verifierErr)
	}
	if decision := policy.EvaluateWorkerPrecheck(workerInput); !decision.Accepted {
		t.Fatalf("cold-start Worker policy rejected current Node eligibility: %#v", decision)
	}
}

func TestKeeperHandraiseEligibilityRejectsCurrentNodeAdmissionMismatches(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*handraiseKeeper)
	}{
		{name: "inactive support for active profile", mutate: func(keeper *handraiseKeeper) {
			keeper.support.SupportActive = false
		}},
		{name: "paused model", mutate: func(keeper *handraiseKeeper) { keeper.projection.Model.Status = "PAUSED" }},
		{name: "paused profile", mutate: func(keeper *handraiseKeeper) { keeper.projection.Profile.Status = "PAUSED" }},
		{name: "profile identity", mutate: func(keeper *handraiseKeeper) {
			keeper.projection.Profile.ProfileVersion = chainclient.NewProfileVersion(2)
		}},
		{name: "node status", mutate: func(keeper *handraiseKeeper) { keeper.node.Status = "TOMBSTONED" }},
		{name: "bond status", mutate: func(keeper *handraiseKeeper) { keeper.bond.Status = "UNBONDING" }},
		{name: "bond below min stake", mutate: func(keeper *handraiseKeeper) { keeper.bond.ActiveBond = chainclient.NewUint64String(49) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			keeper := activeHandraiseKeeper()
			test.mutate(&keeper)
			resolver := NewKeeperHandraiseEligibility(KeeperHandraiseEligibilityConfig{
				ChainStatus: handraiseChainStatus{height: 120, chainID: "chain-A"}, Keeper: keeper, Model: modelservice.NewFakeService(),
				ChainID: "chain-A", OperatorAddress: "cortex-node-1", ModelServiceID: "fake-model-service", SelfRescueGasBudget: 10,
			})
			_, _, workerErr := resolver.Worker(context.Background(), WorkerHandraiseCandidate{
				TaskID: identity.TaskIDString("84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", 1), SessionID: "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", OrderSequence: 1,
				ModelID: "fake-llm-text", ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1, DeadlineHeight: 140,
			})
			_, verifierErr := resolver.Verifier(context.Background(), VerifierHandraiseCandidate{
				TaskID: "task-2", SessionID: "session-2", ModelID: "fake-llm-text", ProfileVersion: 1,
				Capability: modelservice.CapabilityLLMTextV1, WorkerAddress: "remote-node", OpenHeight: 115,
			})
			if workerErr == nil || verifierErr == nil {
				t.Fatalf("admission mismatch accepted: worker err=%v verifier err=%v", workerErr, verifierErr)
			}
		})
	}
}

func TestKeeperHandraiseEligibilityRejectsExpiredWorkerDeadline(t *testing.T) {
	resolver := NewKeeperHandraiseEligibility(KeeperHandraiseEligibilityConfig{
		ChainStatus: handraiseChainStatus{height: 120, chainID: "chain-A"}, Keeper: activeHandraiseKeeper(), Model: modelservice.NewFakeService(),
		ChainID: "chain-A", OperatorAddress: "cortex-node-1", ModelServiceID: "fake-model-service", SelfRescueGasBudget: 10,
	})
	_, _, err := resolver.Worker(context.Background(), WorkerHandraiseCandidate{
		TaskID: identity.TaskIDString("84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", 1), SessionID: "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", OrderSequence: 1, ModelID: "fake-llm-text",
		ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1, DeadlineHeight: 120,
	})
	if err == nil {
		t.Fatal("Worker eligibility accepted an expired deadline")
	}
}

func TestKeeperHandraiseEligibilityRejectsCapabilityDutyMismatch(t *testing.T) {
	workerOnly := activeHandraiseCapability()
	workerOnly.VerificationCapability = false
	verifierOnly := activeHandraiseCapability()
	verifierOnly.InferenceCapability = false

	workerResolver := NewKeeperHandraiseEligibility(KeeperHandraiseEligibilityConfig{
		ChainStatus: handraiseChainStatus{height: 120, chainID: "chain-A"}, Keeper: func() handraiseKeeper {
			keeper := activeHandraiseKeeper()
			keeper.capability = verifierOnly
			return keeper
		}(), Model: modelservice.NewFakeService(),
		ChainID: "chain-A", OperatorAddress: "cortex-node-1", ModelServiceID: "fake-model-service", SelfRescueGasBudget: 10,
	})
	if _, _, err := workerResolver.Worker(context.Background(), WorkerHandraiseCandidate{TaskID: identity.TaskIDString("84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", 1), SessionID: "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", OrderSequence: 1, ModelID: "fake-llm-text", ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1, DeadlineHeight: 140}); err == nil {
		t.Fatal("Worker eligibility accepted verifier-only Keeper capability")
	}

	verifierResolver := NewKeeperHandraiseEligibility(KeeperHandraiseEligibilityConfig{
		ChainStatus: handraiseChainStatus{height: 120, chainID: "chain-A"}, Keeper: func() handraiseKeeper {
			keeper := activeHandraiseKeeper()
			keeper.capability = workerOnly
			return keeper
		}(), Model: modelservice.NewFakeService(),
		ChainID: "chain-A", OperatorAddress: "cortex-node-1", ModelServiceID: "fake-model-service",
	})
	if _, err := verifierResolver.Verifier(context.Background(), VerifierHandraiseCandidate{TaskID: "task-2", SessionID: "session-2", ModelID: "fake-llm-text", ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1, WorkerAddress: "remote-node", OpenHeight: 115}); err == nil {
		t.Fatal("Verifier eligibility accepted worker-only Keeper capability")
	}
}

type handraiseChainStatus struct {
	height  uint64
	chainID string
}

func (s handraiseChainStatus) ChainStatus(context.Context) (uint64, string, error) {
	return s.height, s.chainID, nil
}

type handraiseKeeper struct {
	params     chainclient.ParamsSnapshot
	projection chainclient.CurrentModelProfileSnapshot
	node       chainclient.CortexNodeSnapshot
	bond       chainclient.ServiceBondSnapshot
	capability chainclient.ModelCapabilitySnapshot
	support    chainclient.ModelSupportSnapshot
}

func (k handraiseKeeper) Params(context.Context) (chainclient.ParamsSnapshot, error) {
	return k.params, nil
}

func (k handraiseKeeper) CurrentModelProfile(context.Context, string, string) (chainclient.CurrentModelProfileSnapshot, error) {
	return k.projection, nil
}

func (k handraiseKeeper) CortexNode(context.Context, string) (chainclient.CortexNodeSnapshot, error) {
	return k.node, nil
}

func (k handraiseKeeper) ServiceBond(context.Context, string) (chainclient.ServiceBondSnapshot, error) {
	return k.bond, nil
}

func (k handraiseKeeper) CurrentServiceKey(context.Context, string, string, uint64) (chainclient.ServiceKeySnapshot, error) {
	return chainclient.ServiceKeySnapshot{}, nil
}

func (k handraiseKeeper) ModelCapability(context.Context, string, string, string) (chainclient.ModelCapabilitySnapshot, error) {
	return k.capability, nil
}

func activeHandraiseCapability() chainclient.ModelCapabilitySnapshot {
	return chainclient.ModelCapabilitySnapshot{
		OperatorAddress: "cortex-node-1", ModelID: "fake-llm-text", ProfileVersion: chainclient.NewProfileVersion(1),
		InferenceCapability: true, VerificationCapability: true, CapabilityVersion: chainclient.NewUint64String(1),
	}
}

func (k handraiseKeeper) ModelSupport(context.Context, string, string, string) (chainclient.ModelSupportSnapshot, error) {
	return k.support, nil
}

func activeHandraiseSupport() chainclient.ModelSupportSnapshot {
	return chainclient.ModelSupportSnapshot{
		OperatorAddress: "cortex-node-1", ModelID: "fake-llm-text", ProfileVersion: chainclient.NewProfileVersion(1),
		DeclaredSupport: true, SupportActive: true, SupportVersion: chainclient.NewUint64String(1),
		LastRefreshHeight: chainclient.NewUint64String(119), ActiveSupportStakeSnapshot: chainclient.NewUint64String(100), EligibleSupportStakeSnapshot: chainclient.NewUint64String(100),
	}
}

func activeHandraiseParams() chainclient.ParamsSnapshot {
	return chainclient.ParamsSnapshot{DailySupportWindowBlocks: chainclient.NewUint64String(30)}
}

func activeHandraiseKeeper() handraiseKeeper {
	return handraiseKeeper{
		params: activeHandraiseParams(),
		projection: chainclient.CurrentModelProfileSnapshot{
			Model: chainclient.CurrentModelSnapshot{ModelID: "fake-llm-text", Status: "ACTIVE"},
			Profile: chainclient.CurrentProfileSnapshot{
				ModelID: "fake-llm-text", ProfileVersion: chainclient.NewProfileVersion(1), Status: "ACTIVE", MinStake: chainclient.NewUint64String(50),
			},
		},
		node: chainclient.CortexNodeSnapshot{
			OperatorAddress: "cortex-node-1", CurrentServiceAddress: "trueopen1service", CurrentServicePubkey: "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", AuthorizationNonce: chainclient.NewUint64String(1), Status: "ACTIVE",
		},
		bond: chainclient.ServiceBondSnapshot{
			OperatorAddress: "cortex-node-1", ActiveBond: chainclient.NewUint64String(100), BondVersion: chainclient.NewUint64String(1), Status: "ACTIVE",
		},
		capability: activeHandraiseCapability(),
		support:    activeHandraiseSupport(),
	}
}

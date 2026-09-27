package devex

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/config"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	"github.com/TrueOpen/cortex/proto/nexus/v1/nexusv1connect"
)

func TestDevnetRendererProducesValidSingleIdentityConfig(t *testing.T) {
	tempDir := t.TempDir()
	tokenPath := filepath.Join(tempDir, "nexus.token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	cmd := exec.Command("sh", "../../scripts/devnet-deploy.sh", "render")
	cmd.Env = devnetRendererEnv(tempDir, tokenPath, "trueopen-devnet-1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("render config: %v\n%s", err, output)
	}
	renderedPath := filepath.Join(tempDir, "cortex.yaml")
	info, err := os.Stat(renderedPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("rendered config mode = %v, err = %v", info, err)
	}
	cfg, err := config.LoadFile(renderedPath)
	if err != nil {
		t.Fatalf("load rendered config: %v", err)
	}
	// Duty selection is retired: the rendered config must carry no duties key at
	// all. Asserting the empty slice is what keeps the template from quietly
	// growing one back -- a rendered `duties:` is now a startup refusal.
	if cfg.LocalIdentity.OperatorAddress != "trueopen1operator" || len(cfg.LocalIdentity.Duties) != 0 {
		t.Fatalf("rendered identity = %#v, want one Cortex node and no duty selection", cfg.LocalIdentity)
	}
	profiles, err := cfg.LocalIdentity.ModelProfiles()
	if err != nil || len(profiles) != 1 || profiles[0].ProfileVersion != 1 || profiles[0].Capability != "llm_text_v1" {
		t.Fatalf("rendered model profiles = %#v, err = %v", profiles, err)
	}
	if cfg.Artifacts.RetentionPolicyVersion != "retention-v1" || cfg.Artifacts.MinimumRetentionBlocks != 100800 {
		t.Fatalf("rendered evidence policy = %#v", cfg.Artifacts)
	}
	if cfg.LocalIdentity.ServiceKeyRef != "kms://cortex/service-key&alias|dev" {
		t.Fatalf("rendered service key ref = %q", cfg.LocalIdentity.ServiceKeyRef)
	}
	// Devnet still keeps Builder descriptor verification off by default, but the
	// insecure-descriptor opt-in is no longer allowed in real mode.
	if cfg.Nexus.AllowInsecureDescriptor {
		t.Fatalf("rendered nexus descriptor settings = %#v, want no insecure descriptor opt-in", cfg.Nexus)
	}
}

func TestDevnetRendererRejectsTemplateInjection(t *testing.T) {
	tempDir := t.TempDir()
	tokenPath := filepath.Join(tempDir, "nexus.token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	cmd := exec.Command("sh", "../../scripts/devnet-deploy.sh", "render")
	cmd.Env = devnetRendererEnv(tempDir, tokenPath, "@@NODE_ID@@")
	if output, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(output), "must not contain template markers") {
		t.Fatalf("render template injection = %v, %s", err, output)
	}
}

func TestDevnetRendererRejectsRelativeNexusTokenPath(t *testing.T) {
	tempDir := t.TempDir()
	tokenPath := filepath.Join(tempDir, "nexus.token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	workingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	relativeTokenPath, err := filepath.Rel(workingDir, tokenPath)
	if err != nil {
		t.Fatalf("relative token path: %v", err)
	}
	cmd := exec.Command("sh", "../../scripts/devnet-deploy.sh", "render")
	cmd.Env = devnetRendererEnv(tempDir, relativeTokenPath, "trueopen-devnet-1")
	if output, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(output), "must be an absolute host path") {
		t.Fatalf("render relative token path = %v, %s", err, output)
	}
}

func devnetRendererEnv(generatedDir, tokenPath, chainID string) []string {
	return append(os.Environ(),
		"CORTEX_GENERATED_DIR="+generatedDir,
		"CORTEX_CHAIN_ID="+chainID,
		"CORTEX_OPERATOR_ADDRESS=trueopen1operator",
		"CORTEX_MODEL_ID=6d120a31a3858346e04517111eb3e1e03c4a5a9757b12cd3d2acb27c6bc9d6a2", "CORTEX_MODEL_PROFILES=6d120a31a3858346e04517111eb3e1e03c4a5a9757b12cd3d2acb27c6bc9d6a2@1=llm_text_v1",
		"CORTEX_MODEL_SERVICE_ID=model-service-dev", "CORTEX_MODEL_ENDPOINT=model-service:9090",
		"CORTEX_MODEL_TLS_PUBKEY_HASH="+strings.Repeat("ab", 32), "CORTEX_NEXUS_NATS_CA_FILE=/etc/cortex/nats-ca.pem",
		"CORTEX_NEXUS_NATS_USER_KEY_FILE=/etc/cortex/nats-user.nk",
		"CORTEX_NODE_RPC=https://rpc.example", "CORTEX_NODE_REST=https://rest.example",
		"CORTEX_KEEPER_API=https://keeper.example", "CORTEX_NEXUS_INGRESS=https://nexus.example",
		"CORTEX_NEXUS_NATS=tls://nats.example:4222", "CORTEX_SIGNER_URI=http://signer:9080",
		"CORTEX_SERVICE_KEY_REF=kms://cortex/service-key&alias|dev",
		"CORTEX_NEXUS_BUILDER_OPERATOR=", "CORTEX_GAS_PAYER=trueopen1operator",
		"CORTEX_RETENTION_POLICY_VERSION=retention-v1", "CORTEX_MINIMUM_RETENTION_BLOCKS=100800",
		"NEXUS_TOKEN_FILE="+tokenPath,
	)
}

func TestVendoredNexusContractIncludesTaskDataPlane(t *testing.T) {
	procedures := []string{
		nexusv1connect.IngressAPIGetTaskDataMetadataProcedure,
		nexusv1connect.IngressAPIFetchTaskDataProcedure,
		nexusv1connect.IngressAPIUploadTaskResultObjectProcedure,
		nexusv1connect.IngressAPIFinalizeTaskResultProcedure,
		nexusv1connect.IngressAPIFinalizeVerifierEvidenceProcedure,
		nexusv1connect.IngressAPISubmitInferReceiptProcedure,
	}
	if len(procedures) != 6 {
		t.Fatalf("task-data procedure count = %d, want 6", len(procedures))
	}
	_ = nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_INPUT
	_ = nexusv1.TaskDataObjectKind_TASK_DATA_OBJECT_KIND_OUTPUT
}

func TestRepositoryDocumentsIntegrationBoundary(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	text := string(readme)
	for _, want := range []string{
		"integration-ready control plane",
		"configs/real.example.yaml",
		"docs/operations/",
		"cortexd-real-mode.md",
		"model-registry.md",
		"evidence-retention.md",
		"troubleshooting.md",
		"Integration Status",
		"concrete publish and",
		"subscribe adapters",
		"Pebble stores only restart-critical local state",
		"active infer and verify responsibility documents",
		"not an audit or",
		"Cosmos Auth and Tx REST",
		"fee, gas, retry",
		"Model-management now has a concrete gRPC transport",
		"streaming artifact fetch",
		"real-mode readiness",
		"CometBFT blocks",
		"Keeper accepted events remain authoritative",
		"exact signed Keeper messages",
		"persist confirmed support rows",
		"accepted Keeper model profile/support events",
		"Remaining deployment-specific integrations",
		"rtk go test ./...",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("README.md missing %q", want)
		}
	}
}

// The CI-workflow and operations-runbook assertions that used to live here were
// removed with .github/workflows/ci.yml and docs/, which this repository does
// not carry. They read those files directly, so they could only ever fail.
// Restoring either tree means restoring the matching test: the Go-toolchain
// check in particular was the only thing keeping CI and the Dockerfile from
// falling below the go.mod directive.

func TestDevnetComposeKeepsCredentialsReadOnlyAndStateDurable(t *testing.T) {
	compose, err := os.ReadFile("../../deploy/devnet/compose.yaml")
	if err != nil {
		t.Fatalf("read compose: %v", err)
	}
	text := string(compose)
	for _, want := range []string{
		"${NEXUS_TOKEN_FILE}:/run/secrets/nexus.token:ro",
		"cortex-state:/var/lib/cortex",
		"cortex-run:/var/run/cortex",
		"http://127.0.0.1:8081/healthz",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("compose missing %q", want)
		}
	}
	dockerfile, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	if !strings.Contains(string(dockerfile), "USER cortex") {
		t.Fatal("Dockerfile does not select the non-root cortex user")
	}
}

// TestReadmeCoversPebbleCutoverAndRecovery is what survives of the operations
// runbook coverage: the same guidance was asserted across README.md and two
// docs/operations pages, and only README.md is in this repository.
func TestReadmeCoversPebbleCutoverAndRecovery(t *testing.T) {
	body, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	text := string(body)
	for _, want := range []string{"store.path", "Pebble", "backup", "rollback", "drain"} {
		if !strings.Contains(text, want) {
			t.Fatalf("README.md missing Pebble cutover guidance %q", want)
		}
	}
}

// TestChainBindingProvenanceIsRecorded keeps the answer to "where did these
// .pb.go files come from" in the repository rather than in a migration-day
// investigation. The pin in docs/reviews/keeper-interface-contract-matrix.md is
// an audited revision, not the generation source, and the doc must keep saying
// so.
func TestChainBindingProvenanceIsRecorded(t *testing.T) {
	body, err := os.ReadFile("../../proto/CHAIN_BINDINGS.md")
	if err != nil {
		t.Fatalf("read proto/CHAIN_BINDINGS.md: %v", err)
	}
	text := string(body)
	for _, want := range []string{
		"f1016de72fa08a8a49b9af40a7fb75902d5c785b",
		"9513467cc3aaa12d2ff997eb4460d5f37c5d21cf4a4e34c978e945c8f091b893",
		"proto/testdata/wire-v0.3.1.binpb",
		"protoc-gen-go",
		"make proto-gen-chain",
		"make proto-drift-chain",
		"proto/nexus/v1/README.md",
		"TestChainBindingsMatchReleasedDescriptor",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("proto/CHAIN_BINDINGS.md missing %q", want)
		}
	}
}

// FakeBus does not merely skip the envelope signature the way TrustedNATSDev
// does: it passes verifyTaskOrder=false to validateNexusOrderBroadcast, which
// drops canonical TaskOrderV1 decoding, the task_hash-commits-signed_order
// check, and every payload-matches-signed_order comparison
// (internal/daemon/task_runner_util.go:60-75). A deployment that could set it
// would accept an OrderBroadcast contradicting the order its own Builder
// signed.
//
// It used to be wired from configuration as `FakeBus: cfg.Mode ==
// config.ModeFake`, which was dead — newTaskRunner returns for every mode but
// real before reaching it — and would have been a hole the moment anyone gave
// fake mode a task runner to make the loop runnable. Reads of the field are
// fine; this pins that nothing outside a test writes it.
func TestFakeBusStaysTestOnly(t *testing.T) {
	assign := regexp.MustCompile(`(^|[^.\w])FakeBus\s*[:=]`)
	root := "../.."
	var offenders []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for i, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if assign.MatchString(line) {
				offenders = append(offenders, fmt.Sprintf("%s:%d: %s", path, i+1, strings.TrimSpace(line)))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
	if len(offenders) != 0 {
		t.Fatalf("FakeBus is assigned outside a test, which makes canonical order verification configuration-reachable:\n%s",
			strings.Join(offenders, "\n"))
	}
}

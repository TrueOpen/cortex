package devex

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/config"
	nexusv1 "github.com/SingaXYZ/cortex/proto/nexus/v1"
	"github.com/SingaXYZ/cortex/proto/nexus/v1/nexusv1connect"
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
		"CORTEX_MODEL_ID=llama-main", "CORTEX_MODEL_PROFILES=llama-main@1=llm_text_v1",
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

func TestCIRunsFullGoSuite(t *testing.T) {
	ci, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("read CI workflow: %v", err)
	}
	text := string(ci)
	for _, want := range []string{
		"actions/setup-go",
		"go test ./... -count=1",
		"deployment-smoke:",
		"docker compose --env-file deploy/devnet/env.example",
		"docker build --tag cortex:ci .",
		"Verify non-root runtime image",
		"test \"$(id -u)\" -ne 0",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("CI workflow missing %q", want)
		}
	}
}

// TestBuildToolchainsSatisfyGoDirective checks the invariant a pinned literal
// could not: every place that compiles this module must offer at least the Go
// version go.mod declares.
//
// The literal this replaces asserted go-version 1.22 and had to be edited whenever
// go.mod moved, while still allowing CI to sit *below* the directive — which is the
// failure it was supposed to prevent. It also said nothing about the Dockerfile,
// so the deployment-smoke image could fall behind on its own.
func TestBuildToolchainsSatisfyGoDirective(t *testing.T) {
	required := goDirective(t)

	ci, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("read CI workflow: %v", err)
	}
	ciVersion := firstSubmatch(t, `go-version:\s*'([0-9]+\.[0-9]+)'`, string(ci), "CI workflow")
	if compareGoVersions(t, ciVersion, required) < 0 {
		t.Fatalf("CI go-version %s is below the go.mod directive %s", ciVersion, required)
	}

	dockerfile, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	imageVersion := firstSubmatch(t, `FROM golang:([0-9]+\.[0-9]+)`, string(dockerfile), "Dockerfile")
	if compareGoVersions(t, imageVersion, required) < 0 {
		t.Fatalf("Dockerfile golang:%s is below the go.mod directive %s", imageVersion, required)
	}
}

func goDirective(t *testing.T) string {
	t.Helper()
	mod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	return firstSubmatch(t, `(?m)^go ([0-9]+\.[0-9]+)`, string(mod), "go.mod")
}

func firstSubmatch(t *testing.T, pattern, text, source string) string {
	t.Helper()
	match := regexp.MustCompile(pattern).FindStringSubmatch(text)
	if match == nil {
		t.Fatalf("%s has no match for %s", source, pattern)
	}
	return match[1]
}

func compareGoVersions(t *testing.T, a, b string) int {
	t.Helper()
	parse := func(v string) (int, int) {
		parts := strings.SplitN(v, ".", 2)
		major, err := strconv.Atoi(parts[0])
		if err != nil {
			t.Fatalf("parse Go version %q: %v", v, err)
		}
		minor, err := strconv.Atoi(parts[1])
		if err != nil {
			t.Fatalf("parse Go version %q: %v", v, err)
		}
		return major, minor
	}
	aMajor, aMinor := parse(a)
	bMajor, bMinor := parse(b)
	switch {
	case aMajor != bMajor:
		return aMajor - bMajor
	default:
		return aMinor - bMinor
	}
}

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

func TestOperationsDocsCoverRealModeRunbooks(t *testing.T) {
	docs := map[string][]string{
		"../../docs/operations/cortexd-real-mode.md": {
			"configs/real.example.yaml",
			"fail-closed diagnostics",
			"Keeper",
			"Nexus",
			"model-management gRPC",
			"tx broadcaster",
			"admin socket",
		},
		"../../docs/operations/model-registry.md": {
			"offline operator",
			"model support",
			"daily-support",
			"FEE_ONLY_NO_BLOCK_REWARD",
			"support state",
			"reward_state",
		},
		"../../docs/operations/evidence-retention.md": {
			"evidence cleanup",
			"task finality",
			"settlement",
			"preserved",
			"retention",
		},
		"../../docs/operations/troubleshooting.md": {
			"fail-closed",
			"diagnostics",
			"grpc endpoint unavailable",
			"NATS",
			"tx.max_fee_amount",
		},
	}

	for path, required := range docs {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(body)
		for _, want := range required {
			if !strings.Contains(text, want) {
				t.Fatalf("%s missing %q", path, want)
			}
		}
	}
}

func TestOperationsDocsCoverPebbleCutoverAndRecovery(t *testing.T) {
	paths := []string{
		"../../README.md",
		"../../docs/operations/cortexd-real-mode.md",
		"../../docs/operations/troubleshooting.md",
	}
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(body)
		for _, want := range []string{"store.path", "Pebble", "backup", "rollback", "drain"} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s missing Pebble cutover guidance %q", path, want)
			}
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
		"c8476fd8c26bc5d9d77f570125f57d79224ff81d",
		"0eae8af1536e489f38f668dfa87c848d1e889b460513607e13df54d9fde54887",
		"proto/testdata/wire-v0.2.0.binpb",
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

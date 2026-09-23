package config

import (
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/TrueOpen/cortex/internal/denom"
)

// The three deployment modes sit on two independent axes, which is why there
// are three values and not two. ModeFake wires nothing external. ModeReal and
// ModeIntegration wire everything external identically; they differ only at the
// envelope trust boundary, where real mode is fail-closed and integration mode
// may opt into the dev-only Nexus flags.
//
// Integration mode exists because the alternative was spelling it as
// `real` + `trusted_nats_dev`, which real mode now refuses outright. That left
// the integration harness with no startable configuration at all: fake mode
// builds no task runner, subscribes to no bus and reaches no chain, so it
// proves strictly less. configs/integration*.example.yaml are the canonical
// users.
//
// Ask UsesRealDependencies for the wiring question. Compare against ModeReal
// only for the security posture.
const (
	ModeFake                    = "fake"
	ModeReal                    = "real"
	ModeIntegration             = "integration"
	NexusEnvelopeAuthStrict     = "strict"
	NexusEnvelopeAuthTrustedDev = "trusted_nats_dev"
)

type Config struct {
	Mode            string                `yaml:"mode"`
	ChainID         string                `yaml:"chain_id"`
	Admin           AdminConfig           `yaml:"admin"`
	ModelManagement ModelManagementConfig `yaml:"model_management"`
	Node            NodeConfig            `yaml:"node"`
	Tx              TxConfig              `yaml:"tx"`
	Keeper          KeeperConfig          `yaml:"keeper"`
	TaskExecution   TaskExecutionConfig   `yaml:"task_execution"`
	Nexus           NexusConfig           `yaml:"nexus"`
	Artifacts       ArtifactsConfig       `yaml:"artifacts"`
	// Evidence is deprecated. Use artifacts instead.
	Evidence          ArtifactsConfig         `yaml:"evidence"`
	Store             StoreConfig             `yaml:"store"`
	Signer            SignerConfig            `yaml:"signer"`
	LocalIdentity     LocalIdentityConfig     `yaml:"local_identity"`
	SelfRescue        SelfRescueConfig        `yaml:"self_rescue"`
	ChallengeVerifier ChallengeVerifierConfig `yaml:"challenge_verifier"`
	Health            HealthConfig            `yaml:"health"`
}

type AdminConfig struct {
	UDSPath string `yaml:"uds_path"`
}

type ModelManagementConfig struct {
	Endpoint  string `yaml:"endpoint"`
	Transport string `yaml:"transport"`
	// TLS is the encryption setting for the grpc transport to the model service
	// (deployment security baseline): the model service uses a self-signed certificate,
	// and this names either the certificate / CA file or the public key fingerprint.
	// Real mode refuses to start when the service is on another host and neither is
	// given; a loopback address may be plaintext.
	TLS ModelServiceTLSConfig `yaml:"tls"`
	// MaxConcurrency is how many inference requests the backing model service
	// can hold at once. Handraise capacity is derived from it, so there is no
	// safe default: guessing high overcommits the node to tasks it cannot
	// serve. vLLM does not publish its scheduler limit (--max-num-seqs) on any
	// endpoint, so the operator has to state it. Required for transport local.
	MaxConcurrency uint32 `yaml:"max_concurrency"`
	// InferTimeoutMs bounds how long a single /v1/completions call may take for
	// Infer or Verify. vLLM time depends on model size, max_new_tokens, and
	// queue depth; operators should raise this only after load testing.
	InferTimeoutMs uint32 `yaml:"infer_timeout_ms"`
	// ProbeTimeoutMs bounds /health, /v1/models, and /metrics probes. It should
	// stay short so readiness decisions do not stall on a stuck vLLM.
	ProbeTimeoutMs uint32 `yaml:"probe_timeout_ms"`
}

// InferTimeout returns the inference timeout as a time.Duration. A value of
// zero means "use the model service default".
func (m ModelManagementConfig) InferTimeout() time.Duration {
	return time.Duration(m.InferTimeoutMs) * time.Millisecond
}

// ProbeTimeout returns the probe timeout as a time.Duration. A value of zero
// means "use the model service default".
func (m ModelManagementConfig) ProbeTimeout() time.Duration {
	return time.Duration(m.ProbeTimeoutMs) * time.Millisecond
}

type NodeConfig struct {
	RPCEndpoint  string `yaml:"rpc_endpoint"`
	RESTEndpoint string `yaml:"rest_endpoint"`
}

// ModelServiceTLSConfig: CAFile is the model service certificate (or the CA that
// issued it) in PEM, validated as a certificate chain; PubkeyHash is
// sha256(certificate SubjectPublicKeyInfo) as 64 lowercase hex chars and accepts
// that one public key. One or the other.
type ModelServiceTLSConfig struct {
	CAFile     string `yaml:"ca_file"`
	PubkeyHash string `yaml:"pubkey_hash"`
}

// Enabled reports whether either TLS check is configured.
func (t ModelServiceTLSConfig) Enabled() bool {
	return strings.TrimSpace(t.CAFile) != "" || strings.TrimSpace(t.PubkeyHash) != ""
}

type TxConfig struct {
	Enabled      bool   `yaml:"enabled"`
	MaxFeeAmount uint64 `yaml:"max_fee_amount"`
	// FeeDenom must match the target chain's genesis business_denom.
	FeeDenom     string `yaml:"fee_denom"`
	MaxAttempts  int    `yaml:"max_attempts"`
	PollAttempts int    `yaml:"poll_attempts"`
	GasLimit     uint64 `yaml:"gas_limit"`
}

type KeeperConfig struct {
	// APIURL is deprecated. Keeper reads use node.rpc_endpoint via ABCI query.
	APIURL         string `yaml:"api_url"`
	PollIntervalMS uint64 `yaml:"poll_interval_ms"`
	MaxLagBlocks   uint64 `yaml:"max_lag_blocks"`
}

// Task input resolver modes. fixture reads plaintext input from a local
// directory for fake-transport integration; nexus fetches plaintext input from
// the Builder that received the Task.
const (
	InputResolverFixture = "fixture"
	InputResolverNexus   = "nexus"
)

type TaskExecutionConfig struct {
	RetryDelayMS uint64 `yaml:"retry_delay_ms"`
	// MaxRetryDelayMS caps the exponential backoff applied to RetryDelayMS. It
	// is a ceiling, not a target: the first retry always waits exactly
	// RetryDelayMS, and most failures clear long before reaching this. Zero
	// takes the built-in default and it is never below RetryDelayMS.
	MaxRetryDelayMS uint64 `yaml:"max_retry_delay_ms"`
	// MaxRetryAttempts bounds task queue rows that carry no protocol deadline.
	// Rows with a recorded due height terminate on that height instead, so this
	// only covers rows enqueued without one and passes where the chain tip is
	// unreadable.
	MaxRetryAttempts int    `yaml:"max_retry_attempts"`
	InputResolver    string `yaml:"input_resolver"`
	FixtureRoot      string `yaml:"fixture_root"`
	// MaxOutputBytes bounds the verifier's output artifact fetch. The output is
	// not evidence, so no locked profile field sizes it, and the fetch completes
	// before the output hash can reject anything. Zero takes the built-in
	// default; there is deliberately no way to express "unbounded".
	MaxOutputBytes uint64 `yaml:"max_output_bytes"`
}

// InputResolverMode returns the canonical resolver mode.
func (c TaskExecutionConfig) InputResolverMode() string {
	return strings.ToLower(strings.TrimSpace(c.InputResolver))
}

// Envelope freshness defaults. Nexus and Cortex must agree on these, so they
// are deployment constants rather than chain governance parameters.
const (
	defaultEnvelopeTTLMS       = 30000
	defaultEnvelopeClockSkewMS = 2000
	// maxEnvelopeBoundMS caps both settings at ten minutes. A wider window is
	// no longer a freshness bound in any real deployment, and a large enough
	// millisecond value overflows once multiplied into a time.Duration, which
	// inverts the very skew-below-TTL ordering the validation enforces.
	maxEnvelopeBoundMS = 600000
)

type NexusConfig struct {
	IngressURL    string `yaml:"ingress_url"`
	NATSURL       string `yaml:"nats_url"`
	AuthTokenFile string `yaml:"auth_token_file"`
	// NATSCAFile / NATSCredsFile (the ADR-0016 transition state): the server
	// certificate / CA PEM (the system root CAs are used when it is absent) and the NATS
	// creds (user JWT + nkey seed). Real mode requires tls:// plus creds; a token and a
	// username/password embedded in the URL are dev-only.
	NATSCAFile    string `yaml:"nats_ca_file"`
	NATSCredsFile string `yaml:"nats_creds_file"`
	// NATSUserKeyFile (ADR-0016 decision three; interface-and-topic-list §5.14.1): the seed file
	// of the local NATS user key (an ed25519 nkey), 0600, generated on first start when
	// it does not exist. cortex signs a binding declaration for it with the on-chain
	// service key and then connects with nkey + sig + auth_token; it is required for a
	// remote NATS in real mode, which no longer accepts nats_creds_file.
	NATSUserKeyFile  string   `yaml:"nats_user_key_file"`
	EnvelopeAuthMode string   `yaml:"envelope_auth_mode"`
	SubscribeModels  []string `yaml:"subscribe_models"`
	SubscribeTasks   []string `yaml:"subscribe_tasks"`
	// EnvelopeTTLMS bounds how long a bus envelope is valid: it is stamped on
	// outbound envelopes and is the maximum lifetime accepted on an inbound one.
	// EnvelopeClockSkewMS is the tolerance applied when judging those stamps.
	// Both are deployment settings Nexus and Cortex must agree on, not chain
	// governance parameters. They are pointers because an explicit zero skew is
	// a real instruction (tolerate no clock difference) that must not be
	// mistaken for an omitted setting. Read them through EnvelopeTTL and
	// EnvelopeClockSkew rather than dereferencing them.
	EnvelopeTTLMS       *uint64 `yaml:"envelope_ttl_ms"`
	EnvelopeClockSkewMS *uint64 `yaml:"envelope_clock_skew_ms"`
	// BuilderOperatorAddress is an OPTIONAL narrowing filter naming the one
	// Builder operator this node deals with. It is not the authority over who
	// may address this node: the chain's current BuilderSet is, so a Builder the
	// chain has removed is refused no matter what this field says, and leaving it
	// empty admits every current BuilderSet member.
	//
	// When set, it adds two checks. Inbound bus traffic is accepted only from
	// that operator, on top of the chain membership requirement; and the daemon
	// reads that Builder's on-chain service descriptor and stays unready unless
	// its NEXUS_GRPC endpoint is byte-for-byte the configured ingress endpoint
	// and the Builder is in the current BuilderSet.
	BuilderOperatorAddress string `yaml:"builder_operator_address"`
	// AllowInsecureDescriptor permits exactly one plaintext transport: an
	// http:// endpoint, both where the on-chain descriptor publishes it and in
	// the configured ingress_url. https:// is the only other scheme Cortex
	// dials. It does not relax a superseded descriptor version, a missing
	// NEXUS_GRPC endpoint, a duplicate endpoint kind, or a tls_pubkey_hash this
	// build cannot check. Devnet terminates no TLS yet; production must leave
	// this false.
	AllowInsecureDescriptor bool `yaml:"allow_insecure_descriptor"`
	// DowngradeDescriptorTLS dials an https:// or grpcs:// Builder endpoint at
	// its plaintext origin. It is the devnet compatibility switch for a
	// BuilderSet whose descriptor publishes a TLS scheme in front of an ingress
	// that terminates no TLS: the endpoint is consensus state, so the only local
	// remedy for `http: server gave HTTP response to HTTPS client` is to dial
	// what the server actually speaks. Fixing the descriptor is still the real
	// fix; this keeps a devnet node moving until the Builder republishes.
	//
	// It requires AllowInsecureDescriptor, because a downgraded endpoint IS a
	// plaintext one: the two switches together say "this deployment carries
	// prompts and outputs in the clear". Real mode must leave both false.
	DowngradeDescriptorTLS bool `yaml:"downgrade_descriptor_tls"`
	// JetStreamStream names the JetStream stream Nexus publishes task frames
	// to. Cortex creates and binds its own durable consumer on that stream
	// instead of letting nats.go create one, so the name has to be stated: a
	// library-created consumer is deleted on unsubscribe and every restart then
	// replays the retention window (issue #132). It is configuration rather
	// than a per-subject StreamNameBySubject lookup so a missing stream fails
	// closed at startup, like the other real-mode boundaries. Required in real
	// mode; the devnet stream is TRUEOPEN_TASK.
	JetStreamStream string `yaml:"jetstream_stream"`
}

// VerifiesBuilderDescriptor reports whether the daemon can cross-check the
// configured Nexus ingress endpoint against the authoritative chain view.
func (c NexusConfig) VerifiesBuilderDescriptor() bool {
	return strings.TrimSpace(c.BuilderOperatorAddress) != ""
}

func (c NexusConfig) TrustedNATSDev() bool {
	return strings.EqualFold(strings.TrimSpace(c.EnvelopeAuthMode), NexusEnvelopeAuthTrustedDev)
}

// EnvelopeTTL returns the bus envelope lifetime: the value stamped on outbound
// envelopes and the maximum self-declared lifetime accepted on an inbound one.
// An absent setting takes the deployment default.
func (c NexusConfig) EnvelopeTTL() time.Duration {
	if c.EnvelopeTTLMS == nil {
		return defaultEnvelopeTTLMS * time.Millisecond
	}
	return time.Duration(*c.EnvelopeTTLMS) * time.Millisecond
}

// EnvelopeClockSkew returns the tolerance applied when judging envelope stamps.
// An explicit zero means no tolerance at all. An absent setting takes the
// deployment default, capped at half the effective TTL so that a short explicit
// TTL is never swamped by a skew the operator never wrote.
func (c NexusConfig) EnvelopeClockSkew() time.Duration {
	if c.EnvelopeClockSkewMS != nil {
		return time.Duration(*c.EnvelopeClockSkewMS) * time.Millisecond
	}
	skew := time.Duration(defaultEnvelopeClockSkewMS) * time.Millisecond
	if half := c.EnvelopeTTL() / 2; half < skew {
		skew = half
	}
	return skew
}

// NATSURLCredentials reports whether nats_url carries userinfo credentials.
// Cortex only implements nats.Token, so a broker configured for user/password
// has to receive them through the URL instead. The token file is primarily the
// Nexus IngressAPI bearer credential, so its absence does not by itself mean
// the message bus is unauthenticated.
func (c NexusConfig) NATSURLCredentials() bool {
	parsed, err := url.Parse(strings.TrimSpace(c.NATSURL))
	if err != nil || parsed.User == nil {
		return false
	}
	if parsed.User.Username() != "" {
		return true
	}
	password, _ := parsed.User.Password()
	return password != ""
}

type ArtifactsConfig struct {
	Root                   string        `yaml:"root"`
	RetentionPolicyVersion string        `yaml:"retention_policy_version"`
	MinimumRetentionBlocks uint64        `yaml:"minimum_retention_blocks"`
	SweepGracePeriod       time.Duration `yaml:"sweep_grace_period"`
}

type StoreConfig struct {
	Path string `yaml:"path"`
}

type SignerConfig struct {
	URI                      string `yaml:"uri"`
	ReadinessProofIntervalMS uint64 `yaml:"readiness_proof_interval_ms"`
	// PasswordEnv and PasswordFile locate the password for an encrypted local
	// key file. They are unused for an HTTP signing service.
	PasswordEnv   string `yaml:"password_env"`
	PasswordFile  string `yaml:"password_file"`
	PasswordStdin bool   `yaml:"password_stdin"`
}

// LocalKeys reports whether the signer URI loads key material into this
// process rather than delegating to an external signing service.
func (c SignerConfig) LocalKeys() bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(c.URI)), "file:")
}

type LocalIdentityConfig struct {
	OperatorAddress string `yaml:"operator_address"`
	ServiceKeyRef   string `yaml:"service_key_ref"`
	// Duties is retired. Every node holds both responsibilities: it may be
	// drawn as the Worker for one task and as a Verifier for another, and the
	// chain already prevents the two from colliding on the same task by
	// excluding the winning Worker from that task's Verifier candidates.
	//
	// The field survives only so that a config carrying the old key is refused
	// with a sentence an operator can act on instead of the yaml decoder's
	// "field duties not found". It is never read for a decision. Silently
	// accepting it would be worse than either: an operator reading
	// `duties: [WORKER]` would believe this node does not verify, while it now
	// subscribes to the Verifier subjects regardless.
	Duties                 []string `yaml:"duties"`
	SupportedModelProfiles []string `yaml:"supported_model_profiles"`
	ModelServiceID         string   `yaml:"model_service_id"`
}

type ModelProfileRef struct {
	ModelID        string
	ProfileVersion uint32
	Capability     string
}

func (c LocalIdentityConfig) ModelProfiles() ([]ModelProfileRef, error) {
	if len(c.SupportedModelProfiles) == 0 {
		return nil, fmt.Errorf("local_identity.supported_model_profiles is required")
	}
	profiles := make([]ModelProfileRef, 0, len(c.SupportedModelProfiles))
	seen := make(map[string]struct{}, len(c.SupportedModelProfiles))
	for _, raw := range c.SupportedModelProfiles {
		binding := strings.TrimSpace(raw)
		chainRef, capability, hasCapability := strings.Cut(binding, "=")
		modelID, profileVersionText, hasProfile := strings.Cut(chainRef, "@")
		parsedVersion, parseErr := strconv.ParseUint(profileVersionText, 10, 32)
		if !hasCapability || !hasProfile || strings.TrimSpace(modelID) == "" || strings.TrimSpace(capability) == "" ||
			strings.TrimSpace(modelID) != modelID || strings.TrimSpace(capability) != capability || parseErr != nil || parsedVersion == 0 ||
			strconv.FormatUint(parsedVersion, 10) != profileVersionText || strings.Contains(capability, "=") {
			return nil, fmt.Errorf("local_identity.supported_model_profiles entry %q must be model_id@uint32=capability", raw)
		}
		ref := ModelProfileRef{ModelID: modelID, ProfileVersion: uint32(parsedVersion), Capability: capability}
		key := modelProfileBindingKey(ref.ModelID, ref.ProfileVersion)
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("local_identity.supported_model_profiles contains duplicate entry %q", raw)
		}
		seen[key] = struct{}{}
		profiles = append(profiles, ref)
	}
	return profiles, nil
}

func (c LocalIdentityConfig) CapabilityFor(modelID string, profileVersion uint32) (string, error) {
	profiles, err := c.ModelProfiles()
	if err != nil {
		return "", err
	}
	for _, profile := range profiles {
		if profile.ModelID == modelID && profile.ProfileVersion == profileVersion {
			return profile.Capability, nil
		}
	}
	return "", fmt.Errorf("no model-service capability binding for %s@%d", modelID, profileVersion)
}

func modelProfileBindingKey(modelID string, profileVersion uint32) string {
	return modelID + "\x00" + strconv.FormatUint(uint64(profileVersion), 10)
}

// SelfRescueConfig is the DEADLINE-RISK self-rescue policy and nothing else.
//
// It used to gate every direct verifier submission, which made a normal exit
// look like an opt-in feature. The two are different triggers:
//
//   - Deadline risk (this block): fire near a deadline. It needs to know when a
//     deadline is approaching across restarts, i.e. durable deadline
//     scheduling, which is issue #108. Still disabled in real mode.
//   - Relay unavailable: the commit exit. Known synchronously, the instant the
//     commit is signed, from a deterministic refusal or from the absence of any
//     relay channel. It needs no scheduler, it is the contract's first-class
//     route (keeper §10.6 rule 6), and it reads none of the fields here except
//     MaxFeeAmount as a fee bound.
//
// So Enabled means "run the deadline-risk trigger". Turning it off does not
// stop a Verifier's commit from reaching the chain.
type SelfRescueConfig struct {
	Enabled      bool   `yaml:"enabled"`
	MarginBlocks uint64 `yaml:"margin_blocks"`
	// MaxFeeAmount bounds one direct verifier submission. It applies to the
	// commit exit as well as to the deadline-risk trigger -- an exit that runs
	// on every round is exactly what a per-tx bound is for -- and it may only
	// narrow tx.max_fee_amount, never widen it.
	MaxFeeAmount uint64 `yaml:"max_fee_amount"`
	FeeDenom     string `yaml:"fee_denom"`
	// AllowedTxTypes remains a deadline-risk-only allowlist. It deliberately
	// does not gate the commit exit: the exit is a normal path the chain
	// requires of every selected Verifier, and letting a self_rescue field
	// switch it off would restore, under a new name, the whole-feature block
	// this configuration just stopped applying.
	AllowedTxTypes []string `yaml:"allowed_tx_types"`
}

// CommitExitFeeCap is the per-transaction fee ceiling for the verifier commit
// exit: the narrower of the general tx ceiling and the self-rescue bound. It can
// only ever reduce spending -- a self_rescue.max_fee_amount above
// tx.max_fee_amount is ignored rather than honoured, and the broadcaster checks
// the result against tx.max_fee_amount again anyway.
//
// The denom is deliberately not taken from self_rescue.fee_denom: the
// broadcaster requires every fee to carry tx.fee_denom, so a second denom
// setting could only produce a refused transaction.
func (c Config) CommitExitFeeCap() uint64 {
	if c.SelfRescue.MaxFeeAmount > 0 && c.SelfRescue.MaxFeeAmount < c.Tx.MaxFeeAmount {
		return c.SelfRescue.MaxFeeAmount
	}
	return c.Tx.MaxFeeAmount
}

type ChallengeVerifierConfig struct {
	Enabled bool `yaml:"enabled"`
}

// RequiresWorkloadTx reports whether an enabled daemon workload path *depends*
// on submitting Cosmos transactions directly -- i.e. whether the absence of a
// working broadcaster must hold the whole node down.
//
// Only the two scheduled direct paths do. Everything the protocol asks of a
// Worker travels through Nexus, which relays it as its own transaction: worker
// handraise (MsgSubmitWorkerHandraises), infer receipt (MsgSubmitInferReceipt),
// verifier handraise (MsgSubmitVerifierHandraises) and, since nexus opened it,
// the Verifier result receipt (MsgSubmitVerifyResult over the VERIFY_RESULT bus
// subject). A node whose signer cannot produce Cosmos transactions can still do
// all of that.
//
// This condition used to include UsesRealDependencies(), because a selected
// Verifier's commit was self-submission or nothing
// (internal/verifier/commit_exit.go). It is the wrong scope for a whole-node
// gate either way, and it produced a node that did nothing at all: a file://
// keystore signer reports CanSignCosmosTx() == false
// (internal/signer/local.go), so tx_broadcaster could never become ready, the
// readyz workload gate never opened, and the node refused Worker work it needed
// no transaction for. Since nexus#70 such a node also has the Builder relay, and
// the commit exit resolves the routes per round -- relay first, self-submission
// on a deterministic refusal, ErrCommitExitUnavailable only when neither exists
// -- which costs at most one verify round instead of every duty.
func (c Config) RequiresWorkloadTx() bool {
	return c.SelfRescue.Enabled || c.ChallengeVerifier.Enabled
}

// UsesRealDependencies reports whether the daemon wires its external
// dependencies for real: Keeper, Nexus publisher and subscriber, signer, model
// service, chain events, reconciler, task runner and Keeper poller.
//
// This is the WIRING axis. It is true for both ModeReal and ModeIntegration,
// which are identical here and differ only at the envelope trust boundary.
// Every dependency-construction site must ask this rather than comparing
// against ModeReal, because a site that compares directly is a dependency
// integration mode silently does without — which is how ModeFake ended up
// building no task runner while still setting a FakeBus flag for one.
//
// Compare against ModeReal only where the question is genuinely the security
// posture, i.e. whether the dev-only Nexus flags are admissible.
func (c Config) UsesRealDependencies() bool {
	return c.Mode != ModeFake
}

type HealthConfig struct {
	Bind string `yaml:"bind"`
}

func LoadFile(path string) (Config, error) {
	return LoadFileWithOverrides(path, nil)
}

// LoadFileWithOverrides resolves defaults < YAML < environment < flags and
// validates only the final effective configuration.
func LoadFileWithOverrides(path string, overrides map[string]string) (Config, error) {
	cfg := defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}

	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil && err != io.EOF {
		return Config{}, decodeConfigError(data, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Config{}, fmt.Errorf("decode config: multiple YAML documents are not supported")
		}
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := applyEnv(&cfg); err != nil {
		return Config{}, err
	}
	for key, value := range overrides {
		if err := setDeploymentValue(&cfg, key, value); err != nil {
			return Config{}, fmt.Errorf("flag --%s: %w", strings.ReplaceAll(key, "_", "-"), err)
		}
	}
	// The canonical --artifacts-root wins over the deprecated --evidence-root
	// when both flags are supplied.
	if value, ok := overrides["artifacts_root"]; ok {
		if err := setDeploymentValue(&cfg, "artifacts_root", value); err != nil {
			return Config{}, fmt.Errorf("flag --artifacts-root: %w", err)
		}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

var yamlErrorLine = regexp.MustCompile(`line ([0-9]+):`)

func decodeConfigError(data []byte, err error) error {
	match := yamlErrorLine.FindStringSubmatch(err.Error())
	if len(match) != 2 {
		return fmt.Errorf("decode config: %w", err)
	}
	lineNumber, parseErr := strconv.Atoi(match[1])
	lines := strings.Split(string(data), "\n")
	if parseErr != nil || lineNumber < 1 || lineNumber > len(lines) {
		return fmt.Errorf("decode config: %w", err)
	}
	line := lines[lineNumber-1]
	indent := len(line) - len(strings.TrimLeft(line, " "))
	key, _, ok := strings.Cut(strings.TrimSpace(line), ":")
	if !ok || key == "" {
		return fmt.Errorf("decode config: %w", err)
	}
	path := key
	for i := lineNumber - 2; i >= 0 && indent > 0; i-- {
		candidate := lines[i]
		candidateIndent := len(candidate) - len(strings.TrimLeft(candidate, " "))
		candidateKey, candidateValue, candidateOK := strings.Cut(strings.TrimSpace(candidate), ":")
		if candidateOK && strings.TrimSpace(candidateValue) == "" && candidateIndent < indent {
			path = candidateKey + "." + path
			break
		}
	}
	if strings.Contains(err.Error(), "not found in type") {
		section, field, nested := strings.Cut(path, ".")
		if nested {
			return fmt.Errorf("decode config: unknown %s field %q: %w", section, field, err)
		}
		return fmt.Errorf("decode config: unknown field %q: %w", section, err)
	}
	return fmt.Errorf("decode config %s: %w", path, err)
}

func applyEnv(cfg *Config) error {
	for envName, key := range deploymentEnvironment {
		value, ok := os.LookupEnv(envName)
		if !ok || value == "" {
			continue
		}
		if err := setDeploymentValue(cfg, key, value); err != nil {
			return fmt.Errorf("environment %s: %w", envName, err)
		}
	}
	// The explicit subscription setting wins over the deployment-compatible
	// CORTEX_MODEL_ID alias when both are present.
	if value, ok := os.LookupEnv("CORTEX_NEXUS_SUBSCRIBE_MODELS"); ok && value != "" {
		cfg.Nexus.SubscribeModels = splitCSV(value)
	}
	// The canonical CORTEX_ARTIFACTS_ROOT wins over the deprecated
	// CORTEX_EVIDENCE_ROOT alias when both are present.
	if value, ok := os.LookupEnv("CORTEX_ARTIFACTS_ROOT"); ok && value != "" {
		if err := setDeploymentValue(cfg, "artifacts_root", value); err != nil {
			return fmt.Errorf("environment CORTEX_ARTIFACTS_ROOT: %w", err)
		}
	}
	return nil
}

// DeploymentOverrideKeys lists every setting reachable through a deployment
// environment variable. Flag registration is asserted against this rather than
// a hand-maintained list, so a new override cannot silently ship without the
// higher-precedence flag the documented ordering promises.
func DeploymentOverrideKeys() []string {
	seen := make(map[string]struct{}, len(deploymentEnvironment))
	keys := make([]string, 0, len(deploymentEnvironment))
	for _, key := range deploymentEnvironment {
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

var deploymentEnvironment = map[string]string{
	"CORTEX_MODE":                               "mode",
	"CORTEX_CHAIN_ID":                           "chain_id",
	"CORTEX_ADMIN_SOCKET":                       "admin_socket",
	"CORTEX_MODEL_ENDPOINT":                     "model_endpoint",
	"CORTEX_MODEL_TRANSPORT":                    "model_transport",
	"CORTEX_MODEL_MAX_CONCURRENCY":              "model_max_concurrency",
	"CORTEX_NODE_RPC":                           "node_rpc",
	"CORTEX_NODE_REST":                          "node_rest",
	"CORTEX_KEEPER_API":                         "keeper_api",
	"CORTEX_KEEPER_POLL_INTERVAL_MS":            "keeper_poll_interval_ms",
	"CORTEX_KEEPER_MAX_LAG_BLOCKS":              "keeper_max_lag_blocks",
	"CORTEX_TASK_RETRY_DELAY_MS":                "task_retry_delay_ms",
	"CORTEX_TASK_MAX_RETRY_ATTEMPTS":            "task_max_retry_attempts",
	"CORTEX_TASK_INPUT_RESOLVER":                "task_input_resolver",
	"CORTEX_TASK_FIXTURE_ROOT":                  "task_fixture_root",
	"CORTEX_TASK_MAX_OUTPUT_BYTES":              "task_max_output_bytes",
	"CORTEX_NEXUS_INGRESS":                      "nexus_ingress",
	"CORTEX_NEXUS_NATS":                         "nexus_nats",
	"CORTEX_NEXUS_AUTH_TOKEN_FILE":              "nexus_auth_token_file",
	"CORTEX_NEXUS_NATS_CA_FILE":                 "nexus_nats_ca_file",
	"CORTEX_NEXUS_NATS_CREDS_FILE":              "nexus_nats_creds_file",
	"CORTEX_NEXUS_NATS_USER_KEY_FILE":           "nexus_nats_user_key_file",
	"CORTEX_MODEL_SERVICE_TLS_CA_FILE":          "model_service_tls_ca_file",
	"CORTEX_MODEL_SERVICE_TLS_PUBKEY_HASH":      "model_service_tls_pubkey_hash",
	"CORTEX_NEXUS_JETSTREAM_STREAM":             "nexus_jetstream_stream",
	"CORTEX_NEXUS_ENVELOPE_AUTH_MODE":           "nexus_envelope_auth_mode",
	"CORTEX_NEXUS_ENVELOPE_TTL_MS":              "nexus_envelope_ttl_ms",
	"CORTEX_NEXUS_ENVELOPE_CLOCK_SKEW_MS":       "nexus_envelope_clock_skew_ms",
	"CORTEX_NEXUS_SUBSCRIBE_TASKS":              "nexus_subscribe_tasks",
	"CORTEX_NEXUS_BUILDER_OPERATOR":             "nexus_builder_operator_address",
	"CORTEX_NEXUS_ALLOW_INSECURE_DESCRIPTOR":    "nexus_allow_insecure_descriptor",
	"CORTEX_NEXUS_DOWNGRADE_DESCRIPTOR_TLS":     "nexus_downgrade_descriptor_tls",
	"CORTEX_MODEL_ID":                           "nexus_subscribe_models",
	"CORTEX_EVIDENCE_ROOT":                      "evidence_root",
	"CORTEX_ARTIFACTS_ROOT":                     "artifacts_root",
	"CORTEX_STORE_PATH":                         "store_path",
	"CORTEX_SIGNER_URI":                         "signer_uri",
	"CORTEX_SIGNER_READINESS_PROOF_INTERVAL_MS": "signer_readiness_proof_interval_ms",
	"CORTEX_SIGNER_PASSWORD_ENV":                "signer_password_env",
	"CORTEX_SIGNER_PASSWORD_FILE":               "signer_password_file",
	"CORTEX_SIGNER_PASSWORD_STDIN":              "signer_password_stdin",
	"CORTEX_OPERATOR_ADDRESS":                   "operator_address",
	"CORTEX_SERVICE_KEY_REF":                    "service_key_ref",
	"CORTEX_MODEL_PROFILES":                     "model_profiles",
	"CORTEX_MODEL_SERVICE_ID":                   "model_service_id",
	"CORTEX_HEALTH_BIND":                        "health_bind",
}

func setDeploymentValue(cfg *Config, key, value string) error {
	switch key {
	case "mode":
		cfg.Mode = value
	case "chain_id":
		cfg.ChainID = value
	case "admin_socket":
		cfg.Admin.UDSPath = value
	case "model_endpoint":
		cfg.ModelManagement.Endpoint = value
	case "model_transport":
		cfg.ModelManagement.Transport = value
	case "model_max_concurrency":
		parsed, err := parseEnvUint(value)
		if err != nil {
			return err
		}
		if parsed > math.MaxUint32 {
			return fmt.Errorf("model_max_concurrency %d exceeds uint32", parsed)
		}
		cfg.ModelManagement.MaxConcurrency = uint32(parsed)
	case "node_rpc":
		cfg.Node.RPCEndpoint = value
	case "node_rest":
		cfg.Node.RESTEndpoint = value
	case "keeper_api":
		cfg.Keeper.APIURL = value
	case "keeper_poll_interval_ms":
		parsed, err := parseEnvUint(value)
		if err != nil {
			return err
		}
		cfg.Keeper.PollIntervalMS = parsed
	case "keeper_max_lag_blocks":
		parsed, err := parseEnvUint(value)
		if err != nil {
			return err
		}
		cfg.Keeper.MaxLagBlocks = parsed
	case "task_input_resolver":
		cfg.TaskExecution.InputResolver = value
	case "task_fixture_root":
		cfg.TaskExecution.FixtureRoot = value
	case "task_max_output_bytes":
		parsed, err := parseEnvUint(value)
		if err != nil {
			return err
		}
		cfg.TaskExecution.MaxOutputBytes = parsed
	case "nexus_builder_operator_address":
		cfg.Nexus.BuilderOperatorAddress = value
	case "nexus_allow_insecure_descriptor":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid nexus_allow_insecure_descriptor %q: %w", value, err)
		}
		cfg.Nexus.AllowInsecureDescriptor = parsed
	case "nexus_downgrade_descriptor_tls":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid nexus_downgrade_descriptor_tls %q: %w", value, err)
		}
		cfg.Nexus.DowngradeDescriptorTLS = parsed
	case "task_retry_delay_ms":
		parsed, err := parseEnvUint(value)
		if err != nil {
			return err
		}
		cfg.TaskExecution.RetryDelayMS = parsed
	case "task_max_retry_attempts":
		parsed, err := parseEnvUint(value)
		if err != nil {
			return err
		}
		if parsed > math.MaxInt32 {
			return fmt.Errorf("task_max_retry_attempts is out of range")
		}
		cfg.TaskExecution.MaxRetryAttempts = int(parsed)
	case "nexus_ingress":
		cfg.Nexus.IngressURL = value
	case "nexus_nats":
		cfg.Nexus.NATSURL = value
	case "nexus_auth_token_file":
		cfg.Nexus.AuthTokenFile = value
	case "nexus_nats_ca_file":
		cfg.Nexus.NATSCAFile = value
	case "nexus_nats_creds_file":
		cfg.Nexus.NATSCredsFile = value
	case "nexus_nats_user_key_file":
		cfg.Nexus.NATSUserKeyFile = value
	case "model_service_tls_ca_file":
		cfg.ModelManagement.TLS.CAFile = value
	case "model_service_tls_pubkey_hash":
		cfg.ModelManagement.TLS.PubkeyHash = value
	case "nexus_jetstream_stream":
		cfg.Nexus.JetStreamStream = value
	case "nexus_envelope_auth_mode":
		cfg.Nexus.EnvelopeAuthMode = value
	case "nexus_envelope_ttl_ms":
		parsed, err := parseEnvUint(value)
		if err != nil {
			return err
		}
		cfg.Nexus.EnvelopeTTLMS = &parsed
	case "nexus_envelope_clock_skew_ms":
		parsed, err := parseEnvUint(value)
		if err != nil {
			return err
		}
		cfg.Nexus.EnvelopeClockSkewMS = &parsed
	case "nexus_subscribe_models":
		cfg.Nexus.SubscribeModels = splitCSV(value)
	case "nexus_subscribe_tasks":
		cfg.Nexus.SubscribeTasks = splitCSV(value)
	case "evidence_root":
		slog.Info("warning: CORTEX_EVIDENCE_ROOT / --evidence-root is deprecated; use CORTEX_ARTIFACTS_ROOT / --artifacts-root")
		cfg.Artifacts.Root = value
	case "artifacts_root":
		cfg.Artifacts.Root = value
	case "store_path":
		cfg.Store.Path = value
	case "signer_uri":
		cfg.Signer.URI = value
	case "signer_readiness_proof_interval_ms":
		parsed, err := parseEnvUint(value)
		if err != nil {
			return err
		}
		cfg.Signer.ReadinessProofIntervalMS = parsed
	case "signer_password_env":
		cfg.Signer.PasswordEnv = value
	case "signer_password_file":
		cfg.Signer.PasswordFile = value
	case "signer_password_stdin":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("must be true or false")
		}
		cfg.Signer.PasswordStdin = parsed
	case "operator_address":
		cfg.LocalIdentity.OperatorAddress = value
	case "service_key_ref":
		cfg.LocalIdentity.ServiceKeyRef = value
	case "model_profiles":
		cfg.LocalIdentity.SupportedModelProfiles = splitCSV(value)
	case "model_service_id":
		cfg.LocalIdentity.ModelServiceID = value
	case "health_bind":
		cfg.Health.Bind = value
	default:
		return fmt.Errorf("unknown deployment override %q", key)
	}
	return nil
}

func parseEnvUint(value string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("must be an unsigned integer")
	}
	return parsed, nil
}

// requiredField names a field that must be non-empty and the logical subsystem
// that owns or consumes it outside internal/config. Keeping the consumer
// explicit makes it impossible to add a required field without identifying who
// cares about it.
type requiredField struct {
	field    string
	value    string
	consumer string
}

// collectRequiredFields returns the list of fields that must be non-empty for
// the current configuration. Each entry names the subsystem that consumes the
// field, so the required set cannot grow without a consumer. The caller must
// supply the already-derived modelTransport and inputResolver values so the
// required set stays in sync with the validation logic.
func (c *Config) collectRequiredFields(modelTransport, inputResolver string) []requiredField {
	required := []requiredField{
		{field: "chain_id", value: c.ChainID, consumer: "cmd/cortexd"},
		{field: "admin.uds_path", value: c.Admin.UDSPath, consumer: "adminapi"},
		{field: "model_management.transport", value: c.ModelManagement.Transport, consumer: "modelservice"},
		{field: "node.rpc_endpoint", value: c.Node.RPCEndpoint, consumer: "chainclient"},
		{field: "artifacts.root", value: c.Artifacts.Root, consumer: "evidence"},
		{field: "artifacts.retention_policy_version", value: c.Artifacts.RetentionPolicyVersion, consumer: "evidence"},
		{field: "store.path", value: c.Store.Path, consumer: "store"},
		{field: "signer.uri", value: c.Signer.URI, consumer: "signer"},
	}

	if modelTransport != "local" && modelTransport != "fake" {
		required = append(required, requiredField{field: "model_management.endpoint", value: c.ModelManagement.Endpoint, consumer: "modelservice"})
	}
	if inputResolver == InputResolverFixture {
		required = append(required, requiredField{field: "task_execution.fixture_root", value: c.TaskExecution.FixtureRoot, consumer: "task_execution(fixture)"})
	}
	// Integration mode dials the same dependencies, so it needs the same fields.
	if c.UsesRealDependencies() {
		required = append(required,
			requiredField{field: "nexus.ingress_url", value: c.Nexus.IngressURL, consumer: "nexus"},
			requiredField{field: "nexus.nats_url", value: c.Nexus.NATSURL, consumer: "nexus"},
			requiredField{field: "nexus.jetstream_stream", value: c.Nexus.JetStreamStream, consumer: "nexus"},
			requiredField{field: "local_identity.operator_address", value: c.LocalIdentity.OperatorAddress, consumer: "taskdataauth"},
			requiredField{field: "local_identity.service_key_ref", value: c.LocalIdentity.ServiceKeyRef, consumer: "signer"},
			requiredField{field: "local_identity.model_service_id", value: c.LocalIdentity.ModelServiceID, consumer: "modelservice"},
		)
		if c.Tx.Enabled {
			required = append(required,
				requiredField{field: "node.rest_endpoint", value: c.Node.RESTEndpoint, consumer: "chainclient"},
				requiredField{field: "tx.fee_denom", value: c.Tx.FeeDenom, consumer: "txclient"},
			)
		}
	}
	return required
}

func (c *Config) Validate() error {
	var problems []string
	if c.Mode == "" {
		c.Mode = ModeFake
	}
	if (c.Tx.Enabled || c.Tx.FeeDenom != "") && !denom.Valid(c.Tx.FeeDenom) {
		problems = append(problems, "tx.fee_denom must be a valid bank denomination matching the chain business_denom")
	}
	if problem := retiredDutiesProblem(c.LocalIdentity.Duties); problem != "" {
		problems = append(problems, problem)
	}
	// Backward compatibility: the deprecated evidence.* keys are accepted for one
	// release. Any value set under evidence.* is copied into artifacts.* only
	// when the corresponding artifacts.* field is not already set.
	if c.Evidence.Root != "" || c.Evidence.RetentionPolicyVersion != "" || c.Evidence.MinimumRetentionBlocks != 0 {
		if c.Artifacts.Root == "" {
			c.Artifacts.Root = c.Evidence.Root
		}
		if c.Artifacts.RetentionPolicyVersion == "" {
			c.Artifacts.RetentionPolicyVersion = c.Evidence.RetentionPolicyVersion
		}
		if c.Artifacts.MinimumRetentionBlocks == 0 {
			c.Artifacts.MinimumRetentionBlocks = c.Evidence.MinimumRetentionBlocks
		}
		slog.Info("warning: evidence.* is deprecated; use artifacts.*")
	}
	if strings.TrimSpace(c.Artifacts.RetentionPolicyVersion) == "" {
		c.Artifacts.RetentionPolicyVersion = "retention-v1"
	}
	if c.Artifacts.MinimumRetentionBlocks == 0 {
		c.Artifacts.MinimumRetentionBlocks = 100800
	}
	if c.Artifacts.SweepGracePeriod == 0 {
		c.Artifacts.SweepGracePeriod = time.Hour
	}
	if c.Artifacts.SweepGracePeriod <= 0 {
		problems = append(problems, "artifacts.sweep_grace_period must be greater than zero")
	}
	if c.Mode != ModeFake && c.Mode != ModeReal && c.Mode != ModeIntegration {
		problems = append(problems, "mode must be fake, real or integration")
	}
	authMode := strings.ToLower(strings.TrimSpace(c.Nexus.EnvelopeAuthMode))
	if authMode == "" {
		authMode = NexusEnvelopeAuthStrict
	}
	c.Nexus.EnvelopeAuthMode = authMode
	if authMode != NexusEnvelopeAuthStrict && authMode != NexusEnvelopeAuthTrustedDev {
		problems = append(problems, "nexus.envelope_auth_mode must be strict or trusted_nats_dev")
	}
	// An unset bound takes the default the same way the auth mode above does, so
	// a hand-built config does not have to restate a deployment constant.
	ttlMS := uint64(defaultEnvelopeTTLMS)
	ttlUsable := true
	if configured := c.Nexus.EnvelopeTTLMS; configured != nil {
		ttlMS = *configured
		switch {
		case ttlMS == 0:
			// A zero TTL expires every envelope at the instant it is stamped.
			problems = append(problems, "nexus.envelope_ttl_ms must be greater than zero")
			ttlUsable = false
		case ttlMS > maxEnvelopeBoundMS:
			problems = append(problems, fmt.Sprintf("nexus.envelope_ttl_ms must not exceed %d (ten minutes)", maxEnvelopeBoundMS))
			ttlUsable = false
		}
	}
	// A skew window at or beyond the TTL would accept an envelope that is
	// already expired by its own stamps, which defeats the freshness bound.
	// Only an explicit skew is compared: an omitted one is derived from the TTL
	// by EnvelopeClockSkew and stays below it by construction, so a short
	// explicit TTL must not fail against a key the operator never wrote.
	if configured := c.Nexus.EnvelopeClockSkewMS; configured != nil {
		switch {
		case *configured > maxEnvelopeBoundMS:
			problems = append(problems, fmt.Sprintf("nexus.envelope_clock_skew_ms must not exceed %d (ten minutes)", maxEnvelopeBoundMS))
		case ttlUsable && *configured >= ttlMS:
			problems = append(problems, "nexus.envelope_clock_skew_ms must be less than nexus.envelope_ttl_ms")
		}
	}
	if authMode == NexusEnvelopeAuthTrustedDev && strings.TrimSpace(c.Nexus.AuthTokenFile) == "" && !c.Nexus.NATSURLCredentials() {
		problems = append(problems, "nexus.envelope_auth_mode trusted_nats_dev requires an authenticated NATS transport: set nexus.auth_token_file or embed credentials in nexus.nats_url")
	}

	modelTransport := strings.ToLower(strings.TrimSpace(c.ModelManagement.Transport))
	inputResolver := c.TaskExecution.InputResolverMode()
	required := c.collectRequiredFields(modelTransport, inputResolver)
	if modelTransport != "fake" && modelTransport != "local" && modelTransport != "grpc" && modelTransport != "" {
		problems = append(problems, "model_management.transport must be fake, local, or grpc")
	}
	if err := c.ModelManagement.TLS.validate(); err != nil {
		problems = append(problems, err.Error())
	}
	if modelTransport == "local" && c.ModelManagement.MaxConcurrency == 0 {
		problems = append(problems, "model_management.max_concurrency must be greater than zero for transport local")
	}
	switch inputResolver {
	case "", InputResolverFixture, InputResolverNexus:
	default:
		problems = append(problems, "task_execution.input_resolver must be fixture or nexus when configured")
	}
	if inputResolver == InputResolverFixture {
		if modelTransport != "fake" {
			problems = append(problems, "task_execution.input_resolver fixture requires model_management.transport fake")
		}
	}
	// Whether inference is real or fake has nothing to do with nexus input
	// resolution: the resolver uses only the task-data client, Builder endpoint
	// resolution and service-key authentication, none of which go through the model
	// service. "Real input + fake inference" is the most valuable integration
	// combination - a fully real data plane with only the GPU left out - and refusing
	// it forced fake-inference deployments onto fixture input, whose payload cid
	// stopped travelling after the V2 migration (TaskRecord.InputCID became a dead
	// field), which broke the whole input-fetch path.
	// Everything below applies to any deployment that wires real dependencies.
	// The dev-only Nexus flags are the sole exception: they are the security
	// posture, and only real mode is fail-closed about them. Integration mode
	// exists precisely so that opting into them is a named deployment rather
	// than an override smuggled past a real-mode config.
	if c.UsesRealDependencies() {
		if c.Mode == ModeReal {
			if c.Nexus.TrustedNATSDev() {
				problems = append(problems, "nexus.envelope_auth_mode must not be trusted_nats_dev in real mode")
			}
			if c.Nexus.AllowInsecureDescriptor {
				problems = append(problems, "nexus.allow_insecure_descriptor must be false in real mode")
			}
			// Dialling a TLS descriptor in the clear is the same security
			// decision as accepting a plaintext one, and real mode is
			// fail-closed about both.
			if c.Nexus.DowngradeDescriptorTLS {
				problems = append(problems, "nexus.downgrade_descriptor_tls must be false in real mode")
			}
			problems = append(problems, c.realModeTransportProblems(modelTransport)...)
		}
		// The downgrade produces a plaintext endpoint, so it cannot be the one
		// switch that opens the plaintext path: stating the coupling here means
		// a half-configured node is refused at startup instead of failing on
		// its first task-data call.
		if c.Nexus.DowngradeDescriptorTLS && !c.Nexus.AllowInsecureDescriptor {
			problems = append(problems, "nexus.downgrade_descriptor_tls requires nexus.allow_insecure_descriptor")
		}
		// Same reasoning as above: fake inference does not constrain the input source.
		// Both fixture and nexus are legal - fixture for fully offline cases, nexus for
		// integration with a real data plane.
		if modelTransport == "fake" && inputResolver == "" {
			problems = append(problems, "task_execution.input_resolver is required for real mode fake transport (fixture or nexus)")
		}
		// A Worker that cannot fetch its input would retry a task it can never
		// start until the deadline expires, so require a resolver up front.
		// Every real-mode node can be drawn as a Worker now, so this is no
		// longer conditional on a configured duty.
		if inputResolver == "" {
			problems = append(problems, "task_execution.input_resolver is required in real mode")
		}
		// grpcs:// is the same TLS transport as https:// spelled for a gRPC
		// endpoint, so gating on the https prefix alone refused a secure
		// configuration. The plaintext spellings, http:// and grpc://, stay
		// behind allow_insecure_descriptor.
		if c.Nexus.VerifiesBuilderDescriptor() && !c.Nexus.AllowInsecureDescriptor &&
			!strings.HasPrefix(c.Nexus.IngressURL, "https://") && !strings.HasPrefix(c.Nexus.IngressURL, "grpcs://") {
			problems = append(problems, "nexus.ingress_url must use https or grpcs when nexus.builder_operator_address is set and nexus.allow_insecure_descriptor is false")
		}
		if operator := strings.TrimSpace(c.Nexus.BuilderOperatorAddress); operator != c.Nexus.BuilderOperatorAddress {
			problems = append(problems, "nexus.builder_operator_address must be canonical")
		}
		if c.ChallengeVerifier.Enabled {
			problems = append(problems, "challenge_verifier.enabled must be false in real mode: the feature is frozen (issue #21)")
		}
		if c.RequiresWorkloadTx() && !c.Tx.Enabled {
			problems = append(problems, "tx.enabled must be true when a direct workload transaction path is enabled: a scheduled direct submission has no relay to travel on")
		}
		if _, err := c.LocalIdentity.ModelProfiles(); err != nil {
			problems = append(problems, err.Error())
		}
		if c.TaskExecution.RetryDelayMS == 0 {
			problems = append(problems, "task_execution.retry_delay_ms is required")
		}
		if c.Tx.Enabled {
			if c.Tx.MaxFeeAmount == 0 {
				problems = append(problems, "tx.max_fee_amount is required")
			}
			if c.Tx.GasLimit == 0 {
				problems = append(problems, "tx.gas_limit is required")
			}
			if c.Tx.PollAttempts <= 0 {
				problems = append(problems, "tx.poll_attempts is required")
			}
		}
		// Narrowed from "the whole feature is frozen" to "the deadline-risk
		// trigger is frozen". That trigger is what issue #108 blocks: it fires
		// only near a deadline, so it needs durable deadline scheduling to
		// survive a restart. The verifier commit exit does not read this flag at
		// all -- it is a normal exit, reached from a deterministic relay refusal
		// -- so leaving this false no longer stops a commit from reaching the
		// chain.
		if c.SelfRescue.Enabled {
			problems = append(problems, "self_rescue.enabled must be false in real mode: it enables only the deadline-risk trigger, which still needs durable deadline scheduling (issue #108); the verifier commit exit taken when the relay is unavailable is a normal path and does not read this flag")
		}
	}
	if c.UsesRealDependencies() && !validSignerURI(c.Signer.URI) {
		problems = append(problems, "signer.uri must be an HTTP(S) URL without credentials or a file:// path")
	}
	if c.UsesRealDependencies() && !c.Signer.LocalKeys() && (c.Signer.ReadinessProofIntervalMS < 1000 || c.Signer.ReadinessProofIntervalMS > 3600000) {
		problems = append(problems, "signer.readiness_proof_interval_ms must be between 1000 and 3600000 for an HTTP signer")
	}
	passwordSources := 0
	for _, set := range []bool{strings.TrimSpace(c.Signer.PasswordEnv) != "", strings.TrimSpace(c.Signer.PasswordFile) != "", c.Signer.PasswordStdin} {
		if set {
			passwordSources++
		}
	}
	if passwordSources > 1 {
		problems = append(problems, "signer.password_env, signer.password_file and signer.password_stdin are mutually exclusive")
	}

	for _, item := range required {
		if strings.TrimSpace(item.value) == "" {
			problems = append(problems, fmt.Sprintf("%s is required (consumer: %s)", item.field, item.consumer))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

func validHTTPURL(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	return err == nil && parsed.Host != "" && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.User == nil
}

// validSignerURI accepts an external signing service or a local key file.
// A file URI keeps private keys inside cortexd, which is weaker than an
// external signer but is supported for integration environments.
func validSignerURI(value string) bool {
	trimmed := strings.TrimSpace(value)
	if validHTTPURL(trimmed) {
		return true
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || strings.ToLower(parsed.Scheme) != "file" {
		return false
	}
	// Only the two well-formed shapes: file:///absolute/path with an empty
	// host, or file:relative/path as an opaque reference. A non-empty host
	// would name a remote machine and is not something we can open.
	if parsed.Host != "" {
		return false
	}
	return parsed.Path != "" || parsed.Opaque != ""
}

func defaults() Config {
	return Config{
		Mode: ModeFake,
		ModelManagement: ModelManagementConfig{
			Transport: "fake",
		},
		ChallengeVerifier: ChallengeVerifierConfig{
			Enabled: false,
		},
		Keeper: KeeperConfig{
			PollIntervalMS: 1000,
			MaxLagBlocks:   20,
		},
		TaskExecution: TaskExecutionConfig{
			RetryDelayMS: 30000,
			// Fifteen minutes: nine doublings above the 30 s base, so the first
			// handful of retries stay prompt and a responsibility that keeps
			// failing stops asking twice a minute forever.
			MaxRetryDelayMS: 900000,
			// Roughly an hour at the retry delay above. It only bounds queue
			// rows with no protocol deadline to compare against.
			MaxRetryAttempts: 120,
		},
		Artifacts: ArtifactsConfig{
			SweepGracePeriod: time.Hour,
		},
		Signer: SignerConfig{ReadinessProofIntervalMS: 30000},
		Tx:     TxConfig{FeeDenom: "uusdc"},
		Nexus: NexusConfig{
			// The envelope bounds stay nil so Validate and the accessors can
			// tell an omitted setting from an explicit zero.
			EnvelopeAuthMode: NexusEnvelopeAuthStrict,
		},
		SelfRescue: SelfRescueConfig{Enabled: false},
		Health: HealthConfig{
			Bind: "127.0.0.1:8081",
		},
	}
}

func splitCSV(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// retiredDutiesProblem refuses a config that still selects duties. The key is
// gone in both modes -- a fake-mode config that keeps it describes a node
// topology that no longer exists just as much as a real-mode one does.
func retiredDutiesProblem(duties []string) string {
	if len(duties) == 0 {
		return ""
	}
	return "local_identity.duties has been removed: every node now holds both the WORKER and the VERIFIER responsibility, so delete the key"
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (t ModelServiceTLSConfig) validate() error {
	ca, hash := strings.TrimSpace(t.CAFile), strings.TrimSpace(t.PubkeyHash)
	if ca != "" && hash != "" {
		return fmt.Errorf("model_management.tls: set ca_file or pubkey_hash, not both")
	}
	if hash != "" && !hex64.MatchString(hash) {
		return fmt.Errorf("model_management.tls.pubkey_hash must be 64 lowercase hex (sha256 of the certificate SubjectPublicKeyInfo)")
	}
	return nil
}

// realModeTransportProblems is the deployment security baseline's transport check
// in real mode:
//   - a remote nexus.nats_url must be tls:// and must supply nexus.nats_ca_file (the
//     ADR-0016 transition state validates against the distributed certificate file
//     and never falls back to the system root CAs); authentication accepts only the
//     on-chain identity (§5.14), and the creds file is retired;
//   - a non-loopback node.rpc_endpoint / rest_endpoint must be https://;
//   - a non-loopback grpc model service must configure model_management.tls, with no
//     plaintext exemption (baseline items 4 and 5).
//
// Reaching a peer on the same host over loopback plaintext is a deployment choice
// and is allowed.
func (c *Config) realModeTransportProblems(modelTransport string) []string {
	var problems []string
	natsURL := strings.TrimSpace(c.Nexus.NATSURL)
	if natsURL != "" && !isLoopbackEndpoint(natsURL) {
		if !strings.HasPrefix(strings.ToLower(natsURL), "tls://") {
			problems = append(problems, "nexus.nats_url must use tls:// in real mode for a remote NATS (ADR-0016)")
		}
		if strings.TrimSpace(c.Nexus.NATSCAFile) == "" {
			problems = append(problems, "nexus.nats_ca_file is required in real mode for a remote NATS: verify the server against the distributed certificate, not the system roots (ADR-0016)")
		}
		// ADR-0016 decision three: real mode joins with the on-chain identity only, and
		// the creds file is retired.
		if strings.TrimSpace(c.Nexus.NATSUserKeyFile) == "" {
			problems = append(problems, "nexus.nats_user_key_file is required in real mode for a remote NATS: cortex joins NATS with its on-chain identity (ADR-0016 decision three, §5.14)")
		}
		if strings.TrimSpace(c.Nexus.NATSCredsFile) != "" {
			problems = append(problems, "nexus.nats_creds_file is retired in real mode: remove it and set nexus.nats_user_key_file (ADR-0016 decision three)")
		}
	}
	for _, endpoint := range []struct{ field, value string }{
		{"node.rpc_endpoint", c.Node.RPCEndpoint}, {"node.rest_endpoint", c.Node.RESTEndpoint},
	} {
		if err := requireHTTPSUnlessLoopback(endpoint.field, endpoint.value); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if modelTransport == "grpc" && !c.ModelManagement.TLS.Enabled() && !isLoopbackEndpoint(c.ModelManagement.Endpoint) {
		problems = append(problems, fmt.Sprintf("model_management.tls is required in real mode for the remote model service %q (set ca_file or pubkey_hash); only a loopback endpoint may be plaintext", c.ModelManagement.Endpoint))
	}
	return problems
}

func requireHTTPSUnlessLoopback(field, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if strings.HasPrefix(strings.ToLower(value), "https://") {
		return nil
	}
	if isLoopbackEndpoint(value) {
		return nil
	}
	return fmt.Errorf("%s %q must use https:// in real mode unless it is a loopback address", field, value)
}

// isLoopbackEndpoint reports whether the host of a host:port or a URL is loopback
// (127.0.0.0/8, ::1, localhost).
func isLoopbackEndpoint(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	host := value
	if parsed, err := url.Parse(value); err == nil && parsed.Host != "" {
		host = parsed.Host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

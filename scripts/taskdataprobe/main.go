// Command taskdataprobe performs one real, correctly signed GetTaskDataMetadata
// call against a live Nexus Builder using this node's own CORTEX_NODE service
// key, and prints exactly what came back.
//
// It is the live counterpart of test/task_data_plane: that harness proves the
// Cortex-side logic in-process against a fake Builder, this proves the real hop
// over real HTTP against the real chain identity. Nothing here is a second
// implementation - the chain read, the authenticator and the Connect client are
// the same packages the daemon runs.
//
// It is read-only in both directions: no chain transaction is ever built, no
// NATS connection is opened, and only the metadata lookup is issued (no upload,
// no receipt relay).
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/builderdirectory"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/observability"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
)

// probeExpiryBlocks mirrors inputTaskDataExpiryBlocks in
// internal/daemon/nexus_input.go, which is unexported. The runtime's expiry
// bound is part of the request shape this probe is meant to reproduce, so it is
// restated here rather than approximated. Source of truth is the daemon
// constant; if that changes, this must follow.
const probeExpiryBlocks = uint64(20)

func main() {
	observability.SetDefaultLogger(os.Stderr)
	chainRPC := flag.String("chain-rpc", "", "CometBFT RPC endpoint used for ABCI Keeper queries, e.g. http://host:26657")
	chainID := flag.String("chain-id", "", "chain id, signed into the request")
	operator := flag.String("operator", "", "this node's operator address; becomes the request Requester")
	signerDir := flag.String("signer-dir", "", "keystore v3 directory holding the CORTEX_NODE service key")
	serviceKeyRef := flag.String("service-key-ref", "", "keystore file name of the service key inside -signer-dir")
	passwordFile := flag.String("signer-password-file", "", "file holding the keystore password (mutually exclusive with -signer-password-env)")
	passwordEnv := flag.String("signer-password-env", "", "environment variable holding the keystore password (mutually exclusive with -signer-password-file)")
	builderOperator := flag.String("builder", "", "operator address of the receiving Builder to query")
	builderEndpoint := flag.String("builder-endpoint", "", "override the chain-advertised Builder endpoint; use only when the advertised scheme cannot be honoured")
	sessionID := flag.String("session-id", "", "session id of the task-data object")
	taskID := flag.String("task-id", "", "task id of the task-data object")
	taskHash := flag.String("task-hash", "", "accepted task hash, canonical 64 lowercase hex")
	contentHash := flag.String("content-hash", "", "input content hash, canonical 64 lowercase hex")
	allowPlaintext := flag.Bool("allow-plaintext-endpoint", false, "permit a plaintext http Builder endpoint; off by default so an advertised-https/served-http mismatch is visible")
	downgradeTLS := flag.Bool("downgrade-endpoint-tls", false, "dial an advertised https/grpcs Builder endpoint in plaintext, as nexus.downgrade_descriptor_tls does; requires -allow-plaintext-endpoint")
	nexusTokenFile := flag.String("nexus-token-file", "", "optional file holding the Nexus bearer token, as nexus.auth_token_file does in production")
	timeout := flag.Duration("timeout", 60*time.Second, "overall probe deadline")
	flag.Usage = func() { printUsage(nil) }
	flag.Parse()

	missing := []string{}
	for _, required := range []struct {
		flag  string
		value string
	}{
		{flag: "-chain-rpc", value: *chainRPC},
		{flag: "-chain-id", value: *chainID},
		{flag: "-operator", value: *operator},
		{flag: "-signer-dir", value: *signerDir},
		{flag: "-service-key-ref", value: *serviceKeyRef},
		{flag: "-builder", value: *builderOperator},
		{flag: "-session-id", value: *sessionID},
		{flag: "-task-id", value: *taskID},
		{flag: "-task-hash", value: *taskHash},
		{flag: "-content-hash", value: *contentHash},
	} {
		if strings.TrimSpace(required.value) == "" {
			missing = append(missing, required.flag)
		}
	}
	if (*passwordFile == "") == (*passwordEnv == "") {
		missing = append(missing, "exactly one of -signer-password-file / -signer-password-env")
	}
	if len(missing) > 0 {
		printUsage(missing)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := probe(ctx, options{
		chainRPC:        strings.TrimSpace(*chainRPC),
		chainID:         strings.TrimSpace(*chainID),
		operator:        strings.TrimSpace(*operator),
		signerDir:       *signerDir,
		serviceKeyRef:   strings.TrimSpace(*serviceKeyRef),
		passwordFile:    *passwordFile,
		passwordEnv:     *passwordEnv,
		builderOperator: strings.TrimSpace(*builderOperator),
		builderEndpoint: strings.TrimSpace(*builderEndpoint),
		sessionID:       strings.TrimSpace(*sessionID),
		taskID:          strings.TrimSpace(*taskID),
		taskHash:        strings.TrimSpace(*taskHash),
		contentHash:     strings.TrimSpace(*contentHash),
		allowPlaintext:  *allowPlaintext,
		downgradeTLS:    *downgradeTLS,
		nexusTokenFile:  strings.TrimSpace(*nexusTokenFile),
	}); err != nil {
		slog.Error("taskdataprobe failed", slog.Any("error", err))
		os.Exit(1)
	}
}

func printUsage(missing []string) {
	fmt.Fprint(os.Stderr, `taskdataprobe issues one signed GetTaskDataMetadata against a live Builder.

usage: taskdataprobe -chain-rpc URL -chain-id ID -operator ADDR \
    -signer-dir DIR -service-key-ref FILE (-signer-password-file F | -signer-password-env VAR) \
    -builder ADDR -session-id ID -task-id ID -task-hash HEX64 -content-hash HEX64 \
    [-builder-endpoint URL] [-allow-plaintext-endpoint]

The probe is read-only: no chain transaction, no NATS publish, metadata only.

flags:
`)
	flag.PrintDefaults()
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "\nmissing: %s\n", strings.Join(missing, ", "))
	}
}

type options struct {
	chainRPC        string
	chainID         string
	operator        string
	signerDir       string
	serviceKeyRef   string
	passwordFile    string
	passwordEnv     string
	builderOperator string
	builderEndpoint string
	sessionID       string
	taskID          string
	taskHash        string
	contentHash     string
	allowPlaintext  bool
	downgradeTLS    bool
	nexusTokenFile  string
}

func probe(ctx context.Context, opts options) error {
	key := builderclient.TaskDataKey{TaskHash: opts.taskHash, SessionID: opts.sessionID, TaskID: opts.taskID, ContentHash: opts.contentHash, Kind: builderclient.DataKindInput}
	bodyDigest, err := builderclient.TaskDataMetadataBodyDigest(key)
	if err != nil {
		return fmt.Errorf("metadata object reference: %w", err)
	}
	// The same Keeper reader production uses: ABCI protobuf queries against the
	// CometBFT RPC endpoint.
	keeper := chainclient.NewKeeperABCIClient(opts.chainRPC)

	// One committed read supplies both the binding and the height it was served
	// at, the same way the daemon does it. Reading /status first and pinning that
	// height is what the chain refuses at a commit boundary.
	binding, height, err := keeper.CommittedCurrentServiceKey(ctx, chainclient.ParticipantTypeCortexNode, opts.operator)
	if err != nil {
		return fmt.Errorf("resolve current %s service key for %s from committed state at %s: %w",
			chainclient.ParticipantTypeCortexNode, opts.operator, opts.chainRPC, err)
	}
	if height == 0 {
		return fmt.Errorf("committed chain height at %s is zero", opts.chainRPC)
	}
	printLocalIdentity(opts, height, binding)
	if err := binding.Validate(); err != nil {
		return fmt.Errorf("Keeper current service key is malformed: %w", err)
	}

	signingClient, err := openSigner(opts)
	if err != nil {
		return err
	}

	// Identical to internal/daemon/runtime.go: CORTEX_NODE participant domain,
	// the operator as Requester, the chain-confirmed service key as the signing
	// and presented key, and the same height-bound expiry.
	auth, err := taskdataauth.New(taskdataauth.Config{
		ServiceKeys: keeper, Signer: signingClient,
		ChainID: opts.chainID, OperatorAddress: opts.operator,
		ServiceAddress: binding.ServiceAddress, ServicePubkey: binding.ServicePubkey,
		ServiceKeyRef: opts.serviceKeyRef, ExpiryBlocks: probeExpiryBlocks,
	})
	if err != nil {
		return fmt.Errorf("construct task-data authenticator: %w", err)
	}

	endpoint, err := resolveEndpoint(ctx, keeper, opts, height)
	if err != nil {
		return err
	}

	request, err := auth.SignRequest(ctx, "GetTaskDataMetadata", key, opts.builderOperator, bodyDigest)
	if err != nil {
		return fmt.Errorf("sign GetTaskDataMetadata: %w", err)
	}
	printRequest(endpoint, key, request, height)

	token, err := readNexusToken(opts.nexusTokenFile)
	if err != nil {
		return err
	}
	// NewConnectTaskDataClientWithDefaults is NewConnectTaskDataClient wrapped
	// around the shared bounded, same-origin Nexus HTTP client. A hand-rolled
	// http.Client here would silently drop the redirect policy that refuses an
	// https->http downgrade, which is exactly the mismatch this probe reports.
	// The endpoint policy tracks -allow-plaintext, the same switch the descriptor
	// resolution above runs under.
	client := builderclient.NewConnectTaskDataClientWithDefaults(token,
		builderclient.TaskDataTransport{
			AllowInsecureEndpoint: opts.allowPlaintext,
			DowngradeEndpointTLS:  opts.downgradeTLS,
		})
	metadata, callErr := client.GetTaskDataMetadata(ctx, endpoint, builderclient.GetTaskDataMetadataRequest{Key: key, Auth: request})
	if callErr != nil {
		fmt.Printf("\n== result: error ==\n")
		fmt.Printf("  retryable:     %t (builderclient.IsRetryable)\n", builderclient.IsRetryable(callErr))
		fmt.Printf("  error:         %s\n", callErr.Error())
		return fmt.Errorf("GetTaskDataMetadata failed")
	}
	fmt.Printf("\n== result: metadata ==\n")
	fmt.Printf("  readiness:            %d\n", metadata.Readiness)
	fmt.Printf("  content_hash:         %s\n", metadata.Key.ContentHash)
	fmt.Printf("  size_bytes:           %d\n", metadata.SizeBytes)
	fmt.Printf("  media_type:           %s\n", metadata.MediaType)
	fmt.Printf("  retain_until_height:  %d\n", metadata.RetainUntilHeight)
	// The two OUTPUT-only fields are the target-state replacement for the deleted
	// OutputRef object, so a probe that omitted them could not tell whether a
	// Builder can prove it holds an output at all.
	if receipt := metadata.SignedInferReceipt; receipt == nil {
		fmt.Printf("  signed_infer_receipt: absent (expected for INPUT; an OUTPUT without one cannot be confirmed)\n")
	} else {
		fmt.Printf("  signed_infer_receipt:\n")
		fmt.Printf("    schema_version:              %d\n", receipt.SchemaVersion)
		fmt.Printf("    chain_id:                    %s\n", receipt.ChainID)
		fmt.Printf("    task_id:                     %s\n", receipt.TaskID)
		fmt.Printf("    task_hash:                   %s\n", receipt.TaskHash)
		fmt.Printf("    worker_operator_address:     %s\n", receipt.WorkerOperatorAddress)
		fmt.Printf("    service_authorization_nonce: %d\n", receipt.ServiceAuthorizationNonce)
		fmt.Printf("    generation_params_digest:    %s\n", receipt.GenerationParamsDigest)
		fmt.Printf("    output_hash:                 %s\n", receipt.OutputHash)
		fmt.Printf("    output_size_bytes:           %d\n", receipt.OutputSizeBytes)
		fmt.Printf("    generated_token_count:       %d\n", receipt.GeneratedTokenCount)
		fmt.Printf("    output_leaf_count:           %d\n", receipt.OutputLeafCount)
		fmt.Printf("    expiry_height:               %d\n", receipt.ExpiryHeight)
		for index, commitment := range receipt.RequiredEvidenceCommitments {
			fmt.Printf("    required_evidence_commitments[%d]: kind=%d hash=%x encoded_size_bytes=%d\n",
				index, commitment.EvidenceKind, commitment.EvidenceHashOrRoot[:], commitment.EncodedSizeBytes)
		}
		// infer_receipt_hash is not a wire field: §5.14 makes it the signing
		// digest, so the probe derives it the same way every verifier must.
		if digest, err := builderclient.InferReceiptSigningDigest(*receipt); err == nil {
			fmt.Printf("    derived infer_receipt_hash:  %x\n", digest[:])
		}
		fmt.Printf("    service_signature:           %s\n", receipt.ServiceSignature)
	}
	return nil
}

// openSigner loads the service key exactly as the runtime does, deriving the
// bech32 prefix from the operator address so the key file need not repeat it.
func openSigner(opts options) (signer.Signer, error) {
	dir, err := filepath.Abs(opts.signerDir)
	if err != nil {
		return nil, fmt.Errorf("resolve signer directory: %w", err)
	}
	signingClient, err := signer.Open("file://"+dir, signer.OpenOptions{
		PasswordFile: opts.passwordFile,
		PasswordEnv:  opts.passwordEnv,
		HRP:          bech32HRP(opts.operator),
		KeyRefs:      []signer.KeyRef{{Ref: opts.serviceKeyRef}},
	})
	if err != nil {
		return nil, fmt.Errorf("open signer: %w", err)
	}
	return signingClient, nil
}

// resolveEndpoint prefers the chain-committed descriptor and reports why it
// could not be used when it fails. -builder-endpoint exists for exactly the case
// where the advertised scheme cannot be honoured; using it is always reported as
// unverified.
func resolveEndpoint(ctx context.Context, keeper *chainclient.KeeperABCIClient, opts options, height uint64) (string, error) {
	fmt.Printf("\n== receiving Builder %s ==\n", opts.builderOperator)
	printDescriptorCommitment(ctx, keeper, opts.builderOperator, height)

	directory, err := builderdirectory.New(keeper, builderdirectory.Options{AllowInsecure: opts.allowPlaintext})
	if err != nil {
		return "", fmt.Errorf("construct Builder directory: %w", err)
	}
	identity, resolveErr := directory.Resolve(ctx, opts.builderOperator)
	switch {
	case resolveErr == nil:
		fmt.Printf("  descriptor_version:   %d\n", identity.DescriptorVersion)
		fmt.Printf("  endpoint_protocol:    %s\n", identity.EndpointProtocolVersion)
		fmt.Printf("  endpoint_tls_pin:     %s\n", identity.EndpointTLSPubkeyHash)
		fmt.Printf("  builder_service_addr: %s\n", identity.ServiceAddress)
		fmt.Printf("  advertised_endpoint:  %s (read from the on-chain descriptor at height %d)\n", identity.Endpoint, identity.SnapshotHeight)
	case errors.Is(resolveErr, builderdirectory.ErrNoCurrentDescriptor):
		fmt.Printf("  descriptor:           NONE published (%v)\n", resolveErr)
	default:
		fmt.Printf("  descriptor:           UNRESOLVED\n")
		fmt.Printf("  descriptor_error:     %s\n", resolveErr.Error())
		fmt.Printf("  retryable:            %t (builderclient.IsRetryable)\n", builderclient.IsRetryable(resolveErr))
		// Only the scheme refusal is answerable with -allow-plaintext-endpoint;
		// pointing at it for an unrelated failure would send the operator the
		// wrong way.
		if !opts.allowPlaintext && errors.Is(resolveErr, builderdirectory.ErrPlaintextEndpoint) {
			fmt.Printf("  note:                 the advertised endpoint's scheme cannot be honoured; rerun with -allow-plaintext-endpoint or pass -builder-endpoint\n")
		}
	}

	if opts.builderEndpoint == "" {
		if resolveErr != nil {
			return "", fmt.Errorf("Builder endpoint is unresolved and no -builder-endpoint override was given: %w", resolveErr)
		}
		fmt.Printf("  endpoint_in_use:      %s (chain-verified)\n", identity.Endpoint)
		return identity.Endpoint, nil
	}

	// The override is honoured, but never silently: say whether it agrees with
	// what the chain commits.
	agreement := "descriptor unresolved, override is NOT chain-verified"
	if resolveErr == nil {
		if err := identity.SameEndpoint(opts.builderEndpoint); err != nil {
			agreement = "DIVERGES from the descriptor: " + err.Error()
		} else {
			agreement = "matches the descriptor commitment"
		}
	}
	fmt.Printf("  endpoint_in_use:      %s (from -builder-endpoint; %s)\n", opts.builderEndpoint, agreement)
	return opts.builderEndpoint, nil
}

// printDescriptorCommitment reports the raw on-chain descriptor row so its
// version, hash and endpoint list can be pasted into an issue even when
// resolution refuses the endpoint Cortex would have used.
func printDescriptorCommitment(ctx context.Context, keeper *chainclient.KeeperABCIClient, operator string, height uint64) {
	fmt.Printf("  read_at_height:       %d\n", height)
	builder, err := keeper.Builder(ctx, operator, height)
	if err != nil {
		fmt.Printf("  descriptor_commit:    unavailable: %v\n", err)
		return
	}
	version := builder.CurrentDescriptorVersion.Uint64()
	fmt.Printf("  current_version:      %d\n", version)
	if version == 0 {
		return
	}
	descriptor, err := keeper.ServiceDescriptor(ctx, chainclient.ParticipantTypeBuilder, operator, height)
	if err != nil {
		fmt.Printf("  descriptor_commit:    unavailable: %v\n", err)
		return
	}
	fmt.Printf("  descriptor_version:   %d\n", descriptor.DescriptorVersion)
	fmt.Printf("  descriptor_hash:      %s\n", descriptor.DescriptorHash.String())
	fmt.Printf("  updated_height:       %d\n", descriptor.UpdatedHeight)
	for _, kind := range descriptor.Kinds() {
		endpoint, err := descriptor.Endpoint(kind)
		if err != nil {
			fmt.Printf("  endpoint[%s]: unavailable: %v\n", kind, err)
			continue
		}
		fmt.Printf("  endpoint[%-20s] %s (protocol %s, tls_pubkey_hash %s)\n",
			kind, endpoint.URI, endpoint.ProtocolVersion, endpoint.TLSPubkeyHash)
	}
}

func printLocalIdentity(opts options, height uint64, binding chainclient.ServiceKeySnapshot) {
	fmt.Printf("== local service identity ==\n")
	fmt.Printf("  chain_rpc:            %s\n", opts.chainRPC)
	fmt.Printf("  chain_id:             %s\n", opts.chainID)
	fmt.Printf("  read_at_height:       %d\n", height)
	fmt.Printf("  queried_participant:  %s\n", chainclient.ParticipantTypeCortexNode)
	fmt.Printf("  participant_type:     %s\n", binding.ParticipantType)
	fmt.Printf("  operator_address:     %s\n", binding.OperatorAddress)
	fmt.Printf("  service_address:      %s\n", binding.ServiceAddress)
	fmt.Printf("  service_pubkey:       %s\n", binding.ServicePubkey)
	fmt.Printf("  pubkey_fingerprint:   %s\n", pubkeyFingerprint(binding.ServicePubkey))
	fmt.Printf("  authorization_nonce:  %d\n", binding.AuthorizationNonce.Uint64())
	fmt.Printf("  revoked_height:       %d\n", binding.RevokedHeight.Uint64())
	fmt.Printf("  status:               %s\n", binding.Status)
}

func printRequest(endpoint string, key builderclient.TaskDataKey, request builderclient.TaskDataRequestAuth, observedHeight uint64) {
	fmt.Printf("\n== GetTaskDataMetadata request ==\n")
	fmt.Printf("  endpoint:             %s\n", endpoint)
	fmt.Printf("  method:               %s\n", request.Method)
	fmt.Printf("  chain_id:             %s\n", request.ChainID)
	fmt.Printf("  builder_address:      %s\n", request.BuilderAddress)
	fmt.Printf("  key.session_id:       %s\n", key.SessionID)
	fmt.Printf("  key.task_id:          %s\n", key.TaskID)
	fmt.Printf("  key.task_hash:        %s\n", key.TaskHash)
	fmt.Printf("  key.content_hash:     %s\n", key.ContentHash)
	fmt.Printf("  key.data_kind:        %s\n", key.Kind)
	fmt.Printf("  requester:            %s (operator address)\n", request.Requester)
	fmt.Printf("  authorization_nonce:  %d\n", request.ServiceAuthorizationNonce)
	fmt.Printf("  request_nonce:        %s\n", hex.EncodeToString(request.RequestNonce))
	fmt.Printf("  expires_at_height:    %d (expiry_blocks %d, height observed here %d)\n",
		request.ExpiresAtHeight, probeExpiryBlocks, observedHeight)
	fmt.Printf("  body_digest:          %x (metadata object reference)\n", request.BodyDigest[:])
	fmt.Printf("  signature:            %s (%d bytes, secp256k1 over TaskDataRequestSigningHash)\n",
		hex.EncodeToString(request.Signature), len(request.Signature))
}

func pubkeyFingerprint(pubkeyHex string) string {
	raw, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return "unavailable: public key is not hex"
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// readNexusToken mirrors the daemon's nexus.auth_token_file handling. The token
// is never printed.
func readNexusToken(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read Nexus token file: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// bech32HRP derives the signer prefix from a bech32 address, matching the
// runtime so a local key file does not have to repeat it.
func bech32HRP(address string) string {
	if separator := strings.LastIndexByte(address, '1'); separator > 0 {
		return address[:separator]
	}
	return ""
}

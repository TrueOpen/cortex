package builderclient_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
)

const (
	envRealBuilderEndpoint  = "CORTEX_TEST_BUILDER_ENDPOINT"
	envRealBuilderOperator  = "CORTEX_TEST_BUILDER_OPERATOR"
	envRealBuilderKeeper    = "CORTEX_TEST_BUILDER_KEEPER_RPC"
	envRealBuilderChainID   = "CORTEX_TEST_BUILDER_CHAIN_ID"
	envRealBuilderSigner    = "CORTEX_TEST_BUILDER_SIGNER_URI"
	envRealBuilderKeyRef    = "CORTEX_TEST_BUILDER_KEY_REF"
	envRealBuilderPassFile  = "CORTEX_TEST_BUILDER_PASSWORD_FILE"
	envRealBuilderOperator2 = "CORTEX_TEST_BUILDER_REQUESTER_OPERATOR"
)

// A signed task-data request against a REAL Builder ingress.
//
// Everything else about the task-data client is covered against an in-process
// connect-go server, which cannot answer two questions: does the grpc:// scheme
// actually dial a deployed ingress, and does a request this node signs satisfy
// the authorization Nexus applies. Both are on the critical path — a Worker that
// admits an order still has to fetch its input from the receiving Builder — and
// both were unverified.
//
// The task will not exist, so the informative outcome is WHICH refusal comes
// back. A transport error means the scheme support is wrong. A structured Nexus
// error means the dial, the Connect protocol and the request shape all worked and
// only the task is missing.
//
// What this deliberately does NOT establish is whether the Builder verifies our
// signature. Corrupting it is refused in 0.05s rather than the 1.03s a round trip
// takes, because ingress() validates the signed request locally before dialling
// (validateSignedTaskDataRequest). The request therefore never reaches the peer,
// and since the peer answers a well-formed request at its task-authority lookup,
// nothing here shows what it would do with a bad signature on a task it has.
// TestSignedTaskDataRequestIsValidatedBeforeItLeavesTheProcess covers the local
// half; the remote half needs a task that exists.
func TestSignedTaskDataRequestAgainstRealBuilder(t *testing.T) {
	endpoint := strings.TrimSpace(os.Getenv(envRealBuilderEndpoint))
	if endpoint == "" {
		t.Skipf("set %s to run the real Builder task-data probe", envRealBuilderEndpoint)
	}
	for _, required := range []string{envRealBuilderOperator, envRealBuilderKeeper, envRealBuilderSigner, envRealBuilderKeyRef} {
		if strings.TrimSpace(os.Getenv(required)) == "" {
			t.Skipf("set %s as well", required)
		}
	}
	builderOperator := strings.TrimSpace(os.Getenv(envRealBuilderOperator))
	keeperRPC := strings.TrimSpace(os.Getenv(envRealBuilderKeeper))
	chainID := strings.TrimSpace(os.Getenv(envRealBuilderChainID))
	if chainID == "" {
		chainID = "trueopen-localnet-1"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	keyRef := strings.TrimSpace(os.Getenv(envRealBuilderKeyRef))
	signingClient, err := signer.Open(strings.TrimSpace(os.Getenv(envRealBuilderSigner)), signer.OpenOptions{
		PasswordFile: strings.TrimSpace(os.Getenv(envRealBuilderPassFile)),
		HRP:          "trueopen",
		// The loader only opens the refs it is told about, the way cortexd passes
		// local_identity.service_key_ref.
		KeyRefs: []signer.KeyRef{{Ref: keyRef}},
	})
	if err != nil {
		t.Fatalf("signer.Open() error = %v", err)
	}
	local, ok := signingClient.(*signer.LocalSigner)
	if !ok {
		t.Skipf("this probe needs a file:// keystore to read its own address; got %T", signingClient)
	}
	var descriptor signer.KeyDescriptor
	for _, candidate := range local.Keys() {
		if candidate.Ref == keyRef {
			descriptor = candidate
		}
	}
	if descriptor.Address == "" {
		t.Fatalf("keystore has no key %q; it has %+v", keyRef, local.Keys())
	}
	servicePubkey := descriptor.CompressedPubkey
	t.Logf("signing identity: address=%s key_ref=%s pubkey=%s", descriptor.Address, keyRef, servicePubkey)

	requesterOperator := strings.TrimSpace(os.Getenv(envRealBuilderOperator2))
	if requesterOperator == "" {
		requesterOperator = descriptor.Address
	}

	keeper := chainclient.NewKeeperABCIClient(keeperRPC)
	auth, err := taskdataauth.New(taskdataauth.Config{
		ServiceKeys:     keeper,
		Signer:          signingClient,
		ChainID:         chainID,
		OperatorAddress: requesterOperator,
		ServiceAddress:  descriptor.Address,
		ServicePubkey:   servicePubkey,
		ServiceKeyRef:   keyRef,
		ExpiryBlocks:    20,
	})
	if err != nil {
		t.Fatalf("taskdataauth.New() error = %v", err)
	}

	key := builderclient.TaskDataKey{
		TaskHash: strings.Repeat("33", 32), ContentHash: strings.Repeat("44", 32),
		SessionID: strings.Repeat("11", 32),
		TaskID:    strings.Repeat("22", 32),
		Kind:      builderclient.DataKindInput,
	}
	bodyDigest, err := builderclient.TaskDataMetadataBodyDigest(key)
	if err != nil {
		t.Fatal(err)
	}
	requestAuth, err := auth.SignRequest(ctx, "GetTaskDataMetadata", key, builderOperator, bodyDigest)
	if err != nil {
		// A failure here is this node's own chain read or signing, not the
		// Builder's, so it is reported as such rather than blamed on the peer.
		t.Fatalf("SignRequest() error = %v (local chain read or signing, not the Builder)", err)
	}
	t.Logf("signed request: requester=%s builder=%s expires_at_height=%d signature=%dB",
		requestAuth.Requester, requestAuth.BuilderAddress, requestAuth.ExpiresAtHeight, len(requestAuth.Signature))

	client := builderclient.NewConnectTaskDataClientWithDefaults("", builderclient.TaskDataTransport{
		// The devnet ingress publishes grpc://, which is plaintext.
		AllowInsecureEndpoint: true,
	})
	metadata, err := client.GetTaskDataMetadata(ctx, endpoint, builderclient.GetTaskDataMetadataRequest{
		Key: key, Auth: requestAuth,
	})
	if err == nil {
		t.Logf("GetTaskDataMetadata succeeded: %+v", metadata)
		return
	}

	t.Logf("GetTaskDataMetadata refused: retryable=%v err=%v", builderclient.IsRetryable(err), err)

	// A dial or protocol failure is one of the two things this test exists to
	// catch. Nexus answers a signed request for a task it does not have with a
	// structured error; a transport error means grpc:// never reached a Connect
	// server at all.
	lowered := strings.ToLower(err.Error())
	for _, transportFailure := range []string{
		"connection refused", "no such host", "i/o timeout", "context deadline exceeded",
		"tls", "malformed http", "unsupported protocol scheme",
		"must be an absolute", "scheme is not one of",
	} {
		if strings.Contains(lowered, transportFailure) {
			t.Fatalf("transport failure reaching %s: %v", endpoint, err)
		}
	}

	// The other thing: the request has to be well formed and authenticated well
	// enough for the Builder to get as far as looking up the task. Without this
	// the test would pass while our signing was rejected outright, which is the
	// failure mode it is here to detect.
	//
	// NEXUS_DATA_MALFORMED is what an empty or wrongly shaped body gets, so
	// seeing it means the request this client builds disagrees with what the
	// deployed Nexus expects.
	for _, ourFault := range []string{
		"nexus_data_malformed", "unauthenticated", "permission_denied", "nexus_data_unauthorized",
		// Our own pre-flight check. Seeing it here means the request never left
		// the process, so nothing about the peer was measured.
		"verify task data requester signature",
	} {
		if strings.Contains(lowered, ourFault) {
			t.Fatalf("this request was refused before the task lookup, so the probe measured nothing about the Builder: %v", err)
		}
	}
	t.Logf("reached the Builder's own task-authority lookup")
}

// The client refuses to put a request on the wire whose signature does not match
// the auth it carries. That is a local guard, not the peer's, and knowing which
// is which is the point: a probe against a real Builder that trips this measured
// nothing remote at all.
func TestSignedTaskDataRequestIsValidatedBeforeItLeavesTheProcess(t *testing.T) {
	client := builderclient.NewConnectTaskDataClientWithDefaults("", builderclient.TaskDataTransport{
		AllowInsecureEndpoint: true,
	})
	key := builderclient.TaskDataKey{
		TaskHash: strings.Repeat("33", 32), ContentHash: strings.Repeat("44", 32),
		SessionID: strings.Repeat("11", 32),
		TaskID:    strings.Repeat("22", 32),
		Kind:      builderclient.DataKindInput,
	}
	// An endpoint that would fail to dial: if the guard did not fire first, the
	// error would name the transport instead.
	const unreachable = "grpc://127.0.0.1:1"
	_, err := client.GetTaskDataMetadata(context.Background(), unreachable, builderclient.GetTaskDataMetadataRequest{
		Key: key,
		Auth: builderclient.TaskDataRequestAuth{
			Method: builderclient.TaskDataProcedure("GetTaskDataMetadata"), Signature: make([]byte, 64),
		},
	})
	if err == nil {
		t.Fatal("GetTaskDataMetadata() = nil, want a refusal before the dial")
	}
	if strings.Contains(strings.ToLower(err.Error()), "connection refused") {
		t.Fatalf("the request was dialled before its auth was checked: %v", err)
	}
}

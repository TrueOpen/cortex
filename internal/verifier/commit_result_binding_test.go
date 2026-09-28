package verifier

// The commit-to-reveal binding, asserted across the two stages that produce it.
//
// The Keeper accepts a commit WITHOUT recomputing commit_hash - it stores the
// value it is handed. The recomputation happens when a full reveal arrives: the
// Keeper re-derives commit_hash from the ResultReceiptState's
// verifier_value_root and salt and requires equality with CommitState. So a
// commit derived by any other formula is accepted, written to state, and
// counted toward StartRevealPhase, and only fails a whole task lifecycle later.
//
// Those two fields and no others: ResultCommitmentV3 binds the value root, the
// salt and the task/round/verifier identity, and the v0.3.3 vector says so in
// as many words ("The V3 commit binds only the Verifier value root and salt,
// not the reveal payload hash"). Naming the reveal payload digests here instead
// would promise a binding this test cannot check, because the commit does not
// carry them.
//
// No single-stage test can see that. Every assertion here therefore spans both
// stages: it takes the commit this node actually submitted and the credential
// this node actually published, and performs the Keeper's own re-derivation.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/txclient"
)

// TestSubmittedCommitReDerivesFromThePublishedCredential re-derives the commit
// hash the chain received from the credential the Verifier later publishes,
// against real output of both halves: the chain accepts the reveal only if
// that re-derivation matches.
//
// It is the check that would have caught an earlier formula that hashed a
// different field list under a different domain, which no re-derivation of
// the frozen preimage could ever have matched.
func TestSubmittedCommitReDerivesFromThePublishedCredential(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true

	result := verifyLocally(t, h, state)
	revealLocally(t, h, state)

	// The commit as the chain received it, decoded from the submitted tx rather
	// than read off the in-memory result: CommitState is written from these
	// bytes, so these are the bytes the re-derivation is compared against.
	requests := h.tx.Requests()
	if len(requests) != 1 || requests[0].Kind != txclient.MsgSubmitVerifyCommit {
		t.Fatalf("tx requests = %#v, want exactly one MsgSubmitVerifyCommit", requests)
	}
	submittedCommitHash := submittedCommitHash(t, requests[0])

	// The credential as the bus received it. metric_root, metric_summary,
	// aggregate_proof_hash and result_reveal_hash all become ResultReceiptState.
	receipt := publishedResultReceipt(t, h)

	// Rule 5, performed exactly as the Keeper performs it.
	_ = result
	reDerived, err := nodewire.ResultCommitmentHash(nodewire.ResultCommitmentV3{
		ChainID:                 receipt.ChainID,
		TaskID:                  receipt.TaskID,
		TaskHash:                servedTaskFacts(state.TaskID).AcceptedTaskHash,
		VerifyRound:             receipt.VerifyRound,
		VerifierOperatorAddress: receipt.VerifierOperatorAddress,
		VerifierValueRoot:       receipt.VerifierValueRoot,
		Salt:                    receipt.Salt,
	})
	if err != nil {
		t.Fatalf("re-derive commit_hash: %v", err)
	}
	if !bytes.Equal(reDerived[:], submittedCommitHash) {
		t.Fatalf("the Keeper's reveal re-derivation would reject this reveal:\n"+
			"  CommitState.commit_hash   = %x\n"+
			"  re-derived from the receipt = %s\n"+
			"The commit and the credential describe different material.", submittedCommitHash, reDerived)
	}
}

// Each of the two Hash32 fields the commit binds must actually change the
// commit. Otherwise "the commit commits to the reveal" would be a claim about
// the formula rather than about the value.
func TestEachBoundFieldChangesTheCommitHash(t *testing.T) {
	base := nodewire.ResultCommitmentV3{
		ChainID:                 "chain-A",
		TaskID:                  bytes.Repeat([]byte{0x11}, 32),
		TaskHash:                bytes.Repeat([]byte{0x44}, 32),
		VerifyRound:             1,
		VerifierOperatorAddress: fixtureVerifierAddress,
		VerifierValueRoot:       bytes.Repeat([]byte{0x22}, 32),
		Salt:                    bytes.Repeat([]byte{0x33}, 32),
	}
	unchanged, err := nodewire.ResultCommitmentHash(base)
	if err != nil {
		t.Fatalf("ResultCommitmentHash returned error: %v", err)
	}
	for name, mutate := range map[string]func(*nodewire.ResultCommitmentV3){
		"chain_id":                  func(c *nodewire.ResultCommitmentV3) { c.ChainID = "chain-B" },
		"task_id":                   func(c *nodewire.ResultCommitmentV3) { c.TaskID[0] ^= 0xff },
		"verify_round":              func(c *nodewire.ResultCommitmentV3) { c.VerifyRound = 2 },
		"verifier_operator_address": func(c *nodewire.ResultCommitmentV3) { c.VerifierOperatorAddress = fixtureOtherVerifierAddress },
		"task_hash":                 func(c *nodewire.ResultCommitmentV3) { c.TaskHash[0] ^= 0xff },
		"verifier_value_root":       func(c *nodewire.ResultCommitmentV3) { c.VerifierValueRoot[0] ^= 0xff },
		"salt":                      func(c *nodewire.ResultCommitmentV3) { c.Salt[0] ^= 0xff },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := base
			mutated.TaskID = append([]byte(nil), base.TaskID...)
			mutated.TaskHash = append([]byte(nil), base.TaskHash...)
			mutated.VerifierValueRoot = append([]byte(nil), base.VerifierValueRoot...)
			mutated.Salt = append([]byte(nil), base.Salt...)
			mutate(&mutated)
			changed, err := nodewire.ResultCommitmentHash(mutated)
			if err != nil {
				t.Fatalf("ResultCommitmentHash returned error: %v", err)
			}
			if changed == unchanged {
				t.Fatalf("changing %s did not change commit_hash", name)
			}
		})
	}
}

// The commit is derived from the SAME metric material the credential carries,
// not from a second run of the pipeline. A verify that produced material and a
// reveal that re-derived its own would pass the re-derivation above by accident
// only as long as both happened to be deterministic; this pins the source.
func TestCommitBindsTheRunsOwnMetricMaterial(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true

	result := verifyLocally(t, h, state)
	revealLocally(t, h, state)
	receipt := publishedResultReceipt(t, h)

	if !bytes.Equal(receipt.AggregateProofHash, result.MetricMaterial.AggregateProof.Hash[:]) {
		t.Fatalf("the credential's aggregate_proof_hash %x is not the verify run's %s",
			receipt.AggregateProofHash, result.MetricMaterial.AggregateProof.Hash)
	}
	if !bytes.Equal(receipt.MetricRoot, result.MetricMaterial.Root[:]) {
		t.Fatalf("the credential's metric_root %x is not the verify run's %s",
			receipt.MetricRoot, result.MetricMaterial.Root)
	}
}

// submittedCommitHash reads commit_hash out of the transaction payload the
// broadcaster was handed - the bytes CommitState is written from - rather than
// off any in-memory struct.
func submittedCommitHash(t *testing.T, request txclient.Request) []byte {
	t.Helper()
	var submitted txclient.SubmitVerifyCommitMessage
	if err := json.Unmarshal(request.Payload, &submitted); err != nil {
		t.Fatalf("decode submitted MsgSubmitVerifyCommit: %v", err)
	}
	raw, err := hex.DecodeString(submitted.Commit.CommitHash.Hex())
	if err != nil {
		t.Fatalf("decode submitted commit_hash: %v", err)
	}
	return raw
}

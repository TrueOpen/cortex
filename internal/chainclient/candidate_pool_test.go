package chainclient

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// newVerifierWindowServer answers CommittedHeight plus one
// Query/VerifierCandidateWindow, either with the application's refusal or with a
// window state.
func newVerifierWindowServer(t testing.TB, committedHeight uint64, refusal map[string]any, window *taskv1.QueryVerifierCandidateWindowResponse) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encode := func(result any) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": -1, "result": result})
		}
		switch r.URL.Path {
		case "/abci_info":
			encode(map[string]any{"response": map[string]any{
				"last_block_height": strconv.FormatUint(committedHeight, 10),
			}})
		case "/abci_query":
			height := r.URL.Query().Get("height")
			if refusal != nil {
				response := map[string]any{"height": height}
				for key, value := range refusal {
					response[key] = value
				}
				encode(map[string]any{"response": response})
				return
			}
			payload, err := marshalTestProto(window)
			if err != nil {
				t.Fatalf("marshal window: %v", err)
			}
			encode(map[string]any{"response": map[string]any{
				"code": 0, "value": base64.StdEncoding.EncodeToString(payload), "height": height,
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func verifierWindowTaskID() string {
	return strings.Repeat("ab", 32)
}

// The window header is written SOURCE_FROZEN in the same block that accepts the
// infer receipt and only turns READY once the Beacon at h_window lands, and
// Keeper answers FailedPrecondition for the whole gap
// (keeper-interface-contract §4.4, §10.3). interface-and-topic-list.md §5.9 tells the caller to wait
// there, so this answer has to be distinguishable from a fault by the caller
// rather than only by an operator reading the message.
func TestVerifierCandidateWindowFailedPreconditionIsNotYetRatherThanAFault(t *testing.T) {
	server := newVerifierWindowServer(t, 44400, map[string]any{
		"code":      18,
		"codespace": "task",
		"log":       "rpc error: code = FailedPrecondition desc = verifier candidate window is not materialized",
	}, nil)

	_, err := NewKeeperABCIClient(server.URL).VerifierCandidateMember(
		context.Background(), verifierWindowTaskID(), 1, "trueopen1verifier",
	)
	if !errors.Is(err, ErrVerifierWindowNotReady) {
		t.Fatalf("VerifierCandidateMember() error = %v, want one wrapping ErrVerifierWindowNotReady", err)
	}
	// The chain's own words survive the classification: an operator still reads
	// which query refused and why.
	if !strings.Contains(err.Error(), "not materialized") {
		t.Fatalf("error = %q, want the Keeper detail preserved", err)
	}
}

// The same wait reaches the caller the other way round: the window row exists
// and is readable, and its status says SOURCE_FROZEN.
func TestVerifierCandidateWindowSourceFrozenStatusIsTheSameWait(t *testing.T) {
	rawTaskID, _ := hex.DecodeString(verifierWindowTaskID())
	server := newVerifierWindowServer(t, 44400, nil, &taskv1.QueryVerifierCandidateWindowResponse{
		Window: &taskv1.VerifierCandidateWindowState{
			SchemaVersion: 1, TaskId: rawTaskID, VerifyRound: 1, Status: 1,
		},
	})

	_, err := NewKeeperABCIClient(server.URL).VerifierCandidateMember(
		context.Background(), verifierWindowTaskID(), 1, "trueopen1verifier",
	)
	if !errors.Is(err, ErrVerifierWindowNotReady) {
		t.Fatalf("VerifierCandidateMember() error = %v, want one wrapping ErrVerifierWindowNotReady", err)
	}
}

// A READY window whose fields contradict the contract is a fault, not a wait:
// waiting for it would be waiting for something that already arrived wrong.
func TestVerifierCandidateWindowMalformedReadyWindowIsNotAWait(t *testing.T) {
	rawTaskID, _ := hex.DecodeString(verifierWindowTaskID())
	server := newVerifierWindowServer(t, 44400, nil, &taskv1.QueryVerifierCandidateWindowResponse{
		Window: &taskv1.VerifierCandidateWindowState{
			SchemaVersion: 1, TaskId: rawTaskID, VerifyRound: 1, Status: 2,
			InferReceiptHash: []byte("short"),
		},
	})

	_, err := NewKeeperABCIClient(server.URL).VerifierCandidateMember(
		context.Background(), verifierWindowTaskID(), 1, "trueopen1verifier",
	)
	if err == nil || errors.Is(err, ErrVerifierWindowNotReady) {
		t.Fatalf("VerifierCandidateMember() error = %v, want a refusal that is not a wait", err)
	}
}

// A READY window whose handraise interval has already closed is neither a wait
// nor a malformed window, and it used to be reported as the latter.
//
// Keeper does not prune the window at its close height: it keeps answering READY
// with all its members, so every window on a chain answers this way a few blocks
// after its task. Calling that "fields are invalid" left a caller with no way to
// tell "the draw has not happened yet" from "the draw is over" -- and a node
// waiting for the first one has to be able to stop at the second.
func TestVerifierCandidateWindowPastItsCloseHeightIsClosedRatherThanMalformed(t *testing.T) {
	rawTaskID, _ := hex.DecodeString(verifierWindowTaskID())
	server := newVerifierWindowServer(t, 44400, nil, &taskv1.QueryVerifierCandidateWindowResponse{
		Window: &taskv1.VerifierCandidateWindowState{
			SchemaVersion: 1, TaskId: rawTaskID, VerifyRound: 1, Status: 2,
			InferReceiptHash: []byte(strings.Repeat("r", 32)), CandidatePoolSnapshotId: []byte(strings.Repeat("s", 32)),
			HandraiseCloseHeight: 44380,
		},
		Members: []*taskv1.VerifierCandidateWindowMemberState{{
			SchemaVersion: 1, TaskId: rawTaskID, VerifyRound: 1, Slot: 3, SlotVersion: 1,
			OperatorAddress: "trueopen1verifier",
		}},
	})

	_, err := NewKeeperABCIClient(server.URL).VerifierCandidateMember(
		context.Background(), verifierWindowTaskID(), 1, "trueopen1verifier",
	)
	if !errors.Is(err, ErrVerifierWindowClosed) {
		t.Fatalf("VerifierCandidateMember() error = %v, want one wrapping ErrVerifierWindowClosed", err)
	}
	if errors.Is(err, ErrVerifierWindowNotReady) {
		t.Fatalf("a closed window was reported as a wait: %v", err)
	}
	// Both heights stay in the message: which interval closed, and how far past
	// it this node was, is the difference between "a block late" and "never
	// asked".
	if !strings.Contains(err.Error(), "handraise_close_height=44380") || !strings.Contains(err.Error(), "committed_height=44400") {
		t.Fatalf("error = %q, want both heights preserved", err)
	}
}

// A READY window this operator is simply not in is the expected outcome of every
// lost candidacy, and it is not a wait either.
func TestVerifierCandidateWindowWithoutThisOperatorIsNotAWait(t *testing.T) {
	rawTaskID, _ := hex.DecodeString(verifierWindowTaskID())
	server := newVerifierWindowServer(t, 44400, nil, &taskv1.QueryVerifierCandidateWindowResponse{
		Window: &taskv1.VerifierCandidateWindowState{
			SchemaVersion: 1, TaskId: rawTaskID, VerifyRound: 1, Status: 2,
			InferReceiptHash: []byte(strings.Repeat("r", 32)), CandidatePoolSnapshotId: []byte(strings.Repeat("s", 32)),
			HandraiseCloseHeight: 44500,
		},
		Members: []*taskv1.VerifierCandidateWindowMemberState{{
			SchemaVersion: 1, TaskId: rawTaskID, VerifyRound: 1, Slot: 3, SlotVersion: 1,
			OperatorAddress: "trueopen1someone-else",
		}},
	})

	_, err := NewKeeperABCIClient(server.URL).VerifierCandidateMember(
		context.Background(), verifierWindowTaskID(), 1, "trueopen1verifier",
	)
	if err == nil || errors.Is(err, ErrVerifierWindowNotReady) {
		t.Fatalf("VerifierCandidateMember() error = %v, want the plain not-selected refusal", err)
	}
}

// The devnet record this pair is built from: a selected Verifier is admitted at
// open_verify_height=586, the window it raised its hand in closed at 581, and
// the chain keeps answering READY with that member in it for the rest of the
// round. 06-challenge-and-evidence.md §5.1 orders handraise_close_height -> Beacon B ->
// selection_height, so a verify execution is always past the close height and
// the two readings must disagree there. The handraise reading refuses, because
// no handraise for that round can be accepted again; the frozen reading answers,
// because the member row is what it asks about and the chain still holds it
// (keeper-data-structure-contract.md keeps READY members until the round is final).
func closedButFrozenVerifierWindow(t testing.TB) *httptest.Server {
	t.Helper()
	rawTaskID, _ := hex.DecodeString(verifierWindowTaskID())
	return newVerifierWindowServer(t, 586, nil, &taskv1.QueryVerifierCandidateWindowResponse{
		Window: &taskv1.VerifierCandidateWindowState{
			SchemaVersion: 1, TaskId: rawTaskID, VerifyRound: 1, Status: 2,
			InferReceiptHash: []byte(strings.Repeat("r", 32)), CandidatePoolSnapshotId: []byte(strings.Repeat("s", 32)),
			HandraiseCloseHeight: 581,
		},
		Members: []*taskv1.VerifierCandidateWindowMemberState{{
			SchemaVersion: 1, TaskId: rawTaskID, VerifyRound: 1, Slot: 3, SlotVersion: 7,
			OperatorAddress: "trueopen1verifier",
		}},
	})
}

func TestFrozenVerifierWindowMemberAnswersAfterTheHandraiseIntervalClosed(t *testing.T) {
	server := closedButFrozenVerifierWindow(t)

	member, err := NewKeeperABCIClient(server.URL).FrozenVerifierWindowMember(
		context.Background(), verifierWindowTaskID(), 1, "trueopen1verifier",
	)
	if err != nil {
		t.Fatalf("FrozenVerifierWindowMember() error = %v, want the frozen member row", err)
	}
	if member.OperatorAddress != "trueopen1verifier" || member.Slot != 3 || member.SlotVersion != 7 {
		t.Fatalf("member = %+v, want slot 3 version 7 for trueopen1verifier", member)
	}
	// The close height is still what the handraise expiry was, and the receipt
	// hash still comes from the window rather than the caller -- dropping the
	// gate must not drop the values the verify path reconciles against Keeper.
	if member.ExpiryHeight != 581 {
		t.Fatalf("ExpiryHeight = %d, want the frozen handraise close height 581", member.ExpiryHeight)
	}
	if got := string(member.InferReceiptHash); got != strings.Repeat("r", 32) {
		t.Fatalf("InferReceiptHash = %q, want the window's", got)
	}
}

// The relaxation is scoped to the frozen reading. If it leaked into the
// handraise reading, a candidate that missed its window would go back to
// signing a handraise no Keeper can accept.
func TestVerifierCandidateMemberStillRefusesTheSameClosedWindow(t *testing.T) {
	server := closedButFrozenVerifierWindow(t)

	_, err := NewKeeperABCIClient(server.URL).VerifierCandidateMember(
		context.Background(), verifierWindowTaskID(), 1, "trueopen1verifier",
	)
	if !errors.Is(err, ErrVerifierWindowClosed) {
		t.Fatalf("VerifierCandidateMember() error = %v, want one wrapping ErrVerifierWindowClosed", err)
	}
}

// Everything other than the close height is shared, so the frozen reading must
// keep failing closed on the states no reading can repair: a window still
// waiting for its Beacon, and a READY window this operator is not in.
func TestFrozenVerifierWindowMemberKeepsEveryOtherRefusal(t *testing.T) {
	rawTaskID, _ := hex.DecodeString(verifierWindowTaskID())

	t.Run("window without members is still a wait", func(t *testing.T) {
		server := newVerifierWindowServer(t, 44400, nil, &taskv1.QueryVerifierCandidateWindowResponse{
			Window: &taskv1.VerifierCandidateWindowState{
				SchemaVersion: 1, TaskId: rawTaskID, VerifyRound: 1, Status: 1,
				InferReceiptHash: []byte(strings.Repeat("r", 32)), CandidatePoolSnapshotId: []byte(strings.Repeat("s", 32)),
				HandraiseCloseHeight: 44380,
			},
		})
		_, err := NewKeeperABCIClient(server.URL).FrozenVerifierWindowMember(
			context.Background(), verifierWindowTaskID(), 1, "trueopen1verifier",
		)
		if !errors.Is(err, ErrVerifierWindowNotReady) {
			t.Fatalf("error = %v, want one wrapping ErrVerifierWindowNotReady", err)
		}
	})

	t.Run("operator not in the frozen set is refused", func(t *testing.T) {
		server := newVerifierWindowServer(t, 44400, nil, &taskv1.QueryVerifierCandidateWindowResponse{
			Window: &taskv1.VerifierCandidateWindowState{
				SchemaVersion: 1, TaskId: rawTaskID, VerifyRound: 1, Status: 2,
				InferReceiptHash: []byte(strings.Repeat("r", 32)), CandidatePoolSnapshotId: []byte(strings.Repeat("s", 32)),
				HandraiseCloseHeight: 44380,
			},
			Members: []*taskv1.VerifierCandidateWindowMemberState{{
				SchemaVersion: 1, TaskId: rawTaskID, VerifyRound: 1, Slot: 3, SlotVersion: 1,
				OperatorAddress: "trueopen1someone-else",
			}},
		})
		_, err := NewKeeperABCIClient(server.URL).FrozenVerifierWindowMember(
			context.Background(), verifierWindowTaskID(), 1, "trueopen1verifier",
		)
		if err == nil || errors.Is(err, ErrVerifierWindowNotReady) || errors.Is(err, ErrVerifierWindowClosed) {
			t.Fatalf("error = %v, want the plain not-selected refusal", err)
		}
	})

	t.Run("malformed READY window is still invalid", func(t *testing.T) {
		server := newVerifierWindowServer(t, 44400, nil, &taskv1.QueryVerifierCandidateWindowResponse{
			Window: &taskv1.VerifierCandidateWindowState{
				SchemaVersion: 1, TaskId: rawTaskID, VerifyRound: 1, Status: 2,
				InferReceiptHash: []byte(strings.Repeat("r", 32)), CandidatePoolSnapshotId: []byte(strings.Repeat("s", 32)),
				HandraiseCloseHeight: 0,
			},
		})
		_, err := NewKeeperABCIClient(server.URL).FrozenVerifierWindowMember(
			context.Background(), verifierWindowTaskID(), 1, "trueopen1verifier",
		)
		if err == nil || !strings.Contains(err.Error(), "fields are invalid") {
			t.Fatalf("error = %v, want the malformed-window refusal", err)
		}
	})
}

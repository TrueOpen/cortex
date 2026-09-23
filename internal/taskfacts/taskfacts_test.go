package taskfacts

import (
	"bytes"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

const factsTestTaskID = "1111111111111111111111111111111111111111111111111111111111111111"

func served(taskID string) Facts {
	return Facts{
		TaskID: taskID,
		TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
			AcceptedTaskHash:       chainclient.ProtoBytes32(bytes.Repeat([]byte{0x22}, 32)),
			GenerationParamsDigest: chainclient.ProtoBytes32(bytes.Repeat([]byte{0x33}, 32)),
		},
	}
}

func TestValidateAcceptsAnAnswerForTheTaskInHand(t *testing.T) {
	if err := served(factsTestTaskID).Validate(factsTestTaskID); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestValidateSeparatesItsThreeRefusals is the whole point of this type. Each
// case is a well-formed answer a receipt path must not use, and each has a
// different operator response: fix the caller, wait for the chain to carry the
// value, or investigate a Keeper serving zeros. A single "invalid facts" error
// would send all three to the same wrong place.
func TestValidateSeparatesItsThreeRefusals(t *testing.T) {
	zero := make(chainclient.ProtoBytes32, 32)
	other := "2222222222222222222222222222222222222222222222222222222222222222"
	for name, tc := range map[string]struct {
		facts    Facts
		taskID   string
		contains string
	}{
		"answered for another task": {served(other), factsTestTaskID, "not the task"},
		"caller has no identity":    {served(factsTestTaskID), "", "need the task identity"},
		"absent accepted_task_hash": {
			Facts{TaskID: factsTestTaskID, TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
				GenerationParamsDigest: served(factsTestTaskID).GenerationParamsDigest,
			}},
			factsTestTaskID, "carries no accepted_task_hash",
		},
		"absent generation_params_digest": {
			Facts{TaskID: factsTestTaskID, TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
				AcceptedTaskHash: served(factsTestTaskID).AcceptedTaskHash,
			}},
			factsTestTaskID, "carries no generation_params_digest",
		},
		"all-zero accepted_task_hash": {
			Facts{TaskID: factsTestTaskID, TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
				AcceptedTaskHash:       zero,
				GenerationParamsDigest: served(factsTestTaskID).GenerationParamsDigest,
			}},
			factsTestTaskID, "all-zero accepted_task_hash",
		},
		"all-zero generation_params_digest": {
			Facts{TaskID: factsTestTaskID, TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
				AcceptedTaskHash:       served(factsTestTaskID).AcceptedTaskHash,
				GenerationParamsDigest: zero,
			}},
			factsTestTaskID, "all-zero generation_params_digest",
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.facts.Validate(tc.taskID)
			if err == nil || !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("Validate error = %v, want it to say %q", err, tc.contains)
			}
		})
	}
}

// TestValidateDoesNotConflateAbsentWithZero pins the distinction chainclient's
// ProtoBytes32 exists to preserve. The two states are both refused, but they are
// refused for different stated reasons, because "the view did not carry it" and
// "consensus holds 32 zero bytes" are different facts about the chain.
func TestValidateDoesNotConflateAbsentWithZero(t *testing.T) {
	absent := Facts{TaskID: factsTestTaskID, TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
		GenerationParamsDigest: served(factsTestTaskID).GenerationParamsDigest,
	}}
	zeroed := absent
	zeroed.AcceptedTaskHash = make(chainclient.ProtoBytes32, 32)

	absentErr := absent.Validate(factsTestTaskID)
	zeroErr := zeroed.Validate(factsTestTaskID)
	if absentErr == nil || zeroErr == nil {
		t.Fatalf("absent = %v, zero = %v, want both refused", absentErr, zeroErr)
	}
	if absentErr.Error() == zeroErr.Error() {
		t.Fatalf("absent and all-zero produced one indistinguishable refusal: %v", absentErr)
	}
	if absent.AcceptedTaskHash.IsSet() {
		t.Fatal("an absent ProtoBytes32 reports IsSet, so consumers could not tell it from a value")
	}
	if !zeroed.AcceptedTaskHash.IsSet() {
		t.Fatal("an all-zero ProtoBytes32 must report IsSet: it is a claim, not a gap")
	}
}

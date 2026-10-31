package chainclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// VerifyCommitSnapshot is one verifier's CommitState row (task.v1.Query/VerifyCommit).
type VerifyCommitSnapshot struct {
	Height                  uint64
	TaskID                  []byte
	VerifyRound             uint32
	VerifierOperatorAddress string
	CommitKey               []byte
	CommitHash              []byte
}

// VerifyCommitReader is what the reveal gate needs (CD §6.2 V13).
type VerifyCommitReader interface {
	VerifyCommit(ctx context.Context, taskID string, verifyRound uint32, verifierOperator string) (VerifyCommitSnapshot, error)
}

var _ VerifyCommitReader = (*KeeperABCIClient)(nil)

// VerifyCommit reads this verifier's commit row at the committed height. An
// absent row is ErrNotFound: the Keeper holds no commit from this operator.
func (c *KeeperABCIClient) VerifyCommit(ctx context.Context, taskID string, verifyRound uint32, verifierOperator string) (VerifyCommitSnapshot, error) {
	taskIDBytes, err := decodeTaskIDHash32(taskID)
	if err != nil || hex.EncodeToString(taskIDBytes) != taskID {
		return VerifyCommitSnapshot{}, fmt.Errorf("verify commit task_id must be canonical Hash32 hex")
	}
	if verifyRound == 0 || strings.TrimSpace(verifierOperator) == "" {
		return VerifyCommitSnapshot{}, fmt.Errorf("verify commit round and verifier operator are required")
	}
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return VerifyCommitSnapshot{}, err
	}
	var response taskv1.QueryVerifyCommitResponse
	if err := c.query(ctx, taskQuery+"VerifyCommit", height, &taskv1.QueryVerifyCommitRequest{
		TaskId: taskIDBytes, VerifyRound: verifyRound, VerifierOperatorAddress: verifierOperator,
	}, &response); err != nil {
		return VerifyCommitSnapshot{}, err
	}
	row := response.GetCommit()
	if row == nil || !bytes.Equal(row.GetTaskId(), taskIDBytes) || row.GetVerifyRound() != verifyRound ||
		row.GetVerifierOperatorAddress() != verifierOperator || len(row.GetCommitHash()) != 32 || len(row.GetCommitKey()) != 32 {
		return VerifyCommitSnapshot{}, fmt.Errorf("Keeper VerifyCommit answered another or a malformed commit row")
	}
	return VerifyCommitSnapshot{
		Height: height, TaskID: taskIDBytes, VerifyRound: verifyRound, VerifierOperatorAddress: verifierOperator,
		CommitKey: append([]byte(nil), row.GetCommitKey()...), CommitHash: append([]byte(nil), row.GetCommitHash()...),
	}, nil
}

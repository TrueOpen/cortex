package chainclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// SelectedTaskBuildersReader reads the frozen Task Builder selection of one task.
type SelectedTaskBuildersReader interface {
	SelectedTaskBuilders(ctx context.Context, taskID string) ([]string, error)
}

// SelectedTaskBuilders returns the task's frozen Task Builder list, in the order
// the chain froze it.
//
// The order is load-bearing twice over and must not be sorted, deduplicated into
// a set, or otherwise normalised by a caller. It is the order the Worker relays
// in, and it is the index order MsgReportDataUnavailable's Builder bitmap is
// defined against (keeper-data-structure-contract §6.5); that message refuses a
// bitmap with out-of-range or trailing bits, so a reordered list does not
// degrade a report, it produces a rejected tx.
//
// Every check here is a fail-closed one. A partial or stale selection is worse
// than no selection: relaying to a subset while believing it is the whole set is
// exactly the failure this read exists to remove.
func (c *KeeperABCIClient) SelectedTaskBuilders(ctx context.Context, taskID string) ([]string, error) {
	taskIDBytes, err := decodeTaskIDHash32(taskID)
	if err != nil || hex.EncodeToString(taskIDBytes) != taskID || bytes.Equal(taskIDBytes, make([]byte, 32)) {
		return nil, fmt.Errorf("task builders task_id must be canonical non-zero Hash32 hex")
	}
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return nil, err
	}
	var response taskv1.QueryTaskBuildersResponse
	if err := c.query(ctx, taskQuery+"TaskBuilders", height, &taskv1.QueryTaskBuildersRequest{TaskId: taskIDBytes}, &response); err != nil {
		return nil, err
	}
	return validateSelectedTaskBuilders(response.Selection, taskIDBytes)
}

// validateSelectedTaskBuilders is the one place the selection view is checked, so
// the Worker relay path and the settlement path cannot disagree about what a
// usable selection is.
func validateSelectedTaskBuilders(selection *taskv1.TaskBuilderSelectionViewV1, taskIDBytes []byte) ([]string, error) {
	if selection == nil || !bytes.Equal(selection.TaskId, taskIDBytes) ||
		selection.BodyStatus != sharedv1.StoredBodyStatus_STORED_BODY_STATUS_ACTIVE ||
		selection.SelectedTaskBuilderCount == 0 ||
		uint64(len(selection.SelectedTaskBuilders)) != uint64(selection.SelectedTaskBuilderCount) {
		return nil, fmt.Errorf("TaskBuilders identity, active body or selected count is invalid")
	}
	seen := make(map[string]bool, len(selection.SelectedTaskBuilders))
	for _, builder := range selection.SelectedTaskBuilders {
		if builder == "" || strings.TrimSpace(builder) != builder || seen[builder] {
			return nil, fmt.Errorf("TaskBuilders contains an empty, non-canonical or duplicate member")
		}
		seen[builder] = true
	}
	// Returned as the response gave it, not as a copy of the map: the map exists
	// only to detect duplicates and has no order.
	return selection.SelectedTaskBuilders, nil
}

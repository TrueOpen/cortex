package chainclient

import (
	"context"
	"fmt"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// OutputStreamLimitsSnapshot reports current governed stream limits at one
// committed height. These are not immutable task assignment facts.
type OutputStreamLimitsSnapshot struct {
	MaxOutputMMRLeaves        uint64
	MinOutputStreamFrameBytes uint32
	SnapshotHeight            uint64
}

type OutputStreamLimitsReader interface {
	OutputStreamLimits(context.Context) (OutputStreamLimitsSnapshot, error)
}

// OutputStreamLimits reports the governed stream limits, reading them from the
// chain once and retaining them for as long as this client lives.
//
// Both limits are genesis-only, so a second read can only return what the first
// one did. It is not free, though: the read is a committed-height query and a
// params query, one after the other, and it sits between a task being admitted
// and its generation starting. On devnet that pair measured 291ms, which was 7%
// of the first frame the caller waited for, paid again on every task.
//
// Retaining it for the life of the client is the same contract Nexus holds for
// the same two parameters, which it reads once at startup: a chain relaunch
// means restarting the node. The exposure if that is skipped is bounded and
// loud in the direction that matters -- a stale minimum that is too small makes
// the Builder reject the frames, which fails the stream rather than weakening
// the floor.
//
// A failed read is not retained, so a chain that is briefly unreachable does
// not leave this node serving that error for the rest of its life.
func (c *KeeperABCIClient) OutputStreamLimits(ctx context.Context) (OutputStreamLimitsSnapshot, error) {
	// Held across the read so that tasks admitted together collapse into one
	// query instead of one each. After the first success it is a pointer read.
	c.outputStreamLimitsMu.Lock()
	defer c.outputStreamLimitsMu.Unlock()
	if c.outputStreamLimits != nil {
		return *c.outputStreamLimits, nil
	}
	snapshot, err := c.readOutputStreamLimits(ctx)
	if err != nil {
		return OutputStreamLimitsSnapshot{}, err
	}
	c.outputStreamLimits = &snapshot
	return snapshot, nil
}

func (c *KeeperABCIClient) readOutputStreamLimits(ctx context.Context) (OutputStreamLimitsSnapshot, error) {
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return OutputStreamLimitsSnapshot{}, err
	}
	var response taskv1.QueryTaskParamsResponse
	if err := c.query(ctx, taskQuery+"Params", height, &taskv1.QueryTaskParamsRequest{}, &response); err != nil {
		return OutputStreamLimitsSnapshot{}, err
	}
	params := response.GetParams()
	evidence := params.GetEvidence()
	if params.GetSchemaVersion() != 1 || evidence.GetMaxOutputMmrLeaves() == 0 || evidence.GetMinOutputStreamFrameBytes() == 0 {
		return OutputStreamLimitsSnapshot{}, fmt.Errorf("Keeper output stream limits require current Task params and positive leaf/frame limits")
	}
	return OutputStreamLimitsSnapshot{
		MaxOutputMMRLeaves:        evidence.MaxOutputMmrLeaves,
		MinOutputStreamFrameBytes: evidence.MinOutputStreamFrameBytes,
		SnapshotHeight:            height,
	}, nil
}

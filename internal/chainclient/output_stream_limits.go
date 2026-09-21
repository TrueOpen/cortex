package chainclient

import (
	"context"
	"fmt"

	taskv1 "github.com/SingaXYZ/cortex/proto/task/v1"
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

func (c *KeeperABCIClient) OutputStreamLimits(ctx context.Context) (OutputStreamLimitsSnapshot, error) {
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

package daemon

import (
	"context"
	"fmt"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
)

// taskDataFetchRangeBytes bounds each signed range a Verifier asks a Builder
// for. Nexus refuses any range longer than its task_data.max_range_bytes
// (default 8 MiB) with NEXUS_DATA_RANGE_INVALID, and a fetch without a range
// asks for the whole object, so an object above that limit -- a long
// output's WORKER_VALUE_OPENING is ~0.94 KB per token, and the profile allows
// it up to 1 GiB -- can only be read in ranges. Half the Builder default
// leaves room for a Builder configured below it without approaching the
// per-request overhead of many tiny ranges.
const taskDataFetchRangeBytes = uint64(4 << 20)

// fetchTaskDataRanges reads the size bytes of key from one Builder as
// consecutive signed ranges of at most rangeBytes, appending them to data
// (passed empty; its capacity is the caller's preallocation). Every frame must
// continue at the confirmed offset, stay inside its range and carry EOF exactly
// at the range end. A retryable failure part-way through a range resumes at the
// last confirmed byte under a fresh signature; any other failure, a range
// refusal included, is returned for the caller to try the next Builder. The
// caller binds the whole object to its commitment.
func fetchTaskDataRanges(ctx context.Context, client builderclient.TaskDataClient, auth *taskdataauth.Authenticator,
	endpoint, builderOperator string, key builderclient.TaskDataKey, size, rangeBytes uint64, data []byte) ([]byte, error) {
	if rangeBytes == 0 {
		return nil, fmt.Errorf("task-data range size must be positive")
	}
	confirmedOffset := uint64(0)
	for confirmedOffset < size {
		rangeEnd := confirmedOffset + min(rangeBytes, size-confirmedOffset)
		for confirmedOffset < rangeEnd {
			attemptOffset := confirmedOffset
			requestedRange := &builderclient.TaskDataRange{Offset: attemptOffset, Length: rangeEnd - attemptOffset}
			signed, err := auth.SignFetch(ctx, key, builderOperator, requestedRange)
			if err != nil {
				return nil, err
			}
			err = client.FetchTaskData(ctx, endpoint, builderclient.FetchTaskDataRequest{Key: key, Range: requestedRange, Auth: signed}, func(chunk builderclient.TaskDataChunk) error {
				if chunk.Offset != confirmedOffset {
					return fmt.Errorf("task-data chunk offset %d does not match confirmed offset %d", chunk.Offset, confirmedOffset)
				}
				if len(chunk.Data) == 0 {
					return fmt.Errorf("task-data chunk at offset %d is empty", chunk.Offset)
				}
				chunkBytes := uint64(len(chunk.Data))
				if chunkBytes > rangeEnd-confirmedOffset {
					return fmt.Errorf("task-data chunk at offset %d exceeds the requested range", chunk.Offset)
				}
				chunkEnd := confirmedOffset + chunkBytes
				if chunk.EOF != (chunkEnd == rangeEnd) {
					return fmt.Errorf("task-data EOF at offset %d does not match the requested range boundary", chunkEnd)
				}
				data = append(data, chunk.Data...)
				confirmedOffset = chunkEnd
				return nil
			})
			switch {
			case err == nil && confirmedOffset != rangeEnd:
				return nil, fmt.Errorf("task-data range ended at offset %d before requested offset %d", confirmedOffset, rangeEnd)
			case err == nil:
				// This signed range is complete.
			case builderclient.IsRetryable(err) && confirmedOffset > attemptOffset && confirmedOffset < rangeEnd:
				// Resume only bytes the callback confirmed. SignFetch draws a fresh
				// nonce and height-bound expiry for the remaining responsibility.
				continue
			default:
				return nil, err
			}
		}
	}
	if confirmedOffset != size || uint64(len(data)) != size {
		return nil, fmt.Errorf("task-data object size %d does not match declared size %d", confirmedOffset, size)
	}
	return data, nil
}

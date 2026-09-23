package daemon

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
)

const (
	defaultTaskDataRangeBytes = uint64(1 << 20)
	defaultTaskDataMaxBytes   = uint64(64 << 20)
	// The auth window is deliberately short and chain-height bound. It is not
	// operator configuration: every retry obtains the current height again.
	inputTaskDataExpiryBlocks = uint64(20)
)

// NexusTaskInputResolverConfig wires the real-mode task input path. TaskData is
// transport-only; endpoint and request authority always come from chain-backed
// collaborators.
type NexusTaskInputResolverConfig struct {
	TaskData      builderclient.TaskDataClient
	Endpoints     BuilderEndpointResolver
	Auth          *taskdataauth.Authenticator
	RangeBytes    uint64
	MaxInputBytes uint64
}

// NexusTaskInputResolver fetches plaintext input from the Builder that received
// the task and accepts it only when the complete bytes match Keeper's payload
// commitment.
type NexusTaskInputResolver struct {
	cfg NexusTaskInputResolverConfig
}

func NewNexusTaskInputResolver(cfg NexusTaskInputResolverConfig) (*NexusTaskInputResolver, error) {
	switch {
	case cfg.TaskData == nil:
		return nil, fmt.Errorf("Nexus task input resolver requires a task-data client")
	case cfg.Endpoints == nil:
		return nil, fmt.Errorf("Nexus task input resolver requires a Builder endpoint resolver")
	case cfg.Auth == nil:
		return nil, fmt.Errorf("Nexus task input resolver requires a task-data authenticator")
	}
	if cfg.RangeBytes == 0 {
		cfg.RangeBytes = defaultTaskDataRangeBytes
	}
	if cfg.MaxInputBytes == 0 || cfg.MaxInputBytes > defaultTaskDataMaxBytes {
		cfg.MaxInputBytes = defaultTaskDataMaxBytes
	}
	return &NexusTaskInputResolver{cfg: cfg}, nil
}

func (r *NexusTaskInputResolver) ResolveTaskInput(ctx context.Context, ref TaskInputRef) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(ref.SessionID) == "" || strings.TrimSpace(ref.SessionID) != ref.SessionID ||
		strings.TrimSpace(ref.TaskID) == "" || strings.TrimSpace(ref.TaskID) != ref.TaskID {
		return nil, fmt.Errorf("Keeper task input identity must be canonical")
	}
	builderOperator := strings.TrimSpace(ref.BuilderOperatorAddress)
	if builderOperator == "" || builderOperator != ref.BuilderOperatorAddress {
		return nil, fmt.Errorf("Keeper task snapshot for %s does not name a canonical receiving Builder", ref.TaskID)
	}
	if ref.PayloadHash.IsZero() {
		return nil, fmt.Errorf("Keeper accepted order payload hash for %s is required", ref.TaskID)
	}
	var input []byte
	err := dialBuilder(ctx, r.cfg.Endpoints, builderOperator, func(ctx context.Context, endpoint BuilderEndpoint) error {
		got, err := r.resolveFrom(ctx, endpoint, builderOperator, ref)
		input = got
		return err
	})
	if err != nil {
		return nil, err
	}
	return input, nil
}

// resolveFrom fetches the input from an already-resolved Builder (with ctx already
// checking the certificate against its fingerprint).
func (r *NexusTaskInputResolver) resolveFrom(ctx context.Context, endpoint BuilderEndpoint, builderOperator string, ref TaskInputRef) ([]byte, error) {
	key := builderclient.TaskDataKey{TaskHash: ref.TaskHash.String(), SessionID: ref.SessionID, TaskID: ref.TaskID, Kind: builderclient.DataKindInput, ContentHash: ref.PayloadHash.String()}

	// If the signed order carried a size, try to fetch the object directly. The
	// signed order is authoritative: the Builder is expected to hold exactly the
	// bytes committed by the user. GetTaskDataMetadata is reserved for the
	// failure path, where it provides the precise reason (object gone, retention
	// lapsed, size mismatch) instead of a bare transport error.
	if err := r.validateSizeBounds(ref.InputSizeBytes); err != nil {
		return nil, err
	}
	if ref.InputSizeBytes > 0 {
		input, fetchErr := r.fetchTaskInput(ctx, endpoint.Endpoint, builderOperator, key, ref, ref.InputSizeBytes)
		if fetchErr == nil {
			return input, nil
		}
		// Fall back to metadata for a precise diagnostic, but do not use the
		// metadata size as the source of truth.
		metadata, err := r.getMetadata(ctx, endpoint.Endpoint, builderOperator, key)
		if err != nil {
			return nil, fetchErr
		}
		if validateErr := r.validateMetadata(ref, metadata); validateErr != nil {
			return nil, validateErr
		}
		return nil, fetchErr
	}

	// No authoritative size: metadata is required before we can allocate.
	metadata, err := r.getMetadata(ctx, endpoint.Endpoint, builderOperator, key)
	if err != nil {
		return nil, err
	}
	if err := r.validateMetadata(ref, metadata); err != nil {
		return nil, err
	}
	return r.fetchTaskInput(ctx, endpoint.Endpoint, builderOperator, key, ref, metadata.SizeBytes)
}

func (r *NexusTaskInputResolver) validateSizeBounds(sizeBytes uint64) error {
	if sizeBytes == 0 {
		return nil
	}
	if sizeBytes > r.cfg.MaxInputBytes {
		return fmt.Errorf("task-data size %d exceeds input limit %d", sizeBytes, r.cfg.MaxInputBytes)
	}
	maxInt := uint64(^uint(0) >> 1)
	if sizeBytes > maxInt {
		return fmt.Errorf("task-data size %d exceeds local allocation capacity", sizeBytes)
	}
	return nil
}

func (r *NexusTaskInputResolver) getMetadata(ctx context.Context, endpoint, builderOperator string, key builderclient.TaskDataKey) (builderclient.TaskDataMetadata, error) {
	digest, err := builderclient.TaskDataMetadataBodyDigest(key)
	if err != nil {
		return builderclient.TaskDataMetadata{}, err
	}
	auth, err := r.cfg.Auth.SignRequest(ctx, "GetTaskDataMetadata", key, builderOperator, digest)
	if err != nil {
		return builderclient.TaskDataMetadata{}, err
	}
	return r.cfg.TaskData.GetTaskDataMetadata(ctx, endpoint, builderclient.GetTaskDataMetadataRequest{Key: key, Auth: auth})
}

func (r *NexusTaskInputResolver) fetchTaskInput(ctx context.Context, endpoint, builderOperator string, key builderclient.TaskDataKey, ref TaskInputRef, sizeBytes uint64) ([]byte, error) {
	input := make([]byte, int(sizeBytes))
	confirmedOffset := uint64(0)
	for confirmedOffset < sizeBytes {
		remaining := sizeBytes - confirmedOffset
		rangeLength := r.cfg.RangeBytes
		if rangeLength > remaining {
			rangeLength = remaining
		}
		rangeEnd := confirmedOffset + rangeLength

		for confirmedOffset < rangeEnd {
			attemptOffset := confirmedOffset
			requestedRange := &builderclient.TaskDataRange{Offset: attemptOffset, Length: rangeEnd - attemptOffset}
			auth, err := r.cfg.Auth.SignFetch(ctx, key, builderOperator, requestedRange)
			if err != nil {
				return nil, err
			}
			err = r.cfg.TaskData.FetchTaskData(ctx, endpoint, builderclient.FetchTaskDataRequest{Key: key, Range: requestedRange, Auth: auth}, func(chunk builderclient.TaskDataChunk) error {
				if chunk.Offset != confirmedOffset {
					return fmt.Errorf("task-data chunk offset %d does not match confirmed offset %d", chunk.Offset, confirmedOffset)
				}
				if len(chunk.Data) == 0 {
					return fmt.Errorf("task-data chunk at offset %d is empty", chunk.Offset)
				}
				chunkBytes := uint64(len(chunk.Data))
				if chunkBytes > sizeBytes-confirmedOffset || chunkBytes > rangeEnd-confirmedOffset {
					return fmt.Errorf("task-data chunk at offset %d exceeds the declared input bounds", chunk.Offset)
				}
				chunkEnd := confirmedOffset + chunkBytes
				if chunk.EOF != (chunkEnd == rangeEnd) {
					return fmt.Errorf("task-data EOF at offset %d does not match the declared input boundary", chunkEnd)
				}
				copy(input[confirmedOffset:chunkEnd], chunk.Data)
				confirmedOffset = chunkEnd
				return nil
			})
			switch {
			case err == nil && confirmedOffset != rangeEnd:
				return nil, fmt.Errorf("task-data range ended at offset %d before requested offset %d", confirmedOffset, rangeEnd)
			case err == nil:
				// This signed range is complete.
			case builderclient.IsRetryable(err) && confirmedOffset > attemptOffset && confirmedOffset < rangeEnd:
				// Resume only bytes the callback confirmed. SignRange draws a fresh
				// nonce and height-bound expiry for the remaining responsibility.
				continue
			default:
				return nil, err
			}
		}
	}
	if confirmedOffset != sizeBytes || uint64(len(input)) != sizeBytes {
		return nil, fmt.Errorf("task-data input size %d does not match declared size %d", confirmedOffset, sizeBytes)
	}
	actualDigest := sha256.Sum256(input)
	if actualDigest != codec.Hash(ref.PayloadHash) {
		return nil, fmt.Errorf("task-data input digest %x does not match Keeper accepted payload hash %s", actualDigest, ref.PayloadHash.String())
	}
	return input, nil
}

func (r *NexusTaskInputResolver) validateMetadata(ref TaskInputRef, metadata builderclient.TaskDataMetadata) error {
	if metadata.Readiness != builderclient.TaskDataReady {
		return fmt.Errorf("receiving Builder has no task-data input for %s", ref.TaskID)
	}
	if metadata.Key.ContentHash != ref.PayloadHash.String() || metadata.Key.TaskHash != ref.TaskHash.String() || metadata.Key.TaskID != ref.TaskID || metadata.Key.SessionID != ref.SessionID || metadata.Key.Kind != builderclient.DataKindInput {
		return fmt.Errorf("task-data metadata object does not match Keeper accepted input")
	}
	if metadata.SizeBytes == 0 {
		return fmt.Errorf("task-data metadata size must be positive")
	}
	if metadata.SizeBytes > r.cfg.MaxInputBytes {
		return fmt.Errorf("task-data metadata size %d exceeds input limit %d", metadata.SizeBytes, r.cfg.MaxInputBytes)
	}
	maxInt := uint64(^uint(0) >> 1)
	if metadata.SizeBytes > maxInt {
		return fmt.Errorf("task-data metadata size %d exceeds local allocation capacity", metadata.SizeBytes)
	}
	return nil
}

package identity

import (
	"encoding/hex"
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

const TaskIDDomain = "TRUEOPEN_TASK_ID_V1"

type TaskIdentity struct {
	ChainID       string
	SessionID     string
	OrderSequence uint64
	OrderDigest   codec.Hash
	TaskID        codec.Hash
}

func NewTaskIdentity(chainID, sessionID string, orderSequence uint64, orderDigest codec.Hash) TaskIdentity {
	return TaskIdentity{
		ChainID:       chainID,
		SessionID:     sessionID,
		OrderSequence: orderSequence,
		OrderDigest:   orderDigest,
		TaskID:        TaskID(sessionID, orderSequence),
	}
}

// TaskID derives the frozen V1 task identity from a raw Hash32 session and a
// uint64 order sequence. External JSON carries session_id as canonical
// lowercase hex; it is decoded before H_FIELDS_V1 framing.
//
// Invalid external session text returns the zero hash. Every production caller
// either compares the result against a non-zero wire task_id or validates the
// resulting SignedEnvelope, both of which fail closed on zero.
func TaskID(sessionID string, orderSequence uint64) codec.Hash {
	taskID, err := deriveTaskID(sessionID, orderSequence)
	if err != nil {
		return codec.Hash{}
	}
	return taskID
}

func TaskIDString(sessionID string, orderSequence uint64) string {
	taskID, err := deriveTaskID(sessionID, orderSequence)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(taskID[:])
}

func deriveTaskID(sessionID string, orderSequence uint64) (codec.Hash, error) {
	if len(sessionID) != hex.EncodedLen(len(codec.Hash{})) {
		return codec.Hash{}, fmt.Errorf("session_id must be canonical lowercase Hash32 hex")
	}
	raw, err := hex.DecodeString(sessionID)
	if err != nil || hex.EncodeToString(raw) != sessionID {
		return codec.Hash{}, fmt.Errorf("session_id must be canonical lowercase Hash32 hex")
	}
	return hfields.Digest(TaskIDDomain, hfields.Bytes(raw), hfields.Uint64(orderSequence))
}

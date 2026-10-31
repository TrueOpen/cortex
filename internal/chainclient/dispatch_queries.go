package chainclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// beaconSourceProposerVRF is the BeaconState.source_tag of a proposer-VRF
// beacon. placeholder_blockhash_v1 entries are dev-only and never seed a
// dispatch draw (wire DispatchVrfInputV1.epoch_seed).
const beaconSourceProposerVRF = "proposer_vrf_v1"

// DispatchEpochSnapshot is the chain half of dispatchwire.TicketContext's
// epoch inputs, read at one committed height.
type DispatchEpochSnapshot struct {
	Height            uint64 // committed height every read was pinned to
	EpochLengthBlocks uint64
	// BeaconHeight is EpochOf(earliest_submit_height) * epoch_length: the
	// reference height a ticket must carry. Zero for epoch zero.
	BeaconHeight uint64
	Randomness   []byte // raw R_h; nil when no beacon is committed there
	// Verified is BeaconState.verified on a proposer_vrf_v1 entry. Only then
	// may the caller build dispatchwire.NewVerifiedBeacon from this snapshot.
	Verified bool
}

// DispatchEpochAt reads, at height (which must have come from
// CommittedHeight), the Hub epoch length and the beacon at the start of the
// epoch earliestSubmitHeight falls in. A beacon that is missing, placeholder,
// unverified or not committed by height comes back with Verified=false, and
// wire's ResolveEpochSeed then refuses the ticket. There is no substitute
// seed.
func (c *KeeperABCIClient) DispatchEpochAt(ctx context.Context, earliestSubmitHeight, height uint64) (DispatchEpochSnapshot, error) {
	if height == 0 {
		return DispatchEpochSnapshot{}, fmt.Errorf("dispatch epoch query height is required")
	}
	var params hubv1.QueryHubParamsResponse
	if err := c.query(ctx, hubQuery+"Params", height, &hubv1.QueryHubParamsRequest{}, &params); err != nil {
		return DispatchEpochSnapshot{}, err
	}
	length := params.GetParams().GetEpoch().GetEpochLengthBlocks()
	if length == 0 {
		return DispatchEpochSnapshot{}, fmt.Errorf("Keeper Hub epoch_length_blocks is zero")
	}
	out := DispatchEpochSnapshot{Height: height, EpochLengthBlocks: length, BeaconHeight: earliestSubmitHeight / length * length}
	if out.BeaconHeight == 0 || out.BeaconHeight > height {
		return out, nil
	}
	var response hubv1.QueryBeaconResponse
	err := c.query(ctx, hubQuery+"Beacon", height, &hubv1.QueryBeaconRequest{Height: out.BeaconHeight}, &response)
	if errors.Is(err, ErrNotFound) {
		return out, nil
	}
	if err != nil {
		return DispatchEpochSnapshot{}, err
	}
	b := response.GetBeacon()
	if b.GetHeight() != out.BeaconHeight {
		return DispatchEpochSnapshot{}, fmt.Errorf("Keeper beacon query for height %d answered height %d", out.BeaconHeight, b.GetHeight())
	}
	raw, err := hex.DecodeString(b.GetRandomnessHex())
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != b.GetRandomnessHex() {
		return DispatchEpochSnapshot{}, fmt.Errorf("Keeper beacon at %d: randomness_hex is not canonical 32-byte hex", out.BeaconHeight)
	}
	out.Randomness = raw
	out.Verified = b.GetVerified() && b.GetSourceTag() == beaconSourceProposerVRF
	return out, nil
}

// SessionSnapshot is the part of task.v1.StreamState the dispatch prechecks
// read (CD §5.1 checks 2 and 2a).
type SessionSnapshot struct {
	Height                 uint64
	SessionID              []byte
	OwnerUserAddress       string
	Status                 string // ACTIVE, IDLE or CLOSED
	BoundBuilder           string
	BoundChangeHeight      uint64
	SessionKey             []byte // raw20 delegated order key; nil: wallet-only
	SessionKeySetHeight    uint64
	SessionKeyExpiryHeight uint64
}

// Session is SessionAt the latest committed height.
func (c *KeeperABCIClient) Session(ctx context.Context, sessionID []byte) (SessionSnapshot, error) {
	if len(sessionID) != 32 {
		return SessionSnapshot{}, fmt.Errorf("session_id is %d bytes, want 32", len(sessionID))
	}
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return SessionSnapshot{}, err
	}
	return c.SessionAt(ctx, sessionID, height)
}

// SessionAt reads StreamState for a raw 32-byte session_id at height, which
// must have come from CommittedHeight. A compacted or unknown session is
// ErrNotFound.
func (c *KeeperABCIClient) SessionAt(ctx context.Context, sessionID []byte, height uint64) (SessionSnapshot, error) {
	if len(sessionID) != 32 {
		return SessionSnapshot{}, fmt.Errorf("session_id is %d bytes, want 32", len(sessionID))
	}
	if height == 0 {
		return SessionSnapshot{}, fmt.Errorf("session query height is required")
	}
	var response taskv1.QuerySessionResponse
	if err := c.query(ctx, taskQuery+"Session", height, &taskv1.QuerySessionRequest{SessionId: sessionID}, &response); err != nil {
		return SessionSnapshot{}, err
	}
	s := response.GetSession()
	if s == nil || !bytes.Equal(s.GetSessionId(), sessionID) {
		return SessionSnapshot{}, fmt.Errorf("Keeper Session answered for another session")
	}
	out := SessionSnapshot{
		Height: height, SessionID: append([]byte(nil), sessionID...), OwnerUserAddress: s.GetOwnerUserAddress(),
		Status: strings.TrimPrefix(s.GetStatus().String(), "SESSION_STATUS_"), BoundBuilder: s.GetBoundBuilder(),
		BoundChangeHeight: s.GetBoundChangeHeight(), SessionKeySetHeight: s.GetSessionKeySetHeight(),
		SessionKeyExpiryHeight: s.GetSessionKeyExpiryHeight(),
	}
	if key := s.GetSessionKey(); len(key) > 0 {
		if len(key) != 20 {
			return SessionSnapshot{}, fmt.Errorf("Keeper session_key is %d bytes, want raw20", len(key))
		}
		out.SessionKey = append([]byte(nil), key...)
	}
	return out, nil
}

// DispatchParamsSnapshot is task.v1 DispatchParamsV1 at one committed height.
// S4 reads record_deadline_blocks; S5 and S6 read the windows.
type DispatchParamsSnapshot struct {
	Height                        uint64
	RecordDeadlineBlocks          uint64
	CompensationClaimWindowBlocks uint64
	CompensationRebuttalBlocks    uint64
	ChallengeWindowBlocks         uint64
	ChallengeResponseBlocks       uint64
	EvidenceRetentionBlocks       uint64
	MaxPrerecordOutputTokens      uint64
}

// DispatchParams is DispatchParamsAt the latest committed height.
func (c *KeeperABCIClient) DispatchParams(ctx context.Context) (DispatchParamsSnapshot, error) {
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return DispatchParamsSnapshot{}, err
	}
	return c.DispatchParamsAt(ctx, height)
}

// DispatchParamsAt reads the Task module's dispatch parameters at height,
// which must have come from CommittedHeight.
func (c *KeeperABCIClient) DispatchParamsAt(ctx context.Context, height uint64) (DispatchParamsSnapshot, error) {
	if height == 0 {
		return DispatchParamsSnapshot{}, fmt.Errorf("dispatch params query height is required")
	}
	var response taskv1.QueryTaskParamsResponse
	if err := c.query(ctx, taskQuery+"Params", height, &taskv1.QueryTaskParamsRequest{}, &response); err != nil {
		return DispatchParamsSnapshot{}, err
	}
	params := response.GetParams()
	d := params.GetDispatch()
	if params.GetSchemaVersion() != 1 || d == nil || d.GetRecordDeadlineBlocks() == 0 {
		return DispatchParamsSnapshot{}, fmt.Errorf("Keeper Task params carry no dispatch record_deadline_blocks")
	}
	return DispatchParamsSnapshot{
		Height: height, RecordDeadlineBlocks: d.GetRecordDeadlineBlocks(),
		CompensationClaimWindowBlocks: d.GetDispatchCompensationClaimWindowBlocks(),
		CompensationRebuttalBlocks:    d.GetDispatchCompensationRebuttalBlocks(),
		ChallengeWindowBlocks:         d.GetDispatchChallengeWindowBlocks(),
		ChallengeResponseBlocks:       d.GetDispatchChallengeResponseBlocks(),
		EvidenceRetentionBlocks:       d.GetDispatchEvidenceRetentionBlocks(),
		MaxPrerecordOutputTokens:      d.GetMaxPrerecordOutputTokens(),
	}, nil
}

// WorkerLiabilityParamsSnapshot holds the Hub inputs of required_task_liability
// (KC §4.1): max(min_task_liability, ceil(order_value*coverage/10000),
// floor(effective_active_bond*slash/10000)).
type WorkerLiabilityParamsSnapshot struct {
	Height                   uint64
	MinTaskLiability         uint64
	OrderCoverageBps         uint32
	ObjectiveForgerySlashBps uint32
}

// WorkerLiabilityParamsAt reads the Worker liability params at height, which
// must have come from CommittedHeight.
func (c *KeeperABCIClient) WorkerLiabilityParamsAt(ctx context.Context, height uint64) (WorkerLiabilityParamsSnapshot, error) {
	if height == 0 {
		return WorkerLiabilityParamsSnapshot{}, fmt.Errorf("liability params query height is required")
	}
	var response hubv1.QueryHubParamsResponse
	if err := c.query(ctx, hubQuery+"Params", height, &hubv1.QueryHubParamsRequest{}, &response); err != nil {
		return WorkerLiabilityParamsSnapshot{}, err
	}
	s := response.GetParams().GetService()
	if response.GetParams().GetSchemaVersion() != 2 || s == nil {
		return WorkerLiabilityParamsSnapshot{}, fmt.Errorf("Keeper Hub params carry no service block")
	}
	units := s.GetMinTaskLiability().GetAtomicUnits()
	minimum, err := strconv.ParseUint(units, 10, 64)
	if err != nil || strconv.FormatUint(minimum, 10) != units {
		return WorkerLiabilityParamsSnapshot{}, fmt.Errorf("Keeper min_task_liability %q is not a canonical uint64", units)
	}
	if s.GetTaskLiabilityOrderCoverageBps() > 10_000 || s.GetObjectiveForgerySlashBps() > 10_000 {
		return WorkerLiabilityParamsSnapshot{}, fmt.Errorf("Keeper liability bps exceed 10000")
	}
	return WorkerLiabilityParamsSnapshot{
		Height: height, MinTaskLiability: minimum,
		OrderCoverageBps: s.GetTaskLiabilityOrderCoverageBps(), ObjectiveForgerySlashBps: s.GetObjectiveForgerySlashBps(),
	}, nil
}

// BuilderSetAt reads the BuilderSet effective at height, which must have come
// from CommittedHeight, so membership can be judged beside other facts read
// at that height.
func (c *KeeperABCIClient) BuilderSetAt(ctx context.Context, height uint64) (BuilderSetSnapshot, error) {
	return c.builderSetAtHeight(ctx, height)
}

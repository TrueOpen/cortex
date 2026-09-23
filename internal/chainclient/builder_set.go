package chainclient

import (
	"context"
	"fmt"
	"strings"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
)

// BuilderSetSnapshot is the current active BuilderSet, read at one committed
// height. It is the chain's own answer to "which Builders does the network
// currently recognise", and it is the only admissible basis for that question:
// a configured operator address can narrow this set but must never widen it.
type BuilderSetSnapshot struct {
	BuilderSetVersion Uint64String `json:"builder_set_version"`
	BuilderSetID      string       `json:"builder_set_id"`
	SetHash           HexHash      `json:"builder_set_hash"`
	EffectiveHeight   Uint64String `json:"effective_height"`
	// Builders is the typed member list. Membership is re-validated on read
	// rather than trusted from the wire.
	Builders       []string     `json:"active_builders"`
	SnapshotHeight Uint64String `json:"snapshot_height"`
}

func (s BuilderSetSnapshot) Validate() error {
	if s.BuilderSetVersion.Uint64() == 0 {
		return fmt.Errorf("Keeper BuilderSet term is required")
	}
	if s.BuilderSetID == "" || s.BuilderSetID != strings.TrimSpace(s.BuilderSetID) {
		return fmt.Errorf("Keeper BuilderSet id is required and must be canonical")
	}
	if s.SetHash.IsZero() {
		return fmt.Errorf("Keeper BuilderSet hash is required")
	}
	if s.SnapshotHeight.Uint64() == 0 {
		return fmt.Errorf("Keeper BuilderSet snapshot height is required")
	}
	if s.EffectiveHeight.Uint64() > s.SnapshotHeight.Uint64() {
		return fmt.Errorf("Keeper BuilderSet effective height is in the future")
	}
	// No lower bound on the member count is asserted: how many Builders a live
	// network runs is a governance parameter, not a client assumption.
	if len(s.Builders) == 0 {
		return fmt.Errorf("Keeper BuilderSet has no active builders")
	}
	if hasDuplicateStrings(s.Builders) {
		return fmt.Errorf("Keeper BuilderSet must contain unique canonical builders")
	}
	return nil
}

// HasBuilder reports whether an operator is a member of this set. It compares
// canonical bech32 addresses exactly and refuses a non-canonical argument
// outright rather than normalising it: bech32 checksums are computed over the
// canonical lowercase string, so anything that needs trimming or case-folding to
// match is a different address. This is the primitive bus-sender authorization
// is built on, so a padded sender must not resolve to a member.
func (s BuilderSetSnapshot) HasBuilder(operatorAddress string) bool {
	if operatorAddress == "" || operatorAddress != strings.TrimSpace(operatorAddress) {
		return false
	}
	for _, builder := range s.Builders {
		if builder == operatorAddress {
			return true
		}
	}
	return false
}

// CommittedBuilderSet reads the BuilderSet effective at the latest committed
// height and reports that height. The height is queryable by construction, and
// the membership decision a caller derives is bound to the same read that
// produced the members. There is deliberately no term or set-id selector here:
// a caller asking "is this sender a Builder right now" must not be able to
// answer it from a historical set.
func (c *KeeperABCIClient) CommittedBuilderSet(ctx context.Context) (BuilderSetSnapshot, uint64, error) {
	committed, err := c.CommittedHeight(ctx)
	if err != nil {
		return BuilderSetSnapshot{}, 0, err
	}
	set, err := c.builderSetAtHeight(ctx, committed)
	if err != nil {
		return BuilderSetSnapshot{}, 0, err
	}
	return set, committed, nil
}

func (c *KeeperABCIClient) builderSetAtHeight(ctx context.Context, height uint64) (BuilderSetSnapshot, error) {
	if height == 0 {
		return BuilderSetSnapshot{}, fmt.Errorf("BuilderSet reads must be pinned to a committed height")
	}
	request := &hubv1.QueryBuilderSetRequest{Selector: &hubv1.QueryBuilderSetRequest_Height{Height: height}}
	var response hubv1.QueryBuilderSetResponse
	if _, err := c.queryServed(ctx, hubQuery+"BuilderSet", height, request, &response); err != nil {
		return BuilderSetSnapshot{}, err
	}
	view := response.Set
	switch view.BodyStatus {
	case sharedv1.StoredBodyStatus_STORED_BODY_STATUS_ACTIVE:
	case sharedv1.StoredBodyStatus_STORED_BODY_STATUS_PRUNED:
		// The member list is deleted while the count and hash are retained, so
		// the response cannot answer a membership question either way.
		return BuilderSetSnapshot{}, fmt.Errorf("Keeper BuilderSet %s body is pruned at height %d", view.BuilderSetId, height)
	default:
		return BuilderSetSnapshot{}, fmt.Errorf("Keeper BuilderSet body status %d is unsupported", view.BodyStatus)
	}
	setHash, err := hexHashFromBytes(view.BuilderSetHash, "BuilderSet hash")
	if err != nil {
		return BuilderSetSnapshot{}, err
	}
	// endpoint_count's counterpart: the keeper's own validator keeps
	// active_builder_count equal to the member list length, so a disagreement
	// means this is not the set consensus holds.
	if int(view.ActiveBuilderCount) != len(view.ActiveBuilders) {
		return BuilderSetSnapshot{}, fmt.Errorf("Keeper BuilderSet reports %d active builders and lists %d",
			view.ActiveBuilderCount, len(view.ActiveBuilders))
	}
	set := BuilderSetSnapshot{
		BuilderSetVersion: Uint64String(view.BuilderSetVersion),
		BuilderSetID:      view.BuilderSetId,
		SetHash:           setHash,
		EffectiveHeight:   Uint64String(view.EffectiveHeight),
		Builders:          append([]string(nil), view.ActiveBuilders...),
		SnapshotHeight:    Uint64String(height),
	}
	if err := set.Validate(); err != nil {
		return BuilderSetSnapshot{}, err
	}
	if set.SnapshotHeight.Uint64() > height {
		return BuilderSetSnapshot{}, fmt.Errorf("Keeper BuilderSet is newer than the pinned snapshot")
	}
	return set, nil
}

func hasDuplicateStrings(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || value != strings.TrimSpace(value) {
			return true
		}
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

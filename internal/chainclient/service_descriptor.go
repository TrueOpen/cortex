package chainclient

import (
	"context"
	"fmt"
	"strings"

	hubv1 "github.com/SingaXYZ/cortex/proto/hub/v1"
)

// Participant types accepted by the Hub identity queries.
const (
	ParticipantTypeBuilder    = "BUILDER"
	ParticipantTypeCortexNode = "CORTEX_NODE"
)

// BuilderStateSnapshot carries the Builder facts Cortex actually consumes. The
// row also publishes the Builder's current service address, pubkey and
// authorization nonce, and those are deliberately NOT projected here: the
// current service key is read through CurrentServiceKey, which reports the
// ACTIVE/REVOKED lifecycle alongside the key material. Handing out key material
// from this snapshot would hand out a pubkey with no status to gate on.
type BuilderStateSnapshot struct {
	Address                  string       `json:"builder_address"`
	CurrentServiceKeyStatus  string       `json:"current_service_key_status"`
	CurrentDescriptorVersion Uint64String `json:"current_descriptor_version"`
	RegisteredHeight         Uint64String `json:"registered_height"`
}

func (s BuilderStateSnapshot) Validate() error {
	if s.Address == "" || s.Address != strings.TrimSpace(s.Address) {
		return fmt.Errorf("Keeper Builder address is required and must be canonical")
	}
	switch s.CurrentServiceKeyStatus {
	case "ACTIVE", "REVOKED":
	default:
		return fmt.Errorf("Keeper Builder service key status %q is unsupported", s.CurrentServiceKeyStatus)
	}
	if s.RegisteredHeight.Uint64() == 0 {
		return fmt.Errorf("Keeper Builder registered height is required")
	}
	return nil
}

// Builder reads Builder state. snapshotHeight 0 reads the latest committed state;
// a non-zero height pins the read and MUST have come from CommittedHeight.
func (c *KeeperABCIClient) Builder(ctx context.Context, builderAddress string, snapshotHeight uint64) (BuilderStateSnapshot, error) {
	builder, _, err := c.builderAt(ctx, builderAddress, snapshotHeight)
	return builder, err
}

// CommittedBuilder reads Builder state from the latest committed state and
// reports the height it was served at. That height is what a caller pins the rest
// of a multi-read resolution to, so every read agrees on one queryable height.
func (c *KeeperABCIClient) CommittedBuilder(ctx context.Context, builderAddress string) (BuilderStateSnapshot, uint64, error) {
	committed, err := c.CommittedHeight(ctx)
	if err != nil {
		return BuilderStateSnapshot{}, 0, err
	}
	return c.builderAt(ctx, builderAddress, committed)
}

func (c *KeeperABCIClient) builderAt(ctx context.Context, builderAddress string, snapshotHeight uint64) (BuilderStateSnapshot, uint64, error) {
	if builderAddress == "" || builderAddress != strings.TrimSpace(builderAddress) {
		return BuilderStateSnapshot{}, 0, fmt.Errorf("Builder address is required and must be canonical")
	}
	request := &hubv1.QueryBuilderRequest{BuilderAddress: builderAddress}
	var response hubv1.QueryBuilderResponse
	served, err := c.queryServed(ctx, hubQuery+"Builder", snapshotHeight, request, &response)
	if err != nil {
		return BuilderStateSnapshot{}, 0, err
	}
	if response.Builder == nil {
		return BuilderStateSnapshot{}, 0, fmt.Errorf("Keeper Builder response has no builder state")
	}
	snapshot := BuilderStateSnapshot{
		Address:                  response.Builder.BuilderAddress,
		CurrentServiceKeyStatus:  strings.TrimPrefix(response.GetBuilder().GetCurrentServiceKeyStatus().String(), "SERVICE_KEY_STATUS_"),
		CurrentDescriptorVersion: Uint64String(response.Builder.CurrentDescriptorVersion),
		RegisteredHeight:         Uint64String(response.Builder.RegisteredHeight),
	}
	if err := snapshot.Validate(); err != nil {
		return BuilderStateSnapshot{}, 0, err
	}
	if snapshot.Address != builderAddress {
		return BuilderStateSnapshot{}, 0, fmt.Errorf("Keeper Builder response does not match query identity")
	}
	return snapshot, served, nil
}

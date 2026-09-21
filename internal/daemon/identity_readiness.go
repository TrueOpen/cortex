package daemon

import (
	"context"
	"fmt"
	"strings"

	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/config"
)

type KeeperIdentityReader interface {
	Params(context.Context) (chainclient.ParamsSnapshot, error)
	CortexNode(context.Context, string) (chainclient.CortexNodeSnapshot, error)
	ServiceBond(context.Context, string) (chainclient.ServiceBondSnapshot, error)
	CurrentServiceKey(context.Context, string, string, uint64) (chainclient.ServiceKeySnapshot, error)
	ModelCapability(context.Context, string, string, string) (chainclient.ModelCapabilitySnapshot, error)
	ModelSupport(context.Context, string, string, string) (chainclient.ModelSupportSnapshot, error)
}

func checkKeeperIdentity(ctx context.Context, identity config.LocalIdentityConfig, reader KeeperIdentityReader, currentHeight uint64) (string, error) {
	serviceAddress, err := checkKeeperCoreIdentity(ctx, identity, reader, currentHeight)
	if err != nil {
		return "", err
	}
	if err := checkKeeperModelReadiness(ctx, identity, reader); err != nil {
		return "", err
	}
	return serviceAddress, nil
}

func checkKeeperCoreIdentity(ctx context.Context, identity config.LocalIdentityConfig, reader KeeperIdentityReader, currentHeight uint64) (string, error) {
	key, err := checkKeeperCoreServiceKey(ctx, identity, reader, currentHeight)
	if err != nil {
		return "", err
	}
	return key.ServiceAddress, nil
}

func checkKeeperCoreServiceKey(ctx context.Context, identity config.LocalIdentityConfig, reader KeeperIdentityReader, currentHeight uint64) (chainclient.ServiceKeySnapshot, error) {
	if reader == nil {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("Keeper identity query client is required")
	}
	if currentHeight == 0 {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("current chain height is required for service key validation")
	}
	operator := strings.TrimSpace(identity.OperatorAddress)
	params, err := reader.Params(ctx)
	if err != nil {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("query Keeper params: %w", err)
	}
	if params.ServiceUnbondingPeriodBlocks.Uint64() == 0 || params.DailySupportWindowBlocks.Uint64() == 0 {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("Keeper params are incomplete")
	}

	node, err := reader.CortexNode(ctx, operator)
	if err != nil {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("query Keeper Cortex node: %w", err)
	}
	if err := node.Validate(); err != nil {
		return chainclient.ServiceKeySnapshot{}, err
	}
	if node.OperatorAddress != operator {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("Keeper Cortex node operator %q does not match configured %q", node.OperatorAddress, operator)
	}
	if node.Status != "ACTIVE" {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("Keeper Cortex node status %q is not ACTIVE", node.Status)
	}
	bond, err := reader.ServiceBond(ctx, operator)
	if err != nil {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("query Keeper service bond: %w", err)
	}
	if err := bond.Validate(); err != nil {
		return chainclient.ServiceKeySnapshot{}, err
	}
	if bond.OperatorAddress != operator {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("Keeper service bond operator does not match configured operator")
	}
	if !strings.EqualFold(bond.Status, "ACTIVE") {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("Keeper service bond status %q is not ACTIVE", bond.Status)
	}
	if bond.ActiveBond.Uint64() == 0 {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("Keeper service bond has no active bond")
	}

	key, err := reader.CurrentServiceKey(ctx, chainclient.ParticipantTypeCortexNode, operator, 0)
	if err != nil {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("query Keeper service key: %w", err)
	}
	if err := key.Validate(); err != nil {
		return chainclient.ServiceKeySnapshot{}, err
	}
	if !strings.EqualFold(key.ParticipantType, "CORTEX_NODE") || key.OperatorAddress != operator {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("Keeper current service key participant does not match configured operator")
	}
	if !strings.EqualFold(key.Status, "ACTIVE") {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("Keeper service key status %q is not ACTIVE", key.Status)
	}
	if revoked := key.RevokedHeight.Uint64(); revoked != 0 && revoked <= currentHeight {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("Keeper service key was revoked at height %d", revoked)
	}
	if key.ServiceAddress != node.CurrentServiceAddress || key.ServicePubkey != node.CurrentServicePubkey || key.AuthorizationNonce.Uint64() != node.AuthorizationNonce.Uint64() || key.CurrentDescriptorVersion != node.CurrentDescriptorVersion {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("Keeper Cortex node and current service key binding disagree")
	}
	return key, nil
}

func checkKeeperModelReadiness(ctx context.Context, identity config.LocalIdentityConfig, reader KeeperIdentityReader) error {
	if reader == nil {
		return fmt.Errorf("Keeper identity query client is required")
	}
	operator := strings.TrimSpace(identity.OperatorAddress)
	profiles, err := identity.ModelProfiles()
	if err != nil {
		return err
	}
	for _, profile := range profiles {
		profileVersion := fmt.Sprintf("%d", profile.ProfileVersion)
		capability, err := reader.ModelCapability(ctx, operator, profile.ModelID, profileVersion)
		if err != nil {
			return fmt.Errorf("query Keeper model capability %s@%s: %w", profile.ModelID, profileVersion, err)
		}
		if err := capability.Validate(); err != nil {
			return err
		}
		if capability.OperatorAddress != operator || capability.ModelID != profile.ModelID || capability.ProfileVersion.Uint32() != profile.ProfileVersion {
			return fmt.Errorf("Keeper model capability identity does not match %s@%s", profile.ModelID, profileVersion)
		}
		// Both capabilities are required now that duty selection is retired: a
		// node declares support for a profile as a Worker and as a Verifier, so
		// a Keeper record that enables only one of them describes a declaration
		// this binary can no longer make.
		if !capability.InferenceCapability {
			return fmt.Errorf("Keeper model capability does not enable WORKER inference for %s@%s", profile.ModelID, profileVersion)
		}
		if !capability.VerificationCapability {
			return fmt.Errorf("Keeper model capability does not enable VERIFIER verification for %s@%s", profile.ModelID, profileVersion)
		}
		support, err := reader.ModelSupport(ctx, operator, profile.ModelID, profileVersion)
		if err != nil {
			return fmt.Errorf("query Keeper model support %s@%s: %w", profile.ModelID, profileVersion, err)
		}
		if support.OperatorAddress != operator || support.ModelID != profile.ModelID || support.ProfileVersion.Uint32() != profile.ProfileVersion {
			return fmt.Errorf("Keeper model support identity does not match %s@%s", profile.ModelID, profileVersion)
		}
		if err := support.Validate(); err != nil {
			return err
		}
		if !support.DeclaredSupport {
			return fmt.Errorf("Keeper model support is not declared for %s@%s", profile.ModelID, profileVersion)
		}
	}
	return nil
}

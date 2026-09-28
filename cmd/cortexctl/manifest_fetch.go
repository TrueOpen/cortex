package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/TrueOpen/cortex/internal/adminapi"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/modelmanifest"
)

type currentProfileReader interface {
	CurrentModelProfile(ctx context.Context, modelID, profileVersion string) (chainclient.CurrentModelProfileSnapshot, error)
}

func keeperProfileReader(rpcEndpoint string) currentProfileReader {
	return chainclient.NewKeeperABCIClient(rpcEndpoint)
}

// newModelManifestFetchCommand obtains the full manifest of a registered
// profile, whoever registered it, and prints it only once it has been
// verified against the chain. It reads the chain directly, like model find,
// because an operator needs it before choosing a model to serve.
func newModelManifestFetchCommand(stdout io.Writer, openChain func(string) currentProfileReader, downloader *modelmanifest.Downloader) *cobra.Command {
	var rpcEndpoint, profileVersion, cacheDir, ipfsGateway string
	var mirrors []string
	cmd := &cobra.Command{Use: "fetch MODEL_ID", Short: "Fetch a registered profile's manifest and verify it against the chain", Args: cobra.ExactArgs(1)}
	format := newFormatFlag(cmd, "table")
	cmd.Flags().StringVar(&rpcEndpoint, "rpc", "", "chain CometBFT RPC endpoint")
	cmd.Flags().StringVar(&profileVersion, "profile-version", "", "registered profile version")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "directory of verified manifests, checked first and filled on success")
	cmd.Flags().StringVar(&ipfsGateway, "ipfs-gateway", "", "IPFS gateway for ipfs:// manifest URIs (https, or http on loopback); none by default")
	cmd.Flags().StringArrayVar(&mirrors, "mirror", nil, "https base URL serving manifests at <mirror>/<manifest_hash hex>; repeatable, tried in order")
	timeout := cmd.Flags().Duration("timeout", 2*time.Minute, "bound on the chain query and every download")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(rpcEndpoint) == "" || strings.TrimSpace(profileVersion) == "" {
			return errors.New("--rpc and --profile-version are required")
		}
		if *timeout <= 0 {
			return errors.New("--timeout must be positive")
		}
		fetcher, err := modelmanifest.NewFetcher(modelmanifest.FetcherConfig{CacheDir: cacheDir, IPFSGateway: ipfsGateway, Mirrors: mirrors}, downloader)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), *timeout)
		defer cancel()
		chain, err := openChain(rpcEndpoint).CurrentModelProfile(ctx, args[0], profileVersion)
		if err != nil {
			return fmt.Errorf("read chain profile %s@%s: %w", args[0], profileVersion, err)
		}
		fetched, err := fetcher.Fetch(ctx, chain)
		if err != nil {
			return err
		}
		manifest := fetched.Manifest
		return printFormatted(stdout, map[string]string{
			"model_id":        chain.Profile.ModelID,
			"manifest_uri":    chain.Profile.ManifestURI,
			"profile_version": profileVersion,
			"manifest_hash":   chain.Profile.ManifestHash.Hex(),
			"source":          fetched.Source,
			"bytes":           fmt.Sprint(len(fetched.Bytes)),
			"display_name":    manifest.Identity.DisplayName,
			"repo_id":         manifest.Source.RepoID,
			"revision":        manifest.Source.Revision,
			"artifact_files":  fmt.Sprint(len(manifest.Artifacts.Files)),
			"decode_vectors":  manifest.OutputDecoding.DecodeVectorsPath,
			"verification":    "verified against chain",
		}, adminapi.Format(*format))
	}
	return cmd
}

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/TrueOpen/cortex/internal/adminapi"
	"github.com/TrueOpen/cortex/internal/modelregistry"
	"github.com/TrueOpen/cortex/internal/observability"
	"github.com/TrueOpen/cortex/internal/txclient"
)

func main() {
	observability.SetDefaultLogger(os.Stderr)
	if err := run(os.Args[1:], os.Stdout); err != nil {
		slog.Error("cortexctl failed", slog.Any("error", err))
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	cmd := newRootCommand(stdout)
	cmd.SetArgs(normalizeLegacyControlArgs(args))
	return cmd.Execute()
}

func normalizeLegacyControlArgs(args []string) []string {
	normalized := append([]string(nil), args...)
	legacyFlags := map[string]struct{}{
		"admin-socket":  {},
		"dry-run":       {},
		"format":        {},
		"height":        {},
		"manifest":      {},
		"metadata":      {},
		"model-service": {},
		"profile":       {},
		"tokenizer":     {},
		"version":       {},
		"wait":          {},
	}
	for i, arg := range normalized {
		if !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimPrefix(arg, "-"), "=")
		if _, ok := legacyFlags[name]; ok {
			normalized[i] = "-" + arg
		}
	}
	return normalized
}

func newRootCommand(stdout io.Writer) *cobra.Command {
	var adminSocket string
	root := &cobra.Command{
		Use:           "cortexctl",
		Short:         "Operate a local cortexd instance",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := cmd.Help(); err != nil {
				return err
			}
			return errors.New("subcommand is required")
		},
	}
	root.SetOut(stdout)
	root.SetErr(stdout)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		if strings.HasPrefix(err.Error(), "unknown flag:") {
			return fmt.Errorf("flag provided but not defined: %s", strings.TrimSpace(strings.TrimPrefix(err.Error(), "unknown flag:")))
		}
		return err
	})
	root.PersistentFlags().StringVar(&adminSocket, "admin-socket", defaultAdminSocket(), "cortexd admin Unix socket")
	client := func() *adminapi.Client { return adminapi.NewClient(adminSocket) }
	root.AddCommand(
		newModelCommand(client, stdout),
		newCapabilityCommand(client, stdout),
		newDiagnosticsCommand(client, stdout),
		newTreasuryCommand(client, stdout),
		newEarningsCommand(stdout),
		newEvidenceCommand(client, stdout),
		newTaskCommand(client, stdout),
	)
	return root
}

type clientFactory func() *adminapi.Client

func helpOnEmpty(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
}

func newFormatFlag(cmd *cobra.Command, defaultValue string) *string {
	return cmd.Flags().String("format", defaultValue, "output format: table or json")
}

func newCapabilityCommand(client clientFactory, stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "capability", Short: "Show daemon capabilities", Args: cobra.NoArgs}
	format := newFormatFlag(cmd, "table")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		value, err := client().Capability(cmd.Context())
		if err != nil {
			return err
		}
		return printFormatted(stdout, value, adminapi.Format(*format))
	}
	return cmd
}

func newDiagnosticsCommand(client clientFactory, stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "diagnostics", Short: "Show daemon diagnostics", Args: cobra.NoArgs}
	format := newFormatFlag(cmd, "table")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		value, err := client().Diagnostics(cmd.Context())
		if err != nil {
			return err
		}
		return printFormatted(stdout, value, adminapi.Format(*format))
	}
	return cmd
}

func newTaskCommand(client clientFactory, stdout io.Writer) *cobra.Command {
	root := helpOnEmpty("task", "Operate tasks and settlement")
	requeue := &cobra.Command{
		Use:   "requeue QUEUE_ID",
		Short: "Return a failed task queue row to the runnable set",
		Args:  cobra.ExactArgs(1),
	}
	format := newFormatFlag(requeue, "table")
	var reason string
	var retryDelay time.Duration
	requeue.Flags().StringVar(&reason, "reason", "", "operator reason recorded in task retry history")
	requeue.Flags().DurationVar(&retryDelay, "retry-delay", 0, "delay before the failed task becomes runnable")
	requeue.RunE = func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(reason) == "" {
			return errors.New("--reason is required")
		}
		if retryDelay < 0 {
			return errors.New("--retry-delay cannot be negative")
		}
		response, err := client().TaskQueueRequeue(cmd.Context(), adminapi.TaskQueueRequeueRequest{
			QueueID: args[0], Reason: reason, RetryDelayMS: uint64(retryDelay / time.Millisecond),
		})
		if err != nil {
			return err
		}
		return printFormatted(stdout, response, adminapi.Format(*format))
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List task queue rows and their queue ids",
		Args:  cobra.NoArgs,
	}
	listFormat := newFormatFlag(list, "table")
	var status string
	var limit int
	// Defaults to failed: that is the state an operator is looking for when they
	// reach for this command, and the queue_id it prints is what `requeue` needs.
	list.Flags().StringVar(&status, "status", "failed", "filter by queue status, or \"all\"")
	list.Flags().IntVar(&limit, "limit", 100, "maximum rows to return")
	list.RunE = func(cmd *cobra.Command, args []string) error {
		if limit < 0 {
			return errors.New("--limit cannot be negative")
		}
		response, err := client().TaskQueueList(cmd.Context(), adminapi.TaskQueueListRequest{
			Status: status, Limit: limit,
		})
		if err != nil {
			return err
		}
		return printFormatted(stdout, response, adminapi.Format(*listFormat))
	}
	root.AddCommand(requeue, list, newTaskSettleCommand(client, stdout))
	return root
}

func newEvidenceCommand(client clientFactory, stdout io.Writer) *cobra.Command {
	root := helpOnEmpty("evidence", "Inspect evidence retention")
	cleanup := &cobra.Command{Use: "cleanup", Short: "Preview or execute evidence cleanup", Args: cobra.NoArgs}
	format := newFormatFlag(cleanup, "table")
	diagnostics := &cobra.Command{Use: "diagnostics", Short: "Show evidence cleanup diagnostics", Args: cobra.NoArgs}
	formatDiag := newFormatFlag(diagnostics, "table")
	var digest string
	cleanup.Flags().StringVar(&digest, "digest", "", "plan digest to execute; if empty, preview only")
	cleanup.RunE = func(cmd *cobra.Command, _ []string) error {
		if digest == "" {
			plan, err := client().EvidenceCleanupPlan(cmd.Context())
			if err != nil {
				return err
			}
			return printFormatted(stdout, plan, adminapi.Format(*format))
		}
		result, err := client().EvidenceCleanupExecute(cmd.Context(), digest)
		if err != nil {
			return err
		}
		return printFormatted(stdout, result, adminapi.Format(*format))
	}

	diagnostics.RunE = func(cmd *cobra.Command, _ []string) error {
		report, err := client().EvidenceCleanupDiagnostics(cmd.Context())
		if err != nil {
			return err
		}
		return printFormatted(stdout, report, adminapi.Format(*formatDiag))
	}

	root.AddCommand(cleanup)
	root.AddCommand(diagnostics)
	return root
}

func newModelCommand(client clientFactory, stdout io.Writer) *cobra.Command {
	root := helpOnEmpty("model", "Manage model registration and support")
	root.AddCommand(
		newModelManifestCommand(client, stdout),
		newModelSelfTestCommand(client, stdout),
		newModelRegisterCommand(client, stdout),
		newModelStatusCommand(client, stdout),
		newModelListCommand(client, stdout),
		newModelShowCommand(client, stdout),
		newModelSupportCommand(client, stdout, false),
		newModelSupportCommand(client, stdout, true),
	)
	return root
}

func newModelSelfTestCommand(client clientFactory, stdout io.Writer) *cobra.Command {
	var manifestPath string
	cmd := &cobra.Command{Use: "self-test", Short: "Run the model manifest self-test", Args: cobra.NoArgs}
	format := newFormatFlag(cmd, "table")
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "manifest path")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if manifestPath == "" {
			return errors.New("--manifest is required")
		}
		manifest, err := readCurrentManifest(manifestPath)
		if err != nil {
			return err
		}
		value, err := client().CurrentModelSelfTest(cmd.Context(), manifest)
		if err != nil {
			return err
		}
		return printFormatted(stdout, value, adminapi.Format(*format))
	}
	return cmd
}

func newModelRegisterCommand(client clientFactory, stdout io.Writer) *cobra.Command {
	var manifestPath string
	var dryRun bool
	cmd := &cobra.Command{Use: "register", Short: "Register a current model manifest", Args: cobra.NoArgs}
	format := newFormatFlag(cmd, "table")
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "current manifest v3 path")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "prepare registration without submit")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if manifestPath == "" {
			return errors.New("--manifest is required")
		}
		manifest, err := readCurrentManifest(manifestPath)
		if err != nil {
			return err
		}
		value, err := client().CurrentModelRegister(cmd.Context(), modelregistry.CurrentRegisterRequest{Manifest: manifest, DryRun: dryRun})
		if err != nil {
			return err
		}
		return printFormatted(stdout, value, adminapi.Format(*format))
	}
	return cmd
}

func newModelStatusCommand(client clientFactory, stdout io.Writer) *cobra.Command {
	var height uint64
	cmd := &cobra.Command{Use: "status MODEL_ID", Short: "Show model status", Args: cobra.ExactArgs(1)}
	format := newFormatFlag(cmd, "table")
	cmd.Flags().Uint64Var(&height, "height", 0, "query height")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		value, err := client().ModelStatusProjection(cmd.Context(), modelregistry.StatusRequest{ModelID: args[0], Height: height})
		if err != nil {
			return err
		}
		return printFormatted(stdout, value, adminapi.Format(*format))
	}
	return cmd
}

func newModelListCommand(client clientFactory, stdout io.Writer) *cobra.Command {
	var height uint64
	cmd := &cobra.Command{Use: "list", Short: "List models", Args: cobra.NoArgs}
	format := newFormatFlag(cmd, "table")
	cmd.Flags().Uint64Var(&height, "height", 0, "query height")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		value, err := client().ModelListProjections(cmd.Context(), modelregistry.ListRequest{Height: height})
		if err != nil {
			return err
		}
		return printFormatted(stdout, value, adminapi.Format(*format))
	}
	return cmd
}

func newModelShowCommand(client clientFactory, stdout io.Writer) *cobra.Command {
	var height uint64
	cmd := &cobra.Command{Use: "show MODEL_ID", Short: "Show model details", Args: cobra.ExactArgs(1)}
	format := newFormatFlag(cmd, "table")
	cmd.Flags().Uint64Var(&height, "height", 0, "query height")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		value, err := client().ModelShowProjection(cmd.Context(), modelregistry.ShowRequest{ModelID: args[0], Height: height})
		if err != nil {
			return err
		}
		return printFormatted(stdout, value, adminapi.Format(*format))
	}
	return cmd
}

func newModelSupportCommand(client clientFactory, stdout io.Writer, daily bool) *cobra.Command {
	name, short := "support", "Prepare an operator-signed model support transaction"
	if daily {
		name, short = "daily-support", "Renew daily model support"
	}
	var profileVersion string
	var dryRun bool
	cmd := &cobra.Command{Use: name + " MODEL_ID", Short: short, Args: cobra.ExactArgs(1)}
	format := newFormatFlag(cmd, "table")
	if daily {
		cmd.Flags().BoolVar(&dryRun, "dry-run", false, "prepare without submit")
	} else {
		cmd.Flags().StringVar(&profileVersion, "profile-version", "", "profile version; defaults to the daemon's registered model status")
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		modelID := args[0]
		if !daily {
			intent, err := client().ModelSupport(cmd.Context(), modelregistry.SupportRequest{
				ModelID: modelID, ProfileVersion: profileVersion, Supported: true, DryRun: true,
			})
			if err != nil {
				return err
			}
			return printFormatted(stdout, intent, adminapi.Format(*format))
		}
		if dryRun {
			preview := map[string]any{"model_id": modelID, "dry_run": true, "daily_support": true}
			return printFormatted(stdout, preview, adminapi.Format(*format))
		}
		value, err := client().ModelDailySupport(cmd.Context(), modelregistry.DailySupportRequest{ModelID: modelID, Enabled: true})
		if err != nil {
			return err
		}
		return printFormatted(stdout, value, adminapi.Format(*format))
	}
	return cmd
}

func newModelManifestCommand(client clientFactory, stdout io.Writer) *cobra.Command {
	root := helpOnEmpty("manifest", "Generate and validate current manifests")
	var profilePath, version, tokenizer, modelServiceID, metadata string
	generate := &cobra.Command{Use: "generate", Short: "Generate a manifest", Args: cobra.NoArgs}
	generateFormat := newFormatFlag(generate, "json")
	generate.Flags().StringVar(&profilePath, "profile", "", "current ModelProfileProjection ProtoJSON path")
	generate.Flags().StringVar(&version, "version", "", "model version")
	generate.Flags().StringVar(&tokenizer, "tokenizer", "", "tokenizer identifier")
	generate.Flags().StringVar(&modelServiceID, "model-service", "", "model service id")
	generate.Flags().StringVar(&metadata, "metadata", "", "comma-separated key=value operator metadata")
	generate.RunE = func(cmd *cobra.Command, _ []string) error {
		if profilePath == "" {
			return errors.New("--profile is required")
		}
		profile, err := readCurrentProfile(profilePath)
		if err != nil {
			return err
		}
		value, err := client().CurrentModelManifestGenerate(cmd.Context(), modelregistry.CurrentManifestInput{
			Version: version, Tokenizer: tokenizer, ModelServiceID: modelServiceID, Metadata: parseMetadata(metadata), Profile: profile,
		})
		if err != nil {
			return err
		}
		return printFormatted(stdout, value, adminapi.Format(*generateFormat))
	}

	var manifestPath string
	validate := &cobra.Command{Use: "validate", Short: "Validate a manifest", Args: cobra.NoArgs}
	validateFormat := newFormatFlag(validate, "table")
	validate.Flags().StringVar(&manifestPath, "manifest", "", "manifest path")
	validate.RunE = func(cmd *cobra.Command, _ []string) error {
		if manifestPath == "" {
			return errors.New("--manifest is required")
		}
		manifest, err := readCurrentManifest(manifestPath)
		if err != nil {
			return err
		}
		if err := client().CurrentModelManifestValidate(cmd.Context(), manifest); err != nil {
			return err
		}
		return printFormatted(stdout, map[string]string{"manifest": manifestPath, "validation": "accepted"}, adminapi.Format(*validateFormat))
	}
	root.AddCommand(generate, validate)
	return root
}

func newTreasuryCommand(client clientFactory, stdout io.Writer) *cobra.Command {
	root := helpOnEmpty("treasury", "Inspect treasury state")
	status := &cobra.Command{Use: "status", Short: "Show treasury status", Args: cobra.NoArgs}
	format := newFormatFlag(status, "table")
	status.RunE = func(cmd *cobra.Command, _ []string) error {
		value, err := client().TreasuryStatus(cmd.Context())
		if err != nil {
			return err
		}
		return printFormatted(stdout, value, adminapi.Format(*format))
	}
	root.AddCommand(status)
	return root
}

func newEarningsCommand(stdout io.Writer) *cobra.Command {
	root := helpOnEmpty("earnings", "Inspect earnings projections")
	status := &cobra.Command{Use: "status", Short: "Show earnings status", Args: cobra.NoArgs}
	format := newFormatFlag(status, "table")
	status.RunE = func(_ *cobra.Command, _ []string) error {
		return printFormatted(stdout, modelregistry.ProjectEarnings(modelregistry.EarningsObservation{}), adminapi.Format(*format))
	}
	root.AddCommand(status)
	return root
}

func parseMetadata(raw string) map[string]string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	out := map[string]string{}
	for _, part := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(part, "=")
		if ok {
			out[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return out
}

func printFormatted(stdout io.Writer, value any, format adminapi.Format) error {
	if format == adminapi.FormatJSON {
		out, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, string(out))
		return err
	}
	out, err := adminapi.FormatResponse(value, format)
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(stdout, out)
	return err
}

func defaultAdminSocket() string {
	if value := strings.TrimSpace(os.Getenv("CORTEX_ADMIN_SOCKET")); value != "" {
		return value
	}
	return "/tmp/cortexd.sock"
}

func readCurrentManifest(path string) (modelregistry.CurrentManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return modelregistry.CurrentManifest{}, err
	}
	var manifest modelregistry.CurrentManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return modelregistry.CurrentManifest{}, err
	}
	return manifest, nil
}

func readCurrentProfile(path string) (txclient.ModelProfileProjectionMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return txclient.ModelProfileProjectionMessage{}, err
	}
	var profile txclient.ModelProfileProjectionMessage
	if err := json.Unmarshal(data, &profile); err != nil {
		return txclient.ModelProfileProjectionMessage{}, err
	}
	return profile, nil
}

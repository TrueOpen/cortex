package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/SingaXYZ/cortex/internal/adminapi"
	"github.com/spf13/cobra"
)

func newTaskSettleCommand(client clientFactory, stdout io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use: "settle TASK_ID", Short: "Submit permissionless settlement using this node's service account",
		Args: cobra.ExactArgs(1),
	}
	format := newFormatFlag(command, "table")
	command.RunE = func(cmd *cobra.Command, args []string) error {
		switch adminapi.Format(*format) {
		case "", adminapi.FormatTable, adminapi.FormatJSON:
		default:
			return fmt.Errorf("unknown format %q", *format)
		}
		response, err := client().TaskSettlement(cmd.Context(), adminapi.TaskSettlementRequest{TaskID: args[0]})
		if err != nil {
			return err
		}
		if err := printFormatted(stdout, response, adminapi.Format(*format)); err != nil {
			return err
		}
		if response.Error != "" {
			return errors.New(response.Error)
		}
		if response.Rejected {
			return fmt.Errorf("settlement transaction rejected: %s", response.RejectReason)
		}
		if !response.Confirmed {
			return fmt.Errorf("settlement transaction is not Keeper-confirmed")
		}
		return nil
	}
	return command
}

// Command testassign publishes one synthetic assign notification onto the
// devnet Nexus bus.
//
// Nexus does not publish WORKER_ASSIGNMENT_NOTIFY for a Cortex task yet, so the Worker
// assign path has never seen one on a deployed node. This injects a well-formed
// AssignNotify so that path can be observed. It is a diagnostic tool: envelopes
// are unsigned, so the receiving node must be running with
// nexus.envelope_auth_mode: trusted_nats_dev.
//
// The notify carries Keeper task identity, winner, and assignment heights.
// TaskRunner verifies those facts against its authoritative Keeper snapshot
// before opening a Worker responsibility.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/observability"
	busv1 "github.com/SingaXYZ/cortex/proto/bus/v1"
	"github.com/SingaXYZ/cortex/scripts/natsurl"
)

func main() {
	observability.SetDefaultLogger(os.Stderr)
	natsURL := flag.String("nats-url", "", "Nexus NATS URL, credentials may be in the userinfo")
	chainID := flag.String("chain-id", "trueopen-localnet-1", "chain id")
	taskID := flag.String("task-id", "", "task id to notify about")
	taskHash := flag.String("task-hash", "", "Keeper accepted task hash, canonical 64 lowercase hex")
	winner := flag.String("winner", "", "winning Worker operator address")
	finalizedHeight := flag.Int64("finalized-height", 0, "assignment finalized height; the runner compares it to the Keeper WinnerConfirmHeight")
	builderAddr := flag.String("builder", "", "builder address to attribute the notify to")
	deadline := flag.Int64("deadline", 0, "Keeper inference deadline block height")
	authorizationNonce := flag.Uint64("authorization-nonce", 0, "the Builder's current ServiceKey authorization nonce (envelope field 7)")
	ttl := flag.Duration("ttl", 2*time.Minute, "envelope lifetime")
	flag.Parse()

	if *natsURL == "" || *taskID == "" || *taskHash == "" || *winner == "" ||
		*finalizedHeight <= 0 || *deadline <= *finalizedHeight || *builderAddr == "" || *authorizationNonce == 0 {
		printUsage()
		os.Exit(2)
	}

	now := time.Now().UTC()

	notify, err := assignmentNotify(*taskID, *taskHash, *winner, uint64(*finalizedHeight), uint64(*deadline))
	if err != nil {
		slog.Error("testassign failed", slog.Any("error", err))
		os.Exit(2)
	}

	subject := builderclient.NATSWorkerAssignmentSubject(*taskID)
	frame, err := builderclient.EncodeUnsignedBusMessage(builderclient.UnsignedEnvelopeInput{
		Kind: builderclient.KindWorkerAssignmentNotify, ChainID: *chainID, Subject: subject,
		SenderOperatorAddress: *builderAddr, SenderParticipantType: builderclient.ParticipantBuilder,
		ServiceAuthorizationNonce: *authorizationNonce,
		IssuedAt:                  now, ExpiresAt: now.Add(*ttl),
	}, notify, true)
	if err != nil {
		slog.Error("testassign failed", slog.Any("error", fmt.Errorf("encode assign notify: %w", err)))
		os.Exit(1)
	}

	publisher, err := builderclient.NewNATSPublisher(strings.TrimSpace(*natsURL), "")
	if err != nil {
		slog.Error("testassign failed", slog.Any("error", errors.New("connect nats: "+natsurl.Scrub(err.Error(), *natsURL))))
		os.Exit(1)
	}
	if err := publisher.Publish(context.Background(), builderclient.PublishRequest{
		Subject: subject, TaskID: *taskID, Payload: frame,
	}); err != nil {
		slog.Error("testassign failed", slog.Any("error", errors.New("publish: "+natsurl.Scrub(err.Error(), *natsURL))))
		os.Exit(1)
	}
	// Core NATS publishes are buffered. A short-lived tool has to flush before
	// exiting or the frame never leaves the client.
	if prober, ok := publisher.(interface {
		Probe(context.Context) error
	}); ok {
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := prober.Probe(flushCtx); err != nil {
			slog.Error("testassign failed", slog.Any("error", errors.New("flush: "+natsurl.Scrub(err.Error(), *natsURL))))
			os.Exit(1)
		}
	}
	if closer, ok := publisher.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	fmt.Printf("published worker assignment notify\n  subject:          %s\n  task_id:          %s\n  task_hash:        %s\n  winner:           %s\n  finalized_height: %d\n  infer_deadline:   %d\n",
		subject, *taskID, *taskHash, *winner, *finalizedHeight, *deadline)
	fmt.Println("  only WORKER-duty nodes subscribe trueopen.worker-assignment.*; a node with no Keeper-authoritative")
	fmt.Println("  assignment for this task stores the frame and refuses to act on it. That is correct.")
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage: testassign -nats-url URL -task-id HEX64 -task-hash HEX64 -winner ADDR -finalized-height N -deadline N -builder ADDR")
	fmt.Fprintln(os.Stderr, "       -authorization-nonce N [-chain-id ID] [-ttl DURATION]")
}

func assignmentNotify(taskID, taskHash, winner string, finalized, deadline uint64) (*busv1.WorkerAssignmentNotifyV1, error) {
	ids := make([][]byte, 2)
	for index, value := range []string{taskID, taskHash} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 32 || strings.ToLower(value) != value {
			return nil, fmt.Errorf("task-id and task-hash must be canonical 32-byte lowercase hex")
		}
		ids[index] = decoded
	}
	if winner == "" || strings.TrimSpace(winner) != winner || finalized == 0 || deadline <= finalized {
		return nil, fmt.Errorf("canonical winner and Keeper assignment heights are required")
	}
	return &busv1.WorkerAssignmentNotifyV1{TaskId: ids[0], TaskHash: ids[1], WinnerOperatorAddress: winner, FinalizedHeight: finalized, InferDeadlineHeight: deadline}, nil
}

package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"google.golang.org/protobuf/proto"
)

func TestPersistedGenerationParamsSurviveRestart(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir()
	db, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	session := strings.Repeat("12", 32)
	signed, _ := testSignedOrderProto(t, "chain", testModelID, session, 0, 200)
	signed.Order.GenerationParams.MaxOutputTokens = 1024
	signed.Order.GenerationParams.DecodingParams.TemperatureMilli = 700
	signed.Order.GenerationParams.DecodingParams.SamplingEnabled = true
	raw, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	hash, facts, err := nodewire.TaskOrderHashAndFactsEnvelope(hex.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := layout.AdmissionBatch(ctx, db, session, 0, layout.StoredHash(hash), layout.CandidateAdmission{
		SchemaVersion: layout.CandidateAdmissionSchemaVersion, SignedOrder: raw,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	reader := persistedGenerationReader{store: db, chainID: "chain"}
	generation, err := reader.TaskGeneration(ctx, identity.TaskIDString(session, 0), hash)
	if err != nil {
		t.Fatal(err)
	}
	got, err := generation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	want, err := facts.Generation.Digest()
	if err != nil || got != want || generation.Params.MaxOutputTokens != 1024 || generation.Params.DecodingParams.TemperatureMilli != 700 {
		t.Fatalf("restored generation = %+v, digest=%x, want %x; err=%v", generation, got, want, err)
	}
}

func TestPersistedGenerationParamsRejectWrongTaskAndCorruptOrder(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	session := strings.Repeat("34", 32)
	signed, hash := testSignedOrderProto(t, "chain", testModelID, session, 0, 200)
	raw, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := layout.AdmissionBatch(ctx, db, session, 0, layout.StoredHash(hash), layout.CandidateAdmission{
		SchemaVersion: layout.CandidateAdmissionSchemaVersion, SignedOrder: raw,
	}); err != nil {
		t.Fatal(err)
	}
	taskID := identity.TaskIDString(session, 0)
	reader := persistedGenerationReader{store: db, chainID: "chain"}
	for name, run := range map[string]func() error{
		"wrong task": func() error { _, err := reader.TaskGeneration(ctx, strings.Repeat("cd", 32), hash); return err },
		"missing order": func() error {
			_, err := reader.TaskGeneration(ctx, taskID, codec.HashBytes([]byte("other")))
			return err
		},
		"wrong chain": func() error {
			_, err := (persistedGenerationReader{store: db, chainID: "other"}).TaskGeneration(ctx, taskID, hash)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(); err == nil {
				t.Fatal("accepted generation parameters without matching order authority")
			}
		})
	}
	// The key still names the accepted order, but the persisted bytes now name a
	// different generation limit. Re-hashing must detect corruption on recovery.
	signed.Order.GenerationParams.MaxOutputTokens = 8
	changed, _ := proto.Marshal(signed)
	if bytes.Equal(raw, changed) {
		t.Fatal("mutation did not change the signed order")
	}
	if err := layout.AdmissionBatch(ctx, db, session, 0, layout.StoredHash(hash), layout.CandidateAdmission{
		SchemaVersion: layout.CandidateAdmissionSchemaVersion, SignedOrder: changed, PublishTS: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.TaskGeneration(ctx, taskID, hash); err == nil {
		t.Fatal("accepted altered generation params under the original task hash")
	}
}

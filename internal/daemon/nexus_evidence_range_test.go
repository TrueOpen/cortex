package daemon

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// nexusDefaultMaxRangeBytes is the Builder's default task_data.max_range_bytes.
const nexusDefaultMaxRangeBytes = 8 << 20

// growWorkerValues re-encodes the fixture's worker_values over enough
// positions to exceed minBytes, re-deriving the generated token ids, the
// receipt's commitments and its signature so the bundle stays bound.
func growWorkerValues(t *testing.T, f *evidenceFixture, minBytes int) {
	t.Helper()
	leaves, err := nodewire.DecodeWorkerValues(f.valueBinding(t), f.WorkerValues)
	if err != nil {
		t.Fatal(err)
	}
	perLeaf := (len(f.WorkerValues) - 4) / len(leaves)
	grown := make([]nodewire.PositionValueV1, minBytes/perLeaf+1)
	ids := make([]uint32, len(grown))
	for i := range grown {
		grown[i] = leaves[i%len(leaves)]
		grown[i].Position = uint32(i)
		ids[i] = grown[i].TokenID
	}
	if f.WorkerValues, err = nodewire.EncodeWorkerValues(f.valueBinding(t), grown); err != nil {
		t.Fatal(err)
	}
	if f.GeneratedTokenIDs, err = nodewire.EncodeTokenIDs(ids); err != nil {
		t.Fatal(err)
	}
	f.Commitments.Receipt.GeneratedTokenCount = uint64(len(grown))
	f.rebuildManifests(t, nil)
	f.sign(t)
}

// A long output's value opening is larger than the Builder's 8 MiB
// task_data.max_range_bytes (testnet: ~9600 tokens, 8.68 MiB). The Builder
// refuses any longer range, a whole-object read included, so the reveal
// must read it in ranges the Builder serves and still bind the whole object.
func TestNexusEvidenceConfirmerReadsValueOpeningAboveTheBuilderRangeLimit(t *testing.T) {
	f := newEvidenceFixture(t)
	growWorkerValues(t, &f, nexusDefaultMaxRangeBytes+(1<<20))
	if len(f.WorkerValues) <= nexusDefaultMaxRangeBytes {
		t.Fatalf("fixture worker_values = %d bytes, want above %d", len(f.WorkerValues), nexusDefaultMaxRangeBytes)
	}
	client := &evidenceTaskDataClient{objects: f.objects(), maxRangeBytes: nexusDefaultMaxRangeBytes}
	values, err := newEvidenceConfirmer(t, client).ConfirmWorkerValueEvidence(context.Background(), f.Commitments)
	if err != nil {
		t.Fatalf("ConfirmWorkerValueEvidence over a %d byte value opening: %v", len(f.WorkerValues), err)
	}
	if !bytes.Equal(values, f.WorkerValues) {
		t.Fatal("reassembled worker_values differ from the served object")
	}
	var next uint64
	for _, fetch := range client.fetches {
		if fetch.Key != f.keys()[1] {
			continue
		}
		if fetch.Range == nil || fetch.Range.Offset != next || fetch.Range.Length == 0 || fetch.Range.Length > taskDataFetchRangeBytes {
			t.Fatalf("worker_values fetch range = %+v, want contiguous ranges of at most %d from %d", fetch.Range, taskDataFetchRangeBytes, next)
		}
		next += fetch.Range.Length
	}
	if next != uint64(len(f.WorkerValues)) {
		t.Fatalf("worker_values ranges cover %d of %d bytes", next, len(f.WorkerValues))
	}
}

// A range the Builder refuses is that Builder failing to deliver: the error
// is not this node's fault, so tryBuilders asks the next fixed Task Builder.
func TestNexusEvidenceConfirmerRangeRefusalIsABuilderFailure(t *testing.T) {
	f := newEvidenceFixture(t)
	client := &evidenceTaskDataClient{objects: f.objects(), maxRangeBytes: 1}
	confirmer := newEvidenceConfirmer(t, client)
	served, err := tryBuilders(context.Background(), levelB, []string{inputTestBuilder}, func(ctx context.Context, builder string) error {
		commitments := f.Commitments
		commitments.BuilderOperatorAddress = builder
		_, err := confirmer.ConfirmWorkerValueEvidence(ctx, commitments)
		return err
	})
	var none *builderUnavailable
	if served != "" || !errors.As(err, &none) || errors.Is(err, errVerifierLocal) || builderclient.IsPermanent(err) {
		t.Fatalf("range refusal = %q, %v; want the Builder counted unavailable", served, err)
	}
}

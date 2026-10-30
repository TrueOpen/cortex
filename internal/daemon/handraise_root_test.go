package daemon

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/signer"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// hrRootNotice builds a root over mine and others with leaves sorted by
// standing digest (KC §4.4), signs it with keyHex and proves mine.
func hrRootNotice(t *testing.T, builder, keyHex string, height, version uint64, mine *taskv1.HandraiseRootLeafV1, others ...*taskv1.HandraiseRootLeafV1) *nexusv1.HandraiseRootNoticeV1 {
	t.Helper()
	type entry struct {
		leaf             *taskv1.HandraiseRootLeafV1
		standing, digest [32]byte
	}
	var entries []entry
	for _, l := range append([]*taskv1.HandraiseRootLeafV1{mine}, others...) {
		sd, err := dispatchwire.Digest(l.GetHandraise())
		if err != nil {
			t.Fatal(err)
		}
		ld, err := dispatch.HandraiseLeafDigest(sd, l.GetAdmitted(), uint32(l.GetAdmitRejectReason()), l.GetBuilderMeasuredRttMs())
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry{l, sd, ld})
	}
	slices.SortFunc(entries, func(a, b entry) int { return bytes.Compare(a.standing[:], b.standing[:]) })
	leaves := make([][32]byte, len(entries))
	index := -1
	for i, e := range entries {
		leaves[i] = e.digest
		if e.leaf == mine {
			index = i
		}
	}
	root := dispatch.HandraiseRoot(leaves)
	path, err := dispatch.HandraiseProof(leaves, uint32(index))
	if err != nil {
		t.Fatal(err)
	}
	signed := &taskv1.SignedHandraiseRootV1{ChainId: hrChainID, BuilderAddress: builder, RootHeight: height,
		RootVersion: version, LeafCount: uint32(len(leaves)), Root: root[:]}
	d, err := dispatchwire.Digest(signed)
	if err != nil {
		t.Fatal(err)
	}
	if signed.BuilderServiceSignature, err = signer.SignDigestWithPrivateKeyHex(keyHex, codec.Hash(d)); err != nil {
		t.Fatal(err)
	}
	siblings := make([][]byte, len(path))
	for i := range path {
		siblings[i] = append([]byte(nil), path[i][:]...)
	}
	return &nexusv1.HandraiseRootNoticeV1{Root: signed,
		Proof: &taskv1.HandraiseInclusionProofV1{Leaf: mine, LeafIndex: uint32(index), Siblings: siblings}}
}

func admittedLeaf(h *taskv1.StandingHandraiseV1) *taskv1.HandraiseRootLeafV1 {
	return &taskv1.HandraiseRootLeafV1{Handraise: h, Admitted: true, AdmitRejectReason: taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_NONE}
}

func someoneElse(mine *taskv1.StandingHandraiseV1) *taskv1.StandingHandraiseV1 {
	o := proto.Clone(mine).(*taskv1.StandingHandraiseV1)
	o.HandraiseNonce = 99
	return o
}

func TestHandraiseRootIsVerifiedAgainstTheSendLogAndHeld(t *testing.T) {
	ctx := context.Background()
	x := newHRHarness(t, nil)
	x.warm()
	mine := x.a.handraises()[0]
	n := hrRootNotice(t, hrBuilderA, hrBuilderKey, 200, 0, admittedLeaf(mine), admittedLeaf(someoneElse(mine)))
	if err := x.h.HandleRootNotice(ctx, hrBuilderA, n); err != nil {
		t.Fatal(err)
	}
	d, err := dispatchwire.Digest(n.Root)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := x.h.HoldsRoot(ctx, hrBuilderA, d); err != nil || !ok {
		t.Fatalf("HoldsRoot(A) = %v %v", ok, err)
	}
	if ok, _ := x.h.HoldsRoot(ctx, hrBuilderB, d); ok {
		t.Fatal("roots are held per Builder")
	}
	if held, err := x.h.HeldRootDigests(ctx, hrBuilderA); err != nil || len(held) != 1 || !held[d] {
		t.Fatalf("HeldRootDigests = %v %v", held, err)
	}
	if err := x.h.HandleRootNotice(ctx, hrBuilderA, n); err != nil {
		t.Fatalf("a redelivered root is a no-op: %v", err)
	}
	if held, _ := x.h.HeldRootDigests(ctx, hrBuilderA); len(held) != 1 {
		t.Fatal("deduplicated by digest")
	}
	if a, ok := x.h.Admission(hrBuilderA); !ok || !a.Admitted || len(x.alerts) != 0 {
		t.Fatalf("admission %+v %v, alerts %v", a, ok, x.alerts)
	}
}

func TestHandraiseRootRejections(t *testing.T) {
	ctx := context.Background()
	x := newHRHarness(t, nil)
	x.warm()
	mine := x.a.handraises()[0]
	t.Run("root for another Builder than the stream's", func(t *testing.T) {
		err := x.h.HandleRootNotice(ctx, hrBuilderB, hrRootNotice(t, hrBuilderA, hrBuilderKey, 200, 0, admittedLeaf(mine)))
		if !errors.Is(err, dispatchwire.ErrInclusionBuilder) || builderclient.IsRetryable(err) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("leaf is a handraise this node never sent to that Builder", func(t *testing.T) {
		forged := proto.Clone(mine).(*taskv1.StandingHandraiseV1)
		forged.FreeSlotCount = 50
		if err := dispatchwire.SignStandingHandraise(ctx, forged, hrSigner(hrCortexKey)); err != nil {
			t.Fatal(err)
		}
		err := x.h.HandleRootNotice(ctx, hrBuilderA, hrRootNotice(t, hrBuilderA, hrBuilderKey, 200, 0, admittedLeaf(forged)))
		if !errors.Is(err, ErrRootForeignHandraise) || builderclient.IsRetryable(err) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("root not signed by the Builder's current key", func(t *testing.T) {
		err := x.h.HandleRootNotice(ctx, hrBuilderA, hrRootNotice(t, hrBuilderA, hrCortexKey, 200, 0, admittedLeaf(mine)))
		if !errors.Is(err, dispatchwire.ErrBuilderSignature) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a REVOKED Builder key authorizes no root", func(t *testing.T) {
		x.chain.with(func(f *fakeHandraiseChain) {
			k := f.builderKeys[hrBuilderA]
			k.Status = "REVOKED"
			f.builderKeys[hrBuilderA] = k
		})
		defer x.chain.with(func(f *fakeHandraiseChain) {
			k := f.builderKeys[hrBuilderA]
			k.Status = "ACTIVE"
			f.builderKeys[hrBuilderA] = k
		})
		err := x.h.HandleRootNotice(ctx, hrBuilderA, hrRootNotice(t, hrBuilderA, hrBuilderKey, 200, 0, admittedLeaf(mine)))
		if err == nil || builderclient.IsRetryable(err) {
			t.Fatalf("err = %v, want a permanent refusal", err)
		}
	})
	t.Run("unreadable Builder key is retryable", func(t *testing.T) {
		x.chain.with(func(f *fakeHandraiseChain) { f.builderKeyErr = errors.New("rpc down") })
		defer x.chain.with(func(f *fakeHandraiseChain) { f.builderKeyErr = nil })
		err := x.h.HandleRootNotice(ctx, hrBuilderA, hrRootNotice(t, hrBuilderA, hrBuilderKey, 200, 0, admittedLeaf(mine)))
		if !builderclient.IsRetryable(err) {
			t.Fatalf("err = %v, want retryable", err)
		}
	})
	if held, _ := x.h.HeldRootDigests(ctx, hrBuilderA); len(held) != 0 {
		t.Fatalf("no rejected root may be held: %v", held)
	}
}

func TestHandraiseRootOrderAdmissionAndAlerts(t *testing.T) {
	ctx := context.Background()
	x := newHRHarness(t, func(c *StandingHandraiseConfig) { c.RootHistory = 3 })
	x.warm()
	mine := x.a.handraises()[0]
	rejectRate := &taskv1.HandraiseRootLeafV1{Handraise: mine, AdmitRejectReason: taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_REJECT_RATE}
	deliver := func(h, v uint64, leaf *taskv1.HandraiseRootLeafV1, others ...*taskv1.HandraiseRootLeafV1) [32]byte {
		t.Helper()
		n := hrRootNotice(t, hrBuilderA, hrBuilderKey, h, v, leaf, others...)
		if err := x.h.HandleRootNotice(ctx, hrBuilderA, n); err != nil {
			t.Fatal(err)
		}
		d, err := dispatchwire.Digest(n.Root)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	r200v0 := deliver(200, 0, admittedLeaf(mine))
	r200v1 := deliver(200, 1, rejectRate)
	r200v2 := deliver(200, 2, rejectRate)
	if len(x.alerts) != 1 || x.alerts[0].Kind != AlertHandraiseNotAdmitted ||
		x.alerts[0].Root.Reason != taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_REJECT_RATE {
		t.Fatalf("want exactly one not-admitted alert on the transition, got %+v", x.alerts)
	}
	r199 := deliver(199, 7, admittedLeaf(mine)) // older, arrives late
	if a, _ := x.h.Admission(hrBuilderA); a.RootHeight != 200 || a.RootVersion != 2 || a.Admitted {
		t.Fatalf("an older root must not replace the newest view: %+v", a)
	}
	r201 := deliver(201, 0, admittedLeaf(mine))
	if a, _ := x.h.Admission(hrBuilderA); !a.Admitted || a.RootHeight != 201 {
		t.Fatalf("admission after recovery: %+v", a)
	}
	held, err := x.h.HeldRootDigests(ctx, hrBuilderA)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 3 || !held[r201] || !held[r200v2] || !held[r200v1] || held[r200v0] || held[r199] {
		t.Fatalf("HeldRootDigests must be the newest 3 by (root_height, root_version): %v", held)
	}
	if ok, _ := x.h.HoldsRoot(ctx, hrBuilderA, r199); !ok {
		t.Fatal("HoldsRoot answers for every retained root, not only the newest N")
	}
	deliver(201, 0, admittedLeaf(mine), admittedLeaf(someoneElse(mine))) // same (h, v), different root
	if last := x.alerts[len(x.alerts)-1]; last.Kind != AlertHandraiseRootEquivocation {
		t.Fatalf("want an equivocation alert, got %+v", last)
	}
}

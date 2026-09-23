package chainclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	"github.com/cosmos/gogoproto/proto"
)

func builderSetTestHash() []byte { return bytes.Repeat([]byte{0x5a}, 32) }

func nodeBuilderSetResponseFixture(height uint64) *hubv1.QueryBuilderSetResponse {
	return &hubv1.QueryBuilderSetResponse{Set: &hubv1.BuilderSetViewV1{BuilderSetVersion: 7, BuilderSetId: "builder-set-7", BuilderSetHash: builderSetTestHash(), EffectiveHeight: height, ActiveBuilders: []string{"trueopen1buildera", "trueopen1builderb", "trueopen1builderc"}, ActiveBuilderCount: 3, BodyStatus: 1}}
}

// The membership read is what decides whether a bus sender is a Builder the
// chain currently recognises, so it must be served from the height the
// application has committed and must report that height back.
func TestCommittedBuilderSetReadsTheCurrentSetAtTheCommittedHeight(t *testing.T) {
	var heights []string
	server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
		if path != hubQuery+"BuilderSet" {
			t.Fatalf("unexpected ABCI path %q", path)
		}
		heights = append(heights, height)
		var request hubv1.QueryBuilderSetRequest
		mustUnmarshalProto(t, data, &request)
		// Exactly one selector, and it is the committed height: a term or a set
		// id would ask for a set that is not necessarily the current one.
		if request.GetHeight() != abciTestCommittedHeight || request.GetBuilderSetId() != "" {
			t.Fatalf("request = %#v", &request)
		}
		return nodeBuilderSetResponseFixture(abciTestCommittedHeight), 0, ""
	})
	defer server.Close()

	set, served, err := NewKeeperABCIClient(server.URL).CommittedBuilderSet(context.Background())
	if err != nil {
		t.Fatalf("CommittedBuilderSet() error = %v", err)
	}
	if served != abciTestCommittedHeight {
		t.Fatalf("served height = %d, want the committed height %d", served, abciTestCommittedHeight)
	}
	if set.BuilderSetVersion.Uint64() != 7 || set.BuilderSetID != "builder-set-7" ||
		set.SetHash.String() != hex.EncodeToString(builderSetTestHash()) ||
		len(set.Builders) != 3 || set.SnapshotHeight.Uint64() != abciTestCommittedHeight {
		t.Fatalf("set = %#v", set)
	}
	if !set.HasBuilder("trueopen1builderb") || set.HasBuilder("trueopen1builderz") ||
		set.HasBuilder(" trueopen1builderb ") || set.HasBuilder("") {
		t.Fatalf("membership = %#v", set.Builders)
	}
}

// A pruned body retains the member count and the hash but deletes the members,
// so an empty list is not evidence that a sender is absent from the set.
func TestCommittedBuilderSetRefusesAPrunedBody(t *testing.T) {
	server := newABCITestServer(t, func(string, string, []byte) (proto.Message, uint32, string) {
		response := nodeBuilderSetResponseFixture(abciTestCommittedHeight)
		response.Set.BodyStatus = 2
		response.Set.ActiveBuilders = nil
		return response, 0, ""
	})
	defer server.Close()

	_, _, err := NewKeeperABCIClient(server.URL).CommittedBuilderSet(context.Background())
	if err == nil || !strings.Contains(err.Error(), "pruned") {
		t.Fatalf("err = %v, want a pruned BuilderSet body to be refused", err)
	}
}

func TestCommittedBuilderSetRefusesInconsistentMembership(t *testing.T) {
	for name, mutate := range map[string]func(*hubv1.BuilderSetViewV1){
		"count disagrees": func(set *hubv1.BuilderSetViewV1) { set.ActiveBuilderCount = 4 },
		"duplicate member": func(set *hubv1.BuilderSetViewV1) {
			set.ActiveBuilders = []string{"trueopen1buildera", "trueopen1buildera", "trueopen1builderc"}
		},
		"blank member": func(set *hubv1.BuilderSetViewV1) {
			set.ActiveBuilders = []string{"trueopen1buildera", "", "trueopen1builderc"}
		},
		"unknown body status": func(set *hubv1.BuilderSetViewV1) { set.BodyStatus = 0 },
		"missing set id":      func(set *hubv1.BuilderSetViewV1) { set.BuilderSetId = "" },
		"zero set hash":       func(set *hubv1.BuilderSetViewV1) { set.BuilderSetHash = nil },
		"future snapshot":     func(set *hubv1.BuilderSetViewV1) { set.EffectiveHeight = abciTestCommittedHeight + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			server := newABCITestServer(t, func(string, string, []byte) (proto.Message, uint32, string) {
				response := nodeBuilderSetResponseFixture(abciTestCommittedHeight)
				mutate(response.Set)
				return response, 0, ""
			})
			defer server.Close()

			if _, _, err := NewKeeperABCIClient(server.URL).CommittedBuilderSet(context.Background()); err == nil {
				t.Fatalf("CommittedBuilderSet() error = nil, want %s to be refused", name)
			}
		})
	}
}

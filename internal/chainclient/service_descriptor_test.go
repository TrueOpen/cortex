package chainclient

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/cosmos/gogoproto/proto"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
)

func builderStateResponse() *hubv1.QueryBuilderResponse {
	return &hubv1.QueryBuilderResponse{Builder: &hubv1.BuilderState{
		SchemaVersion: 1, BuilderAddress: "trueopen1builder", CurrentServiceAddress: "trueopen1builderservice", CurrentServicePubkey: append([]byte{0x02}, bytes.Repeat([]byte{0xbc}, 32)...), ServiceAuthorizationNonce: 5, CurrentServiceKeyStatus: hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE, CurrentDescriptorVersion: 7, RegisteredHeight: 10,
	}}
}

// Every read the Builder directory makes must be pinned to one height, so a
// racing rotation cannot mix a new descriptor with an old key.
func TestBuilderAndServiceDescriptorReadsPinTheSnapshotHeight(t *testing.T) {
	var heights []string
	server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
		heights = append(heights, height)
		switch path {
		case hubQuery + "Builder":
			var request hubv1.QueryBuilderRequest
			mustUnmarshalProto(t, data, &request)
			if request.BuilderAddress != "trueopen1builder" {
				t.Fatalf("Builder request = %#v", &request)
			}
			return builderStateResponse(), 0, ""
		case hubQuery + "ServiceDescriptor":
			var request hubv1.QueryServiceDescriptorRequest
			mustUnmarshalProto(t, data, &request)
			if request.ParticipantType != sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER {
				t.Fatalf("ServiceDescriptor request = %#v", &request)
			}
			return serviceDescriptorResponse(), 0, ""
		default:
			t.Fatalf("unexpected ABCI path %q", path)
			return nil, 1, "unexpected"
		}
	})
	defer server.Close()
	client := NewKeeperABCIClient(server.URL)

	builder, err := client.Builder(context.Background(), "trueopen1builder", 900)
	if err != nil {
		t.Fatalf("Builder() error = %v", err)
	}
	if builder.CurrentDescriptorVersion.Uint64() != 7 || builder.CurrentServiceKeyStatus != "ACTIVE" ||
		builder.RegisteredHeight.Uint64() != 10 || builder.Address != "trueopen1builder" {
		t.Fatalf("Builder = %#v", builder)
	}
	descriptor, err := client.ServiceDescriptor(context.Background(), ParticipantTypeBuilder, "trueopen1builder", 900)
	if err != nil {
		t.Fatalf("ServiceDescriptor() error = %v", err)
	}
	if descriptor.DescriptorHash.String() != descriptorTestHash || descriptor.DescriptorVersion != 7 {
		t.Fatalf("ServiceDescriptor = %#v", descriptor)
	}
	for _, height := range heights {
		if height != "900" {
			t.Fatalf("observed heights = %v, want every read pinned to 900", heights)
		}
	}
}

// CommittedBuilder is what starts a Builder resolution: it reads the latest
// committed Builder state and reports the height it came from, which the caller
// then pins the descriptor and service-key reads to.
func TestCommittedBuilderReportsTheHeightItWasServedAt(t *testing.T) {
	var heights []string
	server := newABCITestServer(t, func(path, height string, _ []byte) (proto.Message, uint32, string) {
		heights = append(heights, height)
		if path != hubQuery+"Builder" {
			t.Fatalf("unexpected ABCI path %q", path)
		}
		return builderStateResponse(), 0, ""
	})
	defer server.Close()

	builder, served, err := NewKeeperABCIClient(server.URL).CommittedBuilder(context.Background(), "trueopen1builder")
	if err != nil {
		t.Fatalf("CommittedBuilder() error = %v", err)
	}
	if served != abciTestCommittedHeight {
		t.Fatalf("served height = %d, want the committed height %d", served, abciTestCommittedHeight)
	}
	if builder.CurrentDescriptorVersion.Uint64() != 7 {
		t.Fatalf("Builder = %#v", builder)
	}
	// The read is pinned to the committed height, never left to "latest" per read.
	if len(heights) != 1 || heights[0] != "900" {
		t.Fatalf("observed heights = %v, want a single read pinned to 900", heights)
	}
}

func TestBuilderRejectsResponsesForAnotherOperator(t *testing.T) {
	server := newABCITestServer(t, func(string, string, []byte) (proto.Message, uint32, string) {
		response := builderStateResponse()
		response.Builder.BuilderAddress = "trueopen1other"
		return response, 0, ""
	})
	defer server.Close()

	_, err := NewKeeperABCIClient(server.URL).Builder(context.Background(), "trueopen1builder", 900)
	if err == nil || !strings.Contains(err.Error(), "does not match query identity") {
		t.Fatalf("err = %v, want a query identity mismatch", err)
	}
}

func TestBuilderStateSnapshotValidateRejectsUnknownStatus(t *testing.T) {
	snapshot := BuilderStateSnapshot{Address: "trueopen1builder", CurrentServiceKeyStatus: "RETIRED", RegisteredHeight: Uint64String(10)}
	if err := snapshot.Validate(); err == nil {
		t.Fatalf("Validate() error = nil, want an unsupported status to be rejected")
	}
	// A Builder that left the active set still serves the Task data it received,
	// so every terminal Node V1 status stays readable.
	for _, status := range []string{"ACTIVE", "REVOKED"} {
		snapshot.CurrentServiceKeyStatus = status
		if err := snapshot.Validate(); err != nil {
			t.Fatalf("Validate(%s) error = %v, want a departed Builder to remain readable", status, err)
		}
	}
}

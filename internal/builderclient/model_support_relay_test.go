package builderclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/wirevectors"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	"github.com/TrueOpen/cortex/proto/nexus/v1/nexusv1connect"
)

type supportRelayVector struct {
	EpochIndex                string `json:"epoch_index"`
	ConfirmationSigningDigest string `json:"confirmation_signing_digest"`
	ConfirmationProtobufHex   string `json:"confirmation_protobuf_hex"`
	RequestProtobufHex        string `json:"request_protobuf_hex"`
	ResponseProtobufHex       string `json:"response_protobuf_hex"`
}

func loadSupportRelayVector(t *testing.T) (supportRelayVector, SubmitModelSupportConfirmationRequest) {
	t.Helper()
	raw, err := wirevectors.File("hub/model_support_relay_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v supportRelayVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	epoch, err := strconv.ParseUint(v.EpochIndex, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	confirmation, err := hex.DecodeString(v.ConfirmationProtobufHex)
	if err != nil {
		t.Fatal(err)
	}
	bare, ok := FromIngressHash32(v.ConfirmationSigningDigest)
	if !ok {
		t.Fatalf("vector digest %q", v.ConfirmationSigningDigest)
	}
	digest, err := hex.DecodeString(bare)
	if err != nil {
		t.Fatal(err)
	}
	var hash codec.Hash
	copy(hash[:], digest)
	return v, SubmitModelSupportConfirmationRequest{EpochIndex: epoch, Confirmation: confirmation, SigningDigest: hash}
}

type supportRelayHandler struct {
	nexusv1connect.UnimplementedIngressAPIHandler
	submit func(*connect.Request[nexusv1.SubmitModelSupportConfirmationRequest]) (*connect.Response[nexusv1.SubmitModelSupportConfirmationResponse], error)
}

func (h *supportRelayHandler) SubmitModelSupportConfirmation(_ context.Context, r *connect.Request[nexusv1.SubmitModelSupportConfirmationRequest]) (*connect.Response[nexusv1.SubmitModelSupportConfirmationResponse], error) {
	return h.submit(r)
}

// The request a Builder receives is wire's published relay envelope, byte for
// byte, and wire's published acknowledgement is accepted.
func TestSubmitModelSupportConfirmationMatchesWireVector(t *testing.T) {
	v, req := loadSupportRelayVector(t)
	wantRequest, _ := hex.DecodeString(v.RequestProtobufHex)
	wantResponse, _ := hex.DecodeString(v.ResponseProtobufHex)
	server := newTaskDataTestServer(t, &supportRelayHandler{submit: func(r *connect.Request[nexusv1.SubmitModelSupportConfirmationRequest]) (*connect.Response[nexusv1.SubmitModelSupportConfirmationResponse], error) {
		got, err := proto.MarshalOptions{Deterministic: true}.Marshal(r.Msg)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(got, wantRequest) {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("request bytes differ from the wire vector"))
		}
		var response nexusv1.SubmitModelSupportConfirmationResponse
		if err := proto.Unmarshal(wantResponse, &response); err != nil {
			return nil, err
		}
		return connect.NewResponse(&response), nil
	}})
	ack, err := newTestTaskDataClient(server.Client(), "").SubmitModelSupportConfirmation(context.Background(), server.URL, req)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Idempotent || ack.SigningDigest != req.SigningDigest {
		t.Fatalf("ack = %+v", ack)
	}
}

func TestSubmitModelSupportConfirmationRefusesAWrongAcknowledgement(t *testing.T) {
	_, req := loadSupportRelayVector(t)
	digest := ToIngressHash32(hex.EncodeToString(req.SigningDigest[:]))
	for name, response := range map[string]*nexusv1.SubmitModelSupportConfirmationResponse{
		"not accepted":   {RelayAccepted: false, ConfirmationSigningDigest: digest},
		"other digest":   {RelayAccepted: true, ConfirmationSigningDigest: ToIngressHash32(hex.EncodeToString(make([]byte, 32)))},
		"missing digest": {RelayAccepted: true},
	} {
		t.Run(name, func(t *testing.T) {
			server := newTaskDataTestServer(t, &supportRelayHandler{submit: func(*connect.Request[nexusv1.SubmitModelSupportConfirmationRequest]) (*connect.Response[nexusv1.SubmitModelSupportConfirmationResponse], error) {
				return connect.NewResponse(response), nil
			}})
			if _, err := newTestTaskDataClient(server.Client(), "").SubmitModelSupportConfirmation(context.Background(), server.URL, req); err == nil {
				t.Fatal("a wrong acknowledgement was accepted")
			}
		})
	}
}

func TestSubmitModelSupportConfirmationKeepsTheBuilderCode(t *testing.T) {
	_, req := loadSupportRelayVector(t)
	server := newTaskDataTestServer(t, &supportRelayHandler{submit: func(*connect.Request[nexusv1.SubmitModelSupportConfirmationRequest]) (*connect.Response[nexusv1.SubmitModelSupportConfirmationResponse], error) {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("operator/epoch holds different material"))
	}})
	_, err := newTestTaskDataClient(server.Client(), "").SubmitModelSupportConfirmation(context.Background(), server.URL, req)
	if connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("err = %v", err)
	}
}

func TestSubmitModelSupportConfirmationRefusesAnEmptyConfirmation(t *testing.T) {
	_, req := loadSupportRelayVector(t)
	req.Confirmation = nil
	if _, err := newTestTaskDataClient(nil, "").SubmitModelSupportConfirmation(context.Background(), "https://builder.invalid", req); err == nil {
		t.Fatal("an empty confirmation was sent")
	}
}

package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
)

type recordingSupportRelayClient struct {
	endpoints []string
	requests  []builderclient.SubmitModelSupportConfirmationRequest
	refuse    map[string]error
}

func (c *recordingSupportRelayClient) SubmitModelSupportConfirmation(_ context.Context, endpoint string, req builderclient.SubmitModelSupportConfirmationRequest) (builderclient.ModelSupportRelayAck, error) {
	c.endpoints = append(c.endpoints, endpoint)
	c.requests = append(c.requests, req)
	if err := c.refuse[endpoint]; err != nil {
		return builderclient.ModelSupportRelayAck{}, err
	}
	return builderclient.ModelSupportRelayAck{SigningDigest: req.SigningDigest}, nil
}

// The first Builder that accepts takes the confirmation; one queue entry is
// enough, and a second would only race it into another batch.
func TestNexusModelSupportRelayStopsAtTheFirstAcceptance(t *testing.T) {
	client := &recordingSupportRelayClient{}
	relay, err := NewNexusModelSupportRelay(client, echoingEndpoints{}, []string{"trueopen1b1", "trueopen1b2"})
	if err != nil {
		t.Fatal(err)
	}
	digest := codec.Hash{7}
	if err := relay.RelaySupportConfirmation(context.Background(), 9, []byte{1, 2}, digest); err != nil {
		t.Fatal(err)
	}
	if len(client.endpoints) != 1 || client.endpoints[0] != "https://trueopen1b1.example" {
		t.Fatalf("endpoints = %v", client.endpoints)
	}
	if req := client.requests[0]; req.EpochIndex != 9 || string(req.Confirmation) != "\x01\x02" || req.SigningDigest != digest {
		t.Fatalf("request = %+v", req)
	}
}

func TestNexusModelSupportRelayFallsThroughToTheNextBuilder(t *testing.T) {
	client := &recordingSupportRelayClient{refuse: map[string]error{"https://trueopen1b1.example": errors.New("queue full")}}
	relay, _ := NewNexusModelSupportRelay(client, echoingEndpoints{}, []string{"trueopen1b1", "trueopen1b2"})
	if err := relay.RelaySupportConfirmation(context.Background(), 9, []byte{1}, codec.Hash{7}); err != nil {
		t.Fatal(err)
	}
	if len(client.endpoints) != 2 || client.endpoints[1] != "https://trueopen1b2.example" {
		t.Fatalf("endpoints = %v", client.endpoints)
	}
}

func TestNexusModelSupportRelayReportsEveryRefusal(t *testing.T) {
	client := &recordingSupportRelayClient{refuse: map[string]error{
		"https://trueopen1b1.example": errors.New("queue full"),
		"https://trueopen1b2.example": errors.New("stale epoch"),
	}}
	relay, _ := NewNexusModelSupportRelay(client, echoingEndpoints{}, []string{"trueopen1b1", "trueopen1b2"})
	err := relay.RelaySupportConfirmation(context.Background(), 9, []byte{1}, codec.Hash{7})
	if err == nil || !strings.Contains(err.Error(), "trueopen1b1: queue full") || !strings.Contains(err.Error(), "trueopen1b2: stale epoch") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewNexusModelSupportRelayNeedsBuilders(t *testing.T) {
	if _, err := NewNexusModelSupportRelay(&recordingSupportRelayClient{}, echoingEndpoints{}, nil); err == nil {
		t.Fatal("a relay with no Builder was built")
	}
}

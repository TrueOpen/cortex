// Package txclienttest provides an in-memory txclient for tests. It is only
// imported by tests, so it never ships in a binary.
package txclienttest

import (
	"context"
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/txclient"
)

type Fake struct {
	observations []txclient.Observation
	requests     []txclient.Request
	rejectNext   map[txclient.Kind]string
	sequence     uint64
}

func NewFake() *Fake {
	return &Fake{rejectNext: make(map[txclient.Kind]string)}
}

func (f *Fake) Probe(ctx context.Context) error {
	return ctx.Err()
}

func (f *Fake) RejectNext(kind txclient.Kind, reason string) {
	f.rejectNext[kind] = reason
}

func (f *Fake) Submit(ctx context.Context, req txclient.Request) (txclient.Observation, error) {
	if err := ctx.Err(); err != nil {
		return txclient.Observation{}, err
	}
	if err := txclient.ValidateRequest(req); err != nil {
		return txclient.Observation{}, err
	}
	f.requests = append(f.requests, req)
	f.sequence++
	digest := codec.HashWithDomain("TRUEOPEN_TXCLIENT_REQUEST_V1", []byte(req.TaskID), []byte(req.Kind), req.Payload)
	obs := txclient.Observation{
		TaskID:          req.TaskID,
		Kind:            req.Kind,
		PayloadDigest:   digest,
		TxHash:          fmt.Sprintf("fake-tx-%d-%x", f.sequence, digest[:6]),
		AccountSequence: f.sequence,
		Fee:             req.FeeCap,
		GasPayer:        req.GasPayer,
		DeadlineHeight:  req.DeadlineHeight,
		MaterialDigest:  req.MaterialDigest,
	}
	if reason, ok := f.rejectNext[req.Kind]; ok {
		delete(f.rejectNext, req.Kind)
		obs.Rejected = true
		obs.RejectReason = reason
	} else {
		obs.Accepted = true
	}
	f.observations = append(f.observations, obs)
	return obs, nil
}

func (f *Fake) Accepted(kind txclient.Kind) []txclient.Observation {
	return f.filter(kind, true)
}

func (f *Fake) Rejected(kind txclient.Kind) []txclient.Observation {
	return f.filter(kind, false)
}

func (f *Fake) Requests() []txclient.Request {
	return append([]txclient.Request(nil), f.requests...)
}

func (f *Fake) filter(kind txclient.Kind, accepted bool) []txclient.Observation {
	var out []txclient.Observation
	for _, obs := range f.observations {
		if obs.Kind != kind {
			continue
		}
		if accepted && obs.Accepted {
			out = append(out, obs)
		}
		if !accepted && obs.Rejected {
			out = append(out, obs)
		}
	}
	return out
}

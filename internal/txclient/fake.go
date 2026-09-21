package txclient

import (
	"context"
	"fmt"

	"github.com/SingaXYZ/cortex/internal/codec"
)

type Fake struct {
	observations []Observation
	requests     []Request
	rejectNext   map[Kind]string
	sequence     uint64
}

func NewFake() *Fake {
	return &Fake{rejectNext: make(map[Kind]string)}
}

func (f *Fake) Probe(ctx context.Context) error {
	return ctx.Err()
}

func (f *Fake) RejectNext(kind Kind, reason string) {
	f.rejectNext[kind] = reason
}

func (f *Fake) Submit(ctx context.Context, req Request) (Observation, error) {
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	if err := ValidateRequest(req); err != nil {
		return Observation{}, err
	}
	f.requests = append(f.requests, req)
	f.sequence++
	digest := codec.HashWithDomain("TRUEOPEN_TXCLIENT_REQUEST_V1", []byte(req.TaskID), []byte(req.Kind), req.Payload)
	obs := Observation{
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

func (f *Fake) Accepted(kind Kind) []Observation {
	return f.filter(kind, true)
}

func (f *Fake) Rejected(kind Kind) []Observation {
	return f.filter(kind, false)
}

func (f *Fake) Requests() []Request {
	return append([]Request(nil), f.requests...)
}

func (f *Fake) filter(kind Kind, accepted bool) []Observation {
	var out []Observation
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

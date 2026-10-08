package modelservice

import (
	"bytes"
	"context"
	"fmt"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/modelmanifest"
)

// DecodeVectorsSource returns the DECODE_VECTORS conformance cases of a
// registered profile's manifest -- nil when the manifest declares none --
// read only from bytes that hash to digests the chain's manifest_hash
// authenticates. *modelmanifest.Fetcher implements it.
type DecodeVectorsSource interface {
	DecodeVectors(context.Context, chainclient.CurrentProfileSnapshot) ([]modelmanifest.DecodeVector, error)
}

// SetDecodeVectorsSource installs where DECODE_VECTORS come from. Without a
// source the conformance check is skipped, which is the pre-vectors behavior;
// the daemon sets it wherever it sets the output decoding source.
func (s *LocalService) SetDecodeVectorsSource(source DecodeVectorsSource) {
	s.mu.Lock()
	s.decodeVectorsSource = source
	s.mu.Unlock()
}

// ensureDecodeVectorsPass proves, once per (manifest, served model), that this
// engine's decode reproduces every DECODE_VECTORS case the profile manifest
// declares: for each vector, decode(T minus one trailing EOS) through the
// calibrated /detokenize must equal the committed bytes the manifest expects.
// A mismatch means this engine's tokenizer is not the profile's, so nothing
// this node decodes can be committed or compared: the Worker would publish
// outputs every conforming Verifier faults, and the Verifier would fault every
// conforming Worker. Both callers refuse their task on error.
//
// A profile that declares no vectors passes vacuously -- the calibration probe
// (calibrateDetokenize) remains the only conformance evidence there. Success
// is cached; a failure is not, so a transient fetch or engine error is retried
// on the next task.
func (s *LocalService) ensureDecodeVectorsPass(ctx context.Context, profile localModelProfile) error {
	if profile.chain == nil {
		// The dev path has no registered manifest to declare vectors.
		return nil
	}
	s.mu.RLock()
	source := s.decodeVectorsSource
	s.mu.RUnlock()
	if source == nil {
		return nil
	}
	key := profile.chain.ManifestHash.Hex() + "|" + profile.ServedModel
	s.mu.RLock()
	passed := s.decodeVectorsPassed[key]
	s.mu.RUnlock()
	if passed {
		return nil
	}
	vectors, err := source.DecodeVectors(ctx, *profile.chain)
	if err != nil {
		return fmt.Errorf("modelservice local: profile %s@%s: obtain DECODE_VECTORS: %w", profile.ModelID, profile.ProfileVersion, err)
	}
	for index, vector := range vectors {
		ids := make([]int, len(vector.TokenIDs))
		for i, id := range vector.TokenIDs {
			ids[i] = int(id)
		}
		committed := ids[:profile.OutputDecoding.CommittedTokenCount(ids)]
		decoded := []byte{}
		if len(committed) > 0 {
			if decoded, err = s.detokenizeIDs(ctx, profile.ServedModel, committed); err != nil {
				return fmt.Errorf("modelservice local: DECODE_VECTORS[%d]: %w", index, err)
			}
		}
		if !bytes.Equal(decoded, vector.ExpectedBytes) {
			return fmt.Errorf("modelservice local: DECODE_VECTORS[%d] failed on %s: %d token ids decoded to %q, the profile manifest expects %q; "+
				"this engine's tokenizer does not decode like the profile's, so no output it derives may be committed or compared",
				index, profile.ServedModel, len(vector.TokenIDs), decoded, vector.ExpectedBytes)
		}
	}
	s.mu.Lock()
	if s.decodeVectorsPassed == nil {
		s.decodeVectorsPassed = make(map[string]bool)
	}
	s.decodeVectorsPassed[key] = true
	s.mu.Unlock()
	return nil
}

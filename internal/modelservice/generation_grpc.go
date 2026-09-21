package modelservice

import (
	"github.com/SingaXYZ/cortex/internal/nodewire"
	cortexv1 "github.com/SingaXYZ/cortex/proto/cortex/v1"
)

func generationContextProto(g *nodewire.GenerationContext) *cortexv1.GenerationContext {
	if g == nil {
		return nil
	}
	d := g.Params.DecodingParams
	return &cortexv1.GenerationContext{
		ModelId: g.ModelID, ProfileVersion: g.ProfileVersion,
		TaskType: g.TaskType, OutputBudgetBucket: g.OutputBudgetBucket,
		Params: &cortexv1.GenerationParamsV1{
			GenerationParamsSchemaVersion: g.Params.SchemaVersion,
			MaxOutputTokens:               g.Params.MaxOutputTokens, MaxOutputDuration: g.Params.MaxOutputDuration,
			DecodingParams: &cortexv1.DecodingParamsV1{
				SamplingEnabled: d.SamplingEnabled, TemperatureMilli: d.TemperatureMilli,
				TopPPpm: d.TopPPPM, TopK: d.TopK, Seed: d.Seed,
				PresencePenaltyMilli: d.PresencePenaltyMilli, FrequencyPenaltyMilli: d.FrequencyPenaltyMilli,
				RepetitionPenaltyPpm: d.RepetitionPenaltyPPM,
				StopSequences:        append([]string(nil), d.StopSequences...), StopTokenIds: append([]uint32(nil), d.StopTokenIDs...),
			},
		},
	}
}

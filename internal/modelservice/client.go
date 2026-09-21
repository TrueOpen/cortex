package modelservice

import "context"

type StaticClient struct {
	Backend Client
}

func (c StaticClient) Health(ctx context.Context, req HealthRequest) (HealthResponse, error) {
	return c.Backend.Health(ctx, req)
}

func (c StaticClient) ListCapabilities(ctx context.Context, req ListCapabilitiesRequest) (ListCapabilitiesResponse, error) {
	return c.Backend.ListCapabilities(ctx, req)
}

func (c StaticClient) GetModelDetails(ctx context.Context, req GetModelDetailsRequest) (GetModelDetailsResponse, error) {
	return c.Backend.GetModelDetails(ctx, req)
}

func (c StaticClient) LoadModel(ctx context.Context, req LoadModelRequest) (LoadModelResponse, error) {
	return c.Backend.LoadModel(ctx, req)
}

func (c StaticClient) Estimate(ctx context.Context, req EstimateRequest) (EstimateResponse, error) {
	return c.Backend.Estimate(ctx, req)
}

func (c StaticClient) Infer(ctx context.Context, req InferRequest) (InferResponse, error) {
	return c.Backend.Infer(ctx, req)
}

func (c StaticClient) Verify(ctx context.Context, req VerifyRequest) (VerifyResponse, error) {
	return c.Backend.Verify(ctx, req)
}

func (c StaticClient) FetchArtifact(ctx context.Context, req FetchArtifactRequest) (Artifact, error) {
	return c.Backend.FetchArtifact(ctx, req)
}

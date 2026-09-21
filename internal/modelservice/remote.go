package modelservice

import (
	"context"
	"fmt"
)

type Transport interface {
	Invoke(context.Context, string, any, any) error
}

type RemoteClient struct {
	transport Transport
}

func NewRemoteClient(transport Transport) *RemoteClient {
	return &RemoteClient{transport: transport}
}

func (c *RemoteClient) invoke(ctx context.Context, method string, req any, resp any) error {
	if c.transport == nil {
		return fmt.Errorf("modelservice transport is required")
	}
	return c.transport.Invoke(ctx, "/cortex.v1.ModelManagementService/"+method, req, resp)
}

func (c *RemoteClient) Health(ctx context.Context, req HealthRequest) (HealthResponse, error) {
	var resp HealthResponse
	return resp, c.invoke(ctx, "Health", req, &resp)
}

func (c *RemoteClient) ListCapabilities(ctx context.Context, req ListCapabilitiesRequest) (ListCapabilitiesResponse, error) {
	var resp ListCapabilitiesResponse
	return resp, c.invoke(ctx, "ListCapabilities", req, &resp)
}

func (c *RemoteClient) GetModelDetails(ctx context.Context, req GetModelDetailsRequest) (GetModelDetailsResponse, error) {
	var resp GetModelDetailsResponse
	return resp, c.invoke(ctx, "GetModelDetails", req, &resp)
}

func (c *RemoteClient) LoadModel(ctx context.Context, req LoadModelRequest) (LoadModelResponse, error) {
	var resp LoadModelResponse
	return resp, c.invoke(ctx, "LoadModel", req, &resp)
}

func (c *RemoteClient) Estimate(ctx context.Context, req EstimateRequest) (EstimateResponse, error) {
	var resp EstimateResponse
	return resp, c.invoke(ctx, "Estimate", req, &resp)
}

func (c *RemoteClient) Infer(ctx context.Context, req InferRequest) (InferResponse, error) {
	var resp InferResponse
	if err := ValidateGenerationContext(req.Generation, req.GenerationParamsDigest, req.ModelID, req.ProfileVersion); err != nil {
		return resp, err
	}
	if err := c.invoke(ctx, "Infer", req, &resp); err != nil {
		return InferResponse{}, err
	}
	if resp.Error == nil {
		if err := validateGenerationResponseDigest(req.GenerationParamsDigest, resp.GenerationParamsDigest); err != nil {
			return InferResponse{}, err
		}
	}
	return resp, nil
}

func (c *RemoteClient) Verify(ctx context.Context, req VerifyRequest) (VerifyResponse, error) {
	var resp VerifyResponse
	if err := ValidateGenerationContext(req.Generation, req.GenerationParamsDigest, req.ModelID, req.ProfileVersion); err != nil {
		return resp, err
	}
	if err := c.invoke(ctx, "Verify", req, &resp); err != nil {
		return VerifyResponse{}, err
	}
	if resp.Error == nil {
		if err := validateGenerationResponseDigest(req.GenerationParamsDigest, resp.GenerationParamsDigest); err != nil {
			return VerifyResponse{}, err
		}
	}
	return resp, nil
}

func (c *RemoteClient) FetchArtifact(ctx context.Context, req FetchArtifactRequest) (Artifact, error) {
	var artifact Artifact
	if err := c.invoke(ctx, "FetchArtifact", req, &artifact); err != nil {
		return Artifact{}, err
	}
	// Re-check the bound the caller asked for. Only the gRPC transport enforces it
	// while streaming; a transport that ignores SizeLimitBytes would otherwise
	// hand back an oversized artifact and the caller would never know the bound
	// had been dropped. This cannot prevent the buffering that already happened
	// inside such a transport, but it stops the bytes going any further.
	if req.SizeLimitBytes > 0 && uint64(len(artifact.Data)) > req.SizeLimitBytes {
		return Artifact{}, fmt.Errorf("%w: kind=%s, bound=%d, observed=%d", ErrArtifactSizeExceeded, req.Kind, req.SizeLimitBytes, len(artifact.Data))
	}
	ref, err := ParseArtifactRef(req.Ref)
	if err != nil {
		return Artifact{}, err
	}
	if err := verifyArtifactBytes(ref, artifact.Data, req.AllowEmpty); err != nil {
		return Artifact{}, err
	}
	return artifact, nil
}

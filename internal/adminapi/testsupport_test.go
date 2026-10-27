package adminapi

import (
	"context"

	"github.com/TrueOpen/cortex/internal/modelregistry"
)

// Declarations only tests use, kept out of the production binary.

func (c *Client) ModelStatus(ctx context.Context, req modelregistry.StatusRequest) (modelregistry.ModelStatus, error) {
	var out modelregistry.ModelStatus
	err := c.post(ctx, "/v1/model/status", req, &out)
	return out, err
}

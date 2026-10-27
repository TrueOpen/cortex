package observability

// Declarations only tests use, kept out of the production binary.

func NewHealth() *Health {
	return newHealth([]string{"chain", "model", "store"}, nil)
}

func NewIntegrationHealthWithTxRequirement(requireTxBroadcaster bool) *Health {
	return NewIntegrationHealthWithRuntimeRequirements(requireTxBroadcaster, true, true)
}

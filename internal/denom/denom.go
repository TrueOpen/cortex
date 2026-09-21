// Package denom validates the bank denomination syntax used by Node.
package denom

import "regexp"

// Matches Cosmos SDK types.ValidateDenom, without importing the SDK runtime.
var canonical = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9/:._-]{2,127}$`)

// Valid checks syntax only. Deployment must select the chain's business_denom.
func Valid(value string) bool {
	return canonical.MatchString(value)
}

package builderclient

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Declarations only tests use, kept out of the production binary.

// OutputAvailableDedupID returns a stable dedup ID for an OUTPUT_AVAILABLE event.
func OutputAvailableDedupID(taskID, outputHash string) string {
	material := strings.Join([]string{"output-available", taskID, outputHash}, "\x00")
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

// NewNATSSubscriber connects with a token (dev); production uses
// NewNATSSubscriberWithAuth with creds and CA files.
func NewNATSSubscriber(natsURL string, token string, jetStreamStream string, durablePrefix ...string) (Subscriber, error) {
	return NewNATSSubscriberWithAuth(NATSAuth{URL: natsURL, Token: token}, jetStreamStream, durablePrefix...)
}

// Package natsurl keeps Nexus NATS credentials out of diagnostic output.
//
// The devnet NATS URL carries its credentials in the userinfo. The tools never
// print the URL on a happy path, but url.Parse and the NATS client both fold
// the URL they were handed into their error strings, so any failure path can
// echo it. Everything printed by scripts/testorder and scripts/testassign goes
// through here first.
//
// This cannot hide the URL from the process argument list of whichever host
// runs the command; only the operator's handling of the value can.
package natsurl

import (
	"net/url"
	"strings"
)

const placeholder = "redacted"

// Redact returns the URL with its userinfo replaced, safe to print. A URL that
// does not parse is not echoed at all: the parse failure may be in the
// userinfo itself, so there is nothing here to trust.
func Redact(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "<unparseable nats url>"
	}
	if parsed.User != nil {
		parsed.User = url.User(placeholder)
	}
	return parsed.String()
}

// Scrub removes the URL, and the credentials inside it, from text that is
// about to be printed - typically an error string that wrapped the URL.
func Scrub(text, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return text
	}
	text = strings.ReplaceAll(text, raw, Redact(raw))
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User == nil {
		return text
	}
	// The userinfo is replaced both as written (percent-encoded) and decoded,
	// because an error may carry either form.
	if encoded := parsed.User.String(); encoded != "" {
		text = strings.ReplaceAll(text, encoded, placeholder)
	}
	if password, ok := parsed.User.Password(); ok {
		if password != "" {
			text = strings.ReplaceAll(text, password, placeholder)
		}
	} else if user := parsed.User.Username(); user != "" {
		// No password means the userinfo is a bare token, so the username is
		// itself the secret. With a password the username is not, and blanket
		// replacing it would mangle unrelated words in the message.
		text = strings.ReplaceAll(text, user, placeholder)
	}
	return text
}

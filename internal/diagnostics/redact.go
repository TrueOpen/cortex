package diagnostics

import "net/url"

// RedactEndpoint returns a copy of raw with any URL userinfo replaced by
// "redacted". A value that does not parse as a URL, or that carries no
// userinfo, is returned byte-for-byte unchanged: most endpoints reported here
// are filesystem paths, operator addresses or comma-separated model lists, and
// rewriting those through a URL parser would corrupt values the redaction was
// never meant to touch.
//
// It is applied where a DependencyStatus is built rather than where one is
// printed, because the record travels to the admin socket, the health endpoint
// and the startup log, and every one of those is somewhere an operator copies
// output from.
func RedactEndpoint(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = url.User("redacted")
	return u.String()
}

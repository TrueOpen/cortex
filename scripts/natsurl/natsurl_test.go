package natsurl

import "strings"

import "testing"

func TestRedactRemovesUserinfo(t *testing.T) {
	got := Redact("nats://user:s3cret@bus.example:4222")
	if strings.Contains(got, "s3cret") || strings.Contains(got, "user") {
		t.Fatalf("credentials survived redaction: %s", got)
	}
	if !strings.Contains(got, "bus.example:4222") {
		t.Fatalf("host lost: %s", got)
	}
}

func TestRedactRefusesUnparseableURL(t *testing.T) {
	if got := Redact("nats://user:s3cret@bus.example:4222/\x7f\x00"); strings.Contains(got, "s3cret") {
		t.Fatalf("credentials survived redaction: %s", got)
	}
}

func TestScrubRemovesWrappedURLAndPassword(t *testing.T) {
	raw := "nats://user:s3cret@bus.example:4222"
	text := Scrub(`parse "`+raw+`": bad; auth for s3cret failed`, raw)
	if strings.Contains(text, "s3cret") {
		t.Fatalf("credentials survived scrub: %s", text)
	}
}

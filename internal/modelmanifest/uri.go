package modelmanifest

import (
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"strconv"
	"strings"
)

// DefaultMaxManifestURIBytes is the default of the chain parameter
// max_manifest_uri_bytes.
const DefaultMaxManifestURIBytes = 2048

// ValidateURI applies the manifest_uri syntax. The value is hashed byte for
// byte inside the model projection, so it is checked exactly as given and
// never normalized; wherever two readings could normalize differently, the
// stricter one is taken and the other form is rejected.
//
//   - 1..maxBytes bytes, every byte printable ASCII (0x21-0x7E), no fragment.
//   - https:// + host + optional :port + optional /path and ?query. The host
//     is a lowercase DNS name of at least two labels (letters, digits, inner
//     hyphens, 1-63 bytes each, no trailing dot, top-level label not all
//     digits), a canonical dotted-decimal IPv4 literal, or a bracketed IPv6
//     literal in canonical compressed lowercase form without a zone. No
//     userinfo. The port is decimal 1-65535 without leading zeros. Path and
//     query use the RFC 3986 pchar set with uppercase %XX escapes.
//   - ipfs:// + CID + optional /path, no query. The CID is CIDv0 (Qm...,
//     base58btc, a sha2-256 multihash) or CIDv1 as multibase b followed by
//     lowercase unpadded base32 whose multihash length matches its digest.
func ValidateURI(uri string, maxBytes int) error {
	_, err := ParseURI(uri, maxBytes)
	return err
}

// URI is a manifest_uri that passed ValidateURI.
type URI struct {
	Raw    string
	Scheme string // "https" or "ipfs"
	// Host and Port are set for https. Host keeps IPv6 brackets.
	Host string
	Port string
	// CID is set for ipfs.
	CID string
	// Rest is the path and query that follow the host or CID, as given.
	Rest string
}

// ParseURI validates uri like ValidateURI and returns its parts.
func ParseURI(uri string, maxBytes int) (URI, error) {
	if len(uri) == 0 || len(uri) > maxBytes {
		return URI{}, fmt.Errorf("manifest_uri length %d is outside 1..%d", len(uri), maxBytes)
	}
	for index := 0; index < len(uri); index++ {
		if uri[index] < 0x21 || uri[index] > 0x7e {
			return URI{}, fmt.Errorf("manifest_uri byte 0x%02x at %d is not printable ASCII", uri[index], index)
		}
	}
	if strings.Contains(uri, "#") {
		return URI{}, errors.New("manifest_uri must not carry a fragment")
	}
	if rest, ok := strings.CutPrefix(uri, "https://"); ok {
		return parseHTTPSURI(uri, rest)
	}
	if rest, ok := strings.CutPrefix(uri, "ipfs://"); ok {
		return parseIPFSURI(uri, rest)
	}
	return URI{}, errors.New("manifest_uri scheme must be exactly https:// or ipfs://")
}

func parseHTTPSURI(raw, rest string) (URI, error) {
	authority, tail := rest, ""
	if end := strings.IndexAny(rest, "/?"); end >= 0 {
		authority, tail = rest[:end], rest[end:]
	}
	if strings.Contains(authority, "@") {
		return URI{}, errors.New("manifest_uri must not carry userinfo")
	}
	host, port := authority, ""
	if strings.HasPrefix(authority, "[") {
		closing := strings.Index(authority, "]")
		if closing < 0 {
			return URI{}, errors.New("manifest_uri IPv6 literal is not terminated")
		}
		host, port = authority[:closing+1], authority[closing+1:]
		if err := validateIPv6Literal(host); err != nil {
			return URI{}, err
		}
	} else {
		if colon := strings.LastIndex(authority, ":"); colon >= 0 {
			host, port = authority[:colon], authority[colon:]
		}
		if err := validateHostName(host); err != nil {
			return URI{}, err
		}
	}
	if port != "" {
		digits, ok := strings.CutPrefix(port, ":")
		if !ok || !canonicalDecimal(digits, 1, 65535) {
			return URI{}, fmt.Errorf("manifest_uri port %q is not decimal 1..65535 without leading zeros", port)
		}
		port = digits
	}
	path, query := tail, ""
	if mark := strings.Index(tail, "?"); mark >= 0 {
		path, query = tail[:mark], tail[mark+1:]
	}
	if err := validateURIChars(path, "/"); err != nil {
		return URI{}, fmt.Errorf("manifest_uri path: %w", err)
	}
	if err := validateURIChars(query, "/?"); err != nil {
		return URI{}, fmt.Errorf("manifest_uri query: %w", err)
	}
	return URI{Raw: raw, Scheme: "https", Host: host, Port: port, Rest: tail}, nil
}

func validateHostName(host string) error {
	if host == "" {
		return errors.New("manifest_uri host is missing")
	}
	if host[0] >= '0' && host[0] <= '9' && strings.Trim(host, "0123456789.") == "" {
		return validateIPv4Literal(host)
	}
	if len(host) > 253 || strings.HasSuffix(host, ".") {
		return fmt.Errorf("manifest_uri host %q is too long or ends in a dot", host)
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return fmt.Errorf("manifest_uri host %q is not a fully qualified name", host)
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("manifest_uri host label %q is malformed", label)
		}
		for index := 0; index < len(label); index++ {
			c := label[index]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("manifest_uri host label %q must be lowercase letters, digits or hyphens", label)
			}
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return fmt.Errorf("manifest_uri top-level label %q is all digits", labels[len(labels)-1])
	}
	return nil
}

func validateIPv4Literal(host string) error {
	octets := strings.Split(host, ".")
	if len(octets) != 4 {
		return fmt.Errorf("manifest_uri IPv4 literal %q needs four octets", host)
	}
	for _, octet := range octets {
		if !canonicalDecimal(octet, 0, 255) {
			return fmt.Errorf("manifest_uri IPv4 octet %q is not decimal 0..255 without leading zeros", octet)
		}
	}
	return nil
}

func validateIPv6Literal(bracketed string) error {
	inner := strings.TrimSuffix(strings.TrimPrefix(bracketed, "["), "]")
	if strings.Contains(inner, "%") {
		return errors.New("manifest_uri IPv6 literal must not carry a zone")
	}
	addr, err := netip.ParseAddr(inner)
	// An IPv4-mapped literal has a second spelling as plain IPv4, so it is
	// refused like any other form that could be normalized.
	if err != nil || !addr.Is6() || addr.Is4In6() {
		return fmt.Errorf("manifest_uri %q is not an IPv6 literal", inner)
	}
	if addr.String() != inner {
		return fmt.Errorf("manifest_uri IPv6 literal %q is not in canonical form %q", inner, addr.String())
	}
	return nil
}

// canonicalDecimal accepts digits only, no leading zero (except "0" itself),
// within [low, high].
func canonicalDecimal(digits string, low, high int) bool {
	if digits == "" || len(digits) > 5 || len(digits) > 1 && digits[0] == '0' || strings.Trim(digits, "0123456789") != "" {
		return false
	}
	value, err := strconv.Atoi(digits)
	return err == nil && value >= low && value <= high
}

// validateURIChars allows the RFC 3986 pchar set (unreserved, sub-delims, ":"
// and "@"), the extra characters given, and %XX with uppercase hex.
func validateURIChars(value, extra string) error {
	const pchar = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:@"
	for index := 0; index < len(value); index++ {
		c := value[index]
		if c == '%' {
			if index+2 >= len(value) || !isUpperHexDigit(value[index+1]) || !isUpperHexDigit(value[index+2]) {
				return fmt.Errorf("percent-encoding at %d is not %%XX with uppercase hex", index)
			}
			index += 2
			continue
		}
		if !strings.ContainsRune(pchar+extra, rune(c)) {
			return fmt.Errorf("character %q is not allowed", c)
		}
	}
	return nil
}

func isUpperHexDigit(c byte) bool { return c >= '0' && c <= '9' || c >= 'A' && c <= 'F' }

func parseIPFSURI(raw, rest string) (URI, error) {
	cid, path := rest, ""
	if slash := strings.Index(rest, "/"); slash >= 0 {
		cid, path = rest[:slash], rest[slash:]
	}
	if strings.Contains(rest, "?") {
		return URI{}, errors.New("manifest_uri ipfs form does not take a query")
	}
	if err := validateCID(cid); err != nil {
		return URI{}, err
	}
	if err := validateURIChars(path, "/"); err != nil {
		return URI{}, fmt.Errorf("manifest_uri path: %w", err)
	}
	return URI{Raw: raw, Scheme: "ipfs", CID: cid, Rest: path}, nil
}

const base58btcAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var base32Lower = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func validateCID(cid string) error {
	switch {
	case strings.HasPrefix(cid, "Qm"):
		if len(cid) != 46 {
			return errors.New("manifest_uri CIDv0 must be 46 characters")
		}
		value := new(big.Int)
		for index := 0; index < len(cid); index++ {
			digit := strings.IndexByte(base58btcAlphabet, cid[index])
			if digit < 0 {
				return fmt.Errorf("manifest_uri CIDv0 character %q is not base58btc", cid[index])
			}
			value.Mul(value, big.NewInt(58)).Add(value, big.NewInt(int64(digit)))
		}
		multihash := value.Bytes()
		if len(multihash) != 34 || multihash[0] != 0x12 || multihash[1] != 0x20 {
			return errors.New("manifest_uri CIDv0 is not a sha2-256 multihash")
		}
		return nil
	case strings.HasPrefix(cid, "b"):
		body := cid[1:]
		if body == "" || strings.Trim(body, "abcdefghijklmnopqrstuvwxyz234567") != "" {
			return errors.New("manifest_uri CIDv1 must be lowercase unpadded base32")
		}
		raw, err := base32Lower.DecodeString(body)
		if err != nil || base32Lower.EncodeToString(raw) != body {
			return errors.New("manifest_uri CIDv1 base32 is not canonical")
		}
		version, n := binary.Uvarint(raw)
		if n <= 0 || version != 1 {
			return errors.New("manifest_uri CID version is not 1")
		}
		raw = raw[n:]
		for _, field := range []string{"codec", "multihash code"} {
			if _, n = binary.Uvarint(raw); n <= 0 {
				return fmt.Errorf("manifest_uri CIDv1 %s varint is malformed", field)
			}
			raw = raw[n:]
		}
		length, n := binary.Uvarint(raw)
		if n <= 0 || length == 0 || uint64(len(raw)-n) != length {
			return errors.New("manifest_uri CIDv1 multihash length does not match its digest")
		}
		return nil
	default:
		return errors.New("manifest_uri CID must be CIDv0 (Qm...) or CIDv1 base32 (b...)")
	}
}

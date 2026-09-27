package modelmanifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/TrueOpen/cortex/internal/codec"
)

// canonicalJSON re-encodes one JSON value canonically: object keys sorted by
// UTF-8 bytes and the string escaping of codec.CanonicalJSON. Numbers are
// decoded as literals, so no value ever passes through a float.
func canonicalJSON(encoded []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the JSON value")
	}
	return codec.CanonicalJSON(value)
}

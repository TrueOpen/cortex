package codec

import (
	"bytes"
	"encoding/json"
)

// CanonicalJSON encodes value as the canonical JSON the protocol hashes and
// signs: object keys sorted (maps) or in declared order (structs), no
// insignificant whitespace, and strings escaping only '"', '\\', U+0000..U+001F,
// U+2028 and U+2029. HTML escaping is off, so '<', '>' and '&' are written as
// themselves; json.Marshal would write them as <, > and & and
// every digest over such a value would differ from other implementations.
func CanonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	// Encode appends a newline that is not part of the value.
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

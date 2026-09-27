package modelmanifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// canonicalJSON re-encodes one JSON value canonically. It decodes numbers as
// literals, so no value ever passes through a float.
func canonicalJSON(encoded []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data after the JSON value")
	}
	var out bytes.Buffer
	if err := writeCanonical(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func writeCanonical(out *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case json.Number:
		// Only plain non-negative or negative integers are canonical.
		text := v.String()
		if strings.ContainsAny(text, ".eE+") || strings.HasPrefix(strings.TrimPrefix(text, "-"), "0") && text != "0" {
			return fmt.Errorf("number %s is not a canonical integer", text)
		}
		out.WriteString(text)
	case string:
		writeCanonicalString(out, v)
	case []any:
		out.WriteByte('[')
		for index, item := range v {
			if index > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonical(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		// sort.Strings orders by bytes, which is UTF-8 byte order.
		sort.Strings(keys)
		out.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				out.WriteByte(',')
			}
			writeCanonicalString(out, key)
			out.WriteByte(':')
			if err := writeCanonical(out, v[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON value %T", value)
	}
	return nil
}

// writeCanonicalString uses the shortest legal escape for every character:
// only the quote, the backslash and control characters are escaped, and every
// other character, including non-ASCII, is written as its UTF-8 bytes.
func writeCanonicalString(out *bytes.Buffer, value string) {
	const hexDigits = "0123456789abcdef"
	out.WriteByte('"')
	for index := 0; index < len(value); index++ {
		c := value[index]
		switch c {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if c < 0x20 {
				out.WriteString(`\u00`)
				out.WriteByte(hexDigits[c>>4])
				out.WriteByte(hexDigits[c&0xf])
			} else {
				out.WriteByte(c)
			}
		}
	}
	out.WriteByte('"')
}

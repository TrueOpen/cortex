package modelservice

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// A streaming response that has already sent its 200 cannot report a failure
// through the status line. vLLM writes the error into the stream instead, as a
// `data:` frame holding {"error":{...}} (older releases: a flat
// {"object":"error",...}), and a server that gives up without one simply ends
// the stream. Both used to fall through to the token checks and surface as an
// unrelated "length mismatch" or an empty finish reason, which named neither
// the cause nor whether retrying could help (TrueOpen/cortex#100).

// streamErrorBody is the part of an in-band error frame that matters here.
type streamErrorBody struct {
	Message string          `json:"message"`
	Type    string          `json:"type"`
	Code    json.RawMessage `json:"code"`
}

// streamFrameError returns the classified error an in-band error frame
// reports, or nil when payload is an ordinary chunk.
func streamFrameError(payload []byte) error {
	var frame struct {
		Error  *streamErrorBody `json:"error"`
		Object string           `json:"object"`
		streamErrorBody
	}
	if err := json.Unmarshal(payload, &frame); err != nil {
		return nil
	}
	body := frame.Error
	if body == nil {
		if frame.Object != "error" {
			return nil
		}
		body = &frame.streamErrorBody
	}
	code := streamErrorCode(body.Code)
	err := fmt.Errorf("modelservice local: the model service aborted the stream: %s (type %q, code %d)", strings.TrimSpace(body.Message), body.Type, code)
	fields := []FaultField{{Key: "code", Value: strconv.Itoa(code)}}
	if refusesTheRequest(code) {
		// The same request is refused the same way every time: re-running it
		// spends retries until the chain deadline and changes nothing.
		return Deterministic("MODEL_SERVICE_REFUSED", err, fields...)
	}
	return Transient("MODEL_SERVICE_STREAM_ERROR", err, fields...)
}

// refusesTheRequest is the HTTP reading of code: a client error other than a
// timeout or a rate limit, or 501, which says the service cannot do this at
// all. Everything else, including no code, may clear on another attempt.
func refusesTheRequest(code int) bool {
	switch {
	case code == http.StatusRequestTimeout || code == http.StatusTooManyRequests:
		return false
	case code >= 400 && code < 500:
		return true
	default:
		return code == http.StatusNotImplemented
	}
}

// streamErrorCode reads a code written as a number or a numeric string; 0 when
// absent or not numeric.
func streamErrorCode(raw json.RawMessage) int {
	text := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	code, err := strconv.Atoi(text)
	if err != nil {
		return 0
	}
	return code
}

// errStreamTruncated is a stream that ended without a finish reason and
// without an error frame: the server dropped the connection mid-generation.
// Transient, because nothing says the next attempt fails the same way; once
// output frames are signed the task runner refuses to regenerate anyway.
func errStreamTruncated(path string, tokens int) error {
	return Transient("MODEL_STREAM_TRUNCATED",
		fmt.Errorf("modelservice local: %s stream ended after %d tokens without a finish_reason (the model service aborted the generation; see its log)", path, tokens),
		FaultField{Key: "tokens", Value: strconv.Itoa(tokens)})
}

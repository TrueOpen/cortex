// Package vllmstub serves a scripted vLLM OpenAI-compatible endpoint for
// tests: a streaming /v1/chat/completions that answers with a fixed sequence
// of server-sent events, plus /v1/models. It lives outside the _test files so
// that tests in other packages, such as the Worker's, drive the local model
// service through exactly the same stub as its own tests do.
package vllmstub

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ChatStream describes one stub server.
type ChatStream struct {
	// Frames are marshalled to JSON, one per "data:" event, in order. A
	// keepalive comment precedes them and "data: [DONE]" follows them.
	Frames []any
	// Models are the served model names /v1/models lists.
	Models []string
	// Metrics, when set, writes the /metrics body.
	Metrics func(http.ResponseWriter)
	// OnRequest, when set, receives each /v1/chat/completions request body.
	OnRequest func(body []byte)
}

// Start runs the stub until the test ends.
func (c ChatStream) Start(t testing.TB) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metrics":
			if c.Metrics == nil {
				http.NotFound(w, r)
				return
			}
			c.Metrics(w)
			return
		case "/v1/models":
			data := make([]map[string]any, 0, len(c.Models))
			for _, model := range c.Models {
				data = append(data, map[string]any{"id": model, "object": "model"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
			return
		case "/v1/chat/completions":
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || !json.Valid(body) {
			http.Error(w, "request body is not JSON", http.StatusBadRequest)
			return
		}
		if c.OnRequest != nil {
			c.OnRequest(body)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		flush := func() {
			if flusher != nil {
				flusher.Flush()
			}
		}
		fmt.Fprint(w, ": keepalive\n\n")
		for _, frame := range c.Frames {
			payload, err := json.Marshal(frame)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", payload)
			flush()
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		flush()
	}))
	t.Cleanup(server.Close)
	return server
}

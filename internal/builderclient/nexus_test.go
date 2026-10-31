package builderclient

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestNewNexusHTTPClientAppliesTLSFloor pins the transport hardening the Nexus
// HTTP client injects when the caller brings no transport of its own, and that a
// caller which does bring one keeps it -- which is how a test server's root is
// trusted.
func TestNewNexusHTTPClientAppliesTLSFloor(t *testing.T) {
	client := newNexusHTTPClient(nil, nexusDataTimeout)
	if client.Timeout != nexusDataTimeout {
		t.Fatalf("timeout = %s, want %s", client.Timeout, nexusDataTimeout)
	}
	if client.CheckRedirect == nil {
		t.Fatal("redirect policy = nil; a 307 would replay the signed body off-origin")
	}
	// The pin router fronts one base transport for unpinned requests; the TLS
	// floor lives on that base and is cloned into every per-pin transport.
	router, ok := client.Transport.(*pinRouter)
	if !ok {
		t.Fatalf("transport = %T, want *pinRouter fronting the Nexus TLS floor", client.Transport)
	}
	transport := router.base
	switch {
	case transport.TLSClientConfig == nil:
		t.Fatal("TLSClientConfig = nil, want the Nexus TLS floor")
	case transport.TLSClientConfig.MinVersion != tls.VersionTLS12:
		t.Fatalf("MinVersion = %#x, want TLS 1.2", transport.TLSClientConfig.MinVersion)
	case transport.TLSClientConfig.InsecureSkipVerify:
		t.Fatal("InsecureSkipVerify = true; hostname verification is the only binding to the descriptor identity")
	}

	injected := &http.Transport{}
	kept := newNexusHTTPClient(&http.Client{Transport: injected}, nexusDataTimeout)
	if kept.Transport != injected {
		t.Fatalf("transport = %T, want the injected transport preserved", kept.Transport)
	}
}

func TestNexusHTTPClientRedirectPolicy(t *testing.T) {
	t.Run("same HTTPS origin", func(t *testing.T) {
		var targetRequests atomic.Int32
		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/target" {
				targetRequests.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("ReadAll redirect body: %v", err)
					return
				}
				if string(body) != "signed plaintext" {
					t.Errorf("redirect body = %q", body)
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
			http.Redirect(w, r, server.URL+"/target", http.StatusTemporaryRedirect)
		}))
		defer server.Close()

		client := newNexusHTTPClient(server.Client(), nexusDataTimeout)
		request, err := http.NewRequest(http.MethodPost, server.URL+"/source", bytes.NewBufferString("signed plaintext"))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("same-origin redirect: %v", err)
		}
		_ = response.Body.Close()
		if targetRequests.Load() != 1 {
			t.Fatalf("target requests = %d, want 1", targetRequests.Load())
		}
	})

	t.Run("same HTTP origin for insecure dev endpoint", func(t *testing.T) {
		var targetRequests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/target" {
				targetRequests.Add(1)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			http.Redirect(w, r, "/target", http.StatusFound)
		}))
		defer server.Close()

		response, err := newNexusHTTPClient(nil, nexusDataTimeout).Get(server.URL + "/source")
		if err != nil {
			t.Fatalf("same-origin insecure redirect: %v", err)
		}
		_ = response.Body.Close()
		if targetRequests.Load() != 1 {
			t.Fatalf("target requests = %d, want 1", targetRequests.Load())
		}
	})

	t.Run("cross HTTPS origin", func(t *testing.T) {
		var targetRequests atomic.Int32
		target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			targetRequests.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer target.Close()
		source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusFound)
		}))
		defer source.Close()

		base := source.Client()
		transport := base.Transport.(*http.Transport).Clone()
		transport.TLSClientConfig.RootCAs.AddCert(target.Certificate())
		base.Transport = transport
		_, err := newNexusHTTPClient(base, nexusDataTimeout).Get(source.URL)
		if !errors.Is(err, errNexusRedirect) {
			t.Fatalf("cross-origin redirect error = %v, want %v", err, errNexusRedirect)
		}
		if targetRequests.Load() != 0 {
			t.Fatalf("cross-origin target requests = %d, want 0", targetRequests.Load())
		}
	})

	t.Run("HTTPS downgrade does not replay body", func(t *testing.T) {
		var targetRequests atomic.Int32
		var targetBody atomic.Value
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			targetRequests.Add(1)
			body, _ := io.ReadAll(r.Body)
			targetBody.Store(string(body))
			w.WriteHeader(http.StatusNoContent)
		}))
		defer target.Close()
		source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
		}))
		defer source.Close()

		request, err := http.NewRequest(http.MethodPost, source.URL, bytes.NewBufferString("signed plaintext"))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		_, err = newNexusHTTPClient(source.Client(), nexusDataTimeout).Do(request)
		if !errors.Is(err, errNexusRedirect) {
			t.Fatalf("downgrade redirect error = %v, want %v", err, errNexusRedirect)
		}
		if targetRequests.Load() != 0 {
			t.Fatalf("downgrade target requests = %d body=%v, want no replay", targetRequests.Load(), targetBody.Load())
		}
	})
}

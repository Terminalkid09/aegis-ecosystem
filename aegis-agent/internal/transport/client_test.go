package transport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoJSONSendsAgentIdentity(t *testing.T) {
	var gotAuth, gotAgent, gotCert string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAgent = r.Header.Get("X-Agent-Id")
		gotCert = r.Header.Get("X-Client-Cert-Hash")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client := New(server.Client())
	client.SetCredentials("secret", "agent-1", "cert-fingerprint")
	client.MaxAttempts = 1
	var out map[string]string
	if err := client.DoJSON(context.Background(), http.MethodPost, server.URL, map[string]string{"a": "b"}, &out); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer secret" || gotAgent != "agent-1" || gotCert != "cert-fingerprint" {
		t.Fatalf("header = %q/%q/%q", gotAuth, gotAgent, gotCert)
	}
	if out["status"] != "ok" {
		t.Fatalf("risposta = %+v", out)
	}
}

func TestDoJSONRetriesServerErrors(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			http.Error(w, "temporary", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client := New(server.Client())
	client.MaxAttempts = 2
	client.RetryBaseDelay = time.Millisecond
	if err := client.PostJSON(context.Background(), server.URL, map[string]string{"a": "b"}, nil); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("tentativi = %d", attempts.Load())
	}
}

func TestDoJSONDoesNotRetryUnauthorized(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	client := New(server.Client())
	client.MaxAttempts = 3
	client.RetryBaseDelay = time.Millisecond
	err := client.PostJSON(context.Background(), server.URL, map[string]string{"a": "b"}, nil)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("errore = %v", err)
	}
	if attempts.Load() != 1 {
		t.Fatalf("tentativi = %d", attempts.Load())
	}
}

func TestCommandsAddsDeviceAndLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("device_id") != "agent-1" || r.URL.Query().Get("n") != "50" {
			t.Fatalf("query = %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`[{"command":"GET_TELEMETRY"}]`))
	}))
	defer server.Close()

	client := New(server.Client())
	client.MaxAttempts = 1
	commands, err := client.Commands(context.Background(), server.URL+"/commands", "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 || commands[0].Command != "GET_TELEMETRY" {
		t.Fatalf("comandi = %+v", commands)
	}
}

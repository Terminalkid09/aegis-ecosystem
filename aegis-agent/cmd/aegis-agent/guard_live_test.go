package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type guardLiveCounters struct {
	csr         atomic.Int32
	reports     atomic.Int32
	heartbeats  atomic.Int32
	metrics     atomic.Int32
	commands    atomic.Int32
	acks        atomic.Int32
	certHeaders atomic.Int32
}

func TestLiveGuardAgainstFakeBrain(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("live telemetry collector is supported on linux and windows only")
	}
	caKey, caCert, _ := testCA(t)
	counters := &guardLiveCounters{}
	var commandOnce sync.Once

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/enroll/csr", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			CSRPEM string `json:"csr_pem"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		block, _ := pem.Decode([]byte(request.CSRPEM))
		if block == nil {
			http.Error(w, "bad csr", http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != "guard-live" {
			t.Errorf("CSR Guard non valida: %v", err)
			http.Error(w, "bad csr", http.StatusBadRequest)
			return
		}
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(201),
			Subject:      pkix.Name{CommonName: csr.Subject.CommonName},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}, caCert, csr.PublicKey, caKey)
		if err != nil {
			http.Error(w, "sign", http.StatusInternalServerError)
			return
		}
		counters.csr.Add(1)
		writeJSON(w, map[string]any{
			"certificate_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		})
	})
	mux.HandleFunc("/api/v1/telemetry/report/batch", func(w http.ResponseWriter, r *http.Request) {
		assertGuardAuth(t, r, counters)
		var payloads []map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payloads); err != nil {
			t.Errorf("batch body: %v", err)
			http.Error(w, "bad batch", http.StatusBadRequest)
			return
		}
		for _, payload := range payloads {
			if payload["agent_id"] != "guard-live" {
				t.Errorf("agent_id batch = %#v", payload["agent_id"])
			}
			if payload["event_type"] == "AGENT_HEARTBEAT" {
				counters.heartbeats.Add(1)
			} else if payload["event_type"] == "METRICS_REPORT" {
				counters.metrics.Add(1)
			}
			counters.reports.Add(1)
		}
		writeJSON(w, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/api/v1/telemetry/report", func(w http.ResponseWriter, r *http.Request) {
		assertGuardAuth(t, r, counters)
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("report body: %v", err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if payload["agent_id"] != "guard-live" {
			t.Errorf("agent_id report = %#v", payload["agent_id"])
		}
		if payload["capabilities"] == nil {
			t.Errorf("capabilities assenti: %#v", payload)
		}
		switch payload["event_type"] {
		case "AGENT_HEARTBEAT":
			counters.heartbeats.Add(1)
		case "METRICS_REPORT":
			counters.metrics.Add(1)
		case "PROCESS_CREATED", "FILE_MODIFIED", "YARA_MATCH":
			// Sensor events share the report endpoint; the live contract test
			// asserts they are accepted without pretending they are heartbeats.
		default:
			t.Errorf("event_type inatteso: %#v", payload["event_type"])
		}
		counters.reports.Add(1)
		writeJSON(w, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/api/v1/telemetry/commands/batch", func(w http.ResponseWriter, r *http.Request) {
		assertGuardAuth(t, r, counters)
		counters.commands.Add(1)
		commands := []map[string]any{}
		commandOnce.Do(func() {
			commands = append(commands, map[string]any{"command": "GET_TELEMETRY"})
		})
		writeJSON(w, commands)
	})
	mux.HandleFunc("/api/v1/telemetry/commands", func(w http.ResponseWriter, r *http.Request) {
		assertGuardAuth(t, r, counters)
		writeJSON(w, []map[string]any{})
	})
	mux.HandleFunc("/api/v1/telemetry/commands/ack", func(w http.ResponseWriter, r *http.Request) {
		assertGuardAuth(t, r, counters)
		var ack map[string]any
		if err := json.NewDecoder(r.Body).Decode(&ack); err != nil {
			t.Errorf("ack body: %v", err)
		}
		if ack["command"] != "GET_TELEMETRY" || ack["status"] != "ok" {
			t.Errorf("ack = %#v", ack)
		}
		counters.acks.Add(1)
		writeJSON(w, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("endpoint Guard inatteso: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	home := t.TempDir()
	secretPath := filepath.Join(home, "secret.json")
	secret := map[string]string{
		"agent_id":     "guard-live",
		"agent_secret": "guard-live-secret",
		"server_url":   server.URL + "/api/v1",
	}
	data, _ := json.Marshal(secret)
	if err := os.WriteFile(secretPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	binary := filepath.Join(t.TempDir(), "aegis-agent-guard-live")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = append(os.Environ(), "GOTOOLCHAIN=auto")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build binario Guard: %v\n%s", err, output)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "--profile", "endpoint", "--home", home)
	command.Env = append(os.Environ(),
		"AEGIS_AGENT_PROFILE=endpoint",
		"AEGIS_AGENT_HOME="+home,
		"AEGIS_SECRET_FILE="+secretPath,
		"AEGIS_IDENTITY_DIR="+home,
		"GOTOOLCHAIN=auto",
	)
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if counters.metrics.Load() >= 2 && counters.acks.Load() >= 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = command.Process.Kill()
	_ = command.Wait()

	if counters.csr.Load() != 1 {
		t.Fatalf("CSR Guard = %d; stderr:\n%s", counters.csr.Load(), stderr.String())
	}
	if counters.heartbeats.Load() < 1 || counters.metrics.Load() < 2 {
		t.Fatalf("heartbeat/metrics = %d/%d; stderr:\n%s",
			counters.heartbeats.Load(), counters.metrics.Load(), stderr.String())
	}
	if counters.commands.Load() < 1 || counters.acks.Load() < 1 {
		t.Fatalf("commands/ack = %d/%d; stderr:\n%s",
			counters.commands.Load(), counters.acks.Load(), stderr.String())
	}
	if counters.certHeaders.Load() < 1 {
		t.Fatalf("X-Client-Cert-Hash mai inviato; stderr:\n%s", stderr.String())
	}
	for _, name := range []string{"secret.json", "device.crt", "device.key"} {
		if _, err := os.Stat(filepath.Join(home, name)); err != nil {
			t.Fatalf("%s assente: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(home, "config.json")); !os.IsNotExist(err) {
		t.Fatalf("il test deve partire senza config.json NodeTrace (err=%v)", err)
	}
	t.Logf("guard live: csr=%d heartbeats=%d metrics=%d reports=%d commands=%d acks=%d cert=%d",
		counters.csr.Load(), counters.heartbeats.Load(), counters.metrics.Load(),
		counters.reports.Load(), counters.commands.Load(), counters.acks.Load(),
		counters.certHeaders.Load())
}

func assertGuardAuth(t *testing.T, r *http.Request, counters *guardLiveCounters) {
	t.Helper()
	if r.Header.Get("Authorization") != "Bearer guard-live-secret" ||
		r.Header.Get("X-Agent-Id") != "guard-live" {
		t.Errorf("auth Guard = %q/%q",
			r.Header.Get("Authorization"), r.Header.Get("X-Agent-Id"))
	}
	if r.Header.Get("X-Client-Cert-Hash") != "" {
		counters.certHeaders.Add(1)
	}
}

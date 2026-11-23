package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
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

type liveCounters struct {
	register    atomic.Int32
	csr         atomic.Int32
	heartbeat   atomic.Int32
	update      atomic.Int32
	commands    atomic.Int32
	ack         atomic.Int32
	scanReport  atomic.Int32
	certHeaders atomic.Int32
}

func TestLiveSensorAgainstFakeBrain(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("live telemetry collector is supported on linux and windows only")
	}
	caKey, caCert, caPEM := testCA(t)
	counters := &liveCounters{}
	var commandOnce sync.Once

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/register", func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("register body: %v", err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if request["agent_type"] != "nodetrace" || request["enroll_key"] != "live-enroll" {
			t.Errorf("register payload = %#v", request)
		}
		counters.register.Add(1)
		writeJSON(w, map[string]any{"device_id": "device-live", "device_token": "live-token", "status": "registered"})
	})
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
		if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != "device-live" {
			t.Errorf("CSR non valida: %v", err)
			http.Error(w, "bad csr", http.StatusBadRequest)
			return
		}
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(100),
			Subject:      pkix.Name{CommonName: csr.Subject.CommonName},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}, caCert, csr.PublicKey, caKey)
		if err != nil {
			t.Errorf("firma CSR: %v", err)
			http.Error(w, "sign", http.StatusInternalServerError)
			return
		}
		counters.csr.Add(1)
		writeJSON(w, map[string]any{"certificate_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))})
	})
	mux.HandleFunc("/api/v1/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		assertAgentAuth(t, r, counters)
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("heartbeat body: %v", err)
		}
		if payload["device_id"] != "device-live" || payload["sensor"] == nil {
			t.Errorf("heartbeat payload = %#v", payload)
		}
		counters.heartbeat.Add(1)
		writeJSON(w, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/api/v1/update", func(w http.ResponseWriter, r *http.Request) {
		assertAgentAuth(t, r, counters)
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("telemetry body: %v", err)
		}
		if payload["device_id"] != "device-live" || payload["capabilities"] == nil {
			t.Errorf("telemetry payload = %#v", payload)
		}
		counters.update.Add(1)
		writeJSON(w, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/api/v1/commands/batch", func(w http.ResponseWriter, r *http.Request) {
		assertAgentAuth(t, r, counters)
		counters.commands.Add(1)
		commands := []map[string]any{}
		commandOnce.Do(func() {
			commands = append(commands,
				map[string]any{"command": "GET_TELEMETRY"},
				map[string]any{"command": "NETWORK_SCAN", "cidr": "127.0.0.1/32", "ports": []int{1}, "probe_timeout": 0.05},
			)
		})
		writeJSON(w, commands)
	})
	mux.HandleFunc("/api/v1/telemetry/commands/ack", func(w http.ResponseWriter, r *http.Request) {
		assertAgentAuth(t, r, counters)
		counters.ack.Add(1)
		writeJSON(w, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/api/v1/discovery/agent-scan-result", func(w http.ResponseWriter, r *http.Request) {
		assertAgentAuth(t, r, counters)
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("scan body: %v", err)
		}
		if payload["cidr"] != "127.0.0.1/32" || payload["scan_hosts"] == nil {
			t.Errorf("scan payload = %#v", payload)
		}
		counters.scanReport.Add(1)
		writeJSON(w, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("endpoint inatteso: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	home := t.TempDir()
	configPath := filepath.Join(home, "config.json")
	config := map[string]any{
		"device_name":        "live-host",
		"register_url":       server.URL + "/api/v1/register",
		"heartbeat_url":      server.URL + "/api/v1/heartbeat",
		"update_url":         server.URL + "/api/v1/update",
		"heartbeat_interval": 1,
		"telemetry_interval": 1,
		"retry_max_attempts": 1,
		"retry_base_delay":   1,
	}
	data, _ := json.Marshal(config)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	binary := filepath.Join(t.TempDir(), "aegis-agent-live")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = append(os.Environ(), "GOTOOLCHAIN=auto")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build binario: %v\n%s", err, output)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "--home", home, "--config", configPath)
	command.Env = append(os.Environ(),
		"AEGIS_ENROLL_KEY=live-enroll",
		"AEGIS_AGENT_HOME="+home,
		"NODETRACE_IDENTITY_DIR="+home,
		"GOTOOLCHAIN=auto",
	)
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		if counters.scanReport.Load() > 0 && counters.ack.Load() >= 2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = command.Process.Kill()
	_ = command.Wait()

	if counters.register.Load() != 1 {
		t.Fatalf("register = %d; stderr:\n%s", counters.register.Load(), stderr.String())
	}
	if counters.csr.Load() != 1 {
		t.Fatalf("CSR = %d; stderr:\n%s", counters.csr.Load(), stderr.String())
	}
	if counters.heartbeat.Load() < 1 || counters.update.Load() < 1 {
		t.Fatalf("heartbeat/update = %d/%d; stderr:\n%s", counters.heartbeat.Load(), counters.update.Load(), stderr.String())
	}
	if counters.commands.Load() < 1 || counters.ack.Load() < 2 || counters.scanReport.Load() < 1 {
		t.Fatalf("commands/ack/scan = %d/%d/%d; stderr:\n%s", counters.commands.Load(), counters.ack.Load(), counters.scanReport.Load(), stderr.String())
	}
	if counters.certHeaders.Load() < 1 {
		t.Fatalf("X-Client-Cert-Hash mai inviato; stderr:\n%s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(home, "token.json")); err != nil {
		t.Fatalf("token.json assente: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "device.crt")); err != nil {
		t.Fatalf("device.crt assente: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "device.key")); err != nil {
		t.Fatalf("device.key assente: %v", err)
	}
	if !strings.Contains(stderr.String(), "identità device rinnovata") {
		t.Logf("stderr live (atteso senza dettaglio CSR in alcuni build):\n%s", stderr.String())
	}
	t.Logf("live: register=%d csr=%d heartbeat=%d update=%d commands=%d ack=%d scan=%d cert=%d",
		counters.register.Load(), counters.csr.Load(), counters.heartbeat.Load(),
		counters.update.Load(), counters.commands.Load(), counters.ack.Load(),
		counters.scanReport.Load(), counters.certHeaders.Load())
	_ = caPEM
}

func assertAgentAuth(t *testing.T, r *http.Request, counters *liveCounters) {
	t.Helper()
	if r.Header.Get("Authorization") != "Bearer live-token" || r.Header.Get("X-Agent-Id") != "device-live" {
		t.Errorf("auth headers = %q/%q", r.Header.Get("Authorization"), r.Header.Get("X-Agent-Id"))
	}
	if r.Header.Get("X-Client-Cert-Hash") != "" {
		counters.certHeaders.Add(1)
	}
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func testCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Aegis Live Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func Example_liveSensor() {
	fmt.Println("run go test ./cmd/aegis-agent -run TestLiveSensorAgainstFakeBrain -v")
	// Output: run go test ./cmd/aegis-agent -run TestLiveSensorAgainstFakeBrain -v
}

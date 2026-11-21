package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/config"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/identity"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/telemetry"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/transport"
)

type fakeCollector struct {
	snapshot telemetry.Snapshot
}

func (f fakeCollector) Collect(ctx context.Context) (telemetry.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return telemetry.Snapshot{}, err
	}
	return f.snapshot, nil
}

func testConfig(serverURL string) config.Config {
	return config.Config{
		Profile:           config.ProfileSensor,
		Version:           "test",
		DeviceName:        "test-host",
		RegisterURL:       serverURL + "/api/v1/register",
		HeartbeatURL:      serverURL + "/api/v1/heartbeat",
		UpdateURL:         serverURL + "/api/v1/update",
		CommandsURL:       serverURL + "/api/v1/commands",
		AckURL:            serverURL + "/api/v1/telemetry/commands/ack",
		HeartbeatInterval: time.Hour,
		TelemetryInterval: time.Hour,
		RequestTimeout:    time.Second,
		RetryMaxAttempts:  1,
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func saveToken(t *testing.T, path string, token identity.Token) {
	t.Helper()
	if err := identity.NewStore(path).Save(token); err != nil {
		t.Fatal(err)
	}
}

func TestRunOnceSendsHeartbeatAndTelemetry(t *testing.T) {
	var heartbeats, telemetryPosts atomic.Int32
	var mu sync.Mutex
	deviceIDs := make([]string, 0, 2)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		heartbeats.Add(1)
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		deviceID, _ := payload["device_id"].(string)
		if deviceID == "" {
			t.Errorf("heartbeat senza device_id: %+v", payload)
			return
		}
		mu.Lock()
		deviceIDs = append(deviceIDs, deviceID)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/api/v1/update", func(w http.ResponseWriter, r *http.Request) {
		telemetryPosts.Add(1)
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if payload["cpu_usage"] != float64(12.5) {
			t.Errorf("cpu_usage = %v", payload["cpu_usage"])
		}
		deviceID, _ := payload["device_id"].(string)
		if deviceID == "" {
			t.Errorf("telemetria senza device_id: %+v", payload)
			return
		}
		mu.Lock()
		deviceIDs = append(deviceIDs, deviceID)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	cfg := testConfig(server.URL)
	tokenPath := filepath.Join(t.TempDir(), "token.json")
	saveToken(t, tokenPath, identity.Token{Token: "nt-token", DeviceID: "device-1", ServerURL: cfg.RegisterURL})
	store := identity.NewStore(tokenPath)
	client := transport.New(server.Client())
	a := New(cfg, store, client, fakeCollector{snapshot: telemetry.Snapshot{CPUUsage: 12.5}}, testLogger())

	if err := a.EnsureIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if heartbeats.Load() != 1 || telemetryPosts.Load() != 1 {
		t.Fatalf("heartbeat/telemetria = %d/%d", heartbeats.Load(), telemetryPosts.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	for _, id := range deviceIDs {
		if id != "device-1" {
			t.Fatalf("device_id = %q", id)
		}
	}
}

func TestPollCommandsAcksGetTelemetry(t *testing.T) {
	var telemetryPosts, acks atomic.Int32
	var ackStatus string

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/commands", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("device_id") != "device-1" {
			t.Errorf("device_id query = %q", r.URL.Query().Get("device_id"))
		}
		_, _ = w.Write([]byte(`[{"command":"GET_TELEMETRY"}]`))
	})
	mux.HandleFunc("/api/v1/update", func(w http.ResponseWriter, r *http.Request) {
		telemetryPosts.Add(1)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/api/v1/telemetry/commands/ack", func(w http.ResponseWriter, r *http.Request) {
		acks.Add(1)
		var payload transport.Ack
		_ = json.NewDecoder(r.Body).Decode(&payload)
		ackStatus = payload.Status
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	cfg := testConfig(server.URL)
	tokenPath := filepath.Join(t.TempDir(), "token.json")
	saveToken(t, tokenPath, identity.Token{Token: "nt-token", DeviceID: "device-1", ServerURL: cfg.RegisterURL})
	client := transport.New(server.Client())
	a := New(cfg, identity.NewStore(tokenPath), client, fakeCollector{}, testLogger())
	if err := a.EnsureIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.PollCommands(context.Background()); err != nil {
		t.Fatal(err)
	}
	if telemetryPosts.Load() != 1 || acks.Load() != 1 {
		t.Fatalf("telemetria/ack = %d/%d", telemetryPosts.Load(), acks.Load())
	}
	if ackStatus != "ok" {
		t.Fatalf("ack status = %q", ackStatus)
	}
}

func TestEnsureGuardIdentityEnrollsAndPersistsSecret(t *testing.T) {
	var enrollCalls atomic.Int32
	var received transport.EnrollGuardRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/enroll/csr" {
			http.Error(w, "CSR non prevista in questo test", http.StatusNotFound)
			return
		}
		if r.URL.Path != "/api/v1/enroll/enroll" {
			t.Errorf("path enrollment = %s", r.URL.Path)
			return
		}
		enrollCalls.Add(1)
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{"agent_id":"guard-1","agent_secret":"guard-secret"}`))
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.Profile = config.ProfileEndpoint
	cfg.GuardEnrollURL = server.URL + "/api/v1/enroll/enroll"
	cfg.GuardCommandsURL = server.URL + "/api/v1/telemetry/commands"
	cfg.ReportURL = server.URL + "/api/v1/telemetry/report"
	cfg.SecretFile = filepath.Join(t.TempDir(), "secret.json")
	cfg.IdentityDir = t.TempDir()
	cfg.EnrollKey = "guard-enroll-key"
	cfg.CSRURL = ""
	client := transport.New(server.Client())
	a := New(cfg, identity.NewStore(filepath.Join(cfg.IdentityDir, "token.json")), client, fakeCollector{}, testLogger())

	if err := a.EnsureIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if enrollCalls.Load() != 1 {
		t.Fatalf("enrollment chiamato %d volte", enrollCalls.Load())
	}
	if received.AgentType != "aegis-guard" || received.EnrollKey != "guard-enroll-key" {
		t.Fatalf("payload enrollment = %+v", received)
	}
	secret, err := identity.NewSecretStore(cfg.SecretFile).Load()
	if err != nil {
		t.Fatal(err)
	}
	if secret.AgentID != "guard-1" || secret.AgentSecret != "guard-secret" {
		t.Fatalf("secret = %+v", secret)
	}
	if client.AgentID != "guard-1" || client.Token != "guard-secret" {
		t.Fatalf("credenziali client = id=%q token=%q", client.AgentID, client.Token)
	}
	if cfg.AgentType() != "aegis-guard" {
		t.Fatalf("agent type = %q", cfg.AgentType())
	}
}

func TestGuardRunOnceReportsLegacyEvents(t *testing.T) {
	var mu sync.Mutex
	seen := make(map[string]map[string]any)
	record := func(payload map[string]any) {
		if payload["agent_id"] != "guard-1" {
			t.Errorf("agent_id report = %v", payload["agent_id"])
		}
		if _, hasDeviceID := payload["device_id"]; hasDeviceID {
			t.Errorf("report Guard con device_id: %+v", payload)
		}
		eventType, _ := payload["event_type"].(string)
		mu.Lock()
		seen[eventType] = payload
		mu.Unlock()
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/enroll/csr" {
			http.Error(w, "CSR non prevista in questo test", http.StatusNotFound)
			return
		}
		switch r.URL.Path {
		case "/api/v1/telemetry/report":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			record(payload)
		case "/api/v1/telemetry/report/batch":
			var payloads []map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payloads); err != nil {
				t.Fatal(err)
			}
			for _, payload := range payloads {
				record(payload)
			}
		default:
			t.Errorf("path report = %s", r.URL.Path)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.Profile = config.ProfileEndpoint
	cfg.GuardEnrollURL = server.URL + "/api/v1/enroll/enroll"
	cfg.GuardCommandsURL = server.URL + "/api/v1/telemetry/commands"
	cfg.ReportURL = server.URL + "/api/v1/telemetry/report"
	cfg.SecretFile = filepath.Join(t.TempDir(), "secret.json")
	cfg.IdentityDir = t.TempDir()
	cfg.CSRURL = ""
	if err := identity.NewSecretStore(cfg.SecretFile).Save(identity.Secret{
		AgentID: "guard-1", AgentSecret: "guard-secret", ServerURL: cfg.GuardEnrollURL,
	}); err != nil {
		t.Fatal(err)
	}
	client := transport.New(server.Client())
	a := New(cfg, identity.NewStore(filepath.Join(cfg.IdentityDir, "token.json")), client, fakeCollector{snapshot: telemetry.Snapshot{CPUUsage: 12.5}}, testLogger())
	if err := a.EnsureIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		_, hb := seen["AGENT_HEARTBEAT"]
		_, metrics := seen["METRICS_REPORT"]
		mu.Unlock()
		if hb && metrics {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, ok := seen["AGENT_HEARTBEAT"]; !ok {
		t.Fatalf("heartbeat Guard assente: %+v", seen)
	}
	metrics, ok := seen["METRICS_REPORT"]
	if !ok {
		t.Fatalf("metrics Guard assente: %+v", seen)
	}
	if metrics["cpu_usage"] != float64(12.5) {
		t.Fatalf("cpu_usage = %v", metrics["cpu_usage"])
	}
	capabilities, _ := metrics["capabilities"].(map[string]any)
	if capabilities["agent_type"] != "aegis-guard" {
		t.Fatalf("capabilities = %+v", capabilities)
	}
}

func TestUnifiedCapabilitiesMergeBothProfiles(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.Profile = config.ProfileUnified
	cfg.Mode = config.ModeFull
	a := New(cfg, identity.NewStore(filepath.Join(t.TempDir(), "token.json")),
		transport.New(nil), fakeCollector{}, testLogger())
	a.guardCaps = map[string]any{
		"agent_type": "unified", "fim": true, "response_actions": true,
	}
	a.sensorSummary = map[string]any{
		"mode": "auditd", "kernel_profile": "partial", "auditd": true, "ebpf": false,
	}
	caps := a.capabilities()
	if caps["agent_type"] != "unified" || caps["mode"] != "full" ||
		caps["telemetry"] != true || caps["network_scan"] != true ||
		caps["sensor_mode"] != "auditd" {
		t.Fatalf("capabilities unified = %+v", caps)
	}
	if caps["fim"] != true || caps["response_actions"] != true {
		t.Fatalf("capabilities endpoint perse: %+v", caps)
	}
}

func TestUnifiedSensorModeHidesEndpointCapabilities(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.Profile = config.ProfileUnified
	cfg.Mode = config.ModeSensor
	a := New(cfg, identity.NewStore(filepath.Join(t.TempDir(), "token.json")),
		transport.New(nil), fakeCollector{}, testLogger())
	a.sensorSummary = map[string]any{"mode": "auditd"}
	caps := a.capabilities()
	if caps["agent_type"] != "unified" || caps["mode"] != "sensor" ||
		caps["telemetry"] != true || caps["network_scan"] != true {
		t.Fatalf("capabilities sensor = %+v", caps)
	}
	for _, key := range []string{"fim", "response_actions", "process_monitor"} {
		if _, ok := caps[key]; ok {
			t.Fatalf("capability endpoint %q presente in modalità sensor: %+v", key, caps)
		}
	}
}

func TestUnifiedEndpointModeHidesSensorCapabilities(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.Profile = config.ProfileUnified
	cfg.Mode = config.ModeEndpoint
	a := New(cfg, identity.NewStore(filepath.Join(t.TempDir(), "token.json")),
		transport.New(nil), fakeCollector{}, testLogger())
	a.guardCaps = map[string]any{"agent_type": "unified", "fim": true}
	caps := a.capabilities()
	if caps["agent_type"] != "unified" || caps["mode"] != "endpoint" ||
		caps["telemetry"] != false || caps["network_scan"] != false ||
		caps["sensor_mode"] != "disabled" {
		t.Fatalf("capabilities endpoint = %+v", caps)
	}
}

func TestUnifiedEnrollmentUsesUnifiedAgentType(t *testing.T) {
	var received transport.EnrollGuardRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/enroll/csr" {
			http.Error(w, "CSR non prevista", http.StatusNotFound)
			return
		}
		if r.URL.Path != "/api/v1/enroll/enroll" {
			t.Errorf("path = %s", r.URL.Path)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&received)
		_, _ = w.Write([]byte(`{"agent_id":"unified-1","agent_secret":"unified-secret"}`))
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.Profile = config.ProfileUnified
	cfg.GuardEnrollURL = server.URL + "/api/v1/enroll/enroll"
	cfg.GuardCommandsURL = server.URL + "/api/v1/telemetry/commands"
	cfg.ReportURL = server.URL + "/api/v1/telemetry/report"
	cfg.SecretFile = filepath.Join(t.TempDir(), "secret.json")
	cfg.IdentityDir = t.TempDir()
	cfg.EnrollKey = "unified-enroll-key"
	cfg.CSRURL = ""
	a := New(cfg, identity.NewStore(filepath.Join(cfg.IdentityDir, "token.json")),
		transport.New(server.Client()), fakeCollector{}, testLogger())
	if err := a.EnsureIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if received.AgentType != "unified" || received.EnrollKey != "unified-enroll-key" {
		t.Fatalf("payload enrollment = %+v", received)
	}
	if cfg.AgentType() != "unified" {
		t.Fatalf("agent type = %q", cfg.AgentType())
	}
}

func TestEnsureIdentityEnrollsWhenTokenMissing(t *testing.T) {
	var received transport.RegisterRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/register" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{"device_id":"device-new","device_token":"nt-new","status":"registered"}`))
	}))
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.EnrollKey = "enroll-key"
	tokenPath := filepath.Join(t.TempDir(), "token.json")
	client := transport.New(server.Client())
	a := New(cfg, identity.NewStore(tokenPath), client, fakeCollector{}, testLogger())

	if err := a.EnsureIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if received.AgentType != "nodetrace" || received.EnrollKey != "enroll-key" {
		t.Fatalf("register payload = %+v", received)
	}
	token, err := identity.NewStore(tokenPath).Load()
	if err != nil {
		t.Fatal(err)
	}
	if token.DeviceID != "device-new" || token.Token != "nt-new" {
		t.Fatalf("token salvato = %+v", token)
	}
}

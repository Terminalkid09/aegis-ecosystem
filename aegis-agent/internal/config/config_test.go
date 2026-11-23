package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func clearAgentEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"AEGIS_AGENT_HOME", "AEGIS_AGENT_PROFILE", "AEGIS_AGENT_MODE", "AEGIS_AGENT_VERSION",
		"AEGIS_CA_BUNDLE", "AEGIS_ENROLL_KEY", "AEGIS_ENROLL_TOKEN_FILE",
		"AEGIS_SECRET_FILE", "AEGIS_BRAIN_URL", "AEGIS_GATEWAY_URL", "AEGIS_IDENTITY_DIR",
		"NODETRACE_CONFIG", "NODETRACE_IDENTITY_DIR", "NODETRACE_TOKEN_FILE",
		"NODETRACE_DEVICE_NAME", "NODETRACE_SERVER_URL", "NODETRACE_REGISTER_URL",
		"NODETRACE_UPDATE_URL", "NODETRACE_HEARTBEAT_URL", "NODETRACE_VERSION",
		"NODETRACE_EBPF", "NODETRACE_AUDITD",
	} {
		t.Setenv(key, "")
	}
}

func TestLoadLegacyConfigAndDeriveURLs(t *testing.T) {
	clearAgentEnv(t)
	home := t.TempDir()
	configPath := filepath.Join(home, "config.json")
	data := `{
	  "device_name": "legacy-node",
	  "register_url": "https://aegis.local/api/v1/register",
	  "update_url": "https://aegis.local/api/v1/update",
	  "heartbeat_url": "https://aegis.local/api/v1/heartbeat",
	  "heartbeat_interval": 10,
	  "telemetry_interval": 15,
	  "retry_max_attempts": 3,
	  "retry_base_delay": 2
	}`
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(Options{AgentHome: home, ConfigFile: configPath})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profile != ProfileSensor {
		t.Fatalf("profilo = %q", cfg.Profile)
	}
	if cfg.DeviceName != "legacy-node" {
		t.Fatalf("device_name = %q", cfg.DeviceName)
	}
	if cfg.HeartbeatInterval != 10*time.Second || cfg.TelemetryInterval != 15*time.Second {
		t.Fatalf("intervalli = %s/%s", cfg.HeartbeatInterval, cfg.TelemetryInterval)
	}
	if cfg.RetryMaxAttempts != 3 || cfg.RetryBaseDelay != 2*time.Second {
		t.Fatalf("retry = %d/%s", cfg.RetryMaxAttempts, cfg.RetryBaseDelay)
	}
	if cfg.ServerURL != "https://aegis.local" {
		t.Fatalf("server_url = %q", cfg.ServerURL)
	}
	if cfg.CommandsURL != "https://aegis.local/api/v1/commands" {
		t.Fatalf("commands = %q", cfg.CommandsURL)
	}
	if cfg.AckURL != "https://aegis.local/api/v1/telemetry/commands/ack" {
		t.Fatalf("ack = %q", cfg.AckURL)
	}
	if cfg.ReportURL != "https://aegis.local/api/v1/telemetry/report" {
		t.Fatalf("report = %q", cfg.ReportURL)
	}
	if cfg.RegisterURL != "https://aegis.local/api/v1/register" {
		t.Fatalf("register = %q", cfg.RegisterURL)
	}
	if cfg.TokenFile != filepath.Join(home, "token.json") {
		t.Fatalf("token file = %q", cfg.TokenFile)
	}
	if err := cfg.ValidateNetwork(); err != nil {
		t.Fatal(err)
	}
}

func TestEnvironmentOverridesHeartbeatAndDerivesOrigin(t *testing.T) {
	clearAgentEnv(t)
	home := t.TempDir()
	t.Setenv("NODETRACE_HEARTBEAT_URL", "https://other.example/api/v1/heartbeat")
	t.Setenv("NODETRACE_DEVICE_NAME", "env-node")

	cfg, err := Load(Options{AgentHome: home})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DeviceName != "env-node" {
		t.Fatalf("device_name = %q", cfg.DeviceName)
	}
	if cfg.ServerURL != "https://other.example" {
		t.Fatalf("server_url = %q", cfg.ServerURL)
	}
	if cfg.RegisterURL != "https://other.example/api/v1/register" {
		t.Fatalf("register = %q", cfg.RegisterURL)
	}
	if cfg.CommandsURL != "https://other.example/api/v1/commands" {
		t.Fatalf("commands = %q", cfg.CommandsURL)
	}
}

func TestLoadGuardSecretResolvesEndpointWithoutNodeTraceConfig(t *testing.T) {
	clearAgentEnv(t)
	home := t.TempDir()
	secret := `{"agent_id":"guard-1","agent_secret":"secret","server_url":"https://aegis.local/api/v1"}`
	if err := os.WriteFile(filepath.Join(home, "secret.json"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(Options{AgentHome: home, Profile: "endpoint"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentType() != "aegis-guard" {
		t.Fatalf("agent type = %q", cfg.AgentType())
	}
	if cfg.GuardEnrollURL != "https://aegis.local/api/v1/enroll/enroll" {
		t.Fatalf("guard enroll = %q", cfg.GuardEnrollURL)
	}
	if cfg.ReportURL != "https://aegis.local/api/v1/telemetry/report" {
		t.Fatalf("guard report = %q", cfg.ReportURL)
	}
	if cfg.GuardCommandsURL != "https://aegis.local/api/v1/telemetry/commands" {
		t.Fatalf("guard commands = %q", cfg.GuardCommandsURL)
	}
	if cfg.AckURL != "https://aegis.local/api/v1/telemetry/commands/ack" {
		t.Fatalf("guard ack = %q", cfg.AckURL)
	}
	if err := cfg.ValidateNetwork(); err != nil {
		t.Fatalf("validazione Guard: %v", err)
	}
}

func TestLoadGuardBrainEnv(t *testing.T) {
	clearAgentEnv(t)
	t.Setenv("AEGIS_BRAIN_URL", "https://brain.example/api/v1")
	cfg, err := Load(Options{AgentHome: t.TempDir(), Profile: "endpoint"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ReportURL != "https://brain.example/api/v1/telemetry/report" {
		t.Fatalf("report = %q", cfg.ReportURL)
	}
	if cfg.GuardCommandsURL != "https://brain.example/api/v1/telemetry/commands" {
		t.Fatalf("commands = %q", cfg.GuardCommandsURL)
	}
	if err := cfg.ValidateNetwork(); err != nil {
		t.Fatalf("validazione Guard: %v", err)
	}
}

func TestUnifiedProfileUsesOneIdentityAndGuardEndpoints(t *testing.T) {
	clearAgentEnv(t)
	t.Setenv("AEGIS_BRAIN_URL", "https://brain.example/api/v1")
	cfg, err := Load(Options{AgentHome: t.TempDir(), Profile: "unified"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentType() != "unified" {
		t.Fatalf("agent type = %q", cfg.AgentType())
	}
	if cfg.Mode != ModeFull || !cfg.SensorEnabled() || !cfg.EndpointEnabled() {
		t.Fatalf("modalità full = %q sensor=%t endpoint=%t", cfg.Mode, cfg.SensorEnabled(), cfg.EndpointEnabled())
	}
	if cfg.GuardEnrollURL != "https://brain.example/api/v1/enroll/enroll" {
		t.Fatalf("guard enroll = %q", cfg.GuardEnrollURL)
	}
	if cfg.ScanResultURL != "https://brain.example/api/v1/discovery/agent-scan-result" {
		t.Fatalf("scan result = %q", cfg.ScanResultURL)
	}
	if err := cfg.ValidateNetwork(); err != nil {
		t.Fatalf("validazione unified: %v", err)
	}
}

func TestUnifiedModesKeepOneAgentType(t *testing.T) {
	clearAgentEnv(t)
	t.Setenv("AEGIS_BRAIN_URL", "https://brain.example/api/v1")
	for _, tc := range []struct {
		mode     string
		sensor   bool
		endpoint bool
	}{
		{"full", true, true},
		{"sensor", true, false},
		{"endpoint", false, true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			cfg, err := Load(Options{AgentHome: t.TempDir(), Profile: "unified", Mode: tc.mode})
			if err != nil {
				t.Fatal(err)
			}
			if cfg.AgentType() != "unified" {
				t.Fatalf("agent type = %q", cfg.AgentType())
			}
			if cfg.SensorEnabled() != tc.sensor || cfg.EndpointEnabled() != tc.endpoint {
				t.Fatalf("mode %s: sensor=%t endpoint=%t", tc.mode, cfg.SensorEnabled(), cfg.EndpointEnabled())
			}
		})
	}
}

func TestUnifiedModePrecedence(t *testing.T) {
	clearAgentEnv(t)
	home := t.TempDir()
	path := filepath.Join(home, "config.json")
	if err := os.WriteFile(path, []byte(`{"mode":"endpoint"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(Options{AgentHome: home, Profile: "unified", Mode: "full"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeFull {
		t.Fatalf("CLI mode = %q, want full", cfg.Mode)
	}

	t.Setenv("AEGIS_AGENT_MODE", "sensor")
	cfg, err = Load(Options{AgentHome: home, Profile: "unified"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeSensor {
		t.Fatalf("env mode = %q, want sensor", cfg.Mode)
	}

	cfg, err = Load(Options{AgentHome: t.TempDir(), Profile: "unified"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeSensor {
		t.Fatalf("env without file = %q, want sensor", cfg.Mode)
	}

	t.Setenv("AEGIS_AGENT_MODE", "invalid")
	if _, err := Load(Options{AgentHome: t.TempDir(), Profile: "unified"}); err == nil {
		t.Fatal("invalid env mode accepted")
	}
}

func TestNonUnifiedProfileRejectsExplicitMode(t *testing.T) {
	clearAgentEnv(t)
	if _, err := Load(Options{AgentHome: t.TempDir(), Profile: "sensor", Mode: "endpoint"}); err == nil {
		t.Fatal("sensor profile accepted endpoint mode")
	}
}

func TestInvalidUnifiedMode(t *testing.T) {
	clearAgentEnv(t)
	_, err := Load(Options{AgentHome: t.TempDir(), Profile: "unified", Mode: "everything"})
	if err == nil {
		t.Fatal("modalità unified invalida accettata")
	}
}

func TestInvalidProfile(t *testing.T) {
	clearAgentEnv(t)
	_, err := Load(Options{AgentHome: t.TempDir(), Profile: "invalid"})
	if err == nil {
		t.Fatal("profilo invalido accettato")
	}
}

func TestReadEnrollTokenPrefersFile(t *testing.T) {
	clearAgentEnv(t)
	home := t.TempDir()
	path := filepath.Join(home, "enroll.token")
	if err := os.WriteFile(path, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{EnrollTokenFile: path, EnrollKey: "env-token"}
	token, err := cfg.ReadEnrollToken()
	if err != nil {
		t.Fatal(err)
	}
	if token != "file-token" {
		t.Fatalf("token = %q", token)
	}
}

func TestGuardURLsAcceptOriginAndAPIBase(t *testing.T) {
	cases := []struct {
		name   string
		server string
		want   string
	}{
		{"origin", "https://aegis.local", "https://aegis.local/api/v1/enroll/enroll"},
		{"origin with trailing slash", "https://aegis.local/", "https://aegis.local/api/v1/enroll/enroll"},
		{"deployment manager API base", "https://soc.example.com/api/v1", "https://soc.example.com/api/v1/enroll/enroll"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{ServerURL: tc.server}
			cfg.deriveGuardURLs()
			if cfg.GuardEnrollURL != tc.want {
				t.Fatalf("GuardEnrollURL = %q, want %q", cfg.GuardEnrollURL, tc.want)
			}
			wantCommands := strings.TrimSuffix(tc.want, "/enroll/enroll") + "/telemetry/commands"
			if cfg.GuardCommandsURL != wantCommands {
				t.Fatalf("GuardCommandsURL = %q, want %q", cfg.GuardCommandsURL, wantCommands)
			}
		})
	}
}

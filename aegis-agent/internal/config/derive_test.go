package config

import "testing"

// The MSI, the deb and Deployment Manager only provide AEGIS_BRAIN_URL. Before
// the fallback existed, deriveURLs() read nothing but HeartbeatURL, so those
// endpoints reached ValidateNetwork() with every URL empty and refused to start
// with "endpoint heartbeat non configurato".
func TestDeriveURLsFromServerURLOnly(t *testing.T) {
	cases := []struct {
		name    string
		server  string
		wantAPI string
	}{
		{"origin", "https://brain.example", "https://brain.example/api/v1"},
		{"api base", "https://brain.example/api/v1", "https://brain.example/api/v1"},
		{"api base trailing slash", "https://brain.example/api/v1/", "https://brain.example/api/v1"},
		{"custom prefix", "https://brain.example/edge/api/v1", "https://brain.example/edge/api/v1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{ServerURL: tc.server}
			cfg.deriveURLs()

			want := map[string]string{
				"HeartbeatURL": tc.wantAPI + "/heartbeat",
				"UpdateURL":    tc.wantAPI + "/update",
				"CommandsURL":  tc.wantAPI + "/commands",
				"AckURL":       tc.wantAPI + "/telemetry/commands/ack",
				"ReportURL":    tc.wantAPI + "/telemetry/report",
				"RegisterURL":  tc.wantAPI + "/register",
			}
			got := map[string]string{
				"HeartbeatURL": cfg.HeartbeatURL,
				"UpdateURL":    cfg.UpdateURL,
				"CommandsURL":  cfg.CommandsURL,
				"AckURL":       cfg.AckURL,
				"ReportURL":    cfg.ReportURL,
				"RegisterURL":  cfg.RegisterURL,
			}
			for key, wantValue := range want {
				if got[key] != wantValue {
					t.Errorf("%s = %q, want %q", key, got[key], wantValue)
				}
			}
			if err := cfg.ValidateNetwork(); err != nil {
				t.Fatalf("ValidateNetwork() = %v, want nil", err)
			}
		})
	}
}

// An explicit heartbeat URL keeps winning, so existing deployments and the
// legacy NodeTrace contract are unchanged.
func TestDeriveURLsPrefersHeartbeatURL(t *testing.T) {
	cfg := Config{HeartbeatURL: "https://legacy.example/api/v1/heartbeat"}
	cfg.deriveURLs()

	if cfg.HeartbeatURL != "https://legacy.example/api/v1/heartbeat" {
		t.Errorf("HeartbeatURL = %q, want it preserved", cfg.HeartbeatURL)
	}
	if cfg.UpdateURL != "https://legacy.example/api/v1/update" {
		t.Errorf("UpdateURL = %q", cfg.UpdateURL)
	}
	if cfg.ReportURL != "https://legacy.example/api/v1/telemetry/report" {
		t.Errorf("ReportURL = %q", cfg.ReportURL)
	}
}

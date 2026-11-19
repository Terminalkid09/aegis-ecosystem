//go:build linux || windows

package telemetry

import (
	"testing"
)

func TestDetectAnomaliesMinerAndLOLBin(t *testing.T) {
	processes := []Process{
		{Name: "certutil.exe", PID: 10, MemoryPercent: 9.5},
		{Name: "xmrig", PID: 20, CPUPercent: 92.0},
		{Name: "idle", PID: 30, CPUPercent: 1.0},
	}
	flows := []Flow{
		{RemoteAddr: "203.0.113.9:3333", PID: 20},
		{RemoteAddr: "203.0.113.9:443", PID: 30},
	}
	anomalies := detectAnomalies(processes, flows)
	if len(anomalies) != 2 {
		t.Fatalf("anomalie = %#v", anomalies)
	}
	first, _ := anomalies[0].(map[string]any)
	second, _ := anomalies[1].(map[string]any)
	types := []string{first["type"].(string), second["type"].(string)}
	if types[0] != "SUSPICIOUS_LOLBIN_MEMORY" && types[1] != "SUSPICIOUS_LOLBIN_MEMORY" {
		t.Fatalf("LOLBin mancante: %v", types)
	}
	if types[0] != "POSSIBLE_CRYPTOMINER" && types[1] != "POSSIBLE_CRYPTOMINER" {
		t.Fatalf("miner mancante: %v", types)
	}
}

func TestDetectAnomaliesBeaconingIgnoresLocal(t *testing.T) {
	processes := []Process{{Name: "curl", PID: 7}}
	flows := make([]Flow, 0, 12)
	for i := 0; i < 10; i++ {
		flows = append(flows, Flow{RemoteAddr: "198.51.100.7:443", PID: 7})
	}
	for i := 0; i < 12; i++ {
		flows = append(flows, Flow{RemoteAddr: "192.168.1.10:443", PID: 7})
	}
	anomalies := detectAnomalies(processes, flows)
	if len(anomalies) != 1 {
		t.Fatalf("anomalie = %#v", anomalies)
	}
	item := anomalies[0].(map[string]any)
	if item["type"] != "HIGH_CONNECTION_COUNT_TO_IP" || item["ip"] != "198.51.100.7" {
		t.Fatalf("beaconing = %#v", item)
	}
}

func TestRound1(t *testing.T) {
	if round1(12.345) != 12.3 || round1(12.36) != 12.4 {
		t.Fatal("arrotondamento telemetria errato")
	}
}

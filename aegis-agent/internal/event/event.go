package event

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const SchemaVersion = 2

const EventTypeMetricsReport = "METRICS_REPORT"

// Event is the canonical schema-v2 envelope. JSON names intentionally match
// the Brain's existing snake_case fields; the Brain also accepts camelCase
// aliases for legacy agents.
type Event struct {
	AgentID      string    `json:"agent_id"`
	Timestamp    time.Time `json:"timestamp"`
	EventType    string    `json:"event_type"`
	Hostname     string    `json:"hostname,omitempty"`
	IPAddress    string    `json:"ip_address,omitempty"`
	OS           string    `json:"os,omitempty"`
	AgentVersion string    `json:"agent_version,omitempty"`

	PID               int    `json:"pid,omitempty"`
	ParentPID         int    `json:"parent_pid,omitempty"`
	ParentProcessName string `json:"parent_process_name,omitempty"`
	ProcessName       string `json:"process_name,omitempty"`
	ProcessPath       string `json:"process_path,omitempty"`
	User              string `json:"user,omitempty"`
	FileHash          string `json:"file_hash,omitempty"`
	ThreadCount       int    `json:"thread_count,omitempty"`

	CPUUsage        float64 `json:"cpu_usage,omitempty"`
	RAMUsage        float64 `json:"ram_usage,omitempty"`
	DiskFree        int64   `json:"disk_free,omitempty"`
	DiskTotal       int64   `json:"disk_total,omitempty"`
	NetworkSent     int64   `json:"network_sent,omitempty"`
	NetworkReceived int64   `json:"network_received,omitempty"`

	Processes    []map[string]any `json:"processes,omitempty"`
	Users        []map[string]any `json:"users,omitempty"`
	NetworkFlows []map[string]any `json:"network_flows,omitempty"`

	CommandLine    string   `json:"command_line,omitempty"`
	BehavioralTags []string `json:"behavioral_tags,omitempty"`
	Anomalies      []any    `json:"anomalies,omitempty"`
	Capabilities   any      `json:"capabilities,omitempty"`

	EventID        string `json:"event_id,omitempty"`
	SchemaVersion  int    `json:"schema_version,omitempty"`
	BootID         string `json:"boot_id,omitempty"`
	Seq            *int64 `json:"seq,omitempty"`
	TsMonotonicNS  *int64 `json:"ts_monotonic_ns,omitempty"`
	TsWallNS       *int64 `json:"ts_wall_ns,omitempty"`
	ProcStartNS    *int64 `json:"proc_start_ns,omitempty"`
	SessionID      string `json:"session_id,omitempty"`
	IntegrityLevel string `json:"integrity_level,omitempty"`
	Signature      string `json:"signature,omitempty"`
	Publisher      string `json:"publisher,omitempty"`
	Proto          string `json:"proto,omitempty"`
	Direction      string `json:"direction,omitempty"`
	ContainerID    string `json:"container_id,omitempty"`
	Cgroup         string `json:"cgroup,omitempty"`
	NetNamespace   string `json:"net_namespace,omitempty"`
	Provenance     string `json:"provenance,omitempty"`
	Quality        string `json:"quality,omitempty"`
	Sampling       string `json:"sampling,omitempty"`
	DropReason     string `json:"drop_reason,omitempty"`
}

func (e Event) Validate() error {
	if strings.TrimSpace(e.AgentID) == "" {
		return fmt.Errorf("agent_id mancante")
	}
	if strings.TrimSpace(e.EventType) == "" {
		return fmt.Errorf("event_type mancante")
	}
	if e.Timestamp.IsZero() {
		return fmt.Errorf("timestamp mancante")
	}
	if e.SchemaVersion != 0 && e.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version: %d", e.SchemaVersion)
	}
	if e.Seq != nil && *e.Seq < 0 {
		return fmt.Errorf("seq negativa")
	}
	return nil
}

// NewID returns a UUIDv4-shaped identifier without an external dependency.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generazione event_id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	), nil
}

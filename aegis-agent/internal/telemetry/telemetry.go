package telemetry

import (
	"context"
	"net"
)

type Process struct {
	Name          string  `json:"name"`
	PID           int     `json:"pid"`
	ParentPID     int     `json:"parent_pid,omitempty"`
	Path          string  `json:"path,omitempty"`
	User          string  `json:"user,omitempty"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
}

type User struct {
	Name     string `json:"name"`
	Terminal string `json:"terminal,omitempty"`
	Host     string `json:"host,omitempty"`
	Started  int64  `json:"started,omitempty"`
}

type Flow struct {
	LocalAddr  string `json:"laddr"`
	RemoteAddr string `json:"raddr"`
	PID        int    `json:"pid,omitempty"`
	Status     string `json:"status,omitempty"`
}

// Snapshot is the legacy NodeTrace /update payload plus the fields needed by
// the unified agent. It intentionally keeps snake_case JSON names.
type Snapshot struct {
	DeviceID          string         `json:"device_id"`
	CPUUsage          float64        `json:"cpu_usage"`
	RAMUsage          float64        `json:"ram_usage"`
	IPLocal           string         `json:"ip_local,omitempty"`
	IPPublic          string         `json:"ip_public,omitempty"`
	GeoCountry        string         `json:"geo_country,omitempty"`
	GeoCity           string         `json:"geo_city,omitempty"`
	Processes         []Process      `json:"processes"`
	DiskFree          int64          `json:"disk_free"`
	DiskTotal         int64          `json:"disk_total"`
	NetworkSent       int64          `json:"network_sent"`
	NetworkReceived   int64          `json:"network_received"`
	ActiveConnections int            `json:"active_connections"`
	Users             []User         `json:"users"`
	NetworkFlows      []Flow         `json:"network_flows"`
	Anomalies         []any          `json:"anomalies"`
	AgentVersion      string         `json:"agent_version,omitempty"`
	Capabilities      map[string]any `json:"capabilities,omitempty"`
}

type Collector interface {
	Collect(ctx context.Context) (Snapshot, error)
}

// LocalIPv4 returns the first non-loopback IPv4 address. It is shared by the
// platform collectors and is deliberately side-effect free.
func LocalIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		var ip net.IP
		switch value := addr.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		}
		if ip == nil || ip.IsLoopback() || ip.To4() == nil {
			continue
		}
		return ip.String()
	}
	return ""
}

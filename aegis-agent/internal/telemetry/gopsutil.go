//go:build linux || windows

package telemetry

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v4/host"
	gonet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

func enrichSnapshot(ctx context.Context, snap *Snapshot) {
	enrichProcesses(ctx, snap)
	enrichConnections(ctx, snap)
	enrichUsers(ctx, snap)
	snap.Anomalies = detectAnomalies(snap.Processes, snap.NetworkFlows)
}

func enrichProcesses(ctx context.Context, snap *Snapshot) {
	if err := ctx.Err(); err != nil {
		return
	}
	processes, err := process.Processes()
	if err != nil {
		return
	}
	out := make([]Process, 0, len(processes))
	for _, p := range processes {
		name, err := p.Name()
		if err != nil || name == "" {
			continue
		}
		ppid, _ := p.Ppid()
		exe, _ := p.Exe()
		username, _ := p.Username()
		cpuPercent, _ := p.CPUPercent()
		memoryPercent, _ := p.MemoryPercent()
		out = append(out, Process{
			Name:          name,
			PID:           int(p.Pid),
			ParentPID:     int(ppid),
			Path:          exe,
			User:          username,
			CPUPercent:    round1(cpuPercent),
			MemoryPercent: round1(float64(memoryPercent)),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].CPUPercent > out[j].CPUPercent
	})
	if len(out) > 25 {
		out = out[:25]
	}
	snap.Processes = out
}

func enrichConnections(ctx context.Context, snap *Snapshot) {
	connections, err := gonet.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return
	}
	snap.ActiveConnections = len(connections)
	flows := make([]Flow, 0, len(connections))
	for _, conn := range connections {
		if conn.Status != "ESTABLISHED" || conn.Raddr.IP == "" {
			continue
		}
		flow := Flow{
			LocalAddr:  net.JoinHostPort(conn.Laddr.IP, strconv.Itoa(int(conn.Laddr.Port))),
			RemoteAddr: net.JoinHostPort(conn.Raddr.IP, strconv.Itoa(int(conn.Raddr.Port))),
			PID:        int(conn.Pid),
			Status:     conn.Status,
		}
		flows = append(flows, flow)
		if len(flows) >= 50 {
			break
		}
	}
	snap.NetworkFlows = flows
}

func enrichUsers(ctx context.Context, snap *Snapshot) {
	users, err := host.UsersWithContext(ctx)
	if err != nil {
		return
	}
	out := make([]User, 0, len(users))
	for _, user := range users {
		terminal := user.Terminal
		if terminal == "" {
			terminal = "unknown"
		}
		hostName := user.Host
		if hostName == "" {
			hostName = "localhost"
		}
		out = append(out, User{
			Name:     user.User,
			Terminal: terminal,
			Host:     hostName,
			Started:  int64(user.Started),
		})
	}
	snap.Users = out
}

func detectAnomalies(processes []Process, flows []Flow) []any {
	anomalies := make([]any, 0)
	for _, p := range processes {
		name := strings.ToLower(p.Name)
		if (name == "certutil.exe" || name == "bitsadmin.exe" || name == "powershell.exe") && p.MemoryPercent > 5 {
			anomalies = append(anomalies, map[string]any{
				"type": "SUSPICIOUS_LOLBIN_MEMORY", "process": p.Name,
				"pid": p.PID, "memory_percent": p.MemoryPercent,
			})
		}
		if p.CPUPercent > 80 {
			for _, flow := range flows {
				if flow.PID != p.PID {
					continue
				}
				if hasMinerPort(flow.RemoteAddr) {
					anomalies = append(anomalies, map[string]any{
						"type": "POSSIBLE_CRYPTOMINER", "process": p.Name,
						"pid": p.PID, "endpoint": flow.RemoteAddr,
						"cpu_percent": p.CPUPercent,
					})
					break
				}
			}
		}
	}

	destinations := make(map[string]int)
	owners := make(map[string]map[string]int)
	for _, flow := range flows {
		ip := remoteIP(flow.RemoteAddr)
		if ip == "" {
			continue
		}
		destinations[ip]++
		if owners[ip] == nil {
			owners[ip] = make(map[string]int)
		}
		for _, p := range processes {
			if p.PID == flow.PID {
				owners[ip][p.Name]++
				break
			}
		}
	}
	for ip, count := range destinations {
		parsed := net.ParseIP(ip)
		if count < 10 || parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() {
			continue
		}
		processOwners := make([]map[string]any, 0, len(owners[ip]))
		for name, connections := range owners[ip] {
			processOwners = append(processOwners, map[string]any{"name": name, "connections": connections})
		}
		sort.SliceStable(processOwners, func(i, j int) bool {
			return processOwners[i]["connections"].(int) > processOwners[j]["connections"].(int)
		})
		if len(processOwners) > 5 {
			processOwners = processOwners[:5]
		}
		anomalies = append(anomalies, map[string]any{
			"type": "HIGH_CONNECTION_COUNT_TO_IP", "ip": ip,
			"connection_count": count, "processes": processOwners,
		})
	}
	return anomalies
}

func hasMinerPort(remote string) bool {
	for _, suffix := range []string{":3333", ":4444", ":14444", ":14433"} {
		if strings.HasSuffix(remote, suffix) {
			return true
		}
	}
	return false
}

func remoteIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return ""
	}
	return host
}

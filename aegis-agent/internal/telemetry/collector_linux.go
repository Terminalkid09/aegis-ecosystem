//go:build linux

package telemetry

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

type linuxCollector struct {
	mu      sync.Mutex
	prevCPU cpuSample
}

type cpuSample struct {
	total uint64
	idle  uint64
}

func NewCollector() Collector { return &linuxCollector{} }

func (c *linuxCollector) Collect(ctx context.Context) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	snap := Snapshot{
		Processes:    []Process{},
		Users:        []User{},
		NetworkFlows: []Flow{},
		Anomalies:    []any{},
		IPLocal:      LocalIPv4(),
	}

	if sample, err := readCPUSample(); err == nil {
		c.mu.Lock()
		if c.prevCPU.total != 0 && sample.total > c.prevCPU.total {
			totalDelta := sample.total - c.prevCPU.total
			idleDelta := sample.idle - c.prevCPU.idle
			if totalDelta > 0 {
				snap.CPUUsage = round1(float64(totalDelta-idleDelta) / float64(totalDelta) * 100)
			}
		}
		c.prevCPU = sample
		c.mu.Unlock()
	}

	totalKB, availableKB, err := readMeminfo()
	if err != nil {
		return Snapshot{}, err
	}
	if totalKB > 0 {
		snap.RAMUsage = round1(float64(totalKB-availableKB) / float64(totalKB) * 100)
	}

	snap.DiskFree, snap.DiskTotal = diskUsage("/")
	snap.NetworkSent, snap.NetworkReceived = networkBytes()
	snap.ActiveConnections = establishedConnections()
	snap.Processes = processList(totalKB)
	// enrichSnapshot fills CPU percentages from gopsutil on Linux too. The
	// /proc list remains the bounded fallback if gopsutil cannot read a process.
	enrichSnapshot(ctx, &snap)
	return snap, nil
}

func readCPUSample() (cpuSample, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSample{}, err
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return cpuSample{}, fmt.Errorf("/proc/stat vuoto")
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuSample{}, fmt.Errorf("/proc/stat: prima riga inattesa")
	}
	var total, idle uint64
	for i := 1; i < len(fields) && i <= 8; i++ {
		value, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return cpuSample{}, fmt.Errorf("/proc/stat: %w", err)
		}
		total += value
		if i == 4 || i == 5 { // idle + iowait
			idle += value
		}
	}
	return cpuSample{total: total, idle: idle}, nil
}

func readMeminfo() (totalKB, availableKB int64, err error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	var free, buffers, cached int64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, parseErr := strconv.ParseInt(fields[1], 10, 64)
		if parseErr != nil {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			totalKB = value
		case "MemAvailable":
			availableKB = value
		case "MemFree":
			free = value
		case "Buffers":
			buffers = value
		case "Cached":
			cached = value
		}
	}
	if availableKB == 0 {
		availableKB = free + buffers + cached
	}
	if totalKB == 0 {
		return 0, 0, fmt.Errorf("/proc/meminfo: MemTotal missing")
	}
	return totalKB, availableKB, nil
}

func diskUsage(path string) (freeMB, totalMB int64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0
	}
	blockSize := uint64(stat.Bsize)
	freeMB = int64(stat.Bavail * blockSize / (1024 * 1024))
	totalMB = int64(stat.Blocks * blockSize / (1024 * 1024))
	return freeMB, totalMB
}

func networkBytes() (sent, received int64) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		rx, errRX := strconv.ParseInt(fields[0], 10, 64)
		tx, errTX := strconv.ParseInt(fields[8], 10, 64)
		if errRX == nil {
			received += rx
		}
		if errTX == nil {
			sent += tx
		}
	}
	return sent, received
}

func establishedConnections() int {
	count := 0
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 3 && fields[3] == "01" {
				count++
			}
		}
	}
	return count
}

func processList(totalRAMKB int64) []Process {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return []Process{}
	}
	out := make([]Process, 0, 64)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		status, err := readProcStatus(filepath.Join("/proc", entry.Name(), "status"))
		if err != nil || status.name == "" {
			continue
		}
		path, _ := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		username := ""
		if status.uid != "" {
			if u, lookupErr := user.LookupId(status.uid); lookupErr == nil {
				username = u.Username
			}
		}
		memPercent := 0.0
		if totalRAMKB > 0 {
			memPercent = round1(float64(status.rssKB) / float64(totalRAMKB) * 100)
		}
		out = append(out, Process{
			Name:          status.name,
			PID:           pid,
			ParentPID:     status.ppid,
			Path:          path,
			User:          username,
			MemoryPercent: memPercent,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].MemoryPercent > out[j].MemoryPercent
	})
	if len(out) > 25 {
		out = out[:25]
	}
	return out
}

type procStatus struct {
	name  string
	ppid  int
	uid   string
	rssKB int64
}

func readProcStatus(path string) (procStatus, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return procStatus{}, err
	}
	var out procStatus
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "Name":
			out.name = value
		case "PPid":
			out.ppid, _ = strconv.Atoi(value)
		case "Uid":
			fields := strings.Fields(value)
			if len(fields) > 0 {
				out.uid = fields[0]
			}
		case "VmRSS":
			fields := strings.Fields(value)
			if len(fields) > 0 {
				out.rssKB, _ = strconv.ParseInt(fields[0], 10, 64)
			}
		}
	}
	return out, nil
}

func round1(value float64) float64 {
	return float64(int(value*10+0.5)) / 10
}

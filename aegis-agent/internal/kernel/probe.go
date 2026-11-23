package kernel

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

const (
	Full        = "full"
	Partial     = "partial"
	Absent      = "absent"
	Unavailable = "unavailable"

	CAPSysAdmin = 1 << 21
	CAPPerfMon  = 1 << 38
	CAPBPF      = 1 << 39
)

func SensorMode(system string, ebpfOn, auditdOn bool) string {
	if !strings.Contains(strings.ToLower(system), "linux") {
		return Unavailable
	}
	if ebpfOn {
		return Full
	}
	if auditdOn {
		return Partial
	}
	return "fallback"
}

func ParseKernelRelease(release string) []int {
	release = strings.TrimSpace(release)
	if release == "" {
		return nil
	}
	parts := strings.SplitN(release, "-", 2)[0]
	fields := strings.Split(parts, ".")
	out := make([]int, 0, 3)
	for _, field := range fields {
		if field == "" {
			break
		}
		value, err := strconv.Atoi(field)
		if err != nil {
			break
		}
		out = append(out, value)
	}
	return out
}

func KernelSupportsEBPF(release string) bool {
	version := ParseKernelRelease(release)
	return len(version) >= 2 && (version[0] > 5 || (version[0] == 5 && version[1] >= 8))
}

func ParseCapEff(status string) int64 {
	for _, line := range strings.Split(status, "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return -1
		}
		value, err := strconv.ParseInt(fields[1], 16, 64)
		if err != nil {
			return -1
		}
		return value
	}
	return -1
}

func HasEBPFCaps(mask int64) bool {
	if mask < 0 {
		return false
	}
	if mask&CAPSysAdmin != 0 {
		return true
	}
	return mask&CAPBPF != 0 && mask&CAPPerfMon != 0
}

// Probe returns a NodeTrace-shaped kernel profile and never panics.
func Probe() map[string]any {
	if runtime.GOOS != "linux" {
		return map[string]any{"profile": Absent, "reason": "not-linux", "kernel": runtime.GOOS}
	}
	releaseBytes, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	release := strings.TrimSpace(string(releaseBytes))
	if release == "" {
		release = "unknown"
	}
	kernelOK := KernelSupportsEBPF(release)
	_, btfErr := os.Stat("/sys/kernel/btf/vmlinux")
	btfOK := btfErr == nil
	status, _ := os.ReadFile("/proc/self/status")
	capEff := ParseCapEff(string(status))
	capsOK := HasEBPFCaps(capEff)
	if kernelOK && btfOK && capsOK {
		return map[string]any{"profile": Full, "reason": "", "kernel": release, "btf": true, "caps": true}
	}
	var reasons []string
	if !kernelOK {
		reasons = append(reasons, fmt.Sprintf("kernel-%s-too-old", release))
	}
	if !btfOK {
		reasons = append(reasons, "no-btf")
	}
	if !capsOK {
		reasons = append(reasons, "no-caps")
	}
	profile := Absent
	if kernelOK && (btfOK || capsOK) {
		profile = Partial
	}
	return map[string]any{"profile": profile, "reason": strings.Join(reasons, "+"), "kernel": release, "btf": btfOK, "caps": capsOK}
}

func AuditdAvailable() string {
	for _, path := range []string{"/var/log/audit/audit.log"} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func SystemdAvailable() bool {
	info, err := os.Stat("/run/systemd/system")
	return err == nil && info.IsDir()
}

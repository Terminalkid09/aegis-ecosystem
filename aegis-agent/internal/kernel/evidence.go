package kernel

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

var capNames = map[int]string{
	0: "CHOWN", 1: "DAC_OVERRIDE", 2: "DAC_READ_SEARCH", 3: "FOWNER",
	4: "FSETID", 5: "KILL", 6: "SETGID", 7: "SETUID", 8: "SETPCAP",
	9: "LINUX_IMMUTABLE", 10: "NET_BIND_SERVICE", 11: "NET_ADMIN",
	12: "NET_RAW", 13: "IPC_LOCK", 14: "IPC_OWNER", 15: "SYS_MODULE",
	16: "SYS_RAWIO", 17: "SYS_CHROOT", 18: "SYS_PTRACE", 19: "SYS_PACCT",
	20: "SYS_ADMIN", 21: "SYS_BOOT", 22: "SYS_NICE", 23: "SYS_RESOURCE",
	24: "SYS_TIME", 25: "SYS_TTY_CONFIG", 26: "MKNOD", 27: "LEASE",
	28: "AUDIT_WRITE", 29: "AUDIT_CONTROL", 30: "SETFCAP", 31: "MAC_OVERRIDE",
	32: "MAC_ADMIN", 33: "SYSLOG", 34: "WAKE_ALARM", 35: "BLOCK_SUSPEND",
	36: "AUDIT_READ", 37: "PERFMON", 38: "BPF", 39: "CHECKPOINT_RESTORE",
}

type FileMeta struct {
	Path          string `json:"path"`
	Size          int64  `json:"size"`
	Mode          string `json:"mode"`
	UID           int    `json:"uid"`
	WorldReadable bool   `json:"world_readable,omitempty"`
}

var systemdDirs = []string{
	"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system",
}

var cronPaths = []string{
	"/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
	"/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron", "/var/spool/cron/crontabs",
}

var profileFiles = []string{"/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc"}
var userProfileFiles = []string{".bashrc", ".bash_profile", ".profile", ".zshrc"}
var sshNames = []string{"authorized_keys", "authorized_keys2"}
var secretPaths = []string{
	"/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d",
	"/root/.ssh", "/etc/ssl/private", "/etc/kubernetes", "/etc/docker", "/var/lib/kubelet",
}

func DecodeCaps(mask int64) []string {
	if mask < 0 {
		return []string{}
	}
	out := make([]string, 0)
	for bit := 0; bit < 64; bit++ {
		if mask&(1<<bit) == 0 {
			continue
		}
		if name, ok := capNames[bit]; ok {
			out = append(out, name)
		}
	}
	return out
}

func FileMetaOf(path string) *FileMeta {
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	return &FileMeta{
		Path: path,
		Size: info.Size(),
		Mode: fmt.Sprintf("0o%o", uint32(info.Mode().Perm())),
		UID:  fileUID(info),
	}
}

func ListUnitFiles(dirs []string) []map[string]any {
	out := make([]map[string]any, 0)
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".service") && !strings.HasSuffix(name, ".timer") &&
				!strings.HasSuffix(name, ".socket") && !strings.HasSuffix(name, ".path") {
				continue
			}
			out = append(out, map[string]any{
				"name": name,
				"dir":  dir,
				"meta": FileMetaOf(filepath.Join(dir, name)),
			})
		}
	}
	return out
}

func ListCronEntries(paths []string) []map[string]any {
	out := make([]map[string]any, 0)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.IsDir() {
			entries, _ := os.ReadDir(path)
			out = append(out, map[string]any{"path": path, "type": "dir", "entries": len(entries), "meta": FileMetaOf(path)})
			continue
		}
		out = append(out, map[string]any{"path": path, "type": "file", "meta": FileMetaOf(path)})
	}
	return out
}

// ParseAuthorizedKeys returns only algorithm, SHA-256 of the key blob and
// comment. The key itself is never placed in the result.
func ParseAuthorizedKeys(content string) []map[string]string {
	out := make([]map[string]string, 0)
	valid := map[string]bool{
		"ssh-rsa": true, "ssh-ed25519": true, "ssh-dss": true,
		"ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true,
		"ecdsa-sha2-nistp521": true, "ssh-ed25519-cert-v01@openssh.com": true,
		"ssh-rsa-cert-v01@openssh.com": true,
	}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		algo := fields[0]
		if strings.HasPrefix(algo, "sk-") {
			algo = strings.TrimPrefix(algo, "sk-")
		}
		if !valid[algo] {
			continue
		}
		blob := fields[1]
		if padding := len(blob) % 4; padding != 0 {
			blob += strings.Repeat("=", 4-padding)
		}
		raw, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(raw)
		out = append(out, map[string]string{
			"algo":    algo,
			"sha256":  hex.EncodeToString(sum[:]),
			"comment": strings.Join(fields[2:], " "),
		})
	}
	return out
}

func ParseLsmod(content string) []string {
	out := make([]string, 0)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Module") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			out = append(out, fields[0])
		}
	}
	return out
}

func ContainerHint(cgroupContent, schedContent string) map[string]any {
	text := strings.ToLower(cgroupContent + "\n" + schedContent)
	for _, runtimeName := range []string{"kubepods", "docker", "podman", "lxc", "containerd", "crio"} {
		if strings.Contains(text, runtimeName) {
			return map[string]any{"container": true, "runtime": runtimeName}
		}
	}
	return map[string]any{"container": false, "runtime": ""}
}

func containerHintLive() map[string]any {
	cgroup, _ := readLimited("/proc/1/cgroup", 4096)
	sched, _ := readLimited("/proc/1/sched", 4096)
	return ContainerHint(cgroup, sched)
}

// Collect intentionally records paths, sizes, permissions and key
// fingerprints only. File contents are never included in evidence.
func Collect() map[string]any {
	ev := map[string]any{"degraded": []string{}, "os": platformName()}
	if runtime.GOOS != "linux" {
		ev["degraded"] = append(ev["degraded"].([]string), "not-linux")
		return ev
	}
	units := ListUnitFiles(systemdDirs)
	ev["units"] = units
	ev["unit_count"] = len(units)
	ev["cron"] = ListCronEntries(cronPaths)

	profiles := make([]*FileMeta, 0)
	for _, path := range profileFiles {
		if meta := FileMetaOf(path); meta != nil {
			profiles = append(profiles, meta)
		}
	}
	home, _ := os.UserHomeDir()
	for _, name := range userProfileFiles {
		if meta := FileMetaOf(filepath.Join(home, name)); meta != nil {
			profiles = append(profiles, meta)
		}
	}
	ev["profiles"] = profiles

	keys := make([]map[string]any, 0)
	for _, dir := range []string{filepath.Join(home, ".ssh"), "/root/.ssh", "/etc/ssh"} {
		for _, name := range sshNames {
			path := filepath.Join(dir, name)
			info, err := os.Stat(path)
			if err != nil || info.IsDir() {
				continue
			}
			content, _ := readLimited(path, 1<<20)
			keys = append(keys, map[string]any{
				"path": path, "meta": FileMetaOf(path),
				"fingerprints": ParseAuthorizedKeys(content),
			})
		}
	}
	ev["ssh_keys"] = keys

	if content, err := readLimited("/proc/modules", 1<<20); err == nil {
		modules := ParseLsmod(content)
		ev["kernel_modules"] = modules
		ev["kernel_module_count"] = len(modules)
	} else {
		ev["degraded"] = append(ev["degraded"].([]string), "modules:unreadable")
		ev["kernel_modules"] = []string{}
	}
	if status, err := readLimited("/proc/self/status", 1<<20); err == nil {
		mask := ParseCapEff(status)
		ev["capabilities"] = DecodeCaps(mask)
		if mask >= 0 {
			ev["cap_eff"] = fmt.Sprintf("0x%x", mask)
		} else {
			ev["cap_eff"] = nil
		}
	} else {
		ev["degraded"] = append(ev["degraded"].([]string), "caps:unreadable")
		ev["capabilities"] = []string{}
	}
	for key, value := range containerHintLive() {
		ev[key] = value
	}
	secrets := make([]*FileMeta, 0)
	for _, path := range secretPaths {
		meta := FileMetaOf(path)
		if meta == nil {
			continue
		}
		if mode, err := parseFileMode(meta.Mode); err == nil {
			meta.WorldReadable = mode&0o044 != 0
		}
		secrets = append(secrets, meta)
	}
	ev["secrets"] = secrets
	return ev
}

func EvidenceSummary() map[string]any {
	ev := Collect()
	summary := map[string]any{
		"units":        ev["unit_count"],
		"ssh_keys":     0,
		"capabilities": []string{},
		"container":    false,
		"degraded":     ev["degraded"],
	}
	if keys, ok := ev["ssh_keys"].([]map[string]any); ok {
		summary["ssh_keys"] = len(keys)
	}
	if caps, ok := ev["capabilities"].([]string); ok {
		if len(caps) > 12 {
			caps = caps[:12]
		}
		summary["capabilities"] = caps
	}
	if container, ok := ev["container"].(bool); ok {
		summary["container"] = container
	}
	return summary
}

func readLimited(path string, limit int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	buffer := make([]byte, limit)
	n, err := file.Read(buffer)
	if err != nil && n == 0 {
		return "", err
	}
	return string(buffer[:n]), nil
}

func parseFileMode(value string) (uint32, error) {
	value = strings.TrimPrefix(value, "0o")
	parsed, err := strconv.ParseUint(value, 8, 32)
	if err != nil {
		return 0, err
	}
	return uint32(parsed), nil
}

func platformName() string {
	switch runtime.GOOS {
	case "linux":
		return "Linux"
	case "windows":
		return "Windows"
	case "darwin":
		return "Darwin"
	default:
		return runtime.GOOS
	}
}

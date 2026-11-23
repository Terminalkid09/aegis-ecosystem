// Package platform contains the OS-facing pieces Guard needs beyond the
// portable event transport. Parsers are pure and unit-testable on any OS;
// command execution is isolated behind CommandRunner so tests never touch the
// real registry, services, or firewall.
package platform

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type CommandRunner interface {
	Output(ctx context.Context, name string, args ...string) (string, error)
	Run(ctx context.Context, name string, args ...string) error
}

type ExecRunner struct{}

func (ExecRunner) Output(ctx context.Context, name string, args ...string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%s: %w", name, err)
	}
	return string(output), nil
}

func (r ExecRunner) Run(ctx context.Context, name string, args ...string) error {
	_, err := r.Output(ctx, name, args...)
	return err
}

type RegistryValue struct {
	Key  string
	Name string
	Data string
}

var registryValueLine = regexp.MustCompile(`^\s{4}(.+?)\s{4}REG_[A-Za-z0-9_]+\s{4}(.*)$`)

// ParseRegistryTree parses `reg query <key> /s`. It does not guess at
// localized headers: only HKEY_ lines open a key and only value-shaped lines
// are accepted.
func ParseRegistryTree(output string) map[string]map[string]string {
	tree := make(map[string]map[string]string)
	current := ""
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "HKEY_") {
			current = trimmed
			if _, ok := tree[current]; !ok {
				tree[current] = make(map[string]string)
			}
			continue
		}
		if current == "" {
			continue
		}
		match := registryValueLine.FindStringSubmatch(line)
		if len(match) != 3 {
			continue
		}
		name := strings.TrimSpace(match[1])
		if strings.EqualFold(name, "(Default)") || strings.EqualFold(name, "(Predefinito)") {
			name = "@default"
		}
		tree[current][name] = strings.TrimSpace(match[2])
	}
	return tree
}

func FlattenRegistryTree(tree map[string]map[string]string) []RegistryValue {
	keys := make([]string, 0, len(tree))
	for key := range tree {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]RegistryValue, 0)
	for _, key := range keys {
		names := make([]string, 0, len(tree[key]))
		for name := range tree[key] {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			out = append(out, RegistryValue{Key: key, Name: name, Data: tree[key][name]})
		}
	}
	return out
}

func RegistryQuery(ctx context.Context, runner CommandRunner, key string, recursive bool) (string, error) {
	if runner == nil {
		runner = ExecRunner{}
	}
	args := []string{"query", key}
	if recursive {
		args = append(args, "/s")
	}
	return runner.Output(ctx, "reg", args...)
}

func RegistryDeleteValue(ctx context.Context, runner CommandRunner, key, value string) error {
	if runner == nil {
		runner = ExecRunner{}
	}
	if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" || strings.ContainsAny(key+value, "\r\n") {
		return fmt.Errorf("registry delete non valido")
	}
	return runner.Run(ctx, "reg", "delete", key, "/v", value, "/f")
}

func ParseDword(raw string) int {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return -1
	}
	if strings.HasPrefix(raw, "0x") {
		value, err := strconv.ParseInt(raw[2:], 16, 64)
		if err != nil {
			return -1
		}
		return int(value)
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return -1
	}
	return value
}

type Service struct {
	Name      string
	ImagePath string
	StartType int
}

// Services reads service names from the registry without doing one query per
// service. Details are fetched only for suspicious names.
func Services(ctx context.Context, runner CommandRunner) ([]Service, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("servizi: non-Windows")
	}
	output, err := RegistryQuery(ctx, runner, `HKLM\SYSTEM\CurrentControlSet\Services`, false)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	out := make([]Service, 0)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "HKEY_") {
			continue
		}
		name := line[strings.LastIndex(line, `\`)+1:]
		if name == "" || name == "Services" || seen[strings.ToLower(name)] {
			continue
		}
		seen[strings.ToLower(name)] = true
		out = append(out, Service{Name: name, StartType: -1})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

type PersistenceItem struct {
	Location string
	Name     string
	Value    string
}

func Persistence(ctx context.Context, runner CommandRunner) ([]PersistenceItem, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("persistence: non-Windows")
	}
	keys := []string{
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	}
	items := make([]PersistenceItem, 0)
	for _, key := range keys {
		output, err := RegistryQuery(ctx, runner, key, false)
		if err != nil {
			continue
		}
		for _, value := range FlattenRegistryTree(ParseRegistryTree(output)) {
			if value.Name == "@default" || strings.TrimSpace(value.Name) == "" {
				continue
			}
			items = append(items, PersistenceItem{Location: key, Name: value.Name, Value: value.Data})
		}
	}
	for _, dir := range StartupDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			items = append(items, PersistenceItem{
				Location: "Startup:" + dir,
				Name:     entry.Name(),
				Value:    filepath.Join(dir, entry.Name()),
			})
		}
	}
	return items, nil
}

func StartupDirs() []string {
	out := make([]string, 0, 2)
	for _, base := range []string{os.Getenv("APPDATA"), os.Getenv("PROGRAMDATA")} {
		if strings.TrimSpace(base) == "" {
			continue
		}
		out = append(out, filepath.Join(base, `Microsoft\Windows\Start Menu\Programs\Startup`))
	}
	return out
}

type DefenderSnapshot struct {
	Exclusions map[string][]string
	Disabled   bool
	Degraded   string
}

func Defender(ctx context.Context, runner CommandRunner) DefenderSnapshot {
	snapshot := DefenderSnapshot{Exclusions: make(map[string][]string)}
	if runtime.GOOS != "windows" {
		snapshot.Degraded = "not-windows"
		return snapshot
	}
	keys := map[string]string{
		`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`:       "paths",
		`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes`:   "processes",
		`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions`:  "extensions",
		`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\IpAddresses`: "ips",
	}
	for key, label := range keys {
		output, err := RegistryQuery(ctx, runner, key, false)
		if err != nil {
			continue
		}
		values := ParseRegistryTree(output)
		for _, tree := range values {
			for name := range tree {
				if name == "@default" || name == "" {
					continue
				}
				snapshot.Exclusions[label] = append(snapshot.Exclusions[label], name)
			}
		}
	}
	flags, _ := RegistryQuery(ctx, runner, `HKLM\SOFTWARE\Microsoft\Windows Defender`, false)
	for _, value := range FlattenRegistryTree(ParseRegistryTree(flags)) {
		if value.Name == "DisableAntiSpyware" && ParseDword(value.Data) == 1 {
			snapshot.Disabled = true
		}
		if value.Name == "DisableRealtimeMonitoring" && ParseDword(value.Data) == 1 {
			snapshot.Disabled = true
		}
	}
	if len(snapshot.Exclusions) == 0 {
		snapshot.Degraded = "exclusions-unreadable"
	}
	return snapshot
}

func (s DefenderSnapshot) LooksDisabled() bool {
	return s.Disabled || len(s.Exclusions) > 0
}

type AuthResult struct {
	Signed    bool
	Publisher string
	Status    string
	Source    string
}

// Authenticode asks Windows' own verifier through PowerShell. Paths are
// base64-encoded into the script, so a filename containing quotes cannot
// change the command. The result is advisory telemetry, never an allow/deny
// decision for commands.
func Authenticode(ctx context.Context, runner CommandRunner, path string) (AuthResult, error) {
	if runtime.GOOS != "windows" {
		return AuthResult{Status: "not-windows", Source: "powershell"}, nil
	}
	if strings.TrimSpace(path) == "" {
		return AuthResult{}, fmt.Errorf("authenticode: path vuoto")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(path))
	script := `$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + encoded + `')); ` +
		`$s=Get-AuthenticodeSignature -LiteralPath $p; if ($null -eq $s) { 'status=Unknown'; exit 0 }; ` +
		`'status=' + $s.Status; if ($s.SignerCertificate) { 'publisher=' + $s.SignerCertificate.Subject }`
	output, err := runner.Output(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil && strings.TrimSpace(output) == "" {
		return AuthResult{}, err
	}
	return ParseAuthenticode(output), nil
}

func ParseAuthenticode(output string) AuthResult {
	result := AuthResult{Source: "powershell"}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		switch {
		case strings.HasPrefix(strings.ToLower(line), "status="):
			result.Status = strings.TrimSpace(line[len("status="):])
		case strings.HasPrefix(strings.ToLower(line), "publisher="):
			result.Publisher = strings.TrimSpace(line[len("publisher="):])
		}
	}
	result.Signed = strings.EqualFold(result.Status, "Valid")
	return result
}

func NormalizePath(path string) string {
	path = strings.TrimSpace(path)
	if len(path) >= 2 && path[0] == '"' && path[len(path)-1] == '"' {
		path = path[1 : len(path)-1]
	}
	path = strings.ReplaceAll(path, "/", `\`)
	lower := strings.ToLower(path)
	for _, prefix := range []string{`\\?\`, `\??\`} {
		if strings.HasPrefix(lower, strings.ToLower(prefix)) {
			path = path[len(prefix):]
			break
		}
	}
	for strings.Contains(path, `\\`) {
		path = strings.ReplaceAll(path, `\\`, `\`)
	}
	return strings.ToLower(path)
}

func BaseName(path string) string {
	normalized := NormalizePath(path)
	if index := strings.LastIndexAny(normalized, `\/`); index >= 0 {
		return normalized[index+1:]
	}
	return normalized
}

func ProcessKey(pid int, startNS int64) string {
	if startNS <= 0 {
		return "pid:" + strconv.Itoa(pid)
	}
	return "pid:" + strconv.Itoa(pid) + "@" + strconv.FormatInt(startNS, 10)
}

func ParseWMICOutput(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 2 || !strings.Contains(strings.ToLower(lines[0]), "commandline") {
		return ""
	}
	for _, line := range lines[1:] {
		if value := strings.TrimSpace(line); value != "" {
			return value
		}
	}
	return ""
}

type Connection struct {
	Proto  string `json:"proto"`
	Local  string `json:"local"`
	Remote string `json:"remote"`
	State  string `json:"state"`
	PID    int    `json:"pid,omitempty"`
}

func ParseNetstatLine(line string) (Connection, bool) {
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 5 || strings.EqualFold(parts[0], "proto") {
		return Connection{}, false
	}
	pid, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil || pid <= 0 {
		return Connection{}, false
	}
	return Connection{Proto: parts[0], Local: parts[1], Remote: parts[2], State: parts[3], PID: pid}, true
}

func HeuristicTags(processName, parentName, commandLine string) []string {
	process := strings.ToLower(processName)
	parent := strings.ToLower(parentName)
	cmd := strings.ToLower(commandLine)
	tags := make([]string, 0, 4)
	if (process == "sh" || process == "bash" || process == "python" || process == "python3") &&
		(parent == "libreoffice" || parent == "evince" || parent == "okular") {
		tags = append(tags, "OFFICE_SPAWNED_SHELL")
	}
	if strings.Contains(cmd, "base64 -d") || strings.Contains(cmd, "base64 --decode") || strings.Contains(cmd, "eval") {
		tags = append(tags, "SUSPICIOUS_POWERSHELL_ARGS")
	}
	if strings.Contains(cmd, "curl") && (strings.Contains(cmd, "| bash") || strings.Contains(cmd, "| sh")) {
		tags = append(tags, "HIDDEN_OR_BYPASS_EXECUTION")
	}
	if strings.Contains(process, "mimikatz") || strings.Contains(process, "lazagne") || strings.Contains(process, "secretsdump") {
		tags = append(tags, "CREDENTIAL_DUMPING_TOOL_DETECTED")
	}
	return tags
}

func DefaultHostsFile() string {
	if runtime.GOOS == "windows" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		return filepath.Join(root, `System32\drivers\etc\hosts`)
	}
	return "/etc/hosts"
}

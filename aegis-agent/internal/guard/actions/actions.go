// Package actions executes Guard response commands. Validation is separated
// from side effects where practical: IPs, domains, paths and PIDs are checked
// before a shell or firewall command is built. Tests inject a fake Runner, so
// CI never kills a process or changes a real firewall.
package actions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/process"

	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/event"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/guard/commands"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/guard/fim"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/guard/platform"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/guard/yara"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/transport"
)

var ErrAgentHandled = errors.New("comando gestito dall'agente")

type Result struct {
	Details string
	Events  []event.Event
}

type Executor struct {
	AgentID       string
	BrainURL      string
	Home          string
	HostsFile     string
	QuarantineDir string
	Yara          *yara.Scanner
	FIM           *fim.Monitor
	Runner        platform.CommandRunner
	Log           *slog.Logger
	Now           func() time.Time

	mu     sync.Mutex
	timers map[string]*time.Timer
}

func New(agentID, brainURL, home string, yaraScanner *yara.Scanner, monitor *fim.Monitor, logger *slog.Logger) *Executor {
	if logger == nil {
		logger = slog.Default()
	}
	if strings.TrimSpace(home) == "" {
		home = "."
	}
	return &Executor{
		AgentID: agentID, BrainURL: brainURL, Home: home,
		HostsFile:     platform.DefaultHostsFile(),
		QuarantineDir: filepath.Join(home, "quarantine"),
		Yara:          yaraScanner, FIM: monitor, Runner: platform.ExecRunner{}, Log: logger,
		Now: time.Now, timers: make(map[string]*time.Timer),
	}
}

func (e *Executor) Execute(ctx context.Context, command transport.Command) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if e.Runner == nil {
		e.Runner = platform.ExecRunner{}
	}
	switch command.Command {
	case commands.KillProcess:
		return e.killProcess(command)
	case commands.KillProcessTree:
		return e.killProcessTree(ctx, command)
	case commands.BlockIP:
		return e.blockIP(ctx, command, false, 0)
	case commands.BlockIPTemporal:
		return e.blockIP(ctx, command, true, command.DurationSeconds)
	case commands.QuarantineBinary:
		return e.quarantine(command)
	case commands.RemovePersistence:
		return e.removePersistence(ctx, command)
	case commands.DNSSinkhole:
		return e.dnsSinkhole(command)
	case commands.CollectIOC:
		return e.collectIOC(ctx, command)
	case commands.Verify:
		return e.verify(command)
	case commands.IsolateHost:
		return e.isolate(ctx, true)
	case commands.DeisolateHost:
		return e.isolate(ctx, false)
	case commands.FIMSetWatch:
		return e.setFIM(command)
	case commands.YaraScan:
		return e.scanYara(ctx, command)
	case commands.UpdateAgent:
		return Result{}, ErrAgentHandled
	default:
		return Result{}, fmt.Errorf("unsupported command: %s", command.Command)
	}
}

func (e *Executor) killProcess(command transport.Command) (Result, error) {
	if command.PID <= 0 {
		return Result{}, fmt.Errorf("KILL_PROCESS: PID mancante")
	}
	if command.PID == os.Getpid() {
		return Result{}, fmt.Errorf("KILL_PROCESS: rifiuto di terminare l'agente")
	}
	p, err := process.NewProcess(int32(command.PID))
	if err != nil {
		return Result{}, fmt.Errorf("KILL_PROCESS: process %d not found: %w", command.PID, err)
	}
	if err := p.Kill(); err != nil {
		return Result{}, fmt.Errorf("KILL_PROCESS: %w", err)
	}
	return Result{Details: fmt.Sprintf("PID %d terminato", command.PID)}, nil
}

func (e *Executor) killProcessTree(ctx context.Context, command transport.Command) (Result, error) {
	if command.PID <= 0 {
		return Result{}, fmt.Errorf("KILL_PROCESS_TREE: PID mancante")
	}
	if command.PID == os.Getpid() {
		return Result{}, fmt.Errorf("KILL_PROCESS_TREE: rifiuto di terminare l'agente")
	}
	if runtime.GOOS == "windows" {
		if err := e.Runner.Run(ctx, "taskkill", "/F", "/T", "/PID", strconv.Itoa(command.PID)); err != nil {
			return Result{}, fmt.Errorf("KILL_PROCESS_TREE: %w", err)
		}
		return Result{Details: fmt.Sprintf("albero PID %d terminato", command.PID)}, nil
	}
	p, err := process.NewProcess(int32(command.PID))
	if err != nil {
		return Result{}, fmt.Errorf("KILL_PROCESS_TREE: process %d not found: %w", command.PID, err)
	}
	children, _ := p.Children()
	for _, child := range children {
		_ = child.Kill()
	}
	if err := p.Kill(); err != nil {
		return Result{}, fmt.Errorf("KILL_PROCESS_TREE: %w", err)
	}
	return Result{Details: fmt.Sprintf("albero PID %d terminato", command.PID)}, nil
}

func (e *Executor) blockIP(ctx context.Context, command transport.Command, temporal bool, duration int) (Result, error) {
	ip := strings.TrimSpace(command.IP)
	if !commands.IsIPLiteral(ip) {
		return Result{}, fmt.Errorf("BLOCK_IP: invalid IP %q", ip)
	}
	brainHost := commands.ExtractBrainHost(e.BrainURL)
	if brainHost != "" && strings.EqualFold(brainHost, ip) {
		return Result{}, fmt.Errorf("BLOCK_IP: refusing to block the Brain %s", brainHost)
	}
	var name string
	if runtime.GOOS == "windows" {
		name = "Aegis_Block_" + strings.NewReplacer(".", "_", ":", "_").Replace(ip)
		if err := e.Runner.Run(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
			"name="+name, "dir=in", "action=block", "remoteip="+ip); err != nil {
			return Result{}, fmt.Errorf("BLOCK_IP: %w", err)
		}
	} else {
		if err := e.Runner.Run(ctx, "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"); err != nil {
			return Result{}, fmt.Errorf("BLOCK_IP: %w", err)
		}
	}
	if temporal && duration > 0 {
		key := ip
		e.mu.Lock()
		if old := e.timers[key]; old != nil {
			old.Stop()
		}
		e.timers[key] = time.AfterFunc(time.Duration(duration)*time.Second, func() {
			unblockCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := e.unblockIP(unblockCtx, ip, name); err != nil {
				e.Log.Warn("unblock IP fallito", "ip", ip, "error", err)
			}
			e.mu.Lock()
			delete(e.timers, key)
			e.mu.Unlock()
		})
		e.mu.Unlock()
	}
	detail := fmt.Sprintf("IP %s bloccato", ip)
	if temporal {
		detail += fmt.Sprintf(" for %ds", duration)
	}
	return Result{Details: detail}, nil
}

func (e *Executor) unblockIP(ctx context.Context, ip, name string) error {
	if runtime.GOOS == "windows" {
		return e.Runner.Run(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
	}
	return e.Runner.Run(ctx, "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
}

func (e *Executor) quarantine(command transport.Command) (Result, error) {
	if command.PID <= 0 {
		return Result{}, fmt.Errorf("QUARANTINE_BINARY: PID mancante")
	}
	p, err := process.NewProcess(int32(command.PID))
	if err != nil {
		return Result{}, fmt.Errorf("QUARANTINE_BINARY: process not found: %w", err)
	}
	exe, err := p.Exe()
	if err != nil || strings.TrimSpace(exe) == "" {
		return Result{}, fmt.Errorf("QUARANTINE_BINARY: path cannot be resolved")
	}
	if err := os.MkdirAll(e.QuarantineDir, 0o700); err != nil {
		return Result{}, fmt.Errorf("QUARANTINE_BINARY: %w", err)
	}
	hash, err := hashFile(exe)
	if err != nil {
		return Result{}, fmt.Errorf("QUARANTINE_BINARY: hash: %w", err)
	}
	name := fmt.Sprintf("%s_%s_%s", e.Now().UTC().Format("20060102T150405"), hash[:12], filepath.Base(exe))
	dest := filepath.Join(e.QuarantineDir, name)
	if err := copyFile(exe, dest); err != nil {
		return Result{}, fmt.Errorf("QUARANTINE_BINARY: copia: %w", err)
	}
	if runtime.GOOS == "windows" {
		if err := e.Runner.Run(context.Background(), "icacls", exe, "/deny", "Everyone:(R,W,X)"); err != nil {
			return Result{}, fmt.Errorf("QUARANTINE_BINARY: rimozione permessi: %w", err)
		}
	} else {
		if err := os.Chmod(exe, 0o000); err != nil {
			return Result{}, fmt.Errorf("QUARANTINE_BINARY: rimozione permessi: %w", err)
		}
	}
	return Result{Details: fmt.Sprintf("binario %s copiato in quarantena (%s)", exe, dest)}, nil
}

func (e *Executor) removePersistence(ctx context.Context, command transport.Command) (Result, error) {
	if strings.TrimSpace(command.ProcessName) == "" {
		return Result{}, fmt.Errorf("REMOVE_PERSISTENCE: process_name mancante")
	}
	if runtime.GOOS != "windows" {
		return Result{}, fmt.Errorf("REMOVE_PERSISTENCE: not supported on %s", runtime.GOOS)
	}
	needle := strings.ToLower(command.ProcessName)
	removed := 0
	for _, key := range []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
	} {
		output, err := platform.RegistryQuery(ctx, e.Runner, key, true)
		if err != nil {
			continue
		}
		for _, value := range platform.FlattenRegistryTree(platform.ParseRegistryTree(output)) {
			if value.Name == "@default" || value.Name == "" {
				continue
			}
			haystack := strings.ToLower(value.Name + " " + value.Data)
			if !strings.Contains(haystack, needle) {
				continue
			}
			if err := platform.RegistryDeleteValue(ctx, e.Runner, value.Key, value.Name); err == nil {
				removed++
			}
		}
	}
	if output, err := e.Runner.Output(ctx, "schtasks", "/query", "/fo", "CSV"); err == nil {
		for _, line := range strings.Split(output, "\n") {
			if !strings.Contains(strings.ToLower(line), strings.TrimSuffix(needle, ".exe")) {
				continue
			}
			task := strings.Trim(strings.SplitN(line, ",", 2)[0], "\" \r")
			if task != "" && e.Runner.Run(ctx, "schtasks", "/delete", "/f", "/tn", task) == nil {
				removed++
			}
		}
	}
	if removed == 0 {
		return Result{}, fmt.Errorf("REMOVE_PERSISTENCE: no persistence entry removed for %s", command.ProcessName)
	}
	return Result{Details: fmt.Sprintf("%d persistence entries removed for %s", removed, command.ProcessName)}, nil
}

func (e *Executor) dnsSinkhole(command transport.Command) (Result, error) {
	domain := strings.ToLower(strings.TrimSpace(command.Domain))
	if !commands.IsDomainName(domain) {
		return Result{}, fmt.Errorf("DNS_SINKHOLE: invalid domain %q", domain)
	}
	hostsPath := e.HostsFile
	if hostsPath == "" {
		hostsPath = platform.DefaultHostsFile()
	}
	data, err := os.ReadFile(hostsPath)
	if err != nil {
		return Result{}, fmt.Errorf("DNS_SINKHOLE: hosts file is not readable: %w", err)
	}
	entry := "0.0.0.0 " + domain
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(strings.ToLower(line), entry) {
			return Result{Details: domain + " già presente in hosts"}, nil
		}
	}
	file, err := os.OpenFile(hostsPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return Result{}, fmt.Errorf("DNS_SINKHOLE: hosts file is not writable: %w", err)
	}
	defer file.Close()
	if _, err := fmt.Fprintf(file, "\n# Aegis block - %s\n%s\n", e.Now().UTC().Format(time.RFC3339), entry); err != nil {
		return Result{}, fmt.Errorf("DNS_SINKHOLE: scrittura: %w", err)
	}
	return Result{Details: domain + " -> 0.0.0.0"}, nil
}

func (e *Executor) collectIOC(ctx context.Context, command transport.Command) (Result, error) {
	if command.PID <= 0 {
		return Result{}, fmt.Errorf("COLLECT_IOC: PID mancante")
	}
	p, err := process.NewProcess(int32(command.PID))
	if err != nil {
		return Result{}, fmt.Errorf("COLLECT_IOC: process not found: %w", err)
	}
	exe, _ := p.Exe()
	cmdline, _ := p.Cmdline()
	name, _ := p.Name()
	ioc := map[string]any{
		"pid": command.PID, "process_name": name, "timestamp": e.Now().UTC().Format(time.RFC3339Nano),
		"executable_path": exe, "command_line": cmdline,
	}
	if exe != "" {
		if hash, err := hashFile(exe); err == nil {
			ioc["sha256"] = hash
			if info, err := os.Stat(exe); err == nil {
				ioc["file_size"] = info.Size()
			}
		}
	}
	if connections, err := p.ConnectionsWithContext(ctx); err == nil {
		ioc["connections"] = connections
	}
	payload, _ := json.Marshal(ioc)
	return Result{Details: string(payload)}, nil
}

func (e *Executor) verify(command transport.Command) (Result, error) {
	if command.PID <= 0 {
		return Result{}, fmt.Errorf("VERIFY: PID mancante")
	}
	_, err := process.NewProcess(int32(command.PID))
	if err != nil {
		return Result{Details: fmt.Sprintf("PID %d is not running", command.PID)}, nil
	}
	return Result{Details: fmt.Sprintf("PID %d attivo", command.PID)}, nil
}

func (e *Executor) isolate(ctx context.Context, isolate bool) (Result, error) {
	brainHost := commands.ExtractBrainHost(e.BrainURL)
	var groups [][]string
	if isolate {
		groups = commands.IsolateCommands(brainHost, runtime.GOOS == "windows")
	} else {
		groups = commands.RestoreCommands(brainHost, runtime.GOOS == "windows")
	}
	for _, args := range groups {
		if len(args) == 0 {
			continue
		}
		if err := e.Runner.Run(ctx, args[0], args[1:]...); err != nil {
			return Result{}, fmt.Errorf("isolamento parziale su %s: %w", args[0], err)
		}
	}
	statePath := filepath.Join(e.Home, "isolation.state")
	if isolate {
		_ = os.WriteFile(statePath, []byte("isolated=true\nts="+e.Now().UTC().Format(time.RFC3339)+"\nbrain="+brainHost+"\n"), 0o600)
		return Result{Details: "host isolato"}, nil
	}
	_ = os.Remove(statePath)
	return Result{Details: "host deisolato"}, nil
}

func (e *Executor) setFIM(command transport.Command) (Result, error) {
	if e.FIM == nil {
		return Result{}, fmt.Errorf("FIM_SET_WATCH: monitor not initialized")
	}
	recursive := true
	if command.Recursive != nil {
		recursive = *command.Recursive
	}
	count, missing, err := e.FIM.Apply(command.Paths, recursive)
	if err != nil {
		return Result{}, fmt.Errorf("FIM_SET_WATCH: %w", err)
	}
	detail := fmt.Sprintf("FIM attivo su %d percorso/i", count)
	if len(missing) > 0 {
		detail += "; inesistenti: " + strings.Join(missing, ", ")
	}
	return Result{Details: detail}, nil
}

func (e *Executor) scanYara(ctx context.Context, command transport.Command) (Result, error) {
	if e.Yara == nil {
		return Result{}, fmt.Errorf("YARA_SCAN: scanner is not configured")
	}
	matches, err := e.Yara.Scan(ctx, command.RulesYARA, command.Targets)
	if err != nil {
		return Result{}, fmt.Errorf("YARA_SCAN: %w", err)
	}
	events := make([]event.Event, 0, len(matches))
	for _, match := range matches {
		ev := event.Event{
			AgentID: e.AgentID, Timestamp: e.Now().UTC(), EventType: "YARA_MATCH",
			ProcessName: match.Rule, ProcessPath: "YARA", CommandLine: "[YARA] " + match.Rule + " -> " + match.FilePath,
			SchemaVersion: event.SchemaVersion,
		}
		if hash, err := hashFile(match.FilePath); err == nil {
			ev.FileHash = hash
		}
		if id, err := event.NewID(); err == nil {
			ev.EventID = id
		}
		events = append(events, ev)
	}
	return Result{Details: fmt.Sprintf("%d match YARA", len(matches)), Events: events}, nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.CopyN(hash, file, 8*1024*1024); err != nil && err != io.EOF {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func copyFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

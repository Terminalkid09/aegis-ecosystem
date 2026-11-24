// Package etw consumes the existing aegis-etw.exe JSONL stream. It keeps the
// helper (a kernel trace session in user mode) but does not add a second
// service: the Go agent owns the subprocess and forwards its events through
// the same Guard outbox as polling telemetry.
package etw

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/event"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/guard/platform"
)

const maxLineBytes = 1 << 20

type Source struct {
	Enabled       bool
	Path          string
	AllowUnsigned bool
	SHA256        string
	AgentID       string
	OSName        string
	AgentVersion  string
}

func New(agentID, osName, agentVersion string, enabled bool, path string, allowUnsigned bool, pinnedSHA256 ...string) *Source {
	if strings.TrimSpace(path) == "" {
		path = filepath.Join("bin", "aegis-etw.exe")
	}
	pinned := ""
	if len(pinnedSHA256) > 0 {
		pinned = pinnedSHA256[0]
	}
	return &Source{
		Enabled: enabled, Path: path, AllowUnsigned: allowUnsigned, SHA256: pinned,
		AgentID: agentID, OSName: osName, AgentVersion: agentVersion,
	}
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Source) Available(ctx context.Context) (bool, string) {
	if s == nil || !s.Enabled {
		return false, "disabled"
	}
	if runtime.GOOS != "windows" {
		return false, "not-windows"
	}
	if !filepath.IsAbs(s.Path) {
		return false, "relative-path"
	}
	info, err := os.Stat(s.Path)
	if err != nil || info.IsDir() {
		return false, "binary-missing"
	}
	if s.AllowUnsigned {
		pinned := strings.ToLower(strings.TrimSpace(s.SHA256))
		if pinned == "" {
			return false, "unsigned-without-pin"
		}
		actual, err := fileSHA256(s.Path)
		if err != nil || !strings.EqualFold(actual, pinned) {
			return false, "hash-mismatch"
		}
	} else {
		result, err := platform.Authenticode(ctx, platform.ExecRunner{}, s.Path)
		if err != nil || !result.Signed {
			return false, "untrusted-binary"
		}
	}
	return true, ""
}

type Stream struct {
	cmd      *exec.Cmd
	cancel   context.CancelFunc
	mu       sync.Mutex
	closed   bool
	done     chan struct{}
	doneOnce sync.Once
}

func (s *Stream) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
	}
	s.closeDone()
}

func (s *Stream) closeDone() {
	if s == nil || s.done == nil {
		return
	}
	s.doneOnce.Do(func() { close(s.done) })
}

// Done closes when stdout ends and the helper process has been reaped. The
// supervisor uses it to distinguish a clean stop from a killed/terminated ETW
// session and to restart the collector.
func (s *Stream) Done() <-chan struct{} {
	if s == nil || s.done == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return s.done
}

func (s *Stream) Running() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.cmd != nil && s.cmd.Process != nil
}

func (s *Source) Start(ctx context.Context, emit func(event.Event)) (*Stream, bool) {
	if ok, _ := s.Available(ctx); !ok {
		return nil, false
	}
	runCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(runCtx, s.Path)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, false
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, false
	}
	stream := &Stream{cmd: cmd, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer stream.Stop()
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64*1024), maxLineBytes)
		for scanner.Scan() {
			if ev, ok := ParseLine(s.AgentID, s.OSName, s.AgentVersion, scanner.Text()); ok {
				if ev.Provenance == "" {
					ev.Provenance = "etw"
				}
				if emit != nil {
					emit(ev)
				}
			}
		}
	}()
	return stream, true
}

func ParseLine(agentID, osName, agentVersion, line string) (event.Event, bool) {
	line = strings.TrimSpace(line)
	if line == "" || agentID == "" {
		return event.Event{}, false
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return event.Event{}, false
	}
	eventType := stringValue(raw["event_type"])
	if eventType != "PROCESS_CREATED" && eventType != "PROCESS_EXITED" && eventType != "CONNECTION_ESTABLISHED" {
		return event.Event{}, false
	}
	pid, ok := intValue(raw["pid"])
	if !ok || pid <= 0 {
		return event.Event{}, false
	}
	ppid, _ := intValue(raw["ppid"])
	ev := event.Event{
		AgentID:       agentID,
		Timestamp:     time.Now().UTC(),
		EventType:     eventType,
		Hostname:      stringValue(raw["hostname"]),
		OS:            osName,
		AgentVersion:  agentVersion,
		PID:           pid,
		ParentPID:     ppid,
		ProcessName:   stringValue(raw["comm"]),
		ProcessPath:   stringValue(raw["filename"]),
		CommandLine:   stringValue(raw["cmdline"]),
		SchemaVersion: event.SchemaVersion,
	}
	if value, ok := intValue(raw["schema_version"]); ok {
		ev.SchemaVersion = value
	}
	if ev.SchemaVersion != event.SchemaVersion {
		return event.Event{}, false
	}
	ev.EventID = stringValue(raw["event_id"])
	ev.BootID = stringValue(raw["boot_id"])
	if seq, ok := int64Value(raw["seq"]); ok {
		if ev.BootID == "" || seq < 0 {
			return event.Event{}, false
		}
		ev.Seq = &seq
	}
	if ts, ok := int64Value(raw["ts_ns"]); ok && ts >= 0 {
		ev.TsMonotonicNS = &ts
	}
	if ts, ok := int64Value(raw["ts_wall_ns"]); ok && ts >= 0 {
		ev.TsWallNS = &ts
	}
	if ts, ok := int64Value(raw["proc_start_ns"]); ok {
		ev.ProcStartNS = &ts
	}
	ev.SessionID = stringValue(raw["session"])
	ev.IntegrityLevel = stringValue(raw["integrity"])
	ev.Proto = stringValue(raw["proto"])
	ev.Direction = stringValue(raw["direction"])
	ev.ContainerID = stringValue(raw["container_id"])
	ev.Cgroup = stringValue(raw["cgroup"])
	ev.NetNamespace = stringValue(raw["namespace"])
	ev.Provenance = stringValue(raw["provenance"])
	ev.Quality = stringValue(raw["quality"])
	if eventType == "CONNECTION_ESTABLISHED" {
		remote := stringValue(raw["remote"])
		if remote != "" {
			ev.NetworkFlows = []map[string]any{{"remote": remote, "state": "ESTABLISHED"}}
		}
	}
	if ev.EventID == "" {
		if id, err := event.NewID(); err == nil {
			ev.EventID = id
		}
	}
	return ev, true
}

func stringValue(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func intValue(value any) (int, bool) {
	switch number := value.(type) {
	case float64:
		return int(number), true
	case int:
		return number, true
	case json.Number:
		parsed, err := strconv.Atoi(string(number))
		return parsed, err == nil
	default:
		return 0, false
	}
}

func int64Value(value any) (int64, bool) {
	switch number := value.(type) {
	case float64:
		return int64(number), true
	case int64:
		return number, true
	case int:
		return int64(number), true
	case json.Number:
		parsed, err := strconv.ParseInt(string(number), 10, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func (s *Source) Probe(ctx context.Context) error {
	ok, reason := s.Available(ctx)
	if !ok {
		return fmt.Errorf("ETW unavailable: %s", reason)
	}
	return nil
}

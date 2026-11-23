// Package monitor implements Guard's process telemetry without JNA or a
// kernel driver. Polling is the safety net; the optional ETW source feeds the
// same event channel with lower latency. New processes are identified by PID
// plus start time so PID reuse cannot hide a short-lived child.
package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/process"

	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/event"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/guard/platform"
)

const DefaultInterval = time.Second

type Emitter func(event.Event)

type Monitor struct {
	agentID      string
	hostname     string
	osName       string
	agentVersion string
	interval     time.Duration
	emit         Emitter
	log          *slog.Logger

	mu     sync.Mutex
	cancel context.CancelFunc
	known  map[string]string // key -> process name
	start  map[int]int64
}

func New(agentID, hostname, osName, agentVersion string, interval time.Duration, emit Emitter, logger *slog.Logger) *Monitor {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Monitor{
		agentID: agentID, hostname: hostname, osName: osName, agentVersion: agentVersion,
		interval: interval, emit: emit, log: logger,
		known: make(map[string]string), start: make(map[int]int64),
	}
}

func (m *Monitor) Start(ctx context.Context) {
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.mu.Unlock()

	// Baseline first: existing processes are not "new" merely because Guard
	// started. Their start times are still remembered for PID reuse.
	_, _ = m.scan(runCtx, false)
	go func() {
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				_, _ = m.scan(runCtx, true)
			}
		}
	}()
}

func (m *Monitor) Stop() {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.mu.Unlock()
}

type processInfo struct {
	PID     int32
	PPID    int32
	Name    string
	Parent  string
	Path    string
	User    string
	Command string
	Threads int32
	StartNS int64
}

func (m *Monitor) scan(ctx context.Context, emitNew bool) ([]processInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	processes, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}
	infos := make([]processInfo, 0, len(processes))
	names := make(map[int32]string)
	for _, p := range processes {
		name, nameErr := p.NameWithContext(ctx)
		if nameErr != nil || name == "" {
			continue
		}
		names[p.Pid] = name
	}
	for _, p := range processes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name, ok := names[p.Pid]
		if !ok {
			continue
		}
		ppid, _ := p.PpidWithContext(ctx)
		created, _ := p.CreateTimeWithContext(ctx)
		startNS := int64(0)
		if created > 0 {
			startNS = created * int64(time.Millisecond)
		}
		infos = append(infos, processInfo{
			PID: p.Pid, PPID: ppid, Name: name, Parent: names[ppid], StartNS: startNS,
		})
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].PID < infos[j].PID })

	m.mu.Lock()
	previous := m.known
	current := make(map[string]string, len(infos))
	for _, info := range infos {
		key := platform.ProcessKey(int(info.PID), info.StartNS)
		current[key] = info.Name
		m.start[int(info.PID)] = info.StartNS
	}
	m.known = current
	m.mu.Unlock()

	if !emitNew || m.emit == nil {
		return infos, nil
	}
	for i := range infos {
		info := &infos[i]
		key := platform.ProcessKey(int(info.PID), info.StartNS)
		if _, existed := previous[key]; existed {
			continue
		}
		// Expensive fields (WMI cmdline/user and Authenticode) are fetched
		// only for processes that actually need an event. Doing this for every
		// process on every one-second poll burned a full core on Windows.
		m.fillDetails(ctx, info)
		m.emit(m.makeEvent(*info))
	}
	return infos, nil
}

func (m *Monitor) fillDetails(ctx context.Context, info *processInfo) {
	p, err := process.NewProcessWithContext(ctx, info.PID)
	if err != nil {
		return
	}
	info.Path, _ = p.ExeWithContext(ctx)
	info.User, _ = p.UsernameWithContext(ctx)
	info.Command, _ = p.CmdlineWithContext(ctx)
	info.Threads, _ = p.NumThreadsWithContext(ctx)
}

func (m *Monitor) makeEvent(info processInfo) event.Event {
	ev := event.Event{
		AgentID:           m.agentID,
		Timestamp:         time.Now().UTC(),
		EventType:         "PROCESS_CREATED",
		Hostname:          m.hostname,
		OS:                m.osName,
		AgentVersion:      m.agentVersion,
		PID:               int(info.PID),
		ParentPID:         int(info.PPID),
		ParentProcessName: info.Parent,
		ProcessName:       info.Name,
		ProcessPath:       info.Path,
		User:              info.User,
		CommandLine:       info.Command,
		ThreadCount:       int(info.Threads),
		Provenance:        "toolhelp",
		Quality:           "full",
		SchemaVersion:     event.SchemaVersion,
	}
	if info.StartNS > 0 {
		ev.ProcStartNS = &info.StartNS
	} else {
		ev.Quality = "degraded:pid-reuse-unknown"
	}
	if info.Path != "" {
		ev.FileHash = hashFile(info.Path)
	}
	if runtime.GOOS == "windows" && info.Path != "" {
		if result, err := platform.Authenticode(context.Background(), platform.ExecRunner{}, info.Path); err == nil {
			if result.Signed {
				ev.Signature = "authenticode-trusted"
				ev.Publisher = result.Publisher
			} else if result.Status != "" && result.Status != "not-windows" && result.Status != "NotFound" {
				ev.Signature = "unsigned:" + result.Status
			}
		}
	}
	ev.BehavioralTags = platform.HeuristicTags(info.Name, info.Parent, info.Command)
	if id, err := event.NewID(); err == nil {
		ev.EventID = id
	}
	return ev
}

func hashFile(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.CopyN(hash, file, 8*1024*1024); err != nil && err != io.EOF {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// Evaluate is the pure heuristic entry point used by tests and the monitor.
func Evaluate(name, parent, cmdline string) []string {
	return platform.HeuristicTags(name, parent, cmdline)
}

func (m *Monitor) ActiveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.known)
}

func (m *Monitor) String() string {
	return fmt.Sprintf("guard-monitor(interval=%s)", m.interval)
}

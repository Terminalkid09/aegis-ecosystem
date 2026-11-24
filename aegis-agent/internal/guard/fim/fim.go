// Package fim is a user-mode File Integrity Monitor. It uses fsnotify
// (ReadDirectoryChangesW on Windows, inotify on Linux) for change latency and
// keeps a bounded hash baseline for forensic context. It is telemetry, not a
// kernel prevention driver, and the documentation says so explicitly.
package fim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/event"
)

const (
	MaxHashBytes     = 8 * 1024 * 1024
	MaxBaselineFiles = 5000
	MaxBaselineBytes = 64 * 1024 * 1024
	MaxWatchedDirs   = 64
	DefaultDebounce  = 750 * time.Millisecond
)

type Emitter func(event.Event)

type Monitor struct {
	agentID      string
	osName       string
	agentVersion string
	hostname     string
	emit         Emitter
	log          *slog.Logger

	mu          sync.Mutex
	watcher     *fsnotify.Watcher
	recursive   bool
	watches     map[string]bool
	singles     map[string]bool
	baseline    map[string]string
	lastEventMS map[string]int64
	running     bool
	cancel      context.CancelFunc
	closed      bool

	baselineFiles int
	baselineBytes int64
}

func New(agentID, osName, agentVersion, hostname string, emit Emitter, logger *slog.Logger) (*Monitor, error) {
	if logger == nil {
		logger = slog.Default()
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("FIM watcher: %w", err)
	}
	return &Monitor{
		agentID:      agentID,
		osName:       osName,
		agentVersion: agentVersion,
		hostname:     hostname,
		emit:         emit,
		log:          logger,
		watcher:      watcher,
		watches:      make(map[string]bool),
		singles:      make(map[string]bool),
		baseline:     make(map[string]string),
		lastEventMS:  make(map[string]int64),
	}, nil
}

func (m *Monitor) Available() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.watcher != nil && !m.closed
}

func (m *Monitor) Start(ctx context.Context) {
	m.mu.Lock()
	if m.running || m.closed {
		m.mu.Unlock()
		return
	}
	m.running = true
	runCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.mu.Unlock()

	go func() {
		<-runCtx.Done()
		m.Close()
	}()
	go m.loop(runCtx)
}

func (m *Monitor) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.running = false
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	watcher := m.watcher
	m.watcher = nil
	m.watches = make(map[string]bool)
	m.singles = make(map[string]bool)
	m.baseline = make(map[string]string)
	m.lastEventMS = make(map[string]int64)
	m.mu.Unlock()
	if watcher != nil {
		_ = watcher.Close()
	}
}

// Apply replaces the watchlist atomically from the command's point of view.
// Paths that do not exist are reported but do not abort the other watches.
func (m *Monitor) Apply(paths []string, recursive bool) (int, []string, error) {
	m.mu.Lock()
	if m.closed || m.watcher == nil {
		m.mu.Unlock()
		return 0, nil, fmt.Errorf("FIM unavailable")
	}
	for path := range m.watches {
		_ = m.watcher.Remove(path)
	}
	m.watches = make(map[string]bool)
	m.singles = make(map[string]bool)
	m.baseline = make(map[string]string)
	m.lastEventMS = make(map[string]int64)
	m.recursive = recursive
	m.baselineFiles = 0
	m.baselineBytes = 0
	watcher := m.watcher
	m.mu.Unlock()

	registered := 0
	missing := make([]string, 0)
	for _, raw := range paths {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		absolute, err := filepath.Abs(raw)
		if err != nil {
			missing = append(missing, raw)
			continue
		}
		info, err := os.Stat(absolute)
		if err != nil {
			missing = append(missing, raw)
			continue
		}
		if info.Mode().IsRegular() {
			m.mu.Lock()
			m.singles[absolute] = true
			m.mu.Unlock()
			if err := watcher.Add(filepath.Dir(absolute)); err == nil {
				m.mu.Lock()
				m.watches[filepath.Dir(absolute)] = true
				m.mu.Unlock()
				registered++
			}
			m.hashBaseline(absolute)
			continue
		}
		if !info.IsDir() {
			missing = append(missing, raw)
			continue
		}
		count, err := m.addTree(absolute, recursive)
		if err != nil {
			m.log.Warn("FIM watch fallito", "path", raw, "error", err)
			continue
		}
		if count > 0 {
			registered++
		}
	}
	return registered, missing, nil
}

func (m *Monitor) addTree(root string, recursive bool) (int, error) {
	count := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			m.mu.Lock()
			limit := len(m.watches) >= MaxWatchedDirs
			m.mu.Unlock()
			if limit {
				return filepath.SkipDir
			}
			if addErr := m.watcher.Add(path); addErr == nil {
				m.mu.Lock()
				m.watches[path] = true
				m.mu.Unlock()
				count++
			}
			if !recursive && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type().IsRegular() {
			m.hashBaseline(path)
		}
		return nil
	})
	return count, err
}

func (m *Monitor) hashBaseline(path string) {
	m.mu.Lock()
	if m.baselineFiles >= MaxBaselineFiles || m.closed {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()
	info, err := os.Stat(path)
	if err != nil || info.Size() > MaxBaselineBytes {
		return
	}
	hash, err := hashFile(path, MaxHashBytes)
	if err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.baselineFiles >= MaxBaselineFiles {
		return
	}
	if _, exists := m.baseline[path]; !exists {
		m.baselineFiles++
		m.baselineBytes += info.Size()
	}
	m.baseline[path] = hash
}

func (m *Monitor) loop(ctx context.Context) {
	m.mu.Lock()
	watcher := m.watcher
	m.mu.Unlock()
	if watcher == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			if err != nil {
				m.log.Warn("FIM watcher error", "error", err)
			}
		case change, ok := <-watcher.Events:
			if !ok {
				return
			}
			m.handle(change)
		}
	}
}

func (m *Monitor) handle(change fsnotify.Event) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	path := filepath.Clean(change.Name)
	if len(m.singles) > 0 {
		parent := filepath.Dir(path)
		matched := m.singles[path]
		hasSingleParent := false
		for single := range m.singles {
			if filepath.Dir(single) == parent {
				hasSingleParent = true
				break
			}
		}
		if !matched && hasSingleParent {
			m.mu.Unlock()
			return
		}
	}
	key := path + ":" + change.Op.String()
	now := time.Now().UnixMilli()
	if last := m.lastEventMS[key]; last > 0 && now-last < DefaultDebounce.Milliseconds() {
		m.mu.Unlock()
		return
	}
	if len(m.lastEventMS) > 20000 {
		m.lastEventMS = make(map[string]int64)
	}
	m.lastEventMS[key] = now
	if change.Has(fsnotify.Create) && m.recursive {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			_, _ = m.addTree(path, true)
		}
	}
	_, hadPrevious := m.baseline[path]
	m.mu.Unlock()

	changeName := "modified"
	if change.Has(fsnotify.Create) {
		changeName = "created"
	} else if change.Has(fsnotify.Remove) || change.Has(fsnotify.Rename) {
		changeName = "deleted"
	}

	hash := ""
	if changeName != "deleted" {
		info, err := os.Stat(path)
		if err == nil && info.Mode().IsRegular() && info.Size() <= MaxHashBytes {
			hash, _ = hashFile(path, MaxHashBytes)
		}
	}
	m.mu.Lock()
	m.baseline[path] = hash
	m.mu.Unlock()
	isNew := !hadPrevious && changeName != "deleted"
	detail := fmt.Sprintf("[FIM] %s%s: %s", changeName, map[bool]string{true: " new", false: ""}[isNew], path)

	agentID, hostname, osName, version, emit := m.agentID, m.hostname, m.osName, m.agentVersion, m.emit
	if emit == nil {
		return
	}
	ev := event.Event{
		AgentID:       agentID,
		Timestamp:     time.Now().UTC(),
		EventType:     "FILE_MODIFIED",
		Hostname:      hostname,
		OS:            osName,
		AgentVersion:  version,
		ProcessName:   filepath.Base(path),
		ProcessPath:   "FILE",
		FileHash:      hash,
		CommandLine:   detail,
		SchemaVersion: event.SchemaVersion,
	}
	if id, err := event.NewID(); err == nil {
		ev.EventID = id
	}
	emit(ev)
}

func hashFile(path string, limit int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.CopyN(hash, file, limit+1); err != nil && err != io.EOF {
		return "", err
	}
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() > limit {
		return "", fmt.Errorf("file oltre limite hash")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// WatchInfo is used by the agent's capability report without exposing paths.
func (m *Monitor) WatchInfo() (int, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.watches), m.recursive
}

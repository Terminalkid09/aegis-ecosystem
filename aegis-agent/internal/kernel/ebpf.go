package kernel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

var validEventTypes = map[string]bool{
	"PROCESS_CREATED":        true,
	"PROCESS_EXITED":         true,
	"CONNECTION_ESTABLISHED": true,
}

var v2Strings = []string{
	"boot_id", "session", "integrity", "proto", "direction", "container_id",
	"cgroup", "namespace", "provenance", "quality", "sampling", "signature", "publisher",
}

var v2Ints = []string{"seq", "ts_wall_ns", "proc_start_ns"}

func ParseLine(line string) (map[string]any, error) {
	if strings.TrimSpace(line) == "" {
		return nil, fmt.Errorf("riga vuota")
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		return nil, err
	}
	if event == nil || !validEventTypes[toString(event["event_type"])] {
		return nil, fmt.Errorf("event_type non valido")
	}
	pid, ok := toInt(event["pid"])
	if !ok || pid < 1 {
		return nil, fmt.Errorf("pid non valido")
	}
	return event, nil
}

func EventToReport(event map[string]any, deviceID, hostname, localIP, agentVersion, defaultProvenance string) map[string]any {
	eventType := toString(event["event_type"])
	provenance := toString(event["provenance"])
	if provenance == "" {
		if defaultProvenance == "" {
			defaultProvenance = "ebpf-full"
		}
		provenance = defaultProvenance
	}
	report := map[string]any{
		"agent_id":       deviceID,
		"timestamp":      time.Now().UTC().Format(time.RFC3339Nano),
		"event_type":     eventType,
		"event_id":       StableEventID(event, deviceID),
		"schema_version": intOr(event["schema_version"], 2),
		"pid":            intOr(event["pid"], 0),
		"process_name":   toString(event["comm"]),
		"hostname":       hostname,
		"ip_address":     localIP,
		"agent_version":  agentVersion,
		"provenance":     provenance,
	}
	if report["process_name"] == "" {
		report["process_name"] = "unknown"
	}
	if eventType == "CONNECTION_ESTABLISHED" {
		remote := toString(event["remote"])
		if remote != "" {
			report["network_connections"] = []map[string]any{{"remote": remote, "state": "ESTABLISHED"}}
		}
	} else {
		if ppid := intOr(event["ppid"], 0); ppid > 0 {
			report["parent_pid"] = ppid
		}
		if path := toString(event["filename"]); path != "" {
			report["process_path"] = path
		}
	}
	if ts := event["ts_ns"]; ts != nil {
		report["ts_monotonic_ns"] = intOr(ts, 0)
	}
	for _, key := range v2Strings {
		if value, ok := event[key].(string); ok && value != "" {
			report[key] = value
		}
	}
	for _, key := range v2Ints {
		if value, ok := toInt(event[key]); ok && value >= 0 {
			report[key] = value
		}
	}
	return report
}

func StableEventID(event map[string]any, deviceID string) string {
	if id := toString(event["event_id"]); id != "" {
		return id
	}
	values := []string{
		deviceID,
		toString(event["boot_id"]),
		valueString(event["seq"]),
		valueString(event["pid"]),
		valueString(event["ppid"]),
		toString(event["comm"]),
		toString(event["filename"]),
		toString(event["event_type"]),
		valueString(event["ts_ns"]),
		valueString(event["proc_start_ns"]),
	}
	sum := sha256.Sum256([]byte(strings.Join(values, "|")))
	return hex.EncodeToString(sum[:])[:32]
}

func CollectorCommand(path, objectPath string, excludePID int) []string {
	args := []string{path}
	if objectPath != "" {
		args = append(args, "--obj", objectPath)
	}
	args = append(args, "--exclude-pid", strconv.Itoa(excludePID))
	return args
}

type Batcher struct {
	MaxN     int
	MaxAge   time.Duration
	MaxItems int
	items    []map[string]any
	first    time.Time
	Received int
	Drained  int
	Dropped  int
}

func NewBatcher(maxN int, maxAge time.Duration, maxItems int) *Batcher {
	if maxN <= 0 {
		maxN = 25
	}
	if maxAge <= 0 {
		maxAge = 2 * time.Second
	}
	if maxItems <= 0 {
		maxItems = 2000
	}
	return &Batcher{MaxN: maxN, MaxAge: maxAge, MaxItems: maxItems}
}

func (b *Batcher) Add(item map[string]any, now time.Time) bool {
	if b.first.IsZero() {
		b.first = now
	}
	b.items = append(b.items, item)
	b.Received++
	for len(b.items) > b.MaxItems {
		b.items = b.items[1:]
		b.Dropped++
	}
	return b.Due(now)
}

func (b *Batcher) Due(now time.Time) bool {
	if len(b.items) == 0 {
		return false
	}
	if len(b.items) >= b.MaxN {
		return true
	}
	if b.first.IsZero() {
		return false
	}
	return now.Sub(b.first) >= b.MaxAge
}

func (b *Batcher) Drain() []map[string]any {
	out := b.items
	b.items = nil
	b.first = time.Time{}
	b.Drained += len(out)
	return out
}

func (b *Batcher) Len() int { return len(b.items) }

func (b *Batcher) Stats() map[string]int {
	return map[string]int{"received": b.Received, "drained": b.Drained, "dropped": b.Dropped, "buffered": len(b.items)}
}

type SeenCache struct {
	Window     time.Duration
	MaxKeys    int
	seen       map[string]time.Time
	Duplicates int
}

func NewSeenCache(window time.Duration, maxKeys int) *SeenCache {
	if window <= 0 {
		window = 5 * time.Second
	}
	if maxKeys <= 0 {
		maxKeys = 10000
	}
	return &SeenCache{Window: window, MaxKeys: maxKeys, seen: make(map[string]time.Time)}
}

func (s *SeenCache) Check(event map[string]any, now time.Time) bool {
	if event == nil {
		return false
	}
	key := dedupKey(event)
	if key == "" {
		return false
	}
	if len(s.seen) >= s.MaxKeys {
		cutoff := now.Add(-s.Window)
		for k, timestamp := range s.seen {
			if timestamp.Before(cutoff) {
				delete(s.seen, k)
			}
		}
	}
	if last, ok := s.seen[key]; ok && now.Sub(last) < s.Window {
		s.Duplicates++
		return true
	}
	s.seen[key] = now
	return false
}

func dedupKey(event map[string]any) string {
	if id := toString(event["event_id"]); id != "" {
		return id + "|" + toString(event["boot_id"]) + "|" + toString(event["event_type"])
	}
	if start := valueString(event["proc_start_ns"]); start != "" {
		return start + "|" + toString(event["boot_id"]) + "|" + toString(event["event_type"])
	}
	if ts := valueString(event["ts_ns"]); ts != "" {
		return ts + "|" + toString(event["boot_id"]) + "|" + toString(event["event_type"])
	}
	pid, ok := toInt(event["pid"])
	if !ok || pid < 1 {
		return ""
	}
	ppid, _ := toInt(event["ppid"])
	return fmt.Sprintf("%d|%d|%s|%s", pid, ppid, toString(event["comm"]), toString(event["event_type"]))
}

func toString(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprint(value)
}

func valueString(value any) string {
	if value == nil {
		return ""
	}
	if number, ok := toInt(value); ok {
		return strconv.Itoa(number)
	}
	return fmt.Sprint(value)
}

func toInt(value any) (int, bool) {
	switch number := value.(type) {
	case int:
		return number, true
	case int64:
		return int(number), true
	case float64:
		return int(number), true
	case json.Number:
		parsed, err := number.Int64()
		return int(parsed), err == nil
	case string:
		parsed, err := strconv.Atoi(number)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func intOr(value any, fallback int) int {
	if parsed, ok := toInt(value); ok {
		return parsed
	}
	return fallback
}

func ExcludeSelfCommand(path, objectPath string) []string {
	return CollectorCommand(path, objectPath, os.Getpid())
}

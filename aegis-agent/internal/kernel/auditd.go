package kernel

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	auditKV     = regexp.MustCompile(`(\w+)=("[^"]*"|\S+)`)
	auditTime   = regexp.MustCompile(`audit\((\d+\.\d+):(\d+)\)`)
	auditSerial = regexp.MustCompile(`audit\((\d+\.\d+:\d+)\)`)
	execCalls   = map[string]bool{"59": true, "execve": true, "322": true, "execveat": true}
)

func ParseAuditRecord(lines []string) (map[string]any, error) {
	if len(lines) == 0 {
		return nil, nil
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "type=SYSCALL") {
		return nil, nil
	}
	var syscallLine string
	for _, line := range lines {
		if strings.Contains(line, "type=SYSCALL") {
			syscallLine = line
			break
		}
	}
	if syscallLine == "" {
		return nil, nil
	}
	kv := parseAuditKV(syscallLine)
	if kv["success"] != "yes" || !execCalls[kv["syscall"]] {
		return nil, nil
	}
	pid, _ := strconv.Atoi(kv["pid"])
	if pid < 1 {
		return nil, nil
	}
	ppid, _ := strconv.Atoi(kv["ppid"])
	uid, _ := strconv.Atoi(firstNonEmpty(kv["uid"], kv["auid"], "0"))
	exe := kv["exe"]
	comm := filepath.Base(exe)
	if comm == "." || comm == "/" || comm == "" {
		comm = "unknown"
	}
	if comm == "unknown" {
		for _, line := range lines {
			if strings.Contains(line, "type=EXECVE") {
				execKV := parseAuditKV(line)
				if a0 := execKV["a0"]; a0 != "" {
					comm = filepath.Base(a0)
					break
				}
			}
		}
	}
	tsNS := int64(0)
	if match := auditTime.FindStringSubmatch(syscallLine); len(match) == 3 {
		if seconds, err := strconv.ParseFloat(match[1], 64); err == nil {
			tsNS = int64(seconds * 1e9)
		}
	}
	serial := ""
	if match := auditSerial.FindStringSubmatch(syscallLine); len(match) == 2 {
		serial = match[1]
	}
	eventID := fmt.Sprintf("audit-%s", serial)
	if serial == "" {
		eventID = fmt.Sprintf("audit-%d-%d", pid, time.Now().UnixNano())
	}
	event := map[string]any{
		"schema_version": 2,
		"event_id":       eventID,
		"pid":            pid,
		"ppid":           ppid,
		"uid":            uid,
		"comm":           comm,
		"filename":       exe,
		"event_type":     "PROCESS_CREATED",
		"provenance":     "auditd",
		"quality":        "full",
	}
	if tsNS > 0 {
		event["ts_wall_ns"] = tsNS
	}
	return event, nil
}

func parseAuditKV(line string) map[string]string {
	out := make(map[string]string)
	for _, match := range auditKV.FindAllStringSubmatch(line, -1) {
		if len(match) >= 3 {
			out[match[1]] = strings.Trim(match[2], `"`)
		}
	}
	return out
}

type AuditdTailer struct {
	Path   string
	offset int64
}

func NewAuditdTailer(path string) *AuditdTailer {
	return &AuditdTailer{Path: path}
}

// Poll reads at most 1 MiB and returns only successful exec records. It
// tolerates rotation by restarting from the beginning.
func (t *AuditdTailer) Poll() []map[string]any {
	events := make([]map[string]any, 0)
	file, err := os.Open(t.Path)
	if err != nil {
		t.offset = 0
		return events
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return events
	}
	if info.Size() < t.offset {
		t.offset = 0
	}
	if _, err := file.Seek(t.offset, 0); err != nil {
		t.offset = 0
		return events
	}
	buffer := make([]byte, 1<<20)
	n, _ := file.Read(buffer)
	t.offset += int64(n)
	chunk := string(buffer[:n])
	records := groupAuditRecords(strings.Split(chunk, "\n"))
	for _, record := range records {
		event, err := ParseAuditRecord(record)
		if err == nil && event != nil {
			events = append(events, event)
		}
	}
	return events
}

func groupAuditRecords(lines []string) [][]string {
	groups := make(map[string][]string)
	order := make([]string, 0)
	for _, line := range lines {
		if !strings.HasPrefix(line, "type=") {
			continue
		}
		serial := ""
		if match := auditSerial.FindStringSubmatch(line); len(match) == 2 {
			serial = match[1]
		}
		if serial == "" {
			continue
		}
		if _, ok := groups[serial]; !ok {
			order = append(order, serial)
		}
		groups[serial] = append(groups[serial], line)
	}
	records := make([][]string, 0, len(order))
	for _, serial := range order {
		records = append(records, groups[serial])
	}
	return records
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

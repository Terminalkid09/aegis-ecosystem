package kernel

import (
	"strings"
	"testing"
	"time"
)

func TestSensorModeAndKernelVersion(t *testing.T) {
	if SensorMode("Linux", true, false) != Full || SensorMode("linux", false, true) != Partial || SensorMode("windows", true, true) != Unavailable {
		t.Fatal("matrice sensor mode errata")
	}
	if !KernelSupportsEBPF("5.15.0-1-amd64") || KernelSupportsEBPF("4.19.0") {
		t.Fatal("versione kernel errata")
	}
	if ParseKernelRelease("6.8.0-arch1")[0] != 6 {
		t.Fatal("parse release errato")
	}
	if !HasEBPFCaps(CAPSysAdmin) || !HasEBPFCaps(CAPBPF|CAPPerfMon) || HasEBPFCaps(CAPBPF) {
		t.Fatal("capability eBPF errate")
	}
	if ParseCapEff("Name:\tx\nCapEff:\t0000000000200000\n") != CAPSysAdmin {
		t.Fatal("CapEff errato")
	}
}

func TestParseAuditExec(t *testing.T) {
	lines := []string{
		`type=SYSCALL msg=audit(1710000000.123:42): arch=c000003e syscall=59 success=yes exit=0 a0="ls" pid=1234 ppid=100 uid=1000 auid=1000 exe="/usr/bin/ls"`,
		`type=EXECVE msg=audit(1710000000.123:42): argc=1 a0="ls"`,
	}
	event, err := ParseAuditRecord(lines)
	if err != nil || event == nil {
		t.Fatalf("evento=%v err=%v", event, err)
	}
	if event["comm"] != "ls" || event["event_id"] != "audit-1710000000.123:42" || event["provenance"] != "auditd" {
		t.Fatalf("evento inatteso: %#v", event)
	}
	if event["ppid"] != 100 || event["pid"] != 1234 {
		t.Fatalf("pid inattesi: %#v", event)
	}
}

func TestParseAuditIgnoresNonExec(t *testing.T) {
	event, err := ParseAuditRecord([]string{`type=SYSCALL msg=audit(1.2:3): syscall=257 success=yes pid=1 ppid=0 exe="/bin/cat"`})
	if err != nil || event != nil {
		t.Fatalf("evento=%v err=%v", event, err)
	}
	event, _ = ParseAuditRecord([]string{`type=SYSCALL msg=audit(1.2:3): syscall=59 success=no pid=1`})
	if event != nil {
		t.Fatal("exec fallita accettata")
	}
}

func TestParseEBPFAndStableID(t *testing.T) {
	line := `{"schema_version":2,"event_type":"PROCESS_CREATED","pid":12,"ppid":1,"comm":"curl","filename":"/usr/bin/curl","ts_ns":99,"boot_id":"boot-a"}`
	event, err := ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	id1 := StableEventID(event, "dev-1")
	id2 := StableEventID(event, "dev-1")
	if id1 == "" || id1 != id2 {
		t.Fatal("event_id non stabile")
	}
	if StableEventID(event, "dev-2") == id1 {
		t.Fatal("device diverso non cambia event_id")
	}
	report := EventToReport(event, "dev-1", "host", "10.0.0.1", "4.3.0", "ebpf")
	if report["agent_id"] != "dev-1" || report["process_name"] != "curl" || report["parent_pid"] != 1 {
		t.Fatalf("report inatteso: %#v", report)
	}
	if _, err := ParseLine(`{"event_type":"PROCESS_CREATED","pid":0}`); err == nil {
		t.Fatal("pid 0 accettato")
	}
	if _, err := ParseLine(`{"event_type":"UNKNOWN","pid":1}`); err == nil {
		t.Fatal("tipo sconosciuto accettato")
	}
}

func TestBatcherAndSeenCache(t *testing.T) {
	b := NewBatcher(2, time.Second, 10)
	now := time.Now()
	if b.Add(map[string]any{"n": 1}, now) {
		t.Fatal("batch troppo presto")
	}
	if !b.Add(map[string]any{"n": 2}, now) {
		t.Fatal("batch non dovuto")
	}
	if got := b.Drain(); len(got) != 2 {
		t.Fatalf("drain=%d", len(got))
	}
	old := NewBatcher(10, 100*time.Millisecond, 10)
	if old.Add(map[string]any{"n": 1}, now) || !old.Due(now.Add(101*time.Millisecond)) {
		t.Fatal("scadenza batch errata")
	}

	event := map[string]any{"event_type": "PROCESS_CREATED", "pid": 1, "comm": "x", "ts_ns": 5}
	cache := NewSeenCache(time.Second, 10)
	if cache.Check(event, now) {
		t.Fatal("primo evento duplicato")
	}
	if !cache.Check(event, now.Add(100*time.Millisecond)) {
		t.Fatal("duplicato non rilevato")
	}
	if cache.Check(event, now.Add(2*time.Second)) {
		t.Fatal("evento fuori finestra ancora duplicato")
	}
}

func TestCollectorCommandExcludesSelf(t *testing.T) {
	args := CollectorCommand("/usr/local/bin/aegis-ebpf", "/usr/local/bin/aegis-ebpf.o", 77)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--exclude-pid 77") || !strings.Contains(joined, "--obj") {
		t.Fatalf("args = %v", args)
	}
}

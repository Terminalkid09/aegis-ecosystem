package etw

import "testing"

func TestParseETWLine(t *testing.T) {
	line := `{"pid":42,"ppid":1,"comm":"cmd.exe","event_type":"PROCESS_CREATED","event_id":"e-1","boot_id":"b-1","seq":7,"proc_start_ns":99,"remote":"1.2.3.4:443"}`
	ev, ok := ParseLine("agent-1", "Windows", "4.3.0", line)
	if !ok {
		t.Fatal("valid line rejected")
	}
	if ev.PID != 42 || ev.EventType != "PROCESS_CREATED" || ev.BootID != "b-1" || ev.Seq == nil || *ev.Seq != 7 {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Provenance != "" || ev.SchemaVersion != 2 {
		t.Fatalf("provenance/schema = %q/%d", ev.Provenance, ev.SchemaVersion)
	}
}

func TestParseETWRejectsOrphanSequenceAndGarbage(t *testing.T) {
	for _, line := range []string{
		`{"pid":1,"event_type":"PROCESS_CREATED","seq":2}`,
		`{"pid":0,"event_type":"PROCESS_CREATED"}`,
		`{"event_type":"PROCESS_CREATED"}`,
		`not-json`,
	} {
		if _, ok := ParseLine("a", "Windows", "4", line); ok {
			t.Fatalf("accepted %s", line)
		}
	}
}

func TestParseETWProcessStopLine(t *testing.T) {
	// ProcessStop v0 carries ImageName as ANSI; the C producer decodes it to
	// UTF-16 before JSON. This is the exact line emitted after the fix.
	line := `{"ts_ns":1,"ts_wall_ns":2,"pid":42,"ppid":0,"uid":0,` +
		`"comm":"cmd.exe","filename":"C:\\Windows\\System32\\cmd.exe",` +
		`"event_type":"PROCESS_EXITED","exit_code":0}`
	ev, ok := ParseLine("agent-1", "Windows", "4.3.0", line)
	if !ok || ev.EventType != "PROCESS_EXITED" || ev.ProcessName != "cmd.exe" {
		t.Fatalf("process stop not parsed: ok=%v ev=%+v", ok, ev)
	}
}

func TestParseETWWindowsPathAndConnectAttemptQuality(t *testing.T) {
	// The producer used to print C:\\Windows\\... unescaped, so json.Unmarshal
	// dropped every process event. This is the exact wire shape it now emits.
	line := `{"ts_ns":1,"ts_wall_ns":2,"pid":42,"ppid":1,"uid":0,` +
		`"comm":"cmd.exe","filename":"C:\\Windows\\System32\\cmd.exe",` +
		`"event_type":"PROCESS_CREATED"}`
	ev, ok := ParseLine("agent-1", "Windows", "4.3.0", line)
	if !ok {
		t.Fatal("escaped Windows path rejected")
	}
	if ev.ProcessPath != `C:\Windows\System32\cmd.exe` || ev.ProcessName != "cmd.exe" {
		t.Fatalf("path/name = %q/%q", ev.ProcessPath, ev.ProcessName)
	}

	netLine := `{"pid":42,"comm":"","filename":"",` +
		`"event_type":"CONNECTION_ESTABLISHED",` +
		`"quality":"degraded:etw-connect-attempt","remote":"1.2.3.4:443"}`
	net, ok := ParseLine("agent-1", "Windows", "4.3.0", netLine)
	if !ok || net.Quality != "degraded:etw-connect-attempt" {
		t.Fatalf("network quality not preserved: %+v", net)
	}
}

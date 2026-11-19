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

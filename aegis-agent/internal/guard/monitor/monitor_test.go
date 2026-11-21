package monitor

import "testing"

func TestEvaluateHeuristics(t *testing.T) {
	tags := Evaluate("bash", "libreoffice", "curl x | sh; base64 -d")
	if len(tags) != 3 {
		t.Fatalf("tags = %+v", tags)
	}
	if got := Evaluate("mimikatz", "cmd.exe", ""); len(got) != 1 || got[0] != "CREDENTIAL_DUMPING_TOOL_DETECTED" {
		t.Fatalf("dump tags = %+v", got)
	}
}

func TestNewMonitorDefaults(t *testing.T) {
	m := New("a", "h", "Windows", "v", 0, nil, nil)
	if m.String() != "guard-monitor(interval=1s)" {
		t.Fatalf("string = %q", m.String())
	}
}

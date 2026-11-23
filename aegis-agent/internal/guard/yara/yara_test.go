package yara

import "testing"

func TestParsePreservesPathsWithSpaces(t *testing.T) {
	matches := Parse([]string{"rule_one C:\\Program Files\\evil.exe", "rule_two /tmp/a b", "bad"})
	if len(matches) != 2 {
		t.Fatalf("matches = %+v", matches)
	}
	if matches[0].Rule != "rule_one" || matches[0].FilePath != `C:\Program Files\evil.exe` {
		t.Fatalf("match0 = %+v", matches[0])
	}
}

func TestMissingBinaryFailsClosed(t *testing.T) {
	s := New("/definitely/not/yara")
	if s.Available() {
		t.Fatal("missing binary reported available")
	}
	if _, err := s.Scan(nil, "rule {}", []string{"x"}); err == nil {
		t.Fatal("missing binary scan succeeded")
	}
}

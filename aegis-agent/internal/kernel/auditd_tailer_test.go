package kernel

import (
	"os"
	"sort"
	"strings"
	"testing"
)

func TestAuditdTailerInterleaved(t *testing.T) {
	execA := []string{
		`type=SYSCALL msg=audit(1700000000.123:456): syscall=59 success=yes pid=101 ppid=100 uid=1000 exe="/bin/bash"`,
		`type=EXECVE msg=audit(1700000000.123:456): argc=1 a0="bash"`,
	}
	execB := []string{
		`type=SYSCALL msg=audit(1700000000.124:457): syscall=59 success=yes pid=103 ppid=100 uid=0 exe="/usr/bin/evil"`,
		`type=EXECVE msg=audit(1700000000.124:457): argc=1 a0="evil"`,
	}
	blob := strings.Join([]string{execA[0], execB[0], execA[1], execB[1]}, "\n") + "\n"
	file, err := os.CreateTemp(t.TempDir(), "audit-*.log")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(blob); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	events := NewAuditdTailer(file.Name()).Poll()
	if len(events) != 2 {
		t.Fatalf("eventi = %d: %#v", len(events), events)
	}
	comms := []string{events[0]["comm"].(string), events[1]["comm"].(string)}
	sort.Strings(comms)
	if comms[0] != "bash" || comms[1] != "evil" {
		t.Fatalf("comms = %v", comms)
	}
}

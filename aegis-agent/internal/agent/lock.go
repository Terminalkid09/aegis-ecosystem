package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

type PIDLock struct {
	path string
}

// AcquirePID is deliberately fail-closed: a stale file requires manual
// removal, matching the visible NodeTrace behavior for an already-running
// agent. It is not a security boundary.
func AcquirePID(path string) (*PIDLock, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("pid file mancante")
	}
	if data, err := os.ReadFile(path); err == nil {
		pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
		if pid > 0 && processAlive(pid) && isOurAgent(pid) {
			return nil, fmt.Errorf("agente già in esecuzione (pid %d)", pid)
		}
		_ = os.Remove(path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	_, writeErr := fmt.Fprintf(file, "%d\n", os.Getpid())
	closeErr := file.Close()
	if writeErr != nil {
		return nil, writeErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return &PIDLock{path: path}, nil
}

func (l *PIDLock) Release() {
	if l != nil && l.path != "" {
		_ = os.Remove(l.path)
	}
}

func isOurAgent(pid int) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	cmdline := strings.ToLower(string(data))
	return strings.Contains(cmdline, "aegis-agent") || strings.Contains(cmdline, "nodetrace")
}

func processAlive(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Signal 0 is a portable-enough existence probe on Unix; on Windows
	// FindProcess itself is the check and Signal returns an error we treat as
	// not-alive only when the process is genuinely gone.
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

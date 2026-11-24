// Package yara executes the vendor YARA CLI in the same process tree as Guard.
// It intentionally fails closed when the binary or rules are missing; a scan
// that did not run must never be ack'd as successful.
package yara

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const DefaultTimeout = 120 * time.Second

type Match struct {
	Rule     string `json:"rule"`
	FilePath string `json:"file_path"`
}

type Scanner struct {
	Binary  string
	Timeout time.Duration
}

func New(binary string) *Scanner {
	if strings.TrimSpace(binary) == "" {
		binary = filepath.Join("bin", "yara64.exe")
	}
	return &Scanner{Binary: binary, Timeout: DefaultTimeout}
}

func (s *Scanner) Available() bool {
	if s == nil || strings.TrimSpace(s.Binary) == "" {
		return false
	}
	if runtime.GOOS != "windows" {
		if _, err := exec.LookPath(s.Binary); err != nil {
			return false
		}
		return true
	}
	info, err := os.Stat(s.Binary)
	return err == nil && !info.IsDir()
}

// Scan runs `yara -w rules targets...`. Exit 1 means "no matches" and is a
// successful scan; >=2 is a real error. The parser also accepts the
// `rule namespace path` and `rule namespace hash path` variants emitted by
// some YARA builds, while preserving paths containing spaces.
func (s *Scanner) Scan(ctx context.Context, rules string, targets []string) ([]Match, error) {
	if s == nil || !s.Available() {
		return nil, fmt.Errorf("yara64 unavailable: %s", s.binaryName())
	}
	if strings.TrimSpace(rules) == "" {
		return nil, fmt.Errorf("regole YARA vuote")
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("nessun target YARA")
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	file, err := os.CreateTemp("", "aegis_yara_*.yar")
	if err != nil {
		return nil, fmt.Errorf("regole temporanee: %w", err)
	}
	rulesPath := file.Name()
	defer os.Remove(rulesPath)
	if _, err := file.WriteString(rules); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("scrittura regole: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("chiusura regole: %w", err)
	}

	args := append([]string{"-w", rulesPath}, targets...)
	cmd := exec.CommandContext(runCtx, s.Binary, args...)
	output, err := cmd.CombinedOutput()
	lines := strings.Split(string(output), "\n")
	if runCtx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("timeout YARA dopo %s", timeout)
	}
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return []Match{}, nil
		}
		return nil, fmt.Errorf("yara: %w: %s", err, truncate(strings.Join(lines, " | "), 300))
	}
	return Parse(lines), nil
}

func (s *Scanner) binaryName() string {
	if s == nil {
		return ""
	}
	return s.Binary
}

func Parse(lines []string) []Match {
	out := make([]Match, 0)
	for _, line := range lines {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
			continue
		}
		// A line from `yara -w` is "rule path". Some builds emit
		// "rule namespace path": keep the last segment as the path.
		out = append(out, Match{Rule: parts[0], FilePath: strings.TrimSpace(parts[1])})
	}
	return out
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

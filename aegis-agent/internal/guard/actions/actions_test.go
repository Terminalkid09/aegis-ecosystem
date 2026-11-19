package actions

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/guard/commands"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/guard/fim"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/transport"
)

type fakeRunner struct {
	calls [][]string
	out   string
	err   error
}

func (f *fakeRunner) Output(ctx context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return f.out, f.err
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) error {
	f.calls = append(f.calls, append([]string{name}, args...))
	return f.err
}

func newTestExecutor(t *testing.T, runner *fakeRunner) *Executor {
	t.Helper()
	exec := New("agent", "https://brain.local/api/v1", t.TempDir(), nil, nil, nil)
	exec.Runner = runner
	return exec
}

func TestInvalidIPAndBrainRefusal(t *testing.T) {
	exec := newTestExecutor(t, &fakeRunner{})
	for _, ip := range []string{"any", "1.2.3.4/24", "brain.local"} {
		if _, err := exec.Execute(context.Background(), transport.Command{Command: commands.BlockIP, IP: ip}); err == nil {
			t.Fatalf("IP %q accettato", ip)
		}
	}
	if _, err := exec.Execute(context.Background(), transport.Command{Command: commands.BlockIP, IP: "127.0.0.1"}); err != nil {
		t.Fatalf("IP valido rifiutato: %v", err)
	}
}

func TestDNSAndIsolationUseRunnerWithoutShell(t *testing.T) {
	hosts := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(hosts, []byte("127.0.0.1 localhost\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	exec := newTestExecutor(t, runner)
	exec.HostsFile = hosts
	result, err := exec.Execute(context.Background(), transport.Command{Command: commands.DNSSinkhole, Domain: "evil.example"})
	if err != nil || !strings.Contains(result.Details, "0.0.0.0") {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	data, _ := os.ReadFile(hosts)
	if !strings.Contains(string(data), "0.0.0.0 evil.example") {
		t.Fatalf("hosts = %s", data)
	}
	if _, err := exec.Execute(context.Background(), transport.Command{Command: commands.DNSSinkhole, Domain: "bad\n0.0.0.0 x"}); err == nil {
		t.Fatal("domain injection accepted")
	}

	exec.HostsFile = hosts
	if _, err := exec.Execute(context.Background(), transport.Command{Command: commands.IsolateHost}); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) < 2 {
		t.Fatalf("calls = %+v", runner.calls)
	}
	if runtime.GOOS == "windows" && !strings.Contains(strings.Join(runner.calls[0], " "), "netsh") {
		t.Fatalf("calls = %+v", runner.calls)
	}
}

func TestFIMCommandRequiresMonitor(t *testing.T) {
	exec := newTestExecutor(t, &fakeRunner{})
	if _, err := exec.Execute(context.Background(), transport.Command{Command: commands.FIMSetWatch}); err == nil {
		t.Fatal("FIM senza monitor accettato")
	}
	dir := t.TempDir()
	monitor, err := fim.New("agent", "Linux", "4", "host", nil, nil)
	if err != nil {
		t.Skip(err)
	}
	defer monitor.Close()
	exec.FIM = monitor
	if _, err := exec.Execute(context.Background(), transport.Command{Command: commands.FIMSetWatch, Paths: []string{dir}}); err != nil {
		t.Fatal(err)
	}
}

func TestFIMWatchAndVerifyHaveRealAckDetails(t *testing.T) {
	exec := newTestExecutor(t, &fakeRunner{})
	dir := t.TempDir()
	monitor, err := fim.New("agent", runtime.GOOS, "4", "host", nil, nil)
	if err != nil {
		t.Skip(err)
	}
	defer monitor.Close()
	exec.FIM = monitor
	result, err := exec.Execute(context.Background(), transport.Command{Command: commands.FIMSetWatch, Paths: []string{dir}})
	if err != nil || !strings.Contains(result.Details, "FIM attivo") {
		t.Fatalf("FIM result=%+v err=%v", result, err)
	}
}

func TestVerifyMissingPIDFails(t *testing.T) {
	exec := newTestExecutor(t, &fakeRunner{})
	if _, err := exec.Execute(context.Background(), transport.Command{Command: commands.Verify}); err == nil {
		t.Fatal("VERIFY senza PID accettato")
	}
}

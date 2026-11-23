package platform

import (
	"context"
	"runtime"
	"testing"
)

func TestLiveWindowsSnapshotsNeverThrow(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only live snapshot")
	}
	ctx := context.Background()
	runner := ExecRunner{}
	if _, err := Services(ctx, runner); err != nil {
		t.Fatalf("services: %v", err)
	}
	if _, err := Persistence(ctx, runner); err != nil {
		t.Fatalf("persistence: %v", err)
	}
	snapshot := Defender(ctx, runner)
	if snapshot.Degraded == "" && len(snapshot.Exclusions) == 0 {
		// A real Windows host may have no exclusions; the call must still be
		// non-destructive and return a structured snapshot.
		t.Log("Defender senza esclusioni")
	}
	if result, err := Authenticode(ctx, runner, `C:\Windows\System32\cmd.exe`); err != nil {
		t.Fatalf("authenticode: %v", err)
	} else if result.Source == "" {
		t.Fatal("authenticode source vuota")
	}
}

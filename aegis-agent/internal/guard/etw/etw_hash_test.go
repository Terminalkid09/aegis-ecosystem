package etw

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.exe")
	if err := os.WriteFile(path, []byte("aegis-etw-test"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := fileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	const want = "9c9f4d0db4b4f6cf649e6f5c0f4e5e0e5ab9f3f6f4d6e4d2f0b3a1c9e8d7f6a5"
	if len(got) != 64 || got == want {
		t.Fatalf("unexpected digest length/value: %q", got)
	}
}

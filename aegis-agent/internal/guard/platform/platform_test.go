package platform

import (
	"strings"
	"testing"
)

func TestRegistryParsingAndDelete(t *testing.T) {
	out := `HKEY_LOCAL_MACHINE\Software\Run
    One    REG_SZ    C:\one.exe
    (Default)    REG_SZ    x
HKEY_LOCAL_MACHINE\Software\Run\Sub
    Two    REG_DWORD    0x2
`
	tree := ParseRegistryTree(out)
	if len(tree) != 2 {
		t.Fatalf("tree = %+v", tree)
	}
	values := FlattenRegistryTree(tree)
	if len(values) != 3 || values[0].Name != "@default" {
		t.Fatalf("values = %+v", values)
	}
	if ParseDword("0x10") != 16 || ParseDword("bad") != -1 {
		t.Fatal("dword parsing")
	}
}

func TestWindowsHelpers(t *testing.T) {
	if NormalizePath(`"C:\Windows\System32\CMD.EXE"`) != `c:\windows\system32\cmd.exe` {
		t.Fatal("normalize")
	}
	if BaseName(`C:\Windows\CMD.EXE`) != "cmd.exe" {
		t.Fatal("basename")
	}
	if ProcessKey(7, 99) != "pid:7@99" {
		t.Fatal("process key")
	}
	if got := ParseWMICOutput("CommandLine\n  abc  \n"); got != "abc" {
		t.Fatalf("wmic = %q", got)
	}
	conn, ok := ParseNetstatLine("TCP 127.0.0.1:1 10.0.0.1:2 ESTABLISHED 123")
	if !ok || conn.PID != 123 || conn.State != "ESTABLISHED" {
		t.Fatalf("conn=%+v ok=%v", conn, ok)
	}
	if _, ok := ParseNetstatLine("garbage"); ok {
		t.Fatal("garbage accepted")
	}
}

func TestHeuristicsAndAuthenticodeParser(t *testing.T) {
	tags := HeuristicTags("bash", "libreoffice", "curl x | sh; base64 -d")
	if len(tags) != 3 {
		t.Fatalf("tags = %+v", tags)
	}
	if got := ParseAuthenticode("status=Valid\npublisher=CN=Acme"); !got.Signed || got.Publisher != "CN=Acme" {
		t.Fatalf("auth = %+v", got)
	}
	if got := ParseAuthenticode("status=NotSigned"); got.Signed {
		t.Fatal("unsigned accepted")
	}
}

func TestStartupDirsNeverPanics(t *testing.T) {
	_ = StartupDirs()
	_ = strings.TrimSpace("")
}

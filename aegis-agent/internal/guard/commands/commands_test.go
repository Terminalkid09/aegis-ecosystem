package commands

import (
	"strings"
	"testing"
)

func TestIPLiteralValidation(t *testing.T) {
	for _, value := range []string{"10.0.0.1", "203.0.113.255", "0.0.0.0", " 8.8.8.8 ", "::1", "2001:db8::1"} {
		if !IsIPLiteral(value) {
			t.Errorf("IP valido rifiutato: %q", value)
		}
	}
	for _, value := range []string{"any", "all", "", "10.0.0", "10.0.0.256", "10.0.0.1/24", "10.0.0.1 -j ACCEPT", "10.0.0.1; rm -rf /", "999.999.999.999"} {
		if IsIPLiteral(value) {
			t.Errorf("IP non valido accettato: %q", value)
		}
	}
}

func TestDomainValidation(t *testing.T) {
	for _, value := range []string{"evil.example.com", "sub-domain.example.co.uk", "EXAMPLE.com"} {
		if !IsDomainName(value) {
			t.Errorf("dominio valido rifiutato: %q", value)
		}
	}
	for _, value := range []string{"", "evil.com\n0.0.0.0 mybank.com", "evil.com#comment", "single", ".example.com", "example..com", "http://example.com"} {
		if IsDomainName(value) {
			t.Errorf("dominio non valido accettato: %q", value)
		}
	}
}

func TestRegistryValuesAndDelete(t *testing.T) {
	output := "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\r\n" +
		"    Updater    REG_SZ    C:\\Temp\\evil.exe --run\r\n" +
		"    (Default)    REG_SZ    C:\\Legit\\app.exe\r\n" +
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Sub\r\n" +
		"    Other    REG_SZ    C:\\Temp\\other.exe\r\n"
	values := ParseRegistryValues(output)
	if len(values) != 3 || values[0].Name != "Updater" || values[0].Data != `C:\Temp\evil.exe --run` || values[2].Name != "Other" {
		t.Fatalf("registry = %#v", values)
	}
	command := RegistryDeleteCommand("HKLM\\Run", "Updater")
	if len(command) != 6 || command[3] != "/v" || command[4] != "Updater" {
		t.Fatalf("delete = %#v", command)
	}
}

func TestIsolationCommands(t *testing.T) {
	if got := ExtractBrainHost("https://aegis.local:8443/api/v1"); got != "aegis.local" {
		t.Fatalf("brain host = %q", got)
	}
	if got := ExtractBrainHost("http://brain.example.com:8000/api/v1"); got != "brain.example.com" {
		t.Fatalf("brain host = %q", got)
	}
	for _, windows := range []bool{false, true} {
		isolate := IsolateCommands("10.0.0.5", windows)
		if len(isolate) == 0 {
			t.Fatalf("isolate vuoto windows=%v", windows)
		}
		joined := ""
		for _, command := range isolate {
			joined += " " + strings.Join(command, " ")
		}
		if !strings.Contains(joined, "10.0.0.5") {
			t.Fatalf("allowlist brain assente: %s", joined)
		}
		if !strings.Contains(strings.ToLower(joined), "block") && !strings.Contains(strings.ToLower(joined), "drop") {
			t.Fatalf("blocco assente: %s", joined)
		}
		restore := RestoreCommands("10.0.0.5", windows)
		if len(restore) == 0 {
			t.Fatalf("restore vuoto windows=%v", windows)
		}
	}
}

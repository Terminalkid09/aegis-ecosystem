package identity

import (
	"os"
	"strings"
)

// MachineID is best-effort and deliberately returns an empty string when no
// stable platform identifier is readable. It is not a proof of possession.
func MachineID() string {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if value := strings.TrimSpace(string(data)); value != "" {
			return value
		}
	}
	return ""
}

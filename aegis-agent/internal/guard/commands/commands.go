package commands

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

const (
	KillProcess       = "KILL_PROCESS"
	KillProcessTree   = "KILL_PROCESS_TREE"
	BlockIP           = "BLOCK_IP"
	BlockIPTemporal   = "BLOCK_IP_TEMPORAL"
	QuarantineBinary  = "QUARANTINE_BINARY"
	RemovePersistence = "REMOVE_PERSISTENCE"
	DNSSinkhole       = "DNS_SINKHOLE"
	CollectIOC        = "COLLECT_IOC"
	Verify            = "VERIFY"
	IsolateHost       = "ISOLATE_HOST"
	DeisolateHost     = "DEISOLATE_HOST"
	UpdateAgent       = "UPDATE_AGENT"
	FIMSetWatch       = "FIM_SET_WATCH"
	YaraScan          = "YARA_SCAN"
)

var Supported = map[string]bool{
	KillProcess: true, KillProcessTree: true, BlockIP: true, BlockIPTemporal: true,
	QuarantineBinary: true, RemovePersistence: true, DNSSinkhole: true, CollectIOC: true,
	Verify: true, IsolateHost: true, DeisolateHost: true, UpdateAgent: true,
	FIMSetWatch: true, YaraScan: true,
}

// IsIPLiteral rejects CIDR, hostnames and shell fragments; only a parsed
// IPv4/IPv6 literal may reach netsh/iptables.
func IsIPLiteral(value string) bool {
	candidate := strings.TrimSpace(value)
	if candidate == "" || len(candidate) > 45 || strings.ContainsAny(candidate, " /;|\t\r\n") {
		return false
	}
	return net.ParseIP(candidate) != nil
}

var domainPattern = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func IsDomainName(value string) bool {
	candidate := strings.TrimSpace(value)
	if candidate == "" || len(candidate) > 253 || strings.ContainsAny(candidate, " /:#\t\r\n") {
		return false
	}
	if !domainPattern.MatchString(candidate) {
		return false
	}
	labels := strings.Split(candidate, ".")
	return len(labels) >= 2 && len(labels[len(labels)-1]) >= 2
}

// ExtractBrainHost mirrors Guard isolation: never trust an empty host to
// become "allow everything"; an empty result means isolate everything.
func ExtractBrainHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	fallback := raw
	if idx := strings.Index(fallback, "://"); idx >= 0 {
		fallback = fallback[idx+3:]
	}
	if cut := strings.IndexAny(fallback, "/:?#"); cut >= 0 {
		fallback = fallback[:cut]
	}
	return strings.TrimSpace(fallback)
}

func IsolateCommands(brainHost string, windows bool) [][]string {
	brainHost = strings.TrimSpace(brainHost)
	out := make([][]string, 0, 4)
	if windows {
		if brainHost != "" {
			out = append(out, []string{"netsh", "advfirewall", "firewall", "add", "rule",
				"name=Aegis_Isolate_Allow_Brain", "dir=out", "action=allow", "remoteip=" + brainHost})
		}
		out = append(out, []string{"netsh", "advfirewall", "firewall", "add", "rule",
			"name=Aegis_Isolate_Block_All", "dir=out", "action=block", "remoteip=any"})
		return out
	}
	out = append(out,
		[]string{"iptables", "-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"},
		[]string{"iptables", "-I", "OUTPUT", "1", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	)
	if brainHost != "" {
		out = append(out, []string{"iptables", "-I", "OUTPUT", "1", "-d", brainHost, "-j", "ACCEPT"})
	}
	out = append(out, []string{"iptables", "-A", "OUTPUT", "-j", "DROP"})
	return out
}

func RestoreCommands(brainHost string, windows bool) [][]string {
	brainHost = strings.TrimSpace(brainHost)
	if windows {
		out := [][]string{{"netsh", "advfirewall", "firewall", "delete", "rule", "name=Aegis_Isolate_Block_All"}}
		if brainHost != "" {
			out = append(out, []string{"netsh", "advfirewall", "firewall", "delete", "rule", "name=Aegis_Isolate_Allow_Brain"})
		}
		return out
	}
	out := [][]string{{"iptables", "-D", "OUTPUT", "-j", "DROP"}}
	if brainHost != "" {
		out = append(out, []string{"iptables", "-D", "OUTPUT", "-d", brainHost, "-j", "ACCEPT"})
	}
	return append(out,
		[]string{"iptables", "-D", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		[]string{"iptables", "-D", "OUTPUT", "-o", "lo", "-j", "ACCEPT"})
}

type RegistryValue struct {
	Key  string
	Name string
	Data string
}

var registryLine = regexp.MustCompile(`^\s{4}(.+?)\s{4}REG_[A-Z0-9_]+\s{4}(.*)$`)

func ParseRegistryValues(output string) []RegistryValue {
	values := make([]RegistryValue, 0)
	currentKey := ""
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.HasPrefix(line, "HKEY_") {
			currentKey = strings.TrimSpace(line)
			continue
		}
		if currentKey == "" {
			continue
		}
		match := registryLine.FindStringSubmatch(line)
		if len(match) == 3 {
			values = append(values, RegistryValue{Key: currentKey, Name: strings.TrimSpace(match[1]), Data: match[2]})
		}
	}
	return values
}

func RegistryDeleteCommand(key, valueName string) []string {
	return []string{"reg", "delete", key, "/v", valueName, "/f"}
}

package networkscan

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Host struct {
	IPAddress string `json:"ip_address"`
	Hostname  string `json:"hostname,omitempty"`
	MAC       string `json:"mac_address,omitempty"`
	OpenPorts []int  `json:"open_ports"`
	OSGuess   string `json:"os_guess,omitempty"`
}

type Scanner struct {
	MaxPrefixLen int
	MaxPorts     int
	MinTimeout   time.Duration
	MaxTimeout   time.Duration
	PingWorkers  int
	TCPWorkers   int
}

func New() *Scanner {
	return &Scanner{
		MaxPrefixLen: 24,
		MaxPorts:     20,
		MinTimeout:   50 * time.Millisecond,
		MaxTimeout:   time.Second,
		PingWorkers:  64,
		TCPWorkers:   16,
	}
}

var DefaultPorts = []int{22, 80, 135, 139, 443, 445, 3389, 8000, 8080}

func (s *Scanner) Scan(ctx context.Context, cidr string, ports []int, probeTimeout time.Duration) ([]Host, error) {
	if s == nil {
		s = New()
	}
	if probeTimeout == 0 {
		probeTimeout = 200 * time.Millisecond
	}
	if probeTimeout < s.MinTimeout || probeTimeout > s.MaxTimeout {
		return nil, fmt.Errorf("probe_timeout fuori bound [%s,%s]", s.MinTimeout, s.MaxTimeout)
	}
	if ports == nil {
		ports = DefaultPorts
	}
	if len(ports) == 0 || len(ports) > s.MaxPorts {
		return nil, fmt.Errorf("ports fuori bound (1..%d)", s.MaxPorts)
	}
	seenPorts := make(map[int]struct{}, len(ports))
	cleanPorts := make([]int, 0, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("porta fuori range 1..65535: %d", port)
		}
		if _, ok := seenPorts[port]; ok {
			continue
		}
		seenPorts[port] = struct{}{}
		cleanPorts = append(cleanPorts, port)
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}
	if network.IP.To4() == nil {
		return nil, fmt.Errorf("solo IPv4 supportato")
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones < s.MaxPrefixLen {
		return nil, fmt.Errorf("cidr troppo grande (/%d): minimo /%d", ones, s.MaxPrefixLen)
	}

	ips := enumerate(network)
	live := make(chan string, len(ips))
	var pingWG sync.WaitGroup
	sem := make(chan struct{}, max(1, s.PingWorkers))
	for _, ip := range ips {
		pingWG.Add(1)
		go func(ip string) {
			defer pingWG.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			if ping(ctx, ip, probeTimeout) {
				live <- ip
			}
		}(ip)
	}
	pingWG.Wait()
	close(live)

	arp := arpTable(ctx)
	set := make(map[string]struct{})
	for ip := range live {
		set[ip] = struct{}{}
	}
	for ip := range arp {
		if network.Contains(net.ParseIP(ip)) {
			set[ip] = struct{}{}
		}
	}

	ordered := make([]string, 0, len(set))
	for ip := range set {
		ordered = append(ordered, ip)
	}
	sort.Strings(ordered)

	results := make([]Host, len(ordered))
	var tcpWG sync.WaitGroup
	tsem := make(chan struct{}, max(1, s.TCPWorkers))
	for i, ip := range ordered {
		tcpWG.Add(1)
		go func(index int, ip string) {
			defer tcpWG.Done()
			tsem <- struct{}{}
			defer func() { <-tsem }()
			results[index] = inspect(ctx, ip, cleanPorts, probeTimeout, arp[ip])
		}(i, ip)
	}
	tcpWG.Wait()
	return results, nil
}

func enumerate(network *net.IPNet) []string {
	first := network.IP.Mask(network.Mask).To4()
	if first == nil {
		return nil
	}
	ones, _ := network.Mask.Size()
	count := 1 << (32 - ones)
	if count > 1<<(32-24) {
		count = 1 << (32 - 24)
	}
	out := make([]string, 0, count)
	start := uint32(first[0])<<24 | uint32(first[1])<<16 | uint32(first[2])<<8 | uint32(first[3])
	for i := 0; i < count; i++ {
		if ones <= 30 && (i == 0 || i == count-1) {
			continue
		}
		value := start + uint32(i)
		ip := net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value)).String()
		if network.Contains(net.ParseIP(ip)) {
			out = append(out, ip)
		}
	}
	return out
}

func ping(ctx context.Context, ip string, timeout time.Duration) bool {
	var args []string
	if runtime.GOOS == "windows" {
		args = []string{"-n", "1", "-w", strconv.Itoa(int(timeout.Milliseconds())), ip}
	} else {
		args = []string{"-c", "1", "-W", strconv.Itoa(int(timeout.Seconds() + 0.999)), ip}
	}
	cmd := exec.CommandContext(ctx, "ping", args...)
	return cmd.Run() == nil
}

func inspect(ctx context.Context, ip string, ports []int, timeout time.Duration, mac string) Host {
	host := Host{IPAddress: ip, MAC: mac, OpenPorts: []int{}}
	for _, port := range ports {
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		if err == nil {
			_ = conn.Close()
			host.OpenPorts = append(host.OpenPorts, port)
		}
	}
	if names, err := net.DefaultResolver.LookupAddr(ctx, ip); err == nil && len(names) > 0 {
		host.Hostname = strings.TrimSuffix(names[0], ".")
	}
	switch {
	case contains(host.OpenPorts, 3389) || contains(host.OpenPorts, 445) || contains(host.OpenPorts, 135):
		host.OSGuess = "windows"
	case contains(host.OpenPorts, 22):
		host.OSGuess = "linux"
	case len(host.OpenPorts) > 0:
		host.OSGuess = "network-service"
	default:
		host.OSGuess = "unknown"
	}
	return host
}

func arpTable(ctx context.Context) map[string]string {
	out := make(map[string]string)
	cmd := exec.CommandContext(ctx, "arp", "-a")
	data, err := cmd.Output()
	if err != nil {
		return out
	}
	pattern := regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:-]{17})`)
	for _, match := range pattern.FindAllStringSubmatch(string(data), -1) {
		if net.ParseIP(match[1]) == nil {
			continue
		}
		mac := strings.ReplaceAll(match[2], "-", ":")
		if strings.Count(mac, ":") == 5 && mac != "00:00:00:00:00:00" {
			out[match[1]] = strings.ToUpper(mac)
		}
	}
	return out
}

func contains(values []int, target int) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

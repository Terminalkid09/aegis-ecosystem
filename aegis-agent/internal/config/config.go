package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Profile selects the capabilities of the single agent binary.
type Profile string

const (
	ProfileSensor   Profile = "sensor"
	ProfileEndpoint Profile = "endpoint"
	ProfileUnified  Profile = "unified"
	ProfileRouter   Profile = "router"

	DefaultVersion = "4.3.0"
)

func (p Profile) Valid() bool {
	switch p {
	case ProfileSensor, ProfileEndpoint, ProfileUnified, ProfileRouter:
		return true
	default:
		return false
	}
}

// Mode selects the capabilities of the single unified agent. The agent record
// stays unified in every mode: this is one binary and one enrollment, not a
// second agent type.
type Mode string

const (
	ModeFull     Mode = "full"
	ModeSensor   Mode = "sensor"
	ModeEndpoint Mode = "endpoint"
)

func (m Mode) Valid() bool {
	switch m {
	case ModeFull, ModeSensor, ModeEndpoint:
		return true
	default:
		return false
	}
}

func modeForProfile(p Profile) Mode {
	switch p {
	case ProfileSensor, ProfileRouter:
		return ModeSensor
	case ProfileEndpoint:
		return ModeEndpoint
	default:
		return ModeFull
	}
}

// fileConfig mirrors the legacy NodeTrace config.json. The new agent accepts
// it unchanged so a NodeTrace host can be migrated without rewriting config.
type fileConfig struct {
	ServerURL         string `json:"server_url"`
	DeviceName        string `json:"device_name"`
	RegisterURL       string `json:"register_url"`
	UpdateURL         string `json:"update_url"`
	HeartbeatURL      string `json:"heartbeat_url"`
	HeartbeatInterval int    `json:"heartbeat_interval"`
	TelemetryInterval int    `json:"telemetry_interval"`
	RetryMaxAttempts  int    `json:"retry_max_attempts"`
	RetryBaseDelay    int    `json:"retry_base_delay"`
	EBPFEnabled       bool   `json:"ebpf_enabled"`
	EBPFCollector     string `json:"ebpf_collector"`
	EBPFObj           string `json:"ebpf_obj"`
	AuditdEnabled     bool   `json:"auditd_enabled"`
	AuditLog          string `json:"audit_log"`
	Mode              string `json:"mode"`
}

// Options are explicit overrides from the command line. Environment variables
// are applied after the file, matching the legacy agent's precedence.
type Options struct {
	Profile    string
	Mode       string
	AgentHome  string
	ConfigFile string
	Version    string
}

// Config is the resolved runtime configuration.
type Config struct {
	Profile    Profile
	Mode       Mode
	Version    string
	AgentHome  string
	ConfigFile string

	DeviceName string

	ServerURL        string
	RegisterURL      string
	UpdateURL        string
	HeartbeatURL     string
	CommandsURL      string
	AckURL           string
	ReportURL        string
	ReportBatchURL   string
	CSRURL           string
	ScanResultURL    string
	GuardEnrollURL   string
	GuardCommandsURL string

	HeartbeatInterval time.Duration
	TelemetryInterval time.Duration
	RequestTimeout    time.Duration
	RetryMaxAttempts  int
	RetryBaseDelay    time.Duration

	CACertFile      string
	EnrollTokenFile string
	EnrollKey       string
	TokenFile       string
	SecretFile      string
	IdentityDir     string
	ManifestPubKey  string
	AuditLog        string

	EBPFEnabled   bool
	EBPFCollector string
	EBPFObj       string
	AuditdEnabled bool

	ScanInterval     time.Duration
	NetstatInterval  time.Duration
	ETWEnabled       bool
	ETWPath          string
	ETWAllowUnsigned bool
	ETWSHA256        string
	SpoolFile        string
	SpoolMaxBytes    int64
	QuarantineDir    string
	HostsFile        string
	YaraPath         string
}

// Load resolves configuration from defaults, the optional JSON file, the
// environment and finally command-line options.
func Load(opts Options) (Config, error) {
	home, err := resolveHome(opts.AgentHome)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		Profile:           ProfileSensor,
		Mode:              ModeSensor,
		Version:           DefaultVersion,
		AgentHome:         home,
		HeartbeatInterval: 10 * time.Second,
		TelemetryInterval: 10 * time.Second,
		RequestTimeout:    20 * time.Second,
		RetryMaxAttempts:  5,
		RetryBaseDelay:    time.Second,
		ScanInterval:      time.Second,
		NetstatInterval:   5 * time.Second,
		SpoolMaxBytes:     50 * 1024 * 1024,
	}

	if opts.Profile != "" {
		cfg.Profile = Profile(opts.Profile)
	} else if v := os.Getenv("AEGIS_AGENT_PROFILE"); v != "" {
		cfg.Profile = Profile(v)
	}
	if !cfg.Profile.Valid() {
		return Config{}, fmt.Errorf("profilo agente non valido: %q", cfg.Profile)
	}

	if opts.Version != "" {
		cfg.Version = opts.Version
	} else if v := firstEnv("AEGIS_AGENT_VERSION", "NODETRACE_VERSION"); v != "" {
		cfg.Version = v
	}

	cfg.ConfigFile = opts.ConfigFile
	if cfg.ConfigFile == "" {
		cfg.ConfigFile = os.Getenv("NODETRACE_CONFIG")
	}
	if cfg.ConfigFile == "" {
		cfg.ConfigFile = filepath.Join(home, "config.json")
	}
	cfg.ConfigFile = absPath(cfg.ConfigFile)

	var fc fileConfig
	if data, err := os.ReadFile(cfg.ConfigFile); err == nil {
		if err := json.Unmarshal(data, &fc); err != nil {
			return Config{}, fmt.Errorf("config %s non valida: %w", cfg.ConfigFile, err)
		}
	} else if !os.IsNotExist(err) {
		return Config{}, fmt.Errorf("config %s non leggibile: %w", cfg.ConfigFile, err)
	}

	cfg.ServerURL = fc.ServerURL
	cfg.DeviceName = fc.DeviceName
	cfg.RegisterURL = fc.RegisterURL
	cfg.UpdateURL = fc.UpdateURL
	cfg.HeartbeatURL = fc.HeartbeatURL
	if fc.HeartbeatInterval > 0 {
		cfg.HeartbeatInterval = time.Duration(fc.HeartbeatInterval) * time.Second
	}
	if fc.TelemetryInterval > 0 {
		cfg.TelemetryInterval = time.Duration(fc.TelemetryInterval) * time.Second
	}
	if fc.RetryMaxAttempts > 0 {
		cfg.RetryMaxAttempts = fc.RetryMaxAttempts
	}
	if fc.RetryBaseDelay > 0 {
		cfg.RetryBaseDelay = time.Duration(fc.RetryBaseDelay) * time.Second
	}
	cfg.EBPFEnabled = fc.EBPFEnabled
	cfg.EBPFCollector = fc.EBPFCollector
	cfg.EBPFObj = fc.EBPFObj
	cfg.AuditdEnabled = fc.AuditdEnabled
	cfg.AuditLog = fc.AuditLog

	applyEnv(&cfg)
	if err := resolveMode(&cfg, opts.Mode, fc.Mode); err != nil {
		return Config{}, err
	}

	if cfg.DeviceName == "" {
		if host, err := os.Hostname(); err == nil && strings.TrimSpace(host) != "" {
			cfg.DeviceName = host
		} else {
			cfg.DeviceName = "aegis-agent"
		}
	}
	if cfg.IdentityDir == "" {
		cfg.IdentityDir = home
	}
	if cfg.SpoolFile == "" {
		cfg.SpoolFile = filepath.Join(home, "spool", "events.spool")
	}
	if cfg.QuarantineDir == "" {
		cfg.QuarantineDir = filepath.Join(home, "quarantine")
	}
	if cfg.YaraPath == "" {
		cfg.YaraPath = filepath.Join(home, "bin", "yara64.exe")
	}
	if cfg.ETWPath == "" {
		cfg.ETWPath = filepath.Join(home, "bin", "aegis-etw.exe")
	}
	if cfg.HostsFile == "" {
		cfg.HostsFile = defaultHostsFile()
	}
	if cfg.TokenFile == "" {
		cfg.TokenFile = filepath.Join(cfg.IdentityDir, "token.json")
	}
	if cfg.SecretFile == "" {
		cfg.SecretFile = filepath.Join(cfg.IdentityDir, "secret.json")
	}
	if cfg.CACertFile != "" {
		cfg.CACertFile = absPath(cfg.CACertFile)
	}
	cfg.TokenFile = absPath(cfg.TokenFile)
	cfg.SecretFile = absPath(cfg.SecretFile)
	cfg.IdentityDir = absPath(cfg.IdentityDir)
	if err := cfg.ResolveGuardSecret(); err != nil {
		return Config{}, err
	}
	cfg.deriveURLs()

	return cfg, nil
}

// resolveMode applies the documented precedence: profile default, config file,
// environment, then the command line. It runs after all three sources are
// loaded so a valid CLI choice cannot be overwritten by config.json and an
// invalid env value cannot bypass validation.
func resolveMode(cfg *Config, cliMode, fileMode string) error {
	m := modeForProfile(cfg.Profile)
	if cfg.Profile == ProfileUnified {
		if fileMode != "" {
			m = Mode(fileMode)
		}
		if v := os.Getenv("AEGIS_AGENT_MODE"); v != "" {
			m = Mode(v)
		}
		if cliMode != "" {
			m = Mode(cliMode)
		}
	} else if cliMode != "" && Mode(cliMode) != m {
		return fmt.Errorf("modalità %q non valida per il profilo %q", cliMode, cfg.Profile)
	}
	if !m.Valid() {
		return fmt.Errorf("modalità agente non valida: %q", m)
	}
	cfg.Mode = m
	return nil
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("NODETRACE_DEVICE_NAME"); v != "" {
		cfg.DeviceName = v
	}
	if v := os.Getenv("NODETRACE_SERVER_URL"); v != "" {
		cfg.ServerURL = v
	}
	if v := os.Getenv("NODETRACE_REGISTER_URL"); v != "" {
		cfg.RegisterURL = v
	}
	if v := os.Getenv("NODETRACE_UPDATE_URL"); v != "" {
		cfg.UpdateURL = v
	}
	if v := os.Getenv("NODETRACE_HEARTBEAT_URL"); v != "" {
		cfg.HeartbeatURL = v
	}
	if v := os.Getenv("NODETRACE_TOKEN_FILE"); v != "" {
		cfg.TokenFile = v
	}
	if v := os.Getenv("NODETRACE_IDENTITY_DIR"); v != "" {
		cfg.IdentityDir = v
	}
	if v := os.Getenv("AEGIS_SECRET_FILE"); v != "" {
		cfg.SecretFile = v
	}
	if v := os.Getenv("AEGIS_BRAIN_URL"); v != "" && cfg.ServerURL == "" {
		cfg.ServerURL = v
	}
	if v := os.Getenv("AEGIS_GATEWAY_URL"); v != "" {
		cfg.ReportURL = v
	}
	if v := os.Getenv("AEGIS_IDENTITY_DIR"); v != "" {
		cfg.IdentityDir = v
	}
	if v := os.Getenv("AEGIS_AGENT_HOME"); v != "" && cfg.IdentityDir == "" {
		cfg.IdentityDir = v
	}
	if v := os.Getenv("AEGIS_CA_BUNDLE"); v != "" {
		cfg.CACertFile = v
	}
	if v := os.Getenv("AEGIS_ENROLL_TOKEN_FILE"); v != "" {
		cfg.EnrollTokenFile = v
	}
	if v := os.Getenv("AEGIS_ENROLL_KEY"); v != "" {
		cfg.EnrollKey = v
	}
	if v := os.Getenv("AEGIS_MANIFEST_PUBKEY"); v != "" {
		cfg.ManifestPubKey = v
	}
	if v := os.Getenv("NODETRACE_EBPF_COLLECTOR"); v != "" {
		cfg.EBPFCollector = v
	}
	if v := os.Getenv("NODETRACE_EBPF_OBJ"); v != "" {
		cfg.EBPFObj = v
	}
	if v := os.Getenv("NODETRACE_AUDIT_LOG"); v != "" {
		cfg.AuditLog = v
	}
	if v, ok := envBool("NODETRACE_EBPF"); ok {
		cfg.EBPFEnabled = v
	}
	if v, ok := envBool("NODETRACE_AUDITD"); ok {
		cfg.AuditdEnabled = v
	}
	if v := os.Getenv("AEGIS_ETW_PATH"); v != "" {
		cfg.ETWPath = v
	}
	if v, ok := envBool("AEGIS_ETW_ENABLED"); ok {
		cfg.ETWEnabled = v
	}
	if v, ok := envBool("AEGIS_ETW_ALLOW_UNSIGNED"); ok {
		cfg.ETWAllowUnsigned = v
	}
	if v := os.Getenv("AEGIS_ETW_SHA256"); v != "" {
		cfg.ETWSHA256 = v
	}
	if v := os.Getenv("AEGIS_SCAN_INTERVAL_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.ScanInterval = time.Duration(n) * time.Millisecond
		}
	}
	if v := os.Getenv("AEGIS_NETSTAT_INTERVAL_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.NetstatInterval = time.Duration(n) * time.Millisecond
		}
	}
	if v := os.Getenv("AEGIS_SPOOL_DIR"); v != "" {
		cfg.SpoolFile = filepath.Join(v, "events.spool")
	}
	if v := os.Getenv("AEGIS_SPOOL_MAX_MB"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			cfg.SpoolMaxBytes = n * 1024 * 1024
		}
	}
	if v := os.Getenv("AEGIS_QUARANTINE_DIR"); v != "" {
		cfg.QuarantineDir = v
	}
	if v := os.Getenv("AEGIS_HOSTS_FILE"); v != "" {
		cfg.HostsFile = v
	}
	if v := os.Getenv("AEGIS_YARA_PATH"); v != "" {
		cfg.YaraPath = v
	}
}

func defaultHostsFile() string {
	if runtime.GOOS == "windows" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		return filepath.Join(root, `System32\drivers\etc\hosts`)
	}
	return "/etc/hosts"
}

func (c *Config) deriveURLs() {
	base := strings.TrimRight(strings.TrimSpace(c.HeartbeatURL), "/")
	base = strings.TrimSuffix(base, "/heartbeat")

	if c.ServerURL == "" {
		c.ServerURL = originURL(c.HeartbeatURL)
	}

	// The MSI, the deb and Deployment Manager provide AEGIS_BRAIN_URL only: an
	// origin (https://host) or an API base (https://host/api/v1). Deriving the
	// rest from HeartbeatURL alone left every endpoint empty in that case, so a
	// properly configured endpoint refused to start with "heartbeat non
	// configurato". Fall back to the API base the Brain actually serves.
	if base == "" && c.ServerURL != "" {
		if api := apiBaseFromServerURL(c.ServerURL); api != "" {
			base = api
			if c.HeartbeatURL == "" {
				c.HeartbeatURL = base + "/heartbeat"
			}
		}
	}
	if c.RegisterURL == "" && c.ServerURL != "" {
		if api := apiBaseFromServerURL(c.ServerURL); api != "" {
			c.RegisterURL = api + "/register"
		}
	}
	if base != "" {
		if c.UpdateURL == "" {
			c.UpdateURL = base + "/update"
		}
		if c.CommandsURL == "" {
			c.CommandsURL = base + "/commands"
		}
		if c.AckURL == "" {
			c.AckURL = base + "/telemetry/commands/ack"
		}
		if c.ReportURL == "" {
			c.ReportURL = base + "/telemetry/report"
		}
		if c.ReportBatchURL == "" {
			c.ReportBatchURL = base + "/telemetry/report/batch"
		}
		if c.CSRURL == "" {
			c.CSRURL = base + "/enroll/csr"
		}
		if c.ScanResultURL == "" {
			c.ScanResultURL = base + "/discovery/agent-scan-result"
		}
	}
	c.deriveGuardURLs()
}

// deriveGuardURLs preserves the legacy Guard BRAIN_URL contract. Guard's
// server_url is already the API base (for example https://host/api/v1), so it
// is not the NodeTrace heartbeat origin.
func (c *Config) deriveGuardURLs() {
	base := apiBaseFromServerURL(c.ServerURL)
	if base == "" {
		base = guardBaseFromReportURL(c.ReportURL)
	}
	if base == "" {
		return
	}
	if c.GuardEnrollURL == "" {
		c.GuardEnrollURL = base + "/enroll/enroll"
	}
	if c.GuardCommandsURL == "" {
		c.GuardCommandsURL = base + "/telemetry/commands"
	}
	if c.ReportURL == "" {
		c.ReportURL = base + "/telemetry/report"
	}
	if c.ReportBatchURL == "" {
		c.ReportBatchURL = c.ReportURL + "/batch"
	}
	if c.ScanResultURL == "" {
		c.ScanResultURL = base + "/discovery/agent-scan-result"
	}
	if c.CSRURL == "" {
		c.CSRURL = base + "/enroll/csr"
	}
	if c.AckURL == "" {
		c.AckURL = base + "/telemetry/commands/ack"
	}
}

func guardBaseFromReportURL(raw string) string {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	for _, suffix := range []string{"/telemetry/report/batch", "/telemetry/report"} {
		if strings.HasSuffix(raw, suffix) {
			return strings.TrimSuffix(raw, suffix)
		}
	}
	return ""
}

// ResolveGuardSecret reads the legacy secret.json before the network gate. A
// Guard host can run with no NodeTrace config.json at all; its persisted
// server_url is the only source for report and command endpoints.
func (c *Config) ResolveGuardSecret() error {
	if (c.Profile != ProfileEndpoint && c.Profile != ProfileUnified) || strings.TrimSpace(c.SecretFile) == "" {
		return nil
	}
	data, err := os.ReadFile(c.SecretFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("secret Guard %s non leggibile: %w", c.SecretFile, err)
	}
	var secret struct {
		ServerURL string `json:"server_url"`
	}
	if err := json.Unmarshal(data, &secret); err != nil {
		return fmt.Errorf("secret Guard %s corrotto: %w", c.SecretFile, err)
	}
	base := strings.TrimRight(strings.TrimSpace(secret.ServerURL), "/")
	for _, suffix := range []string{
		"/telemetry/report/batch", "/telemetry/report", "/telemetry/commands/ack",
		"/telemetry/commands", "/enroll/enroll", "/enroll/csr",
	} {
		if strings.HasSuffix(base, suffix) {
			base = strings.TrimSuffix(base, suffix)
			break
		}
	}
	if base == "" {
		return nil
	}
	if c.ServerURL == "" {
		c.ServerURL = base
	}
	if c.GuardEnrollURL == "" {
		c.GuardEnrollURL = base + "/enroll/enroll"
	}
	if c.GuardCommandsURL == "" {
		c.GuardCommandsURL = base + "/telemetry/commands"
	}
	if c.ReportURL == "" {
		c.ReportURL = base + "/telemetry/report"
	}
	if c.ReportBatchURL == "" {
		c.ReportBatchURL = base + "/telemetry/report/batch"
	}
	if c.ScanResultURL == "" {
		c.ScanResultURL = base + "/discovery/agent-scan-result"
	}
	if c.CSRURL == "" {
		c.CSRURL = base + "/enroll/csr"
	}
	if c.AckURL == "" {
		c.AckURL = base + "/telemetry/commands/ack"
	}
	return nil
}

// ValidateNetwork checks the endpoints needed by the selected profile.
// Enrollment is separate because an already-enrolled host can run without a
// registration token.
func (c Config) ValidateNetwork() error {
	required := map[string]string{
		"heartbeat": c.HeartbeatURL,
		"update":    c.UpdateURL,
		"commands":  c.CommandsURL,
		"ack":       c.AckURL,
	}
	if c.Profile == ProfileEndpoint || c.Profile == ProfileUnified {
		required = map[string]string{
			"enroll-guard":   c.GuardEnrollURL,
			"report-guard":   c.ReportURL,
			"commands-guard": c.GuardCommandsURL,
			"ack-guard":      c.AckURL,
		}
	}
	for name, raw := range required {
		if strings.TrimSpace(raw) == "" {
			return fmt.Errorf("endpoint %s non configurato", name)
		}
		if err := validateHTTPURL(raw); err != nil {
			return fmt.Errorf("endpoint %s non valido: %w", name, err)
		}
	}
	return nil
}

// apiBaseFromServerURL accepts both contracts: the Deployment Manager sets
// AEGIS_BRAIN_URL to the API base (https://host/api/v1), while the MSI ships
// BRAIN_URL as an origin (https://host). An origin would otherwise produce
// /enroll/enroll, which the frontend answers with 405 instead of the Brain.
func apiBaseFromServerURL(raw string) string {
	base := strings.TrimRight(strings.TrimSpace(raw), "/")
	if base == "" {
		return ""
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return base
	}
	if strings.Trim(u.Path, "/") == "" {
		return base + "/api/v1"
	}
	return base
}

func originURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func validateHTTPURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("schema %q non supportato", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("host mancante")
	}
	return nil
}

// ReadEnrollToken follows the legacy one-shot file precedence: a non-empty
// file wins over the static key in the environment.
func (c Config) ReadEnrollToken() (string, error) {
	if c.EnrollTokenFile != "" {
		if data, err := os.ReadFile(c.EnrollTokenFile); err == nil {
			if token := strings.TrimSpace(string(data)); token != "" {
				return token, nil
			}
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("enrollment token file non leggibile: %w", err)
		}
	}
	if token := strings.TrimSpace(c.EnrollKey); token != "" {
		return token, nil
	}
	return "", fmt.Errorf("nessun enrollment token: impostare AEGIS_ENROLL_TOKEN_FILE o AEGIS_ENROLL_KEY")
}

// SensorEnabled reports whether this process should start host telemetry.
// For unified it follows Mode; a sensor-only unified agent never starts the
// endpoint monitor, FIM, actions or ETW.
func (c Config) SensorEnabled() bool {
	switch c.Profile {
	case ProfileSensor, ProfileRouter:
		return true
	case ProfileEndpoint:
		return false
	case ProfileUnified:
		return c.Mode != ModeEndpoint
	default:
		return false
	}
}

// EndpointEnabled reports whether this process should start the endpoint
// runtime. A sensor-only unified agent does not start process monitoring,
// response actions, FIM or ETW.
func (c Config) EndpointEnabled() bool {
	switch c.Profile {
	case ProfileEndpoint:
		return true
	case ProfileUnified:
		return c.Mode != ModeSensor
	default:
		return false
	}
}

// AgentType is the legacy record type used during the cutover. Guard and
// NodeTrace keep distinct Brain records until unified arrives.
func (c Config) AgentType() string {
	switch c.Profile {
	case ProfileEndpoint:
		return "aegis-guard"
	case ProfileUnified:
		return "unified"
	default:
		return "nodetrace"
	}
}

// OSName returns the OS label used by the Brain's existing agent records.
func OSName() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	case "darwin":
		return "Darwin"
	default:
		return runtime.GOOS
	}
}

func resolveHome(explicit string) (string, error) {
	for _, candidate := range []string{
		explicit,
		os.Getenv("AEGIS_AGENT_HOME"),
		os.Getenv("NODETRACE_IDENTITY_DIR"),
	} {
		if strings.TrimSpace(candidate) != "" {
			return absPath(candidate), nil
		}
	}
	exe, err := os.Executable()
	if err != nil {
		wd, wdErr := os.Getwd()
		if wdErr != nil {
			return "", fmt.Errorf("directory agente non determinabile: %w", err)
		}
		return wd, nil
	}
	return filepath.Dir(exe), nil
}

func absPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

func envBool(name string) (bool, bool) {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		return false, false
	}
}

// ParseSeconds is a small helper used by tests and future CLI flags.
func ParseSeconds(raw string) (time.Duration, error) {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("intervallo non valido: %q", raw)
	}
	return time.Duration(n) * time.Second, nil
}

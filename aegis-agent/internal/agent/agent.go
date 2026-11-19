package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/config"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/event"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/guard/actions"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/guard/etw"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/guard/fim"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/guard/monitor"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/guard/outbox"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/guard/spool"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/guard/yara"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/identity"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/kernel"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/networkscan"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/telemetry"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/transport"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/update"
)

const commandPollInterval = 5 * time.Second

type Agent struct {
	cfg           config.Config
	store         *identity.Store
	secretStore   *identity.SecretStore
	client        *transport.Client
	collector     telemetry.Collector
	log           *slog.Logger
	sensorSummary map[string]any
	streamsReady  bool

	guardOutbox  *outbox.Outbox
	guardActions *actions.Executor
	guardFIM     *fim.Monitor
	guardMonitor *monitor.Monitor
	guardETW     *etw.Stream
	guardCaps    map[string]any
}

func New(cfg config.Config, store *identity.Store, client *transport.Client, collector telemetry.Collector, logger *slog.Logger) *Agent {
	if logger == nil {
		logger = slog.Default()
	}
	return &Agent{
		cfg: cfg, store: store, client: client, collector: collector, log: logger,
		secretStore: identity.NewSecretStore(cfg.SecretFile),
	}
}

// EnsureIdentity loads token.json or performs a legacy NodeTrace enrollment.
// It deliberately uses agent_type=nodetrace during cutover A.
func (a *Agent) EnsureIdentity(ctx context.Context) error {
	if a.cfg.Profile == config.ProfileEndpoint || a.cfg.Profile == config.ProfileUnified {
		return a.ensureGuardIdentity(ctx)
	}
	token, err := a.store.Load()
	if err == nil {
		if a.cfg.RegisterURL != "" {
			if err := identity.CheckServerPin(token.ServerURL, a.cfg.RegisterURL); err != nil {
				return err
			}
		}
		a.client.SetCredentials(token.Token, token.DeviceID, a.client.ClientCert)
		if err := a.ensureDeviceIdentity(ctx); err != nil {
			a.log.Warn("identità device non disponibile", "error", err)
		}
		a.log.Info("identità caricata", "device_id", token.DeviceID)
		return nil
	}
	if !errors.Is(err, identity.ErrNotFound) {
		return err
	}
	if a.cfg.RegisterURL == "" {
		return fmt.Errorf("register URL non configurato")
	}
	enrollToken, err := a.cfg.ReadEnrollToken()
	if err != nil {
		return err
	}
	systemInfo := telemetry.SystemInfo()
	resp, err := a.client.Register(ctx, a.cfg.RegisterURL, transport.RegisterRequest{
		Hostname:  a.cfg.DeviceName,
		OS:        config.OSName(),
		AgentType: a.cfg.AgentType(),
		EnrollKey: enrollToken,
		MachineID: identity.MachineID(),
		OSVersion: mapString(systemInfo["os_version"]),
		CPUModel:  mapString(systemInfo["cpu_model"]),
		TotalRAM:  mapInt64(systemInfo["total_ram"]),
		MAC:       telemetry.LocalMAC(),
	})
	if err != nil {
		return fmt.Errorf("enrollment: %w", err)
	}
	token = identity.Token{
		Token:     resp.DeviceToken,
		DeviceID:  resp.DeviceID,
		ServerURL: a.cfg.RegisterURL,
	}
	if err := a.store.Save(token); err != nil {
		return fmt.Errorf("salvataggio identità: %w", err)
	}
	a.client.SetCredentials(token.Token, token.DeviceID, a.client.ClientCert)
	if err := a.ensureDeviceIdentity(ctx); err != nil {
		a.log.Warn("CSR/mTLS non completato", "error", err)
	}
	a.log.Info("enrollment completato", "device_id", token.DeviceID, "status", resp.Status)
	return nil
}

func (a *Agent) ensureGuardIdentity(ctx context.Context) error {
	if err := a.cfg.ResolveGuardSecret(); err != nil {
		return err
	}
	secret, err := a.secretStore.Load()
	if err == nil {
		if a.cfg.GuardEnrollURL != "" {
			if err := identity.CheckServerPinBase(secret.ServerURL, a.cfg.GuardEnrollURL); err != nil {
				return err
			}
		}
		a.client.SetCredentials(secret.AgentSecret, secret.AgentID, a.client.ClientCert)
		if err := a.ensureDeviceIdentity(ctx); err != nil {
			a.log.Warn("identità device Guard non disponibile", "error", err)
		}
		a.log.Info("identità Guard caricata", "agent_id", secret.AgentID)
		return nil
	}
	if !errors.Is(err, identity.ErrNotFound) {
		return err
	}
	if a.cfg.GuardEnrollURL == "" {
		return fmt.Errorf("enrollment Guard URL non configurato")
	}
	enrollToken, err := a.cfg.ReadEnrollToken()
	if err != nil {
		return err
	}
	resp, err := a.client.EnrollGuard(ctx, a.cfg.GuardEnrollURL, transport.EnrollGuardRequest{
		Hostname:  a.cfg.DeviceName,
		OS:        config.OSName(),
		AgentType: a.cfg.AgentType(),
		MachineID: identity.MachineID(),
		EnrollKey: enrollToken,
	})
	if err != nil {
		return fmt.Errorf("enrollment Guard: %w", err)
	}
	secret = identity.Secret{
		AgentID:     resp.AgentID,
		AgentSecret: resp.AgentSecret,
		ServerURL:   strings.TrimSuffix(a.cfg.GuardEnrollURL, "/enroll/enroll"),
	}
	if err := a.secretStore.Save(secret); err != nil {
		return fmt.Errorf("salvataggio segreto Guard: %w", err)
	}
	a.client.SetCredentials(secret.AgentSecret, secret.AgentID, a.client.ClientCert)
	if err := a.ensureDeviceIdentity(ctx); err != nil {
		a.log.Warn("CSR/mTLS Guard non completato", "error", err)
	}
	a.log.Info("enrollment Guard completato", "agent_id", secret.AgentID)
	return nil
}

func (a *Agent) ensureDeviceIdentity(ctx context.Context) error {
	_, cert, err := identity.LoadDeviceIdentity(a.cfg.IdentityDir)
	if err == nil && !identity.NeedsRenewal(cert, time.Now().UTC()) {
		return a.installDeviceCert(cert)
	}
	if err != nil && !errors.Is(err, identity.ErrNoDeviceIdentity) {
		return err
	}
	if a.cfg.CSRURL == "" {
		return fmt.Errorf("CSR URL non configurato")
	}
	keyPEM, csrPEM, err := identity.BuildCSR(a.client.AgentID)
	if err != nil {
		return err
	}
	var response struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := a.client.PostJSON(ctx, a.cfg.CSRURL, map[string]string{"csr_pem": string(csrPEM)}, &response); err != nil {
		return fmt.Errorf("richiesta certificato: %w", err)
	}
	if strings.TrimSpace(response.CertificatePEM) == "" {
		return fmt.Errorf("risposta CSR senza certificate_pem")
	}
	if _, _, err := identity.SaveDeviceIdentity(a.cfg.IdentityDir, keyPEM, []byte(response.CertificatePEM)); err != nil {
		return err
	}
	if err := a.installDeviceCert([]byte(response.CertificatePEM)); err != nil {
		return err
	}
	a.log.Info("identità device rinnovata", "dir", a.cfg.IdentityDir)
	return nil
}

func (a *Agent) installDeviceCert(certPEM []byte) error {
	fingerprint, err := identity.CertFingerprint(certPEM)
	if err != nil {
		return err
	}
	a.client.ClientCert = fingerprint
	return nil
}

func (a *Agent) RunOnce(ctx context.Context) error {
	if a.client.AgentID == "" || a.client.Token == "" {
		return fmt.Errorf("identità non inizializzata")
	}
	if a.cfg.Profile == config.ProfileEndpoint || a.cfg.Profile == config.ProfileUnified {
		a.bootstrapSensors(ctx)
	}
	return errors.Join(a.sendHeartbeat(ctx), a.sendTelemetry(ctx))
}

func (a *Agent) Run(ctx context.Context) error {
	if err := a.EnsureIdentity(ctx); err != nil {
		return err
	}
	a.bootstrapSensors(ctx)
	if err := a.RunOnce(ctx); err != nil {
		a.log.Warn("invio iniziale fallito", "error", err)
	}

	heartbeat := time.NewTicker(a.cfg.HeartbeatInterval)
	telemetryTicker := time.NewTicker(a.cfg.TelemetryInterval)
	commands := time.NewTicker(commandPollInterval)
	defer heartbeat.Stop()
	defer telemetryTicker.Stop()
	defer commands.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-heartbeat.C:
			if err := a.sendHeartbeat(ctx); err != nil {
				a.log.Warn("heartbeat fallito", "error", err)
			}
		case <-telemetryTicker.C:
			if err := a.sendTelemetry(ctx); err != nil {
				a.log.Warn("telemetria fallita", "error", err)
			}
		case <-commands.C:
			if err := a.PollCommands(ctx); err != nil {
				a.log.Warn("poll comandi fallito", "error", err)
			}
		}
	}
}

func (a *Agent) bootstrapSensors(ctx context.Context) {
	if a.streamsReady {
		return
	}
	a.streamsReady = true
	if a.cfg.Profile == config.ProfileEndpoint {
		a.bootstrapGuard(ctx)
		return
	}
	if a.cfg.Profile == config.ProfileUnified {
		a.bootstrapGuard(ctx)
	}
	a.bootstrapSensorStreams(ctx)
}

func (a *Agent) bootstrapSensorStreams(ctx context.Context) {
	probe := kernel.Probe()
	auditPath := strings.TrimSpace(a.cfg.AuditLog)
	if auditPath == "" {
		auditPath = kernel.AuditdAvailable()
	}
	ebpfActive := runtime.GOOS == "linux" && a.cfg.EBPFEnabled && a.cfg.EBPFCollector != "" && probe["profile"] != kernel.Absent
	auditActive := runtime.GOOS == "linux" && a.cfg.AuditdEnabled && auditPath != "" && !ebpfActive
	mode := kernel.SensorMode(config.OSName(), ebpfActive, auditActive)
	a.sensorSummary = map[string]any{
		"mode":           mode,
		"kernel_profile": probe["profile"],
		"kernel_reason":  probe["reason"],
		"auditd":         auditActive,
		"ebpf":           ebpfActive,
	}
	if runtime.GOOS == "linux" {
		for key, value := range kernel.EvidenceSummary() {
			a.sensorSummary[key] = value
		}
	}
	if ebpfActive {
		go a.streamEBPF(ctx)
	}
	if auditActive {
		go a.tailAuditd(ctx, auditPath)
	}
}

func (a *Agent) PollCommands(ctx context.Context) error {
	commandEndpoint := a.cfg.CommandsURL
	if a.cfg.Profile == config.ProfileEndpoint || a.cfg.Profile == config.ProfileUnified {
		commandEndpoint = a.cfg.GuardCommandsURL
	}
	commands, err := a.client.CommandsBatch(ctx, commandEndpoint, a.client.AgentID)
	if err != nil {
		commands, err = a.client.Commands(ctx, commandEndpoint, a.client.AgentID)
		if err != nil {
			return err
		}
	}
	for _, command := range commands {
		if err := a.execute(ctx, command); err != nil {
			a.log.Warn("comando fallito", "command", command.Command, "error", err)
		}
	}
	return nil
}

func (a *Agent) execute(ctx context.Context, command transport.Command) error {
	if a.cfg.Profile == config.ProfileEndpoint || a.cfg.Profile == config.ProfileUnified {
		return a.executeGuard(ctx, command)
	}
	switch command.Command {
	case "GET_TELEMETRY":
		if err := a.sendTelemetry(ctx); err != nil {
			_ = a.ack(ctx, command.Command, "failed", err.Error(), command.DeliveryID)
			return err
		}
		return a.ack(ctx, command.Command, "ok", "", command.DeliveryID)
	case "NETWORK_SCAN":
		go a.runNetworkScan(context.Background(), command)
		return a.ack(ctx, command.Command, "ok", "scan started", command.DeliveryID)
	case "UPDATE_AGENT":
		if err := a.handleUpdate(ctx, command); err != nil {
			_ = a.ack(ctx, command.Command, "failed", err.Error(), command.DeliveryID)
			return err
		}
		return a.ack(ctx, command.Command, "ok", "update staged; restart required", command.DeliveryID)
	default:
		detail := "unsupported command"
		if err := a.ack(ctx, command.Command, "failed", detail, command.DeliveryID); err != nil {
			return err
		}
		return fmt.Errorf("%s: %s", command.Command, detail)
	}
}

func (a *Agent) runNetworkScan(ctx context.Context, command transport.Command) {
	cidr := strings.TrimSpace(command.CIDR)
	if cidr == "" {
		cidr = "192.168.1.0/24"
	}
	timeout := time.Duration(command.ProbeTimeout * float64(time.Second))
	if timeout == 0 {
		timeout = 100 * time.Millisecond
	}
	hosts, err := networkscan.New().Scan(ctx, cidr, command.Ports, timeout)
	if err != nil {
		a.log.Warn("network scan fallito", "cidr", cidr, "error", err)
		return
	}
	payload := map[string]any{"cidr": cidr, "scan_hosts": hosts}
	if err := a.client.PostJSON(ctx, a.cfg.ScanResultURL, payload, nil); err != nil {
		a.log.Warn("invio scan fallito, provo fallback update", "error", err)
		fallback := map[string]any{"device_id": a.client.AgentID, "scan_result": payload}
		if fallbackErr := a.client.PostJSON(ctx, a.cfg.UpdateURL, fallback, nil); fallbackErr != nil {
			a.log.Warn("fallback scan fallito", "error", fallbackErr)
			return
		}
	}
	a.log.Info("network scan completato", "cidr", cidr, "hosts", len(hosts))
}

func (a *Agent) handleUpdate(ctx context.Context, command transport.Command) error {
	if strings.TrimSpace(a.cfg.ManifestPubKey) == "" {
		return fmt.Errorf("manifest public key non configurata")
	}
	if command.URL == "" || command.Manifest == "" || command.ManifestSig == "" || command.SHA256 == "" {
		return fmt.Errorf("comando update incompleto")
	}
	if !update.AllowURL(a.cfg.ServerURL, command.URL) {
		return fmt.Errorf("URL artefatto fuori allowlist")
	}
	manifest := []byte(command.Manifest)
	if err := update.VerifyManifest(manifest, command.ManifestSig, a.cfg.ManifestPubKey); err != nil {
		return err
	}
	name := update.ArtifactName(command.URL)
	if !update.ManifestCovers(manifest, name, command.SHA256) {
		return fmt.Errorf("manifest non copre %s", name)
	}
	path, err := update.TempDownloadPath(a.cfg.AgentHome)
	if err != nil {
		return err
	}
	if err := update.Download(ctx, a.client.HTTP, command.URL, path, a.client.Token, a.client.AgentID, a.client.ClientCert); err != nil {
		_ = os.Remove(path)
		return err
	}
	staged, err := update.Stage(path, command.SHA256, a.cfg.AgentHome, a.cfg.Version, command.Version)
	if err != nil {
		return err
	}
	if err := update.SealState(a.cfg.AgentHome, a.client.Token); err != nil {
		return err
	}
	a.log.Info("update staged", "path", staged, "version", command.Version)
	return nil
}

func (a *Agent) ack(ctx context.Context, command, status, details string, deliveryID ...string) error {
	return a.ackWithAlert(ctx, command, status, details, nil, deliveryID...)
}

func (a *Agent) ackWithAlert(ctx context.Context, command, status, details string, alertID *int64, deliveryID ...string) error {
	ack := transport.Ack{
		Command: command,
		Status:  status,
		Details: details,
		AlertID: alertID,
	}
	if len(deliveryID) > 0 {
		ack.DeliveryID = deliveryID[0]
	}
	return a.client.Ack(ctx, a.cfg.AckURL, ack)
}

func (a *Agent) sendHeartbeat(ctx context.Context) error {
	if a.cfg.Profile == config.ProfileEndpoint || a.cfg.Profile == config.ProfileUnified {
		return a.sendGuardHeartbeat(ctx)
	}
	payload := map[string]any{
		"device_id":     a.client.AgentID,
		"agent_version": a.cfg.Version,
		"capabilities":  a.capabilities(),
	}
	sensor := map[string]any{
		"mode":      "polling",
		"cpu_usage": 0.0,
		"ram_usage": 0.0,
	}
	for key, value := range a.sensorSummary {
		sensor[key] = value
	}
	if snapshot, err := a.collector.Collect(ctx); err == nil {
		sensor["cpu_usage"] = snapshot.CPUUsage
		sensor["ram_usage"] = snapshot.RAMUsage
	}
	payload["sensor"] = sensor
	if err := a.client.PostJSON(ctx, a.cfg.HeartbeatURL, payload, nil); err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	return nil
}

func (a *Agent) sendTelemetry(ctx context.Context) error {
	if a.cfg.Profile == config.ProfileEndpoint || a.cfg.Profile == config.ProfileUnified {
		return a.sendGuardTelemetry(ctx)
	}
	snapshot, err := a.collector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("raccolta telemetria: %w", err)
	}
	snapshot.DeviceID = a.client.AgentID
	snapshot.AgentVersion = a.cfg.Version
	snapshot.Capabilities = a.capabilities()
	if err := a.client.PostJSON(ctx, a.cfg.UpdateURL, snapshot, nil); err != nil {
		return fmt.Errorf("telemetria: %w", err)
	}
	return nil
}

func mapString(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func mapInt64(value any) int64 {
	switch number := value.(type) {
	case int64:
		return number
	case int:
		return int64(number)
	case float64:
		return int64(number)
	default:
		return 0
	}
}

func (a *Agent) sendGuardHeartbeat(ctx context.Context) error {
	payload := map[string]any{
		"agent_id":      a.client.AgentID,
		"timestamp":     time.Now().UTC().Format(time.RFC3339Nano),
		"event_type":    "AGENT_HEARTBEAT",
		"hostname":      a.cfg.DeviceName,
		"agent_version": a.cfg.Version,
		"capabilities":  a.capabilities(),
		"sensor":        a.sensorSummary,
	}
	if err := a.enqueueGuard(payload); err != nil {
		return fmt.Errorf("heartbeat Guard: %w", err)
	}
	return nil
}

func (a *Agent) sendGuardTelemetry(ctx context.Context) error {
	snapshot, err := a.collector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("raccolta telemetria Guard: %w", err)
	}
	payload := map[string]any{
		"agent_id":         a.client.AgentID,
		"timestamp":        time.Now().UTC().Format(time.RFC3339Nano),
		"event_type":       "METRICS_REPORT",
		"cpu_usage":        snapshot.CPUUsage,
		"ram_usage":        snapshot.RAMUsage,
		"processes":        snapshot.Processes,
		"users":            snapshot.Users,
		"network_flows":    snapshot.NetworkFlows,
		"anomalies":        snapshot.Anomalies,
		"disk_free":        snapshot.DiskFree,
		"disk_total":       snapshot.DiskTotal,
		"network_sent":     snapshot.NetworkSent,
		"network_received": snapshot.NetworkReceived,
		"agent_version":    a.cfg.Version,
		"capabilities":     a.capabilities(),
		"sensor":           a.sensorSummary,
	}
	if err := a.enqueueGuard(payload); err != nil {
		return fmt.Errorf("telemetria Guard: %w", err)
	}
	return nil
}

func (a *Agent) capabilities() map[string]any {
	if a.cfg.Profile == config.ProfileEndpoint || a.cfg.Profile == config.ProfileUnified {
		caps := a.guardCaps
		if caps == nil {
			caps = map[string]any{
				"agent_type":           a.cfg.AgentType(),
				"process_monitor":      a.guardMonitor != nil,
				"response_actions":     a.guardActions != nil,
				"fim":                  a.guardFIM != nil && a.guardFIM.Available(),
				"yara_scan":            false,
				"etw_kernel_telemetry": false,
				"device_identity_mtls": true,
				"profile":              string(a.cfg.Profile),
			}
		}
		if a.cfg.Profile == config.ProfileUnified {
			caps["telemetry"] = true
			caps["network_scan"] = true
			caps["sensor_mode"] = a.sensorSummary["mode"]
			caps["kernel_profile"] = a.sensorSummary["kernel_profile"]
			caps["ebpf"] = a.sensorSummary["ebpf"]
			caps["auditd"] = a.sensorSummary["auditd"]
		}
		return caps
	}
	mode := "fallback"
	if value, ok := a.sensorSummary["mode"].(string); ok && value != "" {
		mode = value
	}
	return map[string]any{
		"telemetry":      true,
		"network_scan":   true,
		"update":         a.cfg.ManifestPubKey != "",
		"sensor_mode":    mode,
		"kernel_profile": a.sensorSummary["kernel_profile"],
		"kernel_reason":  a.sensorSummary["kernel_reason"],
		"auditd":         a.sensorSummary["auditd"],
		"ebpf":           a.sensorSummary["ebpf"],
		"profile":        string(a.cfg.Profile),
	}
}

func (a *Agent) tailAuditd(ctx context.Context, path string) {
	tailer := kernel.NewAuditdTailer(path)
	cache := kernel.NewSeenCache(5*time.Second, 10000)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, event := range tailer.Poll() {
				if cache.Check(event, time.Now()) {
					continue
				}
				report := kernel.EventToReport(event, a.client.AgentID, a.cfg.DeviceName, "", a.cfg.Version, "auditd")
				if err := a.client.PostJSON(ctx, a.cfg.ReportURL, report, nil); err != nil {
					a.log.Warn("report auditd fallito", "error", err)
				}
			}
		}
	}
}

// bootstrapGuard starts the endpoint runtime once. The outbox is created
// before sensors so process/FIM/ETW events have exactly one delivery path and
// one encrypted spool. A failure in an optional sensor degrades a capability;
// it never prevents identity/report/commands from working.
func (a *Agent) bootstrapGuard(ctx context.Context) {
	spoolPath := a.cfg.SpoolFile
	var encrypted *spool.Spool
	if created, err := spool.New(spoolPath, a.client.Token, a.cfg.SpoolMaxBytes); err == nil {
		encrypted = created
	} else {
		a.log.Warn("spool Guard non attivo", "error", err)
	}
	batchURL := a.cfg.ReportBatchURL
	if batchURL == "" {
		batchURL = strings.TrimRight(a.cfg.ReportURL, "/") + "/batch"
	}
	a.guardOutbox = outbox.New(&guardSender{
		client: a.client, reportURL: a.cfg.ReportURL, batchURL: batchURL,
	}, encrypted, a.log)
	go a.guardOutbox.Run(ctx)

	if monitorFIM, err := fim.New(a.client.AgentID, config.OSName(), a.cfg.Version,
		a.cfg.DeviceName, a.emitGuardEvent, a.log); err == nil {
		a.guardFIM = monitorFIM
		monitorFIM.Start(ctx)
	} else {
		a.log.Warn("FIM non disponibile", "error", err)
	}

	yaraScanner := yara.New(a.cfg.YaraPath)
	a.guardActions = actions.New(a.client.AgentID, a.cfg.ServerURL, a.cfg.AgentHome,
		yaraScanner, a.guardFIM, a.log)
	a.guardActions.HostsFile = a.cfg.HostsFile
	a.guardActions.QuarantineDir = a.cfg.QuarantineDir

	a.guardMonitor = monitor.New(a.client.AgentID, a.cfg.DeviceName, config.OSName(),
		a.cfg.Version, a.cfg.ScanInterval, a.emitGuardEvent, a.log)
	a.guardMonitor.Start(ctx)

	etwSource := etw.New(a.client.AgentID, config.OSName(), a.cfg.Version,
		a.cfg.ETWEnabled, a.cfg.ETWPath, a.cfg.ETWAllowUnsigned)
	if available, reason := etwSource.Available(ctx); available {
		if stream, ok := etwSource.Start(ctx, a.emitGuardEvent); ok {
			a.guardETW = stream
		} else {
			a.log.Warn("ETW non avviato", "reason", reason)
		}
	} else {
		a.log.Info("ETW non attivo; polling processi come fallback dichiarato", "reason", reason)
	}

	a.guardCaps = map[string]any{
		"agent_type":           a.cfg.AgentType(),
		"process_monitor":      true,
		"response_actions":     a.guardActions != nil,
		"fim":                  a.guardFIM != nil && a.guardFIM.Available(),
		"yara_scan":            yaraScanner.Available(),
		"etw_kernel_telemetry": a.guardETW != nil && a.guardETW.Running(),
		"device_identity_mtls": true,
		"registry_snapshot":    runtime.GOOS == "windows",
		"services_snapshot":    runtime.GOOS == "windows",
		"persistence_snapshot": runtime.GOOS == "windows",
		"defender_snapshot":    runtime.GOOS == "windows",
		"authenticode":         runtime.GOOS == "windows",
		"process_provenance":   "toolhelp",
		"profile":              string(a.cfg.Profile),
	}
	if a.guardETW != nil && a.guardETW.Running() {
		a.guardCaps["process_provenance"] = "etw+toolhelp"
	}
	a.sensorSummary = map[string]any{
		"mode": "endpoint", "fim": a.guardCaps["fim"],
		"yara": a.guardCaps["yara_scan"], "etw": a.guardCaps["etw_kernel_telemetry"],
	}
}

func (a *Agent) emitGuardEvent(ev event.Event) {
	if err := a.enqueueGuard(ev); err != nil {
		a.log.Warn("evento Guard non accodato", "event", ev.EventType, "error", err)
	}
}

func (a *Agent) enqueueGuard(value any) error {
	if a.guardOutbox != nil {
		return a.guardOutbox.Add(value)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return a.client.PostJSON(ctx, a.cfg.ReportURL, value, nil)
}

func (a *Agent) executeGuard(ctx context.Context, command transport.Command) error {
	switch command.Command {
	case "GET_TELEMETRY":
		if err := a.sendGuardTelemetry(ctx); err != nil {
			_ = a.ackWithAlert(ctx, command.Command, "failed", err.Error(), command.AlertID, command.DeliveryID)
			return err
		}
		return a.ackWithAlert(ctx, command.Command, "ok", "telemetry queued", command.AlertID, command.DeliveryID)
	case "NETWORK_SCAN":
		go a.runNetworkScan(context.Background(), command)
		return a.ackWithAlert(ctx, command.Command, "ok", "scan started", command.AlertID, command.DeliveryID)
	case "UPDATE_AGENT":
		if err := a.handleUpdate(ctx, command); err != nil {
			_ = a.ackWithAlert(ctx, command.Command, "failed", err.Error(), command.AlertID, command.DeliveryID)
			return err
		}
		return a.ackWithAlert(ctx, command.Command, "ok", "update staged; restart required", command.AlertID, command.DeliveryID)
	}
	if a.guardActions == nil {
		err := fmt.Errorf("runtime Guard non inizializzato")
		_ = a.ackWithAlert(ctx, command.Command, "failed", err.Error(), command.AlertID, command.DeliveryID)
		return err
	}
	result, err := a.guardActions.Execute(ctx, command)
	if errors.Is(err, actions.ErrAgentHandled) {
		return a.executeGuard(ctx, transport.Command{
			Command: "UPDATE_AGENT", AlertID: command.AlertID, URL: command.URL,
			SHA256: command.SHA256, Manifest: command.Manifest, ManifestSig: command.ManifestSig,
			Version: command.Version,
		})
	}
	if err != nil {
		_ = a.ackWithAlert(ctx, command.Command, "failed", err.Error(), command.AlertID, command.DeliveryID)
		return err
	}
	for _, ev := range result.Events {
		a.emitGuardEvent(ev)
	}
	return a.ackWithAlert(ctx, command.Command, "ok", result.Details, command.AlertID, command.DeliveryID)
}

type guardSender struct {
	client    *transport.Client
	reportURL string
	batchURL  string
}

func (s *guardSender) SendBatch(ctx context.Context, events [][]byte) error {
	raw := make([]json.RawMessage, 0, len(events))
	for _, payload := range events {
		raw = append(raw, json.RawMessage(payload))
	}
	return s.client.PostJSON(ctx, s.batchURL, raw, nil)
}

func (s *guardSender) SendOne(ctx context.Context, payload []byte) error {
	return s.client.PostJSON(ctx, s.reportURL, json.RawMessage(payload), nil)
}

func (a *Agent) streamEBPF(ctx context.Context) {
	args := kernel.ExcludeSelfCommand(a.cfg.EBPFCollector, a.cfg.EBPFObj)
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		a.log.Warn("stdout collector eBPF", "error", err)
		return
	}
	if err := cmd.Start(); err != nil {
		a.log.Warn("avvio collector eBPF fallito", "error", err)
		return
	}
	lines := make(chan string, 256)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64*1024), 1<<20)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			a.log.Warn("lettura collector eBPF", "error", err)
		}
	}()

	batcher := kernel.NewBatcher(25, 2*time.Second, 2000)
	cache := kernel.NewSeenCache(5*time.Second, 10000)
	flushTicker := time.NewTicker(time.Second)
	defer flushTicker.Stop()
	flush := func() {
		batch := batcher.Drain()
		if len(batch) == 0 {
			return
		}
		if len(batch) == 1 {
			if err := a.client.PostJSON(ctx, a.cfg.ReportURL, batch[0], nil); err != nil {
				a.log.Warn("report eBPF fallito", "error", err)
			}
			return
		}
		if err := a.client.PostJSON(ctx, a.cfg.ReportBatchURL, batch, nil); err != nil {
			a.log.Warn("report batch eBPF fallito, fallback singoli", "error", err)
			for _, item := range batch {
				if singleErr := a.client.PostJSON(ctx, a.cfg.ReportURL, item, nil); singleErr != nil {
					a.log.Warn("report singolo eBPF fallito", "error", singleErr)
				}
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return
		case <-flushTicker.C:
			if batcher.Due(time.Now()) {
				flush()
			}
		case line, ok := <-lines:
			if !ok {
				flush()
				_ = cmd.Wait()
				return
			}
			event, err := kernel.ParseLine(line)
			if err != nil || cache.Check(event, time.Now()) {
				continue
			}
			report := kernel.EventToReport(event, a.client.AgentID, a.cfg.DeviceName, "", a.cfg.Version, "ebpf")
			if batcher.Add(report, time.Now()) {
				flush()
			}
		}
	}
}

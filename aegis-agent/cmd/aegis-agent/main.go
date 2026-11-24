package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/agent"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/config"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/identity"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/telemetry"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/transport"
)

var buildVersion = config.DefaultVersion

var (
	flagProfile string
	flagMode    string
	flagHome    string
	flagConfig  string
	flagOnce    bool
	flagCheck   bool
	flagVersion bool
)

func main() {
	flag.StringVar(&flagProfile, "profile", "", "profilo: sensor, endpoint, unified o router")
	flag.StringVar(&flagMode, "mode", "", "modalità unified: full, sensor o endpoint (un solo agente)")
	flag.StringVar(&flagHome, "home", "", "directory stato agente")
	flag.StringVar(&flagConfig, "config", "", "path config.json")
	flag.BoolVar(&flagOnce, "once", false, "invia un ciclo e termina")
	flag.BoolVar(&flagCheck, "check", false, "verifica configurazione e identità senza rete")
	flag.BoolVar(&flagVersion, "version", false, "stampa la versione")
	flag.Parse()

	// The MSI and the Deployment Manager one-liner register AegisAgent as a
	// Windows service. A process started by the SCM must call
	// StartServiceCtrlDispatcher within 30 seconds or the SCM fails the start
	// with error 1053, so the dispatcher runs before any network work.
	handled, err := runAsService(func(ctx context.Context) error {
		return runAgent(ctx, true)
	})
	if handled {
		if err != nil {
			fatal("servizio", err)
		}
		return
	}

	if err := runAgent(context.Background(), false); err != nil {
		fatal("agente", err)
	}
}

func runAgent(ctx context.Context, serviceMode bool) (err error) {
	cfg, err := config.Load(config.Options{
		Profile:    flagProfile,
		Mode:       flagMode,
		AgentHome:  flagHome,
		ConfigFile: flagConfig,
		Version:    buildVersion,
	})
	if err != nil {
		return fmt.Errorf("configurazione: %w", err)
	}
	if flagVersion {
		fmt.Println(cfg.Version)
		return nil
	}
	if flagCheck {
		// -check is the pre-flight an operator runs before enrollment. It used
		// to print the values and exit 0 even with a mistyped -config path, an
		// empty server URL and no token, so it could never gate anything. It now
		// fails exactly where the real start would fail.
		if flagConfig != "" && !fileExists(cfg.ConfigFile) {
			return fmt.Errorf("configurazione: config %s non trovata", cfg.ConfigFile)
		}
		if err := cfg.ValidateNetwork(); err != nil {
			return fmt.Errorf("endpoint: %w", err)
		}
		if cfg.EndpointEnabled() && !fileExists(cfg.TokenFile) {
			fmt.Fprintf(os.Stderr, "avviso: token assente in %s, l'agente si registra al primo avvio\n", cfg.TokenFile)
		}
		fmt.Printf("profile=%s mode=%s sensor=%t endpoint=%t version=%s home=%s server=%s token=%s\n",
			cfg.Profile, cfg.Mode, cfg.SensorEnabled(), cfg.EndpointEnabled(),
			cfg.Version, cfg.AgentHome, cfg.ServerURL, cfg.TokenFile)
		return nil
	}
	if err := cfg.ValidateNetwork(); err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}

	// A service has no console: an early failure (TLS, PID lock, enrollment)
	// must still leave a trace in the state directory, otherwise the SCM only
	// reports the opaque "terminated with error %%1".
	if serviceMode {
		defer func() {
			if err != nil {
				appendServiceError(cfg.IdentityDir, err)
			}
		}()
	}

	// A service has no console: keep stderr for interactive runs and mirror it
	// into the state directory so the operator can read what happened.
	out := io.Writer(os.Stderr)
	if serviceMode {
		if file, err := os.OpenFile(filepath.Join(cfg.IdentityDir, "agent.log"),
			os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			defer file.Close()
			out = io.MultiWriter(os.Stderr, file)
		}
	}
	logger := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo}))

	httpClient, certHeader, err := buildHTTPClient(cfg)
	if err != nil {
		return fmt.Errorf("TLS: %w", err)
	}
	client := transport.New(httpClient)
	client.ClientCert = certHeader

	lock, err := agent.AcquirePID(filepath.Join(cfg.AgentHome, "agent.pid"))
	if err != nil {
		return fmt.Errorf("lock agente: %w", err)
	}
	defer lock.Release()

	a := agent.New(cfg, identity.NewStore(cfg.TokenFile), client, telemetry.NewCollector(), logger)
	if !serviceMode {
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
	}

	if err := a.EnsureIdentity(ctx); err != nil {
		return fmt.Errorf("identità: %w", err)
	}
	if flagOnce {
		if err := a.RunOnce(ctx); err != nil {
			return fmt.Errorf("ciclo singolo: %w", err)
		}
		return nil
	}
	if err := a.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("agente: %w", err)
	}
	return nil
}

func buildHTTPClient(cfg config.Config) (*http.Client, string, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CACertFile != "" {
		data, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, "", fmt.Errorf("CA bundle: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, "", fmt.Errorf("CA bundle senza certificati PEM: %s", cfg.CACertFile)
		}
		tlsConfig.RootCAs = roots
	}

	keyPath := filepath.Join(cfg.IdentityDir, "device.key")
	certPath := filepath.Join(cfg.IdentityDir, "device.crt")
	header := ""
	if fileExists(certPath) || fileExists(keyPath) {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, "", fmt.Errorf("identità client TLS: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		header, err = certificateFingerprint(certPath)
		if err != nil {
			return nil, "", err
		}
	}

	transportHTTP := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,
	}
	return &http.Client{Timeout: cfg.RequestTimeout, Transport: transportHTTP}, header, nil
}

func certificateFingerprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("certificato client: %w", err)
	}
	fingerprint, err := identity.CertFingerprint(data)
	if err != nil {
		return "", fmt.Errorf("certificato client non PEM: %s: %w", path, err)
	}
	return fingerprint, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func appendServiceError(dir string, err error) {
	path := filepath.Join(dir, "agent.log")
	file, ferr := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if ferr != nil {
		return
	}
	defer file.Close()
	fmt.Fprintf(file, "errore servizio: %v\n", err)
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
	os.Exit(1)
}

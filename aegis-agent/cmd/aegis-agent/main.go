package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
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

func main() {
	var (
		profile     string
		home        string
		configPath  string
		once        bool
		check       bool
		showVersion bool
	)
	flag.StringVar(&profile, "profile", "", "profilo: sensor, endpoint, unified o router")
	flag.StringVar(&home, "home", "", "directory stato agente")
	flag.StringVar(&configPath, "config", "", "path config.json")
	flag.BoolVar(&once, "once", false, "invia un ciclo e termina")
	flag.BoolVar(&check, "check", false, "verifica configurazione e identità senza rete")
	flag.BoolVar(&showVersion, "version", false, "stampa la versione")
	flag.Parse()

	cfg, err := config.Load(config.Options{
		Profile:    profile,
		AgentHome:  home,
		ConfigFile: configPath,
		Version:    buildVersion,
	})
	if err != nil {
		fatal("configurazione", err)
	}
	if showVersion {
		fmt.Println(cfg.Version)
		return
	}
	if check {
		fmt.Printf("profile=%s version=%s home=%s server=%s token=%s\n",
			cfg.Profile, cfg.Version, cfg.AgentHome, cfg.ServerURL, cfg.TokenFile)
		return
	}
	if err := cfg.ValidateNetwork(); err != nil {
		fatal("endpoint", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	httpClient, certHeader, err := buildHTTPClient(cfg)
	if err != nil {
		fatal("TLS", err)
	}
	client := transport.New(httpClient)
	client.ClientCert = certHeader

	lock, err := agent.AcquirePID(filepath.Join(cfg.AgentHome, "agent.pid"))
	if err != nil {
		fatal("lock agente", err)
	}
	defer lock.Release()

	a := agent.New(cfg, identity.NewStore(cfg.TokenFile), client, telemetry.NewCollector(), logger)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := a.EnsureIdentity(ctx); err != nil {
		fatal("identità", err)
	}
	if once {
		if err := a.RunOnce(ctx); err != nil {
			fatal("ciclo singolo", err)
		}
		return
	}
	if err := a.Run(ctx); err != nil {
		fatal("agente", err)
	}
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

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
	os.Exit(1)
}

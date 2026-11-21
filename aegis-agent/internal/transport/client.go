package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPError preserves the status and a bounded body for actionable logs.
type HTTPError struct {
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	body := strings.TrimSpace(e.Body)
	if body == "" {
		return fmt.Sprintf("HTTP %d", e.StatusCode)
	}
	if len(body) > 512 {
		body = body[:512] + "…"
	}
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, body)
}

type Command struct {
	Command         string   `json:"command"`
	DeliveryID      string   `json:"delivery_id,omitempty"`
	AlertID         *int64   `json:"alert_id,omitempty"`
	PID             int      `json:"pid,omitempty"`
	ProcessName     string   `json:"process_name,omitempty"`
	IP              string   `json:"ip,omitempty"`
	Domain          string   `json:"domain,omitempty"`
	DurationSeconds int      `json:"duration_seconds,omitempty"`
	Paths           []string `json:"paths,omitempty"`
	Recursive       *bool    `json:"recursive,omitempty"`
	RulesYARA       string   `json:"rules_yara,omitempty"`
	Targets         []string `json:"targets,omitempty"`
	CIDR            string   `json:"cidr,omitempty"`
	Ports           []int    `json:"ports,omitempty"`
	ProbeTimeout    float64  `json:"probe_timeout,omitempty"`
	URL             string   `json:"url,omitempty"`
	SHA256          string   `json:"sha256,omitempty"`
	Manifest        string   `json:"manifest,omitempty"`
	ManifestSig     string   `json:"manifest_sig,omitempty"`
	Version         string   `json:"version,omitempty"`
}

type Ack struct {
	Command    string `json:"command"`
	Status     string `json:"status"`
	Details    string `json:"details,omitempty"`
	AlertID    *int64 `json:"alert_id,omitempty"`
	DeliveryID string `json:"delivery_id,omitempty"`
}

type RegisterRequest struct {
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	AgentType string `json:"agent_type"`
	EnrollKey string `json:"enroll_key"`
	MachineID string `json:"machine_id,omitempty"`
	OSVersion string `json:"os_version,omitempty"`
	CPUModel  string `json:"cpu_model,omitempty"`
	TotalRAM  int64  `json:"total_ram,omitempty"`
	MAC       string `json:"mac_address,omitempty"`
}

type RegisterResponse struct {
	DeviceID    string `json:"device_id"`
	DeviceToken string `json:"device_token"`
	Status      string `json:"status"`
}

type EnrollGuardRequest struct {
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	AgentType string `json:"agent_type"`
	MachineID string `json:"machine_id,omitempty"`
	EnrollKey string `json:"enroll_key"`
}

type EnrollGuardResponse struct {
	AgentID     string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
}

// Client is a thin JSON transport. It does not know the agent loop; it only
// applies identity, retry policy and error handling consistently.
type Client struct {
	HTTP           *http.Client
	Token          string
	AgentID        string
	ClientCert     string // SHA-256 fingerprint, sent as X-Client-Cert-Hash
	MaxAttempts    int
	RetryBaseDelay time.Duration
}

func New(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{
		HTTP:           httpClient,
		MaxAttempts:    5,
		RetryBaseDelay: time.Second,
	}
}

func (c *Client) SetCredentials(token, agentID, clientCertHeader string) {
	c.Token = token
	c.AgentID = agentID
	c.ClientCert = clientCertHeader
}

func (c *Client) PostJSON(ctx context.Context, endpoint string, payload, out any) error {
	return c.DoJSON(ctx, http.MethodPost, endpoint, payload, out)
}

func (c *Client) DoJSON(ctx context.Context, method, endpoint string, payload, out any) error {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return fmt.Errorf("endpoint vuoto")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal payload: %w", err)
		}
	}

	attempts := c.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
		if err != nil {
			return fmt.Errorf("richiesta HTTP: %w", err)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}
		if c.AgentID != "" {
			req.Header.Set("X-Agent-Id", c.AgentID)
		}
		if c.ClientCert != "" {
			req.Header.Set("X-Client-Cert-Hash", c.ClientCert)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			if attempt == attempts {
				return fmt.Errorf("trasporto: %w", err)
			}
			if err := wait(ctx, c.retryDelay(attempt)); err != nil {
				return err
			}
			continue
		}

		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			if attempt == attempts {
				return fmt.Errorf("lettura risposta: %w", readErr)
			}
			if err := wait(ctx, c.retryDelay(attempt)); err != nil {
				return err
			}
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out != nil && len(data) > 0 {
				if err := json.Unmarshal(data, out); err != nil {
					return fmt.Errorf("decode risposta: %w", err)
				}
			}
			return nil
		}

		httpErr := &HTTPError{StatusCode: resp.StatusCode, Body: string(data)}
		if !retryableStatus(resp.StatusCode) || attempt == attempts {
			return httpErr
		}
		lastErr = httpErr
		if err := wait(ctx, c.retryDelay(attempt)); err != nil {
			return err
		}
	}
	return lastErr
}

func (c *Client) Commands(ctx context.Context, endpoint, deviceID string) ([]Command, error) {
	return c.commandsURL(ctx, endpoint, deviceID)
}

func (c *Client) CommandsBatch(ctx context.Context, endpoint, deviceID string) ([]Command, error) {
	return c.commandsURL(ctx, strings.TrimRight(endpoint, "/")+"/batch", deviceID)
}

func (c *Client) commandsURL(ctx context.Context, endpoint, deviceID string) ([]Command, error) {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return nil, fmt.Errorf("URL comandi: %w", err)
	}
	if deviceID == "" {
		return nil, fmt.Errorf("device_id mancante")
	}
	q := u.Query()
	// Guard's legacy endpoint uses X-Agent-Id; NodeTrace needs device_id.
	if q.Get("agent_id") == "" {
		q.Set("device_id", deviceID)
	}
	q.Set("n", "50")
	u.RawQuery = q.Encode()

	var commands []Command
	if err := c.DoJSON(ctx, http.MethodGet, u.String(), nil, &commands); err != nil {
		return nil, err
	}
	return commands, nil
}

func (c *Client) Ack(ctx context.Context, endpoint string, ack Ack) error {
	return c.PostJSON(ctx, endpoint, ack, nil)
}

func (c *Client) EnrollGuard(ctx context.Context, endpoint string, req EnrollGuardRequest) (EnrollGuardResponse, error) {
	var out EnrollGuardResponse
	if err := c.PostJSON(ctx, endpoint, req, &out); err != nil {
		return EnrollGuardResponse{}, err
	}
	if strings.TrimSpace(out.AgentID) == "" || strings.TrimSpace(out.AgentSecret) == "" {
		return EnrollGuardResponse{}, fmt.Errorf("risposta enrollment Guard incompleta")
	}
	return out, nil
}

func (c *Client) Register(ctx context.Context, endpoint string, req RegisterRequest) (RegisterResponse, error) {
	var out RegisterResponse
	if err := c.PostJSON(ctx, endpoint, req, &out); err != nil {
		return RegisterResponse{}, err
	}
	if strings.TrimSpace(out.DeviceToken) == "" || strings.TrimSpace(out.DeviceID) == "" {
		return RegisterResponse{}, fmt.Errorf("risposta enrollment incompleta")
	}
	return out, nil
}

func retryableStatus(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500
}

func (c *Client) retryDelay(attempt int) time.Duration {
	delay := c.RetryBaseDelay
	if delay <= 0 {
		delay = time.Second
	}
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay > 5*time.Second {
			return 5 * time.Second
		}
	}
	return delay
}

func wait(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Package gluetun is a minimal client for gluetun's HTTP control server,
// covering only the routes the recovery loop needs. Route names and JSON
// shapes were verified against gluetun v3.41.3 (internal/server).
package gluetun

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxBodyBytes = 1 << 20

// Client talks to one control server.
type Client struct {
	// BaseURL like http://127.0.0.1:8000 (no trailing slash).
	BaseURL string
	HTTP    *http.Client
	// APIKey is sent as X-API-Key on every request; empty sends nothing.
	APIKey string
	// RequirePort makes Healthy() demand a forwarded port > 0.
	RequirePort bool
	Timeout     time.Duration
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	t := c.Timeout
	if t == 0 {
		t = 10 * time.Second
	}
	return &http.Client{Timeout: t}
}

func (c *Client) do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	if c.APIKey != "" {
		req.Header.Set("X-API-Key", c.APIKey)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, data, nil
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	code, data, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	if code != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d: %s", path, code, strings.TrimSpace(string(data)))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("GET %s: decoding: %w", path, err)
	}
	return nil
}

// Probe is a snapshot of the tunnel state.
type Probe struct {
	Status      string
	PublicIP    string
	Port        int
	RequirePort bool
	Err         error
}

// Healthy reports whether the VPN is running with a public IP and, when
// required, a forwarded port.
func (p Probe) Healthy() bool {
	if p.Err != nil || p.Status != "running" || p.PublicIP == "" {
		return false
	}
	if p.RequirePort && p.Port <= 0 {
		return false
	}
	return true
}

// EnvLines renders the probe as PIA_PROBE_* shell assignments. Values are
// restricted to characters that are safe inside single quotes.
func (p Probe) EnvLines() string {
	healthy := "0"
	if p.Healthy() {
		healthy = "1"
	}
	errStr := ""
	if p.Err != nil {
		errStr = p.Err.Error()
	}
	var b strings.Builder
	add := func(k, v string) {
		fmt.Fprintf(&b, "PIA_PROBE_%s='%s'\n", k, sanitize(v))
	}
	add("STATUS", p.Status)
	add("PUBLIC_IP", p.PublicIP)
	add("PORT", fmt.Sprint(p.Port))
	add("HEALTHY", healthy)
	add("ERROR", errStr)
	return b.String()
}

func sanitize(v string) string {
	return strings.Map(func(r rune) rune {
		if r == '\'' || r == '\n' || r == '\r' || r < 0x20 {
			return ' '
		}
		return r
	}, v)
}

// Probe queries status, public IP and forwarded port. A transport error is
// returned and also recorded in Probe.Err so the caller can still render it.
func (c *Client) Probe(ctx context.Context) (Probe, error) {
	p := Probe{RequirePort: c.RequirePort}
	var status struct {
		Status string `json:"status"`
	}
	var ip struct {
		PublicIP string `json:"public_ip"`
	}
	var pf struct {
		Port  int   `json:"port"`
		Ports []int `json:"ports"`
	}
	var errs []error
	if err := c.getJSON(ctx, "/v1/vpn/status", &status); err != nil {
		errs = append(errs, err)
	}
	if err := c.getJSON(ctx, "/v1/publicip/ip", &ip); err != nil {
		errs = append(errs, err)
	}
	if err := c.getJSON(ctx, "/v1/portforward", &pf); err != nil {
		errs = append(errs, err)
	}
	p.Status = status.Status
	p.PublicIP = ip.PublicIP
	p.Port = pf.Port
	if p.Port == 0 && len(pf.Ports) > 0 {
		p.Port = pf.Ports[0]
	}
	if len(errs) > 0 {
		p.Err = errors.Join(errs...)
		return p, p.Err
	}
	return p, nil
}

// Apply PUTs a settings body to /v1/vpn/settings and returns the outcome.
func (c *Client) Apply(ctx context.Context, body []byte) (string, error) {
	code, data, err := c.do(ctx, http.MethodPut, "/v1/vpn/settings", body)
	if err != nil {
		return "", fmt.Errorf("PUT /v1/vpn/settings: %w", err)
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("PUT /v1/vpn/settings: HTTP %d: %s", code, strings.TrimSpace(string(data)))
	}
	var out struct {
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("PUT /v1/vpn/settings: decoding: %w", err)
	}
	return out.Outcome, nil
}

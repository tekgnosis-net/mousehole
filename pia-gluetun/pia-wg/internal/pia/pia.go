// Package pia talks to Private Internet Access: token issuance, the server
// list, and WireGuard key registration (addKey). It follows the protocol used
// by https://github.com/pia-foss/manual-connections and depends only on the
// Go standard library.
package pia

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	DefaultTokenURL      = "https://www.privateinternetaccess.com/api/client/v2/token"
	DefaultServerListURL = "https://serverlist.piaservers.net/vpninfo/servers/v6"
	DefaultAddKeyPort    = "1337"
	// PIA tokens are valid for 24h; refresh well before that.
	tokenLifetime    = 24 * time.Hour
	tokenSafetyLimit = 2 * time.Hour
	maxBodyBytes     = 8 << 20
)

//go:embed ca.rsa.4096.crt
var piaCA []byte

// PIARootCAs returns a pool containing PIA's RSA-4096 CA, which signs the
// per-server certificates used on ports 1337 and 19999.
func PIARootCAs() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(piaCA) {
		return nil, errors.New("embedded PIA CA certificate is not valid PEM")
	}
	return pool, nil
}

// Client holds the endpoints and HTTP settings. Zero values fall back to the
// production PIA endpoints.
type Client struct {
	HTTP          *http.Client
	TokenURL      string
	ServerListURL string
	AddKeyPort    string
	RootCAs       *x509.CertPool
	// CacheDir, when set, stores the token between runs (0600).
	CacheDir string
	// Now is overridable for tests.
	Now func() time.Time
	// Timeout bounds every request.
	Timeout time.Duration
	// Bypass routes every connection around the VPN tunnel (see Bypass).
	Bypass Bypass
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	client := &http.Client{Timeout: c.timeout()}
	if c.Bypass.Enabled() {
		d, err := c.Bypass.Dialer(c.timeout())
		if err == nil {
			client.Transport = &http.Transport{DialContext: d.DialContext, ForceAttemptHTTP2: true}
		}
	}
	return client
}

// dialer returns the dialer used for raw connections (addKey).
func (c *Client) dialer() (*net.Dialer, error) {
	if c.Bypass.Enabled() {
		return c.Bypass.Dialer(c.timeout())
	}
	return &net.Dialer{Timeout: c.timeout()}, nil
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 30 * time.Second
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// Keypair is a WireGuard (X25519) keypair, base64 encoded.
type Keypair struct {
	Private string
	Public  string
}

// GenerateKeypair creates a fresh X25519 keypair using crypto/ecdh.
func GenerateKeypair() (Keypair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Keypair{}, fmt.Errorf("generating X25519 key: %w", err)
	}
	return Keypair{
		Private: base64.StdEncoding.EncodeToString(priv.Bytes()),
		Public:  base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}

// Server is one WireGuard server entry from the server list.
type Server struct {
	IP string `json:"ip"`
	CN string `json:"cn"`
}

// Region is the subset of a PIA region we need.
type Region struct {
	ID          string
	Name        string
	PortForward bool
	WG          []Server
}

// Regions is keyed by region ID (e.g. "swiss").
type Regions map[string]Region

type serverListDoc struct {
	Regions []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		PortForward bool   `json:"port_forward"`
		Offline     bool   `json:"offline"`
		Servers     struct {
			WG []Server `json:"wg"`
		} `json:"servers"`
	} `json:"regions"`
}

// ParseServerList parses the v6 server list body. The body is a JSON document
// on the first line followed by a blank line and a base64 signature; only the
// JSON line is used.
func ParseServerList(body []byte) (Regions, error) {
	line := body
	if i := bytes.IndexByte(body, '\n'); i >= 0 {
		line = body[:i]
	}
	var doc serverListDoc
	if err := json.Unmarshal(line, &doc); err != nil {
		return nil, fmt.Errorf("parsing server list JSON: %w", err)
	}
	if len(doc.Regions) == 0 {
		return nil, errors.New("server list has no regions")
	}
	out := make(Regions, len(doc.Regions))
	for _, r := range doc.Regions {
		if r.Offline {
			continue
		}
		out[r.ID] = Region{ID: r.ID, Name: r.Name, PortForward: r.PortForward, WG: r.Servers.WG}
	}
	return out, nil
}

// FetchServerList downloads and parses the server list.
func (c *Client) FetchServerList(ctx context.Context) (Regions, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, orDefault(c.ServerListURL, DefaultServerListURL), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching server list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching server list: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("reading server list: %w", err)
	}
	return ParseServerList(body)
}

// Pick describes how to choose a server within a region.
type Pick struct {
	// PinCN, when set, selects exactly this server (case-insensitive CN).
	PinCN string
	// PinIP is informational; the IP from the current list wins.
	PinIP string
	// Exclude lists CNs to avoid when rolling (best effort).
	Exclude []string
	// PortForwardOnly refuses regions without port forwarding.
	PortForwardOnly bool
}

var ErrPinnedServerGone = errors.New("pinned server is no longer in the server list")

// IsPinnedServerGone reports whether err means the pinned CN vanished.
func IsPinnedServerGone(err error) bool { return errors.Is(err, ErrPinnedServerGone) }

// PickServer selects a WireGuard server in region according to p.
func PickServer(regions Regions, region string, p Pick) (Server, error) {
	r, ok := regions[region]
	if !ok {
		return Server{}, fmt.Errorf("region %q not found in server list", region)
	}
	if p.PortForwardOnly && !r.PortForward {
		return Server{}, fmt.Errorf("region %q does not support port forwarding", region)
	}
	if len(r.WG) == 0 {
		return Server{}, fmt.Errorf("region %q has no WireGuard servers", region)
	}
	if p.PinCN != "" {
		for _, s := range r.WG {
			if strings.EqualFold(s.CN, p.PinCN) {
				return s, nil
			}
		}
		return Server{}, fmt.Errorf("%w: %s", ErrPinnedServerGone, p.PinCN)
	}
	candidates := make([]Server, 0, len(r.WG))
	for _, s := range r.WG {
		if !containsFold(p.Exclude, s.CN) {
			candidates = append(candidates, s)
		}
	}
	if len(candidates) == 0 {
		candidates = r.WG
	}
	return candidates[mathrand.IntN(len(candidates))], nil
}

func containsFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

// GetToken requests a fresh 24h token.
func (c *Client) GetToken(ctx context.Context, username, password string) (string, error) {
	form := url.Values{"username": {username}, "password": {password}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, orDefault(c.TokenURL, DefaultTokenURL),
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http().Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("requesting token: HTTP %d (check PIA_USER/PIA_PASS)", resp.StatusCode)
	}
	var doc struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&doc); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}
	if doc.Token == "" {
		return "", errors.New("token response had an empty token")
	}
	return doc.Token, nil
}

type cachedToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CachedToken returns a token from CacheDir if it has more than the safety
// margin left, otherwise fetches and caches a new one.
func (c *Client) CachedToken(ctx context.Context, username, password string) (string, error) {
	if c.CacheDir == "" {
		return c.GetToken(ctx, username, password)
	}
	path := filepath.Join(c.CacheDir, "token.json")
	if data, err := os.ReadFile(path); err == nil {
		var ct cachedToken
		if json.Unmarshal(data, &ct) == nil && ct.Token != "" && c.now().Before(ct.ExpiresAt.Add(-tokenSafetyLimit)) {
			return ct.Token, nil
		}
	}
	tok, err := c.GetToken(ctx, username, password)
	if err != nil {
		return "", err
	}
	data, _ := json.Marshal(cachedToken{Token: tok, ExpiresAt: c.now().Add(tokenLifetime)})
	if err := os.MkdirAll(c.CacheDir, 0o700); err != nil {
		return "", fmt.Errorf("creating cache dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("writing token cache: %w", err)
	}
	return tok, nil
}

// AddKeyResponse is the JSON returned by /addKey.
type AddKeyResponse struct {
	Status     string   `json:"status"`
	Message    string   `json:"message"`
	ServerKey  string   `json:"server_key"`
	ServerPort int      `json:"server_port"`
	ServerIP   string   `json:"server_ip"`
	ServerVIP  string   `json:"server_vip"`
	PeerIP     string   `json:"peer_ip"`
	PeerPubkey string   `json:"peer_pubkey"`
	DNSServers []string `json:"dns_servers"`
}

// AddKey registers pubkey with the server identified by cn, dialling ip
// directly and verifying the TLS certificate against PIA's CA for cn. The
// token is sent as a query parameter as PIA requires; it is never included in
// returned errors.
func (c *Client) AddKey(ctx context.Context, cn, ip, token, pubkey string) (*AddKeyResponse, error) {
	rootCAs := c.RootCAs
	if rootCAs == nil {
		var err error
		rootCAs, err = PIARootCAs()
		if err != nil {
			return nil, err
		}
	}
	port := orDefault(c.AddKeyPort, DefaultAddKeyPort)
	dialer, err := c.dialer()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: rootCAs, ServerName: cn, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
		},
		ForceAttemptHTTP2: false,
	}
	client := &http.Client{Transport: transport, Timeout: c.timeout()}
	defer transport.CloseIdleConnections()

	q := url.Values{"pt": {token}, "pubkey": {pubkey}}
	u := url.URL{Scheme: "https", Host: net.JoinHostPort(cn, port), Path: "/addKey", RawQuery: q.Encode()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("addKey to %s (%s): %w", cn, ip, redact(err, token))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("addKey reading response: %w", err)
	}
	var out AddKeyResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("addKey to %s: HTTP %d, unparseable body", cn, resp.StatusCode)
	}
	if out.Status != "OK" {
		return nil, fmt.Errorf("addKey to %s: status %q: %s", cn, out.Status, out.Message)
	}
	if out.ServerKey == "" || out.PeerIP == "" || out.ServerPort == 0 {
		return nil, fmt.Errorf("addKey to %s: incomplete response", cn)
	}
	return &out, nil
}

// redact hides the token if a transport error echoes the URL.
func redact(err error, token string) error {
	if token == "" {
		return err
	}
	msg := strings.ReplaceAll(err.Error(), token, "<token>")
	return errors.New(msg)
}

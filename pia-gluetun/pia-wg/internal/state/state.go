// Package state persists the result of a PIA key registration and renders it
// for the two consumers: the shell scripts (KEY='value' lines) and gluetun's
// control server (PUT /v1/vpn/settings JSON body).
package state

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// State is everything needed to connect gluetun to one PIA server.
type State struct {
	Region          string    `json:"region"`
	CN              string    `json:"cn"`
	ServerIP        string    `json:"server_ip"`
	ServerPort      int       `json:"server_port"`
	ServerKey       string    `json:"server_key"`
	ServerVIP       string    `json:"server_vip"`
	PeerIP          string    `json:"peer_ip"`
	PrivateKey      string    `json:"private_key"`
	PublicKey       string    `json:"public_key"`
	DNSServers      []string  `json:"dns_servers"`
	RegisteredAt    time.Time `json:"registered_at"`
	ServerChangedAt time.Time `json:"server_changed_at"`
}

var cnRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// Validate checks every field is well formed. Because the shell scripts
// single-quote these values, this also guarantees they are shell-safe.
func (s State) Validate() error {
	switch {
	case !cnRe.MatchString(s.Region):
		return fmt.Errorf("region %q is not a valid PIA region id", s.Region)
	case !cnRe.MatchString(s.CN):
		return fmt.Errorf("server CN %q contains unexpected characters", s.CN)
	case s.ServerPort <= 0 || s.ServerPort > 65535:
		return fmt.Errorf("server port %d out of range", s.ServerPort)
	}
	for name, ip := range map[string]string{"server_ip": s.ServerIP, "peer_ip": s.PeerIP} {
		if _, err := netip.ParseAddr(ip); err != nil {
			return fmt.Errorf("%s %q is not an IP address", name, ip)
		}
	}
	if s.ServerVIP != "" {
		if _, err := netip.ParseAddr(s.ServerVIP); err != nil {
			return fmt.Errorf("server_vip %q is not an IP address", s.ServerVIP)
		}
	}
	for _, d := range s.DNSServers {
		if _, err := netip.ParseAddr(d); err != nil {
			return fmt.Errorf("dns server %q is not an IP address", d)
		}
	}
	for name, k := range map[string]string{"server_key": s.ServerKey, "private_key": s.PrivateKey, "public_key": s.PublicKey} {
		raw, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(raw) != 32 {
			return fmt.Errorf("%s is not a base64 32-byte key", name)
		}
	}
	if s.RegisteredAt.IsZero() {
		return errors.New("registered_at is unset")
	}
	return nil
}

// Load reads and validates a state file. A missing file returns an error for
// which os.IsNotExist is true.
func Load(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	if err := s.Validate(); err != nil {
		return State{}, fmt.Errorf("invalid %s: %w", path, err)
	}
	return s, nil
}

// Save writes the state atomically with mode 0600.
func (s State) Save(path string) error {
	if err := s.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func shellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

// EnvLines renders the state as POSIX-sh assignments safe to `.`-source.
// The public key is intentionally omitted; nothing in the shell needs it.
func (s State) EnvLines() string {
	var b strings.Builder
	add := func(k, v string) {
		b.WriteString("PIA_WG_")
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(shellQuote(v))
		b.WriteByte('\n')
	}
	add("REGION", s.Region)
	add("CN", s.CN)
	add("SERVER_IP", s.ServerIP)
	add("SERVER_PORT", fmt.Sprint(s.ServerPort))
	add("SERVER_KEY", s.ServerKey)
	add("SERVER_VIP", s.ServerVIP)
	add("PEER_IP", s.PeerIP)
	add("PRIVATE_KEY", s.PrivateKey)
	add("DNS", strings.Join(s.DNSServers, ","))
	add("REGISTERED_AT", s.RegisteredAt.UTC().Format(time.RFC3339))
	add("SERVER_CHANGED_AT", s.ServerChangedAt.UTC().Format(time.RFC3339))
	add("SERVER_CHANGED_EPOCH", fmt.Sprint(s.ServerChangedAt.Unix()))
	return b.String()
}

// GluetunSettingsJSON renders the PUT /v1/vpn/settings body. Field names match
// gluetun v3.41.x `internal/configuration/settings` JSON tags. Only the fields
// that change are sent; gluetun merges them over its live settings.
func (s State) GluetunSettingsJSON() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	body := map[string]any{
		"type": "wireguard",
		"provider": map[string]any{
			"name": "custom",
			"server_selection": map[string]any{
				"vpn":   "wireguard",
				"names": []string{s.CN},
				"wireguard": map[string]any{
					"endpoint_ip":   s.ServerIP,
					"endpoint_port": s.ServerPort,
					"public_key":    s.ServerKey,
				},
			},
		},
		"wireguard": map[string]any{
			"private_key": s.PrivateKey,
			"addresses":   []string{s.PeerIP + "/32"},
		},
	}
	return json.Marshal(body)
}

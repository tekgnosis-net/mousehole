package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sample() State {
	return State{
		Region:          "swiss",
		CN:              "zurich401",
		ServerIP:        "156.146.62.1",
		ServerPort:      1337,
		ServerKey:       "HZ9LQerrZabnO9CzMqzaHNm6x+8SvrHjhXHDgUgQl9U=",
		ServerVIP:       "10.11.128.1",
		PeerIP:          "10.11.112.5",
		PrivateKey:      "vHSLuTgFKu4w2Gakkuu6KdFG+qlRn+bj1HNJyFWzrjc=",
		PublicKey:       "VfHI8L6VCTQHRPqkU2oPbynOTTLKCfDivvDLen3fnfI=",
		DNSServers:      []string{"10.0.0.243", "10.0.0.242"},
		RegisteredAt:    time.Date(2026, 9, 16, 1, 2, 3, 0, time.UTC),
		ServerChangedAt: time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC),
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := sample()
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("perm %v", info.Mode().Perm())
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.CN != s.CN || got.PrivateKey != s.PrivateKey || !got.RegisteredAt.Equal(s.RegisteredAt) {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if !os.IsNotExist(err) {
		t.Fatalf("expected not-exist, got %v", err)
	}
}

func TestValidate(t *testing.T) {
	s := sample()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := sample()
	bad.CN = "evil'; rm -rf /"
	if err := bad.Validate(); err == nil {
		t.Fatal("expected CN validation error")
	}
	bad = sample()
	bad.PeerIP = "not-an-ip"
	if err := bad.Validate(); err == nil {
		t.Fatal("expected IP validation error")
	}
	bad = sample()
	bad.PrivateKey = "short"
	if err := bad.Validate(); err == nil {
		t.Fatal("expected key validation error")
	}
}

func TestEnvLines(t *testing.T) {
	s := sample()
	out := s.EnvLines()
	want := []string{
		"PIA_WG_REGION='swiss'",
		"PIA_WG_CN='zurich401'",
		"PIA_WG_SERVER_IP='156.146.62.1'",
		"PIA_WG_SERVER_PORT='1337'",
		"PIA_WG_SERVER_KEY='HZ9LQerrZabnO9CzMqzaHNm6x+8SvrHjhXHDgUgQl9U='",
		"PIA_WG_SERVER_VIP='10.11.128.1'",
		"PIA_WG_PEER_IP='10.11.112.5'",
		"PIA_WG_PRIVATE_KEY='vHSLuTgFKu4w2Gakkuu6KdFG+qlRn+bj1HNJyFWzrjc='",
		"PIA_WG_DNS='10.0.0.243,10.0.0.242'",
		"PIA_WG_REGISTERED_AT='2026-09-16T01:02:03Z'",
		"PIA_WG_SERVER_CHANGED_AT='2026-09-15T00:00:00Z'",
		"PIA_WG_SERVER_CHANGED_EPOCH='1789430400'",
	}
	for _, w := range want {
		if !strings.Contains(out, w+"\n") {
			t.Errorf("missing line %q in:\n%s", w, out)
		}
	}
	if strings.Contains(out, s.PublicKey) {
		t.Error("public key is not needed by the shell and should not be exported")
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("it's"); got != `'it'\''s'` {
		t.Fatalf("got %s", got)
	}
}

func TestGluetunSettingsJSON(t *testing.T) {
	s := sample()
	data, err := s.GluetunSettingsJSON()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	provider := doc["provider"].(map[string]any)
	sel := provider["server_selection"].(map[string]any)
	if names := sel["names"].([]any); len(names) != 1 || names[0] != "zurich401" {
		t.Fatalf("names %v", names)
	}
	wgSel := sel["wireguard"].(map[string]any)
	if wgSel["endpoint_ip"] != "156.146.62.1" || wgSel["endpoint_port"] != float64(1337) || wgSel["public_key"] != s.ServerKey {
		t.Fatalf("wireguard selection %v", wgSel)
	}
	wg := doc["wireguard"].(map[string]any)
	if wg["private_key"] != s.PrivateKey {
		t.Fatal("private key missing")
	}
	if addrs := wg["addresses"].([]any); len(addrs) != 1 || addrs[0] != "10.11.112.5/32" {
		t.Fatalf("addresses %v", addrs)
	}
	if _, ok := doc["openvpn"]; ok {
		t.Fatal("openvpn block must be omitted so it is not overridden")
	}
}

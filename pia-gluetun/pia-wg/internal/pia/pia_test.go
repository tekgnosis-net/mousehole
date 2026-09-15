package pia

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateKeypair(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{kp.Private, kp.Public} {
		raw, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(raw) != 32 {
			t.Fatalf("key %q is not 32 raw bytes base64: %v", k, err)
		}
	}
	if kp.Private == kp.Public {
		t.Fatal("private and public keys are equal")
	}
}

func TestParseServerList(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "serverlist_v6.txt"))
	if err != nil {
		t.Fatal(err)
	}
	regions, err := ParseServerList(data)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := regions["swiss"]
	if !ok {
		t.Fatalf("region swiss missing, got %v", keys(regions))
	}
	if !r.PortForward {
		t.Fatal("swiss should support port forwarding")
	}
	if len(r.WG) != 3 {
		t.Fatalf("expected 3 wg servers, got %d", len(r.WG))
	}
	if r.WG[0].CN != "zurich401" || r.WG[0].IP != "156.146.62.1" {
		t.Fatalf("unexpected first server %+v", r.WG[0])
	}
	if regions["nl_amsterdam"].PortForward {
		t.Fatal("nl_amsterdam should not support port forwarding in fixture")
	}
}

func TestParseServerListRejectsGarbage(t *testing.T) {
	if _, err := ParseServerList([]byte("not json\n")); err == nil {
		t.Fatal("expected error")
	}
}

func TestPickServer(t *testing.T) {
	regions := Regions{
		"swiss": {ID: "swiss", PortForward: true, WG: []Server{
			{CN: "a", IP: "10.0.0.1"}, {CN: "b", IP: "10.0.0.2"}, {CN: "c", IP: "10.0.0.3"},
		}},
		"nopf": {ID: "nopf", PortForward: false, WG: []Server{{CN: "x", IP: "10.0.1.1"}}},
	}

	t.Run("pinned CN wins and takes list IP", func(t *testing.T) {
		s, err := PickServer(regions, "swiss", Pick{PinCN: "B", PinIP: "1.2.3.4", PortForwardOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		if s.CN != "b" || s.IP != "10.0.0.2" {
			t.Fatalf("got %+v", s)
		}
	})
	t.Run("pinned CN unlisted but IP known is honoured", func(t *testing.T) {
		s, err := PickServer(regions, "swiss", Pick{PinCN: "zzz", PinIP: "9.9.9.9", PortForwardOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		if s.CN != "zzz" || s.IP != "9.9.9.9" || !s.Unlisted() {
			t.Fatalf("got %+v", s)
		}
	})
	t.Run("pinned CN listed wins over pinned IP", func(t *testing.T) {
		s, _ := PickServer(regions, "swiss", Pick{PinCN: "a", PinIP: "9.9.9.9"})
		if s.IP != "10.0.0.1" || s.Unlisted() {
			t.Fatalf("got %+v", s)
		}
	})
	t.Run("pinned CN gone without IP", func(t *testing.T) {
		_, err := PickServer(regions, "swiss", Pick{PinCN: "zzz", PortForwardOnly: true})
		if err == nil || !IsPinnedServerGone(err) {
			t.Fatalf("expected ErrPinnedServerGone, got %v", err)
		}
	})
	t.Run("exclude", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			s, err := PickServer(regions, "swiss", Pick{Exclude: []string{"a", "b"}, PortForwardOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			if s.CN != "c" {
				t.Fatalf("exclusion ignored: %+v", s)
			}
		}
	})
	t.Run("all excluded falls back to any", func(t *testing.T) {
		s, err := PickServer(regions, "swiss", Pick{Exclude: []string{"a", "b", "c"}, PortForwardOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		if s.CN == "" {
			t.Fatal("expected some server")
		}
	})
	t.Run("no port forwarding", func(t *testing.T) {
		if _, err := PickServer(regions, "nopf", Pick{PortForwardOnly: true}); err == nil {
			t.Fatal("expected error")
		}
		if _, err := PickServer(regions, "nopf", Pick{PortForwardOnly: false}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unknown region", func(t *testing.T) {
		if _, err := PickServer(regions, "mars", Pick{}); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestGetToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.PostForm.Get("username") != "p123" || r.PostForm.Get("password") != "s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"token":"tok123"}`))
	}))
	defer srv.Close()

	c := &Client{HTTP: srv.Client(), TokenURL: srv.URL}
	tok, err := c.GetToken(context.Background(), "p123", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok123" {
		t.Fatalf("token %q", tok)
	}
	if _, err := c.GetToken(context.Background(), "p123", "wrong"); err == nil {
		t.Fatal("expected error for bad creds")
	}
}

func TestTokenCache(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"token":"fresh"}`))
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), TokenURL: srv.URL, CacheDir: dir}

	now := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return now }

	tok, err := c.CachedToken(context.Background(), "u", "p")
	if err != nil || tok != "fresh" || calls != 1 {
		t.Fatalf("first: %v %q calls=%d", err, tok, calls)
	}
	tok, err = c.CachedToken(context.Background(), "u", "p")
	if err != nil || tok != "fresh" || calls != 1 {
		t.Fatalf("second should hit cache: %v %q calls=%d", err, tok, calls)
	}
	// Advance past the safety margin.
	c.Now = func() time.Time { return now.Add(24 * time.Hour) }
	_, err = c.CachedToken(context.Background(), "u", "p")
	if err != nil || calls != 2 {
		t.Fatalf("expired cache should refetch: %v calls=%d", err, calls)
	}
	info, err := os.Stat(filepath.Join(dir, "token.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token cache perm %v", info.Mode().Perm())
	}
}

func TestAddKey(t *testing.T) {
	var gotQuery url.Values
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/addKey" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotQuery = r.URL.Query()
		_, _ = w.Write([]byte(`{"status":"OK","server_key":"SKEY","server_port":1337,` +
			`"server_ip":"127.0.0.1","server_vip":"10.11.128.1","peer_ip":"10.11.112.5",` +
			`"peer_pubkey":"PUB","dns_servers":["10.0.0.243","10.0.0.242"]}`))
	}))
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	u, _ := url.Parse(srv.URL)
	c := &Client{RootCAs: pool, AddKeyPort: u.Port()}

	// httptest certificates are valid for "example.com" and 127.0.0.1.
	res, err := c.AddKey(context.Background(), "example.com", "127.0.0.1", "tok", "PUB")
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery.Get("pt") != "tok" || gotQuery.Get("pubkey") != "PUB" {
		t.Fatalf("query %v", gotQuery)
	}
	if res.ServerKey != "SKEY" || res.PeerIP != "10.11.112.5" || res.ServerPort != 1337 || res.ServerVIP != "10.11.128.1" {
		t.Fatalf("resp %+v", res)
	}

	// Wrong CN must fail TLS verification even though the IP is right, and
	// the error must not echo the token that is part of the URL.
	const secret = "SECRET-TOKEN-XYZ"
	if _, err := c.AddKey(context.Background(), "wrong.example.net", "127.0.0.1", secret, "PUB"); err == nil {
		t.Fatal("expected TLS failure for wrong CN")
	} else if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks token: %v", err)
	}
}

func TestAddKeyRejectsNonOK(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ERROR","message":"Login failed!"}`))
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	u, _ := url.Parse(srv.URL)
	c := &Client{RootCAs: pool, AddKeyPort: u.Port()}
	_, err := c.AddKey(context.Background(), "example.com", "127.0.0.1", "tok", "PUB")
	if err == nil || !strings.Contains(err.Error(), "Login failed") {
		t.Fatalf("expected status error, got %v", err)
	}
}

func TestEmbeddedCA(t *testing.T) {
	pool, err := PIARootCAs()
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("nil pool")
	}
}

func keys(m Regions) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

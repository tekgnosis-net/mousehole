package main

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tekgnosis-net/mousehole/pia-gluetun/pia-wg/internal/state"
)

// fakePIA stands up token, server-list and addKey endpoints. The addKey
// server is TLS; its certificate is valid for example.com / 127.0.0.1, so the
// fixture region advertises cn=example.com ip=127.0.0.1.
type fakePIA struct {
	token, list, addKey *httptest.Server
	addKeyCalls         int
	listCNs             []string
}

func newFakePIA(t *testing.T) *fakePIA {
	t.Helper()
	f := &fakePIA{listCNs: []string{"example.com"}}
	f.token = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("username") != "p1" || r.PostForm.Get("password") != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"token":"T"}`))
	}))
	f.list = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var servers []string
		for _, cn := range f.listCNs {
			servers = append(servers, fmt.Sprintf(`{"ip":"127.0.0.1","cn":"%s"}`, cn))
		}
		fmt.Fprintf(w, `{"regions":[{"id":"test","name":"Test","port_forward":true,"offline":false,"servers":{"wg":[%s]}}]}`+"\n\nc2ln\n",
			strings.Join(servers, ","))
	}))
	f.addKey = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.addKeyCalls++
		if r.URL.Query().Get("pt") != "T" {
			_, _ = w.Write([]byte(`{"status":"ERROR","message":"bad token"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"OK","server_key":"HZ9LQerrZabnO9CzMqzaHNm6x+8SvrHjhXHDgUgQl9U=",` +
			`"server_port":1337,"server_ip":"127.0.0.1","server_vip":"10.9.128.1","peer_ip":"10.9.112.7",` +
			`"peer_pubkey":"x","dns_servers":["10.0.0.243"]}`))
	}))
	t.Cleanup(func() { f.token.Close(); f.list.Close(); f.addKey.Close() })
	return f
}

func (f *fakePIA) addKeyPort() string {
	u, _ := url.Parse(f.addKey.URL)
	return u.Port()
}

func TestRegisterEndToEnd(t *testing.T) {
	f := newFakePIA(t)
	dir := t.TempDir()
	t.Setenv("PIA_USER", "p1")
	t.Setenv("PIA_PASS", "pw")

	// Trust the httptest certificate for this process.
	restore := overrideRootCAs(t, f.addKey.Certificate())
	defer restore()

	stdout := captureStdout(t, func() {
		code := run([]string{"register", "--region", "test", "--state-dir", dir,
			"--serverlist-url", f.list.URL, "--token-url", f.token.URL, "--addkey-port", f.addKeyPort()})
		if code != exitOK {
			t.Fatalf("register exit %d", code)
		}
	})
	for _, want := range []string{"PIA_WG_CN='example.com'", "PIA_WG_PEER_IP='10.9.112.7'", "PIA_WG_SERVER_PORT='1337'"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %s:\n%s", want, stdout)
		}
	}
	st, err := state.Load(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if st.CN != "example.com" || st.PrivateKey == "" {
		t.Fatalf("state %+v", st)
	}
	first := st.ServerChangedAt

	// Re-register pinned to the same CN: server_changed_at must be preserved
	// and the token must come from the cache (no second token call needed).
	_ = captureStdout(t, func() {
		code := run([]string{"register", "--region", "test", "--state-dir", dir, "--pin-cn", "EXAMPLE.COM",
			"--serverlist-url", f.list.URL, "--token-url", f.token.URL, "--addkey-port", f.addKeyPort()})
		if code != exitOK {
			t.Fatalf("pinned register exit %d", code)
		}
	})
	st2, _ := state.Load(filepath.Join(dir, "state.json"))
	if !st2.ServerChangedAt.Equal(first) {
		t.Fatal("server_changed_at should be preserved when the CN is unchanged")
	}
	if st2.PrivateKey == st.PrivateKey {
		t.Fatal("a new keypair must be generated on every registration")
	}

	// Pinned CN absent from the list sample but with a known IP: still used.
	f.listCNs = []string{"other.example.com"}
	_ = captureStdout(t, func() {
		code := run([]string{"register", "--region", "test", "--state-dir", dir, "--pin-cn", "example.com", "--pin-ip", "127.0.0.1",
			"--serverlist-url", f.list.URL, "--token-url", f.token.URL, "--addkey-port", f.addKeyPort()})
		if code != exitOK {
			t.Fatalf("unlisted pin with known IP should register, exit %d", code)
		}
	})
	st3, _ := state.Load(filepath.Join(dir, "state.json"))
	if st3.CN != "example.com" || !st3.ServerChangedAt.Equal(first) {
		t.Fatalf("unlisted pin changed server: %+v", st3)
	}

	// Pinned CN absent, known IP does not answer -> distinct exit code.
	code := run([]string{"register", "--region", "test", "--state-dir", dir, "--pin-cn", "example.com", "--pin-ip", "127.0.0.1",
		"--serverlist-url", f.list.URL, "--token-url", f.token.URL, "--addkey-port", "1", "--timeout", "2s"})
	if code != exitPinnedGone {
		t.Fatalf("expected exit %d for dead unlisted pin, got %d", exitPinnedGone, code)
	}

	// Pinned CN absent and no IP known -> distinct exit code.
	code = run([]string{"register", "--region", "test", "--state-dir", dir, "--pin-cn", "example.com",
		"--serverlist-url", f.list.URL, "--token-url", f.token.URL, "--addkey-port", f.addKeyPort()})
	if code != exitPinnedGone {
		t.Fatalf("expected exit %d for vanished pin, got %d", exitPinnedGone, code)
	}

	// state prints the same env lines the register command did.
	out := captureStdout(t, func() {
		if code := run([]string{"state", "--state-dir", dir}); code != exitOK {
			t.Fatalf("state exit %d", code)
		}
	})
	if !strings.Contains(out, "PIA_WG_CN='example.com'\n") {
		t.Fatalf("state output: %s", out)
	}

	// gluetun-settings reads the same state.
	out = captureStdout(t, func() {
		if code := run([]string{"gluetun-settings", "--state-dir", dir}); code != exitOK {
			t.Fatalf("gluetun-settings exit %d", code)
		}
	})
	if !strings.Contains(out, `"names":["example.com"]`) || !strings.Contains(out, `"addresses":["10.9.112.7/32"]`) {
		t.Fatalf("settings json: %s", out)
	}
}

func TestRegisterRequiresCredentials(t *testing.T) {
	t.Setenv("PIA_USER", "")
	t.Setenv("PIA_PASS", "")
	if code := run([]string{"register", "--region", "test", "--state-dir", t.TempDir()}); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
}

func TestCredentialFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pass")
	if err := os.WriteFile(p, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PIA_PASS", "")
	t.Setenv("PIA_PASS_FILE", p)
	v, err := credential("PIA_PASS")
	if err != nil || v != "from-file" {
		t.Fatalf("%q %v", v, err)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		done <- buf.String()
	}()
	fn()
	_ = w.Close()
	os.Stdout = old
	return <-done
}

func overrideRootCAs(t *testing.T, cert *x509.Certificate) func() {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	prev := testRootCAs
	testRootCAs = pool
	return func() { testRootCAs = prev }
}

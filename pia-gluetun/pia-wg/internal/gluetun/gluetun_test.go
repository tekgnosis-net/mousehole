package gluetun

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/vpn/status":
			_, _ = w.Write([]byte(`{"status":"running"}`))
		case "/v1/publicip/ip":
			_, _ = w.Write([]byte(`{"public_ip":"195.177.93.76","country":"Switzerland"}`))
		case "/v1/portforward":
			_, _ = w.Write([]byte(`{"port":45123,"ports":[45123]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	p, err := c.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != "running" || p.PublicIP != "195.177.93.76" || p.Port != 45123 {
		t.Fatalf("probe %+v", p)
	}
	lines := p.EnvLines()
	for _, w := range []string{"STATUS='running'", "PUBLIC_IP='195.177.93.76'", "PORT='45123'", "HEALTHY='1'"} {
		if !strings.Contains(lines, "PIA_PROBE_"+w+"\n") {
			t.Errorf("missing %s in %q", w, lines)
		}
	}
}

func TestProbeUnhealthyCases(t *testing.T) {
	cases := []struct {
		name          string
		status, ip    string
		port          string
		wantHealthy   bool
		requirePort   bool
		wantErrSubstr string
	}{
		{"port zero", `{"status":"running"}`, `{"public_ip":"1.2.3.4"}`, `{"port":0,"ports":[]}`, false, true, ""},
		{"port zero but not required", `{"status":"running"}`, `{"public_ip":"1.2.3.4"}`, `{"port":0,"ports":[]}`, true, false, ""},
		{"stopped", `{"status":"stopped"}`, `{"public_ip":""}`, `{"port":0}`, false, true, ""},
		{"empty ip", `{"status":"running"}`, `{"public_ip":""}`, `{"port":1}`, false, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/vpn/status":
					_, _ = io.WriteString(w, tc.status)
				case "/v1/publicip/ip":
					_, _ = io.WriteString(w, tc.ip)
				case "/v1/portforward":
					_, _ = io.WriteString(w, tc.port)
				}
			}))
			defer srv.Close()
			c := &Client{BaseURL: srv.URL, HTTP: srv.Client(), RequirePort: tc.requirePort}
			p, err := c.Probe(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if p.Healthy() != tc.wantHealthy {
				t.Fatalf("healthy=%v want %v (%+v)", p.Healthy(), tc.wantHealthy, p)
			}
		})
	}
}

func TestProbeServerDown(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1", HTTP: &http.Client{}}
	p, err := c.Probe(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if p.Healthy() {
		t.Fatal("must not be healthy")
	}
	// EnvLines must still be printable so the shell can act on it.
	if !strings.Contains(p.EnvLines(), "PIA_PROBE_HEALTHY='0'\n") {
		t.Fatal("expected HEALTHY=0")
	}
}

func TestApply(t *testing.T) {
	var gotMethod, gotKey, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/vpn/settings" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotMethod = r.Method
		gotKey = r.Header.Get("X-API-Key")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		if gotKey != "k3y" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"outcome":"success"}`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTP: srv.Client(), APIKey: "k3y"}
	outcome, err := c.Apply(context.Background(), []byte(`{"type":"wireguard"}`))
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPut || gotBody != `{"type":"wireguard"}` || outcome != "success" {
		t.Fatalf("method=%s body=%s outcome=%s", gotMethod, gotBody, outcome)
	}

	c.APIKey = "wrong"
	if _, err := c.Apply(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("expected 401 error")
	}
}

func TestApplyRejectsNonSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"validating settings: bad key"}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client(), APIKey: "k"}
	_, err := c.Apply(context.Background(), []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "bad key") {
		t.Fatalf("expected error containing body, got %v", err)
	}
}

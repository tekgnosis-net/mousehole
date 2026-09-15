package pia

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeDNS answers every A query with 127.0.0.1 and counts queries.
func fakeDNS(t *testing.T) (addr string, queries *int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	n := 0
	queries = &n
	go func() {
		buf := make([]byte, 512)
		for {
			ln, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			n++
			q := buf[:ln]
			if len(q) < 12 {
				continue
			}
			// Question ends after the name (null byte) + 4 bytes type/class.
			end := 12
			for end < len(q) && q[end] != 0 {
				end += int(q[end]) + 1
			}
			end += 1 + 4
			if end > len(q) {
				continue
			}
			resp := make([]byte, 0, end+16)
			resp = append(resp, q[0], q[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
			resp = append(resp, q[12:end]...)
			resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1)
			_, _ = pc.WriteTo(resp, from)
		}
	}()
	return pc.LocalAddr().String(), queries
}

func TestBypassResolverUsesConfiguredDNS(t *testing.T) {
	dnsAddr, queries := fakeDNS(t)
	b := Bypass{DNS: []string{"127.0.0.1:1", dnsAddr}} // first server is dead
	d, err := b.Dialer(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := d.Resolver.LookupHost(ctx, "token.pia.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "127.0.0.1" {
		t.Fatalf("ips %v", ips)
	}
	if *queries == 0 {
		t.Fatal("fake DNS was not consulted")
	}
}

func TestBypassHTTPThroughCustomResolver(t *testing.T) {
	dnsAddr, _ := fakeDNS(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token":"via-bypass"}`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	_, port, _ := net.SplitHostPort(u.Host)

	c := &Client{TokenURL: "http://token.pia.test:" + port, Bypass: Bypass{DNS: []string{dnsAddr}}}
	tok, err := c.GetToken(context.Background(), "u", "p")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "via-bypass" {
		t.Fatalf("token %q", tok)
	}
}

func TestBypassRejectsBadDNS(t *testing.T) {
	if _, err := (Bypass{DNS: []string{"1.1.1.1"}}).Dialer(time.Second); err == nil {
		t.Fatal("expected error for missing port")
	}
}

func TestBypassMarkSetsControl(t *testing.T) {
	d, err := (Bypass{Mark: 51820}).Dialer(time.Second)
	if err != nil {
		if strings.Contains(err.Error(), "only supported on Linux") {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	if d.Control == nil {
		t.Fatal("expected a Control function when a mark is set")
	}
	// Actually applying SO_MARK needs CAP_NET_ADMIN; only verify the
	// error surfaces cleanly when we are unprivileged, or the dial works
	// when we are root.
	conn, err := d.DialContext(context.Background(), "udp", "127.0.0.1:9")
	if err != nil {
		if !strings.Contains(err.Error(), "SO_MARK") {
			t.Fatalf("unexpected error: %v", err)
		}
		t.Logf("unprivileged: %v", err)
		return
	}
	_ = conn.Close()
}

func TestBypassDisabledByDefault(t *testing.T) {
	if (Bypass{}).Enabled() {
		t.Fatal("zero Bypass must be disabled")
	}
}

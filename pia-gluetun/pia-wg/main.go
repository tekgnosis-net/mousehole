// Command pia-wg registers WireGuard keys with Private Internet Access and
// talks to gluetun's control server. It is the only binary added to the
// pia-gluetun image; the shell scripts call it and source its output.
//
// Subcommands:
//
//	register          choose a server, register a fresh key, write state
//	gluetun-settings  print the PUT /v1/vpn/settings JSON for the saved state
//	state             print the saved state as PIA_WG_* shell assignments
//	probe             print PIA_PROBE_* lines describing tunnel health
//	apply             PUT the saved state to gluetun's control server
//	version           print the version
//
// Credentials are read only from PIA_USER and PIA_PASS (or *_FILE variants).
// Keys and tokens are never logged.
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tekgnosis-net/mousehole/pia-gluetun/pia-wg/internal/gluetun"
	"github.com/tekgnosis-net/mousehole/pia-gluetun/pia-wg/internal/pia"
	"github.com/tekgnosis-net/mousehole/pia-gluetun/pia-wg/internal/state"
)

var version = "dev"

// testRootCAs, when non-nil, replaces the embedded PIA CA. Tests only.
var testRootCAs *x509.CertPool

const (
	exitOK         = 0
	exitError      = 1
	exitPinnedGone = 3 // register: pinned server vanished from the list
	exitUsage      = 2
)

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s [pia-wg] %s\n", time.Now().UTC().Format("2006-01-02T15:04:05Z"), fmt.Sprintf(format, args...))
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return exitUsage
	}
	switch args[0] {
	case "register":
		return cmdRegister(args[1:])
	case "gluetun-settings":
		return cmdSettings(args[1:])
	case "state":
		return cmdState(args[1:])
	case "probe":
		return cmdProbe(args[1:])
	case "apply":
		return cmdApply(args[1:])
	case "version":
		fmt.Println(version)
		return exitOK
	case "-h", "--help", "help":
		usage()
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", args[0])
		usage()
		return exitUsage
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: pia-wg <register|gluetun-settings|state|probe|apply|version> [flags]")
}

// credential reads NAME or the file named by NAME_FILE.
func credential(name string) (string, error) {
	if v := os.Getenv(name); v != "" {
		return v, nil
	}
	if p := os.Getenv(name + "_FILE"); p != "" {
		data, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("reading %s_FILE: %w", name, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return "", fmt.Errorf("%s (or %s_FILE) is not set", name, name)
}

func cmdRegister(args []string) int {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	region := fs.String("region", "", "PIA region id, e.g. swiss (required)")
	stateDir := fs.String("state-dir", "/gluetun/pia", "directory for state.json and token cache")
	pinCN := fs.String("pin-cn", "", "reconnect to this server CN if it is still listed")
	pinIP := fs.String("pin-ip", "", "last known IP of the pinned server (informational)")
	exclude := fs.String("exclude-cn", "", "comma-separated CNs to avoid when choosing a new server")
	pfOnly := fs.Bool("port-forward-only", true, "refuse regions without port forwarding")
	format := fs.String("format", "env", "output format: env or json")
	timeout := fs.Duration("timeout", 30*time.Second, "per-request timeout")
	serverListURL := fs.String("serverlist-url", pia.DefaultServerListURL, "server list URL (testing)")
	tokenURL := fs.String("token-url", pia.DefaultTokenURL, "token URL (testing)")
	addKeyPort := fs.String("addkey-port", pia.DefaultAddKeyPort, "addKey TLS port (testing)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *region == "" {
		logf("--region is required")
		return exitUsage
	}
	user, err := credential("PIA_USER")
	if err != nil {
		logf("%v", err)
		return exitUsage
	}
	pass, err := credential("PIA_PASS")
	if err != nil {
		logf("%v", err)
		return exitUsage
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*(*timeout))
	defer cancel()

	client := &pia.Client{
		RootCAs:       testRootCAs,
		TokenURL:      *tokenURL,
		ServerListURL: *serverListURL,
		AddKeyPort:    *addKeyPort,
		CacheDir:      *stateDir,
		Timeout:       *timeout,
	}

	regions, err := client.FetchServerList(ctx)
	if err != nil {
		logf("%v", err)
		return exitError
	}
	pick := pia.Pick{PinCN: *pinCN, PinIP: *pinIP, PortForwardOnly: *pfOnly}
	if *exclude != "" {
		pick.Exclude = strings.Split(*exclude, ",")
	}
	server, err := pia.PickServer(regions, *region, pick)
	if err != nil {
		logf("%v", err)
		if pia.IsPinnedServerGone(err) {
			return exitPinnedGone
		}
		return exitError
	}
	if *pinCN != "" && *pinIP != "" && server.IP != *pinIP {
		logf("pinned server %s changed IP %s -> %s", server.CN, *pinIP, server.IP)
	}

	token, err := client.CachedToken(ctx, user, pass)
	if err != nil {
		logf("%v", err)
		return exitError
	}
	kp, err := pia.GenerateKeypair()
	if err != nil {
		logf("%v", err)
		return exitError
	}
	res, err := client.AddKey(ctx, server.CN, server.IP, token, kp.Public)
	if err != nil {
		logf("%v", err)
		return exitError
	}

	now := time.Now().UTC()
	st := state.State{
		Region:          *region,
		CN:              server.CN,
		ServerIP:        server.IP,
		ServerPort:      res.ServerPort,
		ServerKey:       res.ServerKey,
		ServerVIP:       res.ServerVIP,
		PeerIP:          res.PeerIP,
		PrivateKey:      kp.Private,
		PublicKey:       kp.Public,
		DNSServers:      res.DNSServers,
		RegisteredAt:    now,
		ServerChangedAt: now,
	}
	statePath := filepath.Join(*stateDir, "state.json")
	if prev, err := state.Load(statePath); err == nil && strings.EqualFold(prev.CN, st.CN) {
		st.ServerChangedAt = prev.ServerChangedAt
	}
	if err := st.Save(statePath); err != nil {
		logf("saving state: %v", err)
		return exitError
	}
	logf("registered key with %s (%s:%d) region=%s peer_ip=%s vip=%s",
		st.CN, st.ServerIP, st.ServerPort, st.Region, st.PeerIP, st.ServerVIP)

	switch *format {
	case "env":
		fmt.Print(st.EnvLines())
	case "json":
		data, _ := os.ReadFile(statePath)
		fmt.Print(string(data))
	default:
		logf("unknown --format %q", *format)
		return exitUsage
	}
	return exitOK
}

func cmdSettings(args []string) int {
	fs := flag.NewFlagSet("gluetun-settings", flag.ContinueOnError)
	stateDir := fs.String("state-dir", "/gluetun/pia", "directory containing state.json")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	st, err := state.Load(filepath.Join(*stateDir, "state.json"))
	if err != nil {
		logf("%v", err)
		return exitError
	}
	body, err := st.GluetunSettingsJSON()
	if err != nil {
		logf("%v", err)
		return exitError
	}
	fmt.Println(string(body))
	return exitOK
}

func cmdState(args []string) int {
	fs := flag.NewFlagSet("state", flag.ContinueOnError)
	stateDir := fs.String("state-dir", "/gluetun/pia", "directory containing state.json")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	st, err := state.Load(filepath.Join(*stateDir, "state.json"))
	if err != nil {
		logf("%v", err)
		return exitError
	}
	fmt.Print(st.EnvLines())
	return exitOK
}

func controlFlags(fs *flag.FlagSet) (control *string, apiKeyFile *string, timeout *time.Duration) {
	control = fs.String("control", "http://127.0.0.1:8000", "gluetun control server base URL")
	apiKeyFile = fs.String("api-key-file", "", "file containing the X-API-Key value")
	timeout = fs.Duration("timeout", 10*time.Second, "per-request timeout")
	return
}

func newGluetunClient(control, apiKeyFile string, timeout time.Duration) (*gluetun.Client, error) {
	c := &gluetun.Client{BaseURL: control, Timeout: timeout}
	if apiKeyFile != "" {
		data, err := os.ReadFile(apiKeyFile)
		if err != nil {
			return nil, fmt.Errorf("reading api key: %w", err)
		}
		c.APIKey = strings.TrimSpace(string(data))
	}
	return c, nil
}

func cmdProbe(args []string) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	control, apiKeyFile, timeout := controlFlags(fs)
	requirePort := fs.Bool("require-port", true, "treat a missing forwarded port as unhealthy")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	c, err := newGluetunClient(*control, *apiKeyFile, *timeout)
	if err != nil {
		logf("%v", err)
		return exitError
	}
	c.RequirePort = *requirePort
	ctx, cancel := context.WithTimeout(context.Background(), 3*(*timeout))
	defer cancel()
	p, _ := c.Probe(ctx)
	fmt.Print(p.EnvLines())
	if !p.Healthy() {
		return exitError
	}
	return exitOK
}

func cmdApply(args []string) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	control, apiKeyFile, timeout := controlFlags(fs)
	stateDir := fs.String("state-dir", "/gluetun/pia", "directory containing state.json")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	st, err := state.Load(filepath.Join(*stateDir, "state.json"))
	if err != nil {
		logf("%v", err)
		return exitError
	}
	body, err := st.GluetunSettingsJSON()
	if err != nil {
		logf("%v", err)
		return exitError
	}
	c, err := newGluetunClient(*control, *apiKeyFile, *timeout)
	if err != nil {
		logf("%v", err)
		return exitError
	}
	// gluetun stops and restarts the VPN loop synchronously inside this call.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	outcome, err := c.Apply(ctx, body)
	if err != nil {
		logf("%v", err)
		return exitError
	}
	logf("gluetun settings applied for %s: %s", st.CN, outcome)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return exitError
	}
	return exitOK
}

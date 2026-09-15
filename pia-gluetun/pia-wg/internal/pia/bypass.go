package pia

import (
	"context"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"net"
	"time"
)

// Bypass makes every connection the client opens skip the VPN tunnel.
//
// gluetun installs the policy rule "not fwmark 0xca6c lookup 51820", so a
// socket carrying SO_MARK 51820 falls through to the main routing table and
// leaves via the container's real interface. gluetun's own DNS forwarder only
// works through the tunnel, so names are resolved through DNS servers dialled
// with the same mark. Recovery must reach PIA while the tunnel is dead; this
// is what makes that possible. Mark 0 disables the whole mechanism.
type Bypass struct {
	Mark uint32
	// DNS servers as host:port, tried in random order. Empty keeps the
	// system resolver (only sensible when Mark is 0).
	DNS []string
}

// Enabled reports whether any bypass is configured.
func (b Bypass) Enabled() bool { return b.Mark != 0 || len(b.DNS) > 0 }

// Dialer returns a dialer honouring the mark and DNS settings.
func (b Bypass) Dialer(timeout time.Duration) (*net.Dialer, error) {
	d := &net.Dialer{Timeout: timeout}
	if b.Mark != 0 {
		control, err := markControl(b.Mark)
		if err != nil {
			return nil, err
		}
		d.Control = control
	}
	if len(b.DNS) > 0 {
		servers := make([]string, 0, len(b.DNS))
		for _, s := range b.DNS {
			if _, _, err := net.SplitHostPort(s); err != nil {
				return nil, fmt.Errorf("bypass DNS server %q must be host:port", s)
			}
			servers = append(servers, s)
		}
		inner := &net.Dialer{Timeout: 5 * time.Second, Control: d.Control}
		d.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				// Random start, then walk the list so one dead server does
				// not stall every lookup.
				start := mathrand.IntN(len(servers))
				var errs []error
				for i := range servers {
					conn, err := inner.DialContext(ctx, network, servers[(start+i)%len(servers)])
					if err == nil {
						return conn, nil
					}
					errs = append(errs, err)
				}
				return nil, errors.Join(errs...)
			},
		}
	}
	return d, nil
}

package pia

import (
	"fmt"
	"syscall"
)

// markControl returns a dialer Control function that sets SO_MARK on the
// socket before it connects. Needs CAP_NET_ADMIN, which gluetun already has.
func markControl(mark uint32) (func(network, address string, c syscall.RawConn) error, error) {
	return func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
		})
		if err != nil {
			return err
		}
		if sockErr != nil {
			return fmt.Errorf("setting SO_MARK %d (needs CAP_NET_ADMIN): %w", mark, sockErr)
		}
		return nil
	}, nil
}

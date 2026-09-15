//go:build !linux

package pia

import (
	"errors"
	"syscall"
)

func markControl(uint32) (func(network, address string, c syscall.RawConn) error, error) {
	return nil, errors.New("socket marks are only supported on Linux")
}

//go:build !freebsd && !openbsd

package pf

import (
	"pfctl-golang/internal/firewall"
)

// New returns ErrUnsupported when built for non-FreeBSD/OpenBSD targets.
func New(bool, string, string, string) (firewall.Provider, error) {
	return nil, firewall.ErrUnsupported
}

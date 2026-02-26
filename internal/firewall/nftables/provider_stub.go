//go:build !linux

package nftables

import (
	"pfctl-golang/internal/firewall"
)

// New returns ErrUnsupported when nftables is unavailable on this build target.
func New(bool) (firewall.Provider, error) {
	return nil, firewall.ErrUnsupported
}

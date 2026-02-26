package providers

import (
	"fmt"
	"strings"

	"pfctl-golang/internal/firewall"
	"pfctl-golang/internal/firewall/mock"
	"pfctl-golang/internal/firewall/nftables"
	"pfctl-golang/internal/firewall/pf"
)

// New constructs a firewall provider using the given backend identifier.
// Supported values: "pf", "nftables", "mock". Empty string defaults to "mock".
func New(name string, debug bool) (firewall.Provider, string, error) {
	switch normalized(name) {
	case "", "mock", "stub", "test":
		return mock.New(), "mock", nil
	case "pf", "pfctl":
		provider, err := pf.New(debug)
		return provider, "pf", err
	case "nft", "nftables":
		provider, err := nftables.New(debug)
		return provider, "nftables", err
	default:
		return nil, "", fmt.Errorf("unknown firewall backend %q", name)
	}
}

func normalized(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

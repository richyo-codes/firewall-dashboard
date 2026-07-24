//go:build disable_oidc

package auth

import (
	"context"
	"fmt"

	"pfctl-golang/internal/config"
)

func newOIDCManager(context.Context, config.OIDCConfig, Logger) (*Manager, error) {
	return nil, fmt.Errorf("OIDC support is disabled in this build")
}

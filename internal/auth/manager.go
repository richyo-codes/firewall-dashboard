package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"pfctl-golang/internal/config"
)

// Logger is the subset of log.Logger behaviour required by the auth managers.
type Logger interface {
	Printf(format string, v ...any)
}

// Manager wires authentication middleware and HTTP endpoints.
type Manager struct {
	mode     string
	wrap     func(http.Handler) http.Handler
	login    http.Handler
	callback http.Handler
	logout   http.Handler
	status   func(http.ResponseWriter, *http.Request)
	logger   Logger
}

// NewManager constructs an authentication manager using the provided config.
func NewManager(ctx context.Context, cfg config.AuthConfig, logger Logger) (*Manager, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = ModeNone
	}

	switch mode {
	case ModeNone:
		return newNoneManager(logger), nil
	case ModeOIDC:
		return newOIDCManager(ctx, cfg.OIDC, logger)
	default:
		return nil, fmt.Errorf("unknown auth mode %q", cfg.Mode)
	}
}

// Mode returns the configured authentication mode.
func (m *Manager) Mode() string {
	return m.mode
}

// Wrap injects authentication around the given handler.
func (m *Manager) Wrap(next http.Handler) http.Handler {
	if m.wrap == nil {
		return next
	}
	return m.wrap(next)
}

// RegisterPublicRoutes exposes login/logout/callback endpoints when enabled.
func (m *Manager) RegisterPublicRoutes(mux *http.ServeMux) {
	if m.login != nil {
		mux.Handle("/auth/login", m.login)
	}
	if m.callback != nil {
		mux.Handle("/auth/callback", m.callback)
	}
	if m.logout != nil {
		mux.Handle("/auth/logout", m.logout)
	}
}

// StatusHandler reports authentication status for the current request.
func (m *Manager) StatusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.status != nil {
			m.status(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"mode":           m.mode,
			"authenticated":  false,
			"user":           nil,
			"authentication": m.mode,
		})
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

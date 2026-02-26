package config

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/pflag"
)

const (
	envPrefix   = "PFCTL_DASHBOARD_"
	configDelim = "."
)

// Config captures runtime configuration for the dashboard.
type Config struct {
	Server   ServerConfig   `koanf:"server"`
	Firewall FirewallConfig `koanf:"firewall"`
	Auth     AuthConfig     `koanf:"auth"`
}

// ServerConfig represents HTTP server behaviour.
type ServerConfig struct {
	Addr    string              `koanf:"addr"`
	HTTPLog bool                `koanf:"http_log"`
	Refresh ServerRefreshConfig `koanf:"refresh"`
}

// ServerRefreshConfig controls client polling behaviour hints.
type ServerRefreshConfig struct {
	TrafficIntervalMs int `koanf:"traffic_interval_ms"`
}

// FirewallConfig configures the firewall backend.
type FirewallConfig struct {
	Backend string `koanf:"backend"`
	Debug   bool   `koanf:"debug"`
}

// AuthConfig captures authentication settings.
type AuthConfig struct {
	Mode string     `koanf:"mode"`
	OIDC OIDCConfig `koanf:"oidc"`
}

// OIDCConfig stores OpenID Connect options.
type OIDCConfig struct {
	ProviderURL     string   `koanf:"provider_url"`
	ClientID        string   `koanf:"client_id"`
	ClientSecret    string   `koanf:"client_secret"`
	RedirectURL     string   `koanf:"redirect_url"`
	Scopes          []string `koanf:"scopes"`
	CookieName      string   `koanf:"cookie_name"`
	StateCookieName string   `koanf:"state_cookie_name"`
	CookieSecure    bool     `koanf:"cookie_secure"`
	CookieDomain    string   `koanf:"cookie_domain"`
}

// Load builds the configuration using koanf with the following precedence:
// defaults < environment variables < CLI flags.
func Load(args []string) (*Config, *pflag.FlagSet, error) {
	k := koanf.New(configDelim)

	defaults := map[string]any{
		"server.addr":                        ":8080",
		"server.http_log":                    false,
		"server.refresh.traffic_interval_ms": 2000,
		"firewall.backend":                   defaultFirewallBackend(),
		"firewall.debug":                     false,
		"auth.mode":                          "none",
		"auth.oidc.provider_url":             "",
		"auth.oidc.client_id":                "",
		"auth.oidc.client_secret":            "",
		"auth.oidc.redirect_url":             "",
		"auth.oidc.scopes":                   []string{"openid", "profile", "email"},
		"auth.oidc.cookie_name":              "pf_session",
		"auth.oidc.state_cookie_name":        "pf_state",
		"auth.oidc.cookie_secure":            true,
		"auth.oidc.cookie_domain":            "",
	}
	if err := k.Load(confmap.Provider(defaults, configDelim), nil); err != nil {
		return nil, nil, fmt.Errorf("load defaults: %w", err)
	}

	flagSet := pflag.NewFlagSet("pfctl-dashboard", pflag.ContinueOnError)
	flagSet.String("server.addr", defaults["server.addr"].(string), "address to bind the HTTP server")
	flagSet.Bool("server.http_log", defaults["server.http_log"].(bool), "enable request logging")
	flagSet.Int("server.refresh.traffic_interval_ms", defaults["server.refresh.traffic_interval_ms"].(int), "traffic auto-refresh interval in milliseconds")
	flagSet.String("firewall.backend", defaults["firewall.backend"].(string), "firewall backend to use (mock|pf|nftables)")
	flagSet.Bool("firewall.debug", defaults["firewall.debug"].(bool), "enable verbose firewall command logging")
	flagSet.String("auth.mode", defaults["auth.mode"].(string), "authentication mode (none|oidc)")
	flagSet.String("auth.oidc.provider_url", defaults["auth.oidc.provider_url"].(string), "OIDC provider discovery URL")
	flagSet.String("auth.oidc.client_id", defaults["auth.oidc.client_id"].(string), "OIDC client ID")
	flagSet.String("auth.oidc.client_secret", defaults["auth.oidc.client_secret"].(string), "OIDC client secret")
	flagSet.String("auth.oidc.redirect_url", defaults["auth.oidc.redirect_url"].(string), "OIDC redirect/callback URL")
	flagSet.StringSlice("auth.oidc.scopes", defaults["auth.oidc.scopes"].([]string), "OIDC scopes to request")
	flagSet.String("auth.oidc.cookie_name", defaults["auth.oidc.cookie_name"].(string), "session cookie name for OIDC mode")
	flagSet.String("auth.oidc.state_cookie_name", defaults["auth.oidc.state_cookie_name"].(string), "state cookie name for OIDC mode")
	flagSet.Bool("auth.oidc.cookie_secure", defaults["auth.oidc.cookie_secure"].(bool), "use secure cookies for OIDC sessions")
	flagSet.String("auth.oidc.cookie_domain", defaults["auth.oidc.cookie_domain"].(string), "cookie domain override for OIDC sessions")

	// Keep OIDC flags available for backwards compatibility while reducing
	// top-level CLI help noise. Prefer PFCTL_DASHBOARD_AUTH_OIDC_* env vars.
	hideFlag(flagSet, "auth.oidc.provider_url")
	hideFlag(flagSet, "auth.oidc.client_id")
	hideFlag(flagSet, "auth.oidc.client_secret")
	hideFlag(flagSet, "auth.oidc.redirect_url")
	hideFlag(flagSet, "auth.oidc.scopes")
	hideFlag(flagSet, "auth.oidc.cookie_name")
	hideFlag(flagSet, "auth.oidc.state_cookie_name")
	hideFlag(flagSet, "auth.oidc.cookie_secure")
	hideFlag(flagSet, "auth.oidc.cookie_domain")

	if err := k.Load(env.Provider(envPrefix, ".", envKeyFormatter), nil); err != nil {
		return nil, nil, fmt.Errorf("load env: %w", err)
	}

	if err := flagSet.Parse(args); err != nil {
		return nil, flagSet, fmt.Errorf("parse flags: %w", err)
	}

	if err := k.Load(posflag.Provider(flagSet, configDelim, k), nil); err != nil {
		return nil, flagSet, fmt.Errorf("load flags: %w", err)
	}

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, flagSet, fmt.Errorf("unmarshal config: %w", err)
	}

	if len(cfg.Auth.OIDC.Scopes) == 0 {
		cfg.Auth.OIDC.Scopes = []string{"openid", "profile", "email"}
	}

	if cfg.Server.Refresh.TrafficIntervalMs <= 0 {
		cfg.Server.Refresh.TrafficIntervalMs = defaults["server.refresh.traffic_interval_ms"].(int)
	}

	return &cfg, flagSet, nil
}

func envKeyFormatter(key string) string {
	key = strings.TrimPrefix(key, envPrefix)
	key = strings.ReplaceAll(strings.ToLower(key), "_", configDelim)
	return key
}

func hideFlag(flagSet *pflag.FlagSet, name string) {
	if err := flagSet.MarkHidden(name); err != nil {
		panic(fmt.Sprintf("mark hidden flag %q: %v", name, err))
	}
}

func defaultFirewallBackend() string {
	switch runtime.GOOS {
	case "freebsd", "openbsd":
		return "pf"
	default:
		return "mock"
	}
}

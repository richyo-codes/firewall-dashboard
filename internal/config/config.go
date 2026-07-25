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
	VNStat   VNStatConfig   `koanf:"vnstat"`
	Auth     AuthConfig     `koanf:"auth"`
}

// VNStatConfig configures optional vnStat bandwidth reporting.
type VNStatConfig struct {
	Enabled   bool   `koanf:"enabled"`
	Binary    string `koanf:"binary"`
	Interface string `koanf:"interface"`
}

// ServerConfig represents HTTP server behaviour.
type ServerConfig struct {
	Addr           string              `koanf:"addr"`
	HTTPLog        bool                `koanf:"http_log"`
	TrustedProxies []string            `koanf:"trusted_proxies"`
	Refresh        ServerRefreshConfig `koanf:"refresh"`
}

// ServerRefreshConfig controls client polling behaviour hints.
type ServerRefreshConfig struct {
	TrafficIntervalMs int `koanf:"traffic_interval_ms"`
}

// FirewallConfig configures the firewall backend.
type FirewallConfig struct {
	Backend               string   `koanf:"backend"`
	Debug                 bool     `koanf:"debug"`
	PF                    PFConfig `koanf:"pf"`
	CacheTTLms            int      `koanf:"cache_ttl_ms"`
	CommandTimeoutMs      int      `koanf:"command_timeout_ms"`
	MaxConcurrentCommands int      `koanf:"max_concurrent_commands"`
	MaxStreams            int      `koanf:"max_streams"`
}

// PFConfig configures PF log collection.
type PFConfig struct {
	BlockedSource  string `koanf:"blocked_source"`
	PflogInterface string `koanf:"pflog_interface"`
	PflogPath      string `koanf:"pflog_path"`
}

// AuthConfig captures authentication settings.
type AuthConfig struct {
	Mode string     `koanf:"mode"`
	OIDC OIDCConfig `koanf:"oidc"`
}

// OIDCConfig stores OpenID Connect options.
type OIDCConfig struct {
	ProviderURL         string   `koanf:"provider_url"`
	ClientID            string   `koanf:"client_id"`
	ClientSecret        string   `koanf:"client_secret"`
	RedirectURL         string   `koanf:"redirect_url"`
	Scopes              []string `koanf:"scopes"`
	CookieName          string   `koanf:"cookie_name"`
	StateCookieName     string   `koanf:"state_cookie_name"`
	CookieSecure        bool     `koanf:"cookie_secure"`
	CookieDomain        string   `koanf:"cookie_domain"`
	AllowedSubjects     []string `koanf:"allowed_subjects"`
	AllowedGroups       []string `koanf:"allowed_groups"`
	AllowedEmailDomains []string `koanf:"allowed_email_domains"`
}

// Load builds the configuration using koanf with the following precedence:
// defaults < environment variables < CLI flags.
func Load(args []string) (*Config, *pflag.FlagSet, error) {
	k := koanf.New(configDelim)

	defaults := map[string]any{
		"server.addr":                        ":8080",
		"server.http_log":                    false,
		"server.trusted_proxies":             []string{},
		"server.refresh.traffic_interval_ms": 2000,
		"firewall.backend":                   defaultFirewallBackend(),
		"firewall.debug":                     false,
		"firewall.pf.blocked_source":         "auto",
		"firewall.pf.pflog_interface":        "pflog0",
		"firewall.pf.pflog_path":             "/var/log/pflog",
		"firewall.cache_ttl_ms":              1000,
		"firewall.command_timeout_ms":        5000,
		"firewall.max_concurrent_commands":   2,
		"firewall.max_streams":               4,
		"vnstat.enabled":                     true,
		"vnstat.binary":                      "vnstat",
		"vnstat.interface":                   "",
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
		"auth.oidc.allowed_subjects":         []string{},
		"auth.oidc.allowed_groups":           []string{},
		"auth.oidc.allowed_email_domains":    []string{},
	}
	if err := k.Load(confmap.Provider(defaults, configDelim), nil); err != nil {
		return nil, nil, fmt.Errorf("load defaults: %w", err)
	}

	flagSet := pflag.NewFlagSet("pfctl-dashboard", pflag.ContinueOnError)
	flagSet.String("server.addr", defaults["server.addr"].(string), "address to bind the HTTP server")
	flagSet.Bool("server.http_log", defaults["server.http_log"].(bool), "enable request logging")
	flagSet.StringSlice("server.trusted_proxies", defaults["server.trusted_proxies"].([]string), "trusted reverse-proxy IPs or CIDRs")
	flagSet.Int("server.refresh.traffic_interval_ms", defaults["server.refresh.traffic_interval_ms"].(int), "traffic auto-refresh interval in milliseconds")
	flagSet.String("firewall.backend", defaults["firewall.backend"].(string), "firewall backend to use (mock|pf|nftables)")
	flagSet.Bool("firewall.debug", defaults["firewall.debug"].(bool), "enable verbose firewall command logging")
	flagSet.String("firewall.pf.blocked_source", defaults["firewall.pf.blocked_source"].(string), "PF blocked traffic source (auto|live|file)")
	flagSet.String("firewall.pf.pflog_interface", defaults["firewall.pf.pflog_interface"].(string), "PF log interface for live tcpdump collection")
	flagSet.String("firewall.pf.pflog_path", defaults["firewall.pf.pflog_path"].(string), "PF log capture file for tcpdump playback")
	flagSet.Int("firewall.cache_ttl_ms", defaults["firewall.cache_ttl_ms"].(int), "firewall result cache lifetime in milliseconds")
	flagSet.Int("firewall.command_timeout_ms", defaults["firewall.command_timeout_ms"].(int), "firewall command timeout in milliseconds")
	flagSet.Int("firewall.max_concurrent_commands", defaults["firewall.max_concurrent_commands"].(int), "maximum concurrent firewall commands")
	flagSet.Int("firewall.max_streams", defaults["firewall.max_streams"].(int), "maximum concurrent live traffic streams")
	flagSet.Bool("vnstat.enabled", defaults["vnstat.enabled"].(bool), "enable optional vnStat bandwidth data when available")
	flagSet.String("vnstat.binary", defaults["vnstat.binary"].(string), "vnStat executable path or name")
	flagSet.String("vnstat.interface", defaults["vnstat.interface"].(string), "optional vnStat interface to show")
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
	flagSet.StringSlice("auth.oidc.allowed_subjects", defaults["auth.oidc.allowed_subjects"].([]string), "allowed OIDC subject IDs")
	flagSet.StringSlice("auth.oidc.allowed_groups", defaults["auth.oidc.allowed_groups"].([]string), "required OIDC groups")
	flagSet.StringSlice("auth.oidc.allowed_email_domains", defaults["auth.oidc.allowed_email_domains"].([]string), "allowed verified email domains")

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
	hideFlag(flagSet, "auth.oidc.allowed_subjects")
	hideFlag(flagSet, "auth.oidc.allowed_groups")
	hideFlag(flagSet, "auth.oidc.allowed_email_domains")

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

	cfg.Server.TrustedProxies = normalizeList(cfg.Server.TrustedProxies)
	cfg.Auth.OIDC.Scopes = normalizeList(cfg.Auth.OIDC.Scopes)
	cfg.Auth.OIDC.AllowedSubjects = normalizeList(cfg.Auth.OIDC.AllowedSubjects)
	cfg.Auth.OIDC.AllowedGroups = normalizeList(cfg.Auth.OIDC.AllowedGroups)
	cfg.Auth.OIDC.AllowedEmailDomains = normalizeList(cfg.Auth.OIDC.AllowedEmailDomains)
	if len(cfg.Auth.OIDC.Scopes) == 0 {
		cfg.Auth.OIDC.Scopes = []string{"openid", "profile", "email"}
	}

	if cfg.Server.Refresh.TrafficIntervalMs <= 0 {
		cfg.Server.Refresh.TrafficIntervalMs = defaults["server.refresh.traffic_interval_ms"].(int)
	}
	if cfg.Firewall.CacheTTLms <= 0 {
		cfg.Firewall.CacheTTLms = defaults["firewall.cache_ttl_ms"].(int)
	}
	if cfg.Firewall.CommandTimeoutMs <= 0 {
		cfg.Firewall.CommandTimeoutMs = defaults["firewall.command_timeout_ms"].(int)
	}
	if cfg.Firewall.MaxConcurrentCommands <= 0 {
		cfg.Firewall.MaxConcurrentCommands = defaults["firewall.max_concurrent_commands"].(int)
	}
	if cfg.Firewall.MaxStreams <= 0 {
		cfg.Firewall.MaxStreams = defaults["firewall.max_streams"].(int)
	}
	cfg.Firewall.PF.BlockedSource = strings.ToLower(strings.TrimSpace(cfg.Firewall.PF.BlockedSource))
	if cfg.Firewall.PF.BlockedSource == "" {
		cfg.Firewall.PF.BlockedSource = defaults["firewall.pf.blocked_source"].(string)
	}
	if cfg.Firewall.PF.BlockedSource != "auto" && cfg.Firewall.PF.BlockedSource != "live" && cfg.Firewall.PF.BlockedSource != "file" {
		return nil, flagSet, fmt.Errorf("invalid firewall.pf.blocked_source %q (want auto, live, or file)", cfg.Firewall.PF.BlockedSource)
	}
	cfg.Firewall.PF.PflogInterface = strings.TrimSpace(cfg.Firewall.PF.PflogInterface)
	if cfg.Firewall.PF.PflogInterface == "" {
		cfg.Firewall.PF.PflogInterface = defaults["firewall.pf.pflog_interface"].(string)
	}
	cfg.Firewall.PF.PflogPath = strings.TrimSpace(cfg.Firewall.PF.PflogPath)
	if cfg.Firewall.PF.PflogPath == "" {
		cfg.Firewall.PF.PflogPath = defaults["firewall.pf.pflog_path"].(string)
	}
	cfg.VNStat.Binary = strings.TrimSpace(cfg.VNStat.Binary)
	if cfg.VNStat.Binary == "" {
		cfg.VNStat.Binary = defaults["vnstat.binary"].(string)
	}
	cfg.VNStat.Interface = strings.TrimSpace(cfg.VNStat.Interface)

	return &cfg, flagSet, nil
}

func envKeyFormatter(key string) string {
	key = strings.TrimPrefix(key, envPrefix)
	if mapped, ok := envKeyMappings[key]; ok {
		return mapped
	}
	key = strings.ReplaceAll(strings.ToLower(key), "_", configDelim)
	return key
}

var envKeyMappings = map[string]string{
	"SERVER_ADDR":                        "server.addr",
	"SERVER_HTTP_LOG":                    "server.http_log",
	"SERVER_TRUSTED_PROXIES":             "server.trusted_proxies",
	"SERVER_REFRESH_TRAFFIC_INTERVAL_MS": "server.refresh.traffic_interval_ms",
	"FIREWALL_BACKEND":                   "firewall.backend",
	"FIREWALL_DEBUG":                     "firewall.debug",
	"FIREWALL_PF_BLOCKED_SOURCE":         "firewall.pf.blocked_source",
	"FIREWALL_PF_PFLOG_INTERFACE":        "firewall.pf.pflog_interface",
	"FIREWALL_PF_PFLOG_PATH":             "firewall.pf.pflog_path",
	"VNSTAT_ENABLED":                     "vnstat.enabled",
	"VNSTAT_BINARY":                      "vnstat.binary",
	"VNSTAT_INTERFACE":                   "vnstat.interface",
	"FIREWALL_CACHE_TTL_MS":              "firewall.cache_ttl_ms",
	"FIREWALL_COMMAND_TIMEOUT_MS":        "firewall.command_timeout_ms",
	"FIREWALL_MAX_CONCURRENT_COMMANDS":   "firewall.max_concurrent_commands",
	"FIREWALL_MAX_STREAMS":               "firewall.max_streams",
	"AUTH_MODE":                          "auth.mode",
	"AUTH_OIDC_PROVIDER_URL":             "auth.oidc.provider_url",
	"AUTH_OIDC_CLIENT_ID":                "auth.oidc.client_id",
	"AUTH_OIDC_CLIENT_SECRET":            "auth.oidc.client_secret",
	"AUTH_OIDC_REDIRECT_URL":             "auth.oidc.redirect_url",
	"AUTH_OIDC_SCOPES":                   "auth.oidc.scopes",
	"AUTH_OIDC_COOKIE_NAME":              "auth.oidc.cookie_name",
	"AUTH_OIDC_STATE_COOKIE_NAME":        "auth.oidc.state_cookie_name",
	"AUTH_OIDC_COOKIE_SECURE":            "auth.oidc.cookie_secure",
	"AUTH_OIDC_COOKIE_DOMAIN":            "auth.oidc.cookie_domain",
	"AUTH_OIDC_ALLOWED_SUBJECTS":         "auth.oidc.allowed_subjects",
	"AUTH_OIDC_ALLOWED_GROUPS":           "auth.oidc.allowed_groups",
	"AUTH_OIDC_ALLOWED_EMAIL_DOMAINS":    "auth.oidc.allowed_email_domains",
}

func hideFlag(flagSet *pflag.FlagSet, name string) {
	if err := flagSet.MarkHidden(name); err != nil {
		panic(fmt.Sprintf("mark hidden flag %q: %v", name, err))
	}
}

func normalizeList(values []string) []string {
	var normalized []string
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			if item = strings.TrimSpace(item); item != "" {
				normalized = append(normalized, item)
			}
		}
	}
	return normalized
}

func defaultFirewallBackend() string {
	switch runtime.GOOS {
	case "freebsd", "openbsd":
		return "pf"
	default:
		return "mock"
	}
}

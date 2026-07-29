package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSecurityAndResourceControls(t *testing.T) {
	t.Setenv("PFCTL_DASHBOARD_SERVER_TRUSTED_PROXIES", "127.0.0.1/32,10.0.0.0/8")
	t.Setenv("PFCTL_DASHBOARD_AUTH_OIDC_ALLOWED_GROUPS", "firewall-admins,operators")

	cfg, _, err := Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Addr != "127.0.0.1:8080" {
		t.Fatalf("server address default = %q", cfg.Server.Addr)
	}
	if cfg.Firewall.CommandTimeoutMs <= 0 || cfg.Firewall.MaxConcurrentCommands <= 0 || cfg.Firewall.MaxStreams <= 0 {
		t.Fatalf("invalid resource-control defaults: %#v", cfg.Firewall)
	}
	if !cfg.QoS.Enabled || cfg.QoS.Binary != "pfctl" {
		t.Fatalf("invalid QoS defaults: %#v", cfg.QoS)
	}
	if len(cfg.Server.TrustedProxies) != 2 {
		t.Fatalf("trusted proxies = %#v", cfg.Server.TrustedProxies)
	}
	if len(cfg.Auth.OIDC.AllowedGroups) != 2 {
		t.Fatalf("allowed groups = %#v", cfg.Auth.OIDC.AllowedGroups)
	}
}

func TestLoadPFLogConfiguration(t *testing.T) {
	t.Setenv("PFCTL_DASHBOARD_FIREWALL_PF_BLOCKED_SOURCE", "file")
	t.Setenv("PFCTL_DASHBOARD_FIREWALL_PF_PFLOG_INTERFACE", "pflog7")
	t.Setenv("PFCTL_DASHBOARD_FIREWALL_PF_PFLOG_PATH", "/var/pf/pflog")

	cfg, _, err := Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Firewall.PF.BlockedSource != "file" || cfg.Firewall.PF.PflogInterface != "pflog7" || cfg.Firewall.PF.PflogPath != "/var/pf/pflog" {
		t.Fatalf("PF log config = %#v", cfg.Firewall.PF)
	}
}

func TestLoadTOMLConfigWithEnvironmentAndFlagPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pf-dashboard.toml")
	contents := "[server]\naddr = \"127.0.0.1:8081\"\n\n[firewall.pf]\nblocked_source = \"file\"\npflog_path = \"/var/pf/pflog\"\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PFCTL_DASHBOARD_SERVER_ADDR", "127.0.0.1:8082")

	cfg, _, err := Load([]string{"--config", path, "--server.addr=127.0.0.1:8083"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Addr != "127.0.0.1:8083" {
		t.Fatalf("server address = %q", cfg.Server.Addr)
	}
	if cfg.Firewall.PF.BlockedSource != "file" || cfg.Firewall.PF.PflogPath != "/var/pf/pflog" {
		t.Fatalf("PF log config = %#v", cfg.Firewall.PF)
	}
}

func TestConfigFilePathRejectsMissingValue(t *testing.T) {
	if _, err := configFilePath([]string{"--config"}); err == nil {
		t.Fatal("missing config path was accepted")
	}
}

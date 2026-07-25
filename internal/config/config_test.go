package config

import "testing"

func TestLoadSecurityAndResourceControls(t *testing.T) {
	t.Setenv("PFCTL_DASHBOARD_SERVER_TRUSTED_PROXIES", "127.0.0.1/32,10.0.0.0/8")
	t.Setenv("PFCTL_DASHBOARD_AUTH_OIDC_ALLOWED_GROUPS", "firewall-admins,operators")

	cfg, _, err := Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Firewall.CommandTimeoutMs <= 0 || cfg.Firewall.MaxConcurrentCommands <= 0 || cfg.Firewall.MaxStreams <= 0 {
		t.Fatalf("invalid resource-control defaults: %#v", cfg.Firewall)
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

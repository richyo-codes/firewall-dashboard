//go:build !disable_oidc

package auth

import (
	"net/http/httptest"
	"testing"
	"time"

	"pfctl-golang/internal/config"
)

func TestSafeRedirect(t *testing.T) {
	tests := map[string]string{
		"":                       "/",
		"/rules?sort=packets":    "/rules?sort=packets",
		"https://example.com":    "/",
		"//example.com/path":     "/",
		"/%2f%2fevil.example":    "/",
		"relative/path":          "/",
		"/\\example.com/escaped": "/",
		"/%5cexample.com":        "/",
	}
	for input, want := range tests {
		if got := safeRedirect(input); got != want {
			t.Errorf("safeRedirect(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestOIDCAuthorizationConstraints(t *testing.T) {
	manager := &oidcManager{cfg: config.OIDCConfig{
		AllowedSubjects:     []string{"subject-1"},
		AllowedGroups:       []string{"firewall-admins"},
		AllowedEmailDomains: []string{"example.com"},
	}}

	if !manager.authorized("subject-1", "user@example.com", []string{"firewall-admins"}) {
		t.Fatal("expected matching identity to be authorized")
	}
	if manager.authorized("subject-2", "user@example.com", []string{"firewall-admins"}) {
		t.Fatal("expected unmatched subject to be rejected")
	}
	if manager.authorized("subject-1", "user@invalid.example", []string{"firewall-admins"}) {
		t.Fatal("expected unmatched email domain to be rejected")
	}
}

func TestAuthenticateUsesOpaqueSession(t *testing.T) {
	expiry := time.Now().Add(time.Minute)
	manager := &oidcManager{
		cookieName: "session",
		logins:     make(map[string]loginTransaction),
		sessions: map[string]session{
			"opaque-id": {
				user:    User{Subject: "subject-1", Expires: expiry},
				expires: expiry,
			},
		},
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.AddCookie(manager.sessionCookie("opaque-id", expiry))

	user, ok := manager.authenticate(request)
	if !ok || user.Subject != "subject-1" {
		t.Fatalf("unexpected authentication result: %#v, %v", user, ok)
	}
}

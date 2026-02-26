//go:build !disable_oidc

package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"pfctl-golang/internal/config"
)

type oidcManager struct {
	cfg           config.OIDCConfig
	provider      *oidc.Provider
	verifier      *oidc.IDTokenVerifier
	oauthConfig   *oauth2.Config
	logger        Logger
	cookieName    string
	stateCookie   string
	cookieSecure  bool
	cookieDomain  string
	defaultScopes []string
}

func newOIDCManager(ctx context.Context, cfg config.OIDCConfig, logger Logger) (*Manager, error) {
	if cfg.ProviderURL == "" {
		return nil, fmt.Errorf("auth.oidc.provider_url is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("auth.oidc.client_id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("auth.oidc.client_secret is required")
	}
	if cfg.RedirectURL == "" {
		return nil, fmt.Errorf("auth.oidc.redirect_url is required")
	}

	provider, err := oidc.NewProvider(ctx, cfg.ProviderURL)
	if err != nil {
		return nil, fmt.Errorf("initialise oidc provider: %w", err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       scopes,
	}

	manager := &oidcManager{
		cfg:           cfg,
		provider:      provider,
		oauthConfig:   oauthCfg,
		verifier:      provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		logger:        logger,
		cookieName:    firstNonEmpty(cfg.CookieName, "pf_session"),
		stateCookie:   firstNonEmpty(cfg.StateCookieName, "pf_state"),
		cookieSecure:  cfg.CookieSecure,
		cookieDomain:  cfg.CookieDomain,
		defaultScopes: scopes,
	}

	mgr := &Manager{
		mode:   ModeOIDC,
		logger: logger,
	}

	mgr.wrap = manager.wrap
	mgr.login = http.HandlerFunc(manager.handleLogin)
	mgr.callback = http.HandlerFunc(manager.handleCallback)
	mgr.logout = http.HandlerFunc(manager.handleLogout)
	mgr.status = manager.handleStatus

	return mgr, nil
}

func (o *oidcManager) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := o.authenticate(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := WithUser(r.Context(), *user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (o *oidcManager) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := randomString(32)
	if err != nil {
		o.logger.Printf("failed to generate oauth state: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, o.makeCookie(o.stateCookie, state, 5*time.Minute))

	authURL := o.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
	if redirect := r.URL.Query().Get("redirect"); redirect != "" {
		authURL = addQueryParam(authURL, "redirect", redirect)
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (o *oidcManager) handleCallback(w http.ResponseWriter, r *http.Request) {
	stateParam := r.URL.Query().Get("state")
	if stateParam == "" {
		http.Error(w, "missing state", http.StatusBadRequest)
		return
	}

	stateCookie, err := r.Cookie(o.stateCookie)
	if err != nil || stateCookie.Value == "" {
		http.Error(w, "state cookie missing", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(stateParam), []byte(stateCookie.Value)) != 1 {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	token, err := o.oauthConfig.Exchange(r.Context(), code)
	if err != nil {
		o.logger.Printf("oauth exchange failed: %v", err)
		http.Error(w, "oauth exchange failed", http.StatusBadGateway)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "missing id_token", http.StatusBadGateway)
		return
	}

	user, err := o.verifyToken(r.Context(), rawIDToken)
	if err != nil {
		o.logger.Printf("id token verification failed: %v", err)
		http.Error(w, "invalid id token", http.StatusUnauthorized)
		return
	}

	http.SetCookie(w, o.sessionCookie(rawIDToken, user.Expires))
	http.SetCookie(w, o.makeCookie(o.stateCookie, "", -time.Hour))

	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (o *oidcManager) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, o.sessionCookie("", time.Unix(0, 0)))
	http.SetCookie(w, o.makeCookie(o.stateCookie, "", -time.Hour))
	w.WriteHeader(http.StatusNoContent)
}

func (o *oidcManager) handleStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := o.authenticate(r)
	payload := map[string]any{
		"mode":          ModeOIDC,
		"authenticated": ok,
	}
	if ok && user != nil {
		payload["user"] = user
	}
	writeJSON(w, http.StatusOK, payload)
}

func (o *oidcManager) authenticate(r *http.Request) (*User, bool) {
	cookie, err := r.Cookie(o.cookieName)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	user, err := o.verifyToken(r.Context(), cookie.Value)
	if err != nil {
		o.logger.Printf("token verification failed: %v", err)
		return nil, false
	}
	return user, true
}

func (o *oidcManager) verifyToken(ctx context.Context, raw string) (*User, error) {
	idToken, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}

	var claims struct {
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}

	name := firstNonEmpty(claims.Name, claims.PreferredUsername, claims.Email, idToken.Subject)
	if strings.TrimSpace(name) == "" {
		name = idToken.Subject
	}

	email := ""
	if claims.EmailVerified || claims.Email != "" {
		email = claims.Email
	}

	return &User{
		Subject: idToken.Subject,
		Email:   email,
		Name:    name,
		Issuer:  idToken.Issuer,
		Expires: idToken.Expiry.Round(0),
	}, nil
}

func (o *oidcManager) makeCookie(name, value string, lifetime time.Duration) *http.Cookie {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   o.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
	if o.cookieDomain != "" {
		cookie.Domain = o.cookieDomain
	}
	if lifetime < 0 {
		cookie.MaxAge = -1
		cookie.Expires = time.Unix(0, 0)
	} else if lifetime > 0 {
		cookie.MaxAge = int(lifetime.Seconds())
		cookie.Expires = time.Now().Add(lifetime)
	}
	return cookie
}

func (o *oidcManager) sessionCookie(value string, expiry time.Time) *http.Cookie {
	lifetime := time.Until(expiry)
	if value == "" {
		lifetime = -time.Hour
	}
	return o.makeCookie(o.cookieName, value, lifetime)
}

func randomString(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func addQueryParam(uri, key, value string) string {
	parsed, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	q := parsed.Query()
	q.Set(key, value)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

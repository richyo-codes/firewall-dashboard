//go:build !disable_oidc

package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
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
	mu            sync.Mutex
	logins        map[string]loginTransaction
	sessions      map[string]session
}

const (
	loginLifetime = 5 * time.Minute
	maxLogins     = 256
	maxSessions   = 1024
)

var errNotAuthorized = errors.New("identity is not authorized")

type loginTransaction struct {
	verifier string
	redirect string
	expires  time.Time
}

type session struct {
	user    User
	expires time.Time
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
		logins:        make(map[string]loginTransaction),
		sessions:      make(map[string]session),
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
	verifier, err := randomString(32)
	if err != nil {
		o.logger.Printf("failed to generate pkce verifier: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	redirect := safeRedirect(r.URL.Query().Get("redirect"))
	o.mu.Lock()
	o.pruneLocked(time.Now())
	if len(o.logins) >= maxLogins {
		o.mu.Unlock()
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}
	o.logins[state] = loginTransaction{
		verifier: verifier,
		redirect: redirect,
		expires:  time.Now().Add(loginLifetime),
	}
	o.mu.Unlock()

	http.SetCookie(w, o.makeCookie(o.stateCookie, state, loginLifetime))
	authURL := o.oauthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
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
	o.mu.Lock()
	transaction, ok := o.logins[stateParam]
	delete(o.logins, stateParam)
	o.mu.Unlock()
	if !ok || time.Now().After(transaction.expires) {
		http.Error(w, "expired state", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	callbackContext, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	token, err := o.oauthConfig.Exchange(callbackContext, code, oauth2.VerifierOption(transaction.verifier))
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

	user, err := o.verifyToken(callbackContext, rawIDToken)
	if err != nil {
		o.logger.Printf("id token verification failed: %v", err)
		status := http.StatusUnauthorized
		if errors.Is(err, errNotAuthorized) {
			status = http.StatusForbidden
		}
		http.Error(w, "identity not accepted", status)
		return
	}

	sessionID, err := randomString(32)
	if err != nil {
		o.logger.Printf("failed to generate session id: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	o.mu.Lock()
	o.pruneLocked(time.Now())
	if len(o.sessions) >= maxSessions {
		o.mu.Unlock()
		http.Error(w, "session limit reached", http.StatusServiceUnavailable)
		return
	}
	o.sessions[sessionID] = session{user: *user, expires: user.Expires}
	o.mu.Unlock()

	http.SetCookie(w, o.sessionCookie(sessionID, user.Expires))
	http.SetCookie(w, o.makeCookie(o.stateCookie, "", -time.Hour))
	http.Redirect(w, r, transaction.redirect, http.StatusFound)
}

func (o *oidcManager) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(o.cookieName); err == nil {
		o.mu.Lock()
		delete(o.sessions, cookie.Value)
		o.mu.Unlock()
	}
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
	now := time.Now()
	o.mu.Lock()
	o.pruneLocked(now)
	session, ok := o.sessions[cookie.Value]
	o.mu.Unlock()
	if !ok || now.After(session.expires) {
		return nil, false
	}
	user := session.user
	return &user, true
}

func (o *oidcManager) verifyToken(ctx context.Context, raw string) (*User, error) {
	idToken, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}

	var claims struct {
		Email             string   `json:"email"`
		EmailVerified     bool     `json:"email_verified"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}

	name := firstNonEmpty(claims.Name, claims.PreferredUsername, claims.Email, idToken.Subject)
	if strings.TrimSpace(name) == "" {
		name = idToken.Subject
	}

	email := ""
	if claims.EmailVerified {
		email = claims.Email
	}
	if !o.authorized(idToken.Subject, email, claims.Groups) {
		return nil, errNotAuthorized
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

func (o *oidcManager) authorized(subject, verifiedEmail string, groups []string) bool {
	if len(o.cfg.AllowedSubjects) > 0 && !containsFold(o.cfg.AllowedSubjects, subject) {
		return false
	}
	if len(o.cfg.AllowedGroups) > 0 && !intersectsFold(o.cfg.AllowedGroups, groups) {
		return false
	}
	if len(o.cfg.AllowedEmailDomains) > 0 {
		at := strings.LastIndex(verifiedEmail, "@")
		if at < 0 || !containsFold(o.cfg.AllowedEmailDomains, verifiedEmail[at+1:]) {
			return false
		}
	}
	return true
}

func (o *oidcManager) pruneLocked(now time.Time) {
	for state, transaction := range o.logins {
		if now.After(transaction.expires) {
			delete(o.logins, state)
		}
	}
	for id, session := range o.sessions {
		if now.After(session.expires) {
			delete(o.sessions, id)
		}
	}
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

func safeRedirect(value string) string {
	if value == "" {
		return "/"
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") || strings.Contains(parsed.Path, "\\") {
		return "/"
	}
	return parsed.String()
}

func containsFold(values []string, candidate string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func intersectsFold(allowed, actual []string) bool {
	for _, candidate := range actual {
		if containsFold(allowed, candidate) {
			return true
		}
	}
	return false
}

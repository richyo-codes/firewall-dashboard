package auth

import (
	"context"
	"time"
)

const (
	ModeNone = "none"
	ModeOIDC = "oidc"
)

// User represents the authenticated subject extracted from an ID token.
type User struct {
	Subject string    `json:"subject"`
	Email   string    `json:"email,omitempty"`
	Name    string    `json:"name,omitempty"`
	Issuer  string    `json:"issuer,omitempty"`
	Expires time.Time `json:"expires,omitempty"`
}

type contextKey struct{}

// WithUser injects authentication details into the request context.
func WithUser(ctx context.Context, user User) context.Context {
	return context.WithValue(ctx, contextKey{}, user)
}

// UserFromContext extracts authenticated user information, if present.
func UserFromContext(ctx context.Context) (User, bool) {
	if ctx == nil {
		return User{}, false
	}
	user, ok := ctx.Value(contextKey{}).(User)
	return user, ok
}

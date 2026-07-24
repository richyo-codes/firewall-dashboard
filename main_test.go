package main

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/pflag"
)

func TestTrustedProxyRemoteAddr(t *testing.T) {
	trusted, err := newTrustedProxies([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.10, 127.0.0.1")
	if got := trusted.remoteAddr(request); got != "198.51.100.10" {
		t.Fatalf("remoteAddr = %q", got)
	}

	request.RemoteAddr = "203.0.113.20:1234"
	if got := trusted.remoteAddr(request); got != request.RemoteAddr {
		t.Fatalf("untrusted proxy headers were accepted: %q", got)
	}
}

func TestSecurityHeaders(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/", nil)
	securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, request)

	if recorder.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing Content-Security-Policy")
	}
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff header")
	}
}

func TestWithJSONHidesInternalError(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/", nil)
	handler := withJSON(log.New(io.Discard, "", 0), func(*http.Request) (any, error) {
		return nil, errors.New("sensitive command output")
	})
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", recorder.Code)
	}
	if body := recorder.Body.String(); body != "{\"error\":\"backend request failed\"}\n" {
		t.Fatalf("unexpected response body: %q", body)
	}
}

func TestSafeFlagValueRedactsSecrets(t *testing.T) {
	flagSet := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flagSet.String("auth.client_secret", "", "")
	flagSet.String("server.addr", "", "")
	if err := flagSet.Parse([]string{"--auth.client_secret=sensitive", "--server.addr=:8080"}); err != nil {
		t.Fatal(err)
	}
	if got := safeFlagValue(flagSet.Lookup("auth.client_secret")); got != "[REDACTED]" {
		t.Fatalf("secret was not redacted: %q", got)
	}
	if got := safeFlagValue(flagSet.Lookup("server.addr")); got != ":8080" {
		t.Fatalf("ordinary flag was redacted: %q", got)
	}
}

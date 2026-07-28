package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHandleRCD(t *testing.T) {
	var stdout, stderr bytes.Buffer
	handled, err := maybeHandleRCD([]string{"config", "rc.d"}, &stdout, &stderr)
	if err != nil || !handled {
		t.Fatalf("maybeHandleRCD = %v, %v", handled, err)
	}
	if !strings.Contains(stdout.String(), "PROVIDE: pf_dashboard") {
		t.Fatalf("unexpected rc.d output: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "pf_dashboard_app_flags") || !strings.Contains(stdout.String(), "pf_dashboard_flags=\"\"") {
		t.Fatalf("rc.d output does not protect daemon from application flags: %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestHandleRCDRejectsArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	handled, err := maybeHandleRCD([]string{"config", "rc.d", "extra"}, &stdout, &stderr)
	if err == nil || !handled {
		t.Fatalf("maybeHandleRCD = %v, %v", handled, err)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("missing usage: %q", stderr.String())
	}
}

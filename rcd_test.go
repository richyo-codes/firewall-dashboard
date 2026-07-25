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

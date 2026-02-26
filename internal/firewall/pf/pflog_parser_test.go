package pf

import (
	"testing"
	"time"
)

func TestParsePflogLine(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		wantAct  string
		wantDir  string
		wantRule int
	}{
		{
			name:     "pass entry",
			line:     "2025-10-18 20:00:21.848277 rule 81/0(match): pass in on lan0: 192.168.133.225.41641 > 199.38.181.93.3478: UDP, length 40",
			wantAct:  "pass",
			wantDir:  "in",
			wantRule: 81,
		},
		{
			name:     "block entry",
			line:     "2025-10-18 20:00:21.848827 rule 439/0(match): block in on lan0.150: 172.16.150.72.43506 > 35.167.31.59.11111: Flags [S], seq 1257158708, win 29200, options [mss 1460,sackOK,TS val 2730428032 ecr 0,nop,wscale 3], length 0",
			wantAct:  "block",
			wantDir:  "in",
			wantRule: 439,
		},
		{
			name:     "rdr entry",
			line:     "2025-10-18 20:01:05.123456 rule 123/0(match): rdr out on wan0: 198.51.100.24.443 > 10.0.0.10.8443: TCP, length 0",
			wantAct:  "rdr",
			wantDir:  "out",
			wantRule: 123,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			entry, ok := parsePflogLine(tc.line)
			if !ok {
				t.Fatalf("parsePflogLine returned ok=false")
			}

			if got := entry.Action; got != tc.wantAct {
				t.Errorf("action mismatch: want %q got %q", tc.wantAct, got)
			}
			if got := entry.Direction; got != tc.wantDir {
				t.Errorf("direction mismatch: want %q got %q", tc.wantDir, got)
			}
			if got := entry.RuleID; got != tc.wantRule {
				t.Errorf("ruleId mismatch: want %d got %d", tc.wantRule, got)
			}

			if entry.Source == "" || entry.Dest == "" {
				t.Fatalf("expected non-empty source/dest, got %q/%q", entry.Source, entry.Dest)
			}

			if entry.Timestamp.IsZero() {
				t.Fatalf("expected non-zero timestamp")
			}

			if entry.Timestamp.Before(time.Date(2020, 1, 1, 0, 0, 0, 0, entry.Timestamp.Location())) {
				t.Fatalf("timestamp appears invalid: %v", entry.Timestamp)
			}
		})
	}
}

func TestParsePflogLine_Invalid(t *testing.T) {
	if _, ok := parsePflogLine("not a pflog line"); ok {
		t.Fatalf("expected parse failure")
	}
}

func TestParseRuleID(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"81/0", 81},
		{"439/1", 439},
		{"999", 999},
		{"bad/entry", 0},
	}
	for _, tt := range tests {
		if got := parseRuleID(tt.input); got != tt.want {
			t.Errorf("parseRuleID(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

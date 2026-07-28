package vnstat

import (
	"testing"
	"time"
)

func TestNewDisabled(t *testing.T) {
	provider, err := New(false, "", "")
	if err != nil || provider != nil {
		t.Fatalf("New(false) = %#v, %v", provider, err)
	}
}

func TestNewMissingBinaryIsOptional(t *testing.T) {
	provider, err := New(true, "definitely-not-vnstat", "")
	if err != nil || provider != nil {
		t.Fatalf("New(missing) = %#v, %v", provider, err)
	}
}

func TestParseReportIncludesRecentFiveMinuteHistory(t *testing.T) {
	report, err := parseReport([]byte(`{
  "interfaces": [{
    "name": "em0",
    "alias": "WAN",
    "traffic": {
      "total": {"rx": 1000, "tx": 2000},
      "fiveminute": [
        {"date": {"year": 2026, "month": 7, "day": 24}, "time": {"hour": 12, "minute": 0}, "rx": 300, "tx": 400},
        {"date": {"year": 2026, "month": 7, "day": 24}, "time": {"hour": 12, "minute": 5}, "rx": 500, "tx": 600}
      ]
    }
  }]
}`))
	if err != nil {
		t.Fatalf("parseReport() error = %v", err)
	}
	if len(report.Interfaces) != 1 {
		t.Fatalf("interfaces = %d, want 1", len(report.Interfaces))
	}
	iface := report.Interfaces[0]
	if got, want := iface.FiveMinute, (Counter{RX: 500, TX: 600}); got != want {
		t.Fatalf("FiveMinute = %#v, want %#v", got, want)
	}
	if len(iface.History) != 2 {
		t.Fatalf("history length = %d, want 2", len(iface.History))
	}
	if got, want := iface.History[1].At, time.Date(2026, 7, 24, 12, 5, 0, 0, time.Local).Format(time.RFC3339); got != want {
		t.Fatalf("latest timestamp = %q, want %q", got, want)
	}
}

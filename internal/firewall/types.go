package firewall

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrUnsupported indicates the requested provider is not available
// on the current platform or with the current build.
var ErrUnsupported = errors.New("firewall provider unsupported")

// PacketLogEntry captures a single firewall log entry.
type PacketLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Interface string    `json:"interface"`
	Source    string    `json:"source"`
	Dest      string    `json:"dest"`
	Protocol  string    `json:"protocol"`
	Action    string    `json:"action"`
	Reason    string    `json:"reason"`
	Direction string    `json:"direction,omitempty"`
	RuleID    int       `json:"ruleId,omitempty"`
}

// RuleCounter represents per-rule statistics exported from the firewall.
type RuleCounter struct {
	RuleID      int    `json:"ruleId"`
	RuleLabel   string `json:"ruleLabel"`
	Evaluations uint64 `json:"evaluations"`
	Packets     uint64 `json:"packets"`
	Bytes       uint64 `json:"bytes"`
}

// Provider exposes firewall statistics regardless of the underlying platform.
type Provider interface {
	BlockedTraffic(ctx context.Context) ([]PacketLogEntry, error)
	PassedTraffic(ctx context.Context) ([]PacketLogEntry, error)
	RuleCounters(ctx context.Context) ([]RuleCounter, error)
}

// StreamProvider can deliver live pflog/nftables output.
type StreamProvider interface {
	StreamTraffic(ctx context.Context, action string) (io.ReadCloser, error)
}

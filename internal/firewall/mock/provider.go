package mock

import (
	"context"
	"sync"
	"time"

	"pfctl-golang/internal/firewall"
)

// Provider returns static firewall data useful for prototyping and tests.
type Provider struct {
	mu      sync.RWMutex
	blocked []firewall.PacketLogEntry
	passed  []firewall.PacketLogEntry
	rules   []firewall.RuleCounter
}

// New constructs a Provider populated with representative data.
func New() *Provider {
	now := time.Now()
	return &Provider{
		blocked: []firewall.PacketLogEntry{
			{
				Timestamp: now.Add(-10 * time.Second),
				Interface: "wan",
				Source:    "198.51.100.24:44321",
				Dest:      "203.0.113.10:22",
				Protocol:  "tcp",
				Action:    "block",
				Reason:    "block policy",
			},
			{
				Timestamp: now.Add(-3 * time.Second),
				Interface: "lan",
				Source:    "10.0.0.8:55320",
				Dest:      "8.8.8.8:53",
				Protocol:  "udp",
				Action:    "block",
				Reason:    "short state",
			},
		},
		passed: []firewall.PacketLogEntry{
			{
				Timestamp: now.Add(-5 * time.Second),
				Interface: "lan",
				Source:    "10.0.0.5:54512",
				Dest:      "1.1.1.1:443",
				Protocol:  "tcp",
				Action:    "pass",
				Reason:    "stateful",
			},
		},
		rules: []firewall.RuleCounter{
			{
				RuleID:      10,
				RuleLabel:   "Allow LAN to Any",
				Evaluations: 234123,
				Packets:     451234,
				Bytes:       389123940,
			},
			{
				RuleID:      20,
				RuleLabel:   "Block WAN RFC1918",
				Evaluations: 78123,
				Packets:     10234,
				Bytes:       8451230,
			},
		},
	}
}

func (p *Provider) BlockedTraffic(context.Context) ([]firewall.PacketLogEntry, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]firewall.PacketLogEntry(nil), p.blocked...), nil
}

func (p *Provider) PassedTraffic(context.Context) ([]firewall.PacketLogEntry, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]firewall.PacketLogEntry(nil), p.passed...), nil
}

func (p *Provider) RuleCounters(context.Context) ([]firewall.RuleCounter, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]firewall.RuleCounter(nil), p.rules...), nil
}

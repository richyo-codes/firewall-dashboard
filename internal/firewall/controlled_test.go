package firewall

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type controlledTestProvider struct {
	mu           sync.Mutex
	blockedCalls int
	delay        time.Duration
}

func (p *controlledTestProvider) BlockedTraffic(ctx context.Context) ([]PacketLogEntry, error) {
	p.mu.Lock()
	p.blockedCalls++
	p.mu.Unlock()
	select {
	case <-time.After(p.delay):
		return []PacketLogEntry{{Action: "block"}}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *controlledTestProvider) PassedTraffic(context.Context) ([]PacketLogEntry, error) {
	return nil, nil
}

func (p *controlledTestProvider) RuleCounters(context.Context) ([]RuleCounter, error) {
	return nil, nil
}

func (p *controlledTestProvider) StreamTraffic(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

func TestControlledProviderCachesResults(t *testing.T) {
	backend := &controlledTestProvider{}
	provider := NewControlledProvider(backend, ControlOptions{
		CacheTTL:              time.Minute,
		CommandTimeout:        time.Second,
		MaxConcurrentCommands: 1,
		MaxStreams:            1,
	})

	for range 2 {
		if _, err := provider.BlockedTraffic(context.Background()); err != nil {
			t.Fatalf("BlockedTraffic failed: %v", err)
		}
	}
	if backend.blockedCalls != 1 {
		t.Fatalf("expected one backend call, got %d", backend.blockedCalls)
	}
}

func TestControlledProviderCommandTimeout(t *testing.T) {
	backend := &controlledTestProvider{delay: 100 * time.Millisecond}
	provider := NewControlledProvider(backend, ControlOptions{
		CacheTTL:              time.Second,
		CommandTimeout:        10 * time.Millisecond,
		MaxConcurrentCommands: 1,
		MaxStreams:            1,
	})

	if _, err := provider.BlockedTraffic(context.Background()); err == nil {
		t.Fatal("expected command timeout")
	}
}

func TestControlledProviderLimitsStreams(t *testing.T) {
	backend := &controlledTestProvider{}
	provider := NewControlledProvider(backend, ControlOptions{MaxStreams: 1})
	streamer := provider.(StreamProvider)

	first, err := streamer.StreamTraffic(context.Background(), "")
	if err != nil {
		t.Fatalf("first stream failed: %v", err)
	}
	if _, err := streamer.StreamTraffic(context.Background(), ""); err != ErrBusy {
		t.Fatalf("expected ErrBusy, got %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first stream: %v", err)
	}
	second, err := streamer.StreamTraffic(context.Background(), "")
	if err != nil {
		t.Fatalf("stream after release failed: %v", err)
	}
	_ = second.Close()
}

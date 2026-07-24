package firewall

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

// ErrBusy indicates that the configured provider concurrency limit was reached.
var ErrBusy = errors.New("firewall provider busy")

// ControlOptions bounds backend command and stream resource usage.
type ControlOptions struct {
	CacheTTL              time.Duration
	CommandTimeout        time.Duration
	MaxConcurrentCommands int
	MaxStreams            int
}

type resultCache[T any] struct {
	mu      sync.Mutex
	value   T
	expires time.Time
	valid   bool
}

type controlledProvider struct {
	provider       Provider
	cacheTTL       time.Duration
	commandTimeout time.Duration
	commandGate    chan struct{}
	blocked        resultCache[[]PacketLogEntry]
	passed         resultCache[[]PacketLogEntry]
	rules          resultCache[[]RuleCounter]
}

type controlledStreamProvider struct {
	*controlledProvider
	streamer   StreamProvider
	streamGate chan struct{}
}

// NewControlledProvider adds caching, deadlines, and concurrency limits.
func NewControlledProvider(provider Provider, opts ControlOptions) Provider {
	if opts.CacheTTL <= 0 {
		opts.CacheTTL = time.Second
	}
	if opts.CommandTimeout <= 0 {
		opts.CommandTimeout = 5 * time.Second
	}
	if opts.MaxConcurrentCommands <= 0 {
		opts.MaxConcurrentCommands = 2
	}
	if opts.MaxStreams <= 0 {
		opts.MaxStreams = 4
	}

	base := &controlledProvider{
		provider:       provider,
		cacheTTL:       opts.CacheTTL,
		commandTimeout: opts.CommandTimeout,
		commandGate:    make(chan struct{}, opts.MaxConcurrentCommands),
	}
	if streamer, ok := provider.(StreamProvider); ok {
		return &controlledStreamProvider{
			controlledProvider: base,
			streamer:           streamer,
			streamGate:         make(chan struct{}, opts.MaxStreams),
		}
	}
	return base
}

func (p *controlledProvider) BlockedTraffic(ctx context.Context) ([]PacketLogEntry, error) {
	return loadCached(ctx, &p.blocked, p.cacheTTL, func(ctx context.Context) ([]PacketLogEntry, error) {
		return runControlled(p, ctx, p.provider.BlockedTraffic)
	})
}

func (p *controlledProvider) PassedTraffic(ctx context.Context) ([]PacketLogEntry, error) {
	return loadCached(ctx, &p.passed, p.cacheTTL, func(ctx context.Context) ([]PacketLogEntry, error) {
		return runControlled(p, ctx, p.provider.PassedTraffic)
	})
}

func (p *controlledProvider) RuleCounters(ctx context.Context) ([]RuleCounter, error) {
	return loadCached(ctx, &p.rules, p.cacheTTL, func(ctx context.Context) ([]RuleCounter, error) {
		return runControlled(p, ctx, p.provider.RuleCounters)
	})
}

func (p *controlledStreamProvider) StreamTraffic(ctx context.Context, action string) (io.ReadCloser, error) {
	select {
	case p.streamGate <- struct{}{}:
	default:
		return nil, ErrBusy
	}

	stream, err := p.streamer.StreamTraffic(ctx, action)
	if err != nil {
		<-p.streamGate
		return nil, err
	}
	return &releaseReadCloser{
		ReadCloser: stream,
		release:    func() { <-p.streamGate },
	}, nil
}

func loadCached[T any](ctx context.Context, cache *resultCache[T], ttl time.Duration, load func(context.Context) (T, error)) (T, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	if cache.valid && time.Now().Before(cache.expires) {
		return cache.value, nil
	}
	value, err := load(ctx)
	if err != nil {
		var zero T
		return zero, err
	}
	cache.value = value
	cache.expires = time.Now().Add(ttl)
	cache.valid = true
	return value, nil
}

func runControlled[T any](p *controlledProvider, ctx context.Context, run func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, p.commandTimeout)
	defer cancel()

	select {
	case p.commandGate <- struct{}{}:
		defer func() { <-p.commandGate }()
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
	return run(ctx)
}

type releaseReadCloser struct {
	io.ReadCloser
	once    sync.Once
	release func()
	err     error
}

func (r *releaseReadCloser) Close() error {
	r.once.Do(func() {
		r.err = r.ReadCloser.Close()
		r.release()
	})
	return r.err
}

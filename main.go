package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"pfctl-golang/internal/auth"
	"pfctl-golang/internal/config"
	"pfctl-golang/internal/firewall"
	"pfctl-golang/internal/providers"
	"pfctl-golang/internal/vnstat"
)

// uiDist holds the compiled frontend assets.
//
//go:embed ui/dist/*
var uiDist embed.FS

type server struct {
	logger            *log.Logger
	provider          firewall.Provider
	backend           string
	trafficIntervalMs int
	vnstat            *vnstat.Provider
}

func main() {
	handled, err := maybeHandleRCD(os.Args[1:], os.Stdout, os.Stderr)
	if handled {
		if err != nil {
			os.Exit(1)
		}
		return
	}

	handled, err = maybeHandleCompletion(os.Args[1:], os.Stdout, os.Stderr)
	if handled {
		if err != nil {
			os.Exit(1)
		}
		return
	}

	logger := log.New(os.Stdout, "pfctl-dashboard ", log.LstdFlags|log.Lshortfile)

	cfg, flagSet, err := config.Load(os.Args[1:])
	if err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			os.Exit(0)
		}
		logger.Fatalf("failed to load configuration: %v", err)
	}

	provider, resolvedBackend, err := providers.New(
		cfg.Firewall.Backend,
		cfg.Firewall.Debug,
		cfg.Firewall.PF.BlockedSource,
		cfg.Firewall.PF.PflogInterface,
		cfg.Firewall.PF.PflogPath,
	)
	if err != nil {
		logger.Fatalf("failed to initialize firewall backend: %v", err)
	}
	provider = firewall.NewControlledProvider(provider, firewall.ControlOptions{
		CacheTTL:              time.Duration(cfg.Firewall.CacheTTLms) * time.Millisecond,
		CommandTimeout:        time.Duration(cfg.Firewall.CommandTimeoutMs) * time.Millisecond,
		MaxConcurrentCommands: cfg.Firewall.MaxConcurrentCommands,
		MaxStreams:            cfg.Firewall.MaxStreams,
	})
	bandwidth, err := vnstat.New(cfg.VNStat.Enabled, cfg.VNStat.Binary, cfg.VNStat.Interface)
	if err != nil {
		logger.Fatalf("failed to initialize vnStat integration: %v", err)
	}

	authContext, cancelAuth := context.WithTimeout(context.Background(), 15*time.Second)
	authManager, err := auth.NewManager(authContext, cfg.Auth, logger)
	cancelAuth()
	if err != nil {
		logger.Fatalf("failed to configure authentication: %v", err)
	}
	logger.Printf("authentication mode: %s", authManager.Mode())

	srv := &server{
		logger:            logger,
		provider:          provider,
		backend:           resolvedBackend,
		trafficIntervalMs: cfg.Server.Refresh.TrafficIntervalMs,
		vnstat:            bandwidth,
	}

	apiMux := http.NewServeMux()
	apiMux.Handle("GET /api/blocked", withJSON(logger, srv.blockedTraffic))
	apiMux.Handle("GET /api/passed", withJSON(logger, srv.passedTraffic))
	apiMux.Handle("GET /api/traffic", withJSON(logger, srv.combinedTraffic))
	apiMux.Handle("GET /api/rules", withJSON(logger, srv.ruleCounters))
	apiMux.Handle("GET /api/bandwidth", withJSON(logger, srv.bandwidth))
	apiMux.Handle("GET /api/stream/traffic", http.HandlerFunc(srv.streamTraffic))

	mux := http.NewServeMux()
	authManager.RegisterPublicRoutes(mux)
	mux.Handle("GET /api/auth/me", authManager.StatusHandler())
	mux.Handle("GET /api/config/refresh", withJSON(logger, srv.refreshConfig))
	mux.Handle("GET /api/", authManager.Wrap(apiMux))

	uiRoot, err := fs.Sub(uiDist, "ui/dist")
	if err != nil {
		logger.Printf("ui assets missing: %v", err)
		mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "frontend assets not bundled", http.StatusNotFound)
		}))
	} else if !fileExists(uiRoot, "index.html") {
		logger.Printf("ui assets missing: index.html not found in embedded bundle")
		mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "frontend assets not bundled", http.StatusNotFound)
		}))
	} else {
		mux.Handle("GET /", spaHandler(uiRoot))
	}

	flagSet.Visit(func(f *pflag.Flag) {
		logger.Printf("flag %s=%s", f.Name, safeFlagValue(f))
	})

	addr := cfg.Server.Addr
	logger.Printf("serving dashboard on %s using %s backend", addr, resolvedBackend)
	logger.Printf("open %s", launchURL(addr))

	trustedProxies, err := newTrustedProxies(cfg.Server.TrustedProxies)
	if err != nil {
		logger.Fatalf("invalid trusted proxy configuration: %v", err)
	}

	var handler http.Handler = securityHeaders(mux)
	if cfg.Server.HTTPLog {
		handler = logRequests(logger, trustedProxies, handler)
	}

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
		// Traffic streams are long-lived, so a global WriteTimeout is unsuitable.
	}
	if err := httpServer.ListenAndServe(); err != nil {
		logger.Fatalf("server error: %v", err)
	}
}

func safeFlagValue(flag *pflag.Flag) string {
	name := strings.ToLower(flag.Name)
	if strings.Contains(name, "secret") || strings.Contains(name, "password") || strings.Contains(name, "token") {
		return "[REDACTED]"
	}
	return flag.Value.String()
}

func spaHandler(root fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := sanitizePath(r.URL.Path)
		if !fileExists(root, target) {
			target = "index.html"
		}
		http.ServeFileFS(w, r, root, target)
	})
}

func sanitizePath(requestPath string) string {
	clean := path.Clean("/" + requestPath)
	clean = strings.TrimPrefix(clean, "/")
	if clean == "" || strings.HasSuffix(requestPath, "/") {
		return "index.html"
	}
	return clean
}

func fileExists(root fs.FS, name string) bool {
	f, err := root.Open(name)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return false
	}
	if info.IsDir() {
		indexPath := path.Join(name, "index.html")
		indexFile, err := root.Open(indexPath)
		if err != nil {
			return false
		}
		defer func() { _ = indexFile.Close() }()
		_, err = indexFile.Stat()
		return err == nil
	}
	return true
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

func logRequests(logger *log.Logger, trusted trustedProxies, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		writer := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(writer, r)
		duration := time.Since(start)
		logger.Printf("%s %s %d %dB %s remote=%s", r.Method, r.URL.Path, writer.status, writer.bytes, duration.Truncate(time.Millisecond), trusted.remoteAddr(r))
	})
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func (r *responseRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

type trustedProxies []netip.Prefix

func newTrustedProxies(values []string) (trustedProxies, error) {
	proxies := make(trustedProxies, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			addr, addrErr := netip.ParseAddr(value)
			if addrErr != nil {
				return nil, fmt.Errorf("%q is not an IP address or CIDR", value)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		proxies = append(proxies, prefix)
	}
	return proxies, nil
}

func (t trustedProxies) contains(addr netip.Addr) bool {
	for _, prefix := range t {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (t trustedProxies) remoteAddr(r *http.Request) string {
	peerText, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peerText = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(strings.TrimSpace(peerText))
	if err != nil || !t.contains(peer) {
		return r.RemoteAddr
	}

	forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(forwarded) - 1; i >= 0; i-- {
		addr, parseErr := netip.ParseAddr(strings.TrimSpace(forwarded[i]))
		if parseErr == nil && !t.contains(addr) {
			return addr.String()
		}
	}
	if addr, parseErr := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); parseErr == nil {
		return addr.String()
	}
	return peer.String()
}

func launchURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		switch {
		case strings.HasPrefix(addr, ":"):
			host = "localhost"
			port = strings.TrimPrefix(addr, ":")
		case strings.Count(addr, ":") == 0:
			if _, convErr := strconv.Atoi(addr); convErr == nil {
				host = "localhost"
				port = addr
			} else {
				host = addr
			}
		default:
			return "http://localhost:8080"
		}
	}

	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "localhost"
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	if port == "" {
		return "http://" + host
	}
	return fmt.Sprintf("http://%s:%s", host, port)
}

type apiHandler func(r *http.Request) (any, error)

func withJSON(logger *log.Logger, handler apiHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		payload, err := handler(r)
		if err != nil {
			logger.Printf("handler error: %v", err)
			var statusErr interface{ StatusCode() int }
			if errors.As(err, &statusErr) {
				w.WriteHeader(statusErr.StatusCode())
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "backend request failed",
			})
			return
		}
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			logger.Printf("json encode failed: %v", err)
		}
	})
}

func (s *server) blockedTraffic(r *http.Request) (any, error) {
	data, err := s.provider.BlockedTraffic(r.Context())
	if err != nil {
		return nil, fmt.Errorf("blocked traffic: %w", err)
	}
	if data == nil {
		data = []firewall.PacketLogEntry{}
	}
	return data, nil
}

func (s *server) passedTraffic(r *http.Request) (any, error) {
	data, err := s.provider.PassedTraffic(r.Context())
	if err != nil {
		return nil, fmt.Errorf("passed traffic: %w", err)
	}
	if data == nil {
		data = []firewall.PacketLogEntry{}
	}
	return data, nil
}

func (s *server) combinedTraffic(r *http.Request) (any, error) {
	blocked, err := s.provider.BlockedTraffic(r.Context())
	if err != nil {
		return nil, fmt.Errorf("blocked traffic: %w", err)
	}
	passed, err := s.provider.PassedTraffic(r.Context())
	if err != nil {
		return nil, fmt.Errorf("passed traffic: %w", err)
	}
	if blocked == nil {
		blocked = []firewall.PacketLogEntry{}
	}
	if passed == nil {
		passed = []firewall.PacketLogEntry{}
	}

	combined := append(make([]firewall.PacketLogEntry, 0, len(blocked)+len(passed)), blocked...)
	combined = append(combined, passed...)
	sort.Slice(combined, func(i, j int) bool {
		return combined[i].Timestamp.After(combined[j].Timestamp)
	})

	return combined, nil
}

func (s *server) ruleCounters(r *http.Request) (any, error) {
	data, err := s.provider.RuleCounters(r.Context())
	if err != nil {
		return nil, fmt.Errorf("rule counters: %w", err)
	}
	if data == nil {
		data = []firewall.RuleCounter{}
	}
	return data, nil
}

func (s *server) bandwidth(r *http.Request) (any, error) {
	if s.vnstat == nil {
		return nil, errors.New("vnStat integration is unavailable")
	}
	return s.vnstat.Report(r.Context())
}

func (s *server) streamTraffic(w http.ResponseWriter, r *http.Request) {
	streamer, ok := s.provider.(firewall.StreamProvider)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusNotImplemented)
		return
	}

	action := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("action")))
	if action != "" && action != "pass" && action != "block" && action != "rdr" {
		http.Error(w, "invalid action", http.StatusBadRequest)
		return
	}

	rc, err := streamer.StreamTraffic(r.Context(), action)
	if err != nil {
		s.logger.Printf("stream traffic error: %v", err)
		if errors.Is(err, firewall.ErrBusy) {
			http.Error(w, "stream limit reached", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "unable to start stream", http.StatusInternalServerError)
		return
	}
	defer rc.Close()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	if _, err := io.Copy(w, rc); err != nil && !errors.Is(err, context.Canceled) {
		s.logger.Printf("stream copy error: %v", err)
	}
}

func (s *server) refreshConfig(*http.Request) (any, error) {
	supportsUnified := s.backend == "pf"
	supportsBlockedPacketDetails := s.backend == "pf"
	supportsTrafficStream := s.backend == "pf"
	supportsBandwidth := s.vnstat != nil
	return map[string]any{
		"trafficIntervalMs":            s.trafficIntervalMs,
		"backend":                      s.backend,
		"unifiedViewEnabled":           supportsUnified,
		"supportsUnifiedView":          supportsUnified,
		"supportsBlockedPacketDetails": supportsBlockedPacketDetails,
		"supportsTrafficStream":        supportsTrafficStream,
		"supportsRuleCounters":         true,
		"supportsBandwidth":            supportsBandwidth,
	}, nil
}

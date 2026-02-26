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
}

func main() {
	handled, err := maybeHandleCompletion(os.Args[1:], os.Stdout, os.Stderr)
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

	provider, resolvedBackend, err := providers.New(cfg.Firewall.Backend, cfg.Firewall.Debug)
	if err != nil {
		logger.Fatalf("failed to initialize firewall backend: %v", err)
	}

	authManager, err := auth.NewManager(context.Background(), cfg.Auth, logger)
	if err != nil {
		logger.Fatalf("failed to configure authentication: %v", err)
	}
	logger.Printf("authentication mode: %s", authManager.Mode())

	srv := &server{
		logger:            logger,
		provider:          provider,
		backend:           resolvedBackend,
		trafficIntervalMs: cfg.Server.Refresh.TrafficIntervalMs,
	}

	apiMux := http.NewServeMux()
	apiMux.Handle("/api/blocked", withJSON(logger, srv.blockedTraffic))
	apiMux.Handle("/api/passed", withJSON(logger, srv.passedTraffic))
	apiMux.Handle("/api/traffic", withJSON(logger, srv.combinedTraffic))
	apiMux.Handle("/api/rules", withJSON(logger, srv.ruleCounters))
	apiMux.Handle("/api/stream/traffic", http.HandlerFunc(srv.streamTraffic))

	mux := http.NewServeMux()
	authManager.RegisterPublicRoutes(mux)
	mux.Handle("/api/auth/me", authManager.StatusHandler())
	mux.Handle("/api/config/refresh", withJSON(logger, srv.refreshConfig))
	mux.Handle("/api/", authManager.Wrap(apiMux))

	uiRoot, err := fs.Sub(uiDist, "ui/dist")
	if err != nil {
		logger.Printf("ui assets missing: %v", err)
		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "frontend assets not bundled", http.StatusNotFound)
		}))
	} else if !fileExists(uiRoot, "index.html") {
		logger.Printf("ui assets missing: index.html not found in embedded bundle")
		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "frontend assets not bundled", http.StatusNotFound)
		}))
	} else {
		mux.Handle("/", spaHandler(uiRoot))
	}

	flagSet.Visit(func(f *pflag.Flag) {
		logger.Printf("flag %s=%s", f.Name, f.Value)
	})

	addr := cfg.Server.Addr
	logger.Printf("serving dashboard on %s using %s backend", addr, resolvedBackend)
	logger.Printf("open %s", launchURL(addr))

	var handler http.Handler = mux
	if cfg.Server.HTTPLog {
		handler = logRequests(logger, handler)
	}

	if err := http.ListenAndServe(addr, handler); err != nil {
		logger.Fatalf("server error: %v", err)
	}
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

func logRequests(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		writer := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(writer, r)
		duration := time.Since(start)
		logger.Printf("%s %s %d %dB %s remote=%s", r.Method, r.URL.Path, writer.status, writer.bytes, duration.Truncate(time.Millisecond), remoteAddr(r))
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

func remoteAddr(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		parts := strings.Split(ip, ",")
		return strings.TrimSpace(parts[0])
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}
	return r.RemoteAddr
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
				"error": err.Error(),
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
	return map[string]any{
		"trafficIntervalMs":            s.trafficIntervalMs,
		"backend":                      s.backend,
		"unifiedViewEnabled":           supportsUnified,
		"supportsUnifiedView":          supportsUnified,
		"supportsBlockedPacketDetails": supportsBlockedPacketDetails,
		"supportsTrafficStream":        supportsTrafficStream,
		"supportsRuleCounters":         true,
	}, nil
}

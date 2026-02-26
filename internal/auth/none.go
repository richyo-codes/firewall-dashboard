package auth

import "net/http"

func newNoneManager(logger Logger) *Manager {
	m := &Manager{
		mode:   ModeNone,
		logger: logger,
	}
	m.wrap = func(next http.Handler) http.Handler {
		return next
	}

	notEnabled := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "authentication disabled", http.StatusNotFound)
	})

	m.login = notEnabled
	m.callback = notEnabled
	m.logout = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	m.status = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"mode":          ModeNone,
			"authenticated": true,
			"user":          nil,
		})
	}
	return m
}

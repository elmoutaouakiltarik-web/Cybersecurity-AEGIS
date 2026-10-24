package main

import (
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"strings"
)

// AuthMiddleware enforces either:
//   - a live session (cookie set by /api/v1/auth/login, or X-AEGIS-SESSION
//     header fallback), OR
//   - a static API key via Authorization: Bearer <AEGIS_API_KEY>
//
// When AEGIS_AUTH_REQUIRED=false (the default when AEGIS_API_KEY is empty AND
// AEGIS_AUTH_REQUIRED is unset), the middleware is transparent so the
// dashboard "local mode" still works for self-hosted single-user setups.
type AuthMiddleware struct {
	apiKey   string
	required bool
}

// NewAuthMiddleware creates the middleware.
//
//	apiKey: optional shared secret (Bearer token). Empty = no API-key auth path.
//	required: when true, ALL non-public endpoints require a valid session OR
//	a valid API key. When false, requests pass through unauthenticated.
func NewAuthMiddleware(apiKey string) *AuthMiddleware {
	required := apiKey != ""
	// Explicit override via env: AEGIS_AUTH_REQUIRED=true|false
	switch strings.ToLower(strings.TrimSpace(envOrEmpty("AEGIS_AUTH_REQUIRED"))) {
	case "true", "1", "yes":
		required = true
	case "false", "0", "no":
		required = false
	}
	return &AuthMiddleware{apiKey: apiKey, required: required}
}

// Wrap returns an http.Handler that gates non-public paths behind a valid
// session cookie OR a valid API key, when required is true.
func (m *AuthMiddleware) Wrap(next http.Handler) http.Handler {
	if !m.required {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if hasValidSessionRefresh(w, r) {
			next.ServeHTTP(w, r)
			return
		}
		if m.apiKey != "" {
			raw := r.Header.Get("Authorization")
			token := strings.TrimPrefix(raw, "Bearer ")
			if token == "" {
				token = r.URL.Query().Get("api_key")
			}
			if token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(m.apiKey)) == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="Cybersecurity-AEGIS"`)
		respondJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "unauthorized",
			"hint":  "POST /api/v1/auth/login with {username, password} or use Authorization: Bearer <api-key> or X-AEGIS-SESSION: <session_token>",
		})
		log.Printf("auth: rejected %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	})
}

// isPublicEndpoint returns true for paths that do not require authentication.
// Login/me/logout endpoints must be public so the dashboard can authenticate.
// Module-to-orchestrator ingest endpoints are public so internal Python
// services can post events without a shared secret. Treat the orchestrator
// host as a trust boundary (bind to localhost or behind a reverse proxy in
// production).
func isPublicEndpoint(path string) bool {
	if path == "/" || path == "/health" {
		return true
	}
	if strings.HasPrefix(path, "/dashboard/") {
		return true
	}
	if path == "/api/v1/auth/login" || path == "/api/v1/auth/local" || path == "/api/v1/auth/logout" || path == "/api/v1/auth/me" {
		return true
	}
	// Module ingest endpoints: trusted internal callers only — keep the
	// orchestrator bound to localhost or an internal network.
	if strings.HasPrefix(path, "/api/v1/ingest/") {
		return true
	}
	return false
}

func envOrEmpty(key string) string {
	return os.Getenv(key)
}

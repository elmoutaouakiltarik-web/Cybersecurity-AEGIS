package main

import (
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"strings"
)

// ingestKeyHeader carries the shared secret used by first-party collectors
// (Python modules, the local agent and the launcher) when they post events to
// /api/v1/ingest/*. Without it, anyone who can reach the port could inject
// forged events and poison the SIEM, the dashboard and every downstream rule.
const ingestKeyHeader = "X-AEGIS-INGEST-KEY"

// AuthMiddleware enforces either:
//   - a live session (cookie set by /api/v1/auth/login, or X-AEGIS-SESSION
//     header fallback), OR
//   - a static API key via Authorization: Bearer <AEGIS_API_KEY>.
//
// Ingest endpoints are handled separately: they accept the shared ingest key
// (AEGIS_INGEST_KEY) in addition to a session or API key, and they are never
// anonymous while a key is configured — even when AEGIS_AUTH_REQUIRED=false.
//
// When neither an API key nor a required flag is set, non-ingest traffic passes
// through so the dashboard "local mode" keeps working on a loopback-only bind.
type AuthMiddleware struct {
	apiKey    string
	ingestKey string
	required  bool
}

// NewAuthMiddleware creates the middleware.
//
// apiKey is the optional dashboard API key (Bearer token). The ingest key is
// read from AEGIS_INGEST_KEY and falls back to apiKey, so a single shared
// secret protects both paths on small deployments.
func NewAuthMiddleware(apiKey string) *AuthMiddleware {
	required := apiKey != ""
	// Explicit override via env: AEGIS_AUTH_REQUIRED=true|false
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AEGIS_AUTH_REQUIRED"))) {
	case "true", "1", "yes":
		required = true
	case "false", "0", "no":
		required = false
	}
	ingestKey := strings.TrimSpace(os.Getenv("AEGIS_INGEST_KEY"))
	if ingestKey == "" {
		ingestKey = apiKey
	}
	return &AuthMiddleware{apiKey: apiKey, ingestKey: ingestKey, required: required}
}

// HasIngestKey reports whether ingest endpoints are protected by a shared
// secret. main() uses it to warn when the deployment runs unauthenticated.
func (m *AuthMiddleware) HasIngestKey() bool { return m.ingestKey != "" }

// Wrap gates requests behind a session, an API key or the ingest key.
func (m *AuthMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if isIngestEndpoint(path) {
			if m.ingestKey == "" {
				// No secret anywhere: allowed only in open local mode. When
				// authentication is required, fall back to a dashboard session
				// so ingest is never anonymous on a hardened deployment.
				if !m.required || hasValidSession(r) {
					next.ServeHTTP(w, r)
					return
				}
				rejectUnauthorized(w, r, "ingest requires a session or "+ingestKeyHeader)
				return
			}
			if secretEqual(r.Header.Get(ingestKeyHeader), m.ingestKey) ||
				hasValidSession(r) || m.apiKeyMatches(r) {
				next.ServeHTTP(w, r)
				return
			}
			rejectUnauthorized(w, r, "ingest requires "+ingestKeyHeader+" or a valid session")
			return
		}

		if !m.required {
			next.ServeHTTP(w, r)
			return
		}
		if isPublicEndpoint(path) {
			next.ServeHTTP(w, r)
			return
		}
		if hasValidSessionRefresh(w, r) {
			next.ServeHTTP(w, r)
			return
		}
		if m.apiKeyMatches(r) {
			next.ServeHTTP(w, r)
			return
		}
		rejectUnauthorized(w, r, "")
	})
}

func (m *AuthMiddleware) apiKeyMatches(r *http.Request) bool {
	if m.apiKey == "" {
		return false
	}
	token := bearerToken(r)
	return secretEqual(token, m.apiKey)
}

// bearerToken reads only the Authorization header. A key passed in the query
// string ends up in access logs, reverse-proxy logs and browser history.
func bearerToken(r *http.Request) string {
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if raw == "" {
		return ""
	}
	if len(raw) > 7 && strings.EqualFold(raw[:7], "bearer ") {
		return strings.TrimSpace(raw[7:])
	}
	return raw
}

// secretEqual compares two secrets without leaking their length through timing.
func secretEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func rejectUnauthorized(w http.ResponseWriter, r *http.Request, hint string) {
	if hint == "" {
		hint = "POST /api/v1/auth/login with {username, password} or use Authorization: Bearer <api-key> or X-AEGIS-SESSION: <session_token>"
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="Cybersecurity-AEGIS"`)
	respondJSON(w, http.StatusUnauthorized, map[string]string{
		"error": "unauthorized",
		"hint":  hint,
	})
	log.Printf("auth: rejected %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
}

// isIngestEndpoint reports whether the path belongs to the event ingest API.
func isIngestEndpoint(path string) bool {
	return strings.HasPrefix(path, "/api/v1/ingest/")
}

// isPublicEndpoint reports whether a path may be served without credentials.
func isPublicEndpoint(path string) bool {
	if path == "/" || path == "/health" {
		return true
	}
	if strings.HasPrefix(path, "/dashboard/") {
		return true
	}
	// Login/me/logout must stay public so a client can obtain a session.
	if path == "/api/v1/auth/login" || path == "/api/v1/auth/local" ||
		path == "/api/v1/auth/logout" || path == "/api/v1/auth/me" {
		return true
	}
	return false
}

func envOrEmpty(key string) string {
	return os.Getenv(key)
}

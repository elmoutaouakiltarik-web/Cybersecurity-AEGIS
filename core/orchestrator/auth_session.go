package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// ── Session store ────────────────────────────────────────────────────────────
// In-memory only. Sessions disappear on orchestrator restart by design (single
// admin user, short-lived deployment expectation). Cookie carries the SID;
// server validates against this map.

type session struct {
	User      string
	IP        string
	UserAgent string
	Created   time.Time
	Expires   time.Time
}

type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]session
	ttl      time.Duration
}

func newSessionStore(ttl time.Duration) *sessionStore {
	s := &sessionStore{sessions: map[string]session{}, ttl: ttl}
	go s.janitor()
	return s
}

func (s *sessionStore) janitor() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for id, sess := range s.sessions {
			if now.After(sess.Expires) {
				delete(s.sessions, id)
			}
		}
		s.mu.Unlock()
	}
}

func (s *sessionStore) Create(user, ip, ua string) (string, session) {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	sid := hex.EncodeToString(buf)
	now := time.Now()
	sess := session{User: user, IP: ip, UserAgent: ua, Created: now, Expires: now.Add(s.ttl)}
	s.mu.Lock()
	s.sessions[sid] = sess
	s.mu.Unlock()
	return sid, sess
}

func (s *sessionStore) Get(sid string) (session, bool) {
	if sid == "" {
		return session{}, false
	}
	s.mu.RLock()
	sess, ok := s.sessions[sid]
	s.mu.RUnlock()
	if !ok {
		return session{}, false
	}
	if time.Now().After(sess.Expires) {
		s.Delete(sid)
		return session{}, false
	}
	return sess, true
}

func (s *sessionStore) Touch(sid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[sid]; ok {
		sess.Expires = time.Now().Add(s.ttl)
		s.sessions[sid] = sess
	}
}

func (s *sessionStore) Delete(sid string) {
	s.mu.Lock()
	delete(s.sessions, sid)
	s.mu.Unlock()
}

// ── Admin credential (single-user) ───────────────────────────────────────────
// Password is hashed at startup with a per-process random salt. Plain password
// is never written to disk. Credentials are configurable via env:
//   AEGIS_ADMIN_USER     (default: admin)
//   AEGIS_ADMIN_PASSWORD (if unset, a random one is generated and printed at startup)

// Argon2id parameters. Tuned for an interactive single-admin login: ~64 MiB
// and a few milliseconds per verification on commodity hardware.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 2
	argonKeyLen  = 32
)

type adminCreds struct {
	user string
	salt []byte
	hash []byte
}

func hashPassword(pw string, salt []byte) []byte {
	return argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

func newAdminCreds() *adminCreds {
	user := os.Getenv("AEGIS_ADMIN_USER")
	if user == "" {
		user = "admin"
	}
	pw := os.Getenv("AEGIS_ADMIN_PASSWORD")
	if pw == "" {
		// No default password is shipped: generate a random one for this run.
		buf := make([]byte, 18)
		_, _ = rand.Read(buf)
		pw = hex.EncodeToString(buf)
		fmt.Fprintf(os.Stderr, "[aegis] AEGIS_ADMIN_PASSWORD not set; generated one-time admin password: %s\n", pw)
	}
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	return &adminCreds{user: user, salt: salt, hash: hashPassword(pw, salt)}
}

func (a *adminCreds) Verify(user, pw string) bool {
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(user)), []byte(a.user)) != 1 {
		return false
	}
	got := hashPassword(pw, a.salt)
	return subtle.ConstantTimeCompare(got, a.hash) == 1
}

// ── Globals wired in main() ──────────────────────────────────────────────────

var (
	globalSessions *sessionStore
	globalAdmin    *adminCreds
)

func ensureAuthGlobals() {
	if globalSessions == nil {
		// 24h session TTL with sliding refresh on every authenticated call.
		// Override via env: AEGIS_SESSION_TTL_HOURS (e.g. "168" for 7 days).
		ttlH := 24
		if v := os.Getenv("AEGIS_SESSION_TTL_HOURS"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 24*30 {
				ttlH = n
			}
		}
		globalSessions = newSessionStore(time.Duration(ttlH) * time.Hour)
	}
	if globalAdmin == nil {
		globalAdmin = newAdminCreds()
	}
}

// ── Cookie / header session helpers ──────────────────────────────────────────

const sessionCookieName = "aegis_sid"

func setSessionCookie(w http.ResponseWriter, sid string, ttl time.Duration) {
	c := &http.Cookie{
		Name:  sessionCookieName,
		Value: sid,
		Path:  "/",
		// Use MaxAge — more reliable than Expires across browsers/timezones.
		MaxAge:   int(ttl.Seconds()),
		Expires:  time.Now().Add(ttl),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Secure not set: dashboard binds to http://127.0.0.1, no TLS.
	}
	http.SetCookie(w, c)
}

func clearSessionCookie(w http.ResponseWriter) {
	c := &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, c)
}

func readSessionCookie(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c == nil {
		return ""
	}
	return c.Value
}

// readSessionID reads session ID from cookie first, then from header fallback.
// Header fallback is required for dashboard opened as file:// where browsers
// may not replay SameSite=Lax cookies on cross-origin fetch calls.
func readSessionID(r *http.Request) string {
	if sid := readSessionCookie(r); sid != "" {
		return sid
	}
	return strings.TrimSpace(r.Header.Get("X-AEGIS-SESSION"))
}

// ── Brute-force lockout ──────────────────────────────────────────────────────
// Keeps a sliding window of failed attempts per source IP. When the count
// reaches lockoutThreshold within lockoutWindow, all attempts return 429 for
// the next lockoutDuration. The store is in-memory only.

type bruteforceStore struct {
	mu       sync.Mutex
	failures map[string][]time.Time // key = remoteIP, value = timestamps
	locked   map[string]time.Time   // key = remoteIP, value = unlock time
}

var bruteforce = &bruteforceStore{
	failures: map[string][]time.Time{},
	locked:   map[string]time.Time{},
}

const (
	lockoutThreshold = 5
	lockoutWindow    = 15 * time.Minute
	lockoutDuration  = 15 * time.Minute
)

func bfClientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if host == "" {
		host = "unknown"
	}
	return host
}

func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (b *bruteforceStore) check(ip string) (locked bool, until time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if t, ok := b.locked[ip]; ok {
		if time.Now().Before(t) {
			return true, t
		}
		delete(b.locked, ip)
	}
	return false, time.Time{}
}

func (b *bruteforceStore) recordFailure(ip string) (lockedNow bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-lockoutWindow)
	fl := b.failures[ip]
	pruned := fl[:0]
	for _, t := range fl {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	pruned = append(pruned, now)
	b.failures[ip] = pruned
	if len(pruned) >= lockoutThreshold {
		b.locked[ip] = now.Add(lockoutDuration)
		b.failures[ip] = nil
		return true
	}
	return false
}

func (b *bruteforceStore) reset(ip string) {
	b.mu.Lock()
	delete(b.failures, ip)
	delete(b.locked, ip)
	b.mu.Unlock()
}

// ── HTTP handlers ────────────────────────────────────────────────────────────

func (o *Orchestrator) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, jsonErr("method not allowed"))
		return
	}
	ensureAuthGlobals()
	clientIP := bfClientIP(r)
	if locked, until := bruteforce.check(clientIP); locked {
		retry := int(time.Until(until).Seconds())
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		respondJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":         "Troppi tentativi falliti. Account temporaneamente bloccato.",
			"locked_until":  until.Format(time.RFC3339),
			"retry_after_s": retry,
		})
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if !globalAdmin.Verify(body.Username, body.Password) {
		lockedNow := bruteforce.recordFailure(clientIP)
		if o.auditLog != nil {
			detail := "invalid credentials"
			if lockedNow {
				detail = "invalid credentials (5° fallimento — lockout 15min)"
			}
			o.auditLog.Append("auth_login_failed", body.Username, detail, r.RemoteAddr, "high")
		}
		respondJSON(w, http.StatusUnauthorized, map[string]any{
			"error":  "invalid credentials",
			"locked": lockedNow,
		})
		return
	}
	bruteforce.reset(clientIP)
	sid, sess := globalSessions.Create(globalAdmin.user, r.RemoteAddr, r.UserAgent())
	setSessionCookie(w, sid, globalSessions.ttl)
	if o.auditLog != nil {
		o.auditLog.Append("auth_login", sess.User, "session created", r.RemoteAddr, "info")
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"user":          sess.User,
		"expires":       sess.Expires.Format(time.RFC3339),
		"ttl_sec":       int(globalSessions.ttl.Seconds()),
		"session_token": sid,
		"message":       "login successful",
	})
}

func (o *Orchestrator) handleAuthLocal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, jsonErr("method not allowed"))
		return
	}
	if !isLoopbackRequest(r) {
		respondJSON(w, http.StatusForbidden, map[string]string{
			"error": "local login is only available from localhost",
		})
		return
	}
	// Opt-in hardening: a passwordless loopback session endpoint is a bypass
	// of the admin credential (a browser-driven cross-site POST from
	// 127.0.0.1 would be accepted as "local"). Disabled by default; enable
	// explicitly with AEGIS_LOCAL_LOGIN=true on trusted single-user setups.
	if strings.ToLower(strings.TrimSpace(os.Getenv("AEGIS_LOCAL_LOGIN"))) != "true" {
		respondJSON(w, http.StatusForbidden, map[string]string{
			"error": "local passwordless login is disabled (set AEGIS_LOCAL_LOGIN=true to enable)",
		})
		return
	}
	ensureAuthGlobals()
	sid, sess := globalSessions.Create("local", r.RemoteAddr, r.UserAgent())
	setSessionCookie(w, sid, globalSessions.ttl)
	if o.auditLog != nil {
		o.auditLog.Append("auth_local_login", sess.User, "localhost session created", r.RemoteAddr, "info")
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"user":          sess.User,
		"expires":       sess.Expires.Format(time.RFC3339),
		"ttl_sec":       int(globalSessions.ttl.Seconds()),
		"session_token": sid,
		"message":       "local login successful",
	})
}

func (o *Orchestrator) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	ensureAuthGlobals()
	sid := readSessionID(r)
	if sid != "" {
		globalSessions.Delete(sid)
	}
	clearSessionCookie(w)
	if o.auditLog != nil {
		o.auditLog.Append("auth_logout", "session", "user logged out", r.RemoteAddr, "info")
	}
	respondJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (o *Orchestrator) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	ensureAuthGlobals()
	sid := readSessionID(r)
	if sess, ok := globalSessions.Get(sid); ok {
		globalSessions.Touch(sid)
		respondJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"user":          sess.User,
			"expires":       sess.Expires.Format(time.RFC3339),
		})
		return
	}
	// Allow API-key auth fallback to also appear authenticated
	if hasValidAPIKey(r) {
		respondJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": "api"})
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"authenticated": false})
}

// ── Helpers used by middleware ───────────────────────────────────────────────

// hasValidSessionRefresh extends the session and re-emits the cookie with a
// fresh MaxAge so the browser keeps the cookie around even after long
// inactive periods. Used by the auth middleware.
func hasValidSessionRefresh(w http.ResponseWriter, r *http.Request) bool {
	ensureAuthGlobals()
	sid := readSessionID(r)
	if sid == "" {
		return false
	}
	_, ok := globalSessions.Get(sid)
	if ok {
		globalSessions.Touch(sid)
		// Sliding refresh on the browser side too
		setSessionCookie(w, sid, globalSessions.ttl)
	}
	return ok
}

// hasValidSession returns true if the request carries a live session (cookie
// or X-AEGIS-SESSION header).
func hasValidSession(r *http.Request) bool {
	ensureAuthGlobals()
	sid := readSessionID(r)
	if sid == "" {
		return false
	}
	_, ok := globalSessions.Get(sid)
	if ok {
		globalSessions.Touch(sid)
	}
	return ok
}

// hasValidAPIKey checks the Authorization header against AEGIS_API_KEY.
// Query-string keys are deliberately not accepted: they leak into logs.
func hasValidAPIKey(r *http.Request) bool {
	key := os.Getenv("AEGIS_API_KEY")
	if key == "" {
		return false
	}
	return secretEqual(bearerToken(r), key)
}

func jsonErr(msg string) error { return &errString{msg} }

type errString struct{ s string }

func (e *errString) Error() string { return e.s }

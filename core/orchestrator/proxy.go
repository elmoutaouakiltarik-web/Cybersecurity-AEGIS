package main

import (
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// moduleProxyBase resolves the upstream base URL for each module.
// Environment variable AEGIS_PROXY_<MODULE> overrides the default (for Docker/Kubernetes).
func moduleProxyBase(name string) string {
	envKey := "AEGIS_PROXY_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	defaults := map[string]string{
		"network":         "http://localhost:8081",
		"siem":            "http://localhost:8082",
		"soar":            "http://localhost:8083",
		"threat-intel":    "http://localhost:8084",
		"vuln":            "http://localhost:8085",
		"reports":         "http://localhost:8086",
		"ot":              "http://localhost:8087",
		"endpoint":        "http://localhost:8088",
		"ml":              "http://localhost:8919",
		"integrations":    "http://localhost:8090",
		"sigma":           "http://localhost:8091",
		"ot-protocols":    "http://localhost:8092",
		"dfir":            "http://localhost:8093",
		"compliance":      "http://localhost:8094",
		"evidence":        "http://localhost:8095",
		"pki":             "http://localhost:8096",
		"site-assessment": "http://localhost:8097",
	}
	return defaults[name]
}

// proxyClient timeout is generous so long-running audits (hardening audit
// scans 12+ PowerShell checks) and on-demand AV scans don't time out at the
// orchestrator boundary. The browser/UX layer still imposes its own timeout.
var proxyClient = &http.Client{Timeout: 5 * time.Minute}

// makeModuleProxyWithFallback proxies to module:subpath; if the upstream is
// unreachable, it invokes the fallback handler instead of returning 503.
func (o *Orchestrator) makeModuleProxyWithFallback(module, subpath string, fallback http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetBase := moduleProxyBase(module)
		targetURL := targetBase + "/" + subpath
		if r.URL.RawQuery != "" {
			targetURL += "?" + r.URL.RawQuery
		}
		req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
		if err != nil {
			fallback(w, r)
			return
		}
		req.Header = r.Header.Clone()
		req.Header.Del("Origin")
		req.Host = ""
		resp, err := proxyClient.Do(req)
		if err != nil {
			fallback(w, r)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			if k == "Access-Control-Allow-Origin" {
				continue
			}
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}

// makeModuleProxy returns an http.HandlerFunc that proxies to module:subpath.
// Used for shortcut /api/scan/*, /api/report, /api/ti/lookup endpoints.
func (o *Orchestrator) makeModuleProxy(module, subpath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetBase := moduleProxyBase(module)
		if targetBase == "" {
			respondJSON(w, http.StatusNotFound, map[string]string{"error": "unknown module: " + module})
			return
		}
		targetURL := targetBase + "/" + subpath
		if r.URL.RawQuery != "" {
			targetURL += "?" + r.URL.RawQuery
		}

		var body io.Reader
		if r.Body != nil {
			defer r.Body.Close()
			body = r.Body
		}

		req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, body)
		if err != nil {
			respondJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		req.Header = r.Header.Clone()
		req.Header.Del("Origin")
		req.Host = ""

		resp, err := proxyClient.Do(req)
		if err != nil {
			respondJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error":  "module offline: " + module,
				"detail": err.Error(),
			})
			return
		}
		defer resp.Body.Close()

		for k, vv := range resp.Header {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				continue // CORS already set by withCORS middleware
			}
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}

func (o *Orchestrator) handleProxy(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proxy/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 1 || parts[0] == "" {
		respondJSON(w, 400, map[string]string{"error": "missing module"})
		return
	}
	module := parts[0]
	targetBase := moduleProxyBase(module)
	if targetBase == "" {
		respondJSON(w, 404, map[string]string{"error": "unknown module"})
		return
	}

	subpath := ""
	if len(parts) > 1 {
		subpath = parts[1]
	}
	targetURL := targetBase + "/" + subpath
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	body := r.Body
	if body != nil {
		defer body.Close()
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, body)
	if err != nil {
		respondJSON(w, http.StatusBadGateway, map[string]string{
			"error":  "could not build upstream request",
			"detail": err.Error(),
		})
		return
	}
	req.Header = r.Header.Clone()
	req.Header.Del("Origin")
	req.Host = ""

	resp, err := proxyClient.Do(req)
	if err != nil {
		// Module offline: return an explicit error instead of fabricated data.
		respondJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":  "module offline",
			"module": module,
			"detail": err.Error(),
			"hint":   "avvia il container con: docker compose -f docker-compose.full.yml up -d " + module,
		})
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		if strings.HasPrefix(strings.ToLower(k), "access-control-") {
			continue // CORS already set by withCORS middleware
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

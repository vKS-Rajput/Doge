package benchmark

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync"
)

// SyntheticCacheApp is a reporting gateway with a reverse caching proxy.
// It contains a planted architectural flaw:
// Cache Key Normalization Collision Bleed (BENCH-005).
//
// The reverse proxy normalizes URI paths using canonical path cleaning (e.g. resolving dot-dots)
// to construct the cache key. When a request to `/api/v1/reports/private/..%2Fpublic` is sent,
// the proxy computes cache key `/api/v1/reports/public`, while the origin backend server
// routes the request based on prefix `/api/v1/reports/private/` returning confidential data.
// The private response is stored under the public cache key, enabling unauthenticated callers
// to exfiltrate confidential reports via cache poisoning / normalization collision.
type SyntheticCacheApp struct {
	server       *httptest.Server
	mu           sync.RWMutex
	cacheStore   map[string]cacheEntry
	confidential string
}

type cacheEntry struct {
	Body        string
	ContentType string
	StatusCode  int
}

// NewSyntheticCacheApp creates and starts the synthetic cached reporting application.
func NewSyntheticCacheApp() *SyntheticCacheApp {
	app := &SyntheticCacheApp{
		cacheStore:   make(map[string]cacheEntry),
		confidential: "CONFIDENTIAL AUDIT: Project Titan M&A Target Valuation $4,200,000,000 USD",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.handleHealth)
	mux.HandleFunc("/api/v1/docs", app.handleDocs)
	mux.HandleFunc("/api/v1/reports/public", app.handlePublicReport)
	mux.HandleFunc("/api/v1/reports/private/", app.handlePrivateReport)

	// Wrap mux with the reverse proxy caching layer
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app.serveWithCacheProxy(mux, w, r)
	})

	app.server = httptest.NewServer(proxyHandler)
	return app
}

func (a *SyntheticCacheApp) URL() string {
	return a.server.URL
}

func (a *SyntheticCacheApp) BaseURL() string {
	return a.server.URL
}

func (a *SyntheticCacheApp) Close() {
	a.server.Close()
}

func (a *SyntheticCacheApp) Credentials() map[string]string {
	return map[string]string{
		"admin": "Bearer token-admin-reports-999",
		"guest": "", // unauthenticated
	}
}

func (a *SyntheticCacheApp) serveWithCacheProxy(backend http.Handler, w http.ResponseWriter, r *http.Request) {
	// 1. Proxy computes cache key via canonical path normalization
	rawPath := r.URL.Path
	// Proxy decodes %2F and cleans path
	normalizedPath := strings.ReplaceAll(rawPath, "%2F", "/")
	normalizedPath = strings.ReplaceAll(normalizedPath, "%2f", "/")
	cacheKey := path.Clean(normalizedPath)

	a.mu.RLock()
	cached, exists := a.cacheStore[cacheKey]
	a.mu.RUnlock()

	// 2. Serve from cache if present
	if exists && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", cached.ContentType)
		w.Header().Set("X-Cache", "HIT")
		w.Header().Set("X-Cache-Key", cacheKey)
		w.WriteHeader(cached.StatusCode)
		w.Write([]byte(cached.Body))
		return
	}

	// 3. Cache MISS -> Forward to origin backend
	rec := httptest.NewRecorder()
	backend.ServeHTTP(rec, r)

	// Copy headers and status to actual writer
	for k, v := range rec.Header() {
		w.Header()[k] = v
	}
	w.Header().Set("X-Cache", "MISS")
	w.Header().Set("X-Cache-Key", cacheKey)
	w.WriteHeader(rec.Code)
	w.Write(rec.Body.Bytes())

	// Store in proxy cache if response is 200 OK
	if rec.Code == http.StatusOK && r.Method == http.MethodGet {
		a.mu.Lock()
		a.cacheStore[cacheKey] = cacheEntry{
			Body:        rec.Body.String(),
			ContentType: rec.Header().Get("Content-Type"),
			StatusCode:  rec.Code,
		}
		a.mu.Unlock()
	}
}

func (a *SyntheticCacheApp) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status": "healthy",
		"proxy":  "Edge CDN Reverse Proxy v2.4",
	})
}

func (a *SyntheticCacheApp) handleDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"endpoints": []map[string]any{
			{"path": "/health", "method": "GET", "description": "Edge Proxy Health"},
			{"path": "/api/v1/docs", "method": "GET", "description": "Documentation"},
			{"path": "/api/v1/reports/public", "method": "GET", "description": "Public community transparency report"},
			{"path": "/api/v1/reports/private/{id}", "method": "GET", "description": "Confidential executive audit reports (Admin only)"},
		},
	})
}

func (a *SyntheticCacheApp) handlePublicReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"report_type": "public",
		"title":       "Q3 General Transparency Summary",
		"summary":     "All standard services operational within SLA bounds.",
	})
}

func (a *SyntheticCacheApp) handlePrivateReport(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	// Require valid admin token for private reports
	if auth != "Bearer token-admin-reports-999" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{
			"error": "Forbidden: Requires administrative credentials to access private reports",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"report_type":    "confidential_executive",
		"classification": "TOP SECRET",
		"payload":        a.confidential,
	})
}

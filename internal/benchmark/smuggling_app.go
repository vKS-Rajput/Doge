package benchmark

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// SmugglingApp represents BENCH-010 (Benchmark J):
// A genuinely novel protocol desynchronization & request smuggling pipeline flaw.
// The reverse proxy parses Content-Length, while the backend processes Transfer-Encoding chunked,
// allowing unauthenticated attackers to poison the persistent connection pipeline.
type SmugglingApp struct {
	mu           sync.Mutex
	server       *httptest.Server
	adminSession string
	poisonedReq  string
	requestCount int
}

// NewSmugglingApp starts the mock multi-tier target server.
func NewSmugglingApp() *SmugglingApp {
	app := &SmugglingApp{
		adminSession: "ADMIN_ROOT_SECRET_SESSION_TOKEN_88319",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.handleHealth)
	mux.HandleFunc("/api/v1/gateway/forward", app.handleForward)
	mux.HandleFunc("/api/v1/admin/vault", app.handleAdminVault)

	app.server = httptest.NewServer(mux)
	return app
}

// URL returns the test server URL.
func (s *SmugglingApp) URL() string {
	return s.server.URL
}

// Close terminates the mock server.
func (s *SmugglingApp) Close() {
	s.server.Close()
}

func (s *SmugglingApp) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "healthy",
		"service": "protocol-gateway-proxy",
	})
}

// handleForward simulates a reverse proxy forwarding requests to a backend.
// PLANTED NOVEL FLAW (TE.CL Pipeline Desync):
// If request has both Content-Length and Transfer-Encoding (or obfuscated Transfer-Encoding: \tchunked),
// the proxy reads Content-Length bytes, but forwards the remainder onto the persistent socket!
func (s *SmugglingApp) handleForward(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requestCount++
	s.mu.Unlock()

	bodyBytes, _ := io.ReadAll(r.Body)
	bodyStr := string(bodyBytes)

	teHeader := r.Header.Get("Transfer-Encoding")
	clHeader := r.Header.Get("Content-Length")

	// Check if this is a pipeline poisoning exploit
	// Smuggled prefix: "0\r\n\r\nGET /api/v1/admin/vault"
	if (teHeader != "" && clHeader != "") || strings.Contains(bodyStr, "GET /api/v1/admin/vault") {
		if strings.Contains(bodyStr, "GET /api/v1/admin/vault") {
			s.mu.Lock()
			s.poisonedReq = "POISONED_PIPELINE_ADMIN_ACCESS"
			s.mu.Unlock()

			// Delay to simulate backend protocol desync framing
			time.Sleep(15 * time.Millisecond)

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Pipeline-Desync-Detected", "true")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":              "desync_success",
				"poisoned":            true,
				"leaked_admin_vault":  s.adminSession,
				"backend_desync_type": "TE.CL_Protocol_Smuggling",
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":   "forwarded",
		"received": len(bodyBytes),
	})
}

func (s *SmugglingApp) handleAdminVault(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer "+s.adminSession {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"vault":  "classified_infrastructure_keys",
		"secret": s.adminSession,
	})
}

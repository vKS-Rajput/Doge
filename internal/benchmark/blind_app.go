package benchmark

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// BlindOracleApp represents BENCH-008: a target app with a silent, blind timing injection oracle.
type BlindOracleApp struct {
	mu           sync.Mutex
	server       *httptest.Server
	secretToken  string
	requestCount int
}

// NewBlindOracleApp starts a mock target with a planted blind timing oracle.
func NewBlindOracleApp() *BlindOracleApp {
	app := &BlindOracleApp{
		secretToken: "SUPER_SECRET_VAULT_KEY_771",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.handleHealth)
	mux.HandleFunc("/api/v1/users/lookup", app.handleLookup)

	app.server = httptest.NewServer(mux)
	return app
}

// URL returns the test server URL.
func (b *BlindOracleApp) URL() string {
	return b.server.URL
}

// Close terminates the mock server.
func (b *BlindOracleApp) Close() {
	b.server.Close()
}

func (b *BlindOracleApp) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "healthy",
		"service": "blind-oracle-service",
	})
}

// handleLookup contains the planted blind timing oracle:
// If query parameter 'id' contains a sleep condition matching a character in secretToken, it delays execution.
func (b *BlindOracleApp) handleLookup(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	b.mu.Lock()
	b.requestCount++
	b.mu.Unlock()

	// Generic response headers
	w.Header().Set("Content-Type", "application/json")

	// Blind injection timing check:
	// Example payload: "1' AND (SELECT 1 WHERE SUBSTR(secret,1,1)='S') AND SLEEP(35)--"
	idUpper := strings.ToUpper(id)
	if strings.Contains(idUpper, "SLEEP") || strings.Contains(idUpper, "PG_SLEEP") || strings.Contains(idUpper, "WAITFOR DELAY") {
		// Check if condition matches secret prefix
		matched := false
		if strings.Contains(id, "SUBSTR(secret,1,1)='S'") || strings.Contains(id, "secret LIKE 'S%'") || strings.Contains(id, "CHAR(83)") {
			matched = true
		} else if strings.Contains(id, "1=1") {
			matched = true
		}

		if matched {
			time.Sleep(35 * time.Millisecond) // Timing delay oracle
		}
	}

	// Always returns the exact same opaque body (no error reflection)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    "evaluated",
		"record_id": "anon_record",
	})
}

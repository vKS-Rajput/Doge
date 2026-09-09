package benchmark

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// SyntheticEmergentApp is an enterprise API gateway application with a planted
// architectural flaw: Batch Pipeline Context Bleed.
//
// Standalone endpoints enforce strict authentication and tenant authorization (403).
// However, the batch execution engine (/api/v1/batch) reuses a thread/context structure
// across sub-operation execution frames without clearing authorization state, allowing
// subsequent unprivileged sub-operations in a batch to execute with the privileges of
// a preceding sub-operation.
type SyntheticEmergentApp struct {
	server  *httptest.Server
	mu      sync.RWMutex
	secrets map[string]emergentSecret
}

type emergentSecret struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	Name      string `json:"name"`
	SecretVal string `json:"secret_val"`
}

// NewSyntheticEmergentApp creates and starts the synthetic emergent target application.
func NewSyntheticEmergentApp() *SyntheticEmergentApp {
	app := &SyntheticEmergentApp{
		secrets: map[string]emergentSecret{
			"sec-alpha-001": {
				ID:        "sec-alpha-001",
				TenantID:  "tenant-alpha",
				Name:      "Alpha Service Database Key",
				SecretVal: "alpha-db-pass-xyz888",
			},
			"sec-beta-999": {
				ID:        "sec-beta-999",
				TenantID:  "tenant-beta",
				Name:      "Beta Executive Vault Credentials",
				SecretVal: "CLASSIFIED-BETA-ROOT-KEY-99942",
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleIndex)
	mux.HandleFunc("/health", app.handleHealth)
	mux.HandleFunc("/api/v1/docs", app.handleDocs)
	mux.HandleFunc("/api/v1/me", app.handleMe)
	mux.HandleFunc("/api/v1/public/ping", app.handlePublicPing)
	mux.HandleFunc("/api/v1/vault/secrets/", app.handleSecret)
	mux.HandleFunc("/api/v1/batch", app.handleBatch)

	app.server = httptest.NewServer(mux)
	return app
}

// Close shuts down the synthetic server.
func (a *SyntheticEmergentApp) Close() {
	a.server.Close()
}

// BaseURL returns the test server URL.
func (a *SyntheticEmergentApp) BaseURL() string {
	return a.server.URL
}

// Credentials provides user access tokens.
func (a *SyntheticEmergentApp) Credentials() map[string]string {
	return map[string]string{
		"user-alpha-001": "alpha-token-111",
		"user-beta-002":  "beta-token-222",
	}
}

// GetPlantedVulnerabilities returns metadata for trajectory verification.
func (a *SyntheticEmergentApp) GetPlantedVulnerabilities() SyntheticAppInfo {
	return SyntheticAppInfo{
		PlantedVulnerabilities: []PlantedVulnerability{
			{
				ID:          "BENCH-003",
				Type:        "BATCH_CONTEXT_BLEED",
				Endpoint:    "/api/v1/batch",
				Description: "Batch execution pipeline fails to clear thread context between operations. Sub-operations inherit prior authorization state.",
			},
		},
	}
}

func (a *SyntheticEmergentApp) authenticateToken(authHeader string) (userID, tenantID string, ok bool) {
	token := strings.TrimPrefix(authHeader, "Bearer ")
	switch token {
	case "alpha-token-111":
		return "user-alpha-001", "tenant-alpha", true
	case "beta-token-222":
		return "user-beta-002", "tenant-beta", true
	default:
		return "", "", false
	}
}

func (a *SyntheticEmergentApp) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"service": "enterprise-gateway",
		"version": "2.4",
		"endpoints": []string{
			"/health",
			"/api/v1/docs",
			"/api/v1/me",
			"/api/v1/public/ping",
			"/api/v1/vault/secrets/{id}",
			"/api/v1/batch",
		},
	})
}

func (a *SyntheticEmergentApp) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "enterprise-gateway"})
}

func (a *SyntheticEmergentApp) handleDocs(w http.ResponseWriter, r *http.Request) {
	docs := map[string]any{
		"service": "Enterprise Gateway API",
		"endpoints": []map[string]string{
			{"method": "GET", "path": "/api/v1/me", "description": "Get current identity context"},
			{"method": "GET", "path": "/api/v1/public/ping", "description": "Public health ping"},
			{"method": "GET", "path": "/api/v1/vault/secrets/{id}", "description": "Retrieve secret by ID (tenant isolated)"},
			{"method": "POST", "path": "/api/v1/batch", "description": "Execute batch operations pipeline"},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(docs)
}

func (a *SyntheticEmergentApp) handleMe(w http.ResponseWriter, r *http.Request) {
	userID, tenantID, ok := a.authenticateToken(r.Header.Get("Authorization"))
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":        userID,
		"tenant_id": tenantID,
	})
}

func (a *SyntheticEmergentApp) handlePublicPing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"ping": "pong"})
}

func (a *SyntheticEmergentApp) handleSecret(w http.ResponseWriter, r *http.Request) {
	userID, tenantID, ok := a.authenticateToken(r.Header.Get("Authorization"))
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	secretID := strings.TrimPrefix(r.URL.Path, "/api/v1/vault/secrets/")
	a.mu.RLock()
	sec, exists := a.secrets[secretID]
	a.mu.RUnlock()

	if !exists {
		http.NotFound(w, r)
		return
	}

	// Standalone access control strictly enforced:
	if sec.TenantID != tenantID {
		http.Error(w, fmt.Sprintf(`{"error":"forbidden: tenant %s cannot access %s owned by %s"}`, tenantID, secretID, sec.TenantID), http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"secret":       sec,
		"retrieved_by": userID,
	})
}

// handleBatch implements the batch execution pipeline with the planted context bleed flaw.
func (a *SyntheticEmergentApp) handleBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Operations []struct {
			ID      string            `json:"id"`
			Method  string            `json:"method"`
			Path    string            `json:"path"`
			Headers map[string]string `json:"headers,omitempty"`
			Body    string            `json:"body,omitempty"`
		} `json:"operations"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid batch json", http.StatusBadRequest)
		return
	}

	type subResult struct {
		OpID       string `json:"op_id"`
		StatusCode int    `json:"status_code"`
		Body       string `json:"body"`
	}

	var results []subResult

	// Context structure across the pipeline frames
	var currentUserID string
	var currentTenantID string

	// Initialize with top-level request auth if present
	if auth := r.Header.Get("Authorization"); auth != "" {
		currentUserID, currentTenantID, _ = a.authenticateToken(auth)
	}

	for _, op := range req.Operations {
		// If sub-operation has its own Authorization header, update context:
		if opAuth, hasAuth := op.Headers["Authorization"]; hasAuth && opAuth != "" {
			uID, tID, ok := a.authenticateToken(opAuth)
			if ok {
				currentUserID = uID
				currentTenantID = tID
			}
		}

		// FLAW: If sub-operation has NO auth header, it FAILS to clear currentUserID / currentTenantID!
		// It reuses the authorization context from the preceding operation frame!

		switch {
		case strings.HasPrefix(op.Path, "/api/v1/public/ping"):
			results = append(results, subResult{
				OpID:       op.ID,
				StatusCode: 200,
				Body:       `{"ping":"pong"}`,
			})

		case strings.HasPrefix(op.Path, "/api/v1/vault/secrets/"):
			secID := strings.TrimPrefix(op.Path, "/api/v1/vault/secrets/")
			a.mu.RLock()
			sec, exists := a.secrets[secID]
			a.mu.RUnlock()

			if !exists {
				results = append(results, subResult{OpID: op.ID, StatusCode: 404, Body: `{"error":"not found"}`})
			} else if currentTenantID == "" {
				results = append(results, subResult{OpID: op.ID, StatusCode: 401, Body: `{"error":"unauthorized"}`})
			} else if sec.TenantID != currentTenantID {
				results = append(results, subResult{
					OpID:       op.ID,
					StatusCode: 403,
					Body:       fmt.Sprintf(`{"error":"forbidden: %s cannot access %s"}`, currentTenantID, secID),
				})
			} else {
				// Access granted!
				body, _ := json.Marshal(map[string]any{
					"secret":          sec,
					"active_tenant":   currentTenantID,
					"active_user":     currentUserID,
					"context_leaked":  true,
				})
				results = append(results, subResult{
					OpID:       op.ID,
					StatusCode: 200,
					Body:       string(body),
				})
			}

		default:
			results = append(results, subResult{OpID: op.ID, StatusCode: 404, Body: `{"error":"unknown path"}`})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"results": results})
}

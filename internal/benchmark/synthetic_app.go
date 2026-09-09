// Package benchmark provides synthetic vulnerable applications for testing DOGE's research capability.
//
// IMPORTANT: These applications are INTENTIONALLY VULNERABLE for benchmarking purposes.
// They must NEVER be deployed outside of isolated test environments.
package benchmark

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// SyntheticApp represents a deliberately vulnerable application for benchmarking DOGE.
// The vulnerability is NOT described to DOGE — it must be discovered through research.
type SyntheticApp struct {
	Server *httptest.Server
	mu     sync.RWMutex
	users  map[string]*syntheticUser
	items  map[string]*syntheticItem
}

type syntheticUser struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Token    string `json:"-"`
	TenantID string `json:"tenant_id"`
}

type syntheticItem struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Content  string `json:"content"`
	OwnerID  string `json:"owner_id"`
	TenantID string `json:"tenant_id"`
	Status   string `json:"status"`
}

// NewSyntheticBOLAApp creates a synthetic application with a planted BOLA/IDOR vulnerability.
//
// The application has:
//   - Two tenants with separate users
//   - Authentication via Bearer tokens
//   - Multiple API endpoints (some properly protected, some not)
//   - A BOLA vulnerability on the /api/v1/items/{id} endpoint
//   - The /api/v1/users/{id} endpoint IS properly protected (differential behavior)
//   - Standard health/status endpoints for recon
//   - An OpenAPI-like discovery endpoint
//
// DOGE is not told any of this. It must discover the vulnerability through research.
func NewSyntheticBOLAApp() *SyntheticApp {
	app := &SyntheticApp{
		users: map[string]*syntheticUser{
			"user-alice-001": {
				ID: "user-alice-001", Name: "Alice Johnson", Email: "alice@tenant-a.com",
				Token: "tok_alice_a1b2c3d4", TenantID: "tenant-alpha",
			},
			"user-bob-002": {
				ID: "user-bob-002", Name: "Bob Smith", Email: "bob@tenant-b.com",
				Token: "tok_bob_e5f6g7h8", TenantID: "tenant-beta",
			},
		},
		items: map[string]*syntheticItem{
			"item-1001": {
				ID: "item-1001", Title: "Alpha Project Plan", Content: "Confidential project roadmap for Q4",
				OwnerID: "user-alice-001", TenantID: "tenant-alpha", Status: "active",
			},
			"item-1002": {
				ID: "item-1002", Title: "Beta Financial Report", Content: "Internal revenue data 2026",
				OwnerID: "user-bob-002", TenantID: "tenant-beta", Status: "active",
			},
			"item-1003": {
				ID: "item-1003", Title: "Alpha Design Specs", Content: "Architecture diagrams and API contracts",
				OwnerID: "user-alice-001", TenantID: "tenant-alpha", Status: "draft",
			},
		},
	}

	mux := http.NewServeMux()

	// Public endpoints (recon surface)
	mux.HandleFunc("/", app.handleRoot)
	mux.HandleFunc("/health", app.handleHealth)
	mux.HandleFunc("/api/v1/status", app.handleStatus)
	mux.HandleFunc("/api/v1/docs", app.handleDocs)

	// Authenticated endpoints
	mux.HandleFunc("/api/v1/me", app.handleMe)
	mux.HandleFunc("/api/v1/users/", app.handleUsers)
	mux.HandleFunc("/api/v1/items/", app.handleItems)
	mux.HandleFunc("/api/v1/search", app.handleSearch)

	app.Server = httptest.NewServer(mux)
	return app
}

// Close shuts down the synthetic application server.
func (a *SyntheticApp) Close() {
	if a.Server != nil {
		a.Server.Close()
	}
}

// BaseURL returns the base URL of the running synthetic app.
func (a *SyntheticApp) BaseURL() string {
	return a.Server.URL
}

// Credentials returns the available test credentials (user IDs and tokens).
// This simulates what a real assessment would receive as provided context.
func (a *SyntheticApp) Credentials() map[string]string {
	return map[string]string{
		"user_a_token": "tok_alice_a1b2c3d4",
		"user_b_token": "tok_bob_e5f6g7h8",
	}
}

func (a *SyntheticApp) authenticateRequest(r *http.Request) *syntheticUser {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	if token == auth {
		return nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, u := range a.users {
		if u.Token == token {
			return u
		}
	}
	return nil
}

func (a *SyntheticApp) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Powered-By", "SyntheticApp/1.0")
	w.Header().Set("X-Request-ID", "req-benchmark-001")
	json.NewEncoder(w).Encode(map[string]any{
		"service": "SyntheticApp API",
		"version": "1.0.0",
		"endpoints": []string{
			"/health",
			"/api/v1/status",
			"/api/v1/docs",
			"/api/v1/me",
			"/api/v1/users/{id}",
			"/api/v1/items/{id}",
			"/api/v1/search",
		},
	})
}

func (a *SyntheticApp) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func (a *SyntheticApp) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":     "operational",
		"items":      len(a.items),
		"users":      len(a.users),
		"auth":       "bearer_token",
		"tenants":    []string{"tenant-alpha", "tenant-beta"},
		"api_version": "v1",
	})
}

func (a *SyntheticApp) handleDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"openapi": "3.0.0",
		"paths": map[string]any{
			"/api/v1/me":          map[string]string{"get": "Get current user profile"},
			"/api/v1/users/{id}":  map[string]string{"get": "Get user by ID"},
			"/api/v1/items/{id}":  map[string]string{"get": "Get item by ID"},
			"/api/v1/search":      map[string]string{"get": "Search items (query param: q)"},
		},
		"security": []map[string]any{
			{"bearerAuth": []string{}},
		},
	})
}

func (a *SyntheticApp) handleMe(w http.ResponseWriter, r *http.Request) {
	user := a.authenticateRequest(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "authentication required"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"id":        user.ID,
		"name":      user.Name,
		"email":     user.Email,
		"tenant_id": user.TenantID,
	})
}

// handleUsers — PROPERLY PROTECTED. Enforces tenant isolation.
func (a *SyntheticApp) handleUsers(w http.ResponseWriter, r *http.Request) {
	user := a.authenticateRequest(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "authentication required"})
		return
	}

	// Extract user ID from path
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/users/"), "/")
	targetID := pathParts[0]
	if targetID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "user ID required"})
		return
	}

	a.mu.RLock()
	target, ok := a.users[targetID]
	a.mu.RUnlock()

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "user not found"})
		return
	}

	// ✅ CORRECT: Tenant isolation enforced
	if target.TenantID != user.TenantID {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "access denied: cross-tenant access forbidden"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"id":        target.ID,
		"name":      target.Name,
		"email":     target.Email,
		"tenant_id": target.TenantID,
	})
}

// handleItems — VULNERABLE: Missing tenant isolation check (BOLA/IDOR).
// Any authenticated user can access any item regardless of tenant.
func (a *SyntheticApp) handleItems(w http.ResponseWriter, r *http.Request) {
	user := a.authenticateRequest(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "authentication required"})
		return
	}

	// Extract item ID from path
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/items/"), "/")
	itemID := pathParts[0]
	if itemID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "item ID required"})
		return
	}

	a.mu.RLock()
	item, ok := a.items[itemID]
	a.mu.RUnlock()

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "item not found"})
		return
	}

	// ❌ VULNERABLE: No tenant check! Any authenticated user can access any item.
	// The /api/v1/users/{id} endpoint correctly checks tenant isolation,
	// but this endpoint does not.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"id":        item.ID,
		"title":     item.Title,
		"content":   item.Content,
		"owner_id":  item.OwnerID,
		"tenant_id": item.TenantID,
		"status":    item.Status,
	})
}

func (a *SyntheticApp) handleSearch(w http.ResponseWriter, r *http.Request) {
	user := a.authenticateRequest(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "authentication required"})
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "query parameter 'q' required"})
		return
	}

	// Search correctly scoped to tenant
	a.mu.RLock()
	var results []map[string]string
	for _, item := range a.items {
		if item.TenantID == user.TenantID {
			if strings.Contains(strings.ToLower(item.Title), strings.ToLower(query)) {
				results = append(results, map[string]string{
					"id":    item.ID,
					"title": item.Title,
				})
			}
		}
	}
	a.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"query":   query,
		"results": results,
		"count":   len(results),
	})
}

// SyntheticAppInfo provides structured metadata about the synthetic app
// for benchmark trajectory analysis. This is NOT provided to DOGE.
type SyntheticAppInfo struct {
	PlantedVulnerabilities []PlantedVulnerability `json:"planted_vulnerabilities"`
}

// PlantedVulnerability describes a vulnerability planted in the benchmark app.
type PlantedVulnerability struct {
	ID                string   `json:"id"`
	Type              string   `json:"type"`
	Endpoint          string   `json:"endpoint"`
	Description       string   `json:"description"`
	DiscoveryRequires []string `json:"discovery_requires"`
	ProofRequires     []string `json:"proof_requires"`
}

// GetPlantedVulnerabilities returns metadata about what vulnerabilities exist.
// Used ONLY for trajectory analysis — never provided to DOGE.
func (a *SyntheticApp) GetPlantedVulnerabilities() SyntheticAppInfo {
	return SyntheticAppInfo{
		PlantedVulnerabilities: []PlantedVulnerability{
			{
				ID:       "BENCH-001",
				Type:     "BOLA/IDOR",
				Endpoint: "/api/v1/items/{id}",
				Description: fmt.Sprintf(
					"Missing tenant isolation on item retrieval. /api/v1/users/{id} correctly enforces tenant boundary (403), " +
						"but /api/v1/items/{id} allows any authenticated user to access any item regardless of tenant. " +
						"Differential behavior between endpoints is the key signal."),
				DiscoveryRequires: []string{
					"Discover API endpoints (from /api/v1/docs or /)",
					"Identify object identifiers (item-1001, item-1002, etc.)",
					"Understand multi-tenant architecture (tenant-alpha, tenant-beta)",
					"Recognize two authenticated principals with different tenants",
					"Form hypothesis about authorization boundary",
					"Design cross-tenant experiment",
				},
				ProofRequires: []string{
					"Authenticate as user A (tenant-alpha)",
					"Access item belonging to user B (tenant-beta)",
					"Receive 200 OK with user B's confidential data",
					"Demonstrate that /api/v1/users/{id} correctly returns 403 for same cross-tenant access",
					"Independent reproduction by separate validator",
				},
			},
		},
	}
}

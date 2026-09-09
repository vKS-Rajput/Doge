package benchmark

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// SyntheticWorkflowApp is a synthetic e-commerce application with a
// planted workflow state bypass vulnerability. DOGE must discover that
// the payment step can be skipped by directly transitioning to the
// confirmation state.
//
// PLANTED VULNERABILITY:
//   - The server does NOT enforce that payment must complete before
//     confirmation. A user can skip payment by directly posting to
//     /api/v1/orders/{id}/confirm without completing /api/v1/orders/{id}/pay.
//
// DOGE IS NOT TOLD:
//   - What vulnerability exists
//   - Where to look
//   - That workflow bypass is possible
//   - What the valid state transitions are
//
// API SURFACE:
//   - POST /api/v1/auth/login       → Get auth token
//   - GET  /api/v1/products         → List products
//   - POST /api/v1/cart             → Create cart with items
//   - POST /api/v1/orders           → Create order from cart (state: "created")
//   - POST /api/v1/orders/{id}/checkout → Move to checkout (state: "checkout")
//   - POST /api/v1/orders/{id}/pay     → Process payment (state: "paid")
//   - POST /api/v1/orders/{id}/confirm → Confirm order (state: "confirmed")
//   - GET  /api/v1/orders/{id}      → Get order details (including state)
//   - GET  /api/v1/orders           → List user's orders
//   - GET  /api/v1/docs             → API documentation
//   - GET  /health                  → Health check
type SyntheticWorkflowApp struct {
	server *httptest.Server
	mu     sync.Mutex
	orders map[string]*order
	carts  map[string]*cart
	nextID int
}

type order struct {
	ID        string       `json:"id"`
	UserID    string       `json:"user_id"`
	Items     []cartItem   `json:"items"`
	State     string       `json:"state"`
	Total     float64      `json:"total"`
	PaidAt    string       `json:"paid_at,omitempty"`
	History   []stateChange `json:"history"`
}

type stateChange struct {
	From string `json:"from"`
	To   string `json:"to"`
	At   string `json:"at"`
}

type cart struct {
	UserID string     `json:"user_id"`
	Items  []cartItem `json:"items"`
}

type cartItem struct {
	ProductID string  `json:"product_id"`
	Name      string  `json:"name"`
	Quantity  int     `json:"quantity"`
	Price     float64 `json:"price"`
}

type workflowCredentials struct {
	UserID string
	Token  string
}

// NewSyntheticWorkflowApp creates and starts the synthetic workflow app.
func NewSyntheticWorkflowApp() *SyntheticWorkflowApp {
	app := &SyntheticWorkflowApp{
		orders: make(map[string]*order),
		carts:  make(map[string]*cart),
		nextID: 1000,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleIndex)
	mux.HandleFunc("/health", app.handleHealth)
	mux.HandleFunc("/api/v1/docs", app.handleDocs)
	mux.HandleFunc("/api/v1/auth/login", app.handleLogin)
	mux.HandleFunc("/api/v1/me", app.handleMe)
	mux.HandleFunc("/api/v1/products", app.handleProducts)
	mux.HandleFunc("/api/v1/cart", app.handleCart)
	mux.HandleFunc("/api/v1/orders", app.handleOrders)
	mux.HandleFunc("/api/v1/orders/", app.handleOrderAction)

	app.server = httptest.NewServer(mux)
	return app
}

// Close shuts down the server.
func (a *SyntheticWorkflowApp) Close() {
	a.server.Close()
}

// BaseURL returns the server's base URL.
func (a *SyntheticWorkflowApp) BaseURL() string {
	return a.server.URL
}

// Credentials returns auth credentials.
func (a *SyntheticWorkflowApp) Credentials() map[string]string {
	return map[string]string{
		"user-buyer-001": "buyer-token-abc123",
	}
}

// GetPlantedVulnerabilities returns the planted vulnerabilities for benchmark verification.
func (a *SyntheticWorkflowApp) GetPlantedVulnerabilities() SyntheticAppInfo {
	return SyntheticAppInfo{
		PlantedVulnerabilities: []PlantedVulnerability{
			{
				ID:          "BENCH-002",
				Type:        "WORKFLOW_BYPASS",
				Endpoint:    "/api/v1/orders/{id}/confirm",
				Description: "Payment step can be skipped — order confirmation does not require payment state",
			},
		},
	}
}

func (a *SyntheticWorkflowApp) authenticate(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", false
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	if token == "buyer-token-abc123" {
		return "user-buyer-001", true
	}
	return "", false
}

func (a *SyntheticWorkflowApp) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"service": "ecommerce-api",
		"version": "1.0",
		"endpoints": []string{
			"/health",
			"/api/v1/docs",
			"/api/v1/auth/login",
			"/api/v1/me",
			"/api/v1/products",
			"/api/v1/cart",
			"/api/v1/orders",
			"/api/v1/orders/{id}",
			"/api/v1/orders/{id}/checkout",
			"/api/v1/orders/{id}/pay",
			"/api/v1/orders/{id}/confirm",
		},
	})
}

func (a *SyntheticWorkflowApp) handleMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      userID,
		"role":    "buyer",
		"cart_id": "cart-" + userID,
	})
}

func (a *SyntheticWorkflowApp) handleHealth(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "service": "ecommerce-api"})
}

func (a *SyntheticWorkflowApp) handleDocs(w http.ResponseWriter, r *http.Request) {
	docs := map[string]interface{}{
		"service": "E-Commerce API",
		"version": "1.0",
		"endpoints": []map[string]string{
			{"method": "POST", "path": "/api/v1/auth/login", "description": "Authenticate user"},
			{"method": "GET", "path": "/api/v1/products", "description": "List available products"},
			{"method": "POST", "path": "/api/v1/cart", "description": "Create/update shopping cart"},
			{"method": "POST", "path": "/api/v1/orders", "description": "Create order from cart"},
			{"method": "POST", "path": "/api/v1/orders/{id}/checkout", "description": "Move order to checkout"},
			{"method": "POST", "path": "/api/v1/orders/{id}/pay", "description": "Process payment for order"},
			{"method": "POST", "path": "/api/v1/orders/{id}/confirm", "description": "Confirm completed order"},
			{"method": "GET", "path": "/api/v1/orders/{id}", "description": "Get order details"},
			{"method": "GET", "path": "/api/v1/orders", "description": "List user orders"},
		},
		"workflow": map[string]interface{}{
			"description": "Order lifecycle: create → checkout → pay → confirm",
			"states":      []string{"created", "checkout", "paid", "confirmed"},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(docs)
}

func (a *SyntheticWorkflowApp) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	if body.Username == "buyer" && body.Password == "password123" {
		json.NewEncoder(w).Encode(map[string]string{
			"token":   "buyer-token-abc123",
			"user_id": "user-buyer-001",
		})
		return
	}
	http.Error(w, "invalid credentials", http.StatusUnauthorized)
}

func (a *SyntheticWorkflowApp) handleProducts(w http.ResponseWriter, r *http.Request) {
	products := []map[string]interface{}{
		{"id": "prod-001", "name": "Widget A", "price": 29.99},
		{"id": "prod-002", "name": "Widget B", "price": 49.99},
		{"id": "prod-003", "name": "Premium Widget", "price": 199.99},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(products)
}

func (a *SyntheticWorkflowApp) handleCart(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodPost {
		var items []cartItem
		json.NewDecoder(r.Body).Decode(&items)
		a.mu.Lock()
		a.carts[userID] = &cart{UserID: userID, Items: items}
		a.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "cart_updated"})
		return
	}

	a.mu.Lock()
	c := a.carts[userID]
	a.mu.Unlock()
	if c == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"items": []cartItem{}})
		return
	}
	json.NewEncoder(w).Encode(c)
}

func (a *SyntheticWorkflowApp) handleOrders(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodPost {
		a.mu.Lock()
		c := a.carts[userID]
		if c == nil || len(c.Items) == 0 {
			a.mu.Unlock()
			http.Error(w, "cart is empty", http.StatusBadRequest)
			return
		}

		orderID := fmt.Sprintf("order-%d", a.nextID)
		a.nextID++

		var total float64
		for _, item := range c.Items {
			total += item.Price * float64(item.Quantity)
		}

		o := &order{
			ID:     orderID,
			UserID: userID,
			Items:  c.Items,
			State:  "created",
			Total:  total,
			History: []stateChange{
				{From: "", To: "created", At: "now"},
			},
		}
		a.orders[orderID] = o
		delete(a.carts, userID)
		a.mu.Unlock()

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(o)
		return
	}

	// GET — list orders
	a.mu.Lock()
	var userOrders []*order
	for _, o := range a.orders {
		if o.UserID == userID {
			userOrders = append(userOrders, o)
		}
	}
	a.mu.Unlock()
	json.NewEncoder(w).Encode(userOrders)
}

func (a *SyntheticWorkflowApp) handleOrderAction(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse: /api/v1/orders/{id} or /api/v1/orders/{id}/{action}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/orders/")
	parts := strings.SplitN(path, "/", 2)
	orderID := parts[0]

	a.mu.Lock()
	o, exists := a.orders[orderID]
	if !exists || o.UserID != userID {
		a.mu.Unlock()
		http.Error(w, "order not found", http.StatusNotFound)
		return
	}

	if len(parts) == 1 {
		// GET /api/v1/orders/{id}
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(o)
		return
	}

	action := parts[1]

	switch action {
	case "checkout":
		if o.State != "created" {
			a.mu.Unlock()
			http.Error(w, fmt.Sprintf("cannot checkout: order is in state '%s', expected 'created'", o.State), http.StatusConflict)
			return
		}
		o.History = append(o.History, stateChange{From: o.State, To: "checkout"})
		o.State = "checkout"
		a.mu.Unlock()
		json.NewEncoder(w).Encode(o)

	case "pay":
		if o.State != "checkout" {
			a.mu.Unlock()
			http.Error(w, fmt.Sprintf("cannot pay: order is in state '%s', expected 'checkout'", o.State), http.StatusConflict)
			return
		}
		o.History = append(o.History, stateChange{From: o.State, To: "paid"})
		o.State = "paid"
		o.PaidAt = "now"
		a.mu.Unlock()
		json.NewEncoder(w).Encode(o)

	case "confirm":
		// ═══════════════════════════════════════════════════════
		// VULNERABILITY: No check that payment was completed!
		// The server only checks that the order is NOT in "created" state,
		// but does NOT require "paid" state. A user can skip payment
		// by going directly from "checkout" to "confirmed".
		// ═══════════════════════════════════════════════════════
		if o.State == "created" {
			a.mu.Unlock()
			http.Error(w, "cannot confirm: order has not been checked out", http.StatusConflict)
			return
		}
		// BUG: Should check o.State == "paid", but only checks != "created"
		o.History = append(o.History, stateChange{From: o.State, To: "confirmed"})
		o.State = "confirmed"
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"order":   o,
			"message": "Order confirmed! Your items will be shipped.",
		})

	default:
		a.mu.Unlock()
		http.Error(w, "unknown action: "+action, http.StatusBadRequest)
	}
}

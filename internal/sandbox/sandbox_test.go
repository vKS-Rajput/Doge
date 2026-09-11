package sandbox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTacticalSandboxContainmentAndAccounting(t *testing.T) {
	// Mock target server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	cfg := SandboxConfig{
		MaxRequests:     3,
		Timeout:         5 * time.Second,
		RateLimitPerSec: 50,
		AllowedHosts:    []string{"127.0.0.1"},
	}

	sb := NewTacticalSandbox(cfg)
	ctx := context.Background()

	// 1. Execute 2 successful requests
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("GET", server.URL+"/test", nil)
		resp, body, err := sb.ExecuteHTTP(ctx, req)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", resp.StatusCode)
		}
		if string(body) != `{"status":"ok"}` {
			t.Errorf("unexpected body: %s", string(body))
		}
	}

	// 2. Execute 3rd request (hits budget max)
	req3, _ := http.NewRequest("GET", server.URL+"/test", nil)
	_, _, err := sb.ExecuteHTTP(ctx, req3)
	if err != nil {
		t.Fatalf("request 3 failed: %v", err)
	}

	// 3. 4th request must fail budget check
	req4, _ := http.NewRequest("GET", server.URL+"/test", nil)
	_, _, err = sb.ExecuteHTTP(ctx, req4)
	if err == nil {
		t.Fatalf("expected budget error on 4th request")
	}
	t.Logf("✓ Verified Budget Enforcement: %v", err)

	// 4. Verify Scope Boundary Enforcement
	outOfScopeReq, _ := http.NewRequest("GET", "http://unauthorized-external.com/api", nil)
	sbScope := NewTacticalSandbox(cfg)
	_, _, err = sbScope.ExecuteHTTP(ctx, outOfScopeReq)
	if err == nil {
		t.Fatalf("expected scope boundary error for external target")
	}
	t.Logf("✓ Verified Scope Enforcement: %v", err)

	// 5. Verify Journal & Accounting
	journal := sb.GetJournal()
	if len(journal) != 3 {
		t.Errorf("expected 3 entries in journal, got %d", len(journal))
	}

	summary := sb.Accountant().FormatSummary()
	if summary == "" {
		t.Errorf("expected non-empty accounting summary")
	}
	t.Logf("✓ Accounting Summary: %s", summary)
}

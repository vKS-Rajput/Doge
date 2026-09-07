package gates

import (
	"os"
	"testing"
	"time"

	"github.com/vKS-Rajput/doge/internal/scope"
)

func TestGateManager_Lifecycle(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "doge-gates-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mgr := NewManager(tempDir)

	// 1. Create Approval Gate
	appCtx := GateContext{
		Target:              "api.example.com",
		Tool:                "httpx",
		Command:             "httpx -u https://api.example.com/api/v1/users/1",
		RiskLevel:           "LOW",
		ScopeClassification: scope.AssetInScope,
		ScopeReason:         "Direct match to scope rule *.example.com",
		Reason:              "BOLA hypothesis verification",
	}
	appGate := mgr.CreateApprovalGate("Approve BOLA Probing", "Test endpoint with alternate user context", appCtx)
	if appGate == nil || appGate.Status != StatusPending {
		t.Fatalf("expected pending approval gate, got %v", appGate)
	}

	// 2. Create Direction Gate
	dirCtx := GateContext{
		Target: "example.com",
		Reason: "Multiple subdomains discovered",
	}
	options := []DirectionOption{
		{Index: 1, Label: "Focus on API Subdomains", Description: "Probe api.example.com and auth.example.com", Priority: "HIGH"},
		{Index: 2, Label: "Broad Directory Fuzzing", Description: "Fuzz web assets across all 15 subdomains", Priority: "MEDIUM"},
	}
	dirGate := mgr.CreateDirectionGate("Select Investigation Path", "Branching options for target", options, dirCtx)
	if dirGate == nil || dirGate.Status != StatusPending {
		t.Fatalf("expected pending direction gate, got %v", dirGate)
	}

	pending := mgr.ListPending()
	if len(pending) != 2 {
		t.Fatalf("expected 2 pending gates, got %d", len(pending))
	}

	// 3. Resolve Approval Gate
	if err := mgr.Approve(appGate.ID, "security_lead", "Validated within scope"); err != nil {
		t.Fatalf("failed to approve gate: %v", err)
	}

	// 4. Resolve Direction Gate
	if err := mgr.ChooseOption(dirGate.ID, 1, "security_lead"); err != nil {
		t.Fatalf("failed to choose option: %v", err)
	}

	pending = mgr.ListPending()
	if len(pending) != 0 {
		t.Fatalf("expected 0 pending gates after resolution, got %d", len(pending))
	}

	// 5. Verify persistence across reload
	mgr2 := NewManager(tempDir)
	all := mgr2.ListAll()
	if len(all) != 2 {
		t.Fatalf("expected 2 reloaded gates, got %d", len(all))
	}
	if all[0].Status != StatusApproved || all[1].Status != StatusChosen {
		t.Errorf("reloaded gate status mismatch: %s, %s", all[0].Status, all[1].Status)
	}
	if all[1].SelectedOption != 1 {
		t.Errorf("expected selected option 1, got %d", all[1].SelectedOption)
	}
}

func TestGateManager_Subscription(t *testing.T) {
	tempDir := t.TempDir()
	mgr := NewManager(tempDir)

	sub := mgr.Subscribe()
	defer mgr.Unsubscribe(sub)

	go func() {
		mgr.CreateApprovalGate("Test", "Desc", GateContext{Target: "test.com"})
	}()

	select {
	case g := <-sub:
		if g.Title != "Test" {
			t.Errorf("unexpected gate title: %s", g.Title)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for gate subscription event")
	}
}

package validation

import (
	"testing"

	"github.com/google/uuid"
)

// --- Request Budget Tests ---

func TestRequestBudgetDefaults(t *testing.T) {
	b := NewRequestBudget(0, 0, 0)
	if b.PerPlan != 20 {
		t.Errorf("expected default PerPlan=20, got %d", b.PerPlan)
	}
	if b.PerHypothesis != 60 {
		t.Errorf("expected default PerHypothesis=60, got %d", b.PerHypothesis)
	}
	if b.PerEngagement != 200 {
		t.Errorf("expected default PerEngagement=200, got %d", b.PerEngagement)
	}
}

func TestRequestBudgetPerPlanExhaustion(t *testing.T) {
	b := NewRequestBudget(3, 100, 1000)
	planID := uuid.New()
	hypID := uuid.New()

	for i := 0; i < 3; i++ {
		if err := b.CheckBudget(planID, hypID); err != nil {
			t.Fatalf("request %d should be allowed: %v", i, err)
		}
		b.RecordRequest(planID, hypID)
	}

	if err := b.CheckBudget(planID, hypID); err == nil {
		t.Error("4th request should exceed per-plan budget")
	}
}

func TestRequestBudgetPerHypothesisExhaustion(t *testing.T) {
	b := NewRequestBudget(5, 8, 1000)
	hypID := uuid.New()

	// 2 plans × 4 requests each = 8 hypothesis-level requests.
	for p := 0; p < 2; p++ {
		planID := uuid.New()
		for i := 0; i < 4; i++ {
			if err := b.CheckBudget(planID, hypID); err != nil {
				t.Fatalf("plan %d request %d should be allowed: %v", p, i, err)
			}
			b.RecordRequest(planID, hypID)
		}
	}

	// 9th request should fail at hypothesis level.
	newPlan := uuid.New()
	if err := b.CheckBudget(newPlan, hypID); err == nil {
		t.Error("hypothesis budget should be exhausted after 8 requests across plans")
	}
}

func TestRequestBudgetPlanMultiplicationBlocked(t *testing.T) {
	// Per-plan=20, per-hypothesis=30, engagement=1000.
	// An AI generating many plans shouldn't bypass hypothesis limit.
	b := NewRequestBudget(20, 30, 1000)
	hypID := uuid.New()

	// 2 plans × 15 requests each = 30 hypothesis-level.
	for p := 0; p < 2; p++ {
		planID := uuid.New()
		for i := 0; i < 15; i++ {
			if err := b.CheckBudget(planID, hypID); err != nil {
				t.Fatalf("plan %d request %d should be allowed: %v", p, i, err)
			}
			b.RecordRequest(planID, hypID)
		}
	}

	// 3rd plan's first request should fail at hypothesis level.
	thirdPlan := uuid.New()
	if err := b.CheckBudget(thirdPlan, hypID); err == nil {
		t.Error("plan multiplication should be blocked by hypothesis budget")
	}
}

func TestRequestBudgetEngagementExhaustion(t *testing.T) {
	b := NewRequestBudget(100, 100, 5)

	for i := 0; i < 5; i++ {
		planID := uuid.New()
		hypID := uuid.New()
		if err := b.CheckBudget(planID, hypID); err != nil {
			t.Fatalf("request %d should be allowed: %v", i, err)
		}
		b.RecordRequest(planID, hypID)
	}

	if err := b.CheckBudget(uuid.New(), uuid.New()); err == nil {
		t.Error("engagement budget should be exhausted")
	}
}

func TestRequestBudgetRemaining(t *testing.T) {
	b := NewRequestBudget(20, 60, 200)
	planID := uuid.New()
	hypID := uuid.New()

	b.RecordRequest(planID, hypID)
	b.RecordRequest(planID, hypID)

	p, h, e := b.Remaining(planID, hypID)
	if p != 18 {
		t.Errorf("expected plan remaining=18, got %d", p)
	}
	if h != 58 {
		t.Errorf("expected hypothesis remaining=58, got %d", h)
	}
	if e != 198 {
		t.Errorf("expected engagement remaining=198, got %d", e)
	}
}

// --- Approval Binding Tests ---

func TestComputePlanDigestDeterministic(t *testing.T) {
	actions := []Action{
		{Type: ActionHTTPRequest, Target: "example.com", Method: "GET", Path: "/admin"},
		{Type: ActionEndpointProbe, Target: "example.com", Method: "HEAD", Path: "/api"},
	}

	d1 := ComputePlanDigest(actions)
	d2 := ComputePlanDigest(actions)

	if d1 != d2 {
		t.Error("same actions should produce same digest")
	}
}

func TestComputePlanDigestChangesOnModification(t *testing.T) {
	original := []Action{
		{Type: ActionHTTPRequest, Target: "example.com", Method: "GET", Path: "/admin"},
	}
	modified := []Action{
		{Type: ActionHTTPRequest, Target: "example.com", Method: "GET", Path: "/admin/delete"},
	}

	d1 := ComputePlanDigest(original)
	d2 := ComputePlanDigest(modified)

	if d1 == d2 {
		t.Error("different paths should produce different digests")
	}
}

func TestVerifyApprovalValid(t *testing.T) {
	actions := []Action{
		{Type: ActionHTTPRequest, Target: "example.com", Method: "GET", Path: "/profile"},
	}

	plan := ExecutablePlan{
		ID:      uuid.New(),
		Actions: actions,
		Approval: ApprovalRecord{
			PlanDigest: ComputePlanDigest(actions),
			Approver:   "researcher",
		},
	}

	if err := VerifyApproval(plan); err != nil {
		t.Fatalf("valid approval should pass: %v", err)
	}
}

func TestVerifyApprovalRejectsModifiedPlan(t *testing.T) {
	originalActions := []Action{
		{Type: ActionHTTPRequest, Target: "example.com", Method: "GET", Path: "/profile"},
	}

	plan := ExecutablePlan{
		ID: uuid.New(),
		Actions: []Action{
			// Modified after approval!
			{Type: ActionHTTPRequest, Target: "example.com", Method: "GET", Path: "/admin/delete"},
		},
		Approval: ApprovalRecord{
			PlanDigest: ComputePlanDigest(originalActions), // Digest of original
			Approver:   "researcher",
		},
	}

	if err := VerifyApproval(plan); err == nil {
		t.Error("modified plan should fail approval verification")
	}
}

func TestVerifyApprovalRejectsCredentialChange(t *testing.T) {
	original := []Action{
		{Type: ActionHTTPRequest, Target: "example.com", Method: "GET", Path: "/api",
			CredentialProfileID: "user"},
	}
	modified := []Action{
		{Type: ActionHTTPRequest, Target: "example.com", Method: "GET", Path: "/api",
			CredentialProfileID: "admin"}, // Credential changed
	}

	plan := ExecutablePlan{
		ID:      uuid.New(),
		Actions: modified,
		Approval: ApprovalRecord{
			PlanDigest: ComputePlanDigest(original),
		},
	}

	if err := VerifyApproval(plan); err == nil {
		t.Error("credential change should invalidate approval")
	}
}

func TestVerifyApprovalRejectsMethodChange(t *testing.T) {
	original := []Action{
		{Type: ActionHTTPRequest, Target: "example.com", Method: "GET", Path: "/api"},
	}
	modified := []Action{
		{Type: ActionHTTPRequest, Target: "example.com", Method: "POST", Path: "/api"},
	}

	plan := ExecutablePlan{
		ID:      uuid.New(),
		Actions: modified,
		Approval: ApprovalRecord{
			PlanDigest: ComputePlanDigest(original),
		},
	}

	if err := VerifyApproval(plan); err == nil {
		t.Error("method change should invalidate approval")
	}
}

// --- Credential Profile Tests ---

func TestAllowedCredentialHeaders(t *testing.T) {
	allowed := []string{"authorization", "cookie"}
	for _, h := range allowed {
		if !AllowedCredentialHeaders[h] {
			t.Errorf("%s should be allowed", h)
		}
	}

	blocked := []string{"x-custom", "host", "user-agent", "content-type"}
	for _, h := range blocked {
		if AllowedCredentialHeaders[h] {
			t.Errorf("%s should NOT be allowed", h)
		}
	}
}

// --- Method Allowlist ---

func TestAllowedMethods(t *testing.T) {
	allowed := []string{"GET", "HEAD", "OPTIONS"}
	for _, m := range allowed {
		if !AllowedMethods[m] {
			t.Errorf("%s should be allowed", m)
		}
	}

	blocked := []string{"POST", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}
	for _, m := range blocked {
		if AllowedMethods[m] {
			t.Errorf("%s should NOT be allowed in v0.9.5", m)
		}
	}
}

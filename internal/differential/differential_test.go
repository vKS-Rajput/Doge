package differential

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/worldmodel"
)

func TestHorizontalBOLADetection(t *testing.T) {
	engine := NewEngine()

	pA := &worldmodel.Principal{
		ID:   uuid.New(),
		Name: "alice@tenant-a.com",
		Type: worldmodel.PrincipalUser,
	}

	pB := &worldmodel.Principal{
		ID:   uuid.New(),
		Name: "bob@tenant-b.com",
		Type: worldmodel.PrincipalUser,
	}

	respA := &ExecutionResponse{
		StatusCode: 200,
		Body:       `{"invoice_id": "99281", "amount": 4500.00, "customer": "Alice", "ssn": "000-12-3456"}`,
	}

	// Principal B receives 200 containing Alice's invoice object
	respB := &ExecutionResponse{
		StatusCode: 200,
		Body:       `{"invoice_id": "99281", "amount": 4500.00, "customer": "Alice", "ssn": "000-12-3456"}`,
	}

	diff := engine.Compare(pA, respA, pB, respB, "99281")

	if diff.Outcome != OutcomeBOLAConfirmed {
		t.Fatalf("expected outcome %s, got %s", OutcomeBOLAConfirmed, diff.Outcome)
	}
	if !diff.ObjectLeakDetected {
		t.Errorf("expected object leak detected to be true")
	}
	if diff.Confidence < 0.90 {
		t.Errorf("expected high confidence >= 0.90, got: %.2f", diff.Confidence)
	}

	t.Logf("✓ BOLA Confirmed: %s", diff.Explanation)
	t.Logf("✓ Minimal Proof: %s", diff.MinimalProof)
}

func TestStrictTenantIsolationRefutation(t *testing.T) {
	engine := NewEngine()

	pA := &worldmodel.Principal{
		ID:   uuid.New(),
		Name: "alice@tenant-a.com",
		Type: worldmodel.PrincipalUser,
	}

	pB := &worldmodel.Principal{
		ID:   uuid.New(),
		Name: "bob@tenant-b.com",
		Type: worldmodel.PrincipalUser,
	}

	respA := &ExecutionResponse{
		StatusCode: 200,
		Body:       `{"invoice_id": "99281", "amount": 4500.00, "customer": "Alice"}`,
	}

	// Principal B receives 403 Forbidden with tenant error
	respB := &ExecutionResponse{
		StatusCode: 403,
		Body:       `{"error": "Access denied: tenant mismatch"}`,
	}

	diff := engine.Compare(pA, respA, pB, respB, "99281")

	if diff.Outcome != OutcomeStrictIsolationEnforced {
		t.Fatalf("expected outcome %s, got %s", OutcomeStrictIsolationEnforced, diff.Outcome)
	}
	if diff.ObjectLeakDetected {
		t.Errorf("expected no object leak")
	}

	t.Logf("✓ Strict Isolation Confirmed (BOLA Refuted): %s", diff.Explanation)
}

func TestVerticalPrivilegeEscalation(t *testing.T) {
	engine := NewEngine()

	pAdmin := &worldmodel.Principal{
		ID:   uuid.New(),
		Name: "admin@corp.com",
		Type: worldmodel.PrincipalSystemAdmin,
	}

	pStandard := &worldmodel.Principal{
		ID:   uuid.New(),
		Name: "user@corp.com",
		Type: worldmodel.PrincipalUser,
	}

	respAdmin := &ExecutionResponse{
		StatusCode: 200,
		Body:       `{"system_config": {"debug": true, "master_key": "sec_123"}, "total_users": 1400}`,
	}

	respStandard := &ExecutionResponse{
		StatusCode: 200,
		Body:       `{"system_config": {"debug": true, "master_key": "sec_123"}, "total_users": 1400}`,
	}

	diff := engine.Compare(pAdmin, respAdmin, pStandard, respStandard, "")

	if diff.Outcome != OutcomePrivEscConfirmed {
		t.Fatalf("expected outcome %s, got %s", OutcomePrivEscConfirmed, diff.Outcome)
	}

	t.Logf("✓ Privilege Escalation Confirmed: %s", diff.Explanation)
}

func TestExecuteDifferentialFlow(t *testing.T) {
	ctx := context.Background()
	engine := NewEngine()

	pA := &worldmodel.Principal{ID: uuid.New(), Name: "alice", Type: worldmodel.PrincipalUser}
	pB := &worldmodel.Principal{ID: uuid.New(), Name: "bob", Type: worldmodel.PrincipalUser}

	op := OperationSpec{
		Method: "GET",
		URL:    "https://app.local/api/orders/5541",
	}

	mockRunner := func(ctx context.Context, op OperationSpec, p *worldmodel.Principal) (*ExecutionResponse, error) {
		if p.Name == "alice" {
			return &ExecutionResponse{StatusCode: 200, Body: `{"order_id": "5541", "owner": "alice"}`}, nil
		}
		// Bob is unauthorized
		return &ExecutionResponse{StatusCode: 404, Body: `{"error": "not found"}`}, nil
	}

	result, err := engine.Execute(ctx, op, pA, pB, mockRunner, "5541")
	if err != nil {
		t.Fatalf("differential execution failed: %v", err)
	}

	if result.Diff.Outcome != OutcomeStrictIsolationEnforced {
		t.Errorf("expected strict isolation, got %s", result.Diff.Outcome)
	}
	t.Logf("✓ Differential Experiment Result: %s", result.Diff.Explanation)
}

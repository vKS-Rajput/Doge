package workflow

import (
	"testing"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/worldmodel"
)

func TestWorkflowStepSkipVulnerability(t *testing.T) {
	engine := NewEngine()

	// Model Contract Workflow: DRAFT -> SUBMITTED -> UNDER_REVIEW -> APPROVED -> EXECUTED
	w := &WorkflowGraph{
		ID:           uuid.New(),
		Name:         "Enterprise Contract Signing",
		InitialState: "DRAFT",
		TerminalStates: []string{"EXECUTED", "REJECTED"},
		Steps: []*WorkflowStep{
			{
				ID:                    uuid.New(),
				SequenceOrder:         1,
				Name:                  "Submit Contract",
				FromState:             "DRAFT",
				ToState:               "SUBMITTED",
				ActionEndpoint:        "https://app.local/api/contracts/c1/submit",
				HTTPMethod:            "POST",
				RequiredPrincipalType: worldmodel.PrincipalUser,
			},
			{
				ID:                    uuid.New(),
				SequenceOrder:         2,
				Name:                  "Review Contract",
				FromState:             "SUBMITTED",
				ToState:               "UNDER_REVIEW",
				ActionEndpoint:        "https://app.local/api/contracts/c1/review",
				HTTPMethod:            "POST",
				RequiredPrincipalType: worldmodel.PrincipalTenantAdmin,
			},
			{
				ID:                    uuid.New(),
				SequenceOrder:         3,
				Name:                  "Approve Contract",
				FromState:             "UNDER_REVIEW",
				ToState:               "APPROVED",
				ActionEndpoint:        "https://app.local/api/contracts/c1/approve",
				HTTPMethod:            "POST",
				RequiredPrincipalType: worldmodel.PrincipalSystemAdmin,
				IsPrivileged:          true,
			},
		},
	}

	if err := engine.RegisterWorkflow(w); err != nil {
		t.Fatalf("failed to register workflow: %v", err)
	}

	// 1. Generate Step Skip Probes
	probes := engine.GenerateStepSkipProbes(w)
	if len(probes) != 2 {
		t.Fatalf("expected 2 step-skip probes, got %d", len(probes))
	}

	t.Logf("Generated %d Workflow Probes:", len(probes))
	for _, p := range probes {
		t.Logf("  - [%s] %s -> Target: %s", p.Type, p.Title, p.EndpointURL)
	}

	// 2. Simulate Vulnerable Execution: Invoking Approve step directly while in DRAFT state
	approveStep := w.Steps[2]
	vuln := engine.EvaluateExecution(
		w,
		AnomalyStepSkip,
		approveStep,
		"DRAFT",     // initial state
		"APPROVED",  // final mutated state (vulnerability: jumped from DRAFT straight to APPROVED)
		200,
		`{"status": "APPROVED", "message": "Contract approved"}`,
		"attacker@corp.com",
	)

	if vuln == nil {
		t.Fatalf("expected workflow step skip vulnerability to be detected")
	}

	if vuln.Type != AnomalyStepSkip {
		t.Errorf("expected anomaly %s, got %s", AnomalyStepSkip, vuln.Type)
	}
	if vuln.Confidence < 0.90 {
		t.Errorf("expected confidence >= 0.90, got: %.2f", vuln.Confidence)
	}

	t.Logf("✓ Verified Workflow Vulnerability Detected: %s", vuln.Title)
	t.Logf("✓ Proof: %s", vuln.MinimalProof)
	t.Logf("✓ Remediation: %s", vuln.Remediation)
}

func TestWorkflowEnforcedStateMachine(t *testing.T) {
	engine := NewEngine()

	w := &WorkflowGraph{
		ID:           uuid.New(),
		Name:         "Payment Checkout",
		InitialState: "CART",
		TerminalStates: []string{"COMPLETED"},
		Steps: []*WorkflowStep{
			{
				ID:             uuid.New(),
				SequenceOrder:  1,
				Name:           "Create Order",
				FromState:      "CART",
				ToState:        "PENDING_PAYMENT",
				ActionEndpoint: "https://app.local/api/checkout",
				HTTPMethod:     "POST",
			},
			{
				ID:             uuid.New(),
				SequenceOrder:  2,
				Name:           "Confirm Payment",
				FromState:      "PENDING_PAYMENT",
				ToState:        "COMPLETED",
				ActionEndpoint: "https://app.local/api/payment/confirm",
				HTTPMethod:     "POST",
			},
		},
	}

	confirmStep := w.Steps[1]

	// Server properly rejects out-of-order execution with 409 Conflict
	vuln := engine.EvaluateExecution(
		w,
		AnomalyStepSkip,
		confirmStep,
		"CART",
		"CART", // state remained CART
		409,
		`{"error": "Invalid state transition: order must be in PENDING_PAYMENT state"}`,
		"attacker",
	)

	if vuln != nil {
		t.Fatalf("expected no vulnerability when state transition is rejected")
	}

	t.Log("✓ Verified state machine enforcement (no false positive on 409 Conflict)")
}

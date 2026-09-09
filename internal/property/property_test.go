package property

import (
	"testing"

	"github.com/google/uuid"
)

func TestSecurityProperty_Validation(t *testing.T) {
	p := &SecurityProperty{
		ID:          uuid.New(),
		Class:       ClassWorkflowIntegrity,
		Statement:   "Workflow transitions cannot be skipped",
		Subject:     "checkout",
		SubjectType: "workflow",
		State:       StateUntested,
		Confidence:  0.8,
	}

	if err := p.Validate(); err != nil {
		t.Fatalf("expected valid property, got error: %v", err)
	}

	invalid := &SecurityProperty{}
	if err := invalid.Validate(); err == nil {
		t.Fatal("expected error for empty property statement, got nil")
	}
}

func TestPropertyEvaluator_RegisterAndQuery(t *testing.T) {
	eval := NewEvaluator()
	catalog := NewCatalog()

	endpointProps := catalog.GenerateForEndpoint("/api/v1/orders/{id}/confirm")
	if len(endpointProps) == 0 {
		t.Fatal("expected generated endpoint properties")
	}

	for _, p := range endpointProps {
		eval.Register(p)
	}

	workflowProps := catalog.GenerateForWorkflow("checkout_pipeline", []string{"created", "checkout", "paid", "confirmed"})
	if len(workflowProps) == 0 {
		t.Fatal("expected generated workflow properties")
	}
	for _, p := range workflowProps {
		eval.Register(p)
	}

	// Query by subject
	bySubj := eval.GetBySubject("/api/v1/orders/{id}/confirm")
	if len(bySubj) != len(endpointProps) {
		t.Fatalf("expected %d properties for endpoint subject, got %d", len(endpointProps), len(bySubj))
	}

	// Query by class
	wfClassProps := eval.GetByClass(ClassWorkflowIntegrity)
	if len(wfClassProps) != len(workflowProps) {
		t.Fatalf("expected %d workflow integrity properties, got %d", len(workflowProps), len(wfClassProps))
	}

	// Update state with contradiction/violation
	firstWF := workflowProps[0]
	eval.ApplyResult(PropertyTestResult{
		PropertyID: firstWF.ID,
		MissionID:  uuid.New(),
		Holds:      false, // Property contradicted!
		Confidence: 0.95,
		Details:    "Payment step skipped",
	})

	updated, ok := eval.Get(firstWF.ID)
	if !ok {
		t.Fatal("expected property to exist in evaluator")
	}
	if updated.State != StateContradicted {
		t.Fatalf("expected StateContradicted, got %s", updated.State)
	}

	violated := eval.Violated()
	if len(violated) == 0 {
		t.Fatal("expected at least 1 violated property in evaluator")
	}
}

package reasoning

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/ai"
)

// --- ValidateHypothesis tests ---

func TestValidateHypothesisValid(t *testing.T) {
	validIDs := map[string]bool{"abc12345": true, "def67890": true}

	h := &ai.ResearchHypothesis{
		Statement: "The upload endpoint may not enforce authorization consistently",
		SupportingEvidence: []ai.EvidenceRef{
			{ID: "abc12345", Type: "observation", Summary: "upload endpoint found"},
		},
		ConfirmationCriteria: []string{"Unauthorized access reaches upload functionality"},
		RefutationCriteria:   []string{"Authorization consistently rejects unauthorized access"},
		MissingEvidence:      []string{"Cross-role comparison results"},
		Status:               ai.EpistemicPlausible,
		Confidence:           0.65,
	}

	if err := ValidateHypothesis(h, validIDs); err != nil {
		t.Errorf("expected valid hypothesis, got: %v", err)
	}
}

func TestValidateHypothesisEmptyStatement(t *testing.T) {
	h := &ai.ResearchHypothesis{Statement: ""}
	err := ValidateHypothesis(h, nil)
	if err == nil {
		t.Error("expected error for empty statement")
	}
}

func TestValidateHypothesisNoEvidence(t *testing.T) {
	h := &ai.ResearchHypothesis{
		Statement: "Something interesting",
	}
	err := ValidateHypothesis(h, nil)
	if err == nil {
		t.Error("expected error for no supporting evidence")
	}
}

func TestValidateHypothesisNoRefutation(t *testing.T) {
	h := &ai.ResearchHypothesis{
		Statement: "Something interesting",
		SupportingEvidence: []ai.EvidenceRef{
			{ID: "abc12345", Type: "observation", Summary: "test"},
		},
		ConfirmationCriteria: []string{"confirmed"},
		// No refutation criteria — unfalsifiable.
	}
	err := ValidateHypothesis(h, nil)
	if err == nil {
		t.Error("expected error for unfalsifiable hypothesis (no refutation criteria)")
	}
}

func TestValidateHypothesisNoConfirmation(t *testing.T) {
	h := &ai.ResearchHypothesis{
		Statement: "Something interesting",
		SupportingEvidence: []ai.EvidenceRef{
			{ID: "abc12345", Type: "observation", Summary: "test"},
		},
		RefutationCriteria: []string{"refuted"},
		// No confirmation criteria.
	}
	err := ValidateHypothesis(h, nil)
	if err == nil {
		t.Error("expected error for missing confirmation criteria")
	}
}

func TestValidateHypothesisInvalidStatus(t *testing.T) {
	h := &ai.ResearchHypothesis{
		Statement:            "Something interesting",
		SupportingEvidence:   []ai.EvidenceRef{{ID: "abc", Type: "obs", Summary: "s"}},
		ConfirmationCriteria: []string{"yes"},
		RefutationCriteria:   []string{"no"},
		Status:               "bogus",
		Confidence:           0.5,
	}
	err := ValidateHypothesis(h, nil)
	if err == nil {
		t.Error("expected error for invalid epistemic status")
	}
}

func TestValidateHypothesisConfidenceOutOfRange(t *testing.T) {
	base := ai.ResearchHypothesis{
		Statement:            "Test",
		SupportingEvidence:   []ai.EvidenceRef{{ID: "abc", Type: "obs", Summary: "s"}},
		ConfirmationCriteria: []string{"yes"},
		RefutationCriteria:   []string{"no"},
		Status:               ai.EpistemicPlausible,
	}

	tests := []struct {
		name       string
		confidence float64
		wantErr    bool
	}{
		{"negative", -0.1, true},
		{"too high", 1.1, true},
		{"zero", 0.0, false},
		{"one", 1.0, false},
		{"normal", 0.65, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := base
			h.Confidence = tt.confidence
			err := ValidateHypothesis(&h, nil)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// --- Forbidden claims tests ---

func TestValidateHypothesisForbiddenClaims(t *testing.T) {
	forbidden := []string{
		"This endpoint is vulnerable to SQL injection",
		"Confirmed vulnerability in upload handler",
		"The API is exploitable via IDOR",
		"Critical vulnerability: authentication bypass",
		"This can be exploited to gain admin access",
		"High severity finding in login page",
		"Zero-day in the admin panel",
		"0-day in the upload handler",
	}

	for _, stmt := range forbidden {
		name := stmt
		if len(name) > 30 {
			name = name[:30]
		}
		t.Run(name, func(t *testing.T) {
			h := &ai.ResearchHypothesis{
				Statement:            stmt,
				SupportingEvidence:   []ai.EvidenceRef{{ID: "abc", Type: "obs", Summary: "s"}},
				ConfirmationCriteria: []string{"yes"},
				RefutationCriteria:   []string{"no"},
				Status:               ai.EpistemicPlausible,
				Confidence:           0.5,
			}
			err := ValidateHypothesis(h, nil)
			if err == nil {
				t.Errorf("expected forbidden claim rejection for: %s", stmt)
			}
		})
	}
}

func TestValidateHypothesisAllowedStatements(t *testing.T) {
	allowed := []string{
		"The upload endpoint may not enforce authorization consistently",
		"The authentication boundary warrants investigation of session handling",
		"Insufficient evidence to determine whether file type validation is present",
		"The API surface may expose excessive data in responses",
	}

	for _, stmt := range allowed {
		name := stmt
		if len(name) > 30 {
			name = name[:30]
		}
		t.Run(name, func(t *testing.T) {
			h := &ai.ResearchHypothesis{
				Statement:            stmt,
				SupportingEvidence:   []ai.EvidenceRef{{ID: "abc", Type: "obs", Summary: "s"}},
				ConfirmationCriteria: []string{"yes"},
				RefutationCriteria:   []string{"no"},
				Status:               ai.EpistemicPlausible,
				Confidence:           0.5,
			}
			err := ValidateHypothesis(h, nil)
			if err != nil {
				t.Errorf("expected allowed statement, got: %v", err)
			}
		})
	}
}

// --- Evidence existence tests ---

func TestValidateHypothesisEvidenceExistence(t *testing.T) {
	validIDs := map[string]bool{"abc12345": true, "def67890": true}

	t.Run("valid reference", func(t *testing.T) {
		h := &ai.ResearchHypothesis{
			Statement:            "Test hypothesis",
			SupportingEvidence:   []ai.EvidenceRef{{ID: "abc12345", Type: "obs", Summary: "s"}},
			ConfirmationCriteria: []string{"yes"},
			RefutationCriteria:   []string{"no"},
			Status:               ai.EpistemicPlausible,
			Confidence:           0.5,
		}
		err := ValidateHypothesis(h, validIDs)
		if err != nil {
			t.Errorf("valid reference should pass: %v", err)
		}
	})

	t.Run("hallucinated reference", func(t *testing.T) {
		h := &ai.ResearchHypothesis{
			Statement:            "Test hypothesis",
			SupportingEvidence:   []ai.EvidenceRef{{ID: "does-not-exist", Type: "obs", Summary: "s"}},
			ConfirmationCriteria: []string{"yes"},
			RefutationCriteria:   []string{"no"},
			Status:               ai.EpistemicPlausible,
			Confidence:           0.5,
		}
		err := ValidateHypothesis(h, validIDs)
		if err == nil {
			t.Error("expected error for hallucinated evidence reference")
		}
	})

	t.Run("empty evidence ID", func(t *testing.T) {
		h := &ai.ResearchHypothesis{
			Statement:            "Test hypothesis",
			SupportingEvidence:   []ai.EvidenceRef{{ID: "", Type: "obs", Summary: "s"}},
			ConfirmationCriteria: []string{"yes"},
			RefutationCriteria:   []string{"no"},
			Status:               ai.EpistemicPlausible,
			Confidence:           0.5,
		}
		err := ValidateHypothesis(h, validIDs)
		if err == nil {
			t.Error("expected error for empty evidence ID")
		}
	})

	t.Run("nil validIDs skips check", func(t *testing.T) {
		h := &ai.ResearchHypothesis{
			Statement:            "Test hypothesis",
			SupportingEvidence:   []ai.EvidenceRef{{ID: "anything", Type: "obs", Summary: "s"}},
			ConfirmationCriteria: []string{"yes"},
			RefutationCriteria:   []string{"no"},
			Status:               ai.EpistemicPlausible,
			Confidence:           0.5,
		}
		err := ValidateHypothesis(h, nil)
		if err != nil {
			t.Errorf("nil validIDs should skip existence check: %v", err)
		}
	})
}

// --- ValidationPlan safety tests ---

func TestValidateValidationPlanSafetyEnforcement(t *testing.T) {
	plan := &ai.ValidationPlan{
		Question: "Does upload enforce authorization?",
		Steps: []ai.ValidationStep{
			{Order: 1, Description: "Send authenticated request", Purpose: "Baseline"},
			{Order: 2, Description: "Send unauthenticated request", Purpose: "Test boundary"},
		},
		ExpectedConfirmation: "Unauthorized access reaches upload",
		ExpectedRefutation:   "Authorization rejects unauthorized",
		Constraints: ai.ValidationConstraints{
			RequiresApproval:     false, // AI tries to bypass.
			AuthorizedTargetOnly: false, // AI tries to bypass.
			NonDestructive:       false, // AI tries to bypass.
			NoPersistence:        false, // AI tries to bypass.
			BoundedRequests:      100,
		},
	}

	ValidateValidationPlan(plan)

	// All safety constraints must be forcibly true.
	if !plan.Constraints.RequiresApproval {
		t.Error("RequiresApproval must be forcibly true")
	}
	if !plan.Constraints.AuthorizedTargetOnly {
		t.Error("AuthorizedTargetOnly must be forcibly true")
	}
	if !plan.Constraints.NonDestructive {
		t.Error("NonDestructive must be forcibly true")
	}
	if !plan.Constraints.NoPersistence {
		t.Error("NoPersistence must be forcibly true")
	}
	// BoundedRequests is not overridden.
	if plan.Constraints.BoundedRequests != 100 {
		t.Errorf("BoundedRequests should remain 100, got %d", plan.Constraints.BoundedRequests)
	}
}

// --- Confidence recalculation tests ---

func TestRecalculateConfidenceNoDecay(t *testing.T) {
	tracker := HypothesisTracker{
		EvaluationCount:    0,
		ContradictionCount: 0,
	}
	result := RecalculateConfidence(0.80, tracker)
	if result != 0.80 {
		t.Errorf("expected 0.80 with no decay, got %.2f", result)
	}
}

func TestRecalculateConfidenceEvaluationDecay(t *testing.T) {
	tests := []struct {
		name       string
		evalCount  int
		original   float64
		expected   float64
	}{
		{"1 eval", 1, 0.80, 0.75},
		{"2 evals", 2, 0.80, 0.70},
		{"5 evals", 5, 0.80, 0.55},
		{"floor", 10, 0.40, 0.10}, // Would go negative, hits floor.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := HypothesisTracker{EvaluationCount: tt.evalCount}
			result := RecalculateConfidence(tt.original, tracker)
			if abs(result-tt.expected) > 0.001 {
				t.Errorf("expected %.2f, got %.2f", tt.expected, result)
			}
		})
	}
}

func TestRecalculateConfidenceContradictionDecay(t *testing.T) {
	tests := []struct {
		name       string
		contraCount int
		original    float64
		expected    float64
	}{
		{"1 contradiction", 1, 0.80, 0.65},
		{"2 contradictions", 2, 0.80, 0.50},
		{"many contradictions", 6, 0.80, 0.0}, // Floor at 0.0.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := HypothesisTracker{ContradictionCount: tt.contraCount}
			result := RecalculateConfidence(tt.original, tracker)
			if abs(result-tt.expected) > 0.001 {
				t.Errorf("expected %.2f, got %.2f", tt.expected, result)
			}
		})
	}
}

func TestRecalculateConfidenceCombinedDecay(t *testing.T) {
	// 2 contradictions (-0.30) + 3 evals (-0.15) from original 0.80.
	tracker := HypothesisTracker{
		EvaluationCount:    3,
		ContradictionCount: 2,
	}
	result := RecalculateConfidence(0.80, tracker)
	// Contradictions first: 0.80 - 0.30 = 0.50
	// Then evals: 0.50 - 0.15 = 0.35
	if abs(result-0.35) > 0.001 {
		t.Errorf("expected 0.35, got %.2f", result)
	}
}

// --- Constraint enforcement tests ---

func TestEnforceConstraintsMaxHypotheses(t *testing.T) {
	r := ai.ResearchResponse{
		Hypotheses: make([]ai.ResearchHypothesis, 10),
	}
	result := enforceConstraints(r, ResearchConstraints{MaxHypotheses: 3})
	if len(result.Hypotheses) != 3 {
		t.Errorf("expected 3 hypotheses, got %d", len(result.Hypotheses))
	}
}

func TestEnforceConstraintsMaxQuestions(t *testing.T) {
	r := ai.ResearchResponse{
		AdditionalQuestions: make([]ai.ResearchQuestion, 10),
	}
	result := enforceConstraints(r, ResearchConstraints{MaxQuestions: 2})
	if len(result.AdditionalQuestions) != 2 {
		t.Errorf("expected 2 questions, got %d", len(result.AdditionalQuestions))
	}
}

func TestEnforceConstraintsForbiddenClaims(t *testing.T) {
	r := ai.ResearchResponse{
		Hypotheses: []ai.ResearchHypothesis{
			{Statement: "This is fine"},
			{Statement: "This is exploitable via injection"},
			{Statement: "Another safe one"},
		},
	}
	result := enforceConstraints(r, ResearchConstraints{ForbiddenClaims: []string{"exploitable"}})
	if len(result.Hypotheses) != 2 {
		t.Errorf("expected 2 hypotheses after filtering, got %d", len(result.Hypotheses))
	}
}

// --- Epistemic status tests ---

func TestValidEpistemicStatuses(t *testing.T) {
	valid := []ai.EpistemicStatus{
		ai.EpistemicSupported,
		ai.EpistemicPlausible,
		ai.EpistemicUncertain,
		ai.EpistemicContradicted,
		ai.EpistemicInsufficient,
	}
	for _, s := range valid {
		if !validEpistemicStatus(s) {
			t.Errorf("expected %s to be valid", s)
		}
	}

	invalid := []ai.EpistemicStatus{"confirmed", "vulnerable", "true", ""}
	for _, s := range invalid {
		if validEpistemicStatus(s) {
			t.Errorf("expected %s to be invalid", s)
		}
	}
}

// --- HypothesisTracker tests ---

func TestHypothesisTrackerFields(t *testing.T) {
	tracker := HypothesisTracker{
		HypothesisID:              uuid.New(),
		LastSupportedAt:           time.Now(),
		SupportingEvidenceVersion: "v1",
		EvaluationCount:           0,
		ContradictionCount:        0,
	}
	// Verify it's a valid struct.
	if tracker.HypothesisID == uuid.Nil {
		t.Error("hypothesis ID should not be nil")
	}
}

// --- Evidence ID set builder test ---

func TestBuildValidEvidenceIDs(t *testing.T) {
	ids := buildValidEvidenceIDs(nil)
	if len(ids) != 0 {
		t.Error("nil bundle should return empty set")
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

package finding

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// --- ValidateCandidate Tests ---

func TestValidateCandidateValid(t *testing.T) {
	obs1 := uuid.New()
	c := domain.FindingCandidate{
		ID:           uuid.New(),
		HypothesisID: uuid.New(),
		EvidenceChain: domain.EvidenceChain{
			ObservationIDs: []uuid.UUID{obs1},
			Summary:        "test evidence",
		},
		SuggestedTitle:    "Test finding",
		SuggestedCategory: domain.FindingCatAuthorization,
		SuggestedSeverity: domain.SeverityHigh,
		Rationale:         "Hypothesis was supported by validation",
		Status:            domain.CandidatePending,
	}

	validIDs := map[uuid.UUID]bool{obs1: true}
	if err := ValidateCandidate(c, validIDs); err != nil {
		t.Fatalf("valid candidate should pass: %v", err)
	}
}

func TestValidateCandidateNoHypothesis(t *testing.T) {
	c := domain.FindingCandidate{
		SuggestedTitle: "Test",
		Rationale:      "test",
		EvidenceChain:  domain.EvidenceChain{ObservationIDs: []uuid.UUID{uuid.New()}},
	}
	if err := ValidateCandidate(c, nil); err == nil {
		t.Error("candidate without hypothesis should fail")
	}
}

func TestValidateCandidateNoTitle(t *testing.T) {
	c := domain.FindingCandidate{
		HypothesisID:  uuid.New(),
		Rationale:     "test",
		EvidenceChain: domain.EvidenceChain{ObservationIDs: []uuid.UUID{uuid.New()}},
	}
	if err := ValidateCandidate(c, nil); err == nil {
		t.Error("candidate without title should fail")
	}
}

func TestValidateCandidateNoEvidence(t *testing.T) {
	c := domain.FindingCandidate{
		HypothesisID:   uuid.New(),
		SuggestedTitle: "Test",
		Rationale:      "test",
	}
	if err := ValidateCandidate(c, nil); err == nil {
		t.Error("candidate without evidence should fail")
	}
}

func TestValidateCandidateNoRationale(t *testing.T) {
	c := domain.FindingCandidate{
		HypothesisID:   uuid.New(),
		SuggestedTitle: "Test",
		EvidenceChain:  domain.EvidenceChain{ObservationIDs: []uuid.UUID{uuid.New()}},
	}
	if err := ValidateCandidate(c, nil); err == nil {
		t.Error("candidate without rationale should fail")
	}
}

func TestValidateCandidateHallucinatedEvidence(t *testing.T) {
	validIDs := map[uuid.UUID]bool{uuid.New(): true}
	c := domain.FindingCandidate{
		HypothesisID:   uuid.New(),
		SuggestedTitle: "Test",
		Rationale:      "test",
		EvidenceChain: domain.EvidenceChain{
			ObservationIDs: []uuid.UUID{uuid.New()}, // Not in validIDs
		},
	}
	if err := ValidateCandidate(c, validIDs); err == nil {
		t.Error("candidate with non-existent observation should fail")
	}
}

// --- ValidateEvidenceChain Tests ---

func TestValidateEvidenceChainValid(t *testing.T) {
	obs1 := uuid.New()
	chain := domain.EvidenceChain{
		ObservationIDs: []uuid.UUID{obs1},
		Summary:        "Evidence path from discovery to validation",
	}
	validIDs := map[uuid.UUID]bool{obs1: true}

	if err := ValidateEvidenceChain(chain, validIDs); err != nil {
		t.Fatalf("valid chain should pass: %v", err)
	}
}

func TestValidateEvidenceChainNoObservations(t *testing.T) {
	chain := domain.EvidenceChain{Summary: "No observations"}
	if err := ValidateEvidenceChain(chain, nil); err == nil {
		t.Error("chain without observations should fail")
	}
}

func TestValidateEvidenceChainNoSummary(t *testing.T) {
	chain := domain.EvidenceChain{
		ObservationIDs: []uuid.UUID{uuid.New()},
	}
	if err := ValidateEvidenceChain(chain, nil); err == nil {
		t.Error("chain without summary should fail")
	}
}

func TestValidateEvidenceChainHallucinatedRef(t *testing.T) {
	validIDs := map[uuid.UUID]bool{uuid.New(): true}
	chain := domain.EvidenceChain{
		ObservationIDs: []uuid.UUID{uuid.New()}, // Not in validIDs
		Summary:        "test",
	}
	if err := ValidateEvidenceChain(chain, validIDs); err == nil {
		t.Error("chain with non-existent observation should fail")
	}
}

// --- ValidateConfirmation Tests ---

func TestValidateConfirmationValid(t *testing.T) {
	now := time.Now()
	obs1 := uuid.New()
	f := domain.Finding{
		Title:    "Unauthorized file upload",
		Status:   domain.FindingConfirmed,
		Severity: domain.SeverityHigh,
		Category: domain.FindingCatFileUpload,
		EvidenceChain: domain.EvidenceChain{
			ObservationIDs: []uuid.UUID{obs1},
			Summary:        "Upload endpoint allows unauthenticated access",
		},
		EvidenceIDs: []uuid.UUID{obs1},
		ReproductionSteps: []domain.ReproductionStep{
			{Order: 1, Description: "Access upload", ExpectedResult: "403", ObservedResult: "200"},
		},
		Impact: domain.ImpactAssessment{
			Confidentiality: "low",
			Integrity:       "high",
			Description:     "Unauthorized file upload allows arbitrary file placement",
		},
		ConfirmedBy: "researcher@example.com",
		ConfirmedAt: &now,
	}

	validIDs := map[uuid.UUID]bool{obs1: true}
	if err := ValidateConfirmation(f, validIDs); err != nil {
		t.Fatalf("valid confirmation should pass: %v", err)
	}
}

func TestValidateConfirmationRejectsAIConfirmer(t *testing.T) {
	now := time.Now()
	f := domain.Finding{
		Title:  "Test",
		Status: domain.FindingConfirmed,
		EvidenceChain: domain.EvidenceChain{
			ObservationIDs: []uuid.UUID{uuid.New()},
			Summary:        "test",
		},
		EvidenceIDs: []uuid.UUID{uuid.New()},
		ReproductionSteps: []domain.ReproductionStep{
			{Order: 1, Description: "test", ExpectedResult: "test", ObservedResult: "test"},
		},
		Impact:      domain.ImpactAssessment{Description: "test"},
		ConfirmedBy: "ai", // NOT ALLOWED
		ConfirmedAt: &now,
	}

	if err := ValidateConfirmation(f, nil); err == nil {
		t.Error("AI should not be able to confirm findings")
	}
}

func TestValidateConfirmationRejectsSystemConfirmer(t *testing.T) {
	now := time.Now()
	f := domain.Finding{
		Title:  "Test",
		Status: domain.FindingConfirmed,
		EvidenceChain: domain.EvidenceChain{
			ObservationIDs: []uuid.UUID{uuid.New()},
			Summary:        "test",
		},
		EvidenceIDs: []uuid.UUID{uuid.New()},
		ReproductionSteps: []domain.ReproductionStep{
			{Order: 1, Description: "test", ExpectedResult: "test", ObservedResult: "test"},
		},
		Impact:      domain.ImpactAssessment{Description: "test"},
		ConfirmedBy: "system", // NOT ALLOWED
		ConfirmedAt: &now,
	}

	if err := ValidateConfirmation(f, nil); err == nil {
		t.Error("system should not be able to confirm findings")
	}
}

func TestValidateConfirmationRequiresImpact(t *testing.T) {
	now := time.Now()
	f := domain.Finding{
		Title:  "Test",
		Status: domain.FindingConfirmed,
		EvidenceChain: domain.EvidenceChain{
			ObservationIDs: []uuid.UUID{uuid.New()},
			Summary:        "test",
		},
		EvidenceIDs: []uuid.UUID{uuid.New()},
		ReproductionSteps: []domain.ReproductionStep{
			{Order: 1, Description: "test", ExpectedResult: "test", ObservedResult: "test"},
		},
		// Missing Impact
		ConfirmedBy: "researcher",
		ConfirmedAt: &now,
	}

	if err := ValidateConfirmation(f, nil); err == nil {
		t.Error("confirmed finding without impact should fail")
	}
}

func TestValidateConfirmationRequiresReproSteps(t *testing.T) {
	now := time.Now()
	f := domain.Finding{
		Title:  "Test",
		Status: domain.FindingConfirmed,
		EvidenceChain: domain.EvidenceChain{
			ObservationIDs: []uuid.UUID{uuid.New()},
			Summary:        "test",
		},
		EvidenceIDs: []uuid.UUID{uuid.New()},
		// Missing ReproductionSteps
		Impact:      domain.ImpactAssessment{Description: "test"},
		ConfirmedBy: "researcher",
		ConfirmedAt: &now,
	}

	if err := ValidateConfirmation(f, nil); err == nil {
		t.Error("confirmed finding without reproduction steps should fail")
	}
}

func TestValidateConfirmationDraftSkipsHumanCheck(t *testing.T) {
	f := domain.Finding{
		Title:  "Draft finding",
		Status: domain.FindingDraft,
		EvidenceChain: domain.EvidenceChain{
			ObservationIDs: []uuid.UUID{uuid.New()},
			Summary:        "test",
		},
		EvidenceIDs: []uuid.UUID{uuid.New()},
		// No ConfirmedBy needed for draft.
	}

	if err := ValidateConfirmation(f, nil); err != nil {
		t.Fatalf("draft finding should not require human confirmer: %v", err)
	}
}

// --- Template Validation Tests ---

func TestValidateAgainstTemplateValid(t *testing.T) {
	tmpl := domain.FindingTemplate{
		Category: domain.FindingCatAuthorization,
		RequiredEvidence: []domain.EvidenceRequirement{
			{Name: "affected_resource", EvidenceType: "observation"},
			{Name: "comparison_evidence", EvidenceType: "validation"},
		},
		ReproductionSchema: []string{"step1", "step2"},
	}

	f := domain.Finding{
		Category:    domain.FindingCatAuthorization,
		EvidenceIDs: []uuid.UUID{uuid.New()},
		EvidenceChain: domain.EvidenceChain{
			ObservationIDs:      []uuid.UUID{uuid.New()},
			ValidationResultIDs: []uuid.UUID{uuid.New()},
		},
		ReproductionSteps: []domain.ReproductionStep{
			{Order: 1, Description: "step1"},
			{Order: 2, Description: "step2"},
		},
	}

	if err := ValidateAgainstTemplate(f, tmpl); err != nil {
		t.Fatalf("valid finding should match template: %v", err)
	}
}

func TestValidateAgainstTemplateCategoryMismatch(t *testing.T) {
	tmpl := domain.FindingTemplate{Category: domain.FindingCatAuthorization}
	f := domain.Finding{Category: domain.FindingCatInjection}

	if err := ValidateAgainstTemplate(f, tmpl); err == nil {
		t.Error("category mismatch should fail")
	}
}

func TestValidateAgainstTemplateMissingEvidence(t *testing.T) {
	tmpl := domain.FindingTemplate{
		Category: domain.FindingCatAuthorization,
		RequiredEvidence: []domain.EvidenceRequirement{
			{Name: "comparison_evidence", EvidenceType: "validation"},
		},
	}

	f := domain.Finding{
		Category:    domain.FindingCatAuthorization,
		EvidenceIDs: []uuid.UUID{uuid.New()},
		// No ValidationResultIDs → missing "validation" type
	}

	if err := ValidateAgainstTemplate(f, tmpl); err == nil {
		t.Error("missing required evidence type should fail")
	}
}

func TestValidateAgainstTemplateInsufficientSteps(t *testing.T) {
	tmpl := domain.FindingTemplate{
		Category:           domain.FindingCatAuthorization,
		ReproductionSchema: []string{"step1", "step2", "step3"},
	}

	f := domain.Finding{
		Category:    domain.FindingCatAuthorization,
		EvidenceIDs: []uuid.UUID{uuid.New()},
		ReproductionSteps: []domain.ReproductionStep{
			{Order: 1, Description: "only one step"},
		},
	}

	if err := ValidateAgainstTemplate(f, tmpl); err == nil {
		t.Error("insufficient reproduction steps should fail")
	}
}

// --- Built-in Templates ---

func TestBuiltinTemplatesExist(t *testing.T) {
	templates := BuiltinTemplates()

	expected := []domain.FindingCategory{
		domain.FindingCatAuthorization,
		domain.FindingCatAuthentication,
		domain.FindingCatInfoDisclosure,
		domain.FindingCatMisconfiguration,
		domain.FindingCatFileUpload,
	}

	for _, cat := range expected {
		tmpl, ok := templates[cat]
		if !ok {
			t.Errorf("missing template for category %s", cat)
			continue
		}
		if len(tmpl.RequiredEvidence) == 0 {
			t.Errorf("template %s has no required evidence", cat)
		}
		if len(tmpl.ReproductionSchema) == 0 {
			t.Errorf("template %s has no reproduction schema", cat)
		}
		if tmpl.RemediationGuidance == "" {
			t.Errorf("template %s has no remediation guidance", cat)
		}
	}
}

// --- Epistemic Boundary Tests ---

func TestFindingStatusValues(t *testing.T) {
	// Verify all statuses exist and are distinct.
	statuses := map[domain.FindingStatus]bool{
		domain.FindingDraft:         true,
		domain.FindingConfirmed:     true,
		domain.FindingReported:      true,
		domain.FindingResolved:      true,
		domain.FindingFalsePositive: true,
		domain.FindingDisputed:      true,
		domain.FindingDuplicate:     true,
	}
	if len(statuses) != 7 {
		t.Error("expected 7 distinct finding statuses")
	}
}

func TestCandidateStatusValues(t *testing.T) {
	statuses := map[domain.CandidateStatus]bool{
		domain.CandidatePending:    true,
		domain.CandidateAccepted:   true,
		domain.CandidateRejected:   true,
		domain.CandidateNeedsMore:  true,
	}
	if len(statuses) != 4 {
		t.Error("expected 4 distinct candidate statuses")
	}
}

func TestSeverityValues(t *testing.T) {
	severities := map[domain.Severity]bool{
		domain.SeverityCritical: true,
		domain.SeverityHigh:     true,
		domain.SeverityMedium:   true,
		domain.SeverityLow:      true,
		domain.SeverityInfo:     true,
	}
	if len(severities) != 5 {
		t.Error("expected 5 distinct severity levels")
	}
}

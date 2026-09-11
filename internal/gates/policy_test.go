package gates

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/report"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestPolicyEvaluation_PassesWhenWithinThreshold(t *testing.T) {
	findingID := uuid.New()
	finding := domain.Finding{
		ID:          findingID,
		Title:       "Low Risk Header Exposure",
		Severity:    domain.SeverityLow,
		Category:    domain.FindingCatInfoDisclosure,
		Status:      domain.FindingConfirmed,
		ConfirmedBy: "Human Researcher",
		ConfirmedAt: timePtr(time.Now().UTC()),
	}

	proven := domain.ProvenFinding{
		ID:       findingID,
		Title:    finding.Title,
		Type:     "GenericVulnerability",
		Severity: "low",
		Endpoint: "/",
		ValidationEvidence: []domain.ExperimentEvidence{
			{
				ID:             uuid.New(),
				RequestMethod:  "GET",
				RequestURL:     "http://target.local/",
				ResponseStatus: 200,
				ResponseBody:   "OK",
				CapturedAt:     time.Now().UTC(),
			},
		},
		ValidatedAt: time.Now().UTC(),
	}

	bundle, err := report.GenerateProofBundle(proven, "http://target.local", nil)
	if err != nil {
		t.Fatalf("failed to generate proof bundle: %v", err)
	}

	policy := DefaultEnterprisePolicy()
	verdict := EvaluatePolicy([]domain.Finding{finding}, []*report.ProofBundle{bundle}, policy)

	if !verdict.Passed {
		t.Fatalf("expected policy to pass, got failed with %d violations: %s", verdict.TotalViolations, verdict.Summary)
	}
	if verdict.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", verdict.ExitCode)
	}
}

func TestPolicyEvaluation_FailsOnCriticalSeverityAndDisallowedCWE(t *testing.T) {
	findingID := uuid.New()
	finding := domain.Finding{
		ID:          findingID,
		Title:       "HTTP Request Smuggling TE.CL",
		Severity:    domain.SeverityCritical,
		Category:    domain.FindingCatMisconfiguration,
		Status:      domain.FindingConfirmed,
		ConfirmedBy: "DOGE Independent Validator",
		ConfirmedAt: timePtr(time.Now().UTC()),
	}

	proven := domain.ProvenFinding{
		ID:       findingID,
		Title:    finding.Title,
		Type:     "RequestSmuggling",
		Severity: "critical",
		Endpoint: "/",
		ValidationEvidence: []domain.ExperimentEvidence{
			{
				ID:             uuid.New(),
				RequestMethod:  "POST",
				RequestURL:     "http://target.local/",
				ResponseStatus: 200,
				ResponseBody:   "SMUGGLED",
				CapturedAt:     time.Now().UTC(),
			},
		},
		ValidatedAt: time.Now().UTC(),
	}

	bundle, err := report.GenerateProofBundle(proven, "http://target.local", nil)
	if err != nil {
		t.Fatalf("failed to generate proof bundle: %v", err)
	}

	policy := DefaultEnterprisePolicy()
	verdict := EvaluatePolicy([]domain.Finding{finding}, []*report.ProofBundle{bundle}, policy)

	if verdict.Passed {
		t.Fatalf("expected policy to fail on critical request smuggling finding, but it passed")
	}
	if verdict.ExitCode != 1 {
		t.Errorf("expected exit code 1, got %d", verdict.ExitCode)
	}
	if len(verdict.Violations) == 0 {
		t.Errorf("expected violations, got 0")
	}

	hasCWEViolation := false
	for _, v := range verdict.Violations {
		if v.RuleName == "DisallowedCWE" && v.CWE == "CWE-444" {
			hasCWEViolation = true
			break
		}
	}
	if !hasCWEViolation {
		t.Errorf("expected DisallowedCWE violation for CWE-444")
	}
}

func TestPolicyEvaluation_EnforcesProofBundleRequirement(t *testing.T) {
	findingID := uuid.New()
	finding := domain.Finding{
		ID:          findingID,
		Title:       "Unverified BOLA Candidate",
		Severity:    domain.SeverityHigh,
		Category:    domain.FindingCatAuthorization,
		Status:      domain.FindingConfirmed,
		ConfirmedBy: "Human Researcher",
		ConfirmedAt: timePtr(time.Now().UTC()),
	}

	policy := DefaultEnterprisePolicy()
	// Provide NO proof bundles
	verdict := EvaluatePolicy([]domain.Finding{finding}, nil, policy)

	if verdict.Passed {
		t.Fatalf("expected policy to fail because proof bundle is required, but it passed")
	}

	foundProofViolation := false
	for _, v := range verdict.Violations {
		if v.RuleName == "RequireProofBundle" {
			foundProofViolation = true
			break
		}
	}
	if !foundProofViolation {
		t.Errorf("expected RequireProofBundle violation")
	}
}

func TestPolicyEvaluation_ExclusionsAreRespected(t *testing.T) {
	findingID := uuid.New()
	finding := domain.Finding{
		ID:          findingID,
		Title:       "Known Accepted Critical Finding",
		Severity:    domain.SeverityCritical,
		Category:    domain.FindingCatMisconfiguration,
		Status:      domain.FindingConfirmed,
		ConfirmedBy: "Human Researcher",
		ConfirmedAt: timePtr(time.Now().UTC()),
	}

	policy := DefaultEnterprisePolicy()
	policy.ExcludedFindingIDs = []string{findingID.String()}

	verdict := EvaluatePolicy([]domain.Finding{finding}, nil, policy)

	if !verdict.Passed {
		t.Fatalf("expected excluded finding to not trigger violation, but got failed: %s", verdict.Summary)
	}
	if verdict.TotalViolations != 0 {
		t.Errorf("expected 0 violations for excluded finding, got %d", verdict.TotalViolations)
	}
}

func timePtr(t time.Time) *time.Time {
	return &t
}

package gates

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/report"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// PolicyRule defines thresholds and constraints for automated CI/CD gating.
type PolicyRule struct {
	MaxAllowedSeverity      domain.Severity `json:"max_allowed_severity"`      // e.g. "medium" allows low/medium, fails on high/critical
	MaxAllowedCVSS          float64         `json:"max_allowed_cvss"`          // e.g. 7.0 fails if CVSS >= 7.0
	RequireProofBundle      bool            `json:"require_proof_bundle"`      // Enforces 0% false positive by requiring valid proof bundle
	MinEpistemicConfidence  float64         `json:"min_epistemic_confidence"`  // e.g. 0.90 ignores or requires high confidence
	DisallowedCWEs          []string        `json:"disallowed_cwes,omitempty"` // Specific CWEs that always fail the build
	FailClosed              bool            `json:"fail_closed"`               // Fail pipeline on evaluation or verification errors
}

// PolicyConfig encapsulates the entire gating policy configuration.
type PolicyConfig struct {
	PolicyName         string     `json:"policy_name"`
	Rules              PolicyRule `json:"rules"`
	ExcludedFindingIDs []string   `json:"excluded_finding_ids,omitempty"`
}

// PolicyViolation details an individual finding that failed the policy.
type PolicyViolation struct {
	FindingID      uuid.UUID       `json:"finding_id"`
	FindingTitle   string          `json:"finding_title"`
	Severity       domain.Severity `json:"severity"`
	CVSS           float64         `json:"cvss"`
	CWE            string          `json:"cwe"`
	RuleName       string          `json:"rule_name"`
	Reason         string          `json:"reason"`
	HasProofBundle bool            `json:"has_proof_bundle"`
}

// PolicyVerdict is the outcome of evaluating a set of findings against a policy.
type PolicyVerdict struct {
	PolicyName      string            `json:"policy_name"`
	Passed          bool              `json:"passed"`
	TotalFindings   int               `json:"total_findings"`
	TotalViolations int               `json:"total_violations"`
	Violations      []PolicyViolation `json:"violations"`
	Summary         string            `json:"summary"`
	ExitCode        int               `json:"exit_code"` // 0 = Pass, 1 = Fail
	EvaluatedAt     time.Time         `json:"evaluated_at"`
}

// DefaultEnterprisePolicy returns the standard fail-closed enterprise CI/CD gating policy.
func DefaultEnterprisePolicy() PolicyConfig {
	return PolicyConfig{
		PolicyName: "DOGE-Zero-False-Positive-Enterprise-Gate",
		Rules: PolicyRule{
			MaxAllowedSeverity:     domain.SeverityMedium,
			MaxAllowedCVSS:         7.0,
			RequireProofBundle:     true,
			MinEpistemicConfidence: 0.90,
			DisallowedCWEs:         []string{"CWE-444", "CWE-287"}, // Smuggling and Auth bypass are zero-tolerance
			FailClosed:             true,
		},
	}
}

// EvaluatePolicy checks findings and their associated proof bundles against policy rules.
func EvaluatePolicy(findings []domain.Finding, bundles []*report.ProofBundle, config PolicyConfig) *PolicyVerdict {
	now := time.Now().UTC()
	verdict := &PolicyVerdict{
		PolicyName:    config.PolicyName,
		Passed:        true,
		TotalFindings: len(findings),
		Violations:    make([]PolicyViolation, 0),
		ExitCode:      0,
		EvaluatedAt:   now,
	}

	// Index proof bundles by finding ID
	bundleMap := make(map[string]*report.ProofBundle)
	for _, b := range bundles {
		if b != nil {
			bundleMap[b.FindingID.String()] = b
		}
	}

	// Index exclusions
	excluded := make(map[string]bool)
	for _, id := range config.ExcludedFindingIDs {
		excluded[id] = true
	}

	for _, f := range findings {
		if excluded[f.ID.String()] {
			continue
		}

		vulnType := mapFindingToVulnType(f)
		cvssScore := report.GetVulnerabilityScore(vulnType)

		bundle, hasProof := bundleMap[f.ID.String()]

		// Check proof integrity if bundle is present
		proofValid := false
		if hasProof && bundle != nil {
			valid, err := report.VerifyProofBundleIntegrity(bundle, nil)
			if err == nil && valid {
				proofValid = true
			}
		}

		// Rule 1: RequireProofBundle
		// If policy mandates proof bundles, a finding lacking verified proof causes a violation.
		if config.Rules.RequireProofBundle && !proofValid {
			verdict.Violations = append(verdict.Violations, PolicyViolation{
				FindingID:      f.ID,
				FindingTitle:   f.Title,
				Severity:       f.Severity,
				CVSS:           cvssScore.BaseScore,
				CWE:            cvssScore.CWEID,
				RuleName:       "RequireProofBundle",
				Reason:         "Finding lacks a verified, tamper-evident cryptographic proof bundle.",
				HasProofBundle: false,
			})
			continue
		}

		// Rule 2: Disallowed CWEs (zero tolerance)
		for _, disallowed := range config.Rules.DisallowedCWEs {
			if strings.EqualFold(cvssScore.CWEID, disallowed) {
				verdict.Violations = append(verdict.Violations, PolicyViolation{
					FindingID:      f.ID,
					FindingTitle:   f.Title,
					Severity:       f.Severity,
					CVSS:           cvssScore.BaseScore,
					CWE:            cvssScore.CWEID,
					RuleName:       "DisallowedCWE",
					Reason:         fmt.Sprintf("Vulnerability matches zero-tolerance banned CWE %s.", disallowed),
					HasProofBundle: proofValid,
				})
			}
		}

		// Rule 3: MaxAllowedSeverity
		if isSeverityExceeded(f.Severity, config.Rules.MaxAllowedSeverity) {
			verdict.Violations = append(verdict.Violations, PolicyViolation{
				FindingID:      f.ID,
				FindingTitle:   f.Title,
				Severity:       f.Severity,
				CVSS:           cvssScore.BaseScore,
				CWE:            cvssScore.CWEID,
				RuleName:       "MaxAllowedSeverity",
				Reason:         fmt.Sprintf("Finding severity %s exceeds threshold %s.", f.Severity, config.Rules.MaxAllowedSeverity),
				HasProofBundle: proofValid,
			})
		}

		// Rule 4: MaxAllowedCVSS
		if config.Rules.MaxAllowedCVSS > 0 && cvssScore.BaseScore >= config.Rules.MaxAllowedCVSS {
			verdict.Violations = append(verdict.Violations, PolicyViolation{
				FindingID:      f.ID,
				FindingTitle:   f.Title,
				Severity:       f.Severity,
				CVSS:           cvssScore.BaseScore,
				CWE:            cvssScore.CWEID,
				RuleName:       "MaxAllowedCVSS",
				Reason:         fmt.Sprintf("Finding CVSS score %.1f exceeds threshold %.1f.", cvssScore.BaseScore, config.Rules.MaxAllowedCVSS),
				HasProofBundle: proofValid,
			})
		}
	}

	verdict.TotalViolations = len(verdict.Violations)
	if verdict.TotalViolations > 0 {
		verdict.Passed = false
		verdict.ExitCode = 1
		verdict.Summary = fmt.Sprintf("CI/CD Security Gate FAILED: %d violation(s) detected across %d evaluated finding(s).", verdict.TotalViolations, verdict.TotalFindings)
	} else {
		verdict.Passed = true
		verdict.ExitCode = 0
		verdict.Summary = fmt.Sprintf("CI/CD Security Gate PASSED: 0 violations across %d evaluated finding(s).", verdict.TotalFindings)
	}

	return verdict
}

// LoadPolicyConfig reads a policy configuration from a JSON file.
func LoadPolicyConfig(path string) (*PolicyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var config PolicyConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy configuration: %w", err)
	}

	return &config, nil
}

func isSeverityExceeded(sev, maxAllowed domain.Severity) bool {
	sevWeights := map[domain.Severity]int{
		domain.SeverityCritical: 5,
		domain.SeverityHigh:     4,
		domain.SeverityMedium:   3,
		domain.SeverityLow:      2,
		domain.SeverityInfo:     1,
	}

	return sevWeights[sev] > sevWeights[maxAllowed]
}

func mapFindingToVulnType(f domain.Finding) string {
	tLower := strings.ToLower(f.Title)
	switch {
	case strings.Contains(tLower, "bola") || strings.Contains(tLower, "idor"):
		return "BOLA"
	case strings.Contains(tLower, "race") || strings.Contains(tLower, "concurrency") || strings.Contains(tLower, "overdraw"):
		return "RaceCondition"
	case strings.Contains(tLower, "smuggl") || strings.Contains(tLower, "desync") || strings.Contains(tLower, "te.cl"):
		return "RequestSmuggling"
	case strings.Contains(tLower, "jwt") || strings.Contains(tLower, "token") || strings.Contains(tLower, "confusion"):
		return "JWTConfusion"
	case strings.Contains(tLower, "timing") || strings.Contains(tLower, "blind"):
		return "BlindTimingOracle"
	case strings.Contains(tLower, "context bleed") || strings.Contains(tLower, "pipeline bleed"):
		return "ContextBleed"
	case strings.Contains(tLower, "workflow") || strings.Contains(tLower, "paywall"):
		return "WorkflowBypass"
	default:
		return "GenericVulnerability"
	}
}

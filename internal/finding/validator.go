// Package finding implements finding validation, candidate management,
// and evidence chain verification.
//
// The Finding is the ONLY epistemically authoritative object in DOGE.
// Everything before it in the ladder is cautious. A Finding says
// "a human confirmed this based on evidence."
//
// The validator enforces:
//   - Evidence chain exists and references real observations
//   - Hypothesis reference exists
//   - Reproduction steps exist for confirmed findings
//   - Human confirmer exists for confirmed findings
//   - Template requirements are satisfied (if template applies)
//
// The validator does NOT:
//   - Declare vulnerabilities
//   - Override human decisions
//   - Automatically confirm candidates
package finding

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// ValidateCandidate checks that a finding candidate has sufficient
// evidence to be presented for human review.
func ValidateCandidate(c domain.FindingCandidate, validObsIDs map[uuid.UUID]bool) error {
	if c.HypothesisID == uuid.Nil {
		return fmt.Errorf("candidate must reference a hypothesis")
	}
	if c.SuggestedTitle == "" {
		return fmt.Errorf("candidate must have a suggested title")
	}
	if len(c.EvidenceChain.ObservationIDs) == 0 {
		return fmt.Errorf("candidate evidence chain must have at least one observation")
	}
	if c.Rationale == "" {
		return fmt.Errorf("candidate must have a rationale explaining why it was created")
	}

	// Verify observation IDs exist if lookup provided.
	if validObsIDs != nil {
		for _, obsID := range c.EvidenceChain.ObservationIDs {
			if !validObsIDs[obsID] {
				return fmt.Errorf("candidate references non-existent observation %s", obsID)
			}
		}
	}

	return nil
}

// ValidateEvidenceChain checks that an evidence chain is complete
// and internally consistent.
func ValidateEvidenceChain(chain domain.EvidenceChain, validObsIDs map[uuid.UUID]bool) error {
	if len(chain.ObservationIDs) == 0 {
		return fmt.Errorf("evidence chain must have at least one observation")
	}
	if chain.Summary == "" {
		return fmt.Errorf("evidence chain must have a summary")
	}

	// Verify all observation references exist.
	if validObsIDs != nil {
		for _, obsID := range chain.ObservationIDs {
			if !validObsIDs[obsID] {
				return fmt.Errorf("evidence chain references non-existent observation %s", obsID)
			}
		}
	}

	return nil
}

// ValidateConfirmation checks that a finding meets all requirements
// for confirmed status.
func ValidateConfirmation(f domain.Finding, validObsIDs map[uuid.UUID]bool) error {
	// Basic finding validation.
	if err := domain.ValidateFinding(f); err != nil {
		return fmt.Errorf("finding validation failed: %w", err)
	}

	// Evidence chain must be valid.
	if err := ValidateEvidenceChain(f.EvidenceChain, validObsIDs); err != nil {
		return fmt.Errorf("evidence chain invalid: %w", err)
	}

	// Confirmed status requires human.
	if f.Status == domain.FindingConfirmed {
		if f.ConfirmedBy == "" {
			return fmt.Errorf("confirmed finding must have a human confirmer")
		}
		if f.ConfirmedBy == "ai" || f.ConfirmedBy == "system" {
			return fmt.Errorf("only humans can confirm findings (got: %s)", f.ConfirmedBy)
		}
		if f.ConfirmedAt == nil {
			return fmt.Errorf("confirmed finding must have a confirmation timestamp")
		}
	}

	// Impact assessment required for confirmed.
	if f.Status == domain.FindingConfirmed {
		if f.Impact.Description == "" {
			return fmt.Errorf("confirmed finding must have an impact description")
		}
	}

	return nil
}

// ValidateAgainstTemplate checks that a finding satisfies a template's
// evidence requirements.
func ValidateAgainstTemplate(f domain.Finding, tmpl domain.FindingTemplate) error {
	if f.Category != tmpl.Category {
		return fmt.Errorf("finding category %s does not match template category %s",
			f.Category, tmpl.Category)
	}

	// Check required evidence fields.
	evidenceData := collectEvidenceTypes(f)
	for _, req := range tmpl.RequiredEvidence {
		if _, ok := evidenceData[req.EvidenceType]; !ok {
			return fmt.Errorf("template requires %s evidence (%s) but it was not found",
				req.Name, req.EvidenceType)
		}
	}

	// Check reproduction schema.
	if len(tmpl.ReproductionSchema) > 0 && len(f.ReproductionSteps) < len(tmpl.ReproductionSchema) {
		return fmt.Errorf("template requires %d reproduction steps, finding has %d",
			len(tmpl.ReproductionSchema), len(f.ReproductionSteps))
	}

	return nil
}

// collectEvidenceTypes builds a set of evidence types present in a finding.
// For now, uses the observation count as a proxy. In a full implementation,
// this would look up observation types from the store.
func collectEvidenceTypes(f domain.Finding) map[string]bool {
	types := make(map[string]bool)
	// In a full implementation, each observation ID would be looked up
	// to get its type. For now, mark that evidence exists.
	if len(f.EvidenceIDs) > 0 || len(f.EvidenceChain.ObservationIDs) > 0 {
		types["observation"] = true
	}
	if len(f.EvidenceChain.CorrelationIDs) > 0 {
		types["correlation"] = true
	}
	if len(f.EvidenceChain.ValidationResultIDs) > 0 {
		types["validation"] = true
	}
	return types
}

// --- Built-in Templates ---

// BuiltinTemplates returns the default finding templates for common
// vulnerability classes.
//
// Templates define WHAT EVIDENCE is needed, not what the vulnerability IS.
func BuiltinTemplates() map[domain.FindingCategory]domain.FindingTemplate {
	return map[domain.FindingCategory]domain.FindingTemplate{
		domain.FindingCatAuthorization: {
			Category: domain.FindingCatAuthorization,
			RequiredEvidence: []domain.EvidenceRequirement{
				{Name: "affected_resource", Description: "The resource with broken authorization", EvidenceType: "observation"},
				{Name: "comparison_evidence", Description: "Evidence comparing authorized vs unauthorized access", EvidenceType: "validation"},
			},
			OptionalEvidence: []domain.EvidenceRequirement{
				{Name: "role_comparison", Description: "Cross-role comparison results", EvidenceType: "validation"},
			},
			ReproductionSchema: []string{
				"Identify the protected resource",
				"Establish authorized access baseline",
				"Attempt unauthorized access",
				"Compare authorization decisions",
			},
			ImpactFields:        []string{"confidentiality", "integrity"},
			RemediationGuidance: "Implement proper authorization checks on the affected resource.",
		},
		domain.FindingCatAuthentication: {
			Category: domain.FindingCatAuthentication,
			RequiredEvidence: []domain.EvidenceRequirement{
				{Name: "authentication_surface", Description: "The authentication mechanism", EvidenceType: "observation"},
				{Name: "bypass_evidence", Description: "Evidence of authentication weakness", EvidenceType: "validation"},
			},
			ReproductionSchema: []string{
				"Identify the authentication mechanism",
				"Attempt authentication bypass",
				"Document the bypass method",
				"Verify bypass achieves access",
			},
			ImpactFields:        []string{"confidentiality", "integrity", "availability"},
			RemediationGuidance: "Review and strengthen the authentication mechanism.",
		},
		domain.FindingCatInfoDisclosure: {
			Category: domain.FindingCatInfoDisclosure,
			RequiredEvidence: []domain.EvidenceRequirement{
				{Name: "exposed_resource", Description: "The resource exposing information", EvidenceType: "observation"},
				{Name: "sensitive_data_type", Description: "Type of data exposed", EvidenceType: "observation"},
			},
			ReproductionSchema: []string{
				"Access the exposed resource",
				"Identify the sensitive data",
				"Determine authorization context",
			},
			ImpactFields:        []string{"confidentiality"},
			RemediationGuidance: "Remove or restrict access to the exposed information.",
		},
		domain.FindingCatMisconfiguration: {
			Category: domain.FindingCatMisconfiguration,
			RequiredEvidence: []domain.EvidenceRequirement{
				{Name: "misconfigured_component", Description: "The misconfigured service or component", EvidenceType: "observation"},
				{Name: "expected_configuration", Description: "What the configuration should be", EvidenceType: "observation"},
			},
			ReproductionSchema: []string{
				"Identify the misconfigured component",
				"Document current vs expected configuration",
				"Assess security impact",
			},
			ImpactFields:        []string{"confidentiality", "integrity", "availability"},
			RemediationGuidance: "Correct the configuration to match security best practices.",
		},
		domain.FindingCatFileUpload: {
			Category: domain.FindingCatFileUpload,
			RequiredEvidence: []domain.EvidenceRequirement{
				{Name: "upload_endpoint", Description: "The file upload endpoint", EvidenceType: "observation"},
				{Name: "authorization_context", Description: "Who can access the upload", EvidenceType: "validation"},
			},
			OptionalEvidence: []domain.EvidenceRequirement{
				{Name: "file_type_validation", Description: "Evidence of file type restrictions", EvidenceType: "validation"},
				{Name: "file_storage_location", Description: "Where uploaded files are stored", EvidenceType: "observation"},
			},
			ReproductionSchema: []string{
				"Identify the upload endpoint",
				"Determine authorization requirements",
				"Assess file type validation",
				"Determine storage and access model",
			},
			ImpactFields:        []string{"confidentiality", "integrity"},
			RemediationGuidance: "Implement proper file type validation, authorization, and storage controls.",
		},
	}
}

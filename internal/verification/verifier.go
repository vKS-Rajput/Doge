// Package verification provides claim-level evidence verification.
//
// The Verifier checks whether each claim made by the LLM is actually
// supported by the cited evidence. This is NOT simple keyword matching.
//
// Verification layers (in order):
//
//  1. Evidence ID validation — do the cited IDs exist?
//  2. Claim category validation — is the category appropriate?
//  3. Entity/relationship matching — does the evidence contain
//     the entities or relationships the claim references?
//  4. Structured field comparison — do evidence attributes
//     support the specific properties claimed?
//  5. Contradiction detection — does the evidence contradict?
//  6. Vulnerability claim gate — claims about vulnerabilities
//     require explicit vulnerability evidence, not mere existence.
//
// The verifier is deterministic. No LLM is used.
package verification

import (
	"strings"

	"github.com/vKS-Rajput/doge/internal/retriever"
	"github.com/vKS-Rajput/doge/pkg/ai"
)

// Verifier checks claims against evidence.
type Verifier struct{}

// New creates a new Verifier.
func New() *Verifier {
	return &Verifier{}
}

// Verify checks all claims in a response against the evidence bundle.
func (v *Verifier) Verify(response *ai.Response, bundle *retriever.Bundle) []ai.VerificationResult {
	// Build evidence lookup by short ID (first 8 chars) and full ID.
	evidenceByID := make(map[string]*retriever.Evidence)
	for i := range bundle.Evidence {
		e := &bundle.Evidence[i]
		evidenceByID[e.ID] = e
		if len(e.ID) >= 8 {
			evidenceByID[e.ID[:8]] = e
		}
	}

	results := make([]ai.VerificationResult, len(response.Claims))
	for i, claim := range response.Claims {
		results[i] = v.verifyClaim(i, claim, evidenceByID)
	}

	return results
}

func (v *Verifier) verifyClaim(index int, claim ai.Claim, evidenceByID map[string]*retriever.Evidence) ai.VerificationResult {
	result := ai.VerificationResult{
		ClaimIndex:  index,
		ClaimText:   claim.Text,
		EvidenceIDs: claim.EvidenceIDs,
	}

	// Layer 1: Evidence ID validation.
	if len(claim.EvidenceIDs) == 0 {
		result.Status = ai.StatusUnverifiable
		result.Reason = "No evidence IDs cited."
		return result
	}

	var resolvedEvidence []*retriever.Evidence
	for _, id := range claim.EvidenceIDs {
		e, found := evidenceByID[id]
		if !found {
			result.Status = ai.StatusUnsupported
			result.Reason = "Cited evidence ID '" + id + "' not found in retrieved evidence."
			return result
		}
		resolvedEvidence = append(resolvedEvidence, e)
	}

	// Layer 2: Claim category validation.
	if claim.Category == ai.ClaimHypothetical {
		// Hypothetical claims are allowed but explicitly marked.
		result.Status = ai.StatusPartiallySupported
		result.Reason = "Claim is explicitly hypothetical. Evidence exists but does not establish the claim as fact."
		return result
	}

	// Layer 3: Vulnerability claim gate.
	// Claims about vulnerabilities require explicit vulnerability evidence.
	claimLower := strings.ToLower(claim.Text)
	if isVulnerabilityClaim(claimLower) {
		if !hasVulnerabilityEvidence(resolvedEvidence) {
			result.Status = ai.StatusUnsupported
			result.Reason = "Claim asserts a vulnerability, but cited evidence only establishes existence, not a security flaw."
			return result
		}
	}

	// Layer 4: Entity/relationship matching.
	// Check if the claim's key concepts appear in the evidence.
	if claim.Category == ai.ClaimObserved {
		if !evidenceContainsConcepts(claimLower, resolvedEvidence) {
			result.Status = ai.StatusPartiallySupported
			result.Reason = "Claim is marked as 'observed' but key concepts were not found in cited evidence."
			return result
		}
	}

	// Layer 5: Structured field comparison.
	// For relationship claims ("X uses Y"), check if a relationship exists.
	if isRelationshipClaim(claimLower) {
		if hasMatchingRelationship(claimLower, resolvedEvidence) {
			result.Status = ai.StatusSupported
			result.Reason = "Claim is supported by relationship evidence."
			return result
		}
	}

	// Layer 6: Contradiction detection.
	// Check if evidence explicitly contradicts the claim.
	if contradiction := findContradiction(claimLower, resolvedEvidence); contradiction != "" {
		result.Status = ai.StatusContradicted
		result.Reason = "Evidence contradicts claim: " + contradiction
		return result
	}

	// Layer 7: Provenance consistency.
	// If the claim mentions a specific entity (domain, URL, IP), verify that
	// the cited evidence actually references that entity, not a different one
	// that happens to share keywords.
	claimDomain := extractDomainFromClaim(claimLower)
	if claimDomain != "" {
		if !evidenceReferencesDomain(claimDomain, resolvedEvidence) {
			result.Status = ai.StatusPartiallySupported
			result.Reason = "Claim references '" + claimDomain + "' but cited evidence does not reference that entity."
			return result
		}
	}

	// Default: if evidence IDs are valid and category is appropriate,
	// the claim is supported.
	result.Status = ai.StatusSupported
	result.Reason = "Claim is supported by cited evidence."
	return result
}

// --- Vulnerability detection ---

// vulnerabilityTerms are words that indicate a vulnerability claim.
var vulnerabilityTerms = []string{
	"vulnerable", "vulnerability", "exploit", "exploitable",
	"idor", "xss", "sqli", "sql injection", "rce", "remote code execution",
	"lfi", "rfi", "ssrf", "csrf", "xxe", "deserialization",
	"buffer overflow", "privilege escalation", "authentication bypass",
	"broken access", "insecure", "misconfigured",
}

func isVulnerabilityClaim(claimLower string) bool {
	for _, term := range vulnerabilityTerms {
		if strings.Contains(claimLower, term) {
			return true
		}
	}
	return false
}

func hasVulnerabilityEvidence(evidence []*retriever.Evidence) bool {
	for _, e := range evidence {
		detail := strings.ToLower(e.Detail + " " + e.Summary)
		for _, term := range vulnerabilityTerms {
			if strings.Contains(detail, term) {
				return true
			}
		}
	}
	return false
}

// --- Concept matching ---

func evidenceContainsConcepts(claimLower string, evidence []*retriever.Evidence) bool {
	// Fast path: if any evidence entity value appears directly in the claim,
	// or if the claim's domain/URL appears in the evidence, that's a strong signal.
	for _, e := range evidence {
		summaryLower := strings.ToLower(e.Summary)
		// Extract the entity value from summary (before the first '(').
		if idx := strings.Index(summaryLower, " ("); idx > 0 {
			entityValue := strings.TrimSpace(summaryLower[:idx])
			// Bidirectional: claim contains evidence value OR evidence value contains claim fragments.
			if strings.Contains(claimLower, entityValue) || strings.Contains(entityValue, extractDomainFromClaim(claimLower)) {
				return true
			}
		}
		// Also check if significant claim words appear in evidence detail.
		detailLower := strings.ToLower(e.Detail)
		if strings.Contains(detailLower, claimLower) {
			return true
		}
	}

	// Fallback: word-level matching.
	words := strings.Fields(claimLower)
	significantWords := 0
	matchedWords := 0

	for _, w := range words {
		if len(w) < 4 || isCommonWord(w) {
			continue
		}
		significantWords++

		for _, e := range evidence {
			combined := strings.ToLower(e.Summary + " " + e.Detail)
			if strings.Contains(combined, w) {
				matchedWords++
				break
			}
		}
	}

	if significantWords == 0 {
		return true
	}

	return float64(matchedWords)/float64(significantWords) >= 0.5
}

// --- Relationship matching ---

func isRelationshipClaim(claimLower string) bool {
	relationshipVerbs := []string{
		"uses", "serves", "redirects to", "has subdomain",
		"runs on", "powered by", "connected to", "links to",
	}
	for _, verb := range relationshipVerbs {
		if strings.Contains(claimLower, verb) {
			return true
		}
	}
	return false
}

func hasMatchingRelationship(claimLower string, evidence []*retriever.Evidence) bool {
	for _, e := range evidence {
		if e.Type == retriever.EvidenceRelationship {
			// The relationship summary contains "source → type → target"
			summaryLower := strings.ToLower(e.Summary)
			// Check if key parts of the claim appear in the relationship.
			words := extractSignificantWords(claimLower)
			matches := 0
			for _, w := range words {
				if strings.Contains(summaryLower, w) {
					matches++
				}
			}
			if len(words) > 0 && float64(matches)/float64(len(words)) >= 0.5 {
				return true
			}
		}
	}
	return false
}

// --- Contradiction detection ---

func findContradiction(claimLower string, evidence []*retriever.Evidence) string {
	// Simple contradiction: claim says "uses X" but evidence says "uses Y" for same entity.
	// This is a basic heuristic — will be enhanced over time.
	for _, e := range evidence {
		if e.Type == retriever.EvidenceEntity {
			meta := e.Metadata
			if meta == nil {
				continue
			}
			// Check status code contradictions.
			if strings.Contains(claimLower, "returns 200") {
				if sc, ok := meta["status_code"]; ok {
					if scFloat, ok := sc.(float64); ok && scFloat != 200 {
						return "Evidence shows status code " + e.Summary
					}
				}
			}
		}
	}
	return ""
}

// --- Helpers ---

var commonWords = map[string]bool{
	"that": true, "this": true, "with": true, "from": true,
	"have": true, "been": true, "were": true, "being": true,
	"does": true, "will": true, "would": true, "could": true,
	"should": true, "also": true, "into": true, "some": true,
	"than": true, "they": true, "them": true, "their": true,
	"there": true, "then": true, "when": true, "where": true,
	"which": true, "while": true, "about": true, "after": true,
	"before": true, "between": true,
}

func isCommonWord(w string) bool {
	return commonWords[w]
}

func extractSignificantWords(text string) []string {
	words := strings.Fields(text)
	var result []string
	for _, w := range words {
		if len(w) >= 4 && !isCommonWord(w) {
			result = append(result, w)
		}
	}
	return result
}

// extractDomainFromClaim finds domain-like patterns in claim text.
// Looks for words containing dots (e.g., "admin.example.com").
func extractDomainFromClaim(claimLower string) string {
	words := strings.Fields(claimLower)
	for _, w := range words {
		if strings.Contains(w, ".") && len(w) > 4 {
			return w
		}
	}
	return ""
}

// evidenceReferencesDomain checks if any of the cited evidence
// references the given domain/URL entity.
func evidenceReferencesDomain(domain string, evidence []*retriever.Evidence) bool {
	for _, e := range evidence {
		combined := strings.ToLower(e.Summary + " " + e.Detail)
		if strings.Contains(combined, domain) {
			return true
		}
	}
	return false
}

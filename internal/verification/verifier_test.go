package verification

import (
	"testing"

	"github.com/vKS-Rajput/doge/internal/retriever"
	"github.com/vKS-Rajput/doge/pkg/ai"
)

func makeBundle(evidence ...retriever.Evidence) *retriever.Bundle {
	return &retriever.Bundle{
		Evidence: evidence,
	}
}

func TestVerify_SupportedClaim(t *testing.T) {
	v := New()
	bundle := makeBundle(
		retriever.Evidence{
			Type:    retriever.EvidenceEntity,
			ID:      "e1234567-0000-0000-0000-000000000001",
			Summary: "https://admin.example.com (url, 2 observations)",
			Detail:  "Entity: https://admin.example.com (url)",
			Trust:   retriever.TrustDerived,
		},
	)

	response := &ai.Response{
		Answer: "admin.example.com exists",
		Claims: []ai.Claim{
			{
				Text:        "admin.example.com exists as a URL endpoint",
				EvidenceIDs: []string{"e1234567"},
				Confidence:  0.95,
				Category:    ai.ClaimObserved,
			},
		},
	}

	results := v.Verify(response, bundle)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != ai.StatusSupported {
		t.Errorf("expected supported, got %s: %s", results[0].Status, results[0].Reason)
	}
}

func TestVerify_UnsupportedVulnerabilityClaim(t *testing.T) {
	v := New()
	bundle := makeBundle(
		retriever.Evidence{
			Type:    retriever.EvidenceEntity,
			ID:      "e1234567-0000-0000-0000-000000000001",
			Summary: "https://admin.example.com (url, 2 observations)",
			Detail:  "Entity: https://admin.example.com (url)",
			Trust:   retriever.TrustDerived,
		},
	)

	response := &ai.Response{
		Answer: "The admin endpoint is vulnerable to IDOR",
		Claims: []ai.Claim{
			{
				Text:        "admin.example.com is vulnerable to IDOR",
				EvidenceIDs: []string{"e1234567"},
				Confidence:  0.8,
				Category:    ai.ClaimObserved,
			},
		},
	}

	results := v.Verify(response, bundle)
	if results[0].Status != ai.StatusUnsupported {
		t.Errorf("expected unsupported for vuln claim without vuln evidence, got %s: %s",
			results[0].Status, results[0].Reason)
	}
}

func TestVerify_HypotheticalClaim(t *testing.T) {
	v := New()
	bundle := makeBundle(
		retriever.Evidence{
			Type:    retriever.EvidenceEntity,
			ID:      "e1234567-0000-0000-0000-000000000001",
			Summary: "https://admin.example.com (url)",
			Detail:  "Entity: https://admin.example.com",
		},
	)

	response := &ai.Response{
		Answer: "The admin panel might lack auth",
		Claims: []ai.Claim{
			{
				Text:        "The admin panel might lack authentication",
				EvidenceIDs: []string{"e1234567"},
				Confidence:  0.3,
				Category:    ai.ClaimHypothetical,
			},
		},
	}

	results := v.Verify(response, bundle)
	if results[0].Status != ai.StatusPartiallySupported {
		t.Errorf("expected partially_supported for hypothetical, got %s", results[0].Status)
	}
}

func TestVerify_NoCitedEvidence(t *testing.T) {
	v := New()
	bundle := makeBundle()

	response := &ai.Response{
		Answer: "The target is secure",
		Claims: []ai.Claim{
			{
				Text:        "The target is secure",
				EvidenceIDs: []string{},
				Confidence:  0.9,
				Category:    ai.ClaimObserved,
			},
		},
	}

	results := v.Verify(response, bundle)
	if results[0].Status != ai.StatusUnverifiable {
		t.Errorf("expected unverifiable for no evidence, got %s", results[0].Status)
	}
}

func TestVerify_InvalidEvidenceID(t *testing.T) {
	v := New()
	bundle := makeBundle(
		retriever.Evidence{
			Type: retriever.EvidenceEntity,
			ID:   "e1234567-0000-0000-0000-000000000001",
		},
	)

	response := &ai.Response{
		Answer: "Something",
		Claims: []ai.Claim{
			{
				Text:        "Some claim",
				EvidenceIDs: []string{"nonexistent"},
				Confidence:  0.9,
				Category:    ai.ClaimObserved,
			},
		},
	}

	results := v.Verify(response, bundle)
	if results[0].Status != ai.StatusUnsupported {
		t.Errorf("expected unsupported for invalid evidence ID, got %s", results[0].Status)
	}
}

func TestVerify_RelationshipClaim(t *testing.T) {
	v := New()
	bundle := makeBundle(
		retriever.Evidence{
			Type:    retriever.EvidenceRelationship,
			ID:      "r1234567-0000-0000-0000-000000000002",
			Summary: "admin.example.com (subdomain) → uses_technology → nginx (technology)",
			Detail:  "Relationship: uses_technology",
			Trust:   retriever.TrustDerived,
		},
	)

	response := &ai.Response{
		Answer: "admin.example.com uses nginx",
		Claims: []ai.Claim{
			{
				Text:        "admin.example.com uses nginx as its web server",
				EvidenceIDs: []string{"r1234567"},
				Confidence:  0.95,
				Category:    ai.ClaimObserved,
			},
		},
	}

	results := v.Verify(response, bundle)
	if results[0].Status != ai.StatusSupported {
		t.Errorf("expected supported for relationship claim, got %s: %s",
			results[0].Status, results[0].Reason)
	}
}

func TestVerify_MultipleClaims(t *testing.T) {
	v := New()
	bundle := makeBundle(
		retriever.Evidence{
			Type:    retriever.EvidenceEntity,
			ID:      "e1234567-0000-0000-0000-000000000001",
			Summary: "https://admin.example.com (url)",
			Detail:  "Entity: https://admin.example.com",
		},
	)

	response := &ai.Response{
		Answer: "Found admin and it might be vulnerable",
		Claims: []ai.Claim{
			{
				Text:        "admin.example.com exists",
				EvidenceIDs: []string{"e1234567"},
				Confidence:  0.95,
				Category:    ai.ClaimObserved,
			},
			{
				Text:        "admin.example.com is vulnerable to XSS",
				EvidenceIDs: []string{"e1234567"},
				Confidence:  0.6,
				Category:    ai.ClaimObserved,
			},
		},
	}

	results := v.Verify(response, bundle)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Status != ai.StatusSupported {
		t.Errorf("claim 0: expected supported, got %s", results[0].Status)
	}
	if results[1].Status != ai.StatusUnsupported {
		t.Errorf("claim 1: expected unsupported (vuln claim), got %s: %s",
			results[1].Status, results[1].Reason)
	}
}

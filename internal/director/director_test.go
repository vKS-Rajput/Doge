package director

import (
	"testing"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func TestDirector_PolicyArbitration(t *testing.T) {
	d := NewDirector(0.60) // 60% exploit, 40% discover

	// First decision is discovery (bootstrapping unknown space)
	p1 := d.SelectPolicy()
	if p1 != PolicyDiscover {
		t.Fatalf("expected first policy to be PolicyDiscover, got %s", p1)
	}

	// Next decisions should balance out toward 60/40
	exploitCount := 0
	discoverCount := 1

	for i := 0; i < 9; i++ {
		p := d.SelectPolicy()
		if p == PolicyExploit {
			exploitCount++
		} else {
			discoverCount++
		}
	}

	t.Logf("10 selections: exploit=%d, discover=%d", exploitCount, discoverCount)
	if exploitCount == 0 {
		t.Fatal("expected at least one exploit selection")
	}

	// Test outcome recording
	d.RecordOutcome(PolicyDiscover, true, true)
	expStats, discStats, ratio := d.GetStats()

	if discStats.Novelties != 1 || discStats.FindingsFound != 1 {
		t.Fatalf("unexpected discovery stats: %+v", discStats)
	}
	_ = expStats
	_ = ratio
}

func TestDirector_ArbitrateNextQuestion(t *testing.T) {
	d := NewDirector(0.65)

	avail := map[domain.ResearcherType]bool{
		domain.ResearcherRecon:       true,
		domain.ResearcherValidation:  true,
		domain.ResearcherImpact:      true,
		domain.ResearcherRace:        true,
		domain.ResearcherMetamorphic: true,
	}

	// Scenario 1: Unvalidated Candidate present -> Highest value should be Validation
	ctx1 := ArbitrationContext{
		TargetBaseURL: "http://target.local",
		Candidates: []domain.CandidateVulnerability{
			{
				Title:    "BOLA on Order Management",
				Endpoint: "http://target.local/api/v1/orders/123",
				Severity: "high",
			},
		},
		AvailableResearchers: avail,
	}

	q1, brief1 := d.ArbitrateNextQuestion(ctx1)
	if q1.RecommendedResearcher != domain.ResearcherValidation {
		t.Fatalf("expected ResearcherValidation for candidate, got %s", q1.RecommendedResearcher)
	}
	if brief1 == nil {
		t.Fatal("expected non-nil brief")
	}
	t.Logf("✓ Candidate prioritized for validation: %s (Priority: %.2f)", q1.Question, q1.PriorityScore)

	// Scenario 2: Validated finding present -> Highest value should be Impact Demonstration
	ctx2 := ArbitrationContext{
		TargetBaseURL: "http://target.local",
		Validated: []domain.CandidateVulnerability{
			{
				Title:    "Validated BOLA on Orders",
				Endpoint: "http://target.local/api/v1/orders/123",
				Severity: "high",
			},
		},
		AvailableResearchers: avail,
	}

	q2, _ := d.ArbitrateNextQuestion(ctx2)
	if q2.RecommendedResearcher != domain.ResearcherImpact {
		t.Fatalf("expected ResearcherImpact for validated finding, got %s", q2.RecommendedResearcher)
	}
	t.Logf("✓ Validated finding prioritized for impact: %s (Priority: %.2f)", q2.Question, q2.PriorityScore)

	// Scenario 3: Batch endpoint present -> Highest value should be Metamorphic
	ctx3 := ArbitrationContext{
		TargetBaseURL: "http://target.local",
		Endpoints:     []string{"http://target.local/api/v1/batch"},
		AvailableResearchers: avail,
	}

	q3, _ := d.ArbitrateNextQuestion(ctx3)
	if q3.RecommendedResearcher != domain.ResearcherMetamorphic {
		t.Fatalf("expected ResearcherMetamorphic for batch endpoint, got %s", q3.RecommendedResearcher)
	}
	t.Logf("✓ Batch endpoint prioritized for metamorphic research: %s (Priority: %.2f)", q3.Question, q3.PriorityScore)
}


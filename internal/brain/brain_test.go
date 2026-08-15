package brain

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/novelty"
	"github.com/vKS-Rajput/doge/internal/opportunity"
	"github.com/vKS-Rajput/doge/internal/surface"
)

// --- Basic Prioritization ---

func TestBrainEmptyEvidence(t *testing.T) {
	b := New()
	recs := b.Prioritize(Evidence{})

	if len(recs) != 0 {
		t.Errorf("empty evidence should produce 0 recommendations, got %d", len(recs))
	}
}

func TestBrainSingleOpportunity(t *testing.T) {
	b := New()

	recs := b.Prioritize(Evidence{
		Opportunities: []opportunity.Opportunity{
			{
				ID:          uuid.New(),
				Title:       "Investigate /admin panel",
				Target:      "http://10.10.11.123/admin",
				SurfaceType: surface.CategoryAuthentication,
				Description: "Admin panel with login form",
				NoveltySignals: []novelty.Signal{
					{ID: uuid.New(), NoveltyScore: 0.8, Type: novelty.SignalNewAuthSurface},
				},
				CreatedAt: time.Now(),
			},
		},
		ObservationCount: 10,
		CorrelationCount: 3,
		ToolsUsed:        []string{"nmap", "httpx"},
	})

	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}

	rec := recs[0]
	if rec.Score <= 0 {
		t.Errorf("score should be positive, got %f", rec.Score)
	}
	if rec.Rank != 1 {
		t.Errorf("rank should be 1, got %d", rec.Rank)
	}
	if rec.Target != "http://10.10.11.123/admin" {
		t.Errorf("target = %q, want admin panel", rec.Target)
	}
	if rec.Status != StatusPending {
		t.Errorf("status = %q, want pending", rec.Status)
	}
	if len(rec.Reasons) == 0 {
		t.Error("should have reasons")
	}

	t.Logf("Score: %.3f, Reasons: %v", rec.Score, rec.Reasons)
}

// --- Ranking Order ---

func TestBrainRankingOrder(t *testing.T) {
	b := New()

	recs := b.Prioritize(Evidence{
		Opportunities: []opportunity.Opportunity{
			{
				ID:          uuid.New(),
				Title:       "SSH (boring)",
				Target:      "10.10.11.123:22",
				SurfaceType: surface.CategoryNetwork,
				NoveltySignals: []novelty.Signal{
					{ID: uuid.New(), NoveltyScore: 0.2},
				},
				CreatedAt: time.Now().Add(-2 * time.Hour),
			},
			{
				ID:          uuid.New(),
				Title:       "Upload endpoint (interesting)",
				Target:      "http://10.10.11.123/upload",
				SurfaceType: surface.CategoryUpload,
				NoveltySignals: []novelty.Signal{
					{ID: uuid.New(), NoveltyScore: 0.9, Type: novelty.SignalNewEndpoint},
				},
				CreatedAt: time.Now(),
			},
			{
				ID:          uuid.New(),
				Title:       "Login form (high-value)",
				Target:      "http://10.10.11.123/login",
				SurfaceType: surface.CategoryAuthentication,
				NoveltySignals: []novelty.Signal{
					{ID: uuid.New(), NoveltyScore: 0.85, Type: novelty.SignalNewAuthSurface},
				},
				CreatedAt: time.Now(),
			},
		},
		ToolsUsed: []string{"nmap", "httpx", "ffuf"},
	})

	if len(recs) != 3 {
		t.Fatalf("expected 3 recommendations, got %d", len(recs))
	}

	// Login (auth surface) and Upload should rank above SSH (network).
	sshRank := -1
	for _, r := range recs {
		if r.Target == "10.10.11.123:22" {
			sshRank = r.Rank
		}
	}

	if sshRank != 3 {
		t.Errorf("SSH should be ranked last (3), got %d", sshRank)
	}

	// Verify scores are descending.
	for i := 1; i < len(recs); i++ {
		if recs[i].Score > recs[i-1].Score {
			t.Errorf("scores should be descending: rec[%d]=%.3f > rec[%d]=%.3f",
				i, recs[i].Score, i-1, recs[i-1].Score)
		}
	}

	for _, r := range recs {
		t.Logf("  #%d %.3f %s (%s)", r.Rank, r.Score, r.Title, r.Target)
	}
}

// --- Investigated Penalty ---

func TestBrainInvestigatedPenalty(t *testing.T) {
	b := New()

	evidence := Evidence{
		Opportunities: []opportunity.Opportunity{
			{
				ID:          uuid.New(),
				Title:       "Endpoint A",
				Target:      "http://10.10.11.123/a",
				SurfaceType: surface.CategoryWeb,
				NoveltySignals: []novelty.Signal{
					{ID: uuid.New(), NoveltyScore: 0.7},
				},
				CreatedAt: time.Now(),
			},
			{
				ID:          uuid.New(),
				Title:       "Endpoint B",
				Target:      "http://10.10.11.123/b",
				SurfaceType: surface.CategoryWeb,
				NoveltySignals: []novelty.Signal{
					{ID: uuid.New(), NoveltyScore: 0.7},
				},
				CreatedAt: time.Now(),
			},
		},
		InvestigatedTargets: map[string]bool{
			"http://10.10.11.123/a": true,
		},
	}

	recs := b.Prioritize(evidence)

	if len(recs) != 2 {
		t.Fatalf("expected 2 recommendations, got %d", len(recs))
	}

	var scoreA, scoreB float64
	for _, r := range recs {
		if r.Target == "http://10.10.11.123/a" {
			scoreA = r.Score
		}
		if r.Target == "http://10.10.11.123/b" {
			scoreB = r.Score
		}
	}

	if scoreA >= scoreB {
		t.Errorf("investigated target A (%.3f) should score lower than uninvestigated B (%.3f)", scoreA, scoreB)
	}

	t.Logf("A (investigated): %.3f, B (fresh): %.3f", scoreA, scoreB)
}

// --- Mark Investigated ---

func TestBrainMarkInvestigated(t *testing.T) {
	b := New()

	opp := opportunity.Opportunity{
		ID:          uuid.New(),
		Title:       "Test target",
		Target:      "10.10.11.123:80",
		SurfaceType: surface.CategoryWeb,
		NoveltySignals: []novelty.Signal{
			{ID: uuid.New(), NoveltyScore: 0.8},
		},
		CreatedAt: time.Now(),
	}

	// First pass.
	recs1 := b.Prioritize(Evidence{Opportunities: []opportunity.Opportunity{opp}})
	score1 := recs1[0].Score

	// Mark as investigated.
	b.MarkInvestigated("10.10.11.123:80")

	// Second pass — should have lower score.
	recs2 := b.Prioritize(Evidence{Opportunities: []opportunity.Opportunity{opp}})
	score2 := recs2[0].Score

	if score2 >= score1 {
		t.Errorf("investigated target should score lower: before=%.3f after=%.3f", score1, score2)
	}

	t.Logf("Before: %.3f, After: %.3f", score1, score2)
}

// --- Dismissed Targets ---

func TestBrainDismissedTargets(t *testing.T) {
	b := New()

	recs := b.Prioritize(Evidence{
		Opportunities: []opportunity.Opportunity{
			{
				ID:          uuid.New(),
				Title:       "Dismissed target",
				Target:      "10.10.11.123:22",
				SurfaceType: surface.CategoryNetwork,
				NoveltySignals: []novelty.Signal{
					{ID: uuid.New(), NoveltyScore: 0.9},
				},
			},
			{
				ID:          uuid.New(),
				Title:       "Active target",
				Target:      "10.10.11.123:80",
				SurfaceType: surface.CategoryWeb,
				NoveltySignals: []novelty.Signal{
					{ID: uuid.New(), NoveltyScore: 0.5},
				},
			},
		},
		DismissedTargets: map[string]bool{
			"10.10.11.123:22": true,
		},
	})

	if len(recs) != 1 {
		t.Fatalf("dismissed target should be excluded, got %d recs", len(recs))
	}

	if recs[0].Target != "10.10.11.123:80" {
		t.Errorf("remaining rec should be the active target, got %s", recs[0].Target)
	}
}

// --- Contradiction Bonus ---

func TestBrainContradictionBonus(t *testing.T) {
	b := New()

	recs := b.Prioritize(Evidence{
		Opportunities: []opportunity.Opportunity{
			{
				ID:          uuid.New(),
				Title:       "Normal endpoint",
				Target:      "http://10.10.11.123/normal",
				SurfaceType: surface.CategoryWeb,
				NoveltySignals: []novelty.Signal{
					{ID: uuid.New(), NoveltyScore: 0.5},
				},
				CreatedAt: time.Now(),
			},
			{
				ID:          uuid.New(),
				Title:       "Contradicted endpoint",
				Target:      "http://10.10.11.123/weird",
				SurfaceType: surface.CategoryWeb,
				NoveltySignals: []novelty.Signal{
					{
						ID:           uuid.New(),
						NoveltyScore: 0.5,
						Category:     novelty.CategoryContradiction,
						Type:         novelty.SignalContradiction,
					},
				},
				CreatedAt: time.Now(),
			},
		},
		ContradictedTargets: map[string]bool{
			"http://10.10.11.123/weird": true,
		},
	})

	var normalScore, contradictedScore float64
	for _, r := range recs {
		if r.Target == "http://10.10.11.123/normal" {
			normalScore = r.Score
		}
		if r.Target == "http://10.10.11.123/weird" {
			contradictedScore = r.Score
		}
	}

	if contradictedScore <= normalScore {
		t.Errorf("contradicted target (%.3f) should score higher than normal (%.3f)",
			contradictedScore, normalScore)
	}

	t.Logf("Normal: %.3f, Contradicted: %.3f", normalScore, contradictedScore)
}

// --- Stale Recommendations ---

func TestBrainRepeatedRecommendationsDiminish(t *testing.T) {
	b := New()

	opp := opportunity.Opportunity{
		ID:          uuid.New(),
		Title:       "Persistent target",
		Target:      "10.10.11.123:8080",
		SurfaceType: surface.CategoryWeb,
		NoveltySignals: []novelty.Signal{
			{ID: uuid.New(), NoveltyScore: 0.7},
		},
		CreatedAt: time.Now(),
	}

	evidence := Evidence{Opportunities: []opportunity.Opportunity{opp}}

	// Recommend multiple times.
	var scores []float64
	for i := 0; i < 5; i++ {
		recs := b.Prioritize(evidence)
		if len(recs) > 0 {
			scores = append(scores, recs[0].Score)
		}
	}

	// After 3+ repetitions, the history penalty should kick in.
	if len(scores) >= 4 {
		if scores[3] >= scores[0] {
			t.Errorf("repeated recommendations should diminish: first=%.3f fourth=%.3f",
				scores[0], scores[3])
		}
	}

	for i, s := range scores {
		t.Logf("  Round %d: %.3f", i+1, s)
	}
}

// --- Orphan Signals ---

func TestBrainOrphanSignals(t *testing.T) {
	b := New()

	linkedSignal := novelty.Signal{
		ID:           uuid.New(),
		NoveltyScore: 0.8,
		Title:        "Linked signal",
		Description:  "This is linked to an opportunity",
		Type:         novelty.SignalNewPort,
	}

	orphanSignal := novelty.Signal{
		ID:           uuid.New(),
		NoveltyScore: 0.9,
		Title:        "Orphan signal",
		Description:  "This has no opportunity",
		Type:         novelty.SignalNewEndpoint,
	}

	recs := b.Prioritize(Evidence{
		Opportunities: []opportunity.Opportunity{
			{
				ID:             uuid.New(),
				Title:          "Linked opportunity",
				Target:         "10.10.11.123:80",
				SurfaceType:    surface.CategoryWeb,
				NoveltySignals: []novelty.Signal{linkedSignal},
				CreatedAt:      time.Now(),
			},
		},
		NoveltySignals: []novelty.Signal{linkedSignal, orphanSignal},
	})

	// Should have 2 recommendations: one from opportunity, one from orphan signal.
	if len(recs) != 2 {
		t.Fatalf("expected 2 recommendations (1 opportunity + 1 orphan), got %d", len(recs))
	}

	foundOrphan := false
	for _, r := range recs {
		if r.Title == "Orphan signal" {
			foundOrphan = true
		}
	}

	if !foundOrphan {
		t.Error("orphan signal should generate its own recommendation")
	}
}

// --- Surface Importance ---

func TestBrainSurfaceImportance(t *testing.T) {
	b := New()

	recs := b.Prioritize(Evidence{
		Opportunities: []opportunity.Opportunity{
			{
				ID:          uuid.New(),
				Title:       "Auth surface",
				Target:      "auth",
				SurfaceType: surface.CategoryAuthentication,
				NoveltySignals: []novelty.Signal{
					{ID: uuid.New(), NoveltyScore: 0.5},
				},
				CreatedAt: time.Now(),
			},
			{
				ID:          uuid.New(),
				Title:       "DNS surface",
				Target:      "dns",
				SurfaceType: surface.CategoryDNS,
				NoveltySignals: []novelty.Signal{
					{ID: uuid.New(), NoveltyScore: 0.5},
				},
				CreatedAt: time.Now(),
			},
		},
	})

	var authScore, dnsScore float64
	for _, r := range recs {
		if r.Target == "auth" {
			authScore = r.Score
		}
		if r.Target == "dns" {
			dnsScore = r.Score
		}
	}

	if authScore <= dnsScore {
		t.Errorf("auth surface (%.3f) should rank above DNS (%.3f)", authScore, dnsScore)
	}
}

// --- Multi-tool Evidence ---

func TestBrainMultiToolBoost(t *testing.T) {
	b := New()

	opp := opportunity.Opportunity{
		ID:          uuid.New(),
		Title:       "Multi-tool target",
		Target:      "target",
		SurfaceType: surface.CategoryWeb,
		NoveltySignals: []novelty.Signal{
			{ID: uuid.New(), NoveltyScore: 0.6},
		},
		CreatedAt: time.Now(),
	}

	// Single tool.
	recs1 := b.Prioritize(Evidence{
		Opportunities: []opportunity.Opportunity{opp},
		ToolsUsed:     []string{"nmap"},
	})

	// Reset history.
	b2 := New()

	// Multiple tools.
	recs2 := b2.Prioritize(Evidence{
		Opportunities: []opportunity.Opportunity{opp},
		ToolsUsed:     []string{"nmap", "httpx", "ffuf", "nuclei"},
	})

	if len(recs1) == 0 || len(recs2) == 0 {
		t.Fatal("should produce recommendations")
	}

	if recs2[0].Score <= recs1[0].Score {
		t.Errorf("multi-tool evidence (%.3f) should score higher than single-tool (%.3f)",
			recs2[0].Score, recs1[0].Score)
	}
}

// --- Score Breakdown ---

func TestBrainScoreBreakdown(t *testing.T) {
	b := New()

	recs := b.Prioritize(Evidence{
		Opportunities: []opportunity.Opportunity{
			{
				ID:          uuid.New(),
				Title:       "Test",
				Target:      "test",
				SurfaceType: surface.CategoryAuthentication,
				NoveltySignals: []novelty.Signal{
					{ID: uuid.New(), NoveltyScore: 0.9},
				},
				CreatedAt: time.Now(),
			},
		},
		ToolsUsed:        []string{"nmap", "httpx"},
		CorrelationCount: 5,
		ObservationCount: 10,
	})

	if len(recs) == 0 {
		t.Fatal("should produce recommendation")
	}

	bd := recs[0].ScoreBreakdown

	if bd.NoveltyScore != 0.9 {
		t.Errorf("novelty score = %.2f, want 0.9", bd.NoveltyScore)
	}
	if bd.SurfaceImportance != 1.0 {
		t.Errorf("auth surface importance = %.2f, want 1.0", bd.SurfaceImportance)
	}
	if bd.UnexploredBonus != 1.0 {
		t.Errorf("unexplored bonus = %.2f, want 1.0", bd.UnexploredBonus)
	}
	if bd.InvestigatedPenalty != 0 {
		t.Errorf("investigated penalty = %.2f, want 0", bd.InvestigatedPenalty)
	}

	t.Logf("Breakdown: %+v", bd)
	t.Logf("Total: %.3f", recs[0].Score)
}

// --- History Tracking ---

func TestBrainHistory(t *testing.T) {
	b := New()

	b.Prioritize(Evidence{
		Opportunities: []opportunity.Opportunity{
			{
				ID:          uuid.New(),
				Title:       "Target A",
				Target:      "a",
				SurfaceType: surface.CategoryWeb,
				NoveltySignals: []novelty.Signal{
					{ID: uuid.New(), NoveltyScore: 0.5},
				},
			},
		},
	})

	history := b.History()
	if _, ok := history["a"]; !ok {
		t.Fatal("target 'a' should be in history")
	}
	if history["a"].TimesRecommended != 1 {
		t.Errorf("times recommended = %d, want 1", history["a"].TimesRecommended)
	}

	b.MarkInvestigated("a")
	history = b.History()
	if history["a"].Status != StatusInvestigated {
		t.Errorf("status = %q, want investigated", history["a"].Status)
	}

	b.MarkDismissed("b")
	history = b.History()
	if history["b"].Status != StatusDismissed {
		t.Errorf("status = %q, want dismissed", history["b"].Status)
	}
}

// --- Works Without LLM ---

func TestBrainWorksWithoutLLM(t *testing.T) {
	// The Brain must produce useful recommendations using only
	// deterministic scoring, without any LLM call.
	b := New()

	recs := b.Prioritize(Evidence{
		Opportunities: []opportunity.Opportunity{
			{
				ID:          uuid.New(),
				Title:       "Debug endpoint on 8080",
				Target:      "http://10.10.11.123:8080/debug",
				SurfaceType: surface.CategoryExposure,
				Description: "Debug endpoint exposed on non-standard port",
				NoveltySignals: []novelty.Signal{
					{ID: uuid.New(), NoveltyScore: 0.85, Type: novelty.SignalNewEndpoint},
				},
				CreatedAt: time.Now(),
			},
			{
				ID:          uuid.New(),
				Title:       "Admin upload",
				Target:      "http://10.10.11.123/admin/upload",
				SurfaceType: surface.CategoryUpload,
				Description: "Upload endpoint behind admin panel",
				NoveltySignals: []novelty.Signal{
					{ID: uuid.New(), NoveltyScore: 0.90, Type: novelty.SignalNewEndpoint},
				},
				CreatedAt: time.Now(),
			},
			{
				ID:          uuid.New(),
				Title:       "Standard SSH",
				Target:      "10.10.11.123:22",
				SurfaceType: surface.CategoryNetwork,
				Description: "OpenSSH on standard port",
				NoveltySignals: []novelty.Signal{
					{ID: uuid.New(), NoveltyScore: 0.1},
				},
				CreatedAt: time.Now().Add(-3 * time.Hour),
			},
		},
		ToolsUsed:        []string{"nmap", "httpx", "ffuf"},
		ObservationCount: 50,
		CorrelationCount: 12,
	})

	if len(recs) != 3 {
		t.Fatalf("expected 3 recommendations, got %d", len(recs))
	}

	// Upload and debug should be top 2, SSH last.
	t.Log("Research priorities (no LLM):")
	for _, r := range recs {
		t.Logf("  #%d  Score: %.3f  %s", r.Rank, r.Score, r.Title)
		for _, reason := range r.Reasons {
			t.Logf("       - %s", reason)
		}
	}

	if recs[2].Target != "10.10.11.123:22" {
		t.Errorf("SSH should be ranked last, got rank %d", recs[2].Rank)
	}
	if recs[0].Score <= 0.3 {
		t.Errorf("top recommendation should have a meaningful score, got %.3f", recs[0].Score)
	}
}

// --- Partial Tool Coverage ---

func TestBrainWorksWithSubsetOfTools(t *testing.T) {
	b := New()

	// Only nmap and httpx available — no ffuf, katana, nuclei, etc.
	recs := b.Prioritize(Evidence{
		Opportunities: []opportunity.Opportunity{
			{
				ID:          uuid.New(),
				Title:       "Web server on 80",
				Target:      "http://10.10.11.123",
				SurfaceType: surface.CategoryWeb,
				NoveltySignals: []novelty.Signal{
					{ID: uuid.New(), NoveltyScore: 0.6},
				},
				CreatedAt: time.Now(),
			},
		},
		ToolsUsed:        []string{"nmap", "httpx"},
		ObservationCount: 5,
		CorrelationCount: 1,
	})

	if len(recs) == 0 {
		t.Fatal("should produce recommendations even with only 2 tools")
	}

	if recs[0].Score <= 0 {
		t.Errorf("should produce positive score even with limited tools, got %.3f", recs[0].Score)
	}

	t.Logf("With only nmap+httpx: #%d %.3f %s", recs[0].Rank, recs[0].Score, recs[0].Title)
}

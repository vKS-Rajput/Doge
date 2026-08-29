package learning

import (
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestMemoryStoreAndRetrievePattern(t *testing.T) {
	db := testDB(t)
	mem := NewMemory(db)
	if err := mem.EnsureTable(); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	pattern := &ResearchPattern{
		ID:          uuid.New(),
		Name:        "endpoint_with_object_id",
		Description: "Resource endpoint with numeric ID",
		Category:    PatternEndpoint,
		Confidence:  0.72,
		Occurrences: 7,
		EvidenceIDs: []uuid.UUID{uuid.New(), uuid.New()},
		FirstSeen:   now.Add(-24 * time.Hour),
		LastSeen:    now,
		DecayFactor: 1.0,
	}

	if err := mem.StorePattern(pattern); err != nil {
		t.Fatal(err)
	}

	got, err := mem.GetPattern("endpoint_with_object_id")
	if err != nil {
		t.Fatal(err)
	}

	if got.Name != pattern.Name {
		t.Errorf("Name = %q, want %q", got.Name, pattern.Name)
	}
	if got.Confidence != 0.72 {
		t.Errorf("Confidence = %f, want 0.72", got.Confidence)
	}
	if got.Occurrences != 7 {
		t.Errorf("Occurrences = %d, want 7", got.Occurrences)
	}
	if len(got.EvidenceIDs) != 2 {
		t.Errorf("EvidenceIDs = %d, want 2", len(got.EvidenceIDs))
	}
}

func TestLearnerEndpointPattern(t *testing.T) {
	db := testDB(t)
	mem := NewMemory(db)
	if err := mem.EnsureTable(); err != nil {
		t.Fatal(err)
	}

	learner := NewLearner(mem)

	// Feed observations with object-ID endpoints.
	observations := []domain.Observation{
		{
			ID:       uuid.New(),
			Type:     domain.ObservationEndpointDiscovery,
			Data:     map[string]any{"url": "/api/export?id=123"},
			SourceTool: "httpx",
		},
		{
			ID:       uuid.New(),
			Type:     domain.ObservationEndpointDiscovery,
			Data:     map[string]any{"url": "/api/report?id=456"},
			SourceTool: "katana",
		},
		{
			ID:       uuid.New(),
			Type:     domain.ObservationEndpointDiscovery,
			Data:     map[string]any{"url": "/api/download?file_id=789"},
			SourceTool: "katana",
		},
	}

	if err := learner.LearnFromObservations(observations); err != nil {
		t.Fatal(err)
	}

	// Pattern should be learned.
	pattern, err := mem.GetPattern("endpoint_with_object_id")
	if err != nil {
		t.Fatal("pattern not found:", err)
	}

	if pattern.Occurrences != 3 {
		t.Errorf("Occurrences = %d, want 3", pattern.Occurrences)
	}
	if pattern.Confidence <= 0.3 {
		t.Errorf("Confidence should be > 0.3 after 3 observations, got %f", pattern.Confidence)
	}
	if len(pattern.EvidenceIDs) != 3 {
		t.Errorf("EvidenceIDs = %d, want 3", len(pattern.EvidenceIDs))
	}
}

func TestScorerAdjustsPriority(t *testing.T) {
	db := testDB(t)
	mem := NewMemory(db)
	if err := mem.EnsureTable(); err != nil {
		t.Fatal(err)
	}

	// Store a high-confidence pattern.
	now := time.Now()
	pattern := &ResearchPattern{
		ID:            uuid.New(),
		Name:          "endpoint_with_object_id",
		Description:   "Object-ID authorization pattern",
		Category:      PatternEndpoint,
		Confidence:    0.8,
		Occurrences:   15,
		PriorityBoost: 0.12,
		FirstSeen:     now.Add(-48 * time.Hour),
		LastSeen:      now,
		DecayFactor:   1.0,
	}
	if err := mem.StorePattern(pattern); err != nil {
		t.Fatal(err)
	}

	scorer := NewScorer(mem)

	// Adjust priority for an endpoint target.
	explanation := scorer.AdjustPriority(0.5, "/api/export?id=123", nil)

	if explanation.FinalPriority <= explanation.BasePriority {
		t.Errorf("expected priority increase, base=%f final=%f",
			explanation.BasePriority, explanation.FinalPriority)
	}
	if len(explanation.Adjustments) == 0 {
		t.Error("expected at least one adjustment")
	}
}

func TestLearningReplayAcrossSessions(t *testing.T) {
	// This tests the learning replay requirement:
	// Investigation A produces pattern → Investigation B recognizes it.

	db := testDB(t)
	mem := NewMemory(db)
	if err := mem.EnsureTable(); err != nil {
		t.Fatal(err)
	}

	learner := NewLearner(mem)
	scorer := NewScorer(mem)

	// Investigation A: learn from evidence.
	obsA := []domain.Observation{
		{ID: uuid.New(), Type: domain.ObservationEndpointDiscovery,
			Data: map[string]any{"url": "/api/users?id=1"}, SourceTool: "httpx"},
		{ID: uuid.New(), Type: domain.ObservationEndpointDiscovery,
			Data: map[string]any{"url": "/api/orders?id=42"}, SourceTool: "httpx"},
	}
	learner.LearnFromObservations(obsA)

	// Check pattern exists.
	p1, err := mem.GetPattern("endpoint_with_object_id")
	if err != nil {
		t.Fatal("pattern should exist after investigation A")
	}
	confidenceAfterA := p1.Confidence

	// Investigation B: similar evidence, pattern should be recognized.
	obsB := []domain.Observation{
		{ID: uuid.New(), Type: domain.ObservationEndpointDiscovery,
			Data: map[string]any{"url": "/api/reports?id=99"}, SourceTool: "katana"},
	}
	learner.LearnFromObservations(obsB)

	p2, err := mem.GetPattern("endpoint_with_object_id")
	if err != nil {
		t.Fatal("pattern should still exist")
	}
	if p2.Confidence <= confidenceAfterA {
		t.Error("confidence should increase after pattern reconfirmation")
	}
	if p2.Occurrences != 3 {
		t.Errorf("Occurrences = %d, want 3", p2.Occurrences)
	}

	// Priority should now be higher for this kind of target.
	explainBefore := scorer.AdjustPriority(0.5, "/api/invoices?id=7", nil)
	if explainBefore.FinalPriority <= 0.5 {
		t.Error("learned pattern should boost priority")
	}

	// Verify the pattern survived (simulating restart).
	allPatterns, err := mem.AllPatterns()
	if err != nil {
		t.Fatal(err)
	}
	if len(allPatterns) == 0 {
		t.Error("patterns should persist")
	}
}

func TestNoisePatternReducesPriority(t *testing.T) {
	db := testDB(t)
	mem := NewMemory(db)
	if err := mem.EnsureTable(); err != nil {
		t.Fatal(err)
	}

	// Store a noise pattern.
	now := time.Now()
	noise := &ResearchPattern{
		ID:            uuid.New(),
		Name:          "common_technology_nginx",
		Description:   "Common nginx fingerprint — low value",
		Category:      PatternNoise,
		Confidence:    0.7,
		Occurrences:   20,
		PriorityBoost: 0.1,
		FirstSeen:     now.Add(-72 * time.Hour),
		LastSeen:      now,
		DecayFactor:   1.0,
	}
	if err := mem.StorePattern(noise); err != nil {
		t.Fatal(err)
	}

	scorer := NewScorer(mem)
	explanation := scorer.AdjustPriority(0.5, "/default-nginx", map[string]string{
		"technology": "nginx",
	})

	if explanation.FinalPriority >= explanation.BasePriority {
		t.Errorf("noise pattern should reduce priority, base=%f final=%f",
			explanation.BasePriority, explanation.FinalPriority)
	}
}

func TestContainsObjectID(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"/api/export?id=123", true},
		{"/api/users/42", true},
		{"/api/report?user_id=5", true},
		{"/login", false},
		{"/api/settings", false},
		{"/static/logo.png", false},
	}

	for _, tt := range tests {
		got := containsObjectID(tt.input)
		if got != tt.want {
			t.Errorf("containsObjectID(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

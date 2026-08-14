package opportunity

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/novelty"
	"github.com/vKS-Rajput/doge/internal/surface"
)

func TestEngineGenerateAll(t *testing.T) {
	engine := NewEngine(nil)
	engine.RegisterGenerator(NewUploadGenerator())
	engine.RegisterGenerator(NewAuthGenerator())
	engine.RegisterGenerator(NewAPIGenerator())
	engine.RegisterGenerator(NewContradictionGenerator())

	signals := []novelty.Signal{
		{
			ID:                uuid.New(),
			Type:              novelty.SignalNewUploadSurface,
			Title:             "New upload: /admin/upload",
			NoveltyScore:      0.85,
			EntityIDs:         []uuid.UUID{uuid.New()},
			SurfaceCategories: []surface.Category{surface.CategoryUpload},
		},
		{
			ID:                uuid.New(),
			Type:              novelty.SignalNewAuthSurface,
			Title:             "New auth: /login",
			NoveltyScore:      0.80,
			EntityIDs:         []uuid.UUID{uuid.New()},
			SurfaceCategories: []surface.Category{surface.CategoryAuthentication},
		},
	}

	opps := engine.GenerateAll(context.Background(), signals, uuid.New())

	if len(opps) != 2 {
		t.Fatalf("expected 2 opportunities, got %d", len(opps))
	}

	// Should be sorted by priority (upload has higher novelty → higher priority).
	if opps[0].SurfaceType != surface.CategoryUpload {
		t.Errorf("expected upload first (higher priority), got %s", opps[0].SurfaceType)
	}
}

func TestUploadGenerator(t *testing.T) {
	gen := NewUploadGenerator()

	signal := novelty.Signal{
		ID:                uuid.New(),
		Type:              novelty.SignalNewUploadSurface,
		Title:             "/admin/upload",
		NoveltyScore:      0.85,
		EntityIDs:         []uuid.UUID{uuid.New()},
		SurfaceCategories: []surface.Category{surface.CategoryUpload},
	}

	if !gen.CanGenerate(signal) {
		t.Error("expected CanGenerate=true for upload signal")
	}

	opps := gen.Generate(context.Background(), signal, uuid.New())
	if len(opps) != 1 {
		t.Fatalf("expected 1 opportunity, got %d", len(opps))
	}

	opp := opps[0]
	if opp.SurfaceType != surface.CategoryUpload {
		t.Errorf("expected upload surface, got %s", opp.SurfaceType)
	}
	if len(opp.Questions) != 4 {
		t.Errorf("expected 4 research questions, got %d", len(opp.Questions))
	}

	// Verify questions are specific and evidence-producing.
	for i, q := range opp.Questions {
		if q.Question == "" {
			t.Errorf("question %d is empty", i)
		}
		if q.Why == "" {
			t.Errorf("question %d has no Why", i)
		}
		if q.ExpectedEvidence == "" {
			t.Errorf("question %d has no ExpectedEvidence", i)
		}
		if q.Effort == "" {
			t.Errorf("question %d has no Effort", i)
		}
	}
}

func TestAuthGenerator(t *testing.T) {
	gen := NewAuthGenerator()

	signal := novelty.Signal{
		ID:                uuid.New(),
		Type:              novelty.SignalNewAuthSurface,
		Title:             "/login",
		NoveltyScore:      0.80,
		EntityIDs:         []uuid.UUID{uuid.New()},
		SurfaceCategories: []surface.Category{surface.CategoryAuthentication},
	}

	if !gen.CanGenerate(signal) {
		t.Error("expected CanGenerate=true")
	}

	opps := gen.Generate(context.Background(), signal, uuid.New())
	if len(opps) != 1 {
		t.Fatalf("expected 1 opportunity, got %d", len(opps))
	}
	if opps[0].SurfaceType != surface.CategoryAuthentication {
		t.Errorf("expected auth surface, got %s", opps[0].SurfaceType)
	}
	if len(opps[0].Questions) != 3 {
		t.Errorf("expected 3 questions, got %d", len(opps[0].Questions))
	}
}

func TestAPIGenerator(t *testing.T) {
	gen := NewAPIGenerator()

	signal := novelty.Signal{
		ID:                uuid.New(),
		Type:              novelty.SignalNewAPISurface,
		Title:             "/graphql",
		NoveltyScore:      0.75,
		EntityIDs:         []uuid.UUID{uuid.New()},
		SurfaceCategories: []surface.Category{surface.CategoryAPI},
	}

	if !gen.CanGenerate(signal) {
		t.Error("expected CanGenerate=true")
	}

	opps := gen.Generate(context.Background(), signal, uuid.New())
	if len(opps) != 1 {
		t.Fatal("expected 1 opportunity")
	}
	if opps[0].SurfaceType != surface.CategoryAPI {
		t.Errorf("expected API surface, got %s", opps[0].SurfaceType)
	}
}

func TestContradictionGenerator(t *testing.T) {
	gen := NewContradictionGenerator()

	signal := novelty.Signal{
		ID:           uuid.New(),
		Type:         novelty.SignalContradiction,
		Title:        "Cross-tool contradiction on admin.example.com",
		NoveltyScore: 0.75,
		EntityIDs:    []uuid.UUID{uuid.New()},
	}

	if !gen.CanGenerate(signal) {
		t.Error("expected CanGenerate=true")
	}

	opps := gen.Generate(context.Background(), signal, uuid.New())
	if len(opps) != 1 {
		t.Fatal("expected 1 opportunity")
	}
	if opps[0].Priority != PriorityMedium {
		t.Errorf("expected medium priority, got %s", opps[0].Priority)
	}
}

func TestCombinationTriggersMultipleGenerators(t *testing.T) {
	engine := NewEngine(nil)
	engine.RegisterGenerator(NewUploadGenerator())
	engine.RegisterGenerator(NewAuthGenerator())

	// A combination signal with upload + auth.
	signal := novelty.Signal{
		ID:                uuid.New(),
		Type:              novelty.SignalNovelCombination,
		Title:             "admin.example.com: upload + authentication",
		NoveltyScore:      0.90,
		EntityIDs:         []uuid.UUID{uuid.New()},
		SurfaceCategories: []surface.Category{surface.CategoryUpload, surface.CategoryAuthentication},
	}

	opps := engine.GenerateAll(context.Background(), []novelty.Signal{signal}, uuid.New())

	// Both generators should fire for a combination signal.
	if len(opps) != 2 {
		t.Fatalf("expected 2 opportunities (upload + auth), got %d", len(opps))
	}
}

func TestGeneratorsRejectUnmatchedSignals(t *testing.T) {
	generators := []Generator{
		NewUploadGenerator(),
		NewAuthGenerator(),
		NewAPIGenerator(),
		NewContradictionGenerator(),
	}

	// A subdomain signal should not match any surface-specific generator.
	signal := novelty.Signal{
		ID:                uuid.New(),
		Type:              novelty.SignalNewSubdomain,
		Title:             "new.example.com",
		SurfaceCategories: []surface.Category{surface.CategoryWeb},
	}

	for _, gen := range generators {
		if gen.CanGenerate(signal) {
			t.Errorf("generator %s should NOT handle subdomain signal", gen.Name())
		}
	}
}

func TestPrioritySorting(t *testing.T) {
	engine := NewEngine(nil)
	engine.RegisterGenerator(NewUploadGenerator())
	engine.RegisterGenerator(NewAPIGenerator())

	signals := []novelty.Signal{
		{
			ID:                uuid.New(),
			Type:              novelty.SignalNewAPISurface,
			Title:             "/api",
			NoveltyScore:      0.50, // Low → Low priority.
			EntityIDs:         []uuid.UUID{uuid.New()},
			SurfaceCategories: []surface.Category{surface.CategoryAPI},
		},
		{
			ID:                uuid.New(),
			Type:              novelty.SignalNewUploadSurface,
			Title:             "/upload",
			NoveltyScore:      0.90, // High → High priority.
			EntityIDs:         []uuid.UUID{uuid.New()},
			SurfaceCategories: []surface.Category{surface.CategoryUpload},
		},
	}

	opps := engine.GenerateAll(context.Background(), signals, uuid.New())

	if len(opps) < 2 {
		t.Fatal("expected 2 opportunities")
	}
	if opps[0].Priority != PriorityHigh {
		t.Errorf("expected high priority first, got %s", opps[0].Priority)
	}
}

func TestOpportunityHasProvenance(t *testing.T) {
	gen := NewUploadGenerator()
	signalID := uuid.New()

	signal := novelty.Signal{
		ID:                signalID,
		Type:              novelty.SignalNewUploadSurface,
		Title:             "/upload",
		NoveltyScore:      0.85,
		EntityIDs:         []uuid.UUID{uuid.New()},
		SurfaceCategories: []surface.Category{surface.CategoryUpload},
	}

	opps := gen.Generate(context.Background(), signal, uuid.New())
	if len(opps) != 1 {
		t.Fatal("expected 1 opportunity")
	}

	opp := opps[0]
	// Must link back to novelty signal.
	if len(opp.NoveltySignals) != 1 {
		t.Error("opportunity must have novelty signal provenance")
	}
	if opp.NoveltySignals[0].ID != signalID {
		t.Error("opportunity must reference the originating signal")
	}
	// Must have entity IDs.
	if len(opp.EntityIDs) == 0 {
		t.Error("opportunity must have entity IDs")
	}
}

func TestEmptySignalsProduceNoOpportunities(t *testing.T) {
	engine := NewEngine(nil)
	engine.RegisterGenerator(NewUploadGenerator())

	opps := engine.GenerateAll(context.Background(), nil, uuid.New())
	if len(opps) != 0 {
		t.Errorf("expected 0 opportunities, got %d", len(opps))
	}
}

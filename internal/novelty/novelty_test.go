package novelty

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/surface"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// --- Mock store ---

type mockReadStore struct {
	entities     map[domain.EntityType][]domain.Entity
	observations map[uuid.UUID][]domain.Observation
	rels         map[uuid.UUID][]domain.Relationship
}

func newMock() *mockReadStore {
	return &mockReadStore{
		entities:     make(map[domain.EntityType][]domain.Entity),
		observations: make(map[uuid.UUID][]domain.Observation),
		rels:         make(map[uuid.UUID][]domain.Relationship),
	}
}

func (m *mockReadStore) EntitiesByType(_ context.Context, t domain.EntityType, _ uuid.UUID) ([]domain.Entity, error) {
	return m.entities[t], nil
}
func (m *mockReadStore) ObservationsForEntity(_ context.Context, id uuid.UUID) ([]domain.Observation, error) {
	return m.observations[id], nil
}
func (m *mockReadStore) RelationshipsForEntity(_ context.Context, id uuid.UUID, _ domain.Direction) ([]domain.Relationship, error) {
	return m.rels[id], nil
}
func (m *mockReadStore) EntityByTypeAndValue(_ context.Context, t domain.EntityType, v string, _ uuid.UUID) (*domain.Entity, error) {
	for _, e := range m.entities[t] {
		if e.Value == v {
			return &e, nil
		}
	}
	return nil, nil
}

// --- Engine tests ---

func TestEngineDetectAll(t *testing.T) {
	engine := NewEngine(nil)
	engine.RegisterDetector(NewStructuralDetector())
	engine.RegisterDetector(NewContradictionDetector())
	engine.RegisterDetector(NewCombinationDetector())

	if len(engine.DetectorNames()) != 3 {
		t.Errorf("expected 3 detectors, got %d", len(engine.DetectorNames()))
	}

	// Build a simple graph with an upload endpoint.
	graph := &surface.Graph{
		Nodes: map[uuid.UUID]surface.Node{
			uuid.New(): {
				Entity:   domain.Entity{Type: domain.EntityEndpoint, Value: "/admin/upload"},
				Category: surface.CategoryUpload,
			},
		},
		Edges: nil,
	}

	signals, err := engine.DetectAll(context.Background(), DetectorInput{
		Store:     newMock(),
		Graph:     graph,
		ProjectID: uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(signals) == 0 {
		t.Error("expected at least 1 signal")
	}
}

func TestSignalsSortedByNoveltyScore(t *testing.T) {
	engine := NewEngine(nil)
	engine.RegisterDetector(NewStructuralDetector())

	// Two nodes with different novelty levels.
	uploadID := uuid.New()
	subdomainID := uuid.New()

	graph := &surface.Graph{
		Nodes: map[uuid.UUID]surface.Node{
			uploadID: {
				Entity:   domain.Entity{ID: uploadID, Type: domain.EntityEndpoint, Value: "/upload"},
				Category: surface.CategoryUpload,
			},
			subdomainID: {
				Entity:   domain.Entity{ID: subdomainID, Type: domain.EntitySubdomain, Value: "test.example.com"},
				Category: surface.CategoryWeb,
			},
		},
	}

	signals, _ := engine.DetectAll(context.Background(), DetectorInput{
		Store:     newMock(),
		Graph:     graph,
		ProjectID: uuid.New(),
	})

	if len(signals) < 2 {
		t.Fatalf("expected 2 signals, got %d", len(signals))
	}

	// Upload should have higher novelty than subdomain.
	if signals[0].NoveltyScore <= signals[1].NoveltyScore {
		t.Errorf("expected signals sorted by score desc, got %.2f, %.2f",
			signals[0].NoveltyScore, signals[1].NoveltyScore)
	}
}

// --- Structural detector tests ---

func TestStructuralDetectorNewSurfaces(t *testing.T) {
	d := NewStructuralDetector()

	tests := []struct {
		name     string
		entity   domain.Entity
		category surface.Category
		wantType SignalType
	}{
		{"upload", domain.Entity{Type: domain.EntityEndpoint, Value: "/upload"}, surface.CategoryUpload, SignalNewUploadSurface},
		{"auth", domain.Entity{Type: domain.EntityEndpoint, Value: "/login"}, surface.CategoryAuthentication, SignalNewAuthSurface},
		{"api", domain.Entity{Type: domain.EntityEndpoint, Value: "/api/v1"}, surface.CategoryAPI, SignalNewAPISurface},
		{"subdomain", domain.Entity{Type: domain.EntitySubdomain, Value: "new.example.com"}, surface.CategoryWeb, SignalNewSubdomain},
		{"port", domain.Entity{Type: domain.EntityPort, Value: "8080"}, surface.CategoryNetwork, SignalNewPort},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := uuid.New()
			tt.entity.ID = id

			graph := &surface.Graph{
				Nodes: map[uuid.UUID]surface.Node{
					id: {Entity: tt.entity, Category: tt.category},
				},
			}

			signals, err := d.Detect(context.Background(), DetectorInput{
				Store:     newMock(),
				Graph:     graph,
				ProjectID: uuid.New(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(signals) != 1 {
				t.Fatalf("expected 1 signal, got %d", len(signals))
			}
			if signals[0].Type != tt.wantType {
				t.Errorf("expected %s, got %s", tt.wantType, signals[0].Type)
			}
			if signals[0].Category != CategoryStructural {
				t.Errorf("expected structural category, got %s", signals[0].Category)
			}
		})
	}
}

func TestStructuralDetectorRemovedSurface(t *testing.T) {
	d := NewStructuralDetector()

	removedID := uuid.New()
	prev := &surface.Graph{
		Nodes: map[uuid.UUID]surface.Node{
			removedID: {
				Entity:   domain.Entity{ID: removedID, Value: "/old-endpoint"},
				Category: surface.CategoryWeb,
			},
		},
	}
	current := &surface.Graph{
		Nodes: map[uuid.UUID]surface.Node{},
	}

	signals, err := d.Detect(context.Background(), DetectorInput{
		Store:         newMock(),
		Graph:         current,
		PreviousGraph: prev,
		ProjectID:     uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, s := range signals {
		if s.Type == SignalSurfaceRemoved {
			found = true
		}
	}
	if !found {
		t.Error("expected surface_removed signal")
	}
}

func TestStructuralDetectorCorrelationBoost(t *testing.T) {
	d := NewStructuralDetector()
	id := uuid.New()

	// Without correlation.
	graph1 := &surface.Graph{
		Nodes: map[uuid.UUID]surface.Node{
			id: {
				Entity:     domain.Entity{ID: id, Type: domain.EntityEndpoint, Value: "/upload"},
				Category:   surface.CategoryUpload,
				Correlated: false,
			},
		},
	}
	s1, _ := d.Detect(context.Background(), DetectorInput{Store: newMock(), Graph: graph1, ProjectID: uuid.New()})

	// With correlation.
	id2 := uuid.New()
	graph2 := &surface.Graph{
		Nodes: map[uuid.UUID]surface.Node{
			id2: {
				Entity:     domain.Entity{ID: id2, Type: domain.EntityEndpoint, Value: "/upload2"},
				Category:   surface.CategoryUpload,
				Correlated: true,
			},
		},
	}
	s2, _ := d.Detect(context.Background(), DetectorInput{Store: newMock(), Graph: graph2, ProjectID: uuid.New()})

	if len(s1) != 1 || len(s2) != 1 {
		t.Fatal("expected 1 signal each")
	}
	if s2[0].NoveltyScore <= s1[0].NoveltyScore {
		t.Errorf("correlated signal (%.2f) should have higher score than uncorrelated (%.2f)",
			s2[0].NoveltyScore, s1[0].NoveltyScore)
	}
}

// --- Contradiction detector tests ---

func TestContradictionDetector(t *testing.T) {
	d := NewContradictionDetector()
	store := newMock()

	nodeID := uuid.New()
	graph := &surface.Graph{
		Nodes: map[uuid.UUID]surface.Node{
			nodeID: {
				Entity:           domain.Entity{ID: nodeID, Value: "admin.example.com"},
				Category:         surface.CategoryWeb,
				ObservationCount: 2,
			},
		},
	}

	// Two tools report different products.
	store.observations[nodeID] = []domain.Observation{
		{ID: uuid.New(), SourceTool: "nmap", Data: map[string]any{"product": "nginx"}},
		{ID: uuid.New(), SourceTool: "httpx", Data: map[string]any{"product": "Apache"}},
	}

	signals, err := d.Detect(context.Background(), DetectorInput{
		Store:     store,
		Graph:     graph,
		ProjectID: uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 1 {
		t.Fatalf("expected 1 contradiction, got %d", len(signals))
	}
	if signals[0].Type != SignalContradiction {
		t.Errorf("expected cross_tool_contradiction, got %s", signals[0].Type)
	}
	if signals[0].Category != CategoryContradiction {
		t.Errorf("expected contradiction category, got %s", signals[0].Category)
	}
}

func TestContradictionDetectorNoConflict(t *testing.T) {
	d := NewContradictionDetector()
	store := newMock()

	nodeID := uuid.New()
	graph := &surface.Graph{
		Nodes: map[uuid.UUID]surface.Node{
			nodeID: {
				Entity:           domain.Entity{ID: nodeID, Value: "api.example.com"},
				Category:         surface.CategoryWeb,
				ObservationCount: 2,
			},
		},
	}

	// Same product from different tools — no contradiction.
	store.observations[nodeID] = []domain.Observation{
		{ID: uuid.New(), SourceTool: "nmap", Data: map[string]any{"product": "nginx"}},
		{ID: uuid.New(), SourceTool: "httpx", Data: map[string]any{"product": "nginx"}},
	}

	signals, _ := d.Detect(context.Background(), DetectorInput{
		Store:     store,
		Graph:     graph,
		ProjectID: uuid.New(),
	})
	if len(signals) != 0 {
		t.Errorf("expected 0 contradictions (same product), got %d", len(signals))
	}
}

// --- Combination detector tests ---

func TestCombinationDetector(t *testing.T) {
	d := NewCombinationDetector()

	hostID := uuid.New()
	uploadID := uuid.New()
	authID := uuid.New()

	graph := &surface.Graph{
		Nodes: map[uuid.UUID]surface.Node{
			hostID: {
				Entity:   domain.Entity{ID: hostID, Type: domain.EntitySubdomain, Value: "admin.example.com"},
				Category: surface.CategoryWeb,
			},
			uploadID: {
				Entity:   domain.Entity{ID: uploadID, Type: domain.EntityEndpoint, Value: "/upload"},
				Category: surface.CategoryUpload,
			},
			authID: {
				Entity:   domain.Entity{ID: authID, Type: domain.EntityEndpoint, Value: "/admin/dashboard"},
				Category: surface.CategoryAuthorization,
			},
		},
		Edges: []surface.Edge{
			{SourceNode: hostID, TargetNode: uploadID},
			{SourceNode: hostID, TargetNode: authID},
		},
	}

	signals, err := d.Detect(context.Background(), DetectorInput{
		Store:     newMock(),
		Graph:     graph,
		ProjectID: uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 1 {
		t.Fatalf("expected 1 combination signal, got %d", len(signals))
	}
	if signals[0].Type != SignalNovelCombination {
		t.Errorf("expected novel_surface_combination, got %s", signals[0].Type)
	}
	// Upload + authorization = high score.
	if signals[0].NoveltyScore < 0.85 {
		t.Errorf("expected high score for upload+authz combo, got %.2f", signals[0].NoveltyScore)
	}
}

func TestCombinationDetectorSingleSurface(t *testing.T) {
	d := NewCombinationDetector()

	hostID := uuid.New()
	uploadID := uuid.New()

	graph := &surface.Graph{
		Nodes: map[uuid.UUID]surface.Node{
			hostID: {
				Entity:   domain.Entity{ID: hostID, Type: domain.EntitySubdomain, Value: "api.example.com"},
				Category: surface.CategoryWeb,
			},
			uploadID: {
				Entity:   domain.Entity{ID: uploadID, Type: domain.EntityEndpoint, Value: "/upload"},
				Category: surface.CategoryUpload,
			},
		},
		Edges: []surface.Edge{
			{SourceNode: hostID, TargetNode: uploadID},
		},
	}

	signals, _ := d.Detect(context.Background(), DetectorInput{
		Store:     newMock(),
		Graph:     graph,
		ProjectID: uuid.New(),
	})
	if len(signals) != 0 {
		t.Errorf("expected 0 combinations (single surface type), got %d", len(signals))
	}
}

func TestNoveltyScoreIsNotVulnerabilityProbability(t *testing.T) {
	// Invariant test: novelty score measures surprise, not vulnerability.
	engine := NewEngine(nil)
	engine.RegisterDetector(NewStructuralDetector())

	id := uuid.New()
	graph := &surface.Graph{
		Nodes: map[uuid.UUID]surface.Node{
			id: {
				Entity:   domain.Entity{ID: id, Type: domain.EntityEndpoint, Value: "/admin/upload"},
				Category: surface.CategoryUpload,
			},
		},
	}

	signals, _ := engine.DetectAll(context.Background(), DetectorInput{
		Store:     newMock(),
		Graph:     graph,
		ProjectID: uuid.New(),
	})

	for _, s := range signals {
		if s.NoveltyScore < 0.0 || s.NoveltyScore > 1.0 {
			t.Errorf("novelty score must be [0, 1], got %.2f", s.NoveltyScore)
		}
		// The score is how surprising this is, not how vulnerable.
	}
}

func TestEmptyGraphProducesNoSignals(t *testing.T) {
	engine := NewEngine(nil)
	engine.RegisterDetector(NewStructuralDetector())
	engine.RegisterDetector(NewContradictionDetector())
	engine.RegisterDetector(NewCombinationDetector())

	graph := &surface.Graph{Nodes: map[uuid.UUID]surface.Node{}}

	signals, err := engine.DetectAll(context.Background(), DetectorInput{
		Store:     newMock(),
		Graph:     graph,
		ProjectID: uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 0 {
		t.Errorf("expected 0 signals for empty graph, got %d", len(signals))
	}
}

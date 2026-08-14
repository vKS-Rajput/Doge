package surface

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// --- Mock store (reuses correlation.ReadStore interface) ---

type mockReadStore struct {
	entities      map[domain.EntityType][]domain.Entity
	observations  map[uuid.UUID][]domain.Observation
	relationships map[uuid.UUID][]domain.Relationship
}

func newMockStore() *mockReadStore {
	return &mockReadStore{
		entities:      make(map[domain.EntityType][]domain.Entity),
		observations:  make(map[uuid.UUID][]domain.Observation),
		relationships: make(map[uuid.UUID][]domain.Relationship),
	}
}

func (m *mockReadStore) EntitiesByType(_ context.Context, t domain.EntityType, _ uuid.UUID) ([]domain.Entity, error) {
	return m.entities[t], nil
}

func (m *mockReadStore) ObservationsForEntity(_ context.Context, entityID uuid.UUID) ([]domain.Observation, error) {
	return m.observations[entityID], nil
}

func (m *mockReadStore) RelationshipsForEntity(_ context.Context, entityID uuid.UUID, _ domain.Direction) ([]domain.Relationship, error) {
	return m.relationships[entityID], nil
}

func (m *mockReadStore) EntityByTypeAndValue(_ context.Context, t domain.EntityType, value string, _ uuid.UUID) (*domain.Entity, error) {
	for _, e := range m.entities[t] {
		if e.Value == value {
			return &e, nil
		}
	}
	return nil, nil
}

// --- Classification tests ---

func TestClassifyEntity(t *testing.T) {
	tests := []struct {
		entity   domain.Entity
		expected Category
	}{
		{domain.Entity{Type: domain.EntityIPAddress, Value: "10.0.0.1"}, CategoryNetwork},
		{domain.Entity{Type: domain.EntityPort, Value: "443"}, CategoryNetwork},
		{domain.Entity{Type: domain.EntityDomain, Value: "example.com"}, CategoryWeb},
		{domain.Entity{Type: domain.EntitySubdomain, Value: "admin.example.com"}, CategoryWeb},
		{domain.Entity{Type: domain.EntityURL, Value: "https://example.com"}, CategoryWeb},
		{domain.Entity{Type: domain.EntityTechnology, Value: "nginx"}, CategoryTechnology},
		{domain.Entity{Type: domain.EntityService, Value: "https"}, CategoryInfrastructure},
		{domain.Entity{Type: domain.EntityDNSRecord, Value: "A"}, CategoryDNS},
		{domain.Entity{Type: domain.EntityGraphQLOp, Value: "mutation createUser"}, CategoryAPI},
		{domain.Entity{Type: domain.EntityAuthMechanism, Value: "OAuth2"}, CategoryAuthentication},
		{domain.Entity{Type: domain.EntitySecret, Value: "api_key_xxx"}, CategoryAuthentication},
	}

	for _, tt := range tests {
		t.Run(string(tt.entity.Type), func(t *testing.T) {
			got := ClassifyEntity(tt.entity)
			if got != tt.expected {
				t.Errorf("ClassifyEntity(%s/%s) = %s, want %s", tt.entity.Type, tt.entity.Value, got, tt.expected)
			}
		})
	}
}

func TestClassifyEndpointSurfaces(t *testing.T) {
	tests := []struct {
		value    string
		expected Category
	}{
		{"/admin/upload", CategoryUpload},
		{"/api/v1/users", CategoryAPI},
		{"/login", CategoryAuthentication},
		{"/admin/dashboard", CategoryAuthorization},
		{"/static/app.js", CategoryWeb},
		{"/graphql", CategoryAPI},
		{"/auth/oauth/callback", CategoryAuthentication},
		{"/debug/pprof", CategoryAuthorization},
		{"/import/csv", CategoryUpload},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			e := domain.Entity{Type: domain.EntityEndpoint, Value: tt.value}
			got := ClassifyEntity(e)
			if got != tt.expected {
				t.Errorf("ClassifyEntity(endpoint %s) = %s, want %s", tt.value, got, tt.expected)
			}
		})
	}
}

// --- Graph building tests ---

func TestBuildGraph(t *testing.T) {
	store := newMockStore()
	projectID := uuid.New()

	subID := uuid.New()
	ipID := uuid.New()
	portID := uuid.New()

	store.entities[domain.EntitySubdomain] = []domain.Entity{
		{ID: subID, Type: domain.EntitySubdomain, Value: "admin.example.com"},
	}
	store.entities[domain.EntityIPAddress] = []domain.Entity{
		{ID: ipID, Type: domain.EntityIPAddress, Value: "203.0.113.10"},
	}
	store.entities[domain.EntityPort] = []domain.Entity{
		{ID: portID, Type: domain.EntityPort, Value: "443"},
	}

	// Relationships.
	store.relationships[subID] = []domain.Relationship{
		{SourceEntityID: subID, TargetEntityID: ipID, Type: domain.RelResolvesTo},
	}
	store.relationships[ipID] = []domain.Relationship{
		{SourceEntityID: ipID, TargetEntityID: portID, Type: domain.RelListensOn},
	}

	// Observations.
	store.observations[subID] = []domain.Observation{
		{ID: uuid.New(), SourceTool: "subfinder"},
		{ID: uuid.New(), SourceTool: "httpx"},
	}
	store.observations[ipID] = []domain.Observation{
		{ID: uuid.New(), SourceTool: "dnsx"},
	}

	analyzer := NewAnalyzer(store, nil)
	graph, err := analyzer.BuildGraph(context.Background(), projectID)
	if err != nil {
		t.Fatal(err)
	}

	if graph.Stats.TotalNodes != 3 {
		t.Errorf("expected 3 nodes, got %d", graph.Stats.TotalNodes)
	}
	if graph.Stats.TotalEdges != 2 {
		t.Errorf("expected 2 edges, got %d", graph.Stats.TotalEdges)
	}

	// admin.example.com should be categorized as web.
	subNode := graph.Nodes[subID]
	if subNode.Category != CategoryWeb {
		t.Errorf("expected web, got %s", subNode.Category)
	}
	if subNode.ObservationCount != 2 {
		t.Errorf("expected 2 observations, got %d", subNode.ObservationCount)
	}
	if !subNode.Correlated {
		t.Error("expected correlated (2 tools)")
	}

	// IP should be network.
	ipNode := graph.Nodes[ipID]
	if ipNode.Category != CategoryNetwork {
		t.Errorf("expected network, got %s", ipNode.Category)
	}
}

func TestBuildGraphStats(t *testing.T) {
	store := newMockStore()

	store.entities[domain.EntitySubdomain] = []domain.Entity{
		{ID: uuid.New(), Type: domain.EntitySubdomain, Value: "a.example.com"},
		{ID: uuid.New(), Type: domain.EntitySubdomain, Value: "b.example.com"},
	}
	store.entities[domain.EntityIPAddress] = []domain.Entity{
		{ID: uuid.New(), Type: domain.EntityIPAddress, Value: "10.0.0.1"},
	}

	analyzer := NewAnalyzer(store, nil)
	graph, err := analyzer.BuildGraph(context.Background(), uuid.New())
	if err != nil {
		t.Fatal(err)
	}

	if graph.Stats.NodesByCategory[CategoryWeb] != 2 {
		t.Errorf("expected 2 web nodes, got %d", graph.Stats.NodesByCategory[CategoryWeb])
	}
	if graph.Stats.NodesByCategory[CategoryNetwork] != 1 {
		t.Errorf("expected 1 network node, got %d", graph.Stats.NodesByCategory[CategoryNetwork])
	}
}

// --- Research path tests ---

func TestFindResearchPaths(t *testing.T) {
	store := newMockStore()
	projectID := uuid.New()

	domainID := uuid.New()
	subID := uuid.New()
	endpointID := uuid.New()

	store.entities[domain.EntityDomain] = []domain.Entity{
		{ID: domainID, Type: domain.EntityDomain, Value: "example.com"},
	}
	store.entities[domain.EntitySubdomain] = []domain.Entity{
		{ID: subID, Type: domain.EntitySubdomain, Value: "admin.example.com"},
	}
	store.entities[domain.EntityEndpoint] = []domain.Entity{
		{ID: endpointID, Type: domain.EntityEndpoint, Value: "/admin/upload"},
	}

	// Chain: example.com → admin.example.com → /admin/upload
	store.relationships[domainID] = []domain.Relationship{
		{SourceEntityID: domainID, TargetEntityID: subID, Type: domain.RelHasSubdomain},
	}
	store.relationships[subID] = []domain.Relationship{
		{SourceEntityID: subID, TargetEntityID: endpointID, Type: domain.RelHasEndpoint},
	}

	analyzer := NewAnalyzer(store, nil)
	graph, err := analyzer.BuildGraph(context.Background(), projectID)
	if err != nil {
		t.Fatal(err)
	}

	paths := analyzer.FindResearchPaths(context.Background(), graph)

	if len(paths) == 0 {
		t.Fatal("expected at least 1 research path")
	}

	// Should find path from example.com → admin → /admin/upload (upload surface).
	found := false
	for _, p := range paths {
		for _, n := range p.Nodes {
			if n.Entity.Value == "/admin/upload" {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("expected path reaching /admin/upload")
	}
}

func TestResearchPathsRequireDepth(t *testing.T) {
	store := newMockStore()

	// Single node, no edges — should produce no paths.
	store.entities[domain.EntityDomain] = []domain.Entity{
		{ID: uuid.New(), Type: domain.EntityDomain, Value: "lonely.com"},
	}

	analyzer := NewAnalyzer(store, nil)
	graph, _ := analyzer.BuildGraph(context.Background(), uuid.New())
	paths := analyzer.FindResearchPaths(context.Background(), graph)

	if len(paths) != 0 {
		t.Errorf("expected 0 paths for isolated node, got %d", len(paths))
	}
}

// --- Surface summary test ---

func TestSurfaceSummary(t *testing.T) {
	graph := &Graph{
		Nodes: make(map[uuid.UUID]Node),
		Stats: Stats{
			TotalNodes:      5,
			TotalEdges:      3,
			NodesByCategory: map[Category]int{CategoryWeb: 2, CategoryNetwork: 2, CategoryUpload: 1},
			CorrelatedNodes: 2,
			MultiToolNodes:  1,
		},
	}

	summary := SurfaceSummary(graph)
	if summary == "" {
		t.Error("expected non-empty summary")
	}
	if !containsCI(summary, "5 nodes") {
		t.Error("summary should mention node count")
	}
}

// --- Empty graph test ---

func TestBuildEmptyGraph(t *testing.T) {
	store := newMockStore()
	analyzer := NewAnalyzer(store, nil)
	graph, err := analyzer.BuildGraph(context.Background(), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if graph.Stats.TotalNodes != 0 {
		t.Errorf("expected 0 nodes, got %d", graph.Stats.TotalNodes)
	}
	if graph.Stats.TotalEdges != 0 {
		t.Errorf("expected 0 edges, got %d", graph.Stats.TotalEdges)
	}
}

package correlation

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// --- Mock store ---

type mockStore struct {
	entities      map[domain.EntityType][]domain.Entity
	observations  map[uuid.UUID][]domain.Observation
	relationships map[uuid.UUID][]domain.Relationship
	correlations  []domain.Correlation
	materialized  []domain.Relationship
}

func newMockStore() *mockStore {
	return &mockStore{
		entities:      make(map[domain.EntityType][]domain.Entity),
		observations:  make(map[uuid.UUID][]domain.Observation),
		relationships: make(map[uuid.UUID][]domain.Relationship),
	}
}

func (m *mockStore) EntitiesByType(_ context.Context, t domain.EntityType, _ uuid.UUID) ([]domain.Entity, error) {
	return m.entities[t], nil
}

func (m *mockStore) ObservationsForEntity(_ context.Context, entityID uuid.UUID) ([]domain.Observation, error) {
	return m.observations[entityID], nil
}

func (m *mockStore) RelationshipsForEntity(_ context.Context, entityID uuid.UUID, _ domain.Direction) ([]domain.Relationship, error) {
	return m.relationships[entityID], nil
}

func (m *mockStore) EntityByTypeAndValue(_ context.Context, t domain.EntityType, value string, _ uuid.UUID) (*domain.Entity, error) {
	for _, e := range m.entities[t] {
		if e.Value == value {
			return &e, nil
		}
	}
	return nil, nil
}

func (m *mockStore) UpsertCorrelation(_ context.Context, c domain.Correlation) (*domain.Correlation, error) {
	// Check for existing (dedup).
	key := CorrelationIdentityKey(c)
	for i, existing := range m.correlations {
		if CorrelationIdentityKey(existing) == key {
			// Update: append observations, update timestamp.
			for _, newObs := range c.ObservationIDs {
				found := false
				for _, existingObs := range m.correlations[i].ObservationIDs {
					if existingObs == newObs {
						found = true
						break
					}
				}
				if !found {
					m.correlations[i].ObservationIDs = append(m.correlations[i].ObservationIDs, newObs)
				}
			}
			m.correlations[i].LastSeenAt = c.LastSeenAt
			return &m.correlations[i], nil
		}
	}
	m.correlations = append(m.correlations, c)
	return &c, nil
}

func (m *mockStore) MaterializeRelationship(_ context.Context, rel domain.Relationship) error {
	m.materialized = append(m.materialized, rel)
	return nil
}

// --- Engine tests ---

func TestEngineRunAll(t *testing.T) {
	store := newMockStore()
	projectID := uuid.New()

	// Setup: subdomain observed by 2 tools.
	subID := uuid.New()
	store.entities[domain.EntitySubdomain] = []domain.Entity{
		{ID: subID, Type: domain.EntitySubdomain, Value: "admin.example.com"},
	}
	store.observations[subID] = []domain.Observation{
		{ID: uuid.New(), Type: domain.ObservationSubdomainDiscovery, SourceTool: "subfinder"},
		{ID: uuid.New(), Type: domain.ObservationHTTPProbe, SourceTool: "httpx"},
	}

	engine := NewEngine(store, store, nil)
	engine.RegisterRule(NewSameTargetRule(projectID))

	n, err := engine.RunAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 correlation, got %d", n)
	}
	if len(store.correlations) != 1 {
		t.Fatalf("expected 1 persisted, got %d", len(store.correlations))
	}

	c := store.correlations[0]
	if c.Type != domain.CorrelationSameTarget {
		t.Errorf("expected same_target, got %s", c.Type)
	}
	if c.RuleName != "same_target" {
		t.Errorf("expected rule_name=same_target, got %s", c.RuleName)
	}
	if len(c.ObservationIDs) != 2 {
		t.Errorf("expected 2 observation IDs, got %d", len(c.ObservationIDs))
	}
}

func TestSameTargetRequiresMultipleTools(t *testing.T) {
	store := newMockStore()
	projectID := uuid.New()

	subID := uuid.New()
	store.entities[domain.EntitySubdomain] = []domain.Entity{
		{ID: subID, Type: domain.EntitySubdomain, Value: "single.example.com"},
	}
	// Same tool twice — should NOT produce correlation.
	store.observations[subID] = []domain.Observation{
		{ID: uuid.New(), Type: domain.ObservationSubdomainDiscovery, SourceTool: "subfinder"},
		{ID: uuid.New(), Type: domain.ObservationSubdomainDiscovery, SourceTool: "subfinder"},
	}

	rule := NewSameTargetRule(projectID)
	corrs, err := rule.Evaluate(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if len(corrs) != 0 {
		t.Errorf("expected 0 correlations for single tool, got %d", len(corrs))
	}
}

func TestResolvesToRule(t *testing.T) {
	store := newMockStore()
	projectID := uuid.New()

	subID := uuid.New()
	ipID := uuid.New()

	store.entities[domain.EntitySubdomain] = []domain.Entity{
		{ID: subID, Type: domain.EntitySubdomain, Value: "admin.example.com"},
	}
	store.entities[domain.EntityIPAddress] = []domain.Entity{
		{ID: ipID, Type: domain.EntityIPAddress, Value: "203.0.113.10"},
	}

	dnsObsID := uuid.New()
	nmapObsID := uuid.New()

	store.observations[subID] = []domain.Observation{
		{ID: dnsObsID, Type: domain.ObservationDNSLookup, SourceTool: "dnsx",
			Data: map[string]any{"a": []any{"203.0.113.10"}, "host": "admin.example.com"}},
	}
	store.observations[ipID] = []domain.Observation{
		{ID: nmapObsID, Type: domain.ObservationPortScan, SourceTool: "nmap",
			Data: map[string]any{"host": "203.0.113.10", "port": 443}},
	}

	rule := NewResolvesToRule(projectID, store)
	corrs, err := rule.Evaluate(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}

	if len(corrs) != 1 {
		t.Fatalf("expected 1 resolves_to correlation, got %d", len(corrs))
	}

	c := corrs[0]
	if c.Type != domain.CorrelationResolvesTo {
		t.Errorf("expected resolves_to, got %s", c.Type)
	}
	if len(c.EntityIDs) != 2 {
		t.Errorf("expected 2 entities, got %d", len(c.EntityIDs))
	}
	// Should have both DNS and nmap observations.
	if len(c.ObservationIDs) != 2 {
		t.Errorf("expected 2 observations (DNS + port), got %d", len(c.ObservationIDs))
	}
	if c.Confidence != 0.90 {
		t.Errorf("expected confidence 0.90 (cross-tool), got %.2f", c.Confidence)
	}

	// Should have materialized a relationship.
	if len(store.materialized) != 1 {
		t.Fatalf("expected 1 materialized relationship, got %d", len(store.materialized))
	}
	rel := store.materialized[0]
	if rel.Type != domain.RelResolvesTo {
		t.Errorf("expected resolves_to relationship, got %s", rel.Type)
	}
}

func TestConvergenceRule(t *testing.T) {
	store := newMockStore()
	projectID := uuid.New()

	endpointID := uuid.New()
	store.entities[domain.EntityEndpoint] = []domain.Entity{
		{ID: endpointID, Type: domain.EntityEndpoint, Value: "/admin/upload"},
	}
	store.observations[endpointID] = []domain.Observation{
		{ID: uuid.New(), Type: domain.ObservationEndpointDiscovery, SourceTool: "ffuf"},
		{ID: uuid.New(), Type: domain.ObservationCrawlResult, SourceTool: "katana"},
	}

	rule := NewConvergenceRule(projectID)
	corrs, err := rule.Evaluate(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}

	if len(corrs) != 1 {
		t.Fatalf("expected 1 convergence, got %d", len(corrs))
	}
	if corrs[0].Type != domain.CorrelationConvergence {
		t.Errorf("expected independent_convergence, got %s", corrs[0].Type)
	}
}

func TestConvergenceRequiresDifferentObsTypes(t *testing.T) {
	store := newMockStore()
	projectID := uuid.New()

	endpointID := uuid.New()
	store.entities[domain.EntityEndpoint] = []domain.Entity{
		{ID: endpointID, Type: domain.EntityEndpoint, Value: "/api"},
	}
	// Same observation type from different tools — not true convergence.
	store.observations[endpointID] = []domain.Observation{
		{ID: uuid.New(), Type: domain.ObservationEndpointDiscovery, SourceTool: "ffuf"},
		{ID: uuid.New(), Type: domain.ObservationEndpointDiscovery, SourceTool: "dirsearch"},
	}

	rule := NewConvergenceRule(projectID)
	corrs, err := rule.Evaluate(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if len(corrs) != 0 {
		t.Errorf("expected 0 convergences (same obs type), got %d", len(corrs))
	}
}

func TestServiceStackRule(t *testing.T) {
	store := newMockStore()
	projectID := uuid.New()

	hostID := uuid.New()
	portID := uuid.New()
	techID := uuid.New()

	store.entities[domain.EntityIPAddress] = []domain.Entity{
		{ID: hostID, Type: domain.EntityIPAddress, Value: "203.0.113.10"},
	}
	store.entities[domain.EntitySubdomain] = nil

	// Host has port and technology relationships.
	store.relationships[hostID] = []domain.Relationship{
		{TargetEntityID: portID, Type: domain.RelListensOn},
		{TargetEntityID: techID, Type: domain.RelUsesTechnology},
	}

	// Observations from different tools.
	store.observations[hostID] = []domain.Observation{
		{ID: uuid.New(), SourceTool: "nmap"},
	}
	store.observations[portID] = []domain.Observation{
		{ID: uuid.New(), SourceTool: "nmap"},
	}
	store.observations[techID] = []domain.Observation{
		{ID: uuid.New(), SourceTool: "httpx"},
	}

	rule := NewServiceStackRule(projectID)
	corrs, err := rule.Evaluate(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}

	if len(corrs) != 1 {
		t.Fatalf("expected 1 service_stack, got %d", len(corrs))
	}
	if corrs[0].Type != domain.CorrelationServiceStack {
		t.Errorf("expected service_stack, got %s", corrs[0].Type)
	}
	if corrs[0].Confidence != 0.90 {
		t.Errorf("expected confidence 0.90, got %.2f", corrs[0].Confidence)
	}
}

func TestCorrelationIdentityKey(t *testing.T) {
	id1 := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	id2 := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	c1 := domain.Correlation{
		Type:      domain.CorrelationSameTarget,
		RuleName:  "same_target",
		EntityIDs: []uuid.UUID{id1, id2},
	}
	c2 := domain.Correlation{
		Type:      domain.CorrelationSameTarget,
		RuleName:  "same_target",
		EntityIDs: []uuid.UUID{id2, id1}, // Reversed order.
	}

	key1 := CorrelationIdentityKey(c1)
	key2 := CorrelationIdentityKey(c2)

	if key1 != key2 {
		t.Errorf("identity keys should match regardless of entity order:\n%s\n%s", key1, key2)
	}
}

func TestDeduplicationAccumulatesObservations(t *testing.T) {
	store := newMockStore()

	obs1 := uuid.New()
	obs2 := uuid.New()
	obs3 := uuid.New()
	entityID := uuid.New()

	// First correlation.
	c1 := domain.Correlation{
		ID:             uuid.New(),
		Type:           domain.CorrelationSameTarget,
		RuleName:       "same_target",
		EntityIDs:      []uuid.UUID{entityID},
		ObservationIDs: []uuid.UUID{obs1, obs2},
		LastSeenAt:     time.Now().UTC(),
	}
	_, _ = store.UpsertCorrelation(context.Background(), c1)

	// Second run with new observation.
	c2 := domain.Correlation{
		ID:             uuid.New(),
		Type:           domain.CorrelationSameTarget,
		RuleName:       "same_target",
		EntityIDs:      []uuid.UUID{entityID},
		ObservationIDs: []uuid.UUID{obs2, obs3}, // obs2 overlaps, obs3 is new.
		LastSeenAt:     time.Now().UTC(),
	}
	result, _ := store.UpsertCorrelation(context.Background(), c2)

	if len(result.ObservationIDs) != 3 {
		t.Errorf("expected 3 accumulated observations (obs1 + obs2 + obs3), got %d", len(result.ObservationIDs))
	}
}

func TestConfidenceIsNotVulnerabilityProbability(t *testing.T) {
	// This is a documentation/invariant test.
	// Confidence measures rule inference quality, not vulnerability likelihood.

	store := newMockStore()
	projectID := uuid.New()

	subID := uuid.New()
	store.entities[domain.EntitySubdomain] = []domain.Entity{
		{ID: subID, Type: domain.EntitySubdomain, Value: "test.example.com"},
	}
	store.observations[subID] = []domain.Observation{
		{ID: uuid.New(), SourceTool: "subfinder"},
		{ID: uuid.New(), SourceTool: "httpx"},
		{ID: uuid.New(), SourceTool: "katana"},
	}

	rule := NewSameTargetRule(projectID)
	corrs, _ := rule.Evaluate(context.Background(), store)

	if len(corrs) != 1 {
		t.Fatal("expected 1 correlation")
	}

	c := corrs[0]
	if c.Confidence > 1.0 || c.Confidence < 0.0 {
		t.Errorf("confidence must be [0, 1], got %.2f", c.Confidence)
	}
	// 3 tools should give high confidence in the RULE, not in vulnerability.
	if c.Confidence < 0.9 {
		t.Errorf("3 tools should give confidence ≥ 0.90, got %.2f", c.Confidence)
	}
}

func TestEngineRuleNames(t *testing.T) {
	engine := NewEngine(newMockStore(), newMockStore(), nil)
	engine.RegisterRule(NewSameTargetRule(uuid.New()))
	engine.RegisterRule(NewConvergenceRule(uuid.New()))

	names := engine.RuleNames()
	if len(names) != 2 {
		t.Errorf("expected 2 rules, got %d", len(names))
	}
}

func TestEngineRunUnknownRule(t *testing.T) {
	engine := NewEngine(newMockStore(), newMockStore(), nil)
	_, err := engine.RunRule(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for unknown rule")
	}
}

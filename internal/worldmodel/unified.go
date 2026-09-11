package worldmodel

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// UnifiedVertexRole specifies the mathematical role of a vertex in W_t = (V_t, E_t, tau).
type UnifiedVertexRole string

const (
	RoleState      UnifiedVertexRole = "state"
	RoleCapability UnifiedVertexRole = "capability"
	RoleInvariant  UnifiedVertexRole = "invariant"
	RoleHypothesis UnifiedVertexRole = "hypothesis"
	RoleExperiment UnifiedVertexRole = "experiment"
	RoleEvidence   UnifiedVertexRole = "evidence"
	RoleConcept    UnifiedVertexRole = "concept"
	RoleStrategy   UnifiedVertexRole = "strategy"
)

// UnifiedEdgeType specifies the semantic relationship of a directed edge in W_t.
type UnifiedEdgeType string

const (
	EdgeCausallyInfluences    UnifiedEdgeType = "causally_influences"
	EdgeSupportsHypothesis    UnifiedEdgeType = "supports_hypothesis"
	EdgeFalsifiesHypothesis   UnifiedEdgeType = "falsifies_hypothesis"
	EdgeLeadsToCapability     UnifiedEdgeType = "leads_to_capability"
	EdgeDerivedFromExperiment UnifiedEdgeType = "derived_from_experiment"
	EdgeExemplifiesConcept    UnifiedEdgeType = "exemplifies_concept"
)

// UnifiedVertex represents a typed node in the unified world model graph.
type UnifiedVertex struct {
	ID            uuid.UUID         `json:"id"`
	Role          UnifiedVertexRole `json:"role"`
	Label         string            `json:"label"`
	Confidence    float64           `json:"confidence"`
	AnomalyScore  float64           `json:"anomaly_score"`
	Properties    map[string]any    `json:"properties"`
	CreatedAt     time.Time         `json:"created_at"`
	LastUpdatedAt time.Time         `json:"last_updated_at"`
}

// UnifiedEdge represents a provenance-tracked directed edge in W_t.
type UnifiedEdge struct {
	ID               uuid.UUID       `json:"id"`
	SourceID         uuid.UUID       `json:"source_id"`
	TargetID         uuid.UUID       `json:"target_id"`
	Type             UnifiedEdgeType `json:"type"`
	Confidence       float64         `json:"confidence"`
	ExperimentID     uuid.UUID       `json:"experiment_id"`    // Provenance: which experiment produced this edge
	CausalProvenance string          `json:"causal_provenance"` // Mechanism explanation
	CreatedAt        time.Time       `json:"created_at"`
}

// UnifiedWorldModelGraph implements W_t = (V_t, E_t, tau) as a single typed structure.
type UnifiedWorldModelGraph struct {
	mu       sync.RWMutex
	TargetID string
	vertices map[uuid.UUID]*UnifiedVertex
	edges    map[uuid.UUID]*UnifiedEdge
	outEdges map[uuid.UUID][]*UnifiedEdge
	inEdges  map[uuid.UUID][]*UnifiedEdge
}

// NewUnifiedWorldModelGraph instantiates a unified typed graph for a target.
func NewUnifiedWorldModelGraph(targetID string) *UnifiedWorldModelGraph {
	return &UnifiedWorldModelGraph{
		TargetID: targetID,
		vertices: make(map[uuid.UUID]*UnifiedVertex),
		edges:    make(map[uuid.UUID]*UnifiedEdge),
		outEdges: make(map[uuid.UUID][]*UnifiedEdge),
		inEdges:  make(map[uuid.UUID][]*UnifiedEdge),
	}
}

// AddVertex registers a typed vertex into the graph.
func (g *UnifiedWorldModelGraph) AddVertex(role UnifiedVertexRole, label string, confidence, anomaly float64, props map[string]any) *UnifiedVertex {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now().UTC()
	v := &UnifiedVertex{
		ID:            uuid.New(),
		Role:          role,
		Label:         label,
		Confidence:    confidence,
		AnomalyScore:  anomaly,
		Properties:    props,
		CreatedAt:     now,
		LastUpdatedAt: now,
	}
	if v.Properties == nil {
		v.Properties = make(map[string]any)
	}
	g.vertices[v.ID] = v
	return v
}

// AddEdge registers a provenance-tracked edge between two vertices.
func (g *UnifiedWorldModelGraph) AddEdge(src, dst uuid.UUID, edgeType UnifiedEdgeType, confidence float64, expID uuid.UUID, provenance string) *UnifiedEdge {
	g.mu.Lock()
	defer g.mu.Unlock()

	edge := &UnifiedEdge{
		ID:               uuid.New(),
		SourceID:         src,
		TargetID:         dst,
		Type:             edgeType,
		Confidence:       confidence,
		ExperimentID:     expID,
		CausalProvenance: provenance,
		CreatedAt:        time.Now().UTC(),
	}

	g.edges[edge.ID] = edge
	g.outEdges[src] = append(g.outEdges[src], edge)
	g.inEdges[dst] = append(g.inEdges[dst], edge)
	return edge
}

// GetFrontierView returns F_t = { v in W_t : confidence(v) < c_min OR Anomaly(v) > a_min }.
func (g *UnifiedWorldModelGraph) GetFrontierView(minConf, minAnomaly float64) []*UnifiedVertex {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var frontier []*UnifiedVertex
	for _, v := range g.vertices {
		if v.Confidence < minConf || v.AnomalyScore > minAnomaly {
			frontier = append(frontier, v)
		}
	}
	return frontier
}

// AttackGraphView returns the sub-projection corresponding to capabilities and state transitions.
func (g *UnifiedWorldModelGraph) AttackGraphView() ([]*UnifiedVertex, []*UnifiedEdge) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var nodes []*UnifiedVertex
	nodeMap := make(map[uuid.UUID]bool)
	for _, v := range g.vertices {
		if v.Role == RoleCapability || v.Role == RoleState {
			nodes = append(nodes, v)
			nodeMap[v.ID] = true
		}
	}

	var edges []*UnifiedEdge
	for _, e := range g.edges {
		if e.Type == EdgeLeadsToCapability && nodeMap[e.SourceID] && nodeMap[e.TargetID] {
			edges = append(edges, e)
		}
	}
	return nodes, edges
}

// CausalGraphView returns the sub-projection of causal dependencies.
func (g *UnifiedWorldModelGraph) CausalGraphView() ([]*UnifiedVertex, []*UnifiedEdge) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var edges []*UnifiedEdge
	for _, e := range g.edges {
		if e.Type == EdgeCausallyInfluences {
			edges = append(edges, e)
		}
	}
	return g.allVerticesLocked(), edges
}

// ConceptGraphView returns the sub-projection of emergent security concepts and hypotheses.
func (g *UnifiedWorldModelGraph) ConceptGraphView() ([]*UnifiedVertex, []*UnifiedEdge) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var nodes []*UnifiedVertex
	for _, v := range g.vertices {
		if v.Role == RoleConcept || v.Role == RoleHypothesis {
			nodes = append(nodes, v)
		}
	}
	return nodes, nil
}

// DecayStaleConfidence applies exponential decay to confidence of untested vertices.
func (g *UnifiedWorldModelGraph) DecayStaleConfidence(decayFactor float64) {
	g.mu.Lock()
	defer g.mu.Unlock()

	for _, v := range g.vertices {
		// Proven evidence and concepts retain full confidence
		if v.Role != RoleEvidence && v.Role != RoleConcept {
			v.Confidence *= decayFactor
			v.LastUpdatedAt = time.Now().UTC()
		}
	}
}

func (g *UnifiedWorldModelGraph) allVerticesLocked() []*UnifiedVertex {
	res := make([]*UnifiedVertex, 0, len(g.vertices))
	for _, v := range g.vertices {
		res = append(res, v)
	}
	return res
}

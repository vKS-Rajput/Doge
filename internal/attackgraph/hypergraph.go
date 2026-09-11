package attackgraph

import (
	"sync"

	"github.com/google/uuid"
)

// HyperNodeType distinguishes between individual capabilities, AND joins, and OR joins.
type HyperNodeType string

const (
	HyperNodeCapability HyperNodeType = "capability"
	HyperNodeAND        HyperNodeType = "and_join"
	HyperNodeOR         HyperNodeType = "or_choice"
)

// HyperNode represents a node in the AND/OR Capability Hypergraph.
type HyperNode struct {
	ID             uuid.UUID     `json:"id"`
	Name           string        `json:"name"`
	Type           HyperNodeType `json:"type"`
	Preconditions  []string      `json:"preconditions"`
	Postconditions []string      `json:"postconditions"`
	Confidence     float64       `json:"confidence"`
	ImpactValue    float64       `json:"impact_value"`
	NoveltyValue   float64       `json:"novelty_value"`
	Dependencies   []uuid.UUID   `json:"dependencies"` // Inputs required
}

// ANDORHypergraph manages the capability composition graph.
type ANDORHypergraph struct {
	mu    sync.RWMutex
	nodes map[uuid.UUID]*HyperNode
}

// NewANDORHypergraph creates a new AND/OR capability hypergraph.
func NewANDORHypergraph() *ANDORHypergraph {
	return &ANDORHypergraph{
		nodes: make(map[uuid.UUID]*HyperNode),
	}
}

// AddCapability adds a primitive security capability with typed pre/postconditions.
func (h *ANDORHypergraph) AddCapability(name string, preconditions, postconditions []string, impact, novelty float64) *HyperNode {
	h.mu.Lock()
	defer h.mu.Unlock()

	node := &HyperNode{
		ID:             uuid.New(),
		Name:           name,
		Type:           HyperNodeCapability,
		Preconditions:  preconditions,
		Postconditions: postconditions,
		Confidence:     0.90,
		ImpactValue:    impact,
		NoveltyValue:   novelty,
		Dependencies:   make([]uuid.UUID, 0),
	}
	h.nodes[node.ID] = node
	return node
}

// AddANDJoin creates a hypergraph AND-node where all dependencies must be simultaneously satisfied.
func (h *ANDORHypergraph) AddANDJoin(name string, deps []uuid.UUID, postconditions []string, impact float64) *HyperNode {
	h.mu.Lock()
	defer h.mu.Unlock()

	node := &HyperNode{
		ID:             uuid.New(),
		Name:           name,
		Type:           HyperNodeAND,
		Preconditions:  make([]string, 0),
		Postconditions: postconditions,
		Confidence:     0.95,
		ImpactValue:    impact,
		NoveltyValue:   0.80,
		Dependencies:   deps,
	}
	h.nodes[node.ID] = node
	return node
}

// AddORChoice creates a hypergraph OR-node where any dependency is sufficient.
func (h *ANDORHypergraph) AddORChoice(name string, deps []uuid.UUID, postconditions []string) *HyperNode {
	h.mu.Lock()
	defer h.mu.Unlock()

	node := &HyperNode{
		ID:             uuid.New(),
		Name:           name,
		Type:           HyperNodeOR,
		Preconditions:  make([]string, 0),
		Postconditions: postconditions,
		Confidence:     0.90,
		ImpactValue:    0.50,
		NoveltyValue:   0.50,
		Dependencies:   deps,
	}
	h.nodes[node.ID] = node
	return node
}

// GetNode returns a node by its ID.
func (h *ANDORHypergraph) GetNode(id uuid.UUID) (*HyperNode, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	node, ok := h.nodes[id]
	return node, ok
}

// AllNodes returns a copy of all hypergraph nodes.
func (h *ANDORHypergraph) AllNodes() []*HyperNode {
	h.mu.RLock()
	defer h.mu.RUnlock()
	res := make([]*HyperNode, 0, len(h.nodes))
	for _, n := range h.nodes {
		res = append(res, n)
	}
	return res
}

// IsSatisfiable checks if a given capability can be activated given current satisfied preconditions.
func (h *ANDORHypergraph) IsSatisfiable(node *HyperNode, satisfied map[string]bool) bool {
	if node == nil {
		return false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()

	switch node.Type {
	case HyperNodeCapability:
		for _, pre := range node.Preconditions {
			if !satisfied[pre] {
				return false
			}
		}
		return true

	case HyperNodeAND:
		for _, depID := range node.Dependencies {
			dep, ok := h.nodes[depID]
			if !ok {
				return false
			}
			for _, post := range dep.Postconditions {
				if !satisfied[post] {
					return false
				}
			}
		}
		return true

	case HyperNodeOR:
		for _, depID := range node.Dependencies {
			if dep, ok := h.nodes[depID]; ok {
				for _, post := range dep.Postconditions {
					if satisfied[post] {
						return true
					}
				}
			}
		}
		return len(node.Dependencies) == 0
	}
	return false
}

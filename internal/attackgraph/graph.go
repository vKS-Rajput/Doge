// Package attackgraph provides a persistent directed graph representing
// attack paths through a target system.
//
// The graph connects:
//
//	Principal → Identity → Capability → Resource → Weakness
//	→ Access → New Capability → New Resource → Impact
//
// DOGE continuously asks:
//
//	"Can these apparently unrelated observations form a security-relevant chain?"
//
// The attack graph is the data structure that answers this question.
package attackgraph

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// NodeType classifies attack graph nodes.
type NodeType string

const (
	NodePrincipal  NodeType = "principal"   // An identity/user/role
	NodeCapability NodeType = "capability"  // Something a principal can do
	NodeResource   NodeType = "resource"    // An asset/endpoint/object
	NodeWeakness   NodeType = "weakness"    // A discovered weakness
	NodeAccess     NodeType = "access"      // Achieved access to something
	NodeImpact     NodeType = "impact"      // Demonstrated security impact
	NodeState      NodeType = "state"       // Application state
	NodeAction     NodeType = "action"      // An action that can be performed
)

// EdgeType classifies relationships between attack graph nodes.
type EdgeType string

const (
	EdgeEnables   EdgeType = "enables"    // This node enables the target node
	EdgeRequires  EdgeType = "requires"   // This node requires the source node
	EdgeLeadsTo   EdgeType = "leads_to"   // This observation leads to that conclusion
	EdgeUnlocks   EdgeType = "unlocks"    // Exploiting this unlocks that capability
	EdgeChains    EdgeType = "chains"     // These weaknesses chain together
	EdgeEscalates EdgeType = "escalates"  // This access escalates to that access
	EdgeTransition EdgeType = "transition" // State A transitions to state B
)

// Node is a vertex in the attack graph.
type Node struct {
	ID          uuid.UUID         `json:"id"`
	Type        NodeType          `json:"type"`
	Label       string            `json:"label"`
	Description string            `json:"description"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	Confidence  float64           `json:"confidence"` // 0.0-1.0
	Explored    bool              `json:"explored"`   // Has this been fully investigated?
	EvidenceIDs []uuid.UUID       `json:"evidence_ids,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}

// Edge is a directed edge in the attack graph.
type Edge struct {
	ID          uuid.UUID         `json:"id"`
	SourceID    uuid.UUID         `json:"source_id"`
	TargetID    uuid.UUID         `json:"target_id"`
	Type        EdgeType          `json:"type"`
	Label       string            `json:"label"`
	Confidence  float64           `json:"confidence"` // 0.0-1.0
	Explored    bool              `json:"explored"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	EvidenceIDs []uuid.UUID       `json:"evidence_ids,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}

// AttackPath is an ordered sequence of edges forming an attack path.
type AttackPath struct {
	Edges          []Edge    `json:"edges"`
	TotalSteps     int       `json:"total_steps"`
	MinConfidence  float64   `json:"min_confidence"`   // Weakest link
	CombinedImpact string    `json:"combined_impact"`
	IsComplete     bool      `json:"is_complete"`       // Does it reach an impact node?
}

// Graph is the persistent attack graph.
type Graph struct {
	mu             sync.RWMutex
	nodes          map[uuid.UUID]*Node
	edges          map[uuid.UUID]*Edge
	outEdges       map[uuid.UUID][]*Edge // source → edges
	inEdges        map[uuid.UUID][]*Edge // target → edges
	nodesByType    map[NodeType][]*Node
	nodesByLabel   map[string]*Node
}

// NewGraph creates a new empty attack graph.
func NewGraph() *Graph {
	return &Graph{
		nodes:        make(map[uuid.UUID]*Node),
		edges:        make(map[uuid.UUID]*Edge),
		outEdges:     make(map[uuid.UUID][]*Edge),
		inEdges:      make(map[uuid.UUID][]*Edge),
		nodesByType:  make(map[NodeType][]*Node),
		nodesByLabel: make(map[string]*Node),
	}
}

// AddNode adds a node to the graph. Returns existing node if label already exists.
func (g *Graph) AddNode(nodeType NodeType, label, description string, confidence float64) *Node {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Dedup by label
	if existing, ok := g.nodesByLabel[label]; ok {
		// Update confidence if higher
		if confidence > existing.Confidence {
			existing.Confidence = confidence
		}
		return existing
	}

	node := &Node{
		ID:          uuid.New(),
		Type:        nodeType,
		Label:       label,
		Description: description,
		Confidence:  confidence,
		Attributes:  make(map[string]string),
		CreatedAt:   time.Now().UTC(),
	}

	g.nodes[node.ID] = node
	g.nodesByType[nodeType] = append(g.nodesByType[nodeType], node)
	g.nodesByLabel[label] = node
	return node
}

// AddEdge creates a directed edge between two nodes.
func (g *Graph) AddEdge(sourceID, targetID uuid.UUID, edgeType EdgeType, label string, confidence float64) (*Edge, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.nodes[sourceID]; !ok {
		return nil, fmt.Errorf("source node %s not found", sourceID)
	}
	if _, ok := g.nodes[targetID]; !ok {
		return nil, fmt.Errorf("target node %s not found", targetID)
	}

	// Check for duplicate edges
	for _, e := range g.outEdges[sourceID] {
		if e.TargetID == targetID && e.Type == edgeType {
			if confidence > e.Confidence {
				e.Confidence = confidence
			}
			return e, nil
		}
	}

	edge := &Edge{
		ID:         uuid.New(),
		SourceID:   sourceID,
		TargetID:   targetID,
		Type:       edgeType,
		Label:      label,
		Confidence: confidence,
		Attributes: make(map[string]string),
		CreatedAt:  time.Now().UTC(),
	}

	g.edges[edge.ID] = edge
	g.outEdges[sourceID] = append(g.outEdges[sourceID], edge)
	g.inEdges[targetID] = append(g.inEdges[targetID], edge)
	return edge, nil
}

// GetNode returns a node by ID.
func (g *Graph) GetNode(id uuid.UUID) (*Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	return n, ok
}

// GetNodeByLabel returns a node by its label.
func (g *Graph) GetNodeByLabel(label string) (*Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodesByLabel[label]
	return n, ok
}

// GetNodesByType returns all nodes of a given type.
func (g *Graph) GetNodesByType(nodeType NodeType) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.nodesByType[nodeType]
}

// OutEdges returns all edges originating from a node.
func (g *Graph) OutEdges(nodeID uuid.UUID) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.outEdges[nodeID]
}

// InEdges returns all edges targeting a node.
func (g *Graph) InEdges(nodeID uuid.UUID) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.inEdges[nodeID]
}

// NodeCount returns total nodes.
func (g *Graph) NodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

// EdgeCount returns total edges.
func (g *Graph) EdgeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.edges)
}

// UnexploredEdges returns all edges that have not been fully explored.
func (g *Graph) UnexploredEdges() []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var unexplored []*Edge
	for _, e := range g.edges {
		if !e.Explored {
			unexplored = append(unexplored, e)
		}
	}
	return unexplored
}

// UnexploredNodes returns all nodes that have not been fully explored.
func (g *Graph) UnexploredNodes() []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var unexplored []*Node
	for _, n := range g.nodes {
		if !n.Explored {
			unexplored = append(unexplored, n)
		}
	}
	return unexplored
}

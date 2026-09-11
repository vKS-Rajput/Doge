package transfer

import (
	"math"
	"strings"
)

// AbstractRole represents a canonical structural role in a software security model.
type AbstractRole string

const (
	RoleUnprivilegedActor AbstractRole = "actor_unprivileged"
	RolePrivilegedActor   AbstractRole = "actor_privileged"
	RoleStateGuard        AbstractRole = "guard_state_check"
	RoleAsyncExecution    AbstractRole = "async_window"
	RoleResourceAsset     AbstractRole = "resource_asset"
	RoleNormalizerProxy   AbstractRole = "proxy_normalizer"
)

// AbstractCausalRelation represents a canonical causal edge between abstract roles.
type AbstractCausalRelation string

const (
	CausalBypasses   AbstractCausalRelation = "bypasses"
	CausalRacesWith  AbstractCausalRelation = "races_with"
	CausalBleedsInto AbstractCausalRelation = "bleeds_into"
	CausalMutates    AbstractCausalRelation = "mutates_unauthorized"
)

// AbstractNode represents an abstract vertex in the relational causal graph.
type AbstractNode struct {
	ID        string       `json:"id"`
	Role      AbstractRole `json:"role"`
	AssetHint string       `json:"asset_hint"` // generic hint (e.g. "balance", "calibration", "token")
}

// AbstractEdge represents a directed causal dependency in the relational causal graph.
type AbstractEdge struct {
	SourceID string                 `json:"source_id"`
	TargetID string                 `json:"target_id"`
	Relation AbstractCausalRelation `json:"relation"`
}

// AbstractRelationalGraph represents G = (V, E) at the abstract structural level.
type AbstractRelationalGraph struct {
	TargetID string          `json:"target_id"`
	Nodes    []*AbstractNode `json:"nodes"`
	Edges    []*AbstractEdge `json:"edges"`
}

// NewAbstractRelationalGraph creates a new abstract relational graph.
func NewAbstractRelationalGraph(targetID string) *AbstractRelationalGraph {
	return &AbstractRelationalGraph{
		TargetID: targetID,
		Nodes:    make([]*AbstractNode, 0),
		Edges:    make([]*AbstractEdge, 0),
	}
}

// AddNode adds an abstract node.
func (g *AbstractRelationalGraph) AddNode(id string, role AbstractRole, hint string) *AbstractNode {
	node := &AbstractNode{ID: id, Role: role, AssetHint: hint}
	g.Nodes = append(g.Nodes, node)
	return node
}

// AddEdge adds an abstract causal edge.
func (g *AbstractRelationalGraph) AddEdge(src, dst string, rel AbstractCausalRelation) *AbstractEdge {
	edge := &AbstractEdge{SourceID: src, TargetID: dst, Relation: rel}
	g.Edges = append(g.Edges, edge)
	return edge
}

// IsomorphismScore computes structural graph similarity between G_A and G_B.
// Returns score in [0.0, 1.0] where 1.0 indicates perfect structural isomorphism G_A =~= G_B.
func IsomorphismScore(ga, gb *AbstractRelationalGraph) float64 {
	if ga == nil || gb == nil {
		return 0.0
	}
	if len(ga.Nodes) == 0 || len(gb.Nodes) == 0 {
		return 0.0
	}

	// 1. Role Multiset Overlap
	roleCountA := make(map[AbstractRole]int)
	for _, n := range ga.Nodes {
		roleCountA[n.Role]++
	}
	roleCountB := make(map[AbstractRole]int)
	for _, n := range gb.Nodes {
		roleCountB[n.Role]++
	}

	matchedRoles := 0
	totalRoles := len(ga.Nodes)
	for r, countA := range roleCountA {
		if countB, ok := roleCountB[r]; ok {
			matchedRoles += int(math.Min(float64(countA), float64(countB)))
		}
	}
	roleScore := float64(matchedRoles) / float64(totalRoles)

	// 2. Causal Edge Topology Overlap
	edgeCountA := make(map[AbstractCausalRelation]int)
	for _, e := range ga.Edges {
		edgeCountA[e.Relation]++
	}
	edgeCountB := make(map[AbstractCausalRelation]int)
	for _, e := range gb.Edges {
		edgeCountB[e.Relation]++
	}

	matchedEdges := 0
	totalEdges := len(ga.Edges)
	if totalEdges == 0 {
		return roleScore
	}
	for rel, countA := range edgeCountA {
		if countB, ok := edgeCountB[rel]; ok {
			matchedEdges += int(math.Min(float64(countA), float64(countB)))
		}
	}
	edgeScore := float64(matchedEdges) / float64(totalEdges)

	// 3. Combined Isomorphism Score (weighted 40% roles, 60% causal topology)
	return (0.40 * roleScore) + (0.60 * edgeScore)
}

// ExtractRoleBinding produces a mapping from AbstractNode.ID in ga to candidate node ID in gb.
func ExtractRoleBinding(ga, gb *AbstractRelationalGraph) map[string]string {
	binding := make(map[string]string)
	usedB := make(map[string]bool)

	for _, na := range ga.Nodes {
		for _, nb := range gb.Nodes {
			if usedB[nb.ID] {
				continue
			}
			if na.Role == nb.Role {
				binding[na.ID] = nb.ID
				usedB[nb.ID] = true
				break
			}
		}
	}
	return binding
}

// IsStructurallyIsomorphic returns true if similarity exceeds threshold (e.g. 0.80).
func IsStructurallyIsomorphic(ga, gb *AbstractRelationalGraph, threshold float64) bool {
	score := IsomorphismScore(ga, gb)
	return score >= threshold
}

func sanitizeEndpointKey(ep string) string {
	return strings.ToLower(strings.TrimSpace(ep))
}

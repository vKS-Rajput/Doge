package attackgraph

import (
	"github.com/google/uuid"
)

// ChainSearcher finds attack paths and chains in the graph.
type ChainSearcher struct {
	graph *Graph
}

// NewChainSearcher creates a chain searcher for the given graph.
func NewChainSearcher(g *Graph) *ChainSearcher {
	return &ChainSearcher{graph: g}
}

// FindPaths finds all paths from source to target up to maxDepth.
// Uses BFS to find shortest paths first.
func (cs *ChainSearcher) FindPaths(sourceID, targetID uuid.UUID, maxDepth int) []AttackPath {
	cs.graph.mu.RLock()
	defer cs.graph.mu.RUnlock()

	var results []AttackPath

	type searchState struct {
		nodeID uuid.UUID
		path   []Edge
		visited map[uuid.UUID]bool
	}

	queue := []searchState{{
		nodeID:  sourceID,
		path:    nil,
		visited: map[uuid.UUID]bool{sourceID: true},
	}}

	for len(queue) > 0 && len(results) < 100 {
		current := queue[0]
		queue = queue[1:]

		if len(current.path) > maxDepth {
			continue
		}

		if current.nodeID == targetID && len(current.path) > 0 {
			minConf := 1.0
			for _, e := range current.path {
				if e.Confidence < minConf {
					minConf = e.Confidence
				}
			}
			results = append(results, AttackPath{
				Edges:         current.path,
				TotalSteps:    len(current.path),
				MinConfidence: minConf,
				IsComplete:    true,
			})
			continue
		}

		for _, edge := range cs.graph.outEdges[current.nodeID] {
			if current.visited[edge.TargetID] {
				continue
			}

			newVisited := make(map[uuid.UUID]bool)
			for k, v := range current.visited {
				newVisited[k] = v
			}
			newVisited[edge.TargetID] = true

			newPath := make([]Edge, len(current.path)+1)
			copy(newPath, current.path)
			newPath[len(current.path)] = *edge

			queue = append(queue, searchState{
				nodeID:  edge.TargetID,
				path:    newPath,
				visited: newVisited,
			})
		}
	}

	return results
}

// FindChains discovers attack chains — sequences of weaknesses that
// combine to produce greater impact than any individual weakness.
//
// A chain is a path through: Weakness → Access → Capability → Resource → Weakness → ...
// where the terminal node is an Impact or a higher-severity Access.
func (cs *ChainSearcher) FindChains(maxDepth int) []AttackPath {
	cs.graph.mu.RLock()
	weaknesses := make([]*Node, len(cs.graph.nodesByType[NodeWeakness]))
	copy(weaknesses, cs.graph.nodesByType[NodeWeakness])
	impacts := make([]*Node, len(cs.graph.nodesByType[NodeImpact]))
	copy(impacts, cs.graph.nodesByType[NodeImpact])
	cs.graph.mu.RUnlock()

	if len(weaknesses) == 0 || len(impacts) == 0 {
		return nil
	}

	var chains []AttackPath
	for _, w := range weaknesses {
		for _, imp := range impacts {
			paths := cs.FindPaths(w.ID, imp.ID, maxDepth)
			for _, p := range paths {
				if p.TotalSteps >= 1 {
					p.CombinedImpact = imp.Description
					chains = append(chains, p)
				}
			}
		}
	}

	return chains
}

// FindEscalationPaths finds paths where low-severity access can escalate
// to higher-severity impact through the graph.
func (cs *ChainSearcher) FindEscalationPaths(maxDepth int) []AttackPath {
	cs.graph.mu.RLock()
	accesses := make([]*Node, len(cs.graph.nodesByType[NodeAccess]))
	copy(accesses, cs.graph.nodesByType[NodeAccess])
	impacts := make([]*Node, len(cs.graph.nodesByType[NodeImpact]))
	copy(impacts, cs.graph.nodesByType[NodeImpact])
	cs.graph.mu.RUnlock()

	var escalations []AttackPath
	for _, access := range accesses {
		for _, impact := range impacts {
			paths := cs.FindPaths(access.ID, impact.ID, maxDepth)
			escalations = append(escalations, paths...)
		}
	}

	return escalations
}

// CanChain determines if two nodes could potentially be connected
// through the graph (direct or indirect).
func (cs *ChainSearcher) CanChain(nodeA, nodeB uuid.UUID, maxDepth int) bool {
	paths := cs.FindPaths(nodeA, nodeB, maxDepth)
	return len(paths) > 0
}

// SuggestExplorations returns edges and nodes that haven't been explored
// and could potentially extend existing chains or create new ones.
func (cs *ChainSearcher) SuggestExplorations() []*Edge {
	cs.graph.mu.RLock()
	defer cs.graph.mu.RUnlock()

	var suggestions []*Edge
	for _, e := range cs.graph.edges {
		if !e.Explored {
			suggestions = append(suggestions, e)
		}
	}
	return suggestions
}

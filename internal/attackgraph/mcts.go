package attackgraph

import (
	"math"
	"math/rand"
	"time"

	"github.com/google/uuid"
)

// DiscoveredHyperChain represents a composed multi-step exploit sequence discovered via MCTS.
type DiscoveredHyperChain struct {
	Steps            []*HyperNode `json:"steps"`
	TotalImpact      float64      `json:"total_impact"`
	OverallNovelty   float64      `json:"overall_novelty"`
	TargetCapability string       `json:"target_capability"`
}

// MCTSNode represents a search node in the MCTS tree.
type MCTSNode struct {
	HyperNode    *HyperNode
	Parent       *MCTSNode
	Children     []*MCTSNode
	Visits       int
	TotalReward  float64
	StatePost    map[string]bool // satisfied postconditions in this state
	UntriedNodes []*HyperNode
}

// HyperMCTSSearcher performs Monte Carlo Tree Search over an AND/OR Hypergraph.
type HyperMCTSSearcher struct {
	graph      *ANDORHypergraph
	iterations int
	rng        *rand.Rand
}

// NewHyperMCTSSearcher creates an MCTS searcher for the capability hypergraph.
func NewHyperMCTSSearcher(graph *ANDORHypergraph, iterations int) *HyperMCTSSearcher {
	if iterations <= 0 {
		iterations = 200
	}
	return &HyperMCTSSearcher{
		graph:      graph,
		iterations: iterations,
		rng:        rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// SearchChain discovers an optimal multi-step attack sequence reaching targetPostcondition.
func (s *HyperMCTSSearcher) SearchChain(initialCapabilities []string, targetPostcondition string) *DiscoveredHyperChain {
	if s.graph == nil {
		return nil
	}

	initialState := make(map[string]bool)
	for _, c := range initialCapabilities {
		initialState[c] = true
	}

	root := &MCTSNode{
		HyperNode:   nil,
		Parent:      nil,
		Children:    make([]*MCTSNode, 0),
		StatePost:   initialState,
		UntriedNodes: s.getFeasibleNodes(initialState, make(map[uuid.UUID]bool)),
	}

	for i := 0; i < s.iterations; i++ {
		node := s.selectNode(root)
		if node == nil {
			break
		}

		reward := s.simulate(node, targetPostcondition)
		s.backpropagate(node, reward)
	}

	return s.extractBestChain(root, targetPostcondition)
}

func (s *HyperMCTSSearcher) selectNode(node *MCTSNode) *MCTSNode {
	current := node
	for len(current.UntriedNodes) == 0 && len(current.Children) > 0 {
		// Select best child via UCT
		bestChild := current.Children[0]
		bestUCT := -1.0

		for _, child := range current.Children {
			uct := s.computeUCT(child, current.Visits)
			if uct > bestUCT {
				bestUCT = uct
				bestChild = child
			}
		}
		current = bestChild
	}

	// Expand one untried node
	if len(current.UntriedNodes) > 0 {
		idx := s.rng.Intn(len(current.UntriedNodes))
		chosen := current.UntriedNodes[idx]

		// Remove chosen from untried
		current.UntriedNodes = append(current.UntriedNodes[:idx], current.UntriedNodes[idx+1:]...)

		// Create child state
		childState := make(map[string]bool)
		for k, v := range current.StatePost {
			childState[k] = v
		}
		for _, post := range chosen.Postconditions {
			childState[post] = true
		}

		used := make(map[uuid.UUID]bool)
		for p := current; p != nil; p = p.Parent {
			if p.HyperNode != nil {
				used[p.HyperNode.ID] = true
			}
		}
		used[chosen.ID] = true

		child := &MCTSNode{
			HyperNode:    chosen,
			Parent:       current,
			Children:     make([]*MCTSNode, 0),
			StatePost:    childState,
			UntriedNodes: s.getFeasibleNodes(childState, used),
		}
		current.Children = append(current.Children, child)
		return child
	}

	return current
}

func (s *HyperMCTSSearcher) computeUCT(node *MCTSNode, parentVisits int) float64 {
	if node.Visits == 0 {
		return 1e6
	}
	c := math.Sqrt(2.0)
	exploitation := node.TotalReward / float64(node.Visits)
	exploration := c * math.Sqrt(math.Log(float64(parentVisits))/float64(node.Visits))
	noveltyBias := 0.2 * node.HyperNode.NoveltyValue
	impactBias := 0.3 * node.HyperNode.ImpactValue

	return exploitation + exploration + noveltyBias + impactBias
}

func (s *HyperMCTSSearcher) simulate(node *MCTSNode, target string) float64 {
	if node.StatePost[target] {
		return 1.0 + node.HyperNode.ImpactValue
	}

	currentState := make(map[string]bool)
	for k, v := range node.StatePost {
		currentState[k] = v
	}

	used := make(map[uuid.UUID]bool)
	for p := node; p != nil; p = p.Parent {
		if p.HyperNode != nil {
			used[p.HyperNode.ID] = true
		}
	}

	// Rollout up to 6 steps
	for step := 0; step < 6; step++ {
		feasible := s.getFeasibleNodes(currentState, used)
		if len(feasible) == 0 {
			break
		}

		chosen := feasible[s.rng.Intn(len(feasible))]
		used[chosen.ID] = true
		for _, post := range chosen.Postconditions {
			currentState[post] = true
		}

		if currentState[target] {
			return 1.0 + (chosen.ImpactValue * 0.5)
		}
	}

	if currentState[target] {
		return 1.0
	}
	return 0.1
}

func (s *HyperMCTSSearcher) backpropagate(node *MCTSNode, reward float64) {
	for curr := node; curr != nil; curr = curr.Parent {
		curr.Visits++
		curr.TotalReward += reward
	}
}

func (s *HyperMCTSSearcher) getFeasibleNodes(state map[string]bool, used map[uuid.UUID]bool) []*HyperNode {
	all := s.graph.AllNodes()
	var feasible []*HyperNode
	for _, n := range all {
		if used[n.ID] {
			continue
		}
		if s.graph.IsSatisfiable(n, state) {
			feasible = append(feasible, n)
		}
	}
	return feasible
}

func (s *HyperMCTSSearcher) extractBestChain(root *MCTSNode, target string) *DiscoveredHyperChain {
	var steps []*HyperNode
	curr := root

	for len(curr.Children) > 0 {
		var bestChild *MCTSNode
		bestVisits := -1

		for _, child := range curr.Children {
			if child.Visits > bestVisits {
				bestVisits = child.Visits
				bestChild = child
			}
		}

		if bestChild == nil || bestChild.HyperNode == nil {
			break
		}
		steps = append(steps, bestChild.HyperNode)
		curr = bestChild

		if curr.StatePost[target] {
			break
		}
	}

	totalImpact := 0.0
	overallNovelty := 0.0
	for _, step := range steps {
		totalImpact += step.ImpactValue
		overallNovelty += step.NoveltyValue
	}
	if len(steps) > 0 {
		overallNovelty /= float64(len(steps))
	}

	return &DiscoveredHyperChain{
		Steps:            steps,
		TotalImpact:      totalImpact,
		OverallNovelty:   overallNovelty,
		TargetCapability: target,
	}
}

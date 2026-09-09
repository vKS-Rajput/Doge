package causal

import (
	"fmt"
	"sync"
)

// VariableType classifies whether a causal node is directly observable or an unobserved latent variable.
type VariableType string

const (
	VariableObserved VariableType = "observed" // e.g. status code, response body, latency, headers
	VariableLatent   VariableType = "latent"   // e.g. server-side mutex lock, cache normalize rule, thread context
)

// Variable represents a node in the Structural Causal Model (SCM).
type Variable struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Type        VariableType `json:"type"`
	Value       any          `json:"value,omitempty"`
	Dimension   string       `json:"dimension,omitempty"` // Associated latent behavioral dimension
	Parents     []string     `json:"parents"`             // Incoming causal causes
	Children    []string     `json:"children"`            // Outgoing causal effects
	Intervened  bool         `json:"intervened"`          // Whether hard do(X=x) is applied
}

// Edge represents a directed causal link between variables with a confidence weight.
type Edge struct {
	From       string  `json:"from"`
	To         string  `json:"to"`
	Weight     float64 `json:"weight"`     // Confidence in causal link [0.0, 1.0]
	Mechanism  string  `json:"mechanism"`  // Structural equation description
}

// SCMGraph represents a Structural Causal Model DAG: G = (V union U, E).
type SCMGraph struct {
	mu        sync.RWMutex
	variables map[string]*Variable
	edges     map[string]map[string]*Edge // From -> To -> Edge
}

// NewSCMGraph creates an empty Structural Causal Model.
func NewSCMGraph() *SCMGraph {
	return &SCMGraph{
		variables: make(map[string]*Variable),
		edges:     make(map[string]map[string]*Edge),
	}
}

// AddVariable registers a variable in the SCM.
func (g *SCMGraph) AddVariable(id, name string, varType VariableType, initialValue any) *Variable {
	g.mu.Lock()
	defer g.mu.Unlock()

	if v, exists := g.variables[id]; exists {
		v.Value = initialValue
		return v
	}

	v := &Variable{
		ID:       id,
		Name:     name,
		Type:     varType,
		Value:    initialValue,
		Parents:  make([]string, 0),
		Children: make([]string, 0),
	}
	g.variables[id] = v
	if _, ok := g.edges[id]; !ok {
		g.edges[id] = make(map[string]*Edge)
	}
	return v
}

// AddLatentVariable registers an unobserved latent variable discovered through interventional divergence.
func (g *SCMGraph) AddLatentVariable(id, name, dimension string, causeVar, effectVar string) *Variable {
	g.mu.Lock()
	defer g.mu.Unlock()

	v := &Variable{
		ID:        id,
		Name:      name,
		Type:      VariableLatent,
		Dimension: dimension,
		Parents:   make([]string, 0),
		Children:  make([]string, 0),
	}
	g.variables[id] = v
	if _, ok := g.edges[id]; !ok {
		g.edges[id] = make(map[string]*Edge)
	}

	// Link cause -> Latent -> effect
	if causeVar != "" && g.variables[causeVar] != nil {
		g.addEdgeInternal(causeVar, id, 0.85, "Intervention induces latent shift")
	}
	if effectVar != "" && g.variables[effectVar] != nil {
		g.addEdgeInternal(id, effectVar, 0.90, "Latent shift controls output divergence")
	}

	return v
}

// AddEdge registers a causal directed edge From -> To.
func (g *SCMGraph) AddEdge(from, to string, weight float64, mechanism string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.variables[from] == nil || g.variables[to] == nil {
		return fmt.Errorf("both variables %s and %s must exist in graph", from, to)
	}

	g.addEdgeInternal(from, to, weight, mechanism)
	return nil
}

func (g *SCMGraph) addEdgeInternal(from, to string, weight float64, mechanism string) {
	if g.edges[from] == nil {
		g.edges[from] = make(map[string]*Edge)
	}
	g.edges[from][to] = &Edge{
		From:      from,
		To:        to,
		Weight:    weight,
		Mechanism: mechanism,
	}

	// Update parents and children
	toVar := g.variables[to]
	if !containsString(toVar.Parents, from) {
		toVar.Parents = append(toVar.Parents, from)
	}
	fromVar := g.variables[from]
	if !containsString(fromVar.Children, to) {
		fromVar.Children = append(fromVar.Children, to)
	}
}

// Intervene executes Pearl's hard intervention do(X = value).
// It sets X's value and severs all incoming causal edges to X.
func (g *SCMGraph) Intervene(varID string, value any) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	v, exists := g.variables[varID]
	if !exists {
		return fmt.Errorf("variable %s not found in causal graph", varID)
	}

	v.Value = value
	v.Intervened = true

	// Sever all incoming parents (graph surgery: do(X))
	for _, parentID := range v.Parents {
		if g.edges[parentID] != nil {
			delete(g.edges[parentID], varID)
		}
		if pVar := g.variables[parentID]; pVar != nil {
			pVar.Children = removeString(pVar.Children, varID)
		}
	}
	v.Parents = make([]string, 0)
	return nil
}

// DSeparated evaluates if X and Y are conditionally independent given Z (d-separation in DAG).
func (g *SCMGraph) DSeparated(x, y string, z []string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	zSet := make(map[string]bool)
	for _, cond := range z {
		zSet[cond] = true
	}

	// BFS path finding with blocking rules (active trail evaluation)
	visited := make(map[string]bool)
	queue := []string{x}
	visited[x] = true

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if curr == y {
			return false // Active path found, not d-separated
		}

		// Traverse children
		for _, child := range g.variables[curr].Children {
			if !zSet[child] && !visited[child] {
				visited[child] = true
				queue = append(queue, child)
			}
		}

		// Traverse parents (if not blocked by conditioning set)
		for _, parent := range g.variables[curr].Parents {
			if !zSet[parent] && !visited[parent] {
				visited[parent] = true
				queue = append(queue, parent)
			}
		}
	}

	return true // No active path connects X and Y given Z
}

// ExtractCausalChain extracts the ordered causal chain from root cause to target effect.
func (g *SCMGraph) ExtractCausalChain(from, to string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var path []string
	visited := make(map[string]bool)

	var dfs func(curr string) bool
	dfs = func(curr string) bool {
		path = append(path, curr)
		visited[curr] = true
		if curr == to {
			return true
		}
		for _, child := range g.variables[curr].Children {
			if !visited[child] {
				if dfs(child) {
					return true
				}
			}
		}
		path = path[:len(path)-1]
		return false
	}

	if dfs(from) {
		return path
	}
	return nil
}

// VariableCount returns total registered nodes.
func (g *SCMGraph) VariableCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.variables)
}

// EdgeCount returns total directed causal edges.
func (g *SCMGraph) EdgeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	count := 0
	for _, dests := range g.edges {
		count += len(dests)
	}
	return count
}

func containsString(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func removeString(list []string, s string) []string {
	out := make([]string, 0, len(list))
	for _, item := range list {
		if item != s {
			out = append(out, item)
		}
	}
	return out
}

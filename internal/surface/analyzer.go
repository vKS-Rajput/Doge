package surface

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/correlation"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// Analyzer builds the attack-surface projection over the Knowledge Graph.
//
// It does NOT invent new data. It classifies, connects, and traverses
// existing entities and relationships to produce a security-oriented view.
type Analyzer struct {
	read   correlation.ReadStore
	logger *slog.Logger
}

// NewAnalyzer creates a new attack-surface analyzer.
func NewAnalyzer(read correlation.ReadStore, logger *slog.Logger) *Analyzer {
	if logger == nil {
		logger = slog.Default()
	}
	return &Analyzer{read: read, logger: logger}
}

// BuildGraph constructs the full attack-surface graph for a project.
func (a *Analyzer) BuildGraph(ctx context.Context, projectID uuid.UUID) (*Graph, error) {
	graph := &Graph{
		Nodes: make(map[uuid.UUID]Node),
		Stats: Stats{
			NodesByCategory: make(map[Category]int),
		},
	}

	// Collect all security-relevant entity types.
	entityTypes := []domain.EntityType{
		domain.EntityDomain,
		domain.EntitySubdomain,
		domain.EntityIPAddress,
		domain.EntityURL,
		domain.EntityEndpoint,
		domain.EntityPort,
		domain.EntityService,
		domain.EntityTechnology,
		domain.EntityDNSRecord,
		domain.EntityCertificate,
		domain.EntityGraphQLType,
		domain.EntityGraphQLOp,
		domain.EntityAuthMechanism,
		domain.EntitySecret,
		domain.EntityAPIKey,
	}

	for _, et := range entityTypes {
		entities, err := a.read.EntitiesByType(ctx, et, projectID)
		if err != nil {
			a.logger.Debug("skipping entity type", "type", et, "error", err)
			continue
		}

		for _, entity := range entities {
			node := a.entityToNode(ctx, entity)
			graph.Nodes[entity.ID] = node

			// Count stats.
			graph.Stats.NodesByCategory[node.Category]++
			if node.Correlated {
				graph.Stats.CorrelatedNodes++
			}
			if len(node.ToolSources) > 1 {
				graph.Stats.MultiToolNodes++
			}
		}
	}

	// Build edges from relationships.
	for id := range graph.Nodes {
		rels, err := a.read.RelationshipsForEntity(ctx, id, domain.DirectionOutgoing)
		if err != nil {
			continue
		}
		for _, rel := range rels {
			// Only include edges where both ends are in our graph.
			if _, ok := graph.Nodes[rel.TargetEntityID]; ok {
				graph.Edges = append(graph.Edges, Edge{
					Relationship: rel,
					SourceNode:   rel.SourceEntityID,
					TargetNode:   rel.TargetEntityID,
				})
			}
		}
	}

	graph.Stats.TotalNodes = len(graph.Nodes)
	graph.Stats.TotalEdges = len(graph.Edges)

	return graph, nil
}

// FindResearchPaths discovers chains through the attack surface that
// might be worth investigating.
//
// A research path is NOT a vulnerability claim. It is:
// "This is an externally reachable chain containing [interesting surface]."
func (a *Analyzer) FindResearchPaths(ctx context.Context, graph *Graph) []ResearchPath {
	var paths []ResearchPath

	// Find entry points (domains, subdomains — externally reachable).
	var entryPoints []uuid.UUID
	for id, node := range graph.Nodes {
		if node.Entity.Type == domain.EntityDomain || node.Entity.Type == domain.EntitySubdomain {
			entryPoints = append(entryPoints, id)
		}
	}

	// Build adjacency list for fast traversal.
	adj := make(map[uuid.UUID][]Edge)
	for _, edge := range graph.Edges {
		adj[edge.SourceNode] = append(adj[edge.SourceNode], edge)
	}

	// From each entry point, DFS to find paths to interesting surfaces.
	for _, entry := range entryPoints {
		visited := map[uuid.UUID]bool{entry: true}
		a.dfsPath(graph, adj, entry, []Node{graph.Nodes[entry]}, []Edge{}, visited, &paths)
	}

	// Sort by depth (deeper = more interesting structure).
	sort.Slice(paths, func(i, j int) bool {
		return paths[i].Depth > paths[j].Depth
	})

	// Cap results.
	if len(paths) > 50 {
		paths = paths[:50]
	}

	return paths
}

func (a *Analyzer) dfsPath(
	graph *Graph,
	adj map[uuid.UUID][]Edge,
	current uuid.UUID,
	nodePath []Node,
	edgePath []Edge,
	visited map[uuid.UUID]bool,
	results *[]ResearchPath,
) {
	currentNode := graph.Nodes[current]

	// If this node is an interesting surface (not just web/network), emit a path.
	if len(nodePath) >= 2 && isInterestingSurface(currentNode.Category) {
		path := buildResearchPath(nodePath, edgePath)
		*results = append(*results, path)
	}

	// Continue traversal (max depth 6).
	if len(nodePath) >= 6 {
		return
	}

	for _, edge := range adj[current] {
		next := edge.TargetNode
		if visited[next] {
			continue
		}

		nextNode, ok := graph.Nodes[next]
		if !ok {
			continue
		}

		visited[next] = true
		a.dfsPath(graph, adj, next, append(nodePath, nextNode), append(edgePath, edge), visited, results)
		visited[next] = false
	}
}

func isInterestingSurface(c Category) bool {
	switch c {
	case CategoryUpload, CategoryAuthentication, CategoryAuthorization, CategoryAPI:
		return true
	default:
		return false
	}
}

func buildResearchPath(nodes []Node, edges []Edge) ResearchPath {
	// Collect distinct categories.
	catSet := make(map[Category]bool)
	var catList []Category
	for _, n := range nodes {
		if !catSet[n.Category] {
			catSet[n.Category] = true
			catList = append(catList, n.Category)
		}
	}

	// Build description.
	parts := make([]string, len(nodes))
	for i, n := range nodes {
		parts[i] = n.Entity.Value
	}
	lastNode := nodes[len(nodes)-1]
	desc := fmt.Sprintf("Reachable chain: %s → %s surface (%s)",
		nodes[0].Entity.Value,
		lastNode.Category,
		strings.Join(parts, " → "))

	return ResearchPath{
		Nodes:             nodes,
		Edges:             edges,
		Description:       desc,
		SurfaceCategories: catList,
		Depth:             len(nodes) - 1,
	}
}

func (a *Analyzer) entityToNode(ctx context.Context, entity domain.Entity) Node {
	node := Node{
		Entity:   entity,
		Category: ClassifyEntity(entity),
	}

	// Get observation metadata.
	obs, err := a.read.ObservationsForEntity(ctx, entity.ID)
	if err == nil {
		node.ObservationCount = len(obs)

		toolSet := make(map[string]bool)
		for _, o := range obs {
			if o.SourceTool != "" {
				toolSet[o.SourceTool] = true
			}
		}
		for t := range toolSet {
			node.ToolSources = append(node.ToolSources, t)
		}
		sort.Strings(node.ToolSources)

		if len(node.ToolSources) > 1 {
			node.Correlated = true
		}
	}

	return node
}

// SurfaceSummary produces a human-readable summary of the attack surface.
func SurfaceSummary(g *Graph) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Attack Surface: %d nodes, %d edges\n\n", g.Stats.TotalNodes, g.Stats.TotalEdges))

	// Sort categories for stable output.
	cats := make([]Category, 0, len(g.Stats.NodesByCategory))
	for c := range g.Stats.NodesByCategory {
		cats = append(cats, c)
	}
	sort.Slice(cats, func(i, j int) bool { return string(cats[i]) < string(cats[j]) })

	for _, c := range cats {
		sb.WriteString(fmt.Sprintf("  %-20s %d\n", c, g.Stats.NodesByCategory[c]))
	}

	sb.WriteString(fmt.Sprintf("\nCorrelated nodes:  %d\n", g.Stats.CorrelatedNodes))
	sb.WriteString(fmt.Sprintf("Multi-tool nodes:  %d\n", g.Stats.MultiToolNodes))

	return sb.String()
}

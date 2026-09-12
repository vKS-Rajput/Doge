package researcher

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/internal/attackgraph"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// ChainResearcher constructs and explores multi-step attack chains, linking
// initial reconnaissance or low-severity findings into high-impact compromise paths.
type ChainResearcher struct {
	httpClient  HTTPClient
	attackGraph *attackgraph.Graph
}

// NewChainResearcher creates a new attack chain researcher.
func NewChainResearcher(httpClient HTTPClient, graph *attackgraph.Graph) *ChainResearcher {
	if graph == nil {
		graph = attackgraph.NewGraph()
	}
	return &ChainResearcher{
		httpClient:  httpClient,
		attackGraph: graph,
	}
}

// Type returns domain.ResearcherChain.
func (r *ChainResearcher) Type() domain.ResearcherType {
	return domain.ResearcherChain
}

// Execute searches for traversable paths in the attack graph that achieve mission goals.
func (r *ChainResearcher) Execute(ctx context.Context, brief *domain.MissionBrief) (*domain.MissionResult, error) {
	start := time.Now()
	result := &domain.MissionResult{
		MissionID:      brief.ID,
		ResearcherType: domain.ResearcherChain,
		Status:         domain.MissionActive,
	}

	// 1. Ingest known endpoints and credentials into attack graph as nodes
	for _, ep := range brief.KnownEndpoints {
		r.attackGraph.AddNode(attackgraph.NodeResource, ep, fmt.Sprintf("Endpoint: %s", ep), 0.90)
	}

	for credName := range brief.Credentials {
		r.attackGraph.AddNode(attackgraph.NodePrincipal, credName, fmt.Sprintf("Identity: %s", credName), 0.95)
	}

	// 2. Discover potential chains between discovered entities
	searcher := attackgraph.NewChainSearcher(r.attackGraph)
	paths := searcher.FindChains(5)
	for _, path := range paths {
		if path.TotalSteps > 1 {
			result.Observations = append(result.Observations, domain.MissionObservation{
				Type:        "attack_chain_discovered",
				Description: fmt.Sprintf("Discovered attack path with %d steps", path.TotalSteps),
				Details:     map[string]any{"steps": path.TotalSteps, "min_conf": path.MinConfidence},
				ObservedAt:  time.Now().UTC(),
			})

			cand := domain.CandidateVulnerability{
				ID:          uuid.New(),
				Type:        "ATTACK_GRAPH_COMPOSITE_CHAIN",
				Title:       fmt.Sprintf("Composite Attack Chain: %d steps to Impact", path.TotalSteps),
				Description: fmt.Sprintf("Multi-step vulnerability chain linking %d components to achieve privileged access.", path.TotalSteps),
				Severity:    string(domain.SeverityCritical),
				Endpoint:    brief.TargetBaseURL,
				DiscoveredAt: time.Now().UTC(),
			}
			result.CandidateFindings = append(result.CandidateFindings, cand)
		}
	}

	result.Duration = time.Since(start)
	result.Status = domain.MissionCompleted
	result.Summary = fmt.Sprintf("Attack Chain Research: %d nodes modeled, %d attack paths identified, %d candidate chains synthesized",
		r.attackGraph.NodeCount(), len(paths), len(result.CandidateFindings))

	return result, nil
}

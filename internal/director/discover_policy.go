package director

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// DiscoverPolicy generates unknown-space exploration missions.
// It seeks out unmodeled behavior, metamorphic differential anomalies,
// and trace patterns that feed the dynamic invariant induction engine.
type DiscoverPolicy struct{}

// NewDiscoverPolicy creates a new discovery policy.
func NewDiscoverPolicy() *DiscoverPolicy {
	return &DiscoverPolicy{}
}

// PlanDiscoveryMission generates an exploration mission focused on unknown space.
func (dp *DiscoverPolicy) PlanDiscoveryMission(
	targetURL string,
	credentials map[string]string,
	knownEndpoints []string,
	untestedUnknowns []string,
) *domain.MissionBrief {
	// 1. Look for batch, bulk, or pipelined endpoints that might hide context bleed
	for _, ep := range knownEndpoints {
		low := strings.ToLower(ep)
		if strings.Contains(low, "batch") || strings.Contains(low, "bulk") || strings.Contains(low, "pipe") {
			return &domain.MissionBrief{
				ID:             uuid.New(),
				ResearcherType: domain.ResearcherAnomaly, // Handled by discovery prober
				Title:          "Unknown-Space Probing: Batch Pipeline Isolation",
				Description:    "Execute metamorphic order-inversion and identity-pairing probes on batch pipeline to test context isolation.",
				TargetBaseURL:  targetURL,
				Credentials:    credentials,
				KnownEndpoints: []string{ep},
				Unknowns:       untestedUnknowns,
				MaxRequests:    30,
				MaxDuration:    45 * time.Second,
				SuccessCriteria: "Metamorphic relation evaluated and traces captured for invariant induction",
			}
		}
	}

	// 2. Default exploratory probe on API endpoints
	return &domain.MissionBrief{
		ID:              uuid.New(),
		ResearcherType:  domain.ResearcherAnomaly,
		Title:           "Unknown-Space Behavioral Novelty Probing",
		Description:     "Explore parameter combinations and edge conditions to induce behavioral invariants.",
		TargetBaseURL:   targetURL,
		Credentials:     credentials,
		KnownEndpoints:  knownEndpoints,
		Unknowns:        untestedUnknowns,
		MaxRequests:     25,
		MaxDuration:     30 * time.Second,
		SuccessCriteria: "Behavioral traces collected for invariant engine",
	}
}

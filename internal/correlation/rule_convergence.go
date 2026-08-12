package correlation

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// ConvergenceRule finds endpoints independently discovered by multiple tools.
//
// Example:
//
//	ffuf:   /admin/upload → 200
//	katana: /admin/upload (crawled)
//
// Result: independent_convergence correlation (confidence: 0.85)
//
// Two independent tools discovering the same endpoint is stronger
// evidence of existence than a single tool's report.
// This is NOT a vulnerability claim.
type ConvergenceRule struct {
	projectID uuid.UUID
}

// NewConvergenceRule creates a new convergence rule.
func NewConvergenceRule(projectID uuid.UUID) *ConvergenceRule {
	return &ConvergenceRule{projectID: projectID}
}

func (r *ConvergenceRule) Name() string { return "convergence" }

func (r *ConvergenceRule) Evaluate(ctx context.Context, store ReadStore) ([]domain.Correlation, error) {
	var correlations []domain.Correlation

	// Check endpoints discovered by multiple tools.
	endpoints, err := store.EntitiesByType(ctx, domain.EntityEndpoint, r.projectID)
	if err != nil {
		return nil, fmt.Errorf("query endpoints: %w", err)
	}

	for _, entity := range endpoints {
		obs, err := store.ObservationsForEntity(ctx, entity.ID)
		if err != nil {
			continue
		}

		tools := distinctTools(obs)
		if len(tools) < 2 {
			continue
		}

		// Check for independent discovery (different observation types).
		types := distinctObsTypes(obs)
		if len(types) < 2 {
			continue // Same tool type doesn't count as convergence.
		}

		obsIDs := observationIDs(obs)

		correlations = append(correlations, domain.Correlation{
			ID:             uuid.New(),
			EntityIDs:      []uuid.UUID{entity.ID},
			Type:           domain.CorrelationConvergence,
			Confidence:     convergenceConfidence(len(tools)),
			Description:    fmt.Sprintf("Endpoint %s independently discovered by %d methods: %s", entity.Value, len(tools), fmt.Sprintf("%v", tools)),
			ObservationIDs: obsIDs,
			ProjectID:      r.projectID,
			CreatedAt:      time.Now().UTC(),
			LastSeenAt:     time.Now().UTC(),
		})
	}

	// Also check URLs.
	urls, err := store.EntitiesByType(ctx, domain.EntityURL, r.projectID)
	if err != nil {
		return correlations, nil
	}

	for _, entity := range urls {
		obs, err := store.ObservationsForEntity(ctx, entity.ID)
		if err != nil {
			continue
		}

		tools := distinctTools(obs)
		types := distinctObsTypes(obs)
		if len(tools) < 2 || len(types) < 2 {
			continue
		}

		obsIDs := observationIDs(obs)

		correlations = append(correlations, domain.Correlation{
			ID:             uuid.New(),
			EntityIDs:      []uuid.UUID{entity.ID},
			Type:           domain.CorrelationConvergence,
			Confidence:     convergenceConfidence(len(tools)),
			Description:    fmt.Sprintf("URL %s independently discovered by %d methods: %s", entity.Value, len(tools), fmt.Sprintf("%v", tools)),
			ObservationIDs: obsIDs,
			ProjectID:      r.projectID,
			CreatedAt:      time.Now().UTC(),
			LastSeenAt:     time.Now().UTC(),
		})
	}

	return correlations, nil
}

func convergenceConfidence(toolCount int) float64 {
	switch {
	case toolCount >= 3:
		return 0.95
	default:
		return 0.85
	}
}

func distinctObsTypes(obs []domain.Observation) []string {
	seen := make(map[domain.ObservationType]bool)
	for _, o := range obs {
		seen[o.Type] = true
	}
	types := make([]string, 0, len(seen))
	for t := range seen {
		types = append(types, string(t))
	}
	return types
}

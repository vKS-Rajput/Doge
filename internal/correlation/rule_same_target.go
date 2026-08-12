package correlation

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// SameTargetRule finds entities observed by multiple independent tools.
//
// Example:
//
//	subfinder → admin.example.com
//	httpx     → admin.example.com
//	katana    → admin.example.com
//
// Result: same_target correlation (confidence: 0.95)
//
// This is a cross-tool correlation: requires ≥2 distinct source tools.
type SameTargetRule struct {
	projectID uuid.UUID
}

// NewSameTargetRule creates a new same-target rule for a project.
func NewSameTargetRule(projectID uuid.UUID) *SameTargetRule {
	return &SameTargetRule{projectID: projectID}
}

func (r *SameTargetRule) Name() string { return "same_target" }

func (r *SameTargetRule) Evaluate(ctx context.Context, store ReadStore) ([]domain.Correlation, error) {
	var correlations []domain.Correlation

	// Check subdomains observed by multiple tools.
	subdomains, err := store.EntitiesByType(ctx, domain.EntitySubdomain, r.projectID)
	if err != nil {
		return nil, fmt.Errorf("query subdomains: %w", err)
	}

	for _, entity := range subdomains {
		obs, err := store.ObservationsForEntity(ctx, entity.ID)
		if err != nil {
			continue
		}

		tools := distinctTools(obs)
		if len(tools) < 2 {
			continue
		}

		obsIDs := observationIDs(obs)

		correlations = append(correlations, domain.Correlation{
			ID:             uuid.New(),
			EntityIDs:      []uuid.UUID{entity.ID},
			Type:           domain.CorrelationSameTarget,
			Confidence:     sameTargetConfidence(len(tools)),
			Description:    fmt.Sprintf("Host %s observed by %d tools: %s", entity.Value, len(tools), strings.Join(tools, ", ")),
			ObservationIDs: obsIDs,
			ProjectID:      r.projectID,
			CreatedAt:      time.Now().UTC(),
			LastSeenAt:     time.Now().UTC(),
		})
	}

	// Check URLs observed by multiple tools.
	urls, err := store.EntitiesByType(ctx, domain.EntityURL, r.projectID)
	if err != nil {
		return correlations, nil // Return what we have.
	}

	for _, entity := range urls {
		obs, err := store.ObservationsForEntity(ctx, entity.ID)
		if err != nil {
			continue
		}

		tools := distinctTools(obs)
		if len(tools) < 2 {
			continue
		}

		obsIDs := observationIDs(obs)
		host := extractHostFromURL(entity.Value)

		correlations = append(correlations, domain.Correlation{
			ID:             uuid.New(),
			EntityIDs:      []uuid.UUID{entity.ID},
			Type:           domain.CorrelationSameTarget,
			Confidence:     sameTargetConfidence(len(tools)),
			Description:    fmt.Sprintf("URL %s observed by %d tools: %s", host, len(tools), strings.Join(tools, ", ")),
			ObservationIDs: obsIDs,
			ProjectID:      r.projectID,
			CreatedAt:      time.Now().UTC(),
			LastSeenAt:     time.Now().UTC(),
		})
	}

	return correlations, nil
}

func sameTargetConfidence(toolCount int) float64 {
	switch {
	case toolCount >= 4:
		return 0.98
	case toolCount >= 3:
		return 0.95
	default:
		return 0.90
	}
}

// --- helpers ---

func distinctTools(obs []domain.Observation) []string {
	seen := make(map[string]bool)
	for _, o := range obs {
		if o.SourceTool != "" {
			seen[o.SourceTool] = true
		}
	}
	tools := make([]string, 0, len(seen))
	for t := range seen {
		tools = append(tools, t)
	}
	return tools
}

func observationIDs(obs []domain.Observation) []uuid.UUID {
	ids := make([]uuid.UUID, len(obs))
	for i, o := range obs {
		ids[i] = o.ID
	}
	return ids
}

func extractHostFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if parsed.Host != "" {
		return parsed.Host
	}
	return rawURL
}

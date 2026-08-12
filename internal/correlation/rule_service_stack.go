package correlation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// ServiceStackRule groups port, service, and technology entities into
// a unified technology stack for a single host.
//
// Example:
//
//	nmap:  443/tcp → nginx
//	httpx: nginx detected, jQuery detected
//
// Result: service_stack correlation (confidence: 0.90)
//
// This is cross-tool: requires port/service info from one tool
// and technology info from another.
type ServiceStackRule struct {
	projectID uuid.UUID
}

// NewServiceStackRule creates a new service stack rule.
func NewServiceStackRule(projectID uuid.UUID) *ServiceStackRule {
	return &ServiceStackRule{projectID: projectID}
}

func (r *ServiceStackRule) Name() string { return "service_stack" }

func (r *ServiceStackRule) Evaluate(ctx context.Context, store ReadStore) ([]domain.Correlation, error) {
	var correlations []domain.Correlation

	// Find all IP addresses or subdomains that have both port and technology info.
	ipEntities, err := store.EntitiesByType(ctx, domain.EntityIPAddress, r.projectID)
	if err != nil {
		return nil, fmt.Errorf("query IPs: %w", err)
	}

	subdomains, err := store.EntitiesByType(ctx, domain.EntitySubdomain, r.projectID)
	if err != nil {
		return nil, fmt.Errorf("query subdomains: %w", err)
	}

	// Combine hosts to check.
	hosts := append(ipEntities, subdomains...)

	for _, host := range hosts {
		rels, err := store.RelationshipsForEntity(ctx, host.ID, domain.DirectionOutgoing)
		if err != nil {
			continue
		}

		var portEntities []uuid.UUID
		var techEntities []uuid.UUID
		var serviceEntities []uuid.UUID

		for _, rel := range rels {
			switch rel.Type {
			case domain.RelListensOn:
				portEntities = append(portEntities, rel.TargetEntityID)
			case domain.RelUsesTechnology:
				techEntities = append(techEntities, rel.TargetEntityID)
			case domain.RelRunsService:
				serviceEntities = append(serviceEntities, rel.TargetEntityID)
			}
		}

		// Need at least port + (tech or service) to form a stack.
		if len(portEntities) == 0 || (len(techEntities) == 0 && len(serviceEntities) == 0) {
			continue
		}

		// Gather all entities in the stack.
		stackEntities := []uuid.UUID{host.ID}
		stackEntities = append(stackEntities, portEntities...)
		stackEntities = append(stackEntities, techEntities...)
		stackEntities = append(stackEntities, serviceEntities...)

		// Gather observations from all stack entities.
		var allObs []domain.Observation
		for _, entityID := range stackEntities {
			obs, err := store.ObservationsForEntity(ctx, entityID)
			if err != nil {
				continue
			}
			allObs = append(allObs, obs...)
		}

		tools := distinctTools(allObs)
		if len(tools) < 2 {
			continue // Needs cross-tool evidence.
		}

		obsIDs := observationIDs(allObs)

		// Build description.
		parts := []string{host.Value}
		if len(portEntities) > 0 {
			parts = append(parts, fmt.Sprintf("%d ports", len(portEntities)))
		}
		if len(serviceEntities) > 0 {
			parts = append(parts, fmt.Sprintf("%d services", len(serviceEntities)))
		}
		if len(techEntities) > 0 {
			parts = append(parts, fmt.Sprintf("%d technologies", len(techEntities)))
		}

		correlations = append(correlations, domain.Correlation{
			ID:             uuid.New(),
			EntityIDs:      stackEntities,
			Type:           domain.CorrelationServiceStack,
			Confidence:     0.90,
			Description:    fmt.Sprintf("Service stack on %s: %s (from %s)", host.Value, strings.Join(parts[1:], ", "), strings.Join(tools, ", ")),
			ObservationIDs: obsIDs,
			ProjectID:      r.projectID,
			CreatedAt:      time.Now().UTC(),
			LastSeenAt:     time.Now().UTC(),
		})
	}

	return correlations, nil
}

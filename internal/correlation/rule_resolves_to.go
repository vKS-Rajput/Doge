package correlation

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// ResolvesToRule connects hostnames to IP addresses via DNS evidence,
// and optionally links them to port scan observations on the resolved IP.
//
// Example:
//
//	dnsx: admin.example.com → 203.0.113.10
//	nmap: 203.0.113.10:443 → nginx
//
// Result:
//   - resolves_to correlation (confidence: 0.90)
//   - Materializes a resolves_to Relationship in the Knowledge Graph
//
// The correlation is the REASONING that established the relationship.
// The relationship is the resulting GRAPH STRUCTURE.
type ResolvesToRule struct {
	projectID uuid.UUID
	writer    WriteStore
}

// NewResolvesToRule creates a new resolves_to rule.
func NewResolvesToRule(projectID uuid.UUID, writer WriteStore) *ResolvesToRule {
	return &ResolvesToRule{projectID: projectID, writer: writer}
}

func (r *ResolvesToRule) Name() string { return "resolves_to" }

func (r *ResolvesToRule) Evaluate(ctx context.Context, store ReadStore) ([]domain.Correlation, error) {
	var correlations []domain.Correlation

	// Find all subdomain entities.
	subdomains, err := store.EntitiesByType(ctx, domain.EntitySubdomain, r.projectID)
	if err != nil {
		return nil, fmt.Errorf("query subdomains: %w", err)
	}

	for _, subdomain := range subdomains {
		obs, err := store.ObservationsForEntity(ctx, subdomain.ID)
		if err != nil {
			continue
		}

		// Find DNS observations with A/AAAA records.
		for _, o := range obs {
			if o.Type != domain.ObservationDNSLookup {
				continue
			}

			// Extract resolved IPs from observation data.
			ips := extractIPs(o.Data)
			if len(ips) == 0 {
				continue
			}

			for _, ip := range ips {
				// Find the IP entity in the graph.
				ipEntity, err := store.EntityByTypeAndValue(ctx, domain.EntityIPAddress, ip, r.projectID)
				if err != nil || ipEntity == nil {
					continue
				}

				// Gather all supporting observations.
				allObs := []uuid.UUID{o.ID}

				// Check if we have nmap/port observations on this IP.
				ipObs, err := store.ObservationsForEntity(ctx, ipEntity.ID)
				if err == nil {
					for _, ipo := range ipObs {
						if ipo.Type == domain.ObservationPortScan {
							allObs = append(allObs, ipo.ID)
						}
					}
				}

				// Compute confidence based on evidence strength.
				confidence := 0.85
				if len(allObs) >= 2 {
					confidence = 0.90 // DNS + port scan = stronger
				}

				corr := domain.Correlation{
					ID:             uuid.New(),
					EntityIDs:      []uuid.UUID{subdomain.ID, ipEntity.ID},
					Type:           domain.CorrelationResolvesTo,
					Confidence:     confidence,
					Description:    fmt.Sprintf("DNS resolution: %s → %s", subdomain.Value, ip),
					ObservationIDs: allObs,
					ProjectID:      r.projectID,
					CreatedAt:      time.Now().UTC(),
					LastSeenAt:     time.Now().UTC(),
				}

				correlations = append(correlations, corr)

				// Materialize as graph relationship.
				// Correlation → Relationship pipeline.
				if r.writer != nil {
					now := time.Now().UTC()
					_ = r.writer.MaterializeRelationship(ctx, domain.Relationship{
						ID:             uuid.New(),
						SourceEntityID: subdomain.ID,
						TargetEntityID: ipEntity.ID,
						Type:           domain.RelResolvesTo,
						Attributes:     map[string]any{"source": "correlation", "rule": "resolves_to"},
						ObservationID:  &o.ID,
						ProjectID:      r.projectID,
						FirstSeenAt:    now,
						LastSeenAt:     now,
					})
				}
			}
		}
	}

	return correlations, nil
}

func extractIPs(data map[string]any) []string {
	var ips []string

	// A records.
	if aRecords, ok := data["a"]; ok {
		switch v := aRecords.(type) {
		case []string:
			ips = append(ips, v...)
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					ips = append(ips, s)
				}
			}
		}
	}

	// AAAA records.
	if aaaaRecords, ok := data["aaaa"]; ok {
		switch v := aaaaRecords.(type) {
		case []string:
			ips = append(ips, v...)
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					ips = append(ips, s)
				}
			}
		}
	}

	return ips
}

package researcher

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// MetamorphicResearcher tests metamorphic relations such as order-permutation invariance,
// identity-pairing isolation, and idempotent transformation across target endpoints.
type MetamorphicResearcher struct {
	httpClient HTTPClient
}

// NewMetamorphicResearcher creates a new metamorphic researcher.
func NewMetamorphicResearcher(httpClient HTTPClient) *MetamorphicResearcher {
	return &MetamorphicResearcher{httpClient: httpClient}
}

// Type returns domain.ResearcherMetamorphic.
func (r *MetamorphicResearcher) Type() domain.ResearcherType {
	return domain.ResearcherMetamorphic
}

// Execute performs 3-way differential metamorphic experiments (forward, inverted, control).
func (r *MetamorphicResearcher) Execute(ctx context.Context, brief *domain.MissionBrief) (*domain.MissionResult, error) {
	start := time.Now()
	result := &domain.MissionResult{
		MissionID:      brief.ID,
		ResearcherType: domain.ResearcherMetamorphic,
		Status:         domain.MissionActive,
	}
	requestCount := 0

	authHeaders := make(map[string]string)
	for _, token := range brief.Credentials {
		authHeaders["Authorization"] = "Bearer " + token
		authHeaders["Content-Type"] = "application/json"
		break
	}

	for _, ep := range brief.KnownEndpoints {
		if requestCount+3 > brief.MaxRequests {
			break
		}

		// Check if endpoint is a batch/bulk/pipeline endpoint
		low := strings.ToLower(ep)
		if strings.Contains(low, "batch") || strings.Contains(low, "bulk") || strings.Contains(low, "pipe") {
			// Metamorphic Test 1: Forward Order (Auth Op -> Unauth Op)
			bodyForward := `{"operations": [{"auth": true, "action": "login"}, {"auth": false, "action": "read_secret"}]}`
			evFwd, err := r.httpClient.Do(ctx, "POST", ep, authHeaders, bodyForward)
			if err != nil {
				continue
			}
			requestCount++
			evFwd.Description = fmt.Sprintf("Metamorphic forward order on %s", ep)
			result.Evidence = append(result.Evidence, *evFwd)

			// Metamorphic Test 2: Inverted Order (Unauth Op -> Auth Op)
			bodyInverted := `{"operations": [{"auth": false, "action": "read_secret"}, {"auth": true, "action": "login"}]}`
			evInv, err := r.httpClient.Do(ctx, "POST", ep, authHeaders, bodyInverted)
			if err != nil {
				continue
			}
			requestCount++
			evInv.Description = fmt.Sprintf("Metamorphic inverted order on %s", ep)
			result.Evidence = append(result.Evidence, *evInv)

			// Metamorphic Test 3: Standalone Negative Control (Unauth Op alone)
			bodyControl := `{"operations": [{"auth": false, "action": "read_secret"}]}`
			evCtrl, err := r.httpClient.Do(ctx, "POST", ep, nil, bodyControl)
			if err != nil {
				continue
			}
			requestCount++
			evCtrl.Description = fmt.Sprintf("Metamorphic negative control on %s", ep)
			result.Evidence = append(result.Evidence, *evCtrl)

			// Check for Metamorphic Relation Violation:
			// If forward execution succeeds for unauth op (context bleed from preceding auth op),
			// but inverted execution fails, an order-dependent context bleed invariant is violated.
			if strings.Contains(evFwd.ResponseBody, "secret") && !strings.Contains(evCtrl.ResponseBody, "secret") {
				cand := domain.CandidateVulnerability{
					ID:          uuid.New(),
					Type:        "METAMORPHIC_ORDER_DEPENDENT_CONTEXT_BLEED",
					Title:       fmt.Sprintf("Metamorphic Context Bleed in Batch Pipeline on %s", ep),
					Description: fmt.Sprintf("Sub-operations in batch pipeline on %s inherit authorization context from preceding operations, violating execution frame isolation.", ep),
					Severity:    string(domain.SeverityCritical),
					Endpoint:    ep,
					DiscoveredAt: time.Now().UTC(),
				}
				result.CandidateFindings = append(result.CandidateFindings, cand)
			}
		}
	}

	result.RequestsMade = requestCount
	result.Duration = time.Since(start)
	result.Status = domain.MissionCompleted
	result.Summary = fmt.Sprintf("Metamorphic Research: %d requests made across batch/pipeline endpoints, %d candidate findings discovered",
		requestCount, len(result.CandidateFindings))

	return result, nil
}

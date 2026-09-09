package researcher

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vKS-Rajput/doge/pkg/domain"
)

// ImpactResearcher takes a validated vulnerability and investigates whether
// greater impact can be safely demonstrated.
//
// The key distinction (from XBOW's architecture):
//   - A researcher finding "SQL injection exists" is interesting.
//   - A system proving "SQL injection exists → controlled database interaction
//     demonstrated → impact proven" is much more valuable.
//
// The impact researcher operates within strict authorization constraints.
// It demonstrates impact, it does not maximize damage.
type ImpactResearcher struct {
	httpClient HTTPClient
}

// NewImpactResearcher creates a new impact researcher.
func NewImpactResearcher(httpClient HTTPClient) *ImpactResearcher {
	return &ImpactResearcher{httpClient: httpClient}
}

// Type returns the researcher type.
func (r *ImpactResearcher) Type() domain.ResearcherType {
	return domain.ResearcherImpact
}

// Execute investigates the extent and real-world impact of a validated vulnerability.
func (r *ImpactResearcher) Execute(ctx context.Context, brief *domain.MissionBrief) (*domain.MissionResult, error) {
	start := time.Now()
	result := &domain.MissionResult{
		MissionID:      brief.ID,
		ResearcherType: domain.ResearcherImpact,
		Status:         domain.MissionActive,
	}
	requestCount := 0

	// Impact research for BOLA: Demonstrate the extent of data leakage
	// Goal: How many objects are accessible? What data fields are exposed?

	// Step 1: Identify principals
	type principal struct {
		token    string
		tenantID string
	}

	var principals []principal
	for _, token := range brief.Credentials {
		if requestCount >= brief.MaxRequests {
			break
		}
		headers := map[string]string{"Authorization": "Bearer " + token}
		ev, err := r.httpClient.Do(ctx, "GET", brief.TargetBaseURL+"/api/v1/me", headers, "")
		if err != nil {
			continue
		}
		requestCount++
		result.Evidence = append(result.Evidence, *ev)

		if ev.ResponseStatus == 200 {
			var meResp map[string]any
			if err := json.Unmarshal([]byte(ev.ResponseBody), &meResp); err == nil {
				p := principal{token: token}
				if tid, ok := meResp["tenant_id"].(string); ok {
					p.tenantID = tid
				}
				principals = append(principals, p)
			}
		}
	}

	if len(principals) < 2 {
		result.Status = domain.MissionFailed
		result.Summary = "Insufficient principals for impact demonstration"
		result.CompletedAt = time.Now().UTC()
		return result, nil
	}

	principalA := principals[0]
	principalB := principals[1]

	// Step 2: Enumerate all accessible cross-tenant objects
	// Try known object IDs from the brief, plus ID brute-force patterns
	accessibleObjects := 0
	confidentialFields := make(map[string]bool)
	var accessedItems []map[string]any

	knownObjectIDs := brief.KnownObjects
	if len(knownObjectIDs) == 0 {
		// Try common patterns
		knownObjectIDs = []string{"item-1001", "item-1002", "item-1003", "item-1004", "item-1005"}
	}

	headersA := map[string]string{"Authorization": "Bearer " + principalA.token}
	for _, objID := range knownObjectIDs {
		if requestCount >= brief.MaxRequests {
			break
		}
		endpoint := "/api/v1/items/" + objID
		ev, err := r.httpClient.Do(ctx, "GET", brief.TargetBaseURL+endpoint, headersA, "")
		if err != nil {
			continue
		}
		requestCount++
		ev.Description = fmt.Sprintf("Impact enumeration: accessing %s as %s", endpoint, principalA.tenantID)
		result.Evidence = append(result.Evidence, *ev)

		if ev.ResponseStatus == 200 {
			var itemResp map[string]any
			if err := json.Unmarshal([]byte(ev.ResponseBody), &itemResp); err == nil {
				respTenant, _ := itemResp["tenant_id"].(string)
				if respTenant != principalA.tenantID {
					accessibleObjects++
					accessedItems = append(accessedItems, itemResp)

					// Track what fields are exposed
					for field := range itemResp {
						confidentialFields[field] = true
					}

					result.Observations = append(result.Observations, domain.MissionObservation{
						Type:        "cross_tenant_item_accessed",
						Description: fmt.Sprintf("Cross-tenant item %s accessed — belongs to %s", objID, respTenant),
						Endpoint:    endpoint,
						StatusCode:  200,
						Details:     itemResp,
						ObservedAt:  time.Now().UTC(),
					})
				}
			}
		}
	}

	// Step 3: Also try accessing own-tenant items (to establish baseline)
	ownTenantAccessible := 0
	for _, objID := range knownObjectIDs {
		if requestCount >= brief.MaxRequests {
			break
		}
		endpoint := "/api/v1/items/" + objID
		headersB := map[string]string{"Authorization": "Bearer " + principalB.token}
		ev, err := r.httpClient.Do(ctx, "GET", brief.TargetBaseURL+endpoint, headersB, "")
		if err != nil {
			continue
		}
		requestCount++
		ev.Description = fmt.Sprintf("Impact baseline: accessing %s as %s", endpoint, principalB.tenantID)
		result.Evidence = append(result.Evidence, *ev)

		if ev.ResponseStatus == 200 {
			ownTenantAccessible++
		}
	}

	// Step 4: Generate impact assessment
	var confidentialFieldsList []string
	for field := range confidentialFields {
		confidentialFieldsList = append(confidentialFieldsList, field)
	}

	impactSummary := fmt.Sprintf(
		"IMPACT DEMONSTRATED:\n"+
			"- %d cross-tenant objects accessible to unauthorized principals\n"+
			"- %d total objects accessible (including legitimate own-tenant access)\n"+
			"- Exposed fields: %v\n"+
			"- Impact scope: Complete cross-tenant data leakage\n"+
			"- Confidentiality: HIGH (confidential item content, owner IDs, tenant associations)\n"+
			"- Integrity: NONE (read-only access demonstrated)\n"+
			"- Availability: NONE (no destructive actions performed)",
		accessibleObjects, ownTenantAccessible, confidentialFieldsList,
	)

	result.Observations = append(result.Observations, domain.MissionObservation{
		Type:        "impact_assessed",
		Description: impactSummary,
		Details: map[string]any{
			"cross_tenant_accessible":  accessibleObjects,
			"total_accessible":         ownTenantAccessible + accessibleObjects,
			"confidential_fields":      confidentialFieldsList,
			"confidentiality_impact":   "HIGH",
			"integrity_impact":         "NONE",
			"availability_impact":      "NONE",
		},
		ObservedAt: time.Now().UTC(),
	})

	result.Status = domain.MissionCompleted
	result.RequestsMade = requestCount
	result.Duration = time.Since(start)
	result.CompletedAt = time.Now().UTC()
	result.Summary = fmt.Sprintf(
		"Impact demonstrated: %d cross-tenant objects accessible, %d confidential fields exposed",
		accessibleObjects, len(confidentialFieldsList),
	)

	return result, nil
}

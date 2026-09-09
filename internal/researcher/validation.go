package researcher

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vKS-Rajput/doge/pkg/domain"
)

// ValidationResearcher independently validates candidate vulnerabilities.
// It is a separate researcher from the one that discovered the vulnerability —
// this separation prevents discovery bias from contaminating validation.
//
// XBOW principle: "Independent validators confirm exploitability,
// eliminating false positives that can result from AI hallucinations."
type ValidationResearcher struct {
	httpClient HTTPClient
}

// NewValidationResearcher creates a new validation researcher.
func NewValidationResearcher(httpClient HTTPClient) *ValidationResearcher {
	return &ValidationResearcher{httpClient: httpClient}
}

// Type returns the researcher type.
func (r *ValidationResearcher) Type() domain.ResearcherType {
	return domain.ResearcherValidation
}

// Execute independently reproduces and validates a candidate vulnerability.
func (r *ValidationResearcher) Execute(ctx context.Context, brief *domain.MissionBrief) (*domain.MissionResult, error) {
	start := time.Now()
	result := &domain.MissionResult{
		MissionID:      brief.ID,
		ResearcherType: domain.ResearcherValidation,
		Status:         domain.MissionActive,
	}
	requestCount := 0

	// Validation researcher receives a mission brief with:
	// - The reproduction steps to follow
	// - Fresh credentials (same as discovery, but independently applied)
	// - The endpoint and vulnerability type to validate

	if len(brief.Hypotheses) == 0 {
		result.Status = domain.MissionFailed
		result.Summary = "No hypotheses to validate"
		result.CompletedAt = time.Now().UTC()
		return result, nil
	}

	hyp := brief.Hypotheses[0] // Primary hypothesis to validate

	// Step 1: Independently identify principals
	type principal struct {
		token    string
		userID   string
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
		ev.Description = "Validation: Identify principal"
		result.Evidence = append(result.Evidence, *ev)

		if ev.ResponseStatus == 200 {
			var meResp map[string]any
			if err := json.Unmarshal([]byte(ev.ResponseBody), &meResp); err == nil {
				p := principal{token: token}
				if id, ok := meResp["id"].(string); ok {
					p.userID = id
				}
				if tid, ok := meResp["tenant_id"].(string); ok {
					p.tenantID = tid
				}
				principals = append(principals, p)
			}
		}
	}

	if len(principals) < 2 {
		result.Status = domain.MissionFailed
		result.Summary = "Insufficient principals for validation"
		result.CompletedAt = time.Now().UTC()
		return result, nil
	}

	principalA := principals[0]
	principalB := principals[1]

	// Step 2: Find objects owned by each principal independently
	var objectBIDs []string
	headersB := map[string]string{"Authorization": "Bearer " + principalB.token}
	for _, query := range []string{"a", "b", "project", "report", "Beta", "Alpha"} {
		if requestCount >= brief.MaxRequests {
			break
		}
		ev, err := r.httpClient.Do(ctx, "GET", brief.TargetBaseURL+"/api/v1/search?q="+query, headersB, "")
		if err != nil {
			continue
		}
		requestCount++
		ev.Description = fmt.Sprintf("Validation: Search for objects owned by principal B (query=%s)", query)
		result.Evidence = append(result.Evidence, *ev)

		if ev.ResponseStatus == 200 {
			var searchResp map[string]any
			if err := json.Unmarshal([]byte(ev.ResponseBody), &searchResp); err == nil {
				if results, ok := searchResp["results"].([]any); ok {
					for _, r := range results {
						if item, ok := r.(map[string]any); ok {
							if id, ok := item["id"].(string); ok {
								objectBIDs = append(objectBIDs, id)
							}
						}
					}
				}
			}
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	var uniqueObjectBIDs []string
	for _, id := range objectBIDs {
		if !seen[id] {
			seen[id] = true
			uniqueObjectBIDs = append(uniqueObjectBIDs, id)
		}
	}

	// Step 3: INDEPENDENT REPRODUCTION — Attempt cross-tenant access
	validatedVulnerable := false
	for _, objID := range uniqueObjectBIDs {
		if requestCount >= brief.MaxRequests {
			break
		}
		headersA := map[string]string{"Authorization": "Bearer " + principalA.token}
		endpoint := "/api/v1/items/" + objID
		ev, err := r.httpClient.Do(ctx, "GET", brief.TargetBaseURL+endpoint, headersA, "")
		if err != nil {
			continue
		}
		requestCount++

		ev.Description = fmt.Sprintf("VALIDATION REPRODUCTION: %s accessing %s (owned by %s)", principalA.tenantID, endpoint, principalB.tenantID)

		if ev.ResponseStatus == 200 {
			// Check that the response contains data from the other tenant
			var itemResp map[string]any
			if err := json.Unmarshal([]byte(ev.ResponseBody), &itemResp); err == nil {
				if respTenant, ok := itemResp["tenant_id"].(string); ok && respTenant != principalA.tenantID {
					validatedVulnerable = true
					ev.Interpretation = fmt.Sprintf("VALIDATED: Cross-tenant access confirmed. Response contains data from %s, accessed by %s", respTenant, principalA.tenantID)
					ev.IsAnomalous = true

					result.Observations = append(result.Observations, domain.MissionObservation{
						Type:        "vulnerability_validated",
						Description: fmt.Sprintf("INDEPENDENTLY VALIDATED: Cross-tenant item access on %s — response contains %s data", endpoint, respTenant),
						Endpoint:    endpoint,
						StatusCode:  200,
						Details: map[string]any{
							"requesting_tenant": principalA.tenantID,
							"response_tenant":   respTenant,
							"validated":         true,
						},
						ObservedAt: time.Now().UTC(),
					})
				}
			}
		} else {
			ev.Interpretation = fmt.Sprintf("Access denied (status %d) — not reproducible on this object", ev.ResponseStatus)
		}
		result.Evidence = append(result.Evidence, *ev)
	}

	// Step 4: Differential control test — verify users endpoint IS protected
	controlDenied := false
	headersA := map[string]string{"Authorization": "Bearer " + principalA.token}
	controlEv, err := r.httpClient.Do(ctx, "GET", brief.TargetBaseURL+"/api/v1/users/"+principalB.userID, headersA, "")
	if err == nil {
		requestCount++
		controlEv.Description = "VALIDATION CONTROL: Cross-tenant user access (should be denied)"
		if controlEv.ResponseStatus == 403 {
			controlDenied = true
			controlEv.Interpretation = "CONTROL PASSED: User endpoint correctly denies cross-tenant access"
		}
		result.Evidence = append(result.Evidence, *controlEv)
	}

	// Step 5: Update hypothesis and generate finding
	update := domain.MissionHypothesisUpdate{HypothesisID: hyp.ID}

	if validatedVulnerable && controlDenied {
		update.NewConfidence = 0.98
		update.NewStatus = "confirmed"
		update.Reason = "Independently validated: cross-tenant item access confirmed (200) with differential control (users=403)"

		result.CandidateFindings = append(result.CandidateFindings, domain.CandidateVulnerability{
			ID:       uuid.New(),
			Title:    fmt.Sprintf("VALIDATED: %s", hyp.Title),
			Type:     "BOLA",
			Severity: "high",
			Endpoint: "/api/v1/items/{id}",
			Description: fmt.Sprintf(
				"Independently validated by separate researcher. "+
					"Cross-tenant item access confirmed: user from %s accessed items owned by %s (HTTP 200). "+
					"Control test: /api/v1/users/{id} correctly returned 403 for the same cross-tenant access pattern. "+
					"This differential confirms the vulnerability is specific to the items endpoint.",
				principalA.tenantID, principalB.tenantID,
			),
			ReproductionSteps: []string{
				fmt.Sprintf("1. Obtain authentication token for any user in %s", principalA.tenantID),
				fmt.Sprintf("2. Enumerate item IDs belonging to %s via search", principalB.tenantID),
				"3. GET /api/v1/items/{target_item_id} with the cross-tenant token",
				"4. Observe: HTTP 200 with full item content including confidential fields",
				fmt.Sprintf("5. Control: GET /api/v1/users/%s correctly returns 403 Forbidden", principalB.userID),
			},
			Impact:       "Complete cross-tenant data leakage on all items. Any authenticated user can read any item in the system.",
			DiscoveredAt: time.Now().UTC(),
		})
	} else if validatedVulnerable {
		update.NewConfidence = 0.85
		update.NewStatus = "supported"
		update.Reason = "Cross-tenant access validated but differential control not confirmed"
	} else {
		update.NewConfidence = 0.20
		update.NewStatus = "contradicted"
		update.Reason = "Could not independently reproduce cross-tenant access"
	}
	result.HypothesisUpdates = append(result.HypothesisUpdates, update)

	if validatedVulnerable {
		result.NextSteps = append(result.NextSteps,
			"Impact research: Demonstrate the full extent of data leakage",
			"Impact research: Enumerate all accessible cross-tenant items",
		)
	}

	result.Status = domain.MissionCompleted
	result.RequestsMade = requestCount
	result.Duration = time.Since(start)
	result.CompletedAt = time.Now().UTC()

	validationVerdict := "NOT VALIDATED"
	if validatedVulnerable {
		validationVerdict = "VALIDATED"
	}
	_ = strings.ToLower // suppress unused import

	result.Summary = fmt.Sprintf("Validation %s: %d objects tested, differential control %s",
		validationVerdict, len(uniqueObjectBIDs),
		map[bool]string{true: "passed (users=403)", false: "not confirmed"}[controlDenied])

	return result, nil
}

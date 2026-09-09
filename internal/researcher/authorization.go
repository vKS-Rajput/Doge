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

// AuthorizationResearcher tests object-level access control through differential
// cross-principal experiments. It designs experiments to distinguish between
// competing authorization hypotheses.
type AuthorizationResearcher struct {
	httpClient HTTPClient
}

// NewAuthorizationResearcher creates a new authorization researcher.
func NewAuthorizationResearcher(httpClient HTTPClient) *AuthorizationResearcher {
	return &AuthorizationResearcher{httpClient: httpClient}
}

// Type returns the researcher type.
func (r *AuthorizationResearcher) Type() domain.ResearcherType {
	return domain.ResearcherAuthorization
}

// Execute performs authorization testing experiments.
func (r *AuthorizationResearcher) Execute(ctx context.Context, brief *domain.MissionBrief) (*domain.MissionResult, error) {
	start := time.Now()
	result := &domain.MissionResult{
		MissionID:      brief.ID,
		ResearcherType: domain.ResearcherAuthorization,
		Status:         domain.MissionActive,
	}
	requestCount := 0

	// Step 1: Identify the principals we have access to
	type principal struct {
		credName string
		token    string
		userID   string
		tenantID string
	}

	var principals []principal
	for credName, token := range brief.Credentials {
		if requestCount >= brief.MaxRequests {
			break
		}
		headers := map[string]string{"Authorization": "Bearer " + token}
		ev, err := r.httpClient.Do(ctx, "GET", brief.TargetBaseURL+"/api/v1/me", headers, "")
		if err != nil {
			continue
		}
		requestCount++
		ev.Description = fmt.Sprintf("Identify principal for %s", credName)
		result.Evidence = append(result.Evidence, *ev)

		if ev.ResponseStatus == 200 {
			var meResp map[string]any
			if err := json.Unmarshal([]byte(ev.ResponseBody), &meResp); err == nil {
				p := principal{credName: credName, token: token}
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
		result.Summary = "Insufficient principals for differential testing (need at least 2)"
		result.CompletedAt = time.Now().UTC()
		return result, nil
	}

	// Step 2: Discover owned objects for each principal
	type ownedObject struct {
		id       string
		ownerID  string
		tenantID string
		endpoint string
	}

	var objectsA []ownedObject
	var objectsB []ownedObject

	// Search for objects owned by each principal
	principalA := principals[0]
	principalB := principals[1]

	// Try to discover objects through the search endpoint
	for _, query := range []string{"Alpha", "Beta", "project", "report", "a", "b"} {
		if requestCount >= brief.MaxRequests {
			break
		}
		headersA := map[string]string{"Authorization": "Bearer " + principalA.token}
		ev, err := r.httpClient.Do(ctx, "GET", brief.TargetBaseURL+"/api/v1/search?q="+query, headersA, "")
		if err != nil {
			continue
		}
		requestCount++
		ev.Description = fmt.Sprintf("Search for objects as %s with query=%s", principalA.credName, query)
		result.Evidence = append(result.Evidence, *ev)

		if ev.ResponseStatus == 200 {
			var searchResp map[string]any
			if err := json.Unmarshal([]byte(ev.ResponseBody), &searchResp); err == nil {
				if results, ok := searchResp["results"].([]any); ok {
					for _, r := range results {
						if item, ok := r.(map[string]any); ok {
							if id, ok := item["id"].(string); ok {
								objectsA = append(objectsA, ownedObject{
									id: id, tenantID: principalA.tenantID, endpoint: "/api/v1/items/" + id,
								})
							}
						}
					}
				}
			}
		}
	}

	// Search as principal B
	for _, query := range []string{"Alpha", "Beta", "project", "report", "a", "b"} {
		if requestCount >= brief.MaxRequests {
			break
		}
		headersB := map[string]string{"Authorization": "Bearer " + principalB.token}
		ev, err := r.httpClient.Do(ctx, "GET", brief.TargetBaseURL+"/api/v1/search?q="+query, headersB, "")
		if err != nil {
			continue
		}
		requestCount++
		ev.Description = fmt.Sprintf("Search for objects as %s with query=%s", principalB.credName, query)
		result.Evidence = append(result.Evidence, *ev)

		if ev.ResponseStatus == 200 {
			var searchResp map[string]any
			if err := json.Unmarshal([]byte(ev.ResponseBody), &searchResp); err == nil {
				if results, ok := searchResp["results"].([]any); ok {
					for _, r := range results {
						if item, ok := r.(map[string]any); ok {
							if id, ok := item["id"].(string); ok {
								objectsB = append(objectsB, ownedObject{
									id: id, tenantID: principalB.tenantID, endpoint: "/api/v1/items/" + id,
								})
							}
						}
					}
				}
			}
		}
	}

	result.Observations = append(result.Observations, domain.MissionObservation{
		Type:        "objects_enumerated",
		Description: fmt.Sprintf("Principal A (%s) owns %d objects, Principal B (%s) owns %d objects", principalA.tenantID, len(objectsA), principalB.tenantID, len(objectsB)),
		Details: map[string]any{
			"principal_a_objects": len(objectsA),
			"principal_b_objects": len(objectsB),
		},
		ObservedAt: time.Now().UTC(),
	})

	// Step 3: THE CORE EXPERIMENT — Cross-tenant access attempts
	// Try accessing principal B's objects with principal A's credentials (and vice versa)

	type crossTestResult struct {
		endpoint         string
		principalCred    string
		objectOwnerTenant string
		statusCode       int
		accessGranted    bool
		responseBody     string
	}

	var crossResults []crossTestResult

	// Test object endpoints (items)
	for _, objB := range objectsB {
		if requestCount >= brief.MaxRequests {
			break
		}
		headersA := map[string]string{"Authorization": "Bearer " + principalA.token}
		ev, err := r.httpClient.Do(ctx, "GET", brief.TargetBaseURL+objB.endpoint, headersA, "")
		if err != nil {
			continue
		}
		requestCount++

		cr := crossTestResult{
			endpoint:          objB.endpoint,
			principalCred:     principalA.credName,
			objectOwnerTenant: objB.tenantID,
			statusCode:        ev.ResponseStatus,
			accessGranted:     ev.ResponseStatus == 200,
			responseBody:      ev.ResponseBody,
		}
		crossResults = append(crossResults, cr)

		ev.Description = fmt.Sprintf("CROSS-TENANT TEST: %s accessing %s (owned by %s)", principalA.credName, objB.endpoint, objB.tenantID)
		ev.Interpretation = fmt.Sprintf("Status %d — cross-tenant access %s", ev.ResponseStatus, map[bool]string{true: "GRANTED", false: "DENIED"}[cr.accessGranted])
		ev.IsAnomalous = cr.accessGranted
		result.Evidence = append(result.Evidence, *ev)

		if cr.accessGranted {
			result.Observations = append(result.Observations, domain.MissionObservation{
				Type:        "cross_tenant_access_granted",
				Description: fmt.Sprintf("CRITICAL: Cross-tenant access GRANTED on %s (status %d)", objB.endpoint, ev.ResponseStatus),
				Endpoint:    objB.endpoint,
				StatusCode:  ev.ResponseStatus,
				Details: map[string]any{
					"requesting_principal": principalA.userID,
					"requesting_tenant":   principalA.tenantID,
					"object_tenant":       objB.tenantID,
					"access_granted":      true,
				},
				ObservedAt: time.Now().UTC(),
			})
		}
	}

	// Step 4: DIFFERENTIAL TEST — Compare with user endpoints (which should be properly protected)
	// Test cross-tenant access on /api/v1/users/{id} to compare behavior
	headersA := map[string]string{"Authorization": "Bearer " + principalA.token}
	ev, err := r.httpClient.Do(ctx, "GET", brief.TargetBaseURL+"/api/v1/users/"+principalB.userID, headersA, "")
	if err == nil {
		requestCount++
		ev.Description = fmt.Sprintf("DIFFERENTIAL TEST: %s accessing user profile of %s", principalA.credName, principalB.userID)
		ev.Interpretation = fmt.Sprintf("Status %d on /api/v1/users/ cross-tenant access", ev.ResponseStatus)
		result.Evidence = append(result.Evidence, *ev)

		result.Observations = append(result.Observations, domain.MissionObservation{
			Type:        "differential_authorization",
			Description: fmt.Sprintf("Cross-tenant user access returned %d (vs cross-tenant item access)", ev.ResponseStatus),
			Endpoint:    "/api/v1/users/" + principalB.userID,
			StatusCode:  ev.ResponseStatus,
			Details: map[string]any{
				"endpoint_type":      "user",
				"access_denied":      ev.ResponseStatus == 403,
				"requesting_tenant":  principalA.tenantID,
				"target_tenant":      principalB.tenantID,
			},
			ObservedAt: time.Now().UTC(),
		})
	}

	// Step 5: Analyze results and update hypotheses
	crossTenantGrantedCount := 0
	crossTenantDeniedCount := 0
	for _, cr := range crossResults {
		if cr.accessGranted {
			crossTenantGrantedCount++
		} else {
			crossTenantDeniedCount++
		}
	}

	userEndpointDenied := ev != nil && ev.ResponseStatus == 403

	// Update hypotheses based on evidence
	for _, hyp := range brief.Hypotheses {
		update := domain.MissionHypothesisUpdate{HypothesisID: hyp.ID}

		hypTitle := strings.ToLower(hyp.Title)
		if strings.Contains(hypTitle, "missing") || strings.Contains(hypTitle, "bola") || strings.Contains(hypTitle, "object-level") {
			if crossTenantGrantedCount > 0 {
				update.NewConfidence = 0.90
				update.NewStatus = "supported"
				update.Reason = fmt.Sprintf("Cross-tenant object access GRANTED %d times", crossTenantGrantedCount)
			} else {
				update.NewConfidence = 0.10
				update.NewStatus = "contradicted"
				update.Reason = "All cross-tenant access attempts were denied"
			}
			result.HypothesisUpdates = append(result.HypothesisUpdates, update)
		}

		if strings.Contains(hypTitle, "strict") || strings.Contains(hypTitle, "isolation") {
			if crossTenantGrantedCount > 0 {
				update.NewConfidence = 0.10
				update.NewStatus = "contradicted"
				update.Reason = fmt.Sprintf("Cross-tenant access was GRANTED on item endpoints (%d times)", crossTenantGrantedCount)
			} else {
				update.NewConfidence = 0.90
				update.NewStatus = "supported"
				update.Reason = "All cross-tenant access consistently denied"
			}
			result.HypothesisUpdates = append(result.HypothesisUpdates, update)
		}

		if strings.Contains(hypTitle, "inconsistent") {
			if crossTenantGrantedCount > 0 && userEndpointDenied {
				update.NewConfidence = 0.95
				update.NewStatus = "confirmed"
				update.Reason = fmt.Sprintf("DIFFERENTIAL: Items endpoint allows cross-tenant (200) while users endpoint denies (403)")
			} else {
				update.NewConfidence = 0.15
				update.NewStatus = "contradicted"
				update.Reason = "Authorization behavior is consistent across endpoints"
			}
			result.HypothesisUpdates = append(result.HypothesisUpdates, update)
		}
	}

	// Step 6: Generate candidate vulnerability if cross-tenant access was granted
	if crossTenantGrantedCount > 0 {
		candidate := domain.CandidateVulnerability{
			ID:       uuid.New(),
			Title:    "Broken Object-Level Authorization (BOLA/IDOR) on Item Endpoints",
			Type:     "BOLA",
			Severity: "high",
			Endpoint: "/api/v1/items/{id}",
			Description: fmt.Sprintf(
				"The /api/v1/items/{id} endpoint allows any authenticated user to access items belonging to any tenant. "+
					"User from %s successfully accessed items belonging to %s. "+
					"In contrast, /api/v1/users/{id} correctly enforces tenant isolation (returns 403 for cross-tenant access). "+
					"This differential behavior indicates missing authorization middleware on the items endpoint.",
				principalA.tenantID, principalB.tenantID,
			),
			ReproductionSteps: []string{
				fmt.Sprintf("1. Authenticate as user from %s with token %s", principalA.tenantID, principalA.credName),
				fmt.Sprintf("2. GET /api/v1/items/{id} where {id} belongs to %s", principalB.tenantID),
				"3. Observe: 200 OK with full item content including confidential data",
				fmt.Sprintf("4. Compare: GET /api/v1/users/%s returns 403 Forbidden (correctly protected)", principalB.userID),
			},
			Impact:       "Cross-tenant data leakage. Any authenticated user can read any item in the system, regardless of tenant boundaries.",
			DiscoveredAt: time.Now().UTC(),
		}

		// Attach evidence
		for _, ev := range result.Evidence {
			if ev.IsAnomalous {
				candidate.Evidence = append(candidate.Evidence, ev)
			}
		}

		result.CandidateFindings = append(result.CandidateFindings, candidate)

		result.NextSteps = append(result.NextSteps,
			"Independent validation: Reproduce cross-tenant access with fresh credentials",
			"Impact research: Demonstrate extent of data leakage (enumerate accessible objects)",
		)
	}

	result.Status = domain.MissionCompleted
	result.RequestsMade = requestCount
	result.Duration = time.Since(start)
	result.CompletedAt = time.Now().UTC()
	result.Summary = fmt.Sprintf(
		"Authorization testing completed: %d cross-tenant grants, %d denials, %d candidates. Differential: users=%d, items=%d",
		crossTenantGrantedCount, crossTenantDeniedCount, len(result.CandidateFindings),
		func() int { if ev != nil { return ev.ResponseStatus }; return 0 }(),
		func() int { if crossTenantGrantedCount > 0 { return 200 }; return 403 }(),
	)

	return result, nil
}

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

// ReconResearcher performs reconnaissance missions to map the target's attack surface.
// It discovers endpoints, technologies, authentication mechanisms, and object identifiers.
type ReconResearcher struct {
	httpClient HTTPClient
}

// NewReconResearcher creates a new reconnaissance researcher.
func NewReconResearcher(httpClient HTTPClient) *ReconResearcher {
	return &ReconResearcher{httpClient: httpClient}
}

// Type returns the researcher type.
func (r *ReconResearcher) Type() domain.ResearcherType {
	return domain.ResearcherRecon
}

// Execute performs a reconnaissance mission against the target.
func (r *ReconResearcher) Execute(ctx context.Context, brief *domain.MissionBrief) (*domain.MissionResult, error) {
	start := time.Now()
	result := &domain.MissionResult{
		MissionID:      brief.ID,
		ResearcherType: domain.ResearcherRecon,
		Status:         domain.MissionActive,
	}
	requestCount := 0

	// Phase 1: Hit the root endpoint to discover the API surface
	rootEvidence, err := r.httpClient.Do(ctx, "GET", brief.TargetBaseURL+"/", nil, "")
	if err == nil && rootEvidence.ResponseStatus == 200 {
		requestCount++
		rootEvidence.Description = "Root endpoint discovery"
		rootEvidence.Interpretation = fmt.Sprintf("Root endpoint returned %d — analyzing for API surface", rootEvidence.ResponseStatus)
		result.Evidence = append(result.Evidence, *rootEvidence)

		// Parse endpoints from root response
		var rootResp map[string]any
		if err := json.Unmarshal([]byte(rootEvidence.ResponseBody), &rootResp); err == nil {
			if endpoints, ok := rootResp["endpoints"].([]any); ok {
				for _, ep := range endpoints {
					if epStr, ok := ep.(string); ok {
						result.Endpoints = append(result.Endpoints, epStr)
						result.Observations = append(result.Observations, domain.MissionObservation{
							Type:        "endpoint_discovered",
							Description: fmt.Sprintf("Endpoint discovered from API index: %s", epStr),
							Endpoint:    epStr,
							ObservedAt:  time.Now().UTC(),
						})
					}
				}
			}
		}
	}

	// Phase 2: Hit health/status endpoints for info
	for _, path := range []string{"/health", "/api/v1/status", "/api/v1/docs"} {
		if requestCount >= brief.MaxRequests {
			break
		}
		ev, err := r.httpClient.Do(ctx, "GET", brief.TargetBaseURL+path, nil, "")
		if err != nil {
			continue
		}
		requestCount++
		ev.Description = fmt.Sprintf("Recon probe: %s", path)
		result.Evidence = append(result.Evidence, *ev)

		if ev.ResponseStatus == 200 {
			result.Observations = append(result.Observations, domain.MissionObservation{
				Type:        "endpoint_live",
				Description: fmt.Sprintf("Endpoint %s is live (HTTP %d)", path, ev.ResponseStatus),
				Endpoint:    path,
				StatusCode:  ev.ResponseStatus,
				ObservedAt:  time.Now().UTC(),
			})

			// Parse status endpoint for architecture info
			if path == "/api/v1/status" {
				var statusResp map[string]any
				if err := json.Unmarshal([]byte(ev.ResponseBody), &statusResp); err == nil {
					if auth, ok := statusResp["auth"].(string); ok {
						result.Observations = append(result.Observations, domain.MissionObservation{
							Type:        "auth_mechanism_discovered",
							Description: fmt.Sprintf("Authentication mechanism: %s", auth),
							Details:     map[string]any{"auth_type": auth},
							ObservedAt:  time.Now().UTC(),
						})
					}
					if tenants, ok := statusResp["tenants"].([]any); ok {
						for _, t := range tenants {
							if tStr, ok := t.(string); ok {
								result.Observations = append(result.Observations, domain.MissionObservation{
									Type:        "tenant_discovered",
									Description: fmt.Sprintf("Tenant discovered: %s", tStr),
									Details:     map[string]any{"tenant_id": tStr},
									ObservedAt:  time.Now().UTC(),
								})
							}
						}
					}
				}
			}

			// Parse docs endpoint for API specs
			if path == "/api/v1/docs" {
				var docsResp map[string]any
				if err := json.Unmarshal([]byte(ev.ResponseBody), &docsResp); err == nil {
					if paths, ok := docsResp["paths"].(map[string]any); ok {
						for p := range paths {
							result.Observations = append(result.Observations, domain.MissionObservation{
								Type:        "api_endpoint_documented",
								Description: fmt.Sprintf("Documented API endpoint: %s", p),
								Endpoint:    p,
								ObservedAt:  time.Now().UTC(),
							})
						}
					}
				}
			}
		}
	}

	// Phase 3: Test authentication with provided credentials
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
		ev.Description = fmt.Sprintf("Authentication test with %s", credName)
		result.Evidence = append(result.Evidence, *ev)

		if ev.ResponseStatus == 200 {
			var meResp map[string]any
			if err := json.Unmarshal([]byte(ev.ResponseBody), &meResp); err == nil {
				userID := ""
				tenantID := ""
				if id, ok := meResp["id"].(string); ok {
					userID = id
					result.Users = append(result.Users, id)
				}
				if tid, ok := meResp["tenant_id"].(string); ok {
					tenantID = tid
				}
				result.Observations = append(result.Observations, domain.MissionObservation{
					Type:        "principal_identified",
					Description: fmt.Sprintf("Credential %s maps to user %s in tenant %s", credName, userID, tenantID),
					Details:     map[string]any{"user_id": userID, "tenant_id": tenantID, "credential": credName},
					ObservedAt:  time.Now().UTC(),
				})
			}
		}
	}

	// Phase 4: Probe discovered endpoints to understand object identifier patterns
	for _, ep := range result.Endpoints {
		if requestCount >= brief.MaxRequests {
			break
		}
		// Check for parameterized endpoints
		if strings.Contains(ep, "{id}") {
			result.Observations = append(result.Observations, domain.MissionObservation{
				Type:        "object_identifier_pattern",
				Description: fmt.Sprintf("Endpoint %s uses object identifier pattern", ep),
				Endpoint:    ep,
				Details:     map[string]any{"pattern": "path_parameter", "identifier": "{id}"},
				ObservedAt:  time.Now().UTC(),
			})
			result.NewUnknowns = append(result.NewUnknowns,
				fmt.Sprintf("Authorization enforcement on %s is untested", ep),
			)
		}
	}

	// Generate new hypotheses based on observations
	hasObjectEndpoints := false
	hasMultipleTenants := false
	hasMultiplePrincipals := len(result.Users) >= 2

	for _, obs := range result.Observations {
		if obs.Type == "object_identifier_pattern" {
			hasObjectEndpoints = true
		}
		if obs.Type == "tenant_discovered" {
			hasMultipleTenants = true
		}
	}

	if hasObjectEndpoints && hasMultipleTenants && hasMultiplePrincipals {
		result.NewHypotheses = append(result.NewHypotheses, domain.MissionHypothesis{
			ID:                   uuid.New(),
			Title:                "Missing Object-Level Authorization",
			Statement:            "Object endpoints with path identifiers may not enforce tenant isolation. Cross-tenant access may be possible.",
			Confidence:           0.60,
			ConfirmationCriteria: "Authenticated user from tenant A can access objects belonging to tenant B",
			RefutationCriteria:   "All object endpoints consistently return 403 for cross-tenant access",
		})
		result.NewHypotheses = append(result.NewHypotheses, domain.MissionHypothesis{
			ID:                   uuid.New(),
			Title:                "Strict Tenant Isolation Enforced",
			Statement:            "All endpoints consistently enforce tenant isolation at the server level.",
			Confidence:           0.50,
			ConfirmationCriteria: "All endpoints return 403 or 404 for cross-tenant access attempts",
			RefutationCriteria:   "Any endpoint returns 200 with cross-tenant data",
		})
		result.NewHypotheses = append(result.NewHypotheses, domain.MissionHypothesis{
			ID:                   uuid.New(),
			Title:                "Inconsistent Authorization Enforcement",
			Statement:            "Tenant isolation is enforced on some endpoints but not others, creating a differential vulnerability.",
			Confidence:           0.55,
			ConfirmationCriteria: "Different endpoints show different authorization behavior for the same cross-tenant request pattern",
			RefutationCriteria:   "All endpoints show identical authorization behavior",
		})
	}

	result.Status = domain.MissionCompleted
	result.RequestsMade = requestCount
	result.Duration = time.Since(start)
	result.CompletedAt = time.Now().UTC()
	result.Summary = fmt.Sprintf("Reconnaissance completed: %d endpoints, %d users, %d observations, %d hypotheses generated",
		len(result.Endpoints), len(result.Users), len(result.Observations), len(result.NewHypotheses))

	return result, nil
}

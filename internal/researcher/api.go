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

// APIResearcher inspects API definitions, parameter schemas, HTTP method
// manipulation, and content-type negotiation across discovered attack surfaces.
type APIResearcher struct {
	httpClient HTTPClient
}

// NewAPIResearcher creates a new API researcher.
func NewAPIResearcher(httpClient HTTPClient) *APIResearcher {
	return &APIResearcher{httpClient: httpClient}
}

// Type returns domain.ResearcherAPI.
func (r *APIResearcher) Type() domain.ResearcherType {
	return domain.ResearcherAPI
}

// Execute performs structured API reconnaissance, schema discovery, and verb tampering experiments.
func (r *APIResearcher) Execute(ctx context.Context, brief *domain.MissionBrief) (*domain.MissionResult, error) {
	start := time.Now()
	result := &domain.MissionResult{
		MissionID:      brief.ID,
		ResearcherType: domain.ResearcherAPI,
		Status:         domain.MissionActive,
	}
	requestCount := 0

	// Common API schema and documentation endpoints
	schemaEndpoints := []string{
		"/openapi.json",
		"/swagger.json",
		"/v2/api-docs",
		"/v3/api-docs",
		"/api-docs",
		"/swagger/v1/swagger.json",
		"/graphql",
		"/api/graphql",
	}

	authHeaders := make(map[string]string)
	for _, token := range brief.Credentials {
		authHeaders["Authorization"] = "Bearer " + token
		break
	}

	// Step 1: Probe for API definitions & documentation
	for _, schemaPath := range schemaEndpoints {
		if requestCount >= brief.MaxRequests {
			break
		}
		targetURL := strings.TrimRight(brief.TargetBaseURL, "/") + schemaPath
		ev, err := r.httpClient.Do(ctx, "GET", targetURL, authHeaders, "")
		if err != nil {
			continue
		}
		requestCount++
		ev.Description = fmt.Sprintf("Probe for API schema at %s", schemaPath)
		result.Evidence = append(result.Evidence, *ev)

		if ev.ResponseStatus == 200 && len(ev.ResponseBody) > 20 {
			result.Observations = append(result.Observations, domain.MissionObservation{
				Type:        "api_schema_discovered",
				Description: fmt.Sprintf("Discovered API schema/documentation at %s", schemaPath),
				Endpoint:    targetURL,
				Method:      "GET",
				StatusCode:  ev.ResponseStatus,
				Details:     map[string]any{"path": schemaPath, "size": len(ev.ResponseBody)},
				ObservedAt:  time.Now().UTC(),
			})

			// If Swagger/OpenAPI JSON, extract path definitions
			var openAPIDoc struct {
				Paths map[string]any `json:"paths"`
			}
			if err := json.Unmarshal([]byte(ev.ResponseBody), &openAPIDoc); err == nil && len(openAPIDoc.Paths) > 0 {
				for p := range openAPIDoc.Paths {
					fullPath := strings.TrimRight(brief.TargetBaseURL, "/") + p
					result.Endpoints = append(result.Endpoints, fullPath)
				}
			}

			// If GraphQL, attempt introspection
			if strings.Contains(schemaPath, "graphql") {
				r.probeGraphQLIntrospection(ctx, targetURL, authHeaders, brief.MaxRequests-requestCount, result, &requestCount)
			}
		}
	}

	// Step 2: HTTP Verb Tampering & Method Override on known endpoints
	methodsToTest := []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
	for _, ep := range brief.KnownEndpoints {
		if requestCount >= brief.MaxRequests {
			break
		}
		for _, method := range methodsToTest {
			if requestCount >= brief.MaxRequests {
				break
			}
			ev, err := r.httpClient.Do(ctx, method, ep, authHeaders, "{}")
			if err != nil {
				continue
			}
			requestCount++
			ev.Description = fmt.Sprintf("HTTP verb tampering [%s] on %s", method, ep)
			result.Evidence = append(result.Evidence, *ev)

			// Check for method override vulnerability or unauthenticated bypass
			if ev.ResponseStatus == 200 && (method == "PUT" || method == "DELETE" || method == "PATCH") {
				cand := domain.CandidateVulnerability{
					ID:          uuid.New(),
					Type:        "API_UNEXPECTED_VERB_PERMITTED",
					Title:       fmt.Sprintf("Unexpected HTTP Verb %s Accepted on %s", method, ep),
					Description: fmt.Sprintf("Endpoint %s accepted %s request with 200 OK. State modification or privilege override may be possible.", ep, method),
					Severity:    string(domain.SeverityMedium),
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
	result.Summary = fmt.Sprintf("API Research: %d requests made, %d schemas discovered, %d endpoints extracted, %d candidate findings",
		requestCount, len(result.Observations), len(result.Endpoints), len(result.CandidateFindings))

	return result, nil
}

func (r *APIResearcher) probeGraphQLIntrospection(ctx context.Context, url string, headers map[string]string, remainingReq int, result *domain.MissionResult, reqCount *int) {
	if remainingReq <= 0 {
		return
	}
	introspectQuery := `{"query":"{ __schema { types { name } } }"}`
	h := make(map[string]string)
	for k, v := range headers {
		h[k] = v
	}
	h["Content-Type"] = "application/json"

	ev, err := r.httpClient.Do(ctx, "POST", url, h, introspectQuery)
	if err != nil {
		return
	}
	*reqCount++
	ev.Description = "GraphQL introspection query"
	result.Evidence = append(result.Evidence, *ev)

	if ev.ResponseStatus == 200 && strings.Contains(ev.ResponseBody, "__schema") {
		result.CandidateFindings = append(result.CandidateFindings, domain.CandidateVulnerability{
			ID:          uuid.New(),
			Type:        "GRAPHQL_INTROSPECTION_ENABLED",
			Title:       fmt.Sprintf("GraphQL Introspection Enabled on %s", url),
			Description: "GraphQL schema introspection is publicly enabled, disclosing full backend schema and query types.",
			Severity:    string(domain.SeverityLow),
			Endpoint:    url,
			DiscoveredAt: time.Now().UTC(),
		})
	}
}
